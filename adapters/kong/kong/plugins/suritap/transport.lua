-- suritap socket transport client for OpenResty (Kong).
--
-- Talks to the suritap Suricata plugin over worker-N.stream.sock (see
-- docs/suritap.md §3.6): a 64-byte HELLO/WELCOME exchange, then frames
-- "len:u32 kind:u16 flags:u16 body", little-endian.
--
-- Cosockets are bound to the request (or timer) that created them, and the
-- header/body filter and log phases cannot use them at all. So every nginx
-- worker runs one timer per Suricata worker that owns the session socket
-- (a writer loop plus a reader light thread); requests only queue frames
-- and wait for their verdict on a semaphore. Queuing never yields, so it
-- works in every phase; waiting needs a yieldable phase (access, response).

local ffi = require "ffi"
local bit = require "bit"
local semaphore = require "ngx.semaphore"

local band, rshift, lshift, bor = bit.band, bit.rshift, bit.lshift, bit.bor
local char, byte, sub, concat = string.char, string.byte, string.sub, table.concat
local floor, random = math.floor, math.random
local now, sleep, log = ngx.now, ngx.sleep, ngx.log
local ERR, WARN, DEBUG = ngx.ERR, ngx.WARN, ngx.DEBUG

-- pcall: another module may have declared it already.
pcall(ffi.cdef, [[
int inet_pton(int af, const char *src, void *dst);
]])

local _M = {}

local MAGIC = 0x50415453
local VERSION = 1
local HELLO_SIZE = 64
local K_OPEN, K_DATA, K_GAP, K_CLOSE = 1, 2, 3, 5
local K_VERDICT, K_FLOW_ERROR = 0x81, 0x84
local F_WANT_VERDICT = 1
local MAX_INFLIGHT = 1024 -- STREAM_MAX_INFLIGHT
local MAX_META = 2048

-- Tunables (fields so tests can change them).
_M.dial_timeout = 2         -- seconds, connect and handshake
_M.retry_delay = 1          -- seconds a failed worker is reported unavailable
_M.write_stall = 5          -- seconds one batch may take to be written
_M.stuck_after = 5          -- seconds without any verdict while requests time out
_M.idle_timeout = 300       -- seconds without traffic before a session closes
_M.max_queue = 8 * 1024 * 1024 -- bytes queued per session before payload is dropped (as a gap)

_M.META = { sni = 1, alpn = 2, route = 4, request_id = 5, endpoint = 6, service = 7, user = 8, proto = 9, proxy = 10 }
_M.PASS, _M.DROP, _M.ERROR = 0, 1, 2
_M.REASONS = { [0] = "none", "rule", "policy", "flow", "unknown-flow", "protocol", "engine" }

-- Little-endian encoding. Connection ids stay below 2^53 (Lua numbers).

local function u16(n)
  return char(band(n, 0xff), band(rshift(n, 8), 0xff))
end

local function u32(n)
  return char(band(n, 0xff), band(rshift(n, 8), 0xff), band(rshift(n, 16), 0xff), band(rshift(n, 24), 0xff))
end

local function u64(n)
  local hi = floor(n / 4294967296)
  return u32(n - hi * 4294967296) .. u32(hi)
end

local function get_u16(s, i)
  local a, b = byte(s, i, i + 1)
  return a + b * 256
end

local function get_u32(s, i)
  local a, b, c, d = byte(s, i, i + 3)
  return a + b * 256 + c * 65536 + d * 16777216
end

local function frame_head(kind, flags, body_len)
  return u32(8 + body_len) .. u16(kind) .. u16(flags)
end

local addr_buf = ffi.new("uint8_t[16]")

-- parse_ip returns the 4 or 16 address bytes, or nil.
local function parse_ip(ip)
  if not ip then
    return nil
  end
  if ffi.C.inet_pton(2, ip, addr_buf) == 1 then -- AF_INET
    return ffi.string(addr_buf, 4)
  end
  if ffi.C.inet_pton(10, ip, addr_buf) == 1 then -- AF_INET6
    local b = ffi.string(addr_buf, 16)
    if sub(b, 1, 12) == "\0\0\0\0\0\0\0\0\0\0\255\255" then -- IPv4-mapped
      return sub(b, 13, 16)
    end
    return b
  end
  return nil
end
_M.parse_ip = parse_ip

local function pad(s, n)
  return s .. string.rep("\0", n - #s)
end

local function encode_open(cid, src_ip, src_port, dst_ip, dst_port, meta)
  local family = #src_ip == 4 and 4 or 6
  local b = {
    u64(cid), char(family, 0), u16(0), u32(0),
    u16(src_port), u16(dst_port), u32(0),
    pad(src_ip, 16), pad(dst_ip, 16),
  }
  local total = 0
  for i = 1, #meta do
    local tag, v = meta[i][1], meta[i][2]
    if v and v ~= "" then
      v = tostring(v)
      if #v > 1024 then
        v = sub(v, 1, 1024)
      end
      if total + 4 + #v > MAX_META then
        break
      end
      total = total + 4 + #v
      b[#b + 1] = char(tag, 0) .. u16(#v) .. v
    end
  end
  return concat(b)
end

local function decode_verdict(body)
  local v = { action = byte(body, 14), reason = byte(body, 15), sids = {} }
  if v.action > _M.ERROR then
    v.action = _M.ERROR
  end
  local n = byte(body, 16)
  for i = 0, n - 1 do
    local off = 25 + i * 16
    if off + 3 > #body then
      break
    end
    v.sids[#v.sids + 1] = get_u32(body, off)
  end
  return v
end

local function stream_path(dir, i)
  return dir .. "/worker-" .. i .. ".stream.sock"
end

---------------------------------------------------------------------------
-- Sessions (one per Suricata worker, owned by a timer of this nginx worker)
---------------------------------------------------------------------------

local Session = {}
Session.__index = Session

local function new_session(t, idx)
  return setmetatable({
    t = t,
    idx = idx,
    queue = {},     -- frame fragments waiting for the writer
    qbytes = 0,
    wake = semaphore.new(0),
    signaled = false, -- wake posted and not consumed yet
    waiting = {},   -- token -> waiter table, or false when the waiter gave up
    inflight = 0,   -- outstanding verdict requests (abandoned ones included)
    abandoned = 0,
    next_token = 0,
    ready = false,
    dead = false,
    last_verdict = now(),
    last_use = now(),
  }, Session)
end

-- fail marks the session dead and releases its waiters; the owning timer
-- closes the socket.
function Session:fail(why)
  if self.dead then
    return
  end
  self.dead = true
  self.why = why
  for token, w in pairs(self.waiting) do
    if w then
      w.dead = true
      w.sema:post(1)
    end
    self.waiting[token] = nil
  end
  self.wake:post(1)
  self.t:changed()
end

-- push queues frame fragments; false when the queue is full.
function Session:push(size, ...)
  if self.dead then
    return false
  end
  if self.qbytes + size > _M.max_queue then
    return false
  end
  local q = self.queue
  for i = 1, select("#", ...) do
    q[#q + 1] = select(i, ...)
  end
  self.qbytes = self.qbytes + size
  if not self.signaled then
    self.signaled = true
    self.wake:post(1)
  end
  return true
end

-- recv reads exactly n bytes. Reads time out every second so that a dead
-- session is noticed; a timeout returns the bytes read so far, which are
-- kept (dropping them would break the framing).
local function recv(s, sock, n)
  local got = nil
  while true do
    local data, err, partial = sock:receive(n - (got and #got or 0))
    if data then
      return got and got .. data or data
    end
    if err ~= "timeout" then
      return nil, err
    end
    if partial and partial ~= "" then
      got = got and got .. partial or partial
    end
    if s.dead then
      return nil, "closed"
    end
  end
end

local function reader(s, sock)
  while true do
    local head, err = recv(s, sock, 8)
    if not head then
      s:fail("session closed: " .. err)
      return
    end
    do
      local len = get_u32(head, 1)
      local kind = get_u16(head, 5)
      if len < 8 or len > 1048576 then
        s:fail("bad frame from server")
        return
      end
      local body = ""
      if len > 8 then
        body, err = recv(s, sock, len - 8)
        if not body then
          s:fail("session closed: " .. err)
          return
        end
      end
      if kind == K_VERDICT and #body >= 24 then
        local token = get_u32(body, 9)
        local w = s.waiting[token]
        if w ~= nil then
          s.waiting[token] = nil
          s.inflight = s.inflight - 1
          if w then
            w.body = body
            w.sema:post(1)
          else
            s.abandoned = s.abandoned - 1
          end
        end
        s.last_verdict = now()
      elseif kind == K_FLOW_ERROR then
        log(DEBUG, "suritap: flow error ", get_u32(body, 9))
      end
    end
  end
end

local function handshake(sock, name)
  local hello = u32(MAGIC) .. u16(VERSION) .. u16(HELLO_SIZE) .. u32(ngx.worker.pid())
    .. u32(1) .. pad(sub(name, 1, 32), 32)
  hello = pad(hello, HELLO_SIZE)
  local ok, err = sock:send(hello)
  if not ok then
    return nil, "hello: " .. err
  end
  local w
  w, err = sock:receive(HELLO_SIZE)
  if not w then
    return nil, "welcome: " .. err
  end
  if get_u32(w, 1) ~= MAGIC or get_u16(w, 5) ~= VERSION then
    return nil, "malformed welcome"
  end
  local status = get_u16(w, 7)
  if status ~= 0 then
    local msg = sub(w, 25):gsub("%z.*", "")
    return nil, "session refused (" .. status .. "): " .. msg
  end
  return {
    worker = get_u16(w, 9),
    workers = get_u16(w, 11),
    max_payload = get_u32(w, 13),
  }
end

-- run is the timer that owns the session socket.
local function run(premature, s)
  if premature then
    s:fail("worker exiting")
    return
  end
  local t = s.t
  local sock = ngx.socket.tcp()
  sock:settimeouts(_M.dial_timeout * 1000, _M.dial_timeout * 1000, _M.dial_timeout * 1000)
  local ok, err = sock:connect("unix:" .. stream_path(t.dir, s.idx))
  local info
  if ok then
    info, err = handshake(sock, t.name)
  end
  if not info then
    sock:close()
    t:dial_failed(s, err)
    return
  end
  s.worker, s.workers = info.worker, info.workers
  s.max_payload = info.max_payload
  if s.max_payload <= 0 or s.max_payload > 65536 then
    s.max_payload = 65536
  end
  s.last_verdict, s.last_use = now(), now()
  if not t:install(s) then
    sock:close()
    return
  end
  s.ready = true
  t:changed()
  -- Reads time out every second so the reader notices a dead session.
  sock:settimeouts(_M.dial_timeout * 1000, _M.write_stall * 1000, 1000)
  local rd = ngx.thread.spawn(reader, s, sock)
  while not s.dead do
    if #s.queue == 0 then
      s.wake:wait(1)
      s.signaled = false
      if ngx.worker.exiting() then
        -- nginx waits for running timers on a graceful worker shutdown.
        s:fail("worker exiting")
      elseif #s.queue == 0 and not s.dead and s.inflight == 0 and now() - s.last_use > _M.idle_timeout then
        s:fail("idle")
      end
    end
    if #s.queue > 0 and not s.dead then
      local batch = s.queue
      s.queue, s.qbytes = {}, 0
      s.last_use = now()
      ok, err = sock:send(batch)
      if not ok then
        s:fail("write: " .. err)
      end
    end
  end
  if s.why ~= "idle" then
    log(DEBUG, "suritap: session to worker ", s.idx, " closed: ", s.why)
  end
  sock:close()
  ngx.thread.wait(rd)
end

---------------------------------------------------------------------------
-- Transport (per socket directory and client name, per nginx worker)
---------------------------------------------------------------------------

local Transport = {}
Transport.__index = Transport

local transports = {}

function _M.get(dir, name)
  local key = dir .. "\0" .. name
  local t = transports[key]
  if not t then
    t = setmetatable({
      dir = dir,
      name = name,
      sessions = nil,  -- [0..workers-1] once the worker count is known
      workers = 0,
      probe = nil,     -- session opening worker 0 to learn the worker count
      retry_at = 0,
      cond = semaphore.new(0),
      next_cid = floor(random() * 2 ^ 40) * 256,
    }, Transport)
    transports[key] = t
  end
  return t
end

-- changed wakes every request waiting for a session.
function Transport:changed()
  local n = -self.cond:count()
  if n > 0 then
    self.cond:post(n)
  end
end

function Transport:dial_failed(s, err)
  s.dead, s.why = true, err
  self.retry_at = now() + _M.retry_delay
  if self.probe == s then
    self.probe = nil
  end
  if self.sessions and self.sessions[s.idx] == s then
    self.sessions[s.idx] = nil
  end
  self:changed()
end

-- install records an opened session; a different worker count (Suricata
-- restarted) replaces the layout and closes the old sessions.
function Transport:install(s)
  if self.probe == s then
    self.probe = nil
  end
  if s.workers < 1 or s.worker >= s.workers then
    s:fail("bad welcome")
    return false
  end
  if s.workers ~= self.workers then
    if self.sessions then
      for i = 0, self.workers - 1 do
        local old = self.sessions[i]
        if old and old ~= s then
          old:fail("worker layout changed")
        end
      end
    end
    self.sessions, self.workers = {}, s.workers
  end
  local old = self.sessions[s.worker]
  if old and old ~= s and not old.dead then
    old:fail("session replaced")
  end
  self.sessions[s.worker] = s
  s.idx = s.worker
  return true
end

local function start(t, idx)
  local s = new_session(t, idx)
  local ok, err = ngx.timer.at(0, run, s)
  if not ok then
    return nil, "timer: " .. tostring(err)
  end
  return s
end

-- session returns a ready session for cid, opening one when needed and
-- waiting for it until deadline (ngx.now() based).
function Transport:session(cid, deadline)
  while true do
    local s
    if self.sessions then
      local idx = cid % self.workers
      s = self.sessions[idx]
      if not s or s.dead then
        if now() < self.retry_at then
          return nil, "unavailable"
        end
        local err
        s, err = start(self, idx)
        if not s then
          return nil, err
        end
        self.sessions[idx] = s
      end
    else
      s = self.probe
      if not s then
        if now() < self.retry_at then
          return nil, "unavailable"
        end
        local err
        s, err = start(self, 0)
        if not s then
          return nil, err
        end
        self.probe = s
      end
    end
    if s.ready and not s.dead then
      return s
    end
    local left = deadline - now()
    if left <= 0 then
      return nil, "timeout"
    end
    -- Requires a yieldable phase.
    local ok, err = self.cond:wait(left)
    if not ok and err ~= "timeout" then
      return nil, err
    end
  end
end

---------------------------------------------------------------------------
-- Connections
---------------------------------------------------------------------------

local Conn = {}
Conn.__index = Conn

-- open announces a connection. src/dst are {ip, port}; meta is a list of
-- {tag, value}. timeout (seconds) bounds waiting for a session.
function Transport:open(src_ip, src_port, dst_ip, dst_port, meta, timeout)
  local sb, db = parse_ip(src_ip), parse_ip(dst_ip)
  if not sb then
    return nil, "unusable client address"
  end
  if not db or #db ~= #sb then
    db = string.rep("\0", #sb)
  end
  self.next_cid = self.next_cid + 1
  local cid = self.next_cid
  local s, err = self:session(cid, now() + timeout)
  if not s then
    return nil, err
  end
  local body = encode_open(cid, sb, src_port or 0, db, dst_port or 0, meta or {})
  if not s:push(8 + #body, frame_head(K_OPEN, 0, #body), body) then
    return nil, "queue full"
  end
  return setmetatable({ s = s, cid = cid, gaps = { [0] = 0, 0 } }, Conn)
end

local function data_head(cid, dir, token)
  return u64(cid) .. char(dir, 0, 0, 0) .. u32(token)
end

-- flush_gap queues the pending gap of dir; false when there is no room.
function Conn:flush_gap(dir)
  local n = self.gaps[dir]
  if n == 0 then
    return true
  end
  local b = u64(self.cid) .. char(dir, 0, 0, 0) .. u32(n)
  if not self.s:push(24, frame_head(K_GAP, 0, 16), b) then
    return false
  end
  self.gaps[dir] = 0
  return true
end

-- queue sends data as DATA frames (the last one with token when given).
-- Data that does not fit is reported as a gap.
function Conn:queue(dir, data, token)
  local s = self.s
  if not self:flush_gap(dir) then
    self.gaps[dir] = self.gaps[dir] + #data
    return false
  end
  local len, mp = #data, s.max_payload
  local i = 1
  repeat
    local j = i + mp - 1
    local last = j >= len
    if last then
      j = len
    end
    local n = j - i + 1
    local flags, tok = 0, 0
    if last and token then
      flags, tok = F_WANT_VERDICT, token
    end
    if not s:push(24 + n, frame_head(K_DATA, flags, 16 + n), data_head(self.cid, dir, tok), n == len and data or sub(data, i, j)) then
      self.gaps[dir] = self.gaps[dir] + (len - i + 1)
      return false
    end
    i = j + 1
  until i > len
  return true
end

-- send streams data without waiting (works in every phase).
function Conn:send(dir, data)
  if self.closed or data == "" then
    return true
  end
  return self:queue(dir, data, nil)
end

-- inspect sends data and waits (yieldable phases only) for the verdict
-- covering everything sent so far in dir. Returns the verdict table, or
-- nil and an error ("timeout", "unavailable", ...).
function Conn:inspect(dir, data, timeout)
  local s = self.s
  if s.dead then
    return nil, "unavailable"
  end
  if s.inflight >= MAX_INFLIGHT then
    if s.abandoned >= MAX_INFLIGHT / 2 then
      s:fail("Suricata worker stopped answering")
    end
    self.gaps[dir] = self.gaps[dir] + #data
    return nil, "too many requests in flight"
  end
  s.next_token = s.next_token % 4294967295 + 1 -- 1..2^32-1 (0: no verdict)
  local token = s.next_token
  local w = { sema = semaphore.new(0) }
  s.waiting[token] = w
  s.inflight = s.inflight + 1
  if not self:queue(dir, data, token) then
    s.waiting[token] = nil
    s.inflight = s.inflight - 1
    return nil, "queue full"
  end
  local ok, err = w.sema:wait(timeout)
  if ok and w.body then
    return decode_verdict(w.body)
  end
  if w.dead then
    return nil, "unavailable"
  end
  if s.waiting[token] == w then
    -- Keep the slot until the late verdict arrives.
    s.waiting[token] = false
    s.abandoned = s.abandoned + 1
    if now() - s.last_verdict > _M.stuck_after then
      s:fail("Suricata worker stopped answering")
    end
  end
  return nil, err or "timeout"
end

-- close ends the connection (FIN both ways, or RST when reset).
function Conn:close(reset)
  if self.closed then
    return
  end
  self.closed = true
  local b = u64(self.cid) .. char(reset and 1 or 0, 0, 0, 0) .. u32(0)
  self.s:push(24, frame_head(K_CLOSE, 0, 16), b)
end

_M.Transport = Transport
_M.Conn = Conn
return _M
