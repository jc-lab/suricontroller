-- Transport test for the Kong plugin's socket client (adapters/kong),
-- run with the OpenResty "resty" CLI against suritap-mockd:
--   resty -I adapters/kong test/tap/kong/transport_test.lua <mockd dir> [<silent server dir>]
-- (test/tap/kong/transport.sh runs it in the Kong image).
local transport = require "kong.plugins.suritap.transport"

local dir = arg[1]
local MARKER = "SURITAP-TEST-DROP" -- suritap-mockd drops packets containing it
local failed = 0

local function check(name, cond, ...)
  if cond then
    print("PASS " .. name)
  else
    failed = failed + 1
    local a, b = ...
    print("FAIL " .. name .. ": " .. tostring(a) .. " " .. tostring(b))
  end
end

local t = transport.get(dir, "resty-test")
local meta = { transport.META.proxy, "test", transport.META.sni, "app.example" }

local function inspect(data, timeout, src)
  local c, err = t:open(src or "203.0.113.7", 40000, "10.0.0.1", 443, meta, timeout or 2)
  if not c then
    return nil, err
  end
  local v, e = c:inspect(0, data, timeout or 2)
  c:close(false)
  return v, e
end

local v, err = inspect("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
check("benign request passes", v and v.action == transport.PASS, err)
v, err = inspect("GET /" .. MARKER .. " HTTP/1.1\r\nHost: a\r\n\r\n")
check("marker is dropped", v and v.action == transport.DROP, err)
v, err = inspect("GET / HTTP/1.1\r\n\r\n", 2, "2001:db8::7")
check("IPv6 client", v and v.action == transport.PASS, err)
v, err = inspect(string.rep("x", 300000) .. MARKER)
check("large payload split into frames", v and v.action == transport.DROP, err)

-- Many concurrent requests (light threads) share the worker sessions.
local threads, bad = {}, 0
for i = 1, 50 do
  threads[i] = ngx.thread.spawn(function()
    for _ = 1, 20 do
      local r, e = inspect("GET /x HTTP/1.1\r\n\r\n")
      if not r or r.action ~= transport.PASS then
        bad = bad + 1
        print("  error: " .. tostring(e))
      end
    end
  end)
end
for i = 1, #threads do
  ngx.thread.wait(threads[i])
end
check("1000 concurrent requests", bad == 0, bad)
check("one session per Suricata worker", t.workers == 2 and t.sessions[0] and t.sessions[1], t.workers)

-- A worker that never answers: verdicts time out on time, and after
-- stuck_after without any verdict the session is re-opened.
local silent = arg[2]
if silent then
  transport.stuck_after = 0.3
  local ts = transport.get(silent, "resty-test")
  local function sessions()
    local f = io.open(silent .. "/sessions")
    if not f then
      return 0
    end
    local n = 0
    for _ in f:lines() do
      n = n + 1
    end
    f:close()
    return n
  end
  local start = ngx.now()
  local c = ts:open("203.0.113.7", 40000, "10.0.0.1", 443, meta, 1)
  v, err = c:inspect(0, "GET / HTTP/1.1\r\n\r\n", 0.1)
  local took = ngx.now() - start
  check("silent worker: timeout after 100ms", not v and err == "timeout" and took < 0.5, err, took)
  ngx.sleep(0.4)
  c = ts:open("203.0.113.7", 40000, "10.0.0.1", 443, meta, 1)
  v, err = c:inspect(0, "GET / HTTP/1.1\r\n\r\n", 0.1)
  ngx.sleep(0.2)
  c = ts:open("203.0.113.7", 40000, "10.0.0.1", 443, meta, 1)
  check("stuck session re-opened", c and sessions() == 2, sessions())
end

if failed > 0 then
  print(failed .. " failure(s)")
  os.exit(1)
end
print("ALL PASSED")
os.exit(0) -- the session timers would keep resty running
