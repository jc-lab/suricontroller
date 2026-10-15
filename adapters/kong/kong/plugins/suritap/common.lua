-- Helpers shared by the suritap and suritap-response plugins.

local transport = require "kong.plugins.suritap.transport"

local ngx = ngx
local kong = kong
local fmt, concat, sub = string.format, table.concat, string.sub

local _M = {
  TO_SERVER = 0,
  TO_CLIENT = 1,
}

local STATUS_TEXT = {
  [200] = "OK", [201] = "Created", [202] = "Accepted", [204] = "No Content", [206] = "Partial Content",
  [301] = "Moved Permanently", [302] = "Found", [303] = "See Other", [304] = "Not Modified",
  [307] = "Temporary Redirect", [308] = "Permanent Redirect", [400] = "Bad Request",
  [401] = "Unauthorized", [403] = "Forbidden", [404] = "Not Found", [405] = "Method Not Allowed",
  [409] = "Conflict", [413] = "Payload Too Large", [429] = "Too Many Requests",
  [500] = "Internal Server Error", [502] = "Bad Gateway", [503] = "Service Unavailable",
  [504] = "Gateway Timeout",
}

local unavailable_logged = 0

-- log_unavailable reports transport failures at most every 10 seconds.
function _M.log_unavailable(endpoint, err)
  local now = ngx.now()
  if now - unavailable_logged >= 10 then
    unavailable_logged = now
    kong.log.err("suritap: cannot reach Suricata (", endpoint, "): ", err)
  end
end

function _M.log_block(endpoint, cid, what, v)
  if v then
    kong.log.warn("suritap: blocked ", what, " on ", endpoint, ": cid=", fmt("%.0f", cid),
      " reason=", transport.REASONS[v.reason] or v.reason, " sids=[", concat(v.sids, " "), "]")
  else
    kong.log.warn("suritap: blocked ", what, " on ", endpoint, ": cid=", fmt("%.0f", cid), " (no verdict, fail closed)")
  end
end

-- blocked_response answers 403 for drop verdicts and 503 when refused
-- without one (fail closed).
function _M.blocked_response(cid, drop)
  local headers = {
    ["Content-Type"] = "text/plain; charset=utf-8",
    ["X-Content-Type-Options"] = "nosniff",
  }
  if cid then
    headers["X-Suritap-Cid"] = fmt("%.0f", cid)
  end
  if drop then
    return kong.response.exit(403, "Forbidden\n", headers)
  end
  return kong.response.exit(503, "Service Unavailable\n", headers)
end

-- Framing headers are written by the callers. Expect is dropped: nginx
-- already answered "100 Continue", and Suricata would otherwise hold the
-- request body back waiting for that interim response. Keys are the
-- lower-case names of ngx.req/resp.get_headers.
local SKIP = { ["content-length"] = true, ["transfer-encoding"] = true, trailer = true, expect = true }

-- One reusable buffer for serializing heads (no per-line strings).
local sb = require("string.buffer").new(4096)

local function header_lines(headers, skip, lower)
  for k, v in pairs(headers) do
    if lower then
      k = k:lower()
    end
    if not SKIP[k] and k ~= skip then
      if type(v) == "table" then
        for i = 1, #v do
          sb:put(k, ": ", v[i], "\r\n")
        end
      else
        sb:put(k, ": ", v, "\r\n")
      end
    end
  end
end

-- Header lines the request head gets from us (framing) or must not carry
-- (Expect, see SKIP), removed from raw HTTP/1.x headers.
local RAW_SKIP = [[^(?:content-length|transfer-encoding|trailer|expect)[ \t]*:[^\n]*\n]]

-- request_head serializes the request line and headers as HTTP/1.1. For
-- HTTP/1.x it reuses the client's raw header block (exact bytes, cheaper
-- than building a table); HTTP/2 and 3 headers are serialized from the
-- parsed table.
function _M.request_head(length, version)
  sb:reset()
  sb:put(ngx.req.get_method(), " ", ngx.var.request_uri, " HTTP/1.1\r\n")
  if version < 2 then
    local raw = ngx.re.gsub(ngx.req.raw_header(true), RAW_SKIP, "", "jom")
    -- Without the blank line ending the block: framing follows.
    if sub(raw, -4) == "\r\n\r\n" then
      sb:put(sub(raw, 1, -3))
    elseif sub(raw, -2) == "\n\n" then
      sb:put(sub(raw, 1, -2))
    else
      sb:put(raw)
    end
  else
    local host = ngx.var.host
    if host and host ~= "" then
      sb:put("host: ", host, "\r\n")
    end
    header_lines(ngx.req.get_headers(0), "host")
  end
  if length > 0 then
    sb:put("content-length: ", length, "\r\n")
  end
  sb:put("\r\n")
  return sb:tostring()
end

-- response_head serializes the status line and headers; length < 0 means
-- chunked, nil means no body. lower: header names may not be lower case.
function _M.response_head(status, headers, length, lower)
  sb:reset()
  sb:put("HTTP/1.1 ", status, " ", STATUS_TEXT[status] or "Status", "\r\n")
  header_lines(headers, nil, lower)
  if length and length >= 0 then
    sb:put("content-length: ", length, "\r\n")
  elseif length then
    sb:put("transfer-encoding: chunked\r\n")
  end
  sb:put("\r\n")
  return sb:tostring()
end

-- chunk_prefix is the chunk-size line for n bytes of chunked body.
function _M.chunk_prefix(n)
  return fmt("%x\r\n", n)
end

-- verdict sends data on st.conn and reports whether the traffic must be
-- blocked (and the verdict, when there was one). Without prevent it never
-- waits.
function _M.verdict(st, prevent, dir, data)
  local conn, conf = st.conn, st.conf
  if not prevent then
    conn:send(dir, data)
    return false
  end
  local v, err = conn:inspect(dir, data, conf.timeout / 1000)
  if not v then
    kong.log.debug("suritap: no verdict for cid ", fmt("%.0f", conn.cid), " (", st.endpoint, "): ", err)
    return conf.fail_policy == "closed"
  end
  if v.action == transport.DROP then
    return true, v
  end
  if v.action == transport.ERROR then
    return conf.fail_policy == "closed", v
  end
  return false, v
end

-- state returns the per-request state shared by both plugins (in ngx.ctx:
-- cheaper than kong.ctx.shared, which goes through metamethods).
function _M.state()
  return ngx.ctx.suritap_state
end

function _M.set_state(st)
  ngx.ctx.suritap_state = st
end

return _M
