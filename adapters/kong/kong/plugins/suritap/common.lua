-- Helpers shared by the suritap and suritap-response plugins.

local transport = require "kong.plugins.suritap.transport"

local ngx = ngx
local kong = kong
local fmt, concat, sort = string.format, table.concat, table.sort

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
-- request body back waiting for that interim response.
local SKIP = { ["content-length"] = true, ["transfer-encoding"] = true, trailer = true, expect = true }

local function header_lines(b, headers, skip)
  local names = {}
  for k in pairs(headers) do
    local l = k:lower()
    if not SKIP[l] and l ~= skip then
      names[#names + 1] = k
    end
  end
  sort(names)
  for _, k in ipairs(names) do
    local v = headers[k]
    if type(v) == "table" then
      for _, x in ipairs(v) do
        b[#b + 1] = k .. ": " .. x .. "\r\n"
      end
    else
      b[#b + 1] = k .. ": " .. tostring(v) .. "\r\n"
    end
  end
end

-- request_head serializes the request line and headers as HTTP/1.1.
function _M.request_head(length)
  local b = { ngx.req.get_method(), " ", ngx.var.request_uri, " HTTP/1.1\r\n" }
  local host = ngx.var.http_host or ngx.var.host
  if host and host ~= "" then
    b[#b + 1] = "Host: " .. host .. "\r\n"
  end
  header_lines(b, ngx.req.get_headers(0, true), "host")
  if length > 0 then
    b[#b + 1] = "Content-Length: " .. length .. "\r\n"
  end
  b[#b + 1] = "\r\n"
  return concat(b)
end

-- response_head serializes the status line and headers; length < 0 means
-- chunked, nil means no body.
function _M.response_head(status, headers, length)
  local b = { fmt("HTTP/1.1 %d %s\r\n", status, STATUS_TEXT[status] or "Status") }
  header_lines(b, headers, nil)
  if length and length >= 0 then
    b[#b + 1] = "Content-Length: " .. length .. "\r\n"
  elseif length then
    b[#b + 1] = "Transfer-Encoding: chunked\r\n"
  end
  b[#b + 1] = "\r\n"
  return concat(b)
end

function _M.chunk(data)
  if data == "" then
    return ""
  end
  return fmt("%x\r\n", #data) .. data .. "\r\n"
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

-- state returns the per-request state shared by both plugins.
function _M.state()
  return kong.ctx.shared.suritap
end

return _M
