-- suritap Kong plugin: inspects decrypted HTTP traffic with Suricata via
-- the suritap socket transport (see docs/suritap.md §9).
--
-- Each request is normalized to HTTP/1.1 and inspected on its own
-- synthetic flow in the access phase, after Kong buffered the request body.
-- Drop verdicts become 403 responses carrying X-Suritap-Cid (the cid logged
-- in EVE). Responses are ignored, streamed to Suricata without waiting
-- (detect, from the header and body filters) or inspected before they are
-- sent (prevent: done by the companion suritap-response plugin, since Kong
-- does not allow the response phase next to the filter phases).

local transport = require "kong.plugins.suritap.transport"
local common = require "kong.plugins.suritap.common"

local ngx = ngx
local kong = kong
local fmt, sub = string.format, string.sub
local META = transport.META
local TO_SERVER, TO_CLIENT = common.TO_SERVER, common.TO_CLIENT

local SuritapHandler = {
  -- Before authentication plugins (jwt 1450, key-auth 1250, ...): every
  -- request is inspected, also those authentication would reject.
  PRIORITY = 1500,
  VERSION = "0.1.0",
}

local PROTO = { [1.0] = "HTTP/1.0", [1.1] = "HTTP/1.1", [2.0] = "HTTP/2.0", [3.0] = "HTTP/3.0" }

local function request_meta(endpoint, route, version)
  local service = kong.router.get_service()
  local var = ngx.var
  local rid = var.http_x_request_id
  -- Flat tag, value list (one table per request).
  return {
    META.proto, PROTO[version] or fmt("HTTP/%.1f", version),
    META.sni, var.ssl_server_name,
    META.alpn, var.ssl_alpn_protocol,
    META.request_id, rid or var.kong_request_id,
    META.route, route and (route.name or route.id),
    META.service, service and (service.name or service.id),
    META.proxy, "kong",
    META.endpoint, endpoint,
  }
end

-- read_body returns up to max bytes of the (buffered) request body and its
-- full length.
local function read_body(max)
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  if body then
    if #body > max then
      return sub(body, 1, max), #body
    end
    return body, #body
  end
  local file = ngx.req.get_body_file()
  if not file then
    return "", 0
  end
  local fh = io.open(file, "rb")
  if not fh then
    return "", 0
  end
  local total = fh:seek("end")
  fh:seek("set")
  body = fh:read(math.min(total, max)) or ""
  fh:close()
  return body, total
end

function SuritapHandler:access(conf)
  local route = kong.router.get_route()
  local endpoint = conf.endpoint or (route and route.name) or "kong"
  local prevent = conf.mode == "prevent"

  local version = ngx.req.http_version() or 1.1
  local var = ngx.var
  local t = transport.get(conf.socket_dir, conf.name)
  local conn, err = t:open(var.remote_addr, tonumber(var.remote_port),
    var.server_addr, tonumber(var.server_port), request_meta(endpoint, route, version), conf.timeout / 1000)
  if not conn then
    common.log_unavailable(endpoint, err)
    if conf.fail_policy == "closed" and prevent then
      return common.blocked_response(nil, false)
    end
    return
  end
  local st = { conn = conn, conf = conf, endpoint = endpoint }
  common.set_state(st)

  local body, total = read_body(conf.max_request_body)
  local data = common.request_head(total, version)
  if total > 0 then
    data = data .. body
  end
  local blocked, v
  if total > #body then
    -- Inspect what was read; the rest is reported as a gap.
    conn:send(TO_SERVER, data)
    conn:add_gap(TO_SERVER, total - #body)
    blocked, v = common.verdict(st, prevent, TO_SERVER, "")
  else
    blocked, v = common.verdict(st, prevent, TO_SERVER, data)
  end
  if blocked then
    common.log_block(endpoint, conn.cid, "request", v)
    conn:close(false)
    st.conn = nil
    return common.blocked_response(conn.cid, v and v.action == transport.DROP)
  end
  if conf.response == "off" then
    conn:close(false)
    st.conn = nil
  end
end

-- header_filter and body_filter stream the response (detect).
function SuritapHandler:header_filter(conf)
  local st = common.state()
  if not st or not st.conn or conf.response ~= "detect" then
    return
  end
  local status = ngx.status
  local headers = ngx.resp.get_headers(0)
  local length = -1
  if ngx.req.get_method() == "HEAD" or status == 204 or status == 304 then
    length = nil
    st.no_body = true
  else
    local cl = headers["content-length"]
    if cl then
      length = tonumber(cl) or -1
    end
  end
  st.chunked = length == -1
  st.conn:send(TO_CLIENT, common.response_head(status, headers, length))
end

function SuritapHandler:body_filter(conf)
  local st = common.state()
  if not st or not st.conn or conf.response ~= "detect" or st.no_body then
    return
  end
  local data, eof = ngx.arg[1], ngx.arg[2]
  if data and data ~= "" then
    if st.chunked then
      st.conn:send(TO_CLIENT, data, common.chunk_prefix(#data), "\r\n")
    else
      st.conn:send(TO_CLIENT, data)
    end
  end
  if eof and st.chunked and not st.ended then
    st.ended = true
    st.conn:send(TO_CLIENT, "0\r\n\r\n")
  end
end

local warned_companion = false

function SuritapHandler:log(conf)
  local st = common.state()
  if not st or not st.conn then
    return
  end
  if conf.response == "prevent" and not st.response_done and not warned_companion and ngx.status < 500 then
    warned_companion = true
    kong.log.warn("suritap: response: prevent needs the suritap-response plugin on the same route; responses are not inspected")
  end
  st.conn:close(false)
  st.conn = nil
end

return SuritapHandler
