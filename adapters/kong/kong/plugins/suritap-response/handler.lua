-- suritap-response: inspects buffered responses for the suritap plugin
-- when its response setting is "prevent". Kong runs the response phase
-- (yieldable, after the whole upstream response was buffered) only for
-- plugins without header/body filters, hence the separate plugin.

local transport = require "kong.plugins.suritap.transport"
local common = require "kong.plugins.suritap.common"

local ngx = ngx
local kong = kong
local sub = string.sub
local TO_CLIENT = common.TO_CLIENT

local SuritapResponseHandler = {
  PRIORITY = 1499,
  VERSION = "0.1.0",
}

function SuritapResponseHandler:response()
  local st = common.state()
  if not st or not st.conn or st.conf.response ~= "prevent" then
    return
  end
  st.response_done = true
  local conf = st.conf
  local status = kong.service.response.get_status()
  local headers = kong.service.response.get_headers()
  local body = kong.service.response.get_raw_body() or ""
  local data, rest
  if ngx.req.get_method() == "HEAD" or status == 204 or status == 304 then
    data, rest = common.response_head(status, headers, nil), 0
  else
    local length = #body
    rest = 0
    if length > conf.max_response_body then
      rest = length - conf.max_response_body
      body = sub(body, 1, conf.max_response_body)
    end
    data = common.response_head(status, headers, length) .. body
  end
  local blocked, v
  if rest > 0 then
    -- Inspect the first max_response_body bytes; the rest is a gap.
    st.conn:send(TO_CLIENT, data)
    st.conn.gaps[TO_CLIENT] = st.conn.gaps[TO_CLIENT] + rest
    blocked, v = common.verdict(st, true, TO_CLIENT, "")
  else
    blocked, v = common.verdict(st, true, TO_CLIENT, data)
  end
  if blocked then
    common.log_block(st.endpoint, st.conn.cid, "response", v)
    -- Drop the upstream headers (Set-Cookie, ...) Kong already applied.
    for k in pairs(ngx.resp.get_headers(0, true)) do
      kong.response.clear_header(k)
    end
    return common.blocked_response(st.conn.cid, v and v.action == transport.DROP)
  end
end

return SuritapResponseHandler
