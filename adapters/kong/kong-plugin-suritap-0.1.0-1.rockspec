package = "kong-plugin-suritap"
version = "0.1.0-1"

source = {
  url = "git+https://github.com/jc-lab/suricontroller.git",
  dir = "suricontroller/adapters/kong",
}

description = {
  summary = "Kong plugins that inspect decrypted HTTP traffic with Suricata (suritap socket transport)",
  homepage = "https://github.com/jc-lab/suricontroller",
  license = "MPL-2.0",
}

dependencies = {}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.suritap.handler"] = "kong/plugins/suritap/handler.lua",
    ["kong.plugins.suritap.schema"] = "kong/plugins/suritap/schema.lua",
    ["kong.plugins.suritap.common"] = "kong/plugins/suritap/common.lua",
    ["kong.plugins.suritap.transport"] = "kong/plugins/suritap/transport.lua",
    ["kong.plugins.suritap-response.handler"] = "kong/plugins/suritap-response/handler.lua",
    ["kong.plugins.suritap-response.schema"] = "kong/plugins/suritap-response/schema.lua",
  },
}
