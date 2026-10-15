local typedefs = require "kong.db.schema.typedefs"

-- Companion of the suritap plugin for response: prevent (no settings of
-- its own; it uses the suritap plugin's on the same route).
return {
  name = "suritap-response",
  fields = {
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },
    { config = { type = "record", fields = {} } },
  },
}
