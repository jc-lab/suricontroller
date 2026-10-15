local typedefs = require "kong.db.schema.typedefs"

return {
  name = "suritap",
  fields = {
    { protocols = typedefs.protocols_http },
    { consumer = typedefs.no_consumer },
    {
      config = {
        type = "record",
        fields = {
          { socket_dir = { description = "Directory of the Suricata suritap worker sockets (worker-N.stream.sock).", type = "string", default = "/run/suritap" } },
          { mode = { description = "prevent: block on drop verdicts; detect: never wait for verdicts.", type = "string", default = "prevent", one_of = { "prevent", "detect" } } },
          { response = { description = "Response inspection: off, detect (stream without waiting) or prevent (buffer and inspect before sending).", type = "string", default = "detect", one_of = { "off", "detect", "prevent" } } },
          { fail_policy = { description = "Without a verdict (Suricata down, timeout, error verdict): open (pass) or closed (503).", type = "string", default = "open", one_of = { "open", "closed" } } },
          { timeout = { description = "Verdict timeout in milliseconds.", type = "number", default = 100, gt = 0 } },
          { max_request_body = { description = "Request body bytes inspected; the rest is reported to Suricata as a gap.", type = "integer", default = 1048576, gt = 0 } },
          { max_response_body = { description = "Response body bytes inspected in prevent mode; the rest is reported as a gap.", type = "integer", default = 1048576, gt = 0 } },
          { name = { description = "Client name reported to Suricata.", type = "string", default = "kong" } },
          { endpoint = { description = "Endpoint name logged in EVE (default: the route name).", type = "string" } },
        },
      },
    },
  },
}
