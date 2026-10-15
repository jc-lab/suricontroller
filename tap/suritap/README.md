# suritap

Client library and protocol for **suritap**: TLS-terminating proxies hand
the plaintext of their connections to [Suricata](https://suricata.io/) and
get a verdict (pass / drop, with the matching alerts) for each request.

Suricata runs the suritap capture plugin
(`suricata --capture-plugin=suritap`), which turns what proxies send into
synthetic IPv4/IPv6 TCP packets, so every Suricata feature (stream
reassembly, app-layer parsers, rules, EVE) applies unchanged.

This crate contains:

- the Rust client (`client::Client`): one session per Suricata worker over a
  sealed memfd with two single-producer/single-consumer rings and eventfd
  wake-ups (low latency, no syscall while both sides are busy);
- the wire protocol (`proto`), including the endpoint policy (`policy`)
  the plugin pushes to clients (Off / Detect / Prevent per endpoint);
- the server side used by the plugin (`server`, `engine`), and
  `suritap-mockd`, a stand-alone server with a stub inspector for tests.

Linux only.

```rust,no_run
use std::time::Duration;
use suritap::client::{Client, ClientOptions, OpenParams};
use suritap::proto::{Action, Dir, MetaTag};

let client = Client::connect("/run/suritap", ClientOptions::default())?;
let conn = client.open(
    &OpenParams::new("203.0.113.7:40000".parse()?, "10.0.0.1:443".parse()?)
        .meta(MetaTag::Sni, "api.example.com"),
)?;
let v = conn.inspect(Dir::ToServer, b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n", Duration::from_millis(100))?;
if v.action == Action::Drop {
    // answer 403, close the connection, ...
}
conn.close(false)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Protocol specification, design and benchmarks:
[docs/suritap.md](https://github.com/jc-lab/suricontroller/blob/main/docs/suritap.md).
Other clients: Go (`github.com/jc-lab/suricontroller/pkg/suritap`), the
Traefik plugin ([jc-lab/suritap-traefik](https://github.com/jc-lab/suritap-traefik))
and the Kong plugin (in suricontroller).

## License

MPL-2.0
