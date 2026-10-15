//! Minimal client: `cargo run --example smoke -- /run/suritap`.

use std::time::Duration;

use suritap::{Client, ClientOptions, Dir, MetaTag, OpenParams};

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "/run/suritap".into());
    let client = Client::connect(
        &dir,
        ClientOptions {
            name: "smoke".into(),
            ..Default::default()
        },
    )?;
    println!("workers: {}", client.worker_count());
    let t = Duration::from_secs(2);
    for (src, dst) in [
        ("203.0.113.7:50000", "10.0.0.10:443"),
        ("[2001:db8:9::7]:50001", "[2001:db8:1::10]:443"),
    ] {
        let p = OpenParams::new(src.parse().unwrap(), dst.parse().unwrap()).meta(MetaTag::Sni, "smoke.example");
        let conn = client.open(&p)?;
        let ok = conn.inspect(Dir::ToServer, b"GET / HTTP/1.1\r\nHost: smoke.example\r\n\r\n", t)?;
        println!("{src} benign -> {:?}", ok);
        conn.inspect(Dir::ToClient, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", t)?;
        let bad = conn.inspect(
            Dir::ToServer,
            b"GET /../../etc/passwd HTTP/1.1\r\nHost: smoke.example\r\n\r\n",
            t,
        )?;
        println!("{src} attack -> {:?}", bad);
        conn.close(false)?;
    }
    println!("ping: {:?}", client.ping(0, t)?);
    Ok(())
}
