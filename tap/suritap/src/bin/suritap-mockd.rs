//! A suritap server without Suricata: drops packets whose payload contains
//! a marker. Used for client interoperability tests, transport benchmarks
//! and to dump the synthesized packets as pcap (`--pcap`), which can then
//! be replayed into stock Suricata.

use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use suritap::client::socket_path;
use suritap::engine::{fix_tcp_checksum, Inspector, Outcome, PacketBuffer, PacketInfo, ACTION_ALERT, ACTION_DROP};
use suritap::pcap::PcapWriter;
use suritap::proto::Reason;
use suritap::server::{Worker, WorkerConfig};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

struct Marker {
    marker: Vec<u8>,
    pcap: Option<Arc<Mutex<PcapWriter<BufWriter<File>>>>>,
}

impl Inspector for Marker {
    fn inspect(&mut self, buf: &mut PacketBuffer, _info: &PacketInfo<'_>) -> Outcome {
        if let Some(p) = &self.pcap {
            let mut pkt = buf.packet().to_vec();
            fix_tcp_checksum(&mut pkt);
            let _ = p.lock().unwrap().write(&pkt);
        }
        let mut o = Outcome::default();
        if !self.marker.is_empty() && buf.packet().windows(self.marker.len()).any(|w| w == self.marker) {
            o.action = ACTION_ALERT | ACTION_DROP;
            o.reason = Reason::Rule as u8;
            o.alert_total = 1;
            o.n_alerts = 1;
            o.alerts[0].sid = 1;
            o.alerts[0].gid = 1;
            o.alerts[0].action = ACTION_ALERT | ACTION_DROP;
        }
        o
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: suritap-mockd --dir DIR [--workers N] [--marker STR] [--pcap FILE] [--spin-us N] [--max-segment N]"
    );
    std::process::exit(2);
}

fn main() {
    let mut dir: Option<PathBuf> = None;
    let mut workers: u16 = 1;
    let mut marker = b"SURITAP-TEST-DROP".to_vec();
    let mut pcap: Option<PathBuf> = None;
    let mut spin = 0u64;
    let mut max_segment = 32 * 1024;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().unwrap_or_else(|| usage());
        match a.as_str() {
            "--dir" => dir = Some(val().into()),
            "--workers" => workers = val().parse().unwrap_or_else(|_| usage()),
            "--marker" => marker = val().into_bytes(),
            "--pcap" => pcap = Some(val().into()),
            "--spin-us" => spin = val().parse().unwrap_or_else(|_| usage()),
            "--max-segment" => max_segment = val().parse().unwrap_or_else(|_| usage()),
            _ => usage(),
        }
    }
    let dir = dir.unwrap_or_else(|| usage());
    std::fs::create_dir_all(&dir).expect("create socket dir");
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
    let pcap = pcap.map(|p| {
        Arc::new(Mutex::new(
            PcapWriter::new(BufWriter::new(File::create(p).expect("pcap"))).unwrap(),
        ))
    });
    let mut handles = Vec::new();
    for i in 0..workers {
        let mut cfg = WorkerConfig::new(socket_path(&dir, i as usize), i, workers);
        cfg.spin = Duration::from_micros(spin);
        cfg.engine.max_segment = max_segment;
        let mut w = Worker::new(cfg).expect("listen");
        let mut insp = Marker {
            marker: marker.clone(),
            pcap: pcap.clone(),
        };
        handles.push(std::thread::spawn(move || {
            while !STOP.load(Ordering::Relaxed) {
                w.run_once(&mut insp, 100);
            }
            w.shutdown();
            let s = &w.engine.stats;
            eprintln!(
                "worker {i}: records={} packets={} verdicts={} drops={} flows={}/{}",
                s.records, s.packets, s.verdicts, s.drops, s.flows_opened, s.flows_closed
            );
        }));
    }
    eprintln!("suritap-mockd: listening in {} with {workers} worker(s)", dir.display());
    for h in handles {
        h.join().unwrap();
    }
    if let Some(p) = pcap {
        p.lock().unwrap().flush().unwrap();
    }
}
