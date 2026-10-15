//! Minimal pcap writer for synthesized packets (LINKTYPE_RAW), used to
//! debug the packet engine or replay a session into stock Suricata.

use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PcapWriter<W: Write> {
    w: W,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W) -> io::Result<Self> {
        let mut h = [0u8; 24];
        h[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        h[4..6].copy_from_slice(&2u16.to_le_bytes());
        h[6..8].copy_from_slice(&4u16.to_le_bytes());
        h[16..20].copy_from_slice(&262_144u32.to_le_bytes());
        h[20..24].copy_from_slice(&101u32.to_le_bytes()); // LINKTYPE_RAW
        w.write_all(&h)?;
        Ok(PcapWriter { w })
    }

    pub fn write(&mut self, pkt: &[u8]) -> io::Result<()> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&(now.as_secs() as u32).to_le_bytes());
        h[4..8].copy_from_slice(&now.subsec_micros().to_le_bytes());
        h[8..12].copy_from_slice(&(pkt.len() as u32).to_le_bytes());
        h[12..16].copy_from_slice(&(pkt.len() as u32).to_le_bytes());
        self.w.write_all(&h)?;
        self.w.write_all(pkt)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}
