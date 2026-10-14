//! Record and handshake encoding (protocol version 1, little-endian).
//!
//! c2s record bodies:
//!
//! ```text
//! OPEN   cid:u64 family:u8(4|6) hint:u8 rsv:u16 tenant:u32 sport:u16 dport:u16
//!        rsv:u32 src:[16] dst:[16] then TLVs (tag:u8 rsv:u8 len:u16 value)
//! DATA   cid:u64 dir:u8 rsv:[3] token:u32 payload…      flag WANT_VERDICT
//! GAP    cid:u64 dir:u8 rsv:[3] len:u32
//! EOF    cid:u64 dir:u8 rsv:[7]
//! CLOSE  cid:u64 how:u8(0 fin,1 rst) rsv:[7]
//! PING   token:u32 rsv:u32 ts:u64
//! ```
//!
//! s2c record bodies:
//!
//! ```text
//! VERDICT    cid:u64 token:u32 dir:u8 action:u8 reason:u8 n:u8 drop_reason:u8
//!            rsv:[3] alert_total:u16 rsv:u16, then n × (sid gid rev:u32 action:u8 rsv:[3])
//! BYPASS     cid:u64 dir:u8 rsv:[7]
//! PONG       token:u32 rsv:u32 ts:u64
//! FLOW_ERROR cid:u64 code:u32 rsv:u32
//! ```

use std::net::IpAddr;

pub const MAGIC: u32 = 0x5041_5453; // "STAP"
pub const VERSION: u16 = 1;

pub const K_OPEN: u16 = 1;
pub const K_DATA: u16 = 2;
pub const K_GAP: u16 = 3;
pub const K_EOF: u16 = 4;
pub const K_CLOSE: u16 = 5;
pub const K_PING: u16 = 6;
pub const K_VERDICT: u16 = 0x81;
pub const K_BYPASS: u16 = 0x82;
pub const K_PONG: u16 = 0x83;
pub const K_FLOW_ERROR: u16 = 0x84;

/// DATA flag: answer with a VERDICT covering everything sent so far in
/// this direction.
pub const F_WANT_VERDICT: u16 = 1;

pub const OPEN_FIXED: usize = 56;
pub const DATA_FIXED: usize = 16;
pub const SMALL: usize = 16;
pub const VERDICT_FIXED: usize = 24;
pub const ALERT_SIZE: usize = 16;
pub const MAX_ALERTS: usize = 8;
/// Largest VERDICT record including the ring header.
pub const MAX_VERDICT_RECORD: usize = 8 + VERDICT_FIXED + ALERT_SIZE * MAX_ALERTS;
/// Maximum total size of OPEN TLVs.
pub const MAX_META: usize = 2048;

/// FLOW_ERROR codes.
pub const FE_DUPLICATE: u32 = 1;
pub const FE_OVERLOAD: u32 = 2;
pub const FE_INVALID: u32 = 3;

#[inline]
pub fn get_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
pub fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
#[inline]
pub fn get_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
#[inline]
pub fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
pub fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Direction of payload relative to the proxied connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Dir {
    /// Client (downstream) to server (upstream).
    ToServer = 0,
    /// Server (upstream) to client (downstream).
    ToClient = 1,
}

impl Dir {
    pub fn from_u8(v: u8) -> Option<Dir> {
        match v {
            0 => Some(Dir::ToServer),
            1 => Some(Dir::ToClient),
            _ => None,
        }
    }

    pub fn other(self) -> Dir {
        match self {
            Dir::ToServer => Dir::ToClient,
            Dir::ToClient => Dir::ToServer,
        }
    }
}

/// Verdict action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Pass = 0,
    Drop = 1,
    /// No verdict could be computed; apply the endpoint's fail policy.
    Error = 2,
}

/// Why a verdict is not a plain pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    None = 0,
    /// A drop/reject rule matched.
    Rule = 1,
    /// An engine policy dropped the packet (exception policy, memcap,
    /// stream/decoder error).
    Policy = 2,
    /// The flow was already dropped by an earlier verdict.
    Flow = 3,
    /// The connection id is unknown (never opened, or rejected).
    UnknownFlow = 4,
    /// The record was invalid.
    Protocol = 5,
    /// The engine could not process the packet.
    Engine = 6,
}

impl Reason {
    pub fn from_u8(v: u8) -> Reason {
        match v {
            1 => Reason::Rule,
            2 => Reason::Policy,
            3 => Reason::Flow,
            4 => Reason::UnknownFlow,
            5 => Reason::Protocol,
            6 => Reason::Engine,
            _ => Reason::None,
        }
    }
}

/// Optional connection metadata carried by OPEN (and logged in EVE).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MetaTag {
    Sni = 1,
    Alpn = 2,
    Ja4 = 3,
    Route = 4,
    RequestId = 5,
    Endpoint = 6,
    Service = 7,
    User = 8,
    Proto = 9,
    Proxy = 10,
}

impl MetaTag {
    /// EVE field name of a tag, `None` for unknown tags.
    pub fn name(tag: u8) -> Option<&'static str> {
        Some(match tag {
            1 => "sni",
            2 => "alpn",
            3 => "ja4",
            4 => "route",
            5 => "request_id",
            6 => "endpoint",
            7 => "service",
            8 => "user",
            9 => "proto",
            10 => "proxy",
            _ => return None,
        })
    }
}

/// One alert attached to a verdict.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Alert {
    pub sid: u32,
    pub gid: u32,
    pub rev: u32,
    /// Suricata action bits of the matching rule (alert=1, drop=2, reject=4/8/16, pass=32).
    pub action: u8,
}

/// A decoded VERDICT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub cid: u64,
    pub token: u32,
    pub dir: Dir,
    pub action: Action,
    pub reason: Reason,
    /// Raw Suricata `PKT_DROP_REASON_*` value (version specific).
    pub drop_reason: u8,
    /// Total number of alerts, possibly more than `alerts.len()`.
    pub alert_total: u16,
    pub alerts: Vec<Alert>,
}

impl Verdict {
    pub fn is_drop(&self) -> bool {
        self.action == Action::Drop
    }

    pub fn decode(b: &[u8]) -> Option<Verdict> {
        if b.len() < VERDICT_FIXED {
            return None;
        }
        let n = (b[15] as usize).min(MAX_ALERTS);
        if b.len() < VERDICT_FIXED + n * ALERT_SIZE {
            return None;
        }
        let action = match b[13] {
            0 => Action::Pass,
            1 => Action::Drop,
            _ => Action::Error,
        };
        let alerts = (0..n)
            .map(|i| {
                let o = VERDICT_FIXED + i * ALERT_SIZE;
                Alert {
                    sid: get_u32(b, o),
                    gid: get_u32(b, o + 4),
                    rev: get_u32(b, o + 8),
                    action: b[o + 12],
                }
            })
            .collect();
        Some(Verdict {
            cid: get_u64(b, 0),
            token: get_u32(b, 8),
            dir: Dir::from_u8(b[12]).unwrap_or(Dir::ToServer),
            action,
            reason: Reason::from_u8(b[14]),
            drop_reason: b[16],
            alert_total: get_u16(b, 20),
            alerts,
        })
    }
}

/// Encodes a VERDICT body into `out`, returning its length.
#[allow(clippy::too_many_arguments)]
pub fn encode_verdict(
    out: &mut [u8; VERDICT_FIXED + ALERT_SIZE * MAX_ALERTS],
    cid: u64,
    token: u32,
    dir: Dir,
    action: Action,
    reason: Reason,
    drop_reason: u8,
    alert_total: u16,
    alerts: &[Alert],
) -> usize {
    let n = alerts.len().min(MAX_ALERTS);
    out[..VERDICT_FIXED].fill(0);
    put_u64(out, 0, cid);
    put_u32(out, 8, token);
    out[12] = dir as u8;
    out[13] = action as u8;
    out[14] = reason as u8;
    out[15] = n as u8;
    out[16] = drop_reason;
    put_u16(out, 20, alert_total);
    for (i, a) in alerts.iter().take(n).enumerate() {
        let o = VERDICT_FIXED + i * ALERT_SIZE;
        put_u32(out, o, a.sid);
        put_u32(out, o + 4, a.gid);
        put_u32(out, o + 8, a.rev);
        out[o + 12] = a.action;
        out[o + 13..o + 16].fill(0);
    }
    VERDICT_FIXED + n * ALERT_SIZE
}

/// A decoded OPEN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    pub cid: u64,
    pub v6: bool,
    pub hint: u8,
    pub tenant: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub meta: Vec<(u8, Vec<u8>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadRecord(pub &'static str);

impl Open {
    pub fn new(cid: u64, src: IpAddr, sport: u16, dst: IpAddr, dport: u16) -> Result<Open, BadRecord> {
        let (v6, s, d) = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                let mut a = [0u8; 16];
                let mut b = [0u8; 16];
                a[..4].copy_from_slice(&s.octets());
                b[..4].copy_from_slice(&d.octets());
                (false, a, b)
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => (true, s.octets(), d.octets()),
            _ => return Err(BadRecord("address families differ")),
        };
        Ok(Open {
            cid,
            v6,
            hint: 0,
            tenant: 0,
            src: s,
            dst: d,
            sport,
            dport,
            meta: Vec::new(),
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), BadRecord> {
        let start = out.len();
        out.resize(start + OPEN_FIXED, 0);
        let b = &mut out[start..];
        put_u64(b, 0, self.cid);
        b[8] = if self.v6 { 6 } else { 4 };
        b[9] = self.hint;
        put_u32(b, 12, self.tenant);
        put_u16(b, 16, self.sport);
        put_u16(b, 18, self.dport);
        b[24..40].copy_from_slice(&self.src);
        b[40..56].copy_from_slice(&self.dst);
        let mut meta = 0;
        for (tag, v) in &self.meta {
            if v.len() > u16::MAX as usize {
                return Err(BadRecord("metadata value too long"));
            }
            meta += 4 + v.len();
            if meta > MAX_META {
                return Err(BadRecord("metadata too long"));
            }
            out.push(*tag);
            out.push(0);
            out.extend_from_slice(&(v.len() as u16).to_le_bytes());
            out.extend_from_slice(v);
        }
        Ok(())
    }

    pub fn decode(b: &[u8]) -> Result<Open, BadRecord> {
        if b.len() < OPEN_FIXED || b.len() > OPEN_FIXED + MAX_META {
            return Err(BadRecord("bad OPEN length"));
        }
        let v6 = match b[8] {
            4 => false,
            6 => true,
            _ => return Err(BadRecord("bad address family")),
        };
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&b[24..40]);
        dst.copy_from_slice(&b[40..56]);
        let mut meta = Vec::new();
        let mut off = OPEN_FIXED;
        while off < b.len() {
            if off + 4 > b.len() {
                return Err(BadRecord("truncated TLV"));
            }
            let tag = b[off];
            let len = get_u16(b, off + 2) as usize;
            off += 4;
            if off + len > b.len() {
                return Err(BadRecord("truncated TLV"));
            }
            meta.push((tag, b[off..off + len].to_vec()));
            off += len;
        }
        Ok(Open {
            cid: get_u64(b, 0),
            v6,
            hint: b[9],
            tenant: get_u32(b, 12),
            src,
            dst,
            sport: get_u16(b, 16),
            dport: get_u16(b, 18),
            meta,
        })
    }
}

pub fn data_header(cid: u64, dir: Dir, token: u32) -> [u8; DATA_FIXED] {
    let mut b = [0u8; DATA_FIXED];
    put_u64(&mut b, 0, cid);
    b[8] = dir as u8;
    put_u32(&mut b, 12, token);
    b
}

pub fn small(cid: u64, byte: u8, word: u32) -> [u8; SMALL] {
    let mut b = [0u8; SMALL];
    put_u64(&mut b, 0, cid);
    b[8] = byte;
    put_u32(&mut b, 12, word);
    b
}

pub fn ping(token: u32, ts: u64) -> [u8; SMALL] {
    let mut b = [0u8; SMALL];
    put_u32(&mut b, 0, token);
    put_u64(&mut b, 8, ts);
    b
}

pub const HELLO_SIZE: usize = 64;
pub const WELCOME_SIZE: usize = 64;

/// Handshake status codes.
pub const ST_OK: u16 = 0;
pub const ST_BAD_HELLO: u16 = 1;
pub const ST_BAD_REGION: u16 = 2;
pub const ST_TOO_MANY: u16 = 3;
pub const ST_INTERNAL: u16 = 4;

/// First message of a session (client → server, carries the memfd).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub pid: u32,
    pub flags: u32,
    pub name: String,
}

fn put_str(b: &mut [u8], s: &str) {
    let n = s.len().min(b.len());
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
}

fn get_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl Hello {
    pub fn encode(&self) -> [u8; HELLO_SIZE] {
        let mut b = [0u8; HELLO_SIZE];
        put_u32(&mut b, 0, MAGIC);
        put_u16(&mut b, 4, VERSION);
        put_u16(&mut b, 6, HELLO_SIZE as u16);
        put_u32(&mut b, 8, self.pid);
        put_u32(&mut b, 12, self.flags);
        put_str(&mut b[16..48], &self.name);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Hello> {
        if b.len() != HELLO_SIZE || get_u32(b, 0) != MAGIC || get_u16(b, 4) != VERSION {
            return None;
        }
        Some(Hello {
            pid: get_u32(b, 8),
            flags: get_u32(b, 12),
            name: get_str(&b[16..48]),
        })
    }
}

/// Handshake answer (server → client, carries both eventfds on success).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub status: u16,
    pub worker_index: u16,
    pub worker_count: u16,
    pub max_payload: u32,
    pub max_flows: u32,
    pub session_id: u32,
    pub message: String,
}

impl Welcome {
    pub fn encode(&self) -> [u8; WELCOME_SIZE] {
        let mut b = [0u8; WELCOME_SIZE];
        put_u32(&mut b, 0, MAGIC);
        put_u16(&mut b, 4, VERSION);
        put_u16(&mut b, 6, self.status);
        put_u16(&mut b, 8, self.worker_index);
        put_u16(&mut b, 10, self.worker_count);
        put_u32(&mut b, 12, self.max_payload);
        put_u32(&mut b, 16, self.max_flows);
        put_u32(&mut b, 20, self.session_id);
        put_str(&mut b[24..64], &self.message);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Welcome> {
        if b.len() != WELCOME_SIZE || get_u32(b, 0) != MAGIC || get_u16(b, 4) != VERSION {
            return None;
        }
        Some(Welcome {
            status: get_u16(b, 6),
            worker_index: get_u16(b, 8),
            worker_count: get_u16(b, 10),
            max_payload: get_u32(b, 12),
            max_flows: get_u32(b, 16),
            session_id: get_u32(b, 20),
            message: get_str(&b[24..64]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_roundtrip() {
        let mut o = Open::new(7, "10.0.0.1".parse().unwrap(), 1234, "10.0.0.2".parse().unwrap(), 443).unwrap();
        o.meta.push((MetaTag::Sni as u8, b"example.com".to_vec()));
        let mut b = Vec::new();
        o.encode(&mut b).unwrap();
        assert_eq!(Open::decode(&b).unwrap(), o);
        assert!(Open::decode(&b[..b.len() - 1]).is_err());
        assert!(Open::new(1, "::1".parse().unwrap(), 1, "1.2.3.4".parse().unwrap(), 2).is_err());
    }

    #[test]
    fn verdict_roundtrip() {
        let mut buf = [0u8; VERDICT_FIXED + ALERT_SIZE * MAX_ALERTS];
        let alerts = [Alert {
            sid: 1,
            gid: 1,
            rev: 2,
            action: 2,
        }];
        let n = encode_verdict(&mut buf, 9, 3, Dir::ToClient, Action::Drop, Reason::Rule, 8, 1, &alerts);
        let v = Verdict::decode(&buf[..n]).unwrap();
        assert_eq!(v.cid, 9);
        assert_eq!(v.dir, Dir::ToClient);
        assert!(v.is_drop());
        assert_eq!(v.alerts, alerts);
    }

    #[test]
    fn handshake_roundtrip() {
        let h = Hello {
            pid: 5,
            flags: 0,
            name: "kong".into(),
        };
        assert_eq!(Hello::decode(&h.encode()).unwrap(), h);
        let w = Welcome {
            status: 0,
            worker_index: 1,
            worker_count: 4,
            max_payload: 1000,
            max_flows: 10,
            session_id: 3,
            message: "ok".into(),
        };
        assert_eq!(Welcome::decode(&w.encode()).unwrap(), w);
    }
}
