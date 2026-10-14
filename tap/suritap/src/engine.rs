//! Turns session records into synthetic TCP/IP packets, runs them through
//! an [`Inspector`] and produces verdicts.
//!
//! Every OPEN becomes a TCP flow (3-way handshake) between the real client
//! address and the proxy listener, IPv4 or IPv6. DATA becomes PSH|ACK
//! segments of at most `max_segment` bytes whose ACK field acknowledges
//! everything the other side sent; a pure ACK is added when one direction
//! has more than `ack_threshold` unacknowledged bytes (keeps the engine's
//! reassembly memory and window checks in bounds). EOF/CLOSE become
//! FIN/RST, GAP a sequence jump acknowledged by the peer.
//!
//! The engine assumes the inspector runs inline (Suricata `stream.inline`),
//! so data is inspected as soon as its packet is processed and the outcome
//! of each packet is known synchronously. Outcomes are accumulated per flow
//! and direction until a DATA record asks for a verdict.
//!
//! One packet buffer per worker is reused for every packet; payload is
//! copied once from the shared ring into it.
//!
//! Two details keep the engine's flow table honest:
//!
//! * Discriminator: every connection gets two VLAN ids derived from its
//!   session and connection id. They are part of Suricata's flow key, so a
//!   new connection never lands in a stale flow of an earlier connection
//!   with the same addresses and ports (dropped or bypassed flows never see
//!   their FIN/RST and linger until they time out; reusing one would
//!   silently skip inspection or drop the new connection).
//! * Keepalive: a pure ACK is injected for connections idle longer than
//!   `keepalive`, so long-lived idle connections (pooled database clients,
//!   websockets) are not timed out by the engine and picked up mid-stream.

use std::alloc::{alloc, dealloc, Layout};
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::proto::{self, Action, Alert, Dir, MetaTag, Open, Reason, MAX_ALERTS};
use crate::ring::{Producer, Record, HEADER};
use crate::sys;

/// Bytes reserved in front of each packet for the inspector.
pub const HEADROOM: usize = 256;
const IPV4_HDR: usize = 20;
const IPV6_HDR: usize = 40;
const TCP_HDR: usize = 20;
const SYN_OPTS: [u8; 8] = [2, 4, 0xff, 0xd7, 1, 3, 3, 14]; // MSS 65495, NOP, WS 14
/// Largest header stack the engine writes.
pub const MAX_HEADERS: usize = IPV6_HDR + TCP_HDR + SYN_OPTS.len();
/// Largest TCP payload of one segment (IPv4 total length limit).
pub const MAX_SEGMENT_LIMIT: usize = 65535 - IPV4_HDR - TCP_HDR;

pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_PSH: u8 = 0x08;
pub const TH_ACK: u8 = 0x10;

/// Suricata action bits (`action-globals.h`).
pub const ACTION_ALERT: u8 = 0x01;
pub const ACTION_DROP: u8 = 0x02;
pub const ACTION_REJECT_ANY: u8 = 0x04 | 0x08 | 0x10;
pub const ACTION_PASS: u8 = 0x20;

/// A reusable packet buffer: [`HEADROOM`] bytes followed by the packet.
/// The headroom is 64-byte aligned.
pub struct PacketBuffer {
    ptr: NonNull<u8>,
    cap: usize,
    len: usize,
}

unsafe impl Send for PacketBuffer {}

impl PacketBuffer {
    pub fn new(max_packet: usize) -> Self {
        let cap = HEADROOM + max_packet;
        let ptr = unsafe { alloc(Self::layout(cap)) };
        PacketBuffer {
            ptr: NonNull::new(ptr).expect("out of memory"),
            cap,
            len: 0,
        }
    }

    fn layout(cap: usize) -> Layout {
        Layout::from_size_align(cap, 64).unwrap()
    }

    /// The packet bytes (IP header first).
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(HEADROOM), self.len) }
    }

    pub fn packet_ptr(&self) -> *const u8 {
        unsafe { self.ptr.as_ptr().add(HEADROOM) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Start of the headroom (64-byte aligned).
    pub fn headroom(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Gives the allocation away (it is still referenced elsewhere) and
    /// replaces it with a fresh one. Free the result with
    /// [`PacketBuffer::free_detached`].
    pub fn detach(&mut self) -> (*mut u8, usize) {
        let old = (self.ptr.as_ptr(), self.cap);
        let ptr = unsafe { alloc(Self::layout(self.cap)) };
        self.ptr = NonNull::new(ptr).expect("out of memory");
        self.len = 0;
        old
    }

    /// # Safety
    /// `ptr`/`cap` must come from [`PacketBuffer::detach`] and be freed once.
    pub unsafe fn free_detached(ptr: *mut u8, cap: usize) {
        dealloc(ptr, Self::layout(cap));
    }

    fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr().add(HEADROOM), self.cap - HEADROOM) }
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr.as_ptr(), Self::layout(self.cap)) };
    }
}

/// Immutable per-connection metadata (shared with the inspector, e.g. for
/// EVE enrichment).
#[derive(Debug)]
pub struct FlowMeta {
    pub cid: u64,
    pub session: u32,
    pub client: Arc<str>,
    pub hint: u8,
    pub tags: Vec<(u8, Box<[u8]>)>,
}

/// What the inspector learns about a packet before processing it.
pub struct PacketInfo<'a> {
    pub session: u32,
    pub cid: u64,
    pub dir: Dir,
    pub tcp_flags: u8,
    pub payload_len: usize,
    pub tenant: u32,
    /// Set on the first packet of a flow.
    pub new_flow: bool,
    /// Connection discriminator to put in the packet's VLAN ids
    /// (`[0, 0]` when disabled).
    pub vlan: [u16; 2],
    pub meta: &'a Arc<FlowMeta>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct AlertInfo {
    pub sid: u32,
    pub gid: u32,
    pub rev: u32,
    pub action: u8,
    pub _pad: [u8; 3],
}

/// Result of inspecting one packet.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Outcome {
    /// Suricata action bits applied to the packet.
    pub action: u8,
    /// Raw `PKT_DROP_REASON_*`.
    pub drop_reason: u8,
    /// [`Reason`] category of a drop.
    pub reason: u8,
    /// Number of valid entries in `alerts`.
    pub n_alerts: u8,
    /// Number of alerts on the packet (may exceed `n_alerts`).
    pub alert_total: u16,
    /// The engine asked to bypass the rest of the flow.
    pub bypass: u8,
    /// The packet could not be processed.
    pub failed: u8,
    pub alerts: [AlertInfo; MAX_ALERTS],
}

impl Outcome {
    pub fn failed() -> Outcome {
        Outcome {
            failed: 1,
            ..Default::default()
        }
    }

    pub fn dropped(&self) -> bool {
        self.action & (ACTION_DROP | ACTION_REJECT_ANY) != 0
    }
}

/// The packet engine (Suricata in the plugin).
pub trait Inspector {
    /// Processes one packet stored in `buf` and reports what happened.
    /// Implementations may [`detach`](PacketBuffer::detach) the buffer if it
    /// is still in use when they return.
    fn inspect(&mut self, buf: &mut PacketBuffer, info: &PacketInfo<'_>) -> Outcome;
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Largest TCP payload per synthetic packet.
    pub max_segment: usize,
    /// Unacknowledged bytes per direction before a pure ACK is injected.
    /// Keep it well below 3 x the engine's body minimal inspect size, or
    /// HTTP body inspection stalls on large uploads/downloads.
    pub ack_threshold: u64,
    /// Maximum concurrent flows per session.
    pub max_flows: usize,
    /// Maximum concurrent flows of all sessions of this engine (worker).
    pub max_total_flows: usize,
    /// Tag packets with a per-connection VLAN discriminator.
    pub discriminator: bool,
    /// Inject a pure ACK into connections idle this long (zero disables).
    /// Must be below the engine's TCP established timeout.
    pub keepalive: Duration,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            max_segment: 32 * 1024,
            // Suricata stops inspecting HTTP bodies whose uninspected part
            // exceeds 3 x request/response-body-minimal-inspect-size
            // (96 KiB by default) when the data is not acknowledged.
            ack_threshold: 32 * 1024,
            max_flows: 65536,
            max_total_flows: 262_144,
            discriminator: true,
            keepalive: Duration::from_secs(120),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub records: u64,
    pub packets: u64,
    pub bytes: u64,
    pub verdicts: u64,
    pub drops: u64,
    pub flows_opened: u64,
    pub flows_closed: u64,
    pub flow_errors: u64,
    pub engine_failures: u64,
    pub bypasses: u64,
    pub keepalives: u64,
}

/// A fatal session error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The client sent an invalid record.
    Protocol(&'static str),
    /// The s2c ring had no room for a verdict (client ignored its credits).
    Overflow,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Overflow => write!(f, "verdict ring overflow"),
        }
    }
}

/// s2c side of a session.
pub enum Out<'a> {
    /// Shared-memory ring and the client's eventfd (-1 for none).
    Ring { ring: &'a mut Producer, bell: RawFd },
    /// Socket transport: framed records appended to an output buffer of at
    /// most `limit` bytes.
    Buffer { buf: &'a mut Vec<u8>, limit: usize },
}

impl Out<'_> {
    /// Sends a record the client did not reserve a credit for (BYPASS,
    /// FLOW_ERROR). It is dropped unless half of the ring (or buffer) — the
    /// part the client's verdict credits may use — stays free, so
    /// uncredited records can never make a credited VERDICT overflow.
    fn send_uncredited(&mut self, kind: u16, parts: &[&[u8]]) -> bool {
        let body: usize = parts.iter().map(|p| p.len()).sum();
        let room = match self {
            Out::Ring { ring, .. } => ring.available() >= ring.need(body) + ring.capacity() / 2,
            Out::Buffer { buf, limit } => buf.len() + HEADER + body <= *limit / 2,
        };
        room && self.send(kind, parts)
    }

    fn send(&mut self, kind: u16, parts: &[&[u8]]) -> bool {
        match self {
            Out::Ring { ring, bell } => {
                if !ring.push(kind, 0, parts) {
                    return false;
                }
                if ring.publish() {
                    sys::eventfd_signal(*bell);
                }
                true
            }
            Out::Buffer { buf, limit } => {
                let len = HEADER + parts.iter().map(|p| p.len()).sum::<usize>();
                if buf.len() + len > *limit {
                    return false;
                }
                buf.extend_from_slice(&(len as u32).to_le_bytes());
                buf.extend_from_slice(&kind.to_le_bytes());
                buf.extend_from_slice(&0u16.to_le_bytes());
                for p in parts {
                    buf.extend_from_slice(p);
                }
                true
            }
        }
    }
}

#[derive(Default)]
struct Pending {
    action: u8,
    drop_reason: u8,
    reason: u8,
    failed: bool,
    alerts: Option<Box<AlertAcc>>,
}

struct AlertAcc {
    total: u16,
    n: u8,
    items: [AlertInfo; MAX_ALERTS],
}

impl Pending {
    fn add(&mut self, o: &Outcome) {
        if o.failed != 0 {
            self.failed = true;
            return;
        }
        if o.dropped() && self.reason == 0 {
            self.drop_reason = o.drop_reason;
            self.reason = if o.reason == 0 { Reason::Policy as u8 } else { o.reason };
        }
        self.action |= o.action;
        if o.alert_total > 0 {
            let acc = self.alerts.get_or_insert_with(|| {
                Box::new(AlertAcc {
                    total: 0,
                    n: 0,
                    items: [AlertInfo::default(); MAX_ALERTS],
                })
            });
            acc.total = acc.total.saturating_add(o.alert_total);
            for a in &o.alerts[..o.n_alerts as usize] {
                if (acc.n as usize) < MAX_ALERTS && !acc.items[..acc.n as usize].iter().any(|x| x.sid == a.sid) {
                    acc.items[acc.n as usize] = *a;
                    acc.n += 1;
                }
            }
        }
    }
}

struct Flow {
    v6: bool,
    bypassed: bool,
    /// A packet of the flow was dropped: every later verdict is a drop.
    dropped: bool,
    dropped_reason: u8,
    fin: [bool; 2],
    ip_id: u16,
    sport: u16,
    dport: u16,
    tenant: u32,
    vlan: [u16; 2],
    /// Engine clock (ms) of the last packet.
    last: u64,
    isn: [u32; 2],
    sent: [u64; 2],
    acked: [u64; 2],
    src: [u8; 16],
    dst: [u8; 16],
    pending: [Pending; 2],
    meta: Arc<FlowMeta>,
}

impl Flow {
    /// Next sequence number of direction `d` (FIN counted).
    fn next_seq(&self, d: usize) -> u32 {
        self.isn[d]
            .wrapping_add(1)
            .wrapping_add(self.sent[d] as u32)
            .wrapping_add(self.fin[d] as u32)
    }
}

/// Flows of one session.
pub struct Flows {
    map: HashMap<u64, Flow>,
    session: u32,
    client: Arc<str>,
}

impl Flows {
    pub fn new(session: u32, client: &str) -> Self {
        Flows {
            map: HashMap::new(),
            session,
            client: client.into(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Per-worker packet engine.
pub struct Engine {
    cfg: EngineConfig,
    buf: PacketBuffer,
    rng: u64,
    epoch: Instant,
    /// Engine clock (ms since `epoch`), refreshed by [`Engine::tick`].
    now: u64,
    total_flows: usize,
    pub stats: EngineStats,
}

/// splitmix64 finalizer.
fn mix(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Two VLAN ids (1..=4094 each, ~24 bits) identifying a connection.
pub fn discriminator(session: u32, cid: u64) -> [u16; 2] {
    let h = mix(cid ^ ((session as u64) << 40) ^ 0x5354_4150);
    [1 + (h % 4094) as u16, 1 + ((h >> 32) % 4094) as u16]
}

impl Engine {
    pub fn new(mut cfg: EngineConfig, seed: u64) -> Self {
        cfg.max_segment = cfg.max_segment.clamp(512, MAX_SEGMENT_LIMIT);
        let buf = PacketBuffer::new(MAX_HEADERS + cfg.max_segment);
        Engine {
            cfg,
            buf,
            rng: seed | 1,
            epoch: Instant::now(),
            now: 0,
            total_flows: 0,
            stats: EngineStats::default(),
        }
    }

    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    /// Refreshes the engine clock; call once per processing pass rather
    /// than reading the clock per packet.
    pub fn tick(&mut self) {
        self.now = self.epoch.elapsed().as_millis() as u64;
    }

    /// Flows of all sessions.
    pub fn total_flows(&self) -> usize {
        self.total_flows
    }

    fn random(&mut self) -> u32 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    /// Handles one c2s record.
    pub fn handle<I: Inspector>(
        &mut self,
        insp: &mut I,
        flows: &mut Flows,
        out: &mut Out<'_>,
        rec: &Record,
    ) -> Result<(), Error> {
        self.stats.records += 1;
        match rec.kind {
            proto::K_OPEN => self.open(insp, flows, out, rec),
            proto::K_DATA => self.data(insp, flows, out, rec),
            proto::K_GAP | proto::K_EOF | proto::K_CLOSE => self.control(insp, flows, out, rec),
            proto::K_PING => {
                let b: [u8; proto::SMALL] = rec.prefix().ok_or(Error::Protocol("short PING"))?;
                if out.send(proto::K_PONG, &[&b]) {
                    Ok(())
                } else {
                    Err(Error::Overflow)
                }
            }
            _ => Err(Error::Protocol("unknown record kind")),
        }
    }

    fn flow_error(&mut self, out: &mut Out<'_>, cid: u64, code: u32) {
        self.stats.flow_errors += 1;
        // Best effort: the client learns about it on its next verdict anyway.
        let _ = out.send_uncredited(proto::K_FLOW_ERROR, &[&proto::small(cid, 0, code)]);
    }

    fn open<I: Inspector>(
        &mut self,
        insp: &mut I,
        flows: &mut Flows,
        out: &mut Out<'_>,
        rec: &Record,
    ) -> Result<(), Error> {
        if rec.len() < proto::OPEN_FIXED || rec.len() > proto::OPEN_FIXED + proto::MAX_META {
            return Err(Error::Protocol("bad OPEN length"));
        }
        let mut body = [0u8; proto::OPEN_FIXED + proto::MAX_META];
        rec.copy_to(0, &mut body[..rec.len()]);
        let open = match Open::decode(&body[..rec.len()]) {
            Ok(o) => o,
            Err(_) => {
                self.flow_error(out, proto::get_u64(&body, 0), proto::FE_INVALID);
                return Ok(());
            }
        };
        if flows.map.contains_key(&open.cid) {
            self.flow_error(out, open.cid, proto::FE_DUPLICATE);
            return Ok(());
        }
        if flows.map.len() >= self.cfg.max_flows || self.total_flows >= self.cfg.max_total_flows {
            self.flow_error(out, open.cid, proto::FE_OVERLOAD);
            return Ok(());
        }
        let meta = Arc::new(FlowMeta {
            cid: open.cid,
            session: flows.session,
            client: flows.client.clone(),
            hint: open.hint,
            tags: known_tags(open.meta),
        });
        let mut f = Flow {
            v6: open.v6,
            bypassed: false,
            dropped: false,
            dropped_reason: 0,
            fin: [false; 2],
            ip_id: self.random() as u16,
            sport: open.sport,
            dport: open.dport,
            tenant: open.tenant,
            vlan: if self.cfg.discriminator {
                discriminator(flows.session, open.cid)
            } else {
                [0, 0]
            },
            last: 0,
            isn: [self.random(), self.random()],
            sent: [0; 2],
            acked: [0; 2],
            src: open.src,
            dst: open.dst,
            pending: Default::default(),
            meta,
        };
        let cid = open.cid;
        let session = flows.session;
        self.emit(
            insp,
            Some(&mut *out),
            session,
            cid,
            &mut f,
            Dir::ToServer,
            TH_SYN,
            None,
            true,
        );
        self.emit(
            insp,
            Some(&mut *out),
            session,
            cid,
            &mut f,
            Dir::ToClient,
            TH_SYN | TH_ACK,
            None,
            false,
        );
        self.emit(
            insp,
            Some(&mut *out),
            session,
            cid,
            &mut f,
            Dir::ToServer,
            TH_ACK,
            None,
            false,
        );
        flows.map.insert(cid, f);
        self.total_flows += 1;
        self.stats.flows_opened += 1;
        Ok(())
    }

    fn data<I: Inspector>(
        &mut self,
        insp: &mut I,
        flows: &mut Flows,
        out: &mut Out<'_>,
        rec: &Record,
    ) -> Result<(), Error> {
        let h: [u8; proto::DATA_FIXED] = rec.prefix().ok_or(Error::Protocol("short DATA"))?;
        let cid = proto::get_u64(&h, 0);
        let dir = Dir::from_u8(h[8]).ok_or(Error::Protocol("bad direction"))?;
        let token = proto::get_u32(&h, 12);
        let want = rec.flags & proto::F_WANT_VERDICT != 0;
        let session = flows.session;
        let Some(f) = flows.map.get_mut(&cid) else {
            if want {
                return self.error_verdict(out, cid, token, dir, Reason::UnknownFlow);
            }
            return Ok(());
        };
        let d = dir as usize;
        if f.fin[d] {
            if want {
                return self.error_verdict(out, cid, token, dir, Reason::Protocol);
            }
            return Ok(());
        }
        let len = rec.len() - proto::DATA_FIXED;
        let mut off = 0;
        while off < len {
            let seg = (len - off).min(self.cfg.max_segment);
            let src = unsafe { rec.body_ptr(proto::DATA_FIXED + off) };
            self.emit(
                insp,
                Some(&mut *out),
                session,
                cid,
                f,
                dir,
                TH_ACK | TH_PSH,
                Some((src, seg)),
                false,
            );
            f.sent[d] += seg as u64;
            off += seg;
        }
        if f.sent[d] - f.acked[d] >= self.cfg.ack_threshold {
            self.emit(insp, Some(&mut *out), session, cid, f, dir.other(), TH_ACK, None, false);
        }
        if want {
            let mut p = std::mem::take(&mut f.pending[d]);
            if f.dropped && p.action & (ACTION_DROP | ACTION_REJECT_ANY) == 0 {
                // Dropped earlier (any direction), possibly reported
                // already: the flow stays dropped even when this request
                // produced no packet.
                p.action |= ACTION_DROP;
                p.reason = Reason::Flow as u8;
                p.drop_reason = f.dropped_reason;
            }
            return self.verdict(out, cid, token, dir, p);
        }
        Ok(())
    }

    fn control<I: Inspector>(
        &mut self,
        insp: &mut I,
        flows: &mut Flows,
        out: &mut Out<'_>,
        rec: &Record,
    ) -> Result<(), Error> {
        let b: [u8; proto::SMALL] = rec.prefix().ok_or(Error::Protocol("short record"))?;
        let cid = proto::get_u64(&b, 0);
        let session = flows.session;
        let Some(f) = flows.map.get_mut(&cid) else {
            return Ok(());
        };
        match rec.kind {
            proto::K_GAP => {
                let dir = Dir::from_u8(b[8]).ok_or(Error::Protocol("bad direction"))?;
                let d = dir as usize;
                if !f.fin[d] {
                    f.sent[d] += proto::get_u32(&b, 12) as u64;
                    // The peer acknowledging unseen data makes the engine
                    // register a gap instead of waiting for it.
                    self.emit(insp, Some(&mut *out), session, cid, f, dir.other(), TH_ACK, None, false);
                }
            }
            proto::K_EOF => {
                let dir = Dir::from_u8(b[8]).ok_or(Error::Protocol("bad direction"))?;
                self.fin(insp, Some(&mut *out), session, cid, f, dir);
            }
            _ => {
                let mut f = flows.map.remove(&cid).unwrap();
                if b[8] == 1 {
                    self.emit(
                        insp,
                        Some(&mut *out),
                        session,
                        cid,
                        &mut f,
                        Dir::ToServer,
                        TH_RST | TH_ACK,
                        None,
                        false,
                    );
                } else {
                    self.fin(insp, Some(&mut *out), session, cid, &mut f, Dir::ToServer);
                    self.fin(insp, Some(&mut *out), session, cid, &mut f, Dir::ToClient);
                }
                self.total_flows -= 1;
                self.stats.flows_closed += 1;
            }
        }
        Ok(())
    }

    fn fin<I: Inspector>(
        &mut self,
        insp: &mut I,
        mut out: Option<&mut Out<'_>>,
        session: u32,
        cid: u64,
        f: &mut Flow,
        dir: Dir,
    ) {
        if f.fin[dir as usize] {
            return;
        }
        self.emit(
            insp,
            out.as_deref_mut(),
            session,
            cid,
            f,
            dir,
            TH_FIN | TH_ACK,
            None,
            false,
        );
        f.fin[dir as usize] = true;
        self.emit(insp, out, session, cid, f, dir.other(), TH_ACK, None, false);
    }

    /// Interval at which [`Engine::housekeep`] should run (`None` when
    /// keepalives are disabled).
    pub fn housekeep_interval(&self) -> Option<Duration> {
        (!self.cfg.keepalive.is_zero()).then(|| (self.cfg.keepalive / 4).max(Duration::from_millis(250)))
    }

    /// Injects keepalive ACKs into the idle connections of a session.
    /// Scans every flow: call it every [`Engine::housekeep_interval`].
    pub fn housekeep<I: Inspector>(&mut self, insp: &mut I, flows: &mut Flows) {
        let ka = self.cfg.keepalive.as_millis() as u64;
        if ka == 0 {
            return;
        }
        self.tick();
        let now = self.now;
        let session = flows.session;
        for (cid, f) in flows.map.iter_mut() {
            if now.saturating_sub(f.last) >= ka && !(f.fin[0] && f.fin[1]) {
                self.emit(insp, None, session, *cid, f, Dir::ToServer, TH_ACK, None, false);
                self.stats.keepalives += 1;
            }
        }
    }

    /// Resets every flow of a session that went away.
    pub fn close_all<I: Inspector>(&mut self, insp: &mut I, flows: &mut Flows) {
        let session = flows.session;
        for (cid, mut f) in flows.map.drain() {
            self.emit(
                insp,
                None,
                session,
                cid,
                &mut f,
                Dir::ToServer,
                TH_RST | TH_ACK,
                None,
                false,
            );
            self.total_flows -= 1;
            self.stats.flows_closed += 1;
        }
    }

    fn verdict(&mut self, out: &mut Out<'_>, cid: u64, token: u32, dir: Dir, p: Pending) -> Result<(), Error> {
        let mut alerts = [Alert::default(); MAX_ALERTS];
        let (mut n, mut total) = (0, 0);
        if let Some(acc) = &p.alerts {
            n = acc.n as usize;
            total = acc.total;
            for (dst, a) in alerts.iter_mut().zip(&acc.items[..n]) {
                *dst = Alert {
                    sid: a.sid,
                    gid: a.gid,
                    rev: a.rev,
                    action: a.action,
                };
            }
        }
        let (action, reason) = if p.action & (ACTION_DROP | ACTION_REJECT_ANY) != 0 {
            (Action::Drop, Reason::from_u8(p.reason))
        } else if p.failed {
            (Action::Error, Reason::Engine)
        } else {
            (Action::Pass, Reason::None)
        };
        if action == Action::Drop {
            self.stats.drops += 1;
        }
        self.stats.verdicts += 1;
        let mut buf = [0u8; proto::VERDICT_FIXED + proto::ALERT_SIZE * MAX_ALERTS];
        let len = proto::encode_verdict(
            &mut buf,
            cid,
            token,
            dir,
            action,
            reason,
            p.drop_reason,
            total,
            &alerts[..n],
        );
        if out.send(proto::K_VERDICT, &[&buf[..len]]) {
            Ok(())
        } else {
            Err(Error::Overflow)
        }
    }

    fn error_verdict(
        &mut self,
        out: &mut Out<'_>,
        cid: u64,
        token: u32,
        dir: Dir,
        reason: Reason,
    ) -> Result<(), Error> {
        self.stats.verdicts += 1;
        let mut buf = [0u8; proto::VERDICT_FIXED + proto::ALERT_SIZE * MAX_ALERTS];
        let len = proto::encode_verdict(&mut buf, cid, token, dir, Action::Error, reason, 0, 0, &[]);
        if out.send(proto::K_VERDICT, &[&buf[..len]]) {
            Ok(())
        } else {
            Err(Error::Overflow)
        }
    }

    /// Builds one packet of flow `f` travelling in `dir`, inspects it and
    /// folds the outcome into the flow.
    #[allow(clippy::too_many_arguments)]
    fn emit<I: Inspector>(
        &mut self,
        insp: &mut I,
        out: Option<&mut Out<'_>>,
        session: u32,
        cid: u64,
        f: &mut Flow,
        dir: Dir,
        flags: u8,
        payload: Option<(*const u8, usize)>,
        new_flow: bool,
    ) {
        let d = dir as usize;
        let o = 1 - d;
        let seq = if flags & TH_SYN != 0 { f.isn[d] } else { f.next_seq(d) };
        let ack = if flags & TH_ACK != 0 { f.next_seq(o) } else { 0 };
        let plen = payload.map_or(0, |p| p.1);
        f.ip_id = f.ip_id.wrapping_add(1);
        let hdr = write_headers(self.buf.data_mut(), f, dir, flags, seq, ack, plen);
        if let Some((src, n)) = payload {
            // Single copy from the shared ring into the packet buffer.
            unsafe { ptr::copy_nonoverlapping(src, self.buf.data_mut().as_mut_ptr().add(hdr), n) };
        }
        self.buf.len = hdr + plen;
        if flags & TH_ACK != 0 {
            f.acked[o] = f.sent[o];
        }
        f.last = self.now;
        let info = PacketInfo {
            session,
            cid,
            dir,
            tcp_flags: flags,
            payload_len: plen,
            tenant: f.tenant,
            new_flow,
            vlan: f.vlan,
            meta: &f.meta,
        };
        let outcome = insp.inspect(&mut self.buf, &info);
        self.stats.packets += 1;
        self.stats.bytes += plen as u64;
        if outcome.failed != 0 {
            self.stats.engine_failures += 1;
        }
        f.pending[d].add(&outcome);
        if outcome.dropped() && !f.dropped {
            f.dropped = true;
            f.dropped_reason = outcome.drop_reason;
        }
        if outcome.bypass != 0 && !f.bypassed {
            f.bypassed = true;
            self.stats.bypasses += 1;
            if let Some(out) = out {
                // Best effort: only an optimisation for the client.
                let _ = out.send_uncredited(proto::K_BYPASS, &[&proto::small(cid, 2, 0)]);
            }
        }
    }
}

/// Keeps the first value of each known tag (unknown tags are dropped, so
/// EVE never gets duplicate or unnamed keys).
fn known_tags(meta: Vec<(u8, Vec<u8>)>) -> Vec<(u8, Box<[u8]>)> {
    let mut out: Vec<(u8, Box<[u8]>)> = Vec::with_capacity(meta.len());
    for (t, v) in meta {
        if MetaTag::name(t).is_some() && !out.iter().any(|(x, _)| *x == t) {
            out.push((t, v.into_boxed_slice()));
        }
    }
    out
}

/// Writes IPv4/IPv6 + TCP headers for a packet with `plen` payload bytes;
/// returns the header length.
fn write_headers(b: &mut [u8], f: &Flow, dir: Dir, flags: u8, seq: u32, ack: u32, plen: usize) -> usize {
    let (src, dst, sport, dport) = match dir {
        Dir::ToServer => (&f.src, &f.dst, f.sport, f.dport),
        Dir::ToClient => (&f.dst, &f.src, f.dport, f.sport),
    };
    let opts: &[u8] = if flags & TH_SYN != 0 { &SYN_OPTS } else { &[] };
    let tcp_len = TCP_HDR + opts.len();
    let ip_len = if f.v6 { IPV6_HDR } else { IPV4_HDR };
    if f.v6 {
        b[0] = 0x60;
        b[1] = 0;
        b[2] = 0;
        b[3] = 0;
        b[4..6].copy_from_slice(&((tcp_len + plen) as u16).to_be_bytes());
        b[6] = 6; // TCP
        b[7] = 64;
        b[8..24].copy_from_slice(src);
        b[24..40].copy_from_slice(dst);
    } else {
        b[0] = 0x45;
        b[1] = 0;
        b[2..4].copy_from_slice(&((IPV4_HDR + tcp_len + plen) as u16).to_be_bytes());
        b[4..6].copy_from_slice(&f.ip_id.to_be_bytes());
        b[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
        b[8] = 64;
        b[9] = 6;
        b[10] = 0;
        b[11] = 0;
        b[12..16].copy_from_slice(&src[..4]);
        b[16..20].copy_from_slice(&dst[..4]);
        let c = checksum(&b[..IPV4_HDR]);
        b[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let t = &mut b[ip_len..ip_len + tcp_len];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = ((tcp_len / 4) as u8) << 4;
    t[13] = flags;
    t[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
    t[16..20].fill(0); // checksum (validation is disabled by the inspector), urgent
    t[20..].copy_from_slice(opts);
    ip_len + tcp_len
}

/// One's-complement sum of 16-bit big-endian words (odd tail padded).
fn sum16(sum: u32, b: &[u8]) -> u32 {
    let mut sum = sum;
    let mut chunks = b.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [x] = chunks.remainder() {
        sum += (*x as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// RFC 1071 Internet checksum.
pub fn checksum(b: &[u8]) -> u16 {
    fold(sum16(0, b))
}

/// Fills in the TCP checksum of a packet produced by the engine (only
/// needed when the packets leave the process, e.g. in a pcap file).
pub fn fix_tcp_checksum(pkt: &mut [u8]) {
    let v6 = pkt[0] >> 4 == 6;
    let ip_len = if v6 { IPV6_HDR } else { ((pkt[0] & 0x0f) as usize) * 4 };
    let tcp_len = pkt.len() - ip_len;
    let mut pseudo = Vec::with_capacity(40);
    if v6 {
        pseudo.extend_from_slice(&pkt[8..40]);
        pseudo.extend_from_slice(&(tcp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
    } else {
        pseudo.extend_from_slice(&pkt[12..20]);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
    }
    pkt[ip_len + 16] = 0;
    pkt[ip_len + 17] = 0;
    // Both parts have even length, so summing them separately is exact.
    let c = fold(sum16(sum16(0, &pseudo), &pkt[ip_len..]));
    pkt[ip_len + 16..ip_len + 18].copy_from_slice(&c.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::{Region, MIN_RING};
    use crate::ring::{Consumer, Producer};

    /// Records packets and drops payloads containing "EVIL".
    #[derive(Default)]
    struct Fake {
        packets: Vec<Vec<u8>>,
        infos: Vec<(Dir, u8, usize)>,
    }

    impl Inspector for Fake {
        fn inspect(&mut self, buf: &mut PacketBuffer, info: &PacketInfo<'_>) -> Outcome {
            let pkt = buf.packet().to_vec();
            self.infos.push((info.dir, info.tcp_flags, info.payload_len));
            let evil = pkt.windows(4).any(|w| w == b"EVIL");
            self.packets.push(pkt);
            let mut o = Outcome::default();
            if evil {
                o.action = ACTION_ALERT | ACTION_DROP;
                o.reason = Reason::Rule as u8;
                o.drop_reason = 8;
                o.alert_total = 1;
                o.n_alerts = 1;
                o.alerts[0] = AlertInfo {
                    sid: 42,
                    gid: 1,
                    rev: 3,
                    action: ACTION_ALERT | ACTION_DROP,
                    _pad: [0; 3],
                };
            }
            o
        }
    }

    struct Harness {
        _region: Region,
        c2s_p: Producer,
        c2s_c: Consumer,
        s2c_p: Producer,
        s2c_c: Consumer,
        engine: Engine,
        flows: Flows,
        fake: Fake,
    }

    impl Harness {
        fn new(cfg: EngineConfig) -> Self {
            let r = Region::create(MIN_RING, MIN_RING).unwrap();
            Harness {
                c2s_p: Producer::new(r.c2s_ring()),
                c2s_c: Consumer::new(r.c2s_ring()),
                s2c_p: Producer::new(r.s2c_ring()),
                s2c_c: Consumer::new(r.s2c_ring()),
                _region: r,
                engine: Engine::new(cfg, 1),
                flows: Flows::new(1, "test"),
                fake: Fake::default(),
            }
        }

        fn send(&mut self, kind: u16, flags: u16, parts: &[&[u8]]) -> Result<(), Error> {
            assert!(self.c2s_p.push(kind, flags, parts));
            self.c2s_p.publish();
            let rec = self.c2s_c.peek().unwrap().unwrap();
            let mut out = Out::Ring {
                ring: &mut self.s2c_p,
                bell: -1,
            };
            let r = self.engine.handle(&mut self.fake, &mut self.flows, &mut out, &rec);
            self.c2s_c.advance(&rec);
            self.c2s_c.release();
            r
        }

        fn replies(&mut self) -> Vec<(u16, Vec<u8>)> {
            let mut v = Vec::new();
            while let Some(r) = self.s2c_c.peek().unwrap() {
                let mut b = vec![0u8; r.len()];
                r.copy_to(0, &mut b);
                v.push((r.kind, b));
                self.s2c_c.advance(&r);
            }
            self.s2c_c.release();
            v
        }

        fn open(&mut self, cid: u64, src: &str, dst: &str) {
            let o = Open::new(cid, src.parse().unwrap(), 40000, dst.parse().unwrap(), 443).unwrap();
            let mut b = Vec::new();
            o.encode(&mut b).unwrap();
            self.send(proto::K_OPEN, 0, &[&b]).unwrap();
        }

        fn data(&mut self, cid: u64, dir: Dir, token: u32, want: bool, payload: &[u8]) {
            let flags = if want { proto::F_WANT_VERDICT } else { 0 };
            self.send(proto::K_DATA, flags, &[&proto::data_header(cid, dir, token), payload])
                .unwrap();
        }
    }

    fn tcp(pkt: &[u8]) -> (u32, u32, u8, usize) {
        let ip = if pkt[0] >> 4 == 6 { 40 } else { 20 };
        let t = &pkt[ip..];
        let off = ((t[12] >> 4) as usize) * 4;
        (
            u32::from_be_bytes(t[4..8].try_into().unwrap()),
            u32::from_be_bytes(t[8..12].try_into().unwrap()),
            t[13],
            pkt.len() - ip - off,
        )
    }

    #[test]
    fn handshake_data_and_verdicts_v4() {
        let mut h = Harness::new(EngineConfig::default());
        h.open(1, "203.0.113.5", "10.0.0.10");
        assert_eq!(h.fake.infos.len(), 3);
        let syn = &h.fake.packets[0];
        assert_eq!(syn[0], 0x45);
        assert_eq!(checksum(&syn[..20]), 0, "IPv4 header checksum");
        assert_eq!(&syn[12..16], &[203, 0, 113, 5]);
        let (isn_c, _, fl, _) = tcp(syn);
        assert_eq!(fl, TH_SYN);
        let (isn_s, ack, fl, _) = tcp(&h.fake.packets[1]);
        assert_eq!((fl, ack), (TH_SYN | TH_ACK, isn_c.wrapping_add(1)));
        assert_eq!(
            &h.fake.packets[1][12..16],
            &[10, 0, 0, 10],
            "SYN/ACK comes from the server"
        );

        h.data(1, Dir::ToServer, 7, true, b"GET / HTTP/1.1\r\n\r\n");
        let (seq, ack, fl, plen) = tcp(h.fake.packets.last().unwrap());
        assert_eq!(
            (seq, ack, fl, plen),
            (isn_c.wrapping_add(1), isn_s.wrapping_add(1), TH_ACK | TH_PSH, 18)
        );
        let r = h.replies();
        assert_eq!(r.len(), 1);
        let v = proto::Verdict::decode(&r[0].1).unwrap();
        assert_eq!((v.cid, v.token, v.action), (1, 7, Action::Pass));

        // Response acknowledges the request.
        h.data(1, Dir::ToClient, 0, false, b"HTTP/1.1 200 OK\r\n\r\n");
        let (seq, ack, _, _) = tcp(h.fake.packets.last().unwrap());
        assert_eq!((seq, ack), (isn_s.wrapping_add(1), isn_c.wrapping_add(19)));

        h.data(1, Dir::ToServer, 8, true, b"GET /EVIL HTTP/1.1\r\n\r\n");
        let v = proto::Verdict::decode(&h.replies()[0].1).unwrap();
        assert_eq!((v.action, v.reason, v.drop_reason), (Action::Drop, Reason::Rule, 8));
        assert_eq!(v.alerts[0].sid, 42);
    }

    #[test]
    fn segmentation_ack_threshold_and_v6() {
        let cfg = EngineConfig {
            max_segment: 1000,
            ack_threshold: 2500,
            max_flows: 4,
            ..Default::default()
        };
        let mut h = Harness::new(cfg);
        h.open(5, "2001:db8::1", "2001:db8::2");
        let n0 = h.fake.packets.len();
        h.data(5, Dir::ToServer, 1, true, &[b'a'; 3000]);
        let pkts = &h.fake.infos[n0..];
        // three 1000-byte segments then a pure ACK from the server
        assert_eq!(pkts.len(), 4);
        assert!(pkts[..3].iter().all(|p| p.0 == Dir::ToServer && p.2 == 1000));
        assert_eq!((pkts[3].0, pkts[3].1, pkts[3].2), (Dir::ToClient, TH_ACK, 0));
        let p = &h.fake.packets[n0];
        assert_eq!(p[0] >> 4, 6);
        assert_eq!(u16::from_be_bytes([p[4], p[5]]) as usize, 20 + 1000);
        let (_, ack, _, _) = tcp(h.fake.packets.last().unwrap());
        let (seq0, _, _, _) = tcp(&h.fake.packets[n0]);
        assert_eq!(ack, seq0.wrapping_add(3000));
        assert_eq!(proto::Verdict::decode(&h.replies()[0].1).unwrap().action, Action::Pass);
    }

    #[test]
    fn drop_in_earlier_record_is_reported_later() {
        let mut h = Harness::new(EngineConfig::default());
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.data(1, Dir::ToServer, 0, false, b"xxEVILxx");
        assert!(h.replies().is_empty());
        h.data(1, Dir::ToServer, 9, true, b"tail");
        let v = proto::Verdict::decode(&h.replies()[0].1).unwrap();
        assert_eq!((v.token, v.action), (9, Action::Drop));
        // The pending rule match was consumed; the flow stays dropped.
        h.data(1, Dir::ToServer, 10, true, b"more");
        let v = proto::Verdict::decode(&h.replies()[0].1).unwrap();
        assert_eq!((v.action, v.reason), (Action::Drop, Reason::Flow));
        assert!(v.alerts.is_empty());
    }

    #[test]
    fn unknown_flow_duplicate_and_limits() {
        let cfg = EngineConfig {
            max_flows: 1,
            ..Default::default()
        };
        let mut h = Harness::new(cfg);
        h.data(99, Dir::ToServer, 3, true, b"x");
        let v = proto::Verdict::decode(&h.replies()[0].1).unwrap();
        assert_eq!((v.action, v.reason), (Action::Error, Reason::UnknownFlow));
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.open(2, "1.1.1.1", "2.2.2.2");
        let r = h.replies();
        assert_eq!(
            r.iter().map(|x| (x.0, proto::get_u32(&x.1, 12))).collect::<Vec<_>>(),
            vec![
                (proto::K_FLOW_ERROR, proto::FE_DUPLICATE),
                (proto::K_FLOW_ERROR, proto::FE_OVERLOAD)
            ]
        );
        assert!(h.send(proto::K_DATA, 0, &[&[0u8; 3]]).is_err(), "short DATA is fatal");
    }

    #[test]
    fn drop_is_sticky_even_without_packets() {
        let mut h = Harness::new(EngineConfig::default());
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.data(1, Dir::ToServer, 1, true, b"GET /EVIL");
        assert_eq!(proto::Verdict::decode(&h.replies()[0].1).unwrap().reason, Reason::Rule);
        // An empty flush (no packet reaches the engine) must not pass.
        h.data(1, Dir::ToServer, 2, true, b"");
        let v = proto::Verdict::decode(&h.replies()[0].1).unwrap();
        assert_eq!((v.action, v.reason, v.drop_reason), (Action::Drop, Reason::Flow, 8));
        h.data(1, Dir::ToClient, 3, true, b"");
        assert_eq!(proto::Verdict::decode(&h.replies()[0].1).unwrap().action, Action::Drop);
    }

    #[test]
    fn total_flow_limit() {
        let cfg = EngineConfig {
            max_total_flows: 1,
            ..Default::default()
        };
        let mut h = Harness::new(cfg);
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.open(2, "1.1.1.1", "2.2.2.2");
        let r = h.replies();
        assert_eq!(
            (r[0].0, proto::get_u32(&r[0].1, 12)),
            (proto::K_FLOW_ERROR, proto::FE_OVERLOAD)
        );
        assert_eq!(h.engine.total_flows(), 1);
        h.send(proto::K_CLOSE, 0, &[&proto::small(1, 1, 0)]).unwrap();
        assert_eq!(h.engine.total_flows(), 0);
        h.open(3, "1.1.1.1", "2.2.2.2");
        assert!(h.replies().is_empty());
    }

    #[test]
    fn uncredited_records_leave_room_for_verdicts() {
        let mut h = Harness::new(EngineConfig::default());
        h.open(1, "1.1.1.1", "2.2.2.2");
        // Duplicate OPENs produce FLOW_ERRORs nobody reads.
        for _ in 0..10_000 {
            h.open(1, "1.1.1.1", "2.2.2.2");
        }
        // A credited verdict still fits.
        h.data(1, Dir::ToServer, 7, true, b"x");
        let r = h.replies();
        let errors = r.iter().filter(|x| x.0 == proto::K_FLOW_ERROR).count();
        assert!(errors > 0 && errors * 24 <= MIN_RING / 2, "{errors} uncredited records");
        assert_eq!(r.last().unwrap().0, proto::K_VERDICT);
    }

    #[test]
    fn metadata_dedup() {
        let t = known_tags(vec![
            (1, b"a".to_vec()),
            (200, b"x".to_vec()),
            (1, b"b".to_vec()),
            (5, b"r".to_vec()),
        ]);
        assert_eq!(
            t,
            vec![
                (1, b"a".to_vec().into_boxed_slice()),
                (5, b"r".to_vec().into_boxed_slice())
            ]
        );
    }

    #[test]
    fn keepalive_and_discriminator() {
        let cfg = EngineConfig {
            keepalive: Duration::from_millis(20),
            ..Default::default()
        };
        let mut h = Harness::new(cfg);
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.open(2, "1.1.1.1", "2.2.2.2");
        let n = h.fake.packets.len();
        h.engine.housekeep(&mut h.fake, &mut h.flows);
        assert_eq!(h.fake.packets.len(), n, "not idle yet");
        std::thread::sleep(Duration::from_millis(30));
        h.engine.housekeep(&mut h.fake, &mut h.flows);
        assert_eq!(h.fake.packets.len(), n + 2);
        assert!(h.fake.infos[n..]
            .iter()
            .all(|i| i.0 == Dir::ToServer && i.1 == TH_ACK && i.2 == 0));
        assert_eq!(h.engine.stats.keepalives, 2);
        assert_ne!(discriminator(1, 1), discriminator(1, 2));
        assert_ne!(discriminator(1, 1), discriminator(2, 1));
        let d = discriminator(7, 99);
        assert!((1..=4094).contains(&d[0]) && (1..=4094).contains(&d[1]));
    }

    #[test]
    fn eof_close_gap_ping() {
        let mut h = Harness::new(EngineConfig::default());
        h.open(1, "1.1.1.1", "2.2.2.2");
        h.data(1, Dir::ToServer, 0, false, b"abc");
        let (isn_seq, _, _, _) = tcp(h.fake.packets.last().unwrap());
        h.send(proto::K_GAP, 0, &[&proto::small(1, 0, 100)]).unwrap();
        let (_, ack, fl, _) = tcp(h.fake.packets.last().unwrap());
        assert_eq!((fl, ack), (TH_ACK, isn_seq.wrapping_add(103)));
        h.send(proto::K_EOF, 0, &[&proto::small(1, 0, 0)]).unwrap();
        let n = h.fake.packets.len();
        let (_, _, fl, _) = tcp(&h.fake.packets[n - 2]);
        assert_eq!(fl, TH_FIN | TH_ACK);
        let (_, ack, _, _) = tcp(&h.fake.packets[n - 1]);
        assert_eq!(ack, isn_seq.wrapping_add(104), "FIN consumes a sequence number");
        h.data(1, Dir::ToServer, 4, true, b"late");
        assert_eq!(
            proto::Verdict::decode(&h.replies()[0].1).unwrap().reason,
            Reason::Protocol
        );
        h.send(proto::K_CLOSE, 0, &[&proto::small(1, 1, 0)]).unwrap();
        assert_eq!(tcp(h.fake.packets.last().unwrap()).2, TH_RST | TH_ACK);
        assert!(h.flows.is_empty());
        h.send(proto::K_PING, 0, &[&proto::ping(77, 5)]).unwrap();
        let r = h.replies();
        assert_eq!((r[0].0, proto::get_u32(&r[0].1, 0)), (proto::K_PONG, 77));
    }
}
