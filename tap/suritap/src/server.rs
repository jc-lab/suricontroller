//! Server side: one [`Worker`] per engine thread.
//!
//! A worker owns its sessions and an [`Engine`] and listens on up to two
//! sockets:
//!
//! * `worker-N.sock` (SOCK_SEQPACKET): shared-memory sessions — the HELLO
//!   carries a memfd with the rings,
//! * `worker-N.stream.sock` (SOCK_STREAM): socket sessions for clients
//!   that cannot map shared memory — records travel framed over the socket.
//!
//! [`Worker::run_once`] processes up to `batch` records per session per
//! pass and, when there is nothing to do, sleeps in epoll on the session
//! eventfds, sockets and listeners. All packets of a session are processed
//! by the worker that accepted it, which keeps flows on one engine thread.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::engine::{Engine, EngineConfig, Flows, Inspector, Out};
use crate::proto::{self, Hello, Welcome};
use crate::region::{Region, RegionLimits};
use crate::ring::{Consumer, Producer, Record, HEADER};
use crate::slab::Slab;
use crate::sys::{self, Epoll};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

pub type LogFn = fn(Level, &str);

fn stderr_log(level: Level, msg: &str) {
    eprintln!("suritap {level:?}: {msg}");
}

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Shared-memory listener.
    pub socket_path: PathBuf,
    /// Socket-transport listener (`None` disables it).
    pub stream_path: Option<PathBuf>,
    pub socket_mode: Option<u32>,
    pub index: u16,
    pub count: u16,
    pub max_sessions: usize,
    pub limits: RegionLimits,
    pub engine: EngineConfig,
    /// Records processed per session before moving to the next one.
    pub batch: usize,
    /// Busy-poll the rings this long before sleeping.
    pub spin: Duration,
    pub log: LogFn,
}

impl WorkerConfig {
    pub fn new(socket_path: PathBuf, index: u16, count: u16) -> Self {
        WorkerConfig {
            socket_path,
            stream_path: None,
            socket_mode: None,
            index,
            count,
            max_sessions: 256,
            limits: RegionLimits::default(),
            engine: EngineConfig::default(),
            batch: 64,
            spin: Duration::ZERO,
            log: stderr_log,
        }
    }
}

/// Wakes a worker sleeping in [`Worker::run_once`] from another thread.
#[derive(Clone)]
pub struct Breaker(Arc<OwnedFd>);

impl Breaker {
    pub fn wake(&self) {
        sys::eventfd_signal(self.0.as_raw_fd());
    }
}

#[derive(Clone, Debug, Default)]
pub struct WorkerStats {
    pub sessions_opened: u64,
    pub sessions_closed: u64,
    pub handshake_failures: u64,
    pub protocol_errors: u64,
}

/// Output buffered per stream session before the client is considered
/// stuck (it must read its verdicts).
const STREAM_OUT_LIMIT: usize = 1 << 20;
/// Input buffered per stream session; reading pauses beyond it.
const STREAM_IN_LIMIT: usize = 4 * proto::STREAM_MAX_FRAME;
const STREAM_READ_CHUNK: usize = 64 * 1024;

enum Link {
    Shm {
        c2s_bell: OwnedFd,
        s2c_bell: OwnedFd,
        c2s: Consumer,
        s2c: Producer,
        // Dropped last: the rings point into it.
        _region: Region,
    },
    Stream {
        inbuf: Vec<u8>,
        start: usize,
        outbuf: Vec<u8>,
        readable: bool,
        eof: bool,
        polling_out: bool,
    },
}

struct Session {
    id: u32,
    name: Arc<str>,
    sock: OwnedFd,
    flows: Flows,
    link: Link,
}

/// An accepted connection waiting for HELLO.
struct Pending {
    fd: OwnedFd,
    deadline: Instant,
    /// Socket transport: bytes of the HELLO received so far.
    stream: Option<Vec<u8>>,
}

const T_LISTEN: u64 = 1;
const T_BREAK: u64 = 2;
const T_PENDING: u64 = 3;
const T_SOCK: u64 = 4;
const T_BELL: u64 = 5;
const T_LISTEN_STREAM: u64 = 6;
const MAX_PENDING: usize = 64;
/// A connection must send HELLO within this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

fn token(kind: u64, idx: u32, gen: u32) -> u64 {
    (kind << 56) | ((gen as u64 & 0x00ff_ffff) << 32) | idx as u64
}

fn untoken(t: u64) -> (u64, u32, u32) {
    (t >> 56, (t & 0xffff_ffff) as u32, ((t >> 32) & 0x00ff_ffff) as u32)
}

const SOCK_EVENTS: u32 = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;

pub struct Worker {
    cfg: WorkerConfig,
    ep: Epoll,
    listener: OwnedFd,
    stream_listener: Option<OwnedFd>,
    breaker: Arc<OwnedFd>,
    pending: Slab<Pending>,
    sessions: Slab<Session>,
    streams: usize,
    pub engine: Engine,
    next_id: u32,
    events: Vec<libc::epoll_event>,
    busy_passes: u32,
    next_housekeep: Instant,
    failed: Vec<(u32, String, Level)>,
    pub stats: WorkerStats,
}

impl Worker {
    pub fn new(cfg: WorkerConfig) -> io::Result<Worker> {
        let listener = sys::seqpacket_listen(&cfg.socket_path, cfg.socket_mode)?;
        let ep = Epoll::new()?;
        let breaker = Arc::new(sys::eventfd()?);
        ep.add(listener.as_raw_fd(), token(T_LISTEN, 0, 0), libc::EPOLLIN as u32)?;
        ep.add(breaker.as_raw_fd(), token(T_BREAK, 0, 0), libc::EPOLLIN as u32)?;
        let stream_listener = match &cfg.stream_path {
            Some(p) => {
                let l = sys::stream_listen(p, cfg.socket_mode)?;
                ep.add(l.as_raw_fd(), token(T_LISTEN_STREAM, 0, 0), libc::EPOLLIN as u32)?;
                Some(l)
            }
            None => None,
        };
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
            ^ ((cfg.index as u64) << 48);
        let engine = Engine::new(cfg.engine.clone(), seed);
        Ok(Worker {
            cfg,
            ep,
            listener,
            stream_listener,
            breaker,
            pending: Slab::new(),
            sessions: Slab::new(),
            streams: 0,
            engine,
            next_id: 0,
            events: vec![libc::epoll_event { events: 0, u64: 0 }; 64],
            busy_passes: 0,
            next_housekeep: Instant::now(),
            failed: Vec::new(),
            stats: WorkerStats::default(),
        })
    }

    pub fn breaker(&self) -> Breaker {
        Breaker(self.breaker.clone())
    }

    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn config(&self) -> &WorkerConfig {
        &self.cfg
    }

    fn log(&self, level: Level, msg: &str) {
        (self.cfg.log)(level, msg)
    }

    /// Processes pending records. When there is nothing to do, sleeps up to
    /// `timeout_ms` waiting for records, connections or a [`Breaker`].
    /// Returns true when records were processed.
    pub fn run_once<I: Inspector>(&mut self, insp: &mut I, timeout_ms: i32) -> bool {
        let now = Instant::now();
        self.engine.tick();
        if now >= self.next_housekeep {
            self.housekeep(insp, now);
        }
        let mut work = 0usize;
        {
            let Worker {
                sessions,
                engine,
                cfg,
                failed,
                ep,
                ..
            } = self;
            for idx in 0..sessions.capacity() {
                let gen = sessions.generation(idx);
                let Some(s) = sessions.by_index(idx) else { continue };
                let r = match s.link {
                    Link::Shm { .. } => process_shm(engine, insp, s, cfg.batch),
                    Link::Stream { .. } => {
                        process_stream(engine, insp, s, cfg.batch, ep, token(T_SOCK, idx as u32, gen))
                    }
                };
                match r {
                    Ok(n) => work += n,
                    Err((why, level)) => failed.push((idx as u32, why, level)),
                }
            }
        }
        while let Some((idx, why, level)) = self.failed.pop() {
            if level <= Level::Warning {
                self.stats.protocol_errors += 1;
            }
            self.close_session(idx, insp, &why, level, true);
        }
        if work > 0 {
            self.busy_passes = self.busy_passes.wrapping_add(1);
            // Stream sessions learn about new data from epoll only.
            if self.streams > 0 || self.busy_passes % 64 == 0 {
                self.poll_events(insp, 0);
            }
            return true;
        }
        if !self.cfg.spin.is_zero() && self.sessions.len() > self.streams {
            let deadline = Instant::now() + self.cfg.spin;
            loop {
                let ready = self
                    .sessions
                    .iter_mut()
                    .any(|s| matches!(&s.link, Link::Shm { c2s, .. } if !c2s.is_empty()));
                if ready {
                    return true;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::hint::spin_loop();
            }
        }
        let mut sleep = true;
        for s in self.sessions.iter_mut() {
            let busy = match &mut s.link {
                Link::Shm { c2s, .. } => !c2s.prepare_sleep(),
                Link::Stream { readable, .. } => *readable,
            };
            if busy {
                sleep = false;
                break;
            }
        }
        self.poll_events(insp, if sleep { timeout_ms } else { 0 });
        for s in self.sessions.iter_mut() {
            if let Link::Shm { c2s, .. } = &s.link {
                c2s.cancel_sleep();
            }
        }
        false
    }

    fn poll_events<I: Inspector>(&mut self, insp: &mut I, timeout_ms: i32) {
        let n = match self.ep.wait(&mut self.events, timeout_ms) {
            Ok(n) => n,
            Err(e) => {
                self.log(Level::Error, &format!("epoll_wait: {e}"));
                return;
            }
        };
        for i in 0..n {
            let ev = self.events[i];
            let (data, flags) = (ev.u64, ev.events);
            let (kind, idx, gen) = untoken(data);
            match kind {
                T_LISTEN => self.accept_all(false),
                T_LISTEN_STREAM => self.accept_all(true),
                T_BREAK => sys::eventfd_drain(self.breaker.as_raw_fd()),
                T_PENDING => self.handshake(idx, gen),
                T_SOCK => {
                    let Some(s) = self.sessions.get_mut(idx, gen) else {
                        continue;
                    };
                    match &mut s.link {
                        Link::Stream { readable, .. } => {
                            // Read (or see EOF/errors) on the next pass.
                            if flags & !(libc::EPOLLOUT as u32) != 0 {
                                *readable = true;
                            }
                        }
                        Link::Shm { .. } => {
                            let hup = flags & (libc::EPOLLHUP | libc::EPOLLRDHUP | libc::EPOLLERR) as u32 != 0;
                            // Shared-memory clients send nothing after the
                            // handshake; anything readable is EOF or a
                            // protocol violation.
                            let mut buf = [0u8; 64];
                            let mut fds = Vec::new();
                            let eof = hup
                                || matches!(
                                    sys::recv_with_fds(s.sock.as_raw_fd(), &mut buf, &mut fds),
                                    Ok(0) | Err(_)
                                );
                            if eof {
                                self.close_session(idx, insp, "client disconnected", Level::Info, true);
                            }
                        }
                    }
                }
                T_BELL => {
                    if let Some(Session {
                        link: Link::Shm { c2s_bell, .. },
                        ..
                    }) = self.sessions.get_mut(idx, gen)
                    {
                        sys::eventfd_drain(c2s_bell.as_raw_fd());
                    }
                }
                _ => {}
            }
        }
    }

    /// Keepalives for idle flows and expiry of stalled handshakes; runs on
    /// a worker-level timer so the hot loop reads the clock once per pass.
    fn housekeep<I: Inspector>(&mut self, insp: &mut I, now: Instant) {
        let Worker { sessions, engine, .. } = self;
        for s in sessions.iter_mut() {
            engine.housekeep(insp, &mut s.flows);
        }
        self.expire_pending(now);
        let interval = self
            .engine
            .housekeep_interval()
            .unwrap_or(HANDSHAKE_TIMEOUT)
            .min(HANDSHAKE_TIMEOUT);
        self.next_housekeep = now + interval;
    }

    fn drop_pending(&mut self, idx: u32) {
        if let Some(p) = self.pending.remove(idx) {
            self.ep.delete(p.fd.as_raw_fd());
        }
    }

    fn expire_pending(&mut self, now: Instant) {
        for idx in 0..self.pending.capacity() {
            if matches!(self.pending.by_index(idx), Some(p) if p.deadline <= now) {
                self.stats.handshake_failures += 1;
                self.drop_pending(idx as u32);
            }
        }
    }

    fn accept_all(&mut self, stream: bool) {
        let listener = match (stream, &self.stream_listener) {
            (false, _) => self.listener.as_raw_fd(),
            (true, Some(l)) => l.as_raw_fd(),
            (true, None) => return,
        };
        loop {
            match sys::accept(listener) {
                Ok(Some(fd)) => {
                    if self.pending.len() >= MAX_PENDING {
                        // Make room by evicting the connection waiting the
                        // longest instead of refusing newcomers: idle
                        // connections must not lock legitimate clients out.
                        let oldest = (0..self.pending.capacity())
                            .filter_map(|i| self.pending.by_index(i).map(|p| (p.deadline, i)))
                            .min()
                            .map(|(_, i)| i as u32);
                        if let Some(i) = oldest {
                            self.log(Level::Warning, "too many pending handshakes; evicting the oldest");
                            self.stats.handshake_failures += 1;
                            self.drop_pending(i);
                        }
                    }
                    let raw = fd.as_raw_fd();
                    let (idx, gen) = self.pending.insert(Pending {
                        fd,
                        deadline: Instant::now() + HANDSHAKE_TIMEOUT,
                        stream: stream.then(Vec::new),
                    });
                    if self.ep.add(raw, token(T_PENDING, idx, gen), SOCK_EVENTS).is_err() {
                        self.pending.remove(idx);
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    self.log(Level::Warning, &format!("accept: {e}"));
                    return;
                }
            }
        }
    }

    fn handshake(&mut self, idx: u32, gen: u32) {
        let Some(p) = self.pending.get_mut(idx, gen) else {
            return;
        };
        let raw = p.fd.as_raw_fd();
        if let Some(got) = &mut p.stream {
            // Socket transport: the HELLO may arrive in pieces.
            let mut buf = [0u8; proto::HELLO_SIZE];
            let want = proto::HELLO_SIZE - got.len();
            match sys::recv_nb(raw, &mut buf[..want]) {
                Ok(None) => return,
                Ok(Some(n)) if n > 0 => {
                    got.extend_from_slice(&buf[..n]);
                    if got.len() < proto::HELLO_SIZE {
                        return;
                    }
                }
                _ => {
                    self.drop_pending(idx);
                    return;
                }
            }
            self.ep.delete(raw);
            let p = self.pending.remove(idx).unwrap();
            let hello = p.stream.unwrap();
            if let Err(e) = self.establish_stream(&hello, p.fd) {
                self.stats.handshake_failures += 1;
                self.log(Level::Warning, &format!("handshake refused: {e}"));
            }
            return;
        }
        let mut buf = [0u8; 128];
        let mut fds = Vec::new();
        let r = sys::recv_with_fds(raw, &mut buf, &mut fds);
        if matches!(&r, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
            return;
        }
        self.ep.delete(raw);
        let p = self.pending.remove(idx).unwrap();
        match r {
            Ok(n) if n > 0 => {
                if let Err(e) = self.establish(&buf[..n], fds, p.fd) {
                    self.stats.handshake_failures += 1;
                    self.log(Level::Warning, &format!("handshake refused: {e}"));
                }
            }
            _ => {}
        }
    }

    fn welcome(&self, status: u16, max_payload: u32, session_id: u32, message: &str) -> Welcome {
        Welcome {
            status,
            worker_index: self.cfg.index,
            worker_count: self.cfg.count,
            max_payload,
            max_flows: if status == proto::ST_OK {
                self.cfg.engine.max_flows as u32
            } else {
                0
            },
            session_id,
            message: message.into(),
        }
    }

    fn next_session_id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        ((self.cfg.index as u32) << 24) | (self.next_id & 0x00ff_ffff)
    }

    fn establish(&mut self, msg: &[u8], mut fds: Vec<OwnedFd>, sock: OwnedFd) -> Result<(), String> {
        let refuse = |w: &Worker, status: u16, message: String| {
            let _ = sys::send_with_fds(sock.as_raw_fd(), &w.welcome(status, 0, 0, &message).encode(), &[]);
            message
        };
        let Some(hello) = Hello::decode(msg) else {
            return Err(refuse(self, proto::ST_BAD_HELLO, "malformed hello".into()));
        };
        if fds.len() != 1 {
            return Err(refuse(
                self,
                proto::ST_BAD_HELLO,
                "hello must carry exactly one memfd".into(),
            ));
        }
        if self.sessions.len() >= self.cfg.max_sessions {
            return Err(refuse(self, proto::ST_TOO_MANY, "too many sessions".into()));
        }
        let region = match Region::open(fds.pop().unwrap(), &self.cfg.limits) {
            Ok(r) => r,
            Err(e) => return Err(refuse(self, proto::ST_BAD_REGION, e)),
        };
        let (c2s_bell, s2c_bell) = match (sys::eventfd(), sys::eventfd()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Err(refuse(self, proto::ST_INTERNAL, "eventfd failed".into())),
        };
        let id = self.next_session_id();
        let max_payload = (region.c2s_size() / 4 - HEADER - proto::DATA_FIXED) as u32;
        sys::send_with_fds(
            sock.as_raw_fd(),
            &self.welcome(proto::ST_OK, max_payload, id, "").encode(),
            &[c2s_bell.as_raw_fd(), s2c_bell.as_raw_fd()],
        )
        .map_err(|e| format!("send welcome: {e}"))?;
        let bell_raw = c2s_bell.as_raw_fd();
        let link = Link::Shm {
            c2s: Consumer::new(region.c2s_ring()),
            s2c: Producer::new(region.s2c_ring()),
            c2s_bell,
            s2c_bell,
            _region: region,
        };
        let (idx, gen) = self.add_session(id, &hello, sock, link, "shm")?;
        if self
            .ep
            .add(bell_raw, token(T_BELL, idx, gen), libc::EPOLLIN as u32)
            .is_err()
        {
            if let Some(s) = self.sessions.remove(idx) {
                self.ep.delete(s.sock.as_raw_fd());
            }
            return Err("epoll registration failed".into());
        }
        Ok(())
    }

    fn establish_stream(&mut self, msg: &[u8], sock: OwnedFd) -> Result<(), String> {
        let refuse = |w: &Worker, status: u16, message: String| {
            let _ = sys::send_nb(sock.as_raw_fd(), &w.welcome(status, 0, 0, &message).encode());
            message
        };
        let Some(hello) = Hello::decode(msg) else {
            return Err(refuse(self, proto::ST_BAD_HELLO, "malformed hello".into()));
        };
        if self.sessions.len() >= self.cfg.max_sessions {
            return Err(refuse(self, proto::ST_TOO_MANY, "too many sessions".into()));
        }
        let id = self.next_session_id();
        let w = self
            .welcome(proto::ST_OK, proto::STREAM_MAX_PAYLOAD as u32, id, "")
            .encode();
        // A fresh socket always has room for 64 bytes.
        if sys::send_nb(sock.as_raw_fd(), &w).map_err(|e| format!("send welcome: {e}"))? != w.len() {
            return Err("short welcome".into());
        }
        let link = Link::Stream {
            inbuf: Vec::new(),
            start: 0,
            outbuf: Vec::new(),
            readable: true, // records may have followed the HELLO
            eof: false,
            polling_out: false,
        };
        self.add_session(id, &hello, sock, link, "socket")?;
        self.streams += 1;
        Ok(())
    }

    fn add_session(
        &mut self,
        id: u32,
        hello: &Hello,
        sock: OwnedFd,
        link: Link,
        transport: &str,
    ) -> Result<(u32, u32), String> {
        let name: String = hello.name.chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
        let cred = sys::peer_cred(sock.as_raw_fd()).ok();
        let sock_raw = sock.as_raw_fd();
        let session = Session {
            id,
            name: name.as_str().into(),
            flows: Flows::new(id, &name),
            sock,
            link,
        };
        let (idx, gen) = self.sessions.insert(session);
        if self.ep.add(sock_raw, token(T_SOCK, idx, gen), SOCK_EVENTS).is_err() {
            self.sessions.remove(idx);
            return Err("epoll registration failed".into());
        }
        self.stats.sessions_opened += 1;
        let (pid, uid) = cred.map_or((0, 0), |c| (c.pid, c.uid));
        self.log(
            Level::Info,
            &format!(
                "worker {}: {transport} session {id:#x} opened by '{name}' (pid {pid}, uid {uid}, hello pid {})",
                self.cfg.index, hello.pid
            ),
        );
        Ok((idx, gen))
    }

    fn close_session<I: Inspector>(&mut self, idx: u32, insp: &mut I, why: &str, level: Level, reset_flows: bool) {
        let Some(mut s) = self.sessions.remove(idx) else { return };
        self.ep.delete(s.sock.as_raw_fd());
        match &s.link {
            Link::Shm { c2s_bell, .. } => self.ep.delete(c2s_bell.as_raw_fd()),
            Link::Stream { .. } => self.streams -= 1,
        }
        let flows = s.flows.len();
        if reset_flows {
            self.engine.close_all(insp, &mut s.flows);
        }
        self.stats.sessions_closed += 1;
        self.log(
            level,
            &format!(
                "worker {}: session {:#x} ('{}') closed: {why} ({flows} open flows reset)",
                self.cfg.index, s.id, s.name
            ),
        );
    }

    /// Closes every session without injecting packets and removes the
    /// socket files. Used when the engine is shutting down.
    pub fn shutdown(&mut self) {
        for idx in 0..self.sessions.capacity() {
            if let Some(s) = self.sessions.remove(idx as u32) {
                self.ep.delete(s.sock.as_raw_fd());
            }
        }
        self.streams = 0;
        self.remove_socket_files();
    }

    fn remove_socket_files(&self) {
        let _ = std::fs::remove_file(&self.cfg.socket_path);
        if let Some(p) = &self.cfg.stream_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.remove_socket_files();
    }
}

type ProcessResult = Result<usize, (String, Level)>;

fn fatal(e: impl ToString) -> (String, Level) {
    (e.to_string(), Level::Warning)
}

fn process_shm<I: Inspector>(engine: &mut Engine, insp: &mut I, s: &mut Session, batch: usize) -> ProcessResult {
    let Session { flows, link, .. } = s;
    let Link::Shm { c2s, s2c, s2c_bell, .. } = link else {
        unreachable!()
    };
    let bell = s2c_bell.as_raw_fd();
    let mut out = Out::Ring { ring: s2c, bell };
    let mut n = 0;
    while n < batch {
        let rec = match c2s.peek() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => return Err(fatal(e)),
        };
        let r = engine.handle(insp, flows, &mut out, &rec);
        c2s.advance(&rec);
        n += 1;
        r.map_err(fatal)?;
    }
    if n > 0 && c2s.release() {
        // The client waits for ring space.
        sys::eventfd_signal(bell);
    }
    Ok(n)
}

fn process_stream<I: Inspector>(
    engine: &mut Engine,
    insp: &mut I,
    s: &mut Session,
    batch: usize,
    ep: &Epoll,
    tok: u64,
) -> ProcessResult {
    let sock = s.sock.as_raw_fd();
    let Session { flows, link, .. } = s;
    let Link::Stream {
        inbuf,
        start,
        outbuf,
        readable,
        eof,
        polling_out,
    } = link
    else {
        unreachable!()
    };
    if *readable {
        read_stream(sock, inbuf, start, readable, eof).map_err(fatal)?;
    }
    let mut n = 0;
    {
        let mut out = Out::Buffer {
            buf: outbuf,
            limit: STREAM_OUT_LIMIT,
        };
        while n < batch {
            let avail = &inbuf[*start..];
            if avail.len() < HEADER {
                break;
            }
            let len = u32::from_le_bytes(avail[..4].try_into().unwrap()) as usize;
            if !(HEADER..=proto::STREAM_MAX_FRAME).contains(&len) {
                return Err(fatal("bad frame length"));
            }
            if avail.len() < len {
                break;
            }
            let kind = u16::from_le_bytes([avail[4], avail[5]]);
            let flags = u16::from_le_bytes([avail[6], avail[7]]);
            let rec = Record::from_slice(kind, flags, &avail[HEADER..len]);
            engine.handle(insp, flows, &mut out, &rec).map_err(fatal)?;
            *start += len;
            n += 1;
        }
    }
    if *start == inbuf.len() {
        inbuf.clear();
        *start = 0;
    }
    flush_stream(sock, outbuf, polling_out, ep, tok).map_err(fatal)?;
    if *eof && n == 0 {
        return Err(("client disconnected".into(), Level::Info));
    }
    Ok(n)
}

fn read_stream(
    sock: RawFd,
    inbuf: &mut Vec<u8>,
    start: &mut usize,
    readable: &mut bool,
    eof: &mut bool,
) -> io::Result<()> {
    loop {
        if inbuf.len() - *start >= STREAM_IN_LIMIT {
            // Back pressure: keep `readable` so the next pass continues.
            return Ok(());
        }
        if *start > 0 && inbuf.capacity() - inbuf.len() < STREAM_READ_CHUNK {
            inbuf.drain(..*start);
            *start = 0;
        }
        let len = inbuf.len();
        inbuf.resize(len + STREAM_READ_CHUNK, 0);
        let r = sys::recv_nb(sock, &mut inbuf[len..]);
        match r {
            Ok(Some(0)) => {
                inbuf.truncate(len);
                *eof = true;
                *readable = false;
                return Ok(());
            }
            Ok(Some(n)) => inbuf.truncate(len + n),
            Ok(None) => {
                inbuf.truncate(len);
                *readable = false;
                return Ok(());
            }
            Err(e) => {
                inbuf.truncate(len);
                return Err(e);
            }
        }
    }
}

/// Writes buffered verdicts; asks epoll for writability while some remain.
fn flush_stream(sock: RawFd, outbuf: &mut Vec<u8>, polling_out: &mut bool, ep: &Epoll, tok: u64) -> io::Result<()> {
    let mut sent = 0;
    while sent < outbuf.len() {
        let n = sys::send_nb(sock, &outbuf[sent..])?;
        if n == 0 {
            break;
        }
        sent += n;
    }
    outbuf.drain(..sent);
    let want_out = !outbuf.is_empty();
    if want_out != *polling_out {
        let events = if want_out {
            SOCK_EVENTS | libc::EPOLLOUT as u32
        } else {
            SOCK_EVENTS
        };
        ep.modify(sock, tok, events)?;
        *polling_out = want_out;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Outcome, PacketBuffer, PacketInfo, ACTION_ALERT, ACTION_DROP};
    use crate::proto::{Dir, Open, Verdict};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

    struct Marker;

    impl Inspector for Marker {
        fn inspect(&mut self, buf: &mut PacketBuffer, _: &PacketInfo<'_>) -> Outcome {
            let mut o = Outcome::default();
            if buf.packet().windows(4).any(|w| w == b"EVIL") {
                o.action = ACTION_ALERT | ACTION_DROP;
                o.reason = proto::Reason::Rule as u8;
            }
            o
        }
    }

    fn frame(kind: u16, flags: u16, parts: &[&[u8]]) -> Vec<u8> {
        let len = HEADER + parts.iter().map(|p| p.len()).sum::<usize>();
        let mut f = Vec::with_capacity(len);
        f.extend_from_slice(&(len as u32).to_le_bytes());
        f.extend_from_slice(&kind.to_le_bytes());
        f.extend_from_slice(&flags.to_le_bytes());
        for p in parts {
            f.extend_from_slice(p);
        }
        f
    }

    fn read_frame(s: &mut UnixStream) -> (u16, Vec<u8>) {
        let mut h = [0u8; HEADER];
        s.read_exact(&mut h).unwrap();
        let len = u32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len - HEADER];
        s.read_exact(&mut body).unwrap();
        (u16::from_le_bytes([h[4], h[5]]), body)
    }

    #[test]
    fn socket_transport() {
        let dir = std::env::temp_dir().join(format!("stap-srv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = WorkerConfig::new(dir.join("worker-0.sock"), 0, 1);
        cfg.stream_path = Some(dir.join("worker-0.stream.sock"));
        let mut w = Worker::new(cfg).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let th = std::thread::spawn(move || {
            while !st.load(Relaxed) {
                w.run_once(&mut Marker, 10);
            }
            (
                w.stats.sessions_opened,
                w.stats.sessions_closed,
                w.engine.stats.flows_closed,
            )
        });

        let mut s = UnixStream::connect(dir.join("worker-0.stream.sock")).unwrap();
        let hello = Hello {
            pid: 1,
            flags: 0,
            name: "stream-test".into(),
        }
        .encode();
        // HELLO in two pieces, immediately followed by records.
        s.write_all(&hello[..10]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let open = Open::new(
            5,
            "203.0.113.1".parse().unwrap(),
            1000,
            "10.0.0.1".parse().unwrap(),
            443,
        )
        .unwrap();
        let mut ob = Vec::new();
        open.encode(&mut ob).unwrap();
        let mut batch = hello[10..].to_vec();
        batch.extend(frame(proto::K_OPEN, 0, &[&ob]));
        batch.extend(frame(
            proto::K_DATA,
            proto::F_WANT_VERDICT,
            &[&proto::data_header(5, Dir::ToServer, 1), b"GET / HTTP/1.1\r\n\r\n"],
        ));
        s.write_all(&batch).unwrap();
        let mut w = [0u8; proto::WELCOME_SIZE];
        s.read_exact(&mut w).unwrap();
        let welcome = Welcome::decode(&w).unwrap();
        assert_eq!(
            (welcome.status, welcome.max_payload as usize),
            (proto::ST_OK, proto::STREAM_MAX_PAYLOAD)
        );
        let (k, b) = read_frame(&mut s);
        assert_eq!(k, proto::K_VERDICT);
        assert_eq!(Verdict::decode(&b).unwrap().action, proto::Action::Pass);

        // A large payload split across many socket writes, then a drop.
        let big = vec![b'x'; proto::STREAM_MAX_PAYLOAD];
        let f = frame(
            proto::K_DATA,
            proto::F_WANT_VERDICT,
            &[&proto::data_header(5, Dir::ToClient, 2), &big],
        );
        for c in f.chunks(1000) {
            s.write_all(c).unwrap();
        }
        let (_, b) = read_frame(&mut s);
        let v = Verdict::decode(&b).unwrap();
        assert_eq!((v.token, v.action), (2, proto::Action::Pass));
        s.write_all(&frame(
            proto::K_DATA,
            proto::F_WANT_VERDICT,
            &[&proto::data_header(5, Dir::ToServer, 3), b"EVIL"],
        ))
        .unwrap();
        let (_, b) = read_frame(&mut s);
        assert_eq!(Verdict::decode(&b).unwrap().action, proto::Action::Drop);

        // An oversized frame is a protocol error: the server hangs up.
        s.write_all(&((proto::STREAM_MAX_FRAME + 1) as u32).to_le_bytes())
            .unwrap();
        s.write_all(&[0u8; 4]).unwrap();
        let mut rest = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = s.read_to_end(&mut rest);
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Relaxed);
        let (opened, closed, flows_closed) = th.join().unwrap();
        assert_eq!(
            (opened, closed, flows_closed),
            (1, 1, 1),
            "session closed and its flow reset"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
