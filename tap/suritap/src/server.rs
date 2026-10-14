//! Server side: one [`Worker`] per engine thread.
//!
//! A worker owns a listening socket (`worker-N.sock`), its sessions and an
//! [`Engine`]. [`Worker::run_once`] drains the c2s rings of all sessions
//! (up to `batch` records each per pass) and, when there is nothing to do,
//! sleeps in epoll on the session eventfds, sockets and listener. All
//! packets of a session are processed by the worker that accepted it, which
//! keeps flows on one engine thread.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::engine::{Engine, EngineConfig, Flows, Inspector, Out};
use crate::proto::{self, Hello, Welcome};
use crate::region::{Region, RegionLimits};
use crate::ring::{Consumer, Producer};
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
    pub socket_path: PathBuf,
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

struct Session {
    id: u32,
    name: Arc<str>,
    sock: OwnedFd,
    c2s_bell: OwnedFd,
    s2c_bell: OwnedFd,
    c2s: Consumer,
    s2c: Producer,
    flows: Flows,
    // Dropped last: the rings point into it.
    _region: Region,
}

const T_LISTEN: u64 = 1;
const T_BREAK: u64 = 2;
const T_PENDING: u64 = 3;
const T_SOCK: u64 = 4;
const T_BELL: u64 = 5;
const MAX_PENDING: usize = 64;
/// A connection must send HELLO within this time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

fn token(kind: u64, idx: u32, gen: u32) -> u64 {
    (kind << 56) | ((gen as u64 & 0x00ff_ffff) << 32) | idx as u64
}

fn untoken(t: u64) -> (u64, u32, u32) {
    (t >> 56, idx_of(t), ((t >> 32) & 0x00ff_ffff) as u32)
}

fn idx_of(t: u64) -> u32 {
    (t & 0xffff_ffff) as u32
}

pub struct Worker {
    cfg: WorkerConfig,
    ep: Epoll,
    listener: OwnedFd,
    breaker: Arc<OwnedFd>,
    /// Accepted connections waiting for HELLO, with their deadline.
    pending: Slab<(OwnedFd, Instant)>,
    sessions: Slab<Session>,
    pub engine: Engine,
    next_id: u32,
    events: Vec<libc::epoll_event>,
    busy_passes: u32,
    next_housekeep: Instant,
    failed: Vec<(u32, String)>,
    pub stats: WorkerStats,
}

impl Worker {
    pub fn new(cfg: WorkerConfig) -> io::Result<Worker> {
        let listener = sys::seqpacket_listen(&cfg.socket_path, cfg.socket_mode)?;
        let ep = Epoll::new()?;
        let breaker = Arc::new(sys::eventfd()?);
        ep.add(listener.as_raw_fd(), token(T_LISTEN, 0, 0), libc::EPOLLIN as u32)?;
        ep.add(breaker.as_raw_fd(), token(T_BREAK, 0, 0), libc::EPOLLIN as u32)?;
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
            breaker,
            pending: Slab::new(),
            sessions: Slab::new(),
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
                ..
            } = self;
            for idx in 0..sessions.capacity() {
                let Some(s) = sessions.by_index(idx) else { continue };
                match process(engine, insp, s, cfg.batch) {
                    Ok(n) => work += n,
                    Err(e) => failed.push((idx as u32, e)),
                }
            }
        }
        while let Some((idx, why)) = self.failed.pop() {
            self.stats.protocol_errors += 1;
            self.close_session(idx, insp, &why, Level::Warning, true);
        }
        if work > 0 {
            self.busy_passes = self.busy_passes.wrapping_add(1);
            if self.busy_passes % 64 == 0 {
                self.poll_events(insp, 0);
            }
            return true;
        }
        if !self.cfg.spin.is_zero() && self.sessions.len() > 0 {
            let deadline = Instant::now() + self.cfg.spin;
            loop {
                if self.sessions.iter_mut().any(|s| !s.c2s.is_empty()) {
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
            if !s.c2s.prepare_sleep() {
                sleep = false;
                break;
            }
        }
        self.poll_events(insp, if sleep { timeout_ms } else { 0 });
        for s in self.sessions.iter_mut() {
            s.c2s.cancel_sleep();
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
                T_LISTEN => self.accept_all(),
                T_BREAK => sys::eventfd_drain(self.breaker.as_raw_fd()),
                T_PENDING => self.handshake(idx, gen),
                T_SOCK => {
                    let Some(s) = self.sessions.get_mut(idx, gen) else {
                        continue;
                    };
                    let hup = flags & (libc::EPOLLHUP | libc::EPOLLRDHUP | libc::EPOLLERR) as u32 != 0;
                    // Clients send nothing after the handshake; anything
                    // readable is either EOF or a protocol violation.
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
                T_BELL => {
                    if let Some(s) = self.sessions.get_mut(idx, gen) {
                        sys::eventfd_drain(s.c2s_bell.as_raw_fd());
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
        if let Some((fd, _)) = self.pending.remove(idx) {
            self.ep.delete(fd.as_raw_fd());
        }
    }

    fn expire_pending(&mut self, now: Instant) {
        for idx in 0..self.pending.capacity() {
            if matches!(self.pending.by_index(idx), Some((_, deadline)) if *deadline <= now) {
                self.stats.handshake_failures += 1;
                self.drop_pending(idx as u32);
            }
        }
    }

    fn accept_all(&mut self) {
        loop {
            match sys::accept(self.listener.as_raw_fd()) {
                Ok(Some(fd)) => {
                    if self.pending.len() >= MAX_PENDING {
                        // Make room by evicting the connection waiting the
                        // longest instead of refusing newcomers: idle
                        // connections must not lock legitimate clients out.
                        let oldest = (0..self.pending.capacity())
                            .filter_map(|i| self.pending.by_index(i).map(|(_, d)| (*d, i)))
                            .min()
                            .map(|(_, i)| i as u32);
                        if let Some(i) = oldest {
                            self.log(Level::Warning, "too many pending handshakes; evicting the oldest");
                            self.stats.handshake_failures += 1;
                            self.drop_pending(i);
                        }
                    }
                    let raw = fd.as_raw_fd();
                    let (idx, gen) = self.pending.insert((fd, Instant::now() + HANDSHAKE_TIMEOUT));
                    let events = (libc::EPOLLIN | libc::EPOLLRDHUP) as u32;
                    if self.ep.add(raw, token(T_PENDING, idx, gen), events).is_err() {
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
        let Some((fd, _)) = self.pending.get_mut(idx, gen) else {
            return;
        };
        let raw = fd.as_raw_fd();
        let mut buf = [0u8; 128];
        let mut fds = Vec::new();
        let r = sys::recv_with_fds(raw, &mut buf, &mut fds);
        if matches!(&r, Err(e) if e.kind() == io::ErrorKind::WouldBlock) {
            return;
        }
        self.ep.delete(raw);
        let (sock, _) = self.pending.remove(idx).unwrap();
        match r {
            Ok(n) if n > 0 => {
                if let Err(e) = self.establish(&buf[..n], fds, sock) {
                    self.stats.handshake_failures += 1;
                    self.log(Level::Warning, &format!("handshake refused: {e}"));
                }
            }
            _ => {}
        }
    }

    fn establish(&mut self, msg: &[u8], mut fds: Vec<OwnedFd>, sock: OwnedFd) -> Result<(), String> {
        let refuse = |status: u16, message: String| {
            let w = Welcome {
                status,
                worker_index: self.cfg.index,
                worker_count: self.cfg.count,
                max_payload: 0,
                max_flows: 0,
                session_id: 0,
                message: message.clone(),
            };
            let _ = sys::send_with_fds(sock.as_raw_fd(), &w.encode(), &[]);
            message
        };
        let Some(hello) = Hello::decode(msg) else {
            return Err(refuse(proto::ST_BAD_HELLO, "malformed hello".into()));
        };
        if fds.len() != 1 {
            return Err(refuse(proto::ST_BAD_HELLO, "hello must carry exactly one memfd".into()));
        }
        if self.sessions.len() >= self.cfg.max_sessions {
            return Err(refuse(proto::ST_TOO_MANY, "too many sessions".into()));
        }
        let region = Region::open(fds.pop().unwrap(), &self.cfg.limits).map_err(|e| refuse(proto::ST_BAD_REGION, e))?;
        let (c2s_bell, s2c_bell) = match (sys::eventfd(), sys::eventfd()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => return Err(refuse(proto::ST_INTERNAL, "eventfd failed".into())),
        };
        self.next_id = self.next_id.wrapping_add(1);
        let id = ((self.cfg.index as u32) << 24) | (self.next_id & 0x00ff_ffff);
        let max_payload = (region.c2s_size() / 4 - crate::ring::HEADER - proto::DATA_FIXED) as u32;
        let w = Welcome {
            status: proto::ST_OK,
            worker_index: self.cfg.index,
            worker_count: self.cfg.count,
            max_payload,
            max_flows: self.cfg.engine.max_flows as u32,
            session_id: id,
            message: String::new(),
        };
        sys::send_with_fds(
            sock.as_raw_fd(),
            &w.encode(),
            &[c2s_bell.as_raw_fd(), s2c_bell.as_raw_fd()],
        )
        .map_err(|e| format!("send welcome: {e}"))?;
        let name: String = hello.name.chars().filter(|c| c.is_ascii_graphic()).take(32).collect();
        let cred = sys::peer_cred(sock.as_raw_fd()).ok();
        let session = Session {
            id,
            name: name.as_str().into(),
            c2s: Consumer::new(region.c2s_ring()),
            s2c: Producer::new(region.s2c_ring()),
            flows: Flows::new(id, &name),
            sock,
            c2s_bell,
            s2c_bell,
            _region: region,
        };
        let (sock_raw, bell_raw) = (session.sock.as_raw_fd(), session.c2s_bell.as_raw_fd());
        let (idx, gen) = self.sessions.insert(session);
        let ok = self
            .ep
            .add(
                sock_raw,
                token(T_SOCK, idx, gen),
                (libc::EPOLLIN | libc::EPOLLRDHUP) as u32,
            )
            .is_ok()
            && self
                .ep
                .add(bell_raw, token(T_BELL, idx, gen), libc::EPOLLIN as u32)
                .is_ok();
        if !ok {
            self.ep.delete(sock_raw);
            self.sessions.remove(idx);
            return Err("epoll registration failed".into());
        }
        self.stats.sessions_opened += 1;
        let (pid, uid) = cred.map_or((0, 0), |c| (c.pid, c.uid));
        self.log(
            Level::Info,
            &format!(
                "worker {}: session {id:#x} opened by '{name}' (pid {pid}, uid {uid}, hello pid {})",
                self.cfg.index, hello.pid
            ),
        );
        Ok(())
    }

    fn close_session<I: Inspector>(&mut self, idx: u32, insp: &mut I, why: &str, level: Level, reset_flows: bool) {
        let Some(mut s) = self.sessions.remove(idx) else { return };
        self.ep.delete(s.sock.as_raw_fd());
        self.ep.delete(s.c2s_bell.as_raw_fd());
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
    /// socket file. Used when the engine is shutting down.
    pub fn shutdown(&mut self) {
        for idx in 0..self.sessions.capacity() {
            if let Some(s) = self.sessions.remove(idx as u32) {
                self.ep.delete(s.sock.as_raw_fd());
            }
        }
        let _ = std::fs::remove_file(&self.cfg.socket_path);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cfg.socket_path);
    }
}

fn process<I: Inspector>(engine: &mut Engine, insp: &mut I, s: &mut Session, batch: usize) -> Result<usize, String> {
    let Session {
        c2s,
        s2c,
        flows,
        s2c_bell,
        ..
    } = s;
    let bell = s2c_bell.as_raw_fd();
    let mut out = Out { ring: s2c, bell };
    let mut n = 0;
    while n < batch {
        let rec = match c2s.peek() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => return Err(e.to_string()),
        };
        let r = engine.handle(insp, flows, &mut out, &rec);
        c2s.advance(&rec);
        n += 1;
        r.map_err(|e| e.to_string())?;
    }
    if n > 0 && c2s.release() {
        // The client waits for ring space.
        sys::eventfd_signal(bell);
    }
    Ok(n)
}
