//! Rust client library (the role of "libsuritap").
//!
//! ```no_run
//! use std::time::Duration;
//! use suritap::{Client, ClientOptions, Dir, OpenParams};
//!
//! let client = Client::connect("/run/suritap", ClientOptions::default())?;
//! let conn = client.open(&OpenParams::new("203.0.113.5:51234".parse().unwrap(), "10.0.0.10:443".parse().unwrap()))?;
//! let v = conn.inspect(Dir::ToServer, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Duration::from_millis(50))?;
//! if v.is_drop() { /* reject the request */ }
//! conn.close(false)?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! A [`Client`] lazily opens one session per Suricata worker and spreads
//! connections over them by connection id. A [`Conn`] is thread-safe; each
//! session runs one reader thread that dispatches verdicts.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::*};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::policy::{Mode, Policy};
use crate::proto::{self, Dir, MetaTag, Open, Verdict, Welcome};
use crate::region::Region;
use crate::ring::{Consumer, Producer, Record, HEADER};
use crate::sys;

/// Path of worker `i`'s socket inside the socket directory.
pub fn socket_path(dir: &Path, i: usize) -> PathBuf {
    dir.join(format!("worker-{i}.sock"))
}

#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Name reported to the server (logged).
    pub name: String,
    /// Size of the request ring per session (power of two).
    pub c2s_size: usize,
    /// Size of the verdict ring per session (power of two).
    pub s2c_size: usize,
    /// Handshake timeout.
    pub connect_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            name: "suritap-rs".into(),
            c2s_size: 1 << 20,
            s2c_size: 256 << 10,
            connect_timeout: Duration::from_secs(2),
        }
    }
}

/// Parameters of a new connection.
#[derive(Clone, Debug)]
pub struct OpenParams {
    /// Real client address (after PROXY protocol / trusted forwarding).
    pub src: SocketAddr,
    /// Listener address of the proxy.
    pub dst: SocketAddr,
    /// Protocol hint (informational).
    pub hint: u8,
    /// Detection tenant (0 = default).
    pub tenant: u32,
    pub meta: Vec<(u8, Vec<u8>)>,
}

impl OpenParams {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        OpenParams {
            src,
            dst,
            hint: 0,
            tenant: 0,
            meta: Vec::new(),
        }
    }

    pub fn meta(mut self, tag: MetaTag, value: impl Into<Vec<u8>>) -> Self {
        self.meta.push((tag as u8, value.into()));
        self
    }
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "suritap session closed")
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "suritap timeout")
}

enum Reply {
    Verdict(Verdict),
    Pong,
}

#[derive(Default)]
struct Waiter {
    slot: Mutex<Option<Result<Reply, ()>>>,
    cv: Condvar,
}

impl Waiter {
    fn complete(&self, r: Result<Reply, ()>) {
        *self.slot.lock().unwrap() = Some(r);
        self.cv.notify_one();
    }

    fn wait(&self, deadline: Instant) -> Option<Result<Reply, ()>> {
        let mut g = self.slot.lock().unwrap();
        loop {
            if let Some(r) = g.take() {
                return Some(r);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            g = self.cv.wait_timeout(g, deadline - now).unwrap().0;
        }
    }
}

struct Semaphore {
    n: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    fn acquire(&self, deadline: Instant, dead: &AtomicBool) -> io::Result<()> {
        let mut g = self.n.lock().unwrap();
        loop {
            if dead.load(Acquire) {
                return Err(broken());
            }
            if *g > 0 {
                *g -= 1;
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(timed_out());
            }
            g = self.cv.wait_timeout(g, deadline - now).unwrap().0;
        }
    }

    fn release(&self) {
        *self.n.lock().unwrap() += 1;
        self.cv.notify_one();
    }
}

type PolicySlot = Arc<Mutex<Option<Arc<Policy>>>>;

struct Session {
    sock: OwnedFd,
    c2s_bell: OwnedFd,
    s2c_bell: OwnedFd,
    tx: Mutex<Producer>,
    space: Condvar,
    space_waiters: AtomicUsize,
    waiters: Mutex<HashMap<u32, Arc<Waiter>>>,
    credits: Semaphore,
    next_token: AtomicU32,
    dead: AtomicBool,
    bypassed: Mutex<HashSet<u64>>,
    flow_errors: Mutex<HashMap<u64, u32>>,
    /// Receives the plugin's endpoint policy (shared with the client).
    policy: PolicySlot,
    /// CLOSE records that did not fit in the ring yet: (cid, how). Flushed
    /// before any other record and whenever space frees up, so a closed
    /// connection is never leaked on the server.
    closes: Mutex<Vec<(u64, u8)>>,
    worker_index: u16,
    worker_count: u16,
    max_payload: usize,
    // Dropped last: the rings point into it.
    _region: Region,
}

impl Session {
    fn connect(path: &Path, opts: &ClientOptions, policy: PolicySlot) -> io::Result<Arc<Session>> {
        let region = Region::create(opts.c2s_size, opts.s2c_size)?;
        let sock = sys::seqpacket_connect(path)?;
        let hello = proto::Hello {
            pid: std::process::id(),
            flags: 0,
            name: opts.name.clone(),
        };
        sys::send_with_fds(sock.as_raw_fd(), &hello.encode(), &[region.fd()])?;
        let mut pfd = [libc::pollfd {
            fd: sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        if sys::poll(&mut pfd, opts.connect_timeout.as_millis() as i32)? == 0 {
            return Err(timed_out());
        }
        let mut buf = [0u8; 128];
        let mut fds = Vec::new();
        let n = sys::recv_with_fds(sock.as_raw_fd(), &mut buf, &mut fds)?;
        let w = Welcome::decode(&buf[..n])
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "suritap: malformed welcome"))?;
        if w.status != proto::ST_OK {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("suritap: session refused ({}): {}", w.status, w.message),
            ));
        }
        if fds.len() != 2 || w.worker_count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "suritap: bad welcome"));
        }
        let s2c_bell = fds.pop().unwrap();
        let c2s_bell = fds.pop().unwrap();
        let credits = (region.s2c_size() / proto::MAX_VERDICT_RECORD / 2).max(1);
        let rx = Consumer::new(region.s2c_ring());
        let s = Arc::new(Session {
            tx: Mutex::new(Producer::new(region.c2s_ring())),
            space: Condvar::new(),
            space_waiters: AtomicUsize::new(0),
            waiters: Mutex::new(HashMap::new()),
            credits: Semaphore {
                n: Mutex::new(credits),
                cv: Condvar::new(),
            },
            next_token: AtomicU32::new(1),
            dead: AtomicBool::new(false),
            bypassed: Mutex::new(HashSet::new()),
            flow_errors: Mutex::new(HashMap::new()),
            policy,
            closes: Mutex::new(Vec::new()),
            worker_index: w.worker_index,
            worker_count: w.worker_count,
            max_payload: (w.max_payload as usize).min(region.c2s_size() / 4 - HEADER - proto::DATA_FIXED),
            sock,
            c2s_bell,
            s2c_bell,
            _region: region,
        });
        let reader = s.clone();
        std::thread::Builder::new()
            .name(format!("suritap-rx{}", w.worker_index))
            .spawn(move || reader.read_loop(rx))?;
        Ok(s)
    }

    fn read_loop(self: Arc<Self>, mut rx: Consumer) {
        let mut pfd = [
            libc::pollfd {
                fd: self.s2c_bell.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.sock.as_raw_fd(),
                events: libc::POLLIN | libc::POLLRDHUP,
                revents: 0,
            },
        ];
        loop {
            let mut n = 0;
            loop {
                match rx.peek() {
                    Ok(Some(r)) => {
                        self.dispatch(&r);
                        rx.advance(&r);
                        n += 1;
                    }
                    Ok(None) => break,
                    Err(_) => {
                        self.fail();
                        return;
                    }
                }
            }
            if n > 0 {
                rx.release();
            }
            self.flush_closes();
            self.notify_space();
            if self.dead.load(Acquire) {
                return;
            }
            if n > 0 || !rx.prepare_sleep() {
                continue;
            }
            let r = sys::poll(&mut pfd, 1000);
            rx.cancel_sleep();
            if r.is_err() || pfd[1].revents != 0 {
                self.fail();
                return;
            }
            if pfd[0].revents != 0 {
                sys::eventfd_drain(self.s2c_bell.as_raw_fd());
            }
        }
    }

    fn dispatch(&self, r: &Record) {
        match r.kind {
            proto::K_VERDICT => {
                let mut b = [0u8; proto::VERDICT_FIXED + proto::ALERT_SIZE * proto::MAX_ALERTS];
                let len = r.len().min(b.len());
                r.copy_to(0, &mut b[..len]);
                if let Some(v) = Verdict::decode(&b[..len]) {
                    self.credits.release();
                    if let Some(w) = self.waiters.lock().unwrap().remove(&v.token) {
                        w.complete(Ok(Reply::Verdict(v)));
                    }
                }
            }
            proto::K_PONG => {
                if let Some(b) = r.prefix::<{ proto::SMALL }>() {
                    self.credits.release();
                    if let Some(w) = self.waiters.lock().unwrap().remove(&proto::get_u32(&b, 0)) {
                        w.complete(Ok(Reply::Pong));
                    }
                }
            }
            proto::K_BYPASS => {
                if let Some(b) = r.prefix::<{ proto::SMALL }>() {
                    self.bypassed.lock().unwrap().insert(proto::get_u64(&b, 0));
                }
            }
            proto::K_FLOW_ERROR => {
                if let Some(b) = r.prefix::<{ proto::SMALL }>() {
                    self.flow_errors
                        .lock()
                        .unwrap()
                        .insert(proto::get_u64(&b, 0), proto::get_u32(&b, 12));
                }
            }
            proto::K_POLICY => {
                let mut b = vec![0u8; r.len()];
                r.copy_to(0, &mut b);
                if let Ok(p) = Policy::decode(&b) {
                    *self.policy.lock().unwrap() = Some(Arc::new(p));
                }
            }
            _ => {}
        }
    }

    /// Pushes queued CLOSE records while they fit. Caller holds `tx`.
    fn flush_closes_locked(&self, tx: &mut Producer) {
        let mut q = self.closes.lock().unwrap();
        let mut sent = 0;
        for (cid, how) in q.iter() {
            if !tx.push(proto::K_CLOSE, 0, &[&proto::small(*cid, *how, 0)]) {
                break;
            }
            sent += 1;
        }
        if sent > 0 {
            q.drain(..sent);
            if tx.publish() {
                sys::eventfd_signal(self.c2s_bell.as_raw_fd());
            }
        }
    }

    fn flush_closes(&self) {
        if !self.closes.lock().unwrap().is_empty() {
            let mut tx = self.tx.lock().unwrap();
            self.flush_closes_locked(&mut tx);
        }
    }

    /// Closes a connection without blocking: the CLOSE is queued when the
    /// ring is full.
    fn close_conn(&self, cid: u64, how: u8) {
        self.bypassed.lock().unwrap().remove(&cid);
        self.flow_errors.lock().unwrap().remove(&cid);
        if self.dead.load(Acquire) {
            return;
        }
        self.closes.lock().unwrap().push((cid, how));
        self.flush_closes();
    }

    fn notify_space(&self) {
        if self.space_waiters.load(SeqCst) > 0 {
            // Taking the lock orders us after a producer that is about to wait.
            drop(self.tx.lock().unwrap());
            self.space.notify_all();
        }
    }

    fn fail(&self) {
        self.dead.store(true, Release);
        for (_, w) in self.waiters.lock().unwrap().drain() {
            w.complete(Err(()));
        }
        drop(self.tx.lock().unwrap());
        self.space.notify_all();
        self.credits.cv.notify_all();
    }

    fn shutdown(&self) {
        sys::shutdown(self.sock.as_raw_fd());
    }

    /// Pushes one record, waiting for ring space until `deadline` (no
    /// waiting when `None`).
    fn push(&self, kind: u16, flags: u16, parts: &[&[u8]], deadline: Option<Instant>) -> io::Result<()> {
        let body: usize = parts.iter().map(|p| p.len()).sum();
        let mut tx = self.tx.lock().unwrap();
        loop {
            if self.dead.load(Acquire) {
                return Err(broken());
            }
            // Queued CLOSEs go first; a record that does not fit after them
            // waits for space like any other.
            if !self.closes.lock().unwrap().is_empty() {
                self.flush_closes_locked(&mut tx);
            }
            if tx.push(kind, flags, parts) {
                if tx.publish() {
                    sys::eventfd_signal(self.c2s_bell.as_raw_fd());
                }
                return Ok(());
            }
            if HEADER + body > tx.max_record() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "suritap: record too large"));
            }
            let Some(deadline) = deadline else {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "suritap: ring full"));
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(timed_out());
            }
            self.space_waiters.fetch_add(1, SeqCst);
            let need = tx.need(body);
            if tx.prepare_wait(need) {
                tx = self.space.wait_timeout(tx, deadline - now).unwrap().0;
            }
            self.space_waiters.fetch_sub(1, SeqCst);
        }
    }

    fn request(&self, deadline: Instant, send: impl FnOnce(u32) -> io::Result<()>) -> io::Result<Reply> {
        self.credits.acquire(deadline, &self.dead)?;
        let token = self.next_token.fetch_add(1, Relaxed);
        let w = Arc::new(Waiter::default());
        self.waiters.lock().unwrap().insert(token, w.clone());
        if let Err(e) = send(token) {
            if self.waiters.lock().unwrap().remove(&token).is_some() {
                self.credits.release();
            }
            return Err(e);
        }
        match w.wait(deadline) {
            Some(Ok(r)) => Ok(r),
            Some(Err(())) => Err(broken()),
            None => {
                // The late reply still returns the credit when it arrives.
                if self.waiters.lock().unwrap().remove(&token).is_none() {
                    if let Some(Ok(r)) = w.wait(Instant::now()) {
                        return Ok(r);
                    }
                }
                Err(timed_out())
            }
        }
    }
}

struct Inner {
    dir: PathBuf,
    opts: ClientOptions,
    slots: Vec<Mutex<Option<Arc<Session>>>>,
    next_cid: AtomicU64,
    policy: PolicySlot,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for slot in &self.slots {
            if let Some(s) = slot.lock().unwrap().take() {
                s.shutdown();
            }
        }
    }
}

/// A connection to the Suricata suritap plugin (all workers).
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

impl Client {
    /// Connects to worker 0 to learn the worker count; the other sessions
    /// are opened on first use.
    pub fn connect(dir: impl AsRef<Path>, opts: ClientOptions) -> io::Result<Client> {
        let dir = dir.as_ref().to_path_buf();
        let policy = PolicySlot::default();
        let first = Session::connect(&socket_path(&dir, 0), &opts, policy.clone())?;
        let count = first.worker_count as usize;
        let slots: Vec<_> = (0..count).map(|_| Mutex::new(None)).collect();
        *slots[0].lock().unwrap() = Some(first);
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(Client {
            inner: Arc::new(Inner {
                dir,
                opts,
                slots,
                next_cid: AtomicU64::new(mix(seed) | 1),
                policy,
            }),
        })
    }

    /// The operator's mode for an endpoint from the plugin's endpoint
    /// policy; `None` when it does not list the endpoint (or no policy
    /// arrived yet) and the caller's own setting applies. The last policy
    /// is kept across reconnects.
    pub fn endpoint_mode(&self, endpoint: &str) -> Option<Mode> {
        self.inner.policy.lock().unwrap().as_ref()?.mode(endpoint.as_bytes())
    }

    pub fn worker_count(&self) -> usize {
        self.inner.slots.len()
    }

    fn session(&self, idx: usize) -> io::Result<Arc<Session>> {
        let mut slot = self.inner.slots[idx].lock().unwrap();
        if let Some(s) = slot.as_ref() {
            if !s.dead.load(Acquire) {
                return Ok(s.clone());
            }
        }
        let s = Session::connect(
            &socket_path(&self.inner.dir, idx),
            &self.inner.opts,
            self.inner.policy.clone(),
        )?;
        if s.worker_index as usize != idx {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "suritap: worker index mismatch",
            ));
        }
        *slot = Some(s.clone());
        Ok(s)
    }

    /// Announces a new proxied connection.
    pub fn open(&self, p: &OpenParams) -> io::Result<Conn> {
        let cid = self.inner.next_cid.fetch_add(1, Relaxed);
        let idx = (mix(cid) % self.worker_count() as u64) as usize;
        let s = self.session(idx)?;
        let mut open = Open::new(cid, p.src.ip(), p.src.port(), p.dst.ip(), p.dst.port())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.0))?;
        open.hint = p.hint;
        open.tenant = p.tenant;
        open.meta = p.meta.clone();
        let mut body = Vec::with_capacity(proto::OPEN_FIXED + 64);
        open.encode(&mut body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.0))?;
        s.push(
            proto::K_OPEN,
            0,
            &[&body],
            Some(Instant::now() + self.inner.opts.connect_timeout),
        )?;
        Ok(Conn {
            s,
            cid,
            closed: AtomicBool::new(false),
        })
    }

    /// Round trip through worker `idx` without touching the engine.
    pub fn ping(&self, idx: usize, timeout: Duration) -> io::Result<Duration> {
        let s = self.session(idx)?;
        let start = Instant::now();
        s.request(start + timeout, |token| {
            s.push(proto::K_PING, 0, &[&proto::ping(token, 0)], Some(start + timeout))
        })?;
        Ok(start.elapsed())
    }
}

/// One proxied connection.
pub struct Conn {
    s: Arc<Session>,
    cid: u64,
    closed: AtomicBool,
}

impl Conn {
    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Index of the worker that inspects this connection.
    pub fn worker(&self) -> u16 {
        self.s.worker_index
    }

    /// Largest payload per DATA record (larger buffers are split).
    pub fn max_payload(&self) -> usize {
        self.s.max_payload
    }

    fn send_chunks(&self, dir: Dir, data: &[u8], deadline: Instant) -> io::Result<()> {
        for chunk in data.chunks(self.s.max_payload) {
            self.s.push(
                proto::K_DATA,
                0,
                &[&proto::data_header(self.cid, dir, 0), chunk],
                Some(deadline),
            )?;
        }
        Ok(())
    }

    /// Sends payload without waiting for a verdict (detect-only mode).
    pub fn send(&self, dir: Dir, data: &[u8], timeout: Duration) -> io::Result<()> {
        self.send_chunks(dir, data, Instant::now() + timeout)
    }

    /// Sends payload (possibly empty) and waits for the verdict covering
    /// everything sent so far in `dir`.
    pub fn inspect(&self, dir: Dir, data: &[u8], timeout: Duration) -> io::Result<Verdict> {
        let deadline = Instant::now() + timeout;
        let split = data.len().saturating_sub(1) / self.s.max_payload * self.s.max_payload;
        self.send_chunks(dir, &data[..split], deadline)?;
        let last = &data[split..];
        let reply = self.s.request(deadline, |token| {
            self.s.push(
                proto::K_DATA,
                proto::F_WANT_VERDICT,
                &[&proto::data_header(self.cid, dir, token), last],
                Some(deadline),
            )
        })?;
        match reply {
            Reply::Verdict(v) => Ok(v),
            Reply::Pong => Err(io::Error::new(io::ErrorKind::InvalidData, "suritap: unexpected reply")),
        }
    }

    /// Reports `len` bytes that were not sent (e.g. dropped under load).
    pub fn gap(&self, dir: Dir, mut len: u64, timeout: Duration) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while len > 0 {
            let n = len.min(u32::MAX as u64) as u32;
            self.s.push(
                proto::K_GAP,
                0,
                &[&proto::small(self.cid, dir as u8, n)],
                Some(deadline),
            )?;
            len -= n as u64;
        }
        Ok(())
    }

    /// Half-closes one direction (FIN).
    pub fn eof(&self, dir: Dir, timeout: Duration) -> io::Result<()> {
        self.s.push(
            proto::K_EOF,
            0,
            &[&proto::small(self.cid, dir as u8, 0)],
            Some(Instant::now() + timeout),
        )
    }

    /// Closes the connection (FIN both ways, or RST when `reset`). Never
    /// blocks: when the ring is full the CLOSE is queued and sent as soon
    /// as there is room.
    pub fn close(&self, reset: bool) -> io::Result<()> {
        if self.closed.swap(true, AcqRel) {
            return Ok(());
        }
        if self.s.dead.load(Acquire) {
            return Err(broken());
        }
        self.s.close_conn(self.cid, reset as u8);
        Ok(())
    }

    /// True once Suricata decided the rest of the connection needs no
    /// inspection.
    pub fn bypassed(&self) -> bool {
        self.s.bypassed.lock().unwrap().contains(&self.cid)
    }

    /// FLOW_ERROR code reported for this connection, if any.
    pub fn flow_error(&self) -> Option<u32> {
        self.s.flow_errors.lock().unwrap().get(&self.cid).copied()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if !self.closed.swap(true, AcqRel) {
            self.s.close_conn(self.cid, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Inspector, Outcome, PacketBuffer, PacketInfo, ACTION_ALERT, ACTION_DROP};
    use crate::server::{Worker, WorkerConfig};
    use std::sync::atomic::AtomicBool;

    struct Marker;

    impl Inspector for Marker {
        fn inspect(&mut self, buf: &mut PacketBuffer, _info: &PacketInfo<'_>) -> Outcome {
            let mut o = Outcome::default();
            if buf.packet().windows(4).any(|w| w == b"EVIL") {
                o.action = ACTION_ALERT | ACTION_DROP;
                o.reason = proto::Reason::Rule as u8;
            }
            o
        }
    }

    fn serve(dir: &Path, workers: u16) -> (Arc<AtomicBool>, Vec<std::thread::JoinHandle<()>>) {
        serve_with(dir, workers, None)
    }

    fn serve_with(
        dir: &Path,
        workers: u16,
        policy: Option<PathBuf>,
    ) -> (Arc<AtomicBool>, Vec<std::thread::JoinHandle<()>>) {
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for i in 0..workers {
            let mut cfg = WorkerConfig::new(socket_path(dir, i as usize), i, workers);
            cfg.engine.max_segment = 4096;
            cfg.policy_file = policy.clone();
            let mut w = Worker::new(cfg).unwrap();
            let stop = stop.clone();
            handles.push(std::thread::spawn(move || {
                while !stop.load(Relaxed) {
                    w.run_once(&mut Marker, 20);
                }
                w.shutdown();
            }));
        }
        (stop, handles)
    }

    fn tempdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "suritap-test-{}-{}",
            std::process::id(),
            mix(Instant::now().elapsed().as_nanos() as u64 ^ rand_seed())
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_seed() -> u64 {
        static C: AtomicU64 = AtomicU64::new(1);
        C.fetch_add(1, Relaxed)
    }

    #[test]
    fn endpoint_policy() {
        let dir = tempdir();
        let pf = dir.join("policy");
        std::fs::write(&pf, "web detect\n").unwrap();
        let (stop, handles) = serve_with(&dir, 1, Some(pf));
        let client = Client::connect(&dir, ClientOptions::default()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while client.endpoint_mode("web").is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.endpoint_mode("web"), Some(Mode::Detect));
        assert_eq!(client.endpoint_mode("other"), None);
        stop.store(true, Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn end_to_end_with_worker() {
        let dir = tempdir();
        let (stop, handles) = serve(&dir, 2);
        let opts = ClientOptions {
            c2s_size: 64 << 10,
            s2c_size: 64 << 10,
            ..Default::default()
        };
        let client = Client::connect(&dir, opts).unwrap();
        assert_eq!(client.worker_count(), 2);
        assert!(client.ping(1, Duration::from_secs(1)).is_ok());

        let t = Duration::from_secs(2);
        let mut conns = Vec::new();
        for i in 0..16 {
            let src: SocketAddr = format!("198.51.100.{}:4000{}", i + 1, i % 10).parse().unwrap();
            let p = OpenParams::new(src, "10.0.0.1:443".parse().unwrap()).meta(MetaTag::Sni, "a.example");
            conns.push(client.open(&p).unwrap());
        }
        assert!(conns.iter().any(|c| c.worker() == 0) && conns.iter().any(|c| c.worker() == 1));
        for c in &conns {
            assert_eq!(
                c.inspect(Dir::ToServer, b"GET / HTTP/1.1\r\n\r\n", t).unwrap().action,
                proto::Action::Pass
            );
            // Larger than one record (16 KiB) and the ring (64 KiB): split + backpressure.
            let big = vec![b'x'; 200_000];
            assert_eq!(c.inspect(Dir::ToClient, &big, t).unwrap().action, proto::Action::Pass);
            assert!(c.inspect(Dir::ToServer, b"GET /EVIL", t).unwrap().is_drop());
        }

        // Many threads share a session.
        let c = Arc::new(
            client
                .open(&OpenParams::new(
                    "[2001:db8::1]:1".parse().unwrap(),
                    "[2001:db8::2]:443".parse().unwrap(),
                ))
                .unwrap(),
        );
        let th: Vec<_> = (0..4)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        assert_ne!(
                            c.inspect(Dir::ToServer, b"ping", Duration::from_secs(2))
                                .unwrap()
                                .action,
                            proto::Action::Error
                        );
                    }
                })
            })
            .collect();
        for h in th {
            h.join().unwrap();
        }

        // Closing while the ring is full queues the CLOSE instead of losing it.
        {
            let mut tx = c.s.tx.lock().unwrap();
            // DATA for an unknown connection without WANT_VERDICT: no reply.
            while tx.push(
                proto::K_DATA,
                0,
                &[&proto::data_header(0, Dir::ToServer, 0), &[0u8; 8000]],
            ) {}
            drop(tx);
            let victim = client.open(&OpenParams::new(
                "198.51.100.250:9".parse().unwrap(),
                "10.0.0.1:443".parse().unwrap(),
            ));
            drop(victim);
        }
        let queued = Conn {
            s: c.s.clone(),
            cid: 777,
            closed: AtomicBool::new(false),
        };
        drop(queued);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !c.s.closes.lock().unwrap().is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(c.s.closes.lock().unwrap().is_empty(), "queued CLOSE was not flushed");

        // Unknown connection id after the server dropped it.
        let fake = Conn {
            s: c.s.clone(),
            cid: 12345,
            closed: AtomicBool::new(true),
        };
        assert_eq!(
            fake.inspect(Dir::ToServer, b"x", t).unwrap().reason,
            proto::Reason::UnknownFlow
        );

        stop.store(true, Relaxed);
        for h in handles {
            h.join().unwrap();
        }
        // Server gone: requests fail instead of hanging.
        let e = c.inspect(Dir::ToServer, b"x", Duration::from_millis(500)).unwrap_err();
        assert!(
            matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::TimedOut),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
