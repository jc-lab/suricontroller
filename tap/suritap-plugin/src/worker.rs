//! Worker threads: the receive loop and the Suricata-backed [`Inspector`].
//!
//! Each packet synthesized by the engine is handed to Suricata zero-copy
//! (`PacketSetData` on the engine's buffer) and processed synchronously by
//! `TmThreadsSlotProcessPkt` (decode → flow worker: stream, app-layer,
//! detect, output). Our release callback runs when Suricata is done with
//! the packet and copies its action and alerts into a small context stored
//! in the buffer's headroom.

use std::cell::Cell;
use std::ffi::{c_int, c_void, CString};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use suritap::engine::{EngineConfig, FlowMeta, Inspector, Outcome, PacketBuffer, PacketInfo, HEADROOM};
use suritap::region::RegionLimits;
use suritap::server::{Breaker, Worker, WorkerConfig};

use crate::config::LIVE_DEVICE;
use crate::ffi::{self, LiveDevice, Packet, ThreadVars, TmEcode, TM_ECODE_FAILED, TM_ECODE_OK};
use crate::{config, log};

pub static CALLBACKS: ffi::Callbacks = ffi::Callbacks {
    thread_init,
    r#loop: recv_loop,
    break_loop,
    thread_deinit,
    exit_stats,
};

const CTX_MAGIC: u32 = 0x5354_4358;
const IN_FLIGHT: u32 = 0;
const RELEASED: u32 = 1;
const ABANDONED: u32 = 2;

/// Per-packet context in the buffer headroom.
#[repr(C)]
struct PktCtx {
    magic: u32,
    state: AtomicU32,
    cap: usize,
    outcome: Outcome,
}

const _: () = assert!(std::mem::size_of::<PktCtx>() <= HEADROOM);

thread_local! {
    /// Packet being processed by this thread and its context.
    static CURRENT: Cell<(*const Packet, *mut PktCtx, *const Arc<FlowMeta>)> =
        const { Cell::new((ptr::null(), ptr::null_mut(), ptr::null())) };
}

/// Flow metadata of the packet currently processed by this thread when it
/// is `p` (used by the flow init callback).
pub(crate) fn current_meta(p: *const Packet) -> Option<Arc<FlowMeta>> {
    CURRENT.with(|c| {
        let (cur, _, meta) = c.get();
        (cur == p && !meta.is_null()).then(|| unsafe { (*meta).clone() })
    })
}

/// Marks the packet currently processed by this thread as bypassed.
pub(crate) fn mark_bypass(p: *const Packet) {
    CURRENT.with(|c| {
        let (cur, ctx, _) = c.get();
        if cur == p && !ctx.is_null() {
            unsafe { (*ctx).outcome.bypass = 1 };
        }
    })
}

struct SuriInspector {
    tv: *mut ThreadVars,
    slot_next: *mut c_void,
    dev: *mut LiveDevice,
}

impl Inspector for SuriInspector {
    fn inspect(&mut self, buf: &mut PacketBuffer, info: &PacketInfo<'_>) -> Outcome {
        let p = unsafe { ffi::suritap_packet_get() };
        if p.is_null() {
            return Outcome::failed();
        }
        let ctx = buf.headroom() as *mut PktCtx;
        unsafe {
            ptr::write(
                ctx,
                PktCtx {
                    magic: CTX_MAGIC,
                    state: AtomicU32::new(IN_FLIGHT),
                    cap: buf.capacity(),
                    outcome: Outcome::default(),
                },
            );
            ffi::suritap_packet_setup(
                p,
                buf.packet_ptr(),
                buf.len() as u32,
                self.dev,
                release_packet,
                info.tenant,
                info.vlan[0],
                info.vlan[1],
            );
        }
        let meta: *const Arc<FlowMeta> = if info.new_flow { info.meta } else { ptr::null() };
        CURRENT.with(|c| c.set((p, ctx, meta)));
        let rc = unsafe { ffi::suritap_process(self.tv, self.slot_next, p, self.dev) };
        CURRENT.with(|c| c.set((ptr::null(), ptr::null_mut(), ptr::null())));
        let state = unsafe { &(*ctx).state };
        if state
            .compare_exchange(IN_FLIGHT, ABANDONED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Suricata still holds the packet (not expected in workers
            // mode): hand the buffer over to the release callback.
            buf.detach();
            return Outcome::failed();
        }
        let mut o = unsafe { (*ctx).outcome };
        if rc != 0 {
            o.failed = 1;
        }
        o
    }
}

extern "C" fn release_packet(p: *mut Packet) {
    unsafe {
        let data = ffi::suritap_packet_data(p);
        let ctx = data.sub(HEADROOM) as *mut PktCtx;
        if (*ctx).magic != CTX_MAGIC {
            ffi::suritap_packet_release(p);
            return;
        }
        ffi::suritap_packet_outcome(p, &mut (*ctx).outcome);
        ffi::suritap_packet_release(p);
        if (*ctx).state.swap(RELEASED, Ordering::AcqRel) == ABANDONED {
            let cap = (*ctx).cap;
            PacketBuffer::free_detached(ctx as *mut u8, cap);
        }
    }
}

struct Init {
    index: u16,
}

struct Ctx {
    worker: Worker,
    insp: SuriInspector,
    breaker: Breaker,
    idle_ms: i32,
    counters: Counters,
    last_stats: Instant,
}

struct Counters {
    sessions: u16,
    records: u16,
    packets: u16,
    bytes: u16,
    verdicts: u16,
    drops: u16,
    flows: u16,
    errors: u16,
    bypasses: u16,
    keepalives: u16,
}

impl Counters {
    fn register(tv: *mut ThreadVars) -> Counters {
        let reg = |name: &str| {
            let c = CString::new(format!("suritap.{name}")).unwrap();
            // Suricata keeps the pointer: leak the (tiny, per-thread) name.
            unsafe { ffi::StatsRegisterCounter(c.into_raw(), tv) }
        };
        Counters {
            sessions: reg("sessions"),
            records: reg("records"),
            packets: reg("packets"),
            bytes: reg("bytes"),
            verdicts: reg("verdicts"),
            drops: reg("drops"),
            flows: reg("flows"),
            errors: reg("errors"),
            bypasses: reg("bypasses"),
            keepalives: reg("keepalives"),
        }
    }
}

impl Ctx {
    fn update_stats(&mut self) {
        let tv = self.insp.tv;
        let s = &self.worker.engine.stats;
        let w = &self.worker.stats;
        let c = &self.counters;
        unsafe {
            ffi::StatsSetUI64(tv, c.sessions, self.worker.sessions() as u64);
            ffi::StatsSetUI64(tv, c.records, s.records);
            ffi::StatsSetUI64(tv, c.packets, s.packets);
            ffi::StatsSetUI64(tv, c.bytes, s.bytes);
            ffi::StatsSetUI64(tv, c.verdicts, s.verdicts);
            ffi::StatsSetUI64(tv, c.drops, s.drops);
            ffi::StatsSetUI64(tv, c.flows, s.flows_opened);
            ffi::StatsSetUI64(
                tv,
                c.errors,
                s.flow_errors + s.engine_failures + w.protocol_errors + w.handshake_failures,
            );
            ffi::StatsSetUI64(tv, c.bypasses, s.bypasses);
            ffi::StatsSetUI64(tv, c.keepalives, s.keepalives);
        }
    }
}

pub extern "C" fn runmode_workers() -> c_int {
    let cfg = config();
    unsafe { ffi::suritap_time_mode_live() };
    if let Err(e) = std::fs::create_dir_all(&cfg.socket_dir) {
        log::error(&format!("suritap: cannot create {}: {e}", cfg.socket_dir.display()));
        return -1;
    }
    let iface = CString::new(LIVE_DEVICE).unwrap();
    for i in 0..cfg.threads {
        let name = CString::new(format!("W#{:02}-suritap", i + 1)).unwrap();
        let init = Box::into_raw(Box::new(Init { index: i })) as *mut c_void;
        if unsafe { ffi::suritap_spawn_worker(name.as_ptr(), iface.as_ptr(), init) } != 0 {
            log::error("suritap: failed to spawn worker thread");
            return -1;
        }
    }
    log::notice(&format!(
        "suritap: {} worker(s), sockets in {}, engine in {} mode",
        cfg.threads,
        cfg.socket_dir.display(),
        if cfg.ips { "IPS" } else { "IDS" }
    ));
    0
}

extern "C" fn thread_init(tv: *mut ThreadVars, initdata: *const c_void, data: *mut *mut c_void) -> TmEcode {
    let init = unsafe { Box::from_raw(initdata as *mut Init) };
    let cfg = config();
    let mut wc = WorkerConfig::new(
        cfg.socket_dir.join(format!("worker-{}.sock", init.index)),
        init.index,
        cfg.threads,
    );
    wc.socket_mode = cfg.socket_mode;
    wc.max_sessions = cfg.max_sessions;
    wc.limits = RegionLimits {
        max_region: cfg.max_region,
    };
    wc.engine = EngineConfig {
        max_segment: cfg.max_segment,
        ack_threshold: cfg.ack_threshold,
        max_flows: cfg.max_flows,
        max_total_flows: cfg.max_worker_flows,
        discriminator: cfg.discriminator,
        keepalive: cfg.keepalive,
    };
    wc.batch = cfg.batch;
    wc.spin = cfg.spin;
    wc.log = log::server;
    let worker = match Worker::new(wc) {
        Ok(w) => w,
        Err(e) => {
            log::error(&format!("suritap: worker {} cannot listen: {e}", init.index));
            return TM_ECODE_FAILED;
        }
    };
    let ctx = Box::new(Ctx {
        breaker: worker.breaker(),
        worker,
        // No live device: there is no interface behind the packets.
        insp: SuriInspector {
            tv,
            slot_next: ptr::null_mut(),
            dev: ptr::null_mut(),
        },
        idle_ms: cfg.idle_ms,
        counters: Counters::register(tv),
        last_stats: Instant::now(),
    });
    unsafe { *data = Box::into_raw(ctx) as *mut c_void };
    TM_ECODE_OK
}

extern "C" fn recv_loop(tv: *mut ThreadVars, data: *mut c_void, slot: *mut c_void) -> TmEcode {
    let ctx = unsafe { &mut *(data as *mut Ctx) };
    ctx.insp.slot_next = unsafe { ffi::suritap_slot_next(slot) };
    unsafe { ffi::suritap_thread_running(tv) };
    let mut busy_passes = 0u32;
    loop {
        if unsafe { ffi::suritap_should_stop() } != 0 {
            break;
        }
        let busy = ctx.worker.run_once(&mut ctx.insp, ctx.idle_ms);
        if busy {
            busy_passes = busy_passes.wrapping_add(1);
        }
        // House keeping: packets injected by the flow manager and the
        // detect reload handshake.
        if !busy || busy_passes % 1024 == 0 {
            unsafe { ffi::suritap_capture_timeout(tv) };
        }
        if ctx.last_stats.elapsed() >= Duration::from_secs(1) {
            ctx.update_stats();
            ctx.last_stats = Instant::now();
        }
    }
    ctx.update_stats();
    ctx.worker.shutdown();
    TM_ECODE_OK
}

extern "C" fn break_loop(_tv: *mut ThreadVars, data: *mut c_void) -> TmEcode {
    if !data.is_null() {
        unsafe { (*(data as *mut Ctx)).breaker.wake() };
    }
    TM_ECODE_OK
}

extern "C" fn exit_stats(_tv: *mut ThreadVars, data: *mut c_void) {
    if data.is_null() {
        return;
    }
    let ctx = unsafe { &*(data as *mut Ctx) };
    let s = &ctx.worker.engine.stats;
    let w = &ctx.worker.stats;
    log::notice(&format!(
        "suritap worker {}: sessions {}/{} records {} packets {} bytes {} verdicts {} drops {} flows {}/{} flow-errors {} engine-failures {} protocol-errors {}",
        ctx.worker.config().index,
        w.sessions_opened,
        w.sessions_closed,
        s.records,
        s.packets,
        s.bytes,
        s.verdicts,
        s.drops,
        s.flows_opened,
        s.flows_closed,
        s.flow_errors,
        s.engine_failures,
        w.protocol_errors
    ));
}

extern "C" fn thread_deinit(_tv: *mut ThreadVars, data: *mut c_void) -> TmEcode {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(data as *mut Ctx) });
    }
    TM_ECODE_OK
}
