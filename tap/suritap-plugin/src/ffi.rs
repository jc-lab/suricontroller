//! Declarations of the C glue (shim/shim.c) and of exported Suricata
//! functions with stable, simple signatures.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

use suritap::engine::Outcome;

pub enum ThreadVars {}
pub enum Packet {}
pub enum LiveDevice {}
pub enum Flow {}
pub enum SCJsonBuilder {}

pub type TmEcode = c_int;
pub const TM_ECODE_OK: TmEcode = 0;
pub const TM_ECODE_FAILED: TmEcode = 1;

#[repr(C)]
pub struct Callbacks {
    pub thread_init: extern "C" fn(*mut ThreadVars, *const c_void, *mut *mut c_void) -> TmEcode,
    pub r#loop: extern "C" fn(*mut ThreadVars, *mut c_void, *mut c_void) -> TmEcode,
    pub break_loop: extern "C" fn(*mut ThreadVars, *mut c_void) -> TmEcode,
    pub thread_deinit: extern "C" fn(*mut ThreadVars, *mut c_void) -> TmEcode,
    pub exit_stats: extern "C" fn(*mut ThreadVars, *mut c_void),
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowStorageId {
    pub id: c_int,
}

extern "C" {
    // shim.c
    pub fn suritap_suricata_version() -> *const c_char;
    pub fn suritap_log(level: c_int, msg: *const c_char);
    pub fn suritap_log_level_error() -> c_int;
    pub fn suritap_log_level_warning() -> c_int;
    pub fn suritap_log_level_notice() -> c_int;
    pub fn suritap_log_level_info() -> c_int;
    pub fn suritap_log_level_debug() -> c_int;
    pub fn suritap_register_capture(
        name: *const c_char,
        init: extern "C" fn(*const c_char, c_int, c_int, c_int),
        default_mode: extern "C" fn() -> *const c_char,
    ) -> c_int;
    pub fn suritap_register_modules(receive_slot: c_int, decode_slot: c_int, cb: *const Callbacks);
    pub fn suritap_spawn_worker(name: *const c_char, iface: *const c_char, initdata: *mut c_void) -> c_int;
    pub fn suritap_time_mode_live();
    pub fn suritap_engine_mode_ips();
    pub fn suritap_should_stop() -> c_int;
    pub fn suritap_thread_running(tv: *mut ThreadVars);
    pub fn suritap_slot_next(slot: *mut c_void) -> *mut c_void;
    pub fn suritap_capture_timeout(tv: *mut ThreadVars);
    pub fn suritap_packet_get() -> *mut Packet;
    pub fn suritap_packet_setup(
        p: *mut Packet,
        data: *const u8,
        len: u32,
        dev: *mut LiveDevice,
        release: extern "C" fn(*mut Packet),
        tenant: u32,
        vlan0: u16,
        vlan1: u16,
    );
    pub fn suritap_process(tv: *mut ThreadVars, slot_next: *mut c_void, p: *mut Packet, dev: *mut LiveDevice) -> c_int;
    pub fn suritap_packet_data(p: *const Packet) -> *const u8;
    pub fn suritap_packet_outcome(p: *const Packet, o: *mut Outcome);
    pub fn suritap_packet_release(p: *mut Packet);
    pub fn suritap_flow_bypassed(f: *const Flow) -> c_int;

    // Suricata
    pub fn RunModeRegisterNewRunMode(
        runmode: c_int,
        name: *const c_char,
        description: *const c_char,
        func: extern "C" fn() -> c_int,
        is_ips: extern "C" fn() -> c_int,
    );
    pub fn SCConfGet(name: *const c_char, vptr: *mut *const c_char) -> c_int;
    pub fn SCConfGetBool(name: *const c_char, val: *mut c_int) -> c_int;
    pub fn ParseSizeStringU64(s: *const c_char, res: *mut u64) -> c_int;
    pub fn UtilCpuGetNumProcessorsOnline() -> u16;
    pub fn StatsRegisterCounter(name: *const c_char, tv: *mut ThreadVars) -> u16;
    pub fn StatsSetUI64(tv: *mut ThreadVars, id: u16, v: u64);
    pub fn FlowStorageRegister(
        name: *const c_char,
        size: u32,
        alloc: Option<extern "C" fn(u32) -> *mut c_void>,
        free: extern "C" fn(*mut c_void),
    ) -> FlowStorageId;
    pub fn FlowGetStorageById(f: *const Flow, id: FlowStorageId) -> *mut c_void;
    pub fn FlowSetStorageById(f: *mut Flow, id: FlowStorageId, ptr: *mut c_void) -> c_int;
    pub fn SCFlowRegisterInitCallback(
        f: extern "C" fn(*mut ThreadVars, *mut Flow, *const Packet, *mut c_void),
        user: *mut c_void,
    ) -> bool;
    pub fn SCFlowRegisterUpdateCallback(
        f: extern "C" fn(*mut ThreadVars, *mut Flow, *mut Packet, *mut c_void),
        user: *mut c_void,
    ) -> bool;
    pub fn SCEveRegisterCallback(
        f: extern "C" fn(*mut ThreadVars, *const Packet, *mut Flow, *mut SCJsonBuilder, *mut c_void),
        user: *mut c_void,
    ) -> bool;
    pub fn SCJbOpenObject(jb: *mut SCJsonBuilder, key: *const c_char) -> bool;
    pub fn SCJbSetUint(jb: *mut SCJsonBuilder, key: *const c_char, val: u64) -> bool;
    pub fn SCJbSetStringFromBytes(jb: *mut SCJsonBuilder, key: *const c_char, bytes: *const u8, len: u32) -> bool;
    pub fn SCJbClose(jb: *mut SCJsonBuilder) -> bool;
}
