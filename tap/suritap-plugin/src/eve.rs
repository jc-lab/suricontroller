//! Connection metadata in EVE and bypass detection.
//!
//! The first packet of every synthetic flow carries the connection's
//! [`FlowMeta`]; a flow init callback stores it in flow storage and an EVE
//! callback appends it to every record of that flow:
//!
//! ```json
//! "suritap": {"cid": 42, "session": 16777217, "client": "kong", "sni": "api.example.com"}
//! ```

use std::ffi::{c_void, CString};
use std::sync::{Arc, OnceLock};

use suritap::engine::FlowMeta;
use suritap::proto::MetaTag;

use crate::ffi::{self, Flow, FlowStorageId, Packet, SCJsonBuilder, ThreadVars};
use crate::{log, worker};

static STORAGE: OnceLock<FlowStorageId> = OnceLock::new();

/// Field names, NUL-terminated, indexed by tag.
static TAG_KEYS: OnceLock<Vec<Option<CString>>> = OnceLock::new();

pub fn register() {
    let id = unsafe {
        ffi::FlowStorageRegister(
            c"suritap".as_ptr(),
            std::mem::size_of::<*mut c_void>() as u32,
            None,
            free_meta,
        )
    };
    if id.id < 0 {
        log::warning("suritap: flow storage unavailable; EVE records will not carry connection metadata");
    } else {
        let _ = STORAGE.set(id);
        unsafe {
            ffi::SCFlowRegisterInitCallback(on_flow_init, std::ptr::null_mut());
            ffi::SCEveRegisterCallback(on_eve, std::ptr::null_mut());
        }
    }
    unsafe { ffi::SCFlowRegisterUpdateCallback(on_flow_update, std::ptr::null_mut()) };
    let _ = TAG_KEYS.set(
        (0..=u8::MAX)
            .map(|t| MetaTag::name(t).map(|n| CString::new(n).unwrap()))
            .collect(),
    );
}

extern "C" fn free_meta(ptr: *mut c_void) {
    if !ptr.is_null() {
        drop(unsafe { Arc::from_raw(ptr as *const FlowMeta) });
    }
}

extern "C" fn on_flow_init(_tv: *mut ThreadVars, f: *mut Flow, p: *const Packet, _user: *mut c_void) {
    let Some(id) = STORAGE.get() else { return };
    if let Some(meta) = worker::current_meta(p) {
        let raw = Arc::into_raw(meta) as *mut c_void;
        if unsafe { ffi::FlowSetStorageById(f, *id, raw) } != 0 {
            free_meta(raw);
        }
    }
}

extern "C" fn on_flow_update(_tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet, _user: *mut c_void) {
    if unsafe { ffi::suritap_flow_bypassed(f) } != 0 {
        worker::mark_bypass(p);
    }
}

extern "C" fn on_eve(
    _tv: *mut ThreadVars,
    _p: *const Packet,
    f: *mut Flow,
    jb: *mut SCJsonBuilder,
    _user: *mut c_void,
) {
    let Some(id) = STORAGE.get() else { return };
    if f.is_null() {
        return;
    }
    let ptr = unsafe { ffi::FlowGetStorageById(f, *id) } as *const FlowMeta;
    if ptr.is_null() {
        return;
    }
    let meta = unsafe { &*ptr };
    let keys = TAG_KEYS.get().unwrap();
    unsafe {
        ffi::SCJbOpenObject(jb, c"suritap".as_ptr());
        ffi::SCJbSetUint(jb, c"cid".as_ptr(), meta.cid);
        ffi::SCJbSetUint(jb, c"session".as_ptr(), meta.session as u64);
        ffi::SCJbSetStringFromBytes(jb, c"client".as_ptr(), meta.client.as_ptr(), meta.client.len() as u32);
        for (tag, value) in &meta.tags {
            if let Some(key) = &keys[*tag as usize] {
                ffi::SCJbSetStringFromBytes(jb, key.as_ptr(), value.as_ptr(), value.len() as u32);
            }
        }
        ffi::SCJbClose(jb);
    }
}
