//! Suricata capture plugin `suritap`.
//!
//! Load it with
//!
//! ```yaml
//! plugins:
//!   - /usr/lib/suricata/suritap.so
//! suritap:
//!   socket-dir: /run/suritap
//! ```
//!
//! and run `suricata --capture-plugin=suritap`. Each worker thread listens
//! on `socket-dir/worker-N.sock`; proxies connect with the suritap Go or
//! Rust client and stream plaintext through shared memory. The engine runs
//! in IPS mode (stream inline) so every DATA record can be answered with a
//! verdict.

mod config;
mod eve;
mod ffi;
mod worker;

use std::ffi::{c_char, c_int, CStr};
use std::sync::OnceLock;

pub(crate) use config::Config;

static CONFIG: OnceLock<Config> = OnceLock::new();

pub(crate) fn config() -> &'static Config {
    CONFIG.get().expect("suritap capture plugin not initialized")
}

pub(crate) mod log {
    use std::ffi::CString;

    fn emit(level: std::os::raw::c_int, msg: &str) {
        let msg = CString::new(msg.replace('\0', " ")).unwrap();
        unsafe { crate::ffi::suritap_log(level, msg.as_ptr()) };
    }

    pub fn error(msg: &str) {
        emit(unsafe { crate::ffi::suritap_log_level_error() }, msg)
    }
    pub fn warning(msg: &str) {
        emit(unsafe { crate::ffi::suritap_log_level_warning() }, msg)
    }
    pub fn notice(msg: &str) {
        emit(unsafe { crate::ffi::suritap_log_level_notice() }, msg)
    }
    pub fn info(msg: &str) {
        emit(unsafe { crate::ffi::suritap_log_level_info() }, msg)
    }
    pub fn debug(msg: &str) {
        emit(unsafe { crate::ffi::suritap_log_level_debug() }, msg)
    }

    /// Adapter for `suritap::server::LogFn`.
    pub fn server(level: suritap::server::Level, msg: &str) {
        use suritap::server::Level::*;
        match level {
            Error => error(msg),
            Warning => warning(msg),
            Notice => notice(msg),
            Info => info(msg),
            Debug => debug(msg),
        }
    }
}

/// `SCPlugin` (suricata-plugin.h).
#[repr(C)]
pub struct SCPlugin {
    version: u64,
    suricata_version: *const c_char,
    name: *const c_char,
    plugin_version: *const c_char,
    license: *const c_char,
    author: *const c_char,
    init: extern "C" fn(),
}

unsafe impl Sync for SCPlugin {}

/// `SC_API_VERSION` of Suricata 8.0.
const SC_API_VERSION: u64 = 0x0800;

const SURICATA_VERSION: &CStr = match CStr::from_bytes_with_nul(concat!(env!("SURICATA_VERSION"), "\0").as_bytes()) {
    Ok(s) => s,
    Err(_) => panic!("bad version"),
};

const PLUGIN_VERSION: &CStr = match CStr::from_bytes_with_nul(concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes()) {
    Ok(s) => s,
    Err(_) => panic!("bad version"),
};

static PLUGIN: SCPlugin = SCPlugin {
    version: SC_API_VERSION,
    suricata_version: SURICATA_VERSION.as_ptr(),
    name: c"suritap".as_ptr(),
    plugin_version: PLUGIN_VERSION.as_ptr(),
    license: c"GPL-2.0-only".as_ptr(),
    author: c"jc-lab suricontroller".as_ptr(),
    init: plugin_init,
};

/// Entry point looked up by Suricata's plugin loader.
#[no_mangle]
pub extern "C" fn SCPluginRegister() -> *const SCPlugin {
    &PLUGIN
}

extern "C" fn plugin_init() {
    let running = unsafe { CStr::from_ptr(ffi::suritap_suricata_version()) };
    if running != SURICATA_VERSION {
        // The shim was compiled against another tree: struct layouts may differ.
        log::error(&format!(
            "suritap was built for Suricata {} but is loaded into {}; refusing to register",
            SURICATA_VERSION.to_string_lossy(),
            running.to_string_lossy()
        ));
        return;
    }
    if unsafe { ffi::suritap_register_capture(c"suritap".as_ptr(), capture_init, default_mode) } != 0 {
        log::error("failed to register the suritap capture plugin");
        return;
    }
    eve::register();
}

extern "C" fn default_mode() -> *const c_char {
    c"workers".as_ptr()
}

extern "C" fn capture_init(args: *const c_char, plugin_slot: c_int, receive_slot: c_int, decode_slot: c_int) {
    let args = if args.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(args) }.to_string_lossy().into_owned()
    };
    let cfg = match Config::load(&args) {
        Ok(c) => c,
        Err(e) => {
            log::error(&format!("suritap: invalid configuration: {e}"));
            std::process::exit(1);
        }
    };
    let _ = CONFIG.set(cfg);
    unsafe {
        ffi::RunModeRegisterNewRunMode(
            plugin_slot,
            c"workers".as_ptr(),
            c"Workers suritap mode, each thread serves its own socket and sessions".as_ptr(),
            worker::runmode_workers,
            runmode_is_ips,
        );
        ffi::suritap_register_modules(receive_slot, decode_slot, &worker::CALLBACKS);
    }
}

extern "C" fn runmode_is_ips() -> c_int {
    if config().ips {
        unsafe { ffi::suritap_engine_mode_ips() };
        1
    } else {
        0
    }
}
