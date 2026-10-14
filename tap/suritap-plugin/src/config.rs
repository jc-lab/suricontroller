//! `suritap:` section of suricata.yaml.
//!
//! ```yaml
//! suritap:
//!   socket-dir: /run/suritap   # worker-N.sock files are created here
//!   socket-mode: "0660"        # optional chmod of the sockets
//!   threads: auto              # worker threads (auto = online CPUs)
//!   ips: yes                   # engine in IPS mode (verdicts can drop)
//!   max-sessions: 256          # per worker
//!   max-flows: 65536           # per session
//!   max-segment: 32kb          # TCP payload per synthetic packet
//!   ack-threshold: 256kb       # unacknowledged bytes before a pure ACK
//!   max-region-size: 64mb      # largest shared memory region accepted
//!   batch: 64                  # records per session per pass
//!   spin-us: 0                 # busy-poll before sleeping
//!   idle-ms: 100               # sleep slice (housekeeping interval)
//!   discriminator: yes         # per-connection VLAN ids in the flow key
//!   keepalive: auto            # seconds; auto = flow-timeouts.tcp.established / 3
//! ```
//!
//! The discriminator needs `vlan.use-for-tracking` (default on); EVE
//! records then carry two VLAN ids that identify the connection.
//!
//! `--capture-plugin-args` may override `socket-dir`.

use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::time::Duration;

use crate::ffi;

/// Interface name given to worker threads (no device is registered).
pub const LIVE_DEVICE: &str = "suritap";

#[derive(Clone, Debug)]
pub struct Config {
    pub socket_dir: PathBuf,
    pub socket_mode: Option<u32>,
    pub threads: u16,
    pub ips: bool,
    pub max_sessions: usize,
    pub max_flows: usize,
    pub max_segment: usize,
    pub ack_threshold: u64,
    pub max_region: usize,
    pub batch: usize,
    pub spin: Duration,
    pub idle_ms: i32,
    pub discriminator: bool,
    pub keepalive: Duration,
}

fn get(key: &str) -> Option<String> {
    conf_value(&format!("suritap.{key}"))
}

fn conf_value(key: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let mut v: *const std::os::raw::c_char = std::ptr::null();
    if unsafe { ffi::SCConfGet(k.as_ptr(), &mut v) } == 1 && !v.is_null() {
        Some(unsafe { CStr::from_ptr(v) }.to_string_lossy().into_owned())
    } else {
        None
    }
}

fn get_bool(key: &str, default: bool) -> bool {
    conf_bool(&format!("suritap.{key}"), default)
}

fn conf_bool(key: &str, default: bool) -> bool {
    let k = CString::new(key).unwrap();
    let mut v = 0;
    if unsafe { ffi::SCConfGetBool(k.as_ptr(), &mut v) } == 1 {
        v != 0
    } else {
        default
    }
}

fn get_size(key: &str, default: u64) -> Result<u64, String> {
    let Some(s) = get(key) else { return Ok(default) };
    let c = CString::new(s.clone()).unwrap();
    let mut v = 0u64;
    if unsafe { ffi::ParseSizeStringU64(c.as_ptr(), &mut v) } < 0 {
        return Err(format!("suritap.{key}: invalid size '{s}'"));
    }
    Ok(v)
}

fn get_num<T: std::str::FromStr>(key: &str, default: T) -> Result<T, String> {
    match get(key) {
        None => Ok(default),
        Some(s) => s
            .trim()
            .parse()
            .map_err(|_| format!("suritap.{key}: invalid number '{s}'")),
    }
}

impl Config {
    pub fn load(args: &str) -> Result<Config, String> {
        let socket_dir = if !args.trim().is_empty() {
            PathBuf::from(args.trim())
        } else {
            PathBuf::from(get("socket-dir").unwrap_or_else(|| "/run/suritap".into()))
        };
        let socket_mode = match get("socket-mode") {
            None => None,
            Some(m) => Some(
                u32::from_str_radix(m.trim().trim_start_matches("0o"), 8)
                    .map_err(|_| format!("suritap.socket-mode: invalid octal mode '{m}'"))?,
            ),
        };
        let threads = match get("threads").as_deref().map(str::trim) {
            None | Some("auto") => unsafe { ffi::UtilCpuGetNumProcessorsOnline() }.max(1),
            Some(n) => n.parse().map_err(|_| format!("suritap.threads: invalid value '{n}'"))?,
        };
        if threads == 0 {
            return Err("suritap.threads must be at least 1".into());
        }
        let keepalive = match get("keepalive").as_deref().map(str::trim) {
            None | Some("auto") => {
                // Default Suricata TCP established timeout is 600 s.
                let est: u64 = match conf_value("flow-timeouts.tcp.established") {
                    Some(v) => v
                        .trim()
                        .parse()
                        .map_err(|_| format!("flow-timeouts.tcp.established: invalid value '{v}'"))?,
                    None => 600,
                };
                Duration::from_secs((est / 3).max(5))
            }
            Some(v) => Duration::from_secs(
                v.parse()
                    .map_err(|_| format!("suritap.keepalive: invalid seconds '{v}'"))?,
            ),
        };
        let discriminator = get_bool("discriminator", true);
        if discriminator && conf_value("vlan.use-for-tracking").is_some() && !conf_bool("vlan.use-for-tracking", true) {
            return Err("suritap.discriminator needs vlan.use-for-tracking: true".into());
        }
        Ok(Config {
            socket_dir,
            socket_mode,
            threads,
            ips: get_bool("ips", true),
            max_sessions: get_num("max-sessions", 256)?,
            max_flows: get_num("max-flows", 65536)?,
            max_segment: get_size("max-segment", 32 * 1024)? as usize,
            ack_threshold: get_size("ack-threshold", 256 * 1024)?,
            max_region: get_size("max-region-size", 64 << 20)? as usize,
            batch: get_num("batch", 64usize)?.max(1),
            spin: Duration::from_micros(get_num("spin-us", 0u64)?),
            idle_ms: get_num("idle-ms", 100i32)?.clamp(1, 1000),
            discriminator,
            keepalive,
        })
    }
}
