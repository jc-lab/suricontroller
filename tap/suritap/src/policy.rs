//! Endpoint policy: the inspection mode of each proxy endpoint (Off,
//! Detect, Prevent), set by the operator (suri-node-agent writes it from the
//! controller's desired state) and pushed to clients in POLICY records.
//!
//! Policy file (`suritap.policy-file`), one endpoint per line:
//!
//! ```text
//! # endpoint   mode
//! websecure    prevent
//! api          detect
//! legacy       off
//! ```
//!
//! Clients look up the endpoint they report in OPEN (meta tag `endpoint`)
//! and fall back to their own setting for endpoints the policy does not
//! list. The engine also enforces it: verdicts of flows whose endpoint is
//! in Off or Detect mode never carry a drop.

use std::collections::HashMap;
use std::fmt;

use crate::proto::{get_u16, get_u32};

/// Inspection mode of an endpoint (wire values of the POLICY record).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Mode {
    /// Not inspected: clients send nothing.
    Off = 1,
    /// Inspected without waiting; never blocked.
    Detect = 2,
    /// Inspected; drop verdicts block.
    Prevent = 3,
}

impl Mode {
    pub fn from_u8(v: u8) -> Option<Mode> {
        match v {
            1 => Some(Mode::Off),
            2 => Some(Mode::Detect),
            3 => Some(Mode::Prevent),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "off" => Some(Mode::Off),
            "detect" => Some(Mode::Detect),
            "prevent" => Some(Mode::Prevent),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Detect => "detect",
            Mode::Prevent => "prevent",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Longest endpoint name.
pub const MAX_NAME: usize = 64;
/// Most endpoints in one policy.
pub const MAX_ENDPOINTS: usize = 256;
/// POLICY body: `version:u32 count:u16 rsv:u16` + per endpoint
/// `mode:u8 len:u8 name[len]`.
pub const POLICY_FIXED: usize = 8;

/// valid_name reports whether s may name an endpoint.
pub fn valid_name(s: &[u8]) -> bool {
    !s.is_empty() && s.len() <= MAX_NAME && s.iter().all(|c| c.is_ascii_alphanumeric() || b"._:@/-".contains(c))
}

/// A parsed policy with its wire encoding.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub version: u32,
    modes: HashMap<Box<[u8]>, Mode>,
    encoded: Vec<u8>,
}

impl Policy {
    /// from_entries builds a policy (later duplicates win).
    pub fn from_entries<'a>(
        version: u32,
        entries: impl IntoIterator<Item = (&'a [u8], Mode)>,
    ) -> Result<Policy, String> {
        let mut modes = HashMap::new();
        let mut order: Vec<Box<[u8]>> = Vec::new();
        for (name, mode) in entries {
            if !valid_name(name) {
                return Err(format!("invalid endpoint name {:?}", String::from_utf8_lossy(name)));
            }
            if modes.insert(Box::<[u8]>::from(name), mode).is_none() {
                order.push(name.into());
            }
            if modes.len() > MAX_ENDPOINTS {
                return Err(format!("more than {MAX_ENDPOINTS} endpoints"));
            }
        }
        let mut encoded = Vec::with_capacity(POLICY_FIXED + order.iter().map(|n| 2 + n.len()).sum::<usize>());
        encoded.extend_from_slice(&version.to_le_bytes());
        encoded.extend_from_slice(&(order.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&[0, 0]);
        for name in &order {
            encoded.push(modes[name] as u8);
            encoded.push(name.len() as u8);
            encoded.extend_from_slice(name);
        }
        Ok(Policy {
            version,
            modes,
            encoded,
        })
    }

    /// parse reads the text format (see the module documentation).
    pub fn parse(version: u32, text: &str) -> Result<Policy, String> {
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(name), Some(mode), None) = (it.next(), it.next(), it.next()) else {
                return Err(format!("line {}: want \"<endpoint> <off|detect|prevent>\"", i + 1));
            };
            let mode = Mode::parse(mode).ok_or_else(|| format!("line {}: unknown mode {mode:?}", i + 1))?;
            entries.push((name.as_bytes(), mode));
        }
        Policy::from_entries(version, entries).map_err(|e| format!("policy: {e}"))
    }

    /// decode parses a POLICY record body.
    pub fn decode(b: &[u8]) -> Result<Policy, String> {
        if b.len() < POLICY_FIXED {
            return Err("short POLICY".into());
        }
        let version = get_u32(b, 0);
        let count = get_u16(b, 4) as usize;
        let mut entries = Vec::with_capacity(count);
        let mut off = POLICY_FIXED;
        for _ in 0..count {
            if off + 2 > b.len() {
                return Err("truncated POLICY".into());
            }
            let mode = Mode::from_u8(b[off]).ok_or("bad POLICY mode")?;
            let len = b[off + 1] as usize;
            off += 2;
            if off + len > b.len() {
                return Err("truncated POLICY".into());
            }
            entries.push((&b[off..off + len], mode));
            off += len;
        }
        Policy::from_entries(version, entries)
    }

    /// mode returns the mode of an endpoint, `None` when it is not listed.
    pub fn mode(&self, endpoint: &[u8]) -> Option<Mode> {
        self.modes.get(endpoint).copied()
    }

    pub fn len(&self) -> usize {
        self.modes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modes.is_empty()
    }

    /// encoded is the POLICY record body.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encode_decode() {
        let p = Policy::parse(
            7,
            "# endpoints\nwebsecure prevent\n\napi detect # comment\nlegacy off\napi prevent\n",
        )
        .unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.mode(b"api"), Some(Mode::Prevent), "later duplicates win");
        assert_eq!(p.mode(b"legacy"), Some(Mode::Off));
        assert_eq!(p.mode(b"other"), None);
        let d = Policy::decode(p.encoded()).unwrap();
        assert_eq!(d.version, 7);
        assert_eq!(d.mode(b"websecure"), Some(Mode::Prevent));
        assert_eq!(d.encoded(), p.encoded());
        assert!(Policy::parse(1, "").unwrap().is_empty());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Policy::parse(1, "a b c").is_err());
        assert!(Policy::parse(1, "a block").is_err());
        assert!(Policy::parse(1, "bad name! detect").is_err());
        assert!(Policy::parse(1, &format!("{} off", "x".repeat(65))).is_err());
        let p = Policy::parse(1, "a off\nb detect").unwrap();
        let enc = p.encoded();
        assert!(Policy::decode(&enc[..enc.len() - 1]).is_err());
        let mut bad = enc.to_vec();
        bad[POLICY_FIXED] = 9;
        assert!(Policy::decode(&bad).is_err());
    }
}
