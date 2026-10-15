//! The shared memory region of a session.
//!
//! Layout (all offsets in bytes, integers little-endian):
//!
//! ```text
//! 0      header page (4096)
//!          0  u32 magic "STAP"     4 u16 version   6 u16 header size
//!          8  u32 flags           16 u64 region size
//!         24  u64 c2s offset      32 u64 c2s size
//!         40  u64 s2c offset      48 u64 s2c size
//!       1024  c2s ring control (head, tail, waiting flags; 64-byte lines)
//!       2048  s2c ring control
//! 4096   c2s ring data   (power of two)
//! ...    s2c ring data   (power of two)
//! ```
//!
//! The client creates the memfd and seals its size (`F_SEAL_SHRINK |
//! F_SEAL_GROW | F_SEAL_SEAL`) so the server can never fault on a truncated
//! mapping. The server reads the header once and validates it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};

use crate::proto::MAGIC;
use crate::ring::{RawRing, CTL_SIZE};

pub const HEADER_SIZE: usize = 4096;
pub const LAYOUT_VERSION: u16 = 1;
pub const MIN_RING: usize = 64 * 1024;
pub const MAX_RING: usize = 1 << 30;

const H_MAGIC: usize = 0;
const H_VERSION: usize = 4;
const H_HEADER_SIZE: usize = 6;
const H_REGION_SIZE: usize = 16;
const H_C2S_OFF: usize = 24;
const H_C2S_SIZE: usize = 32;
const H_S2C_OFF: usize = 40;
const H_S2C_SIZE: usize = 48;
const CTL_C2S: usize = 1024;
const CTL_S2C: usize = 2048;

/// Limits a server applies to client-provided regions.
#[derive(Clone, Copy, Debug)]
pub struct RegionLimits {
    pub max_region: usize,
}

impl Default for RegionLimits {
    fn default() -> Self {
        RegionLimits { max_region: 64 << 20 }
    }
}

/// A mapped session region.
pub struct Region {
    base: NonNull<u8>,
    len: usize,
    fd: OwnedFd,
    c2s_size: usize,
    s2c_size: usize,
}

unsafe impl Send for Region {}
unsafe impl Sync for Region {}

fn check_ring(size: usize) -> io::Result<()> {
    if !size.is_power_of_two() || !(MIN_RING..=MAX_RING).contains(&size) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("ring size {size} must be a power of two in [{MIN_RING}, {MAX_RING}]"),
        ));
    }
    Ok(())
}

unsafe fn map(fd: RawFd, len: usize) -> io::Result<NonNull<u8>> {
    let p = libc::mmap(
        ptr::null_mut(),
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if p == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(NonNull::new_unchecked(p as *mut u8))
}

impl Region {
    /// Creates and maps a new sealed region (client side).
    pub fn create(c2s_size: usize, s2c_size: usize) -> io::Result<Region> {
        check_ring(c2s_size)?;
        check_ring(s2c_size)?;
        let len = HEADER_SIZE + c2s_size + s2c_size;
        let raw = unsafe { libc::memfd_create(c"suritap".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let base = unsafe { map(fd.as_raw_fd(), len)? };
        let r = Region {
            base,
            len,
            fd,
            c2s_size,
            s2c_size,
        };
        unsafe {
            let b = base.as_ptr();
            ptr::write(b.add(H_MAGIC) as *mut u32, MAGIC.to_le());
            ptr::write(b.add(H_VERSION) as *mut u16, LAYOUT_VERSION.to_le());
            ptr::write(b.add(H_HEADER_SIZE) as *mut u16, (HEADER_SIZE as u16).to_le());
            ptr::write(b.add(H_REGION_SIZE) as *mut u64, (len as u64).to_le());
            ptr::write(b.add(H_C2S_OFF) as *mut u64, (HEADER_SIZE as u64).to_le());
            ptr::write(b.add(H_C2S_SIZE) as *mut u64, (c2s_size as u64).to_le());
            ptr::write(b.add(H_S2C_OFF) as *mut u64, ((HEADER_SIZE + c2s_size) as u64).to_le());
            ptr::write(b.add(H_S2C_SIZE) as *mut u64, (s2c_size as u64).to_le());
        }
        Ok(r)
    }

    /// Maps and validates a region received from a client (server side).
    pub fn open(fd: OwnedFd, limits: &RegionLimits) -> Result<Region, String> {
        let raw = fd.as_raw_fd();
        let seals = unsafe { libc::fcntl(raw, libc::F_GET_SEALS) };
        if seals < 0 || seals & libc::F_SEAL_SHRINK == 0 {
            return Err("region must be a memfd sealed against shrinking".into());
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } < 0 {
            return Err(format!("fstat: {}", io::Error::last_os_error()));
        }
        let len = st.st_size as usize;
        if len < HEADER_SIZE + 2 * MIN_RING || len > limits.max_region {
            return Err(format!("region size {len} out of range (max {})", limits.max_region));
        }
        let base = unsafe { map(raw, len) }.map_err(|e| format!("mmap: {e}"))?;
        let mut r = Region {
            base,
            len,
            fd,
            c2s_size: 0,
            s2c_size: 0,
        };
        let rd64 = |off: usize| u64::from_le(unsafe { ptr::read_volatile(base.as_ptr().add(off) as *const u64) });
        let rd32 = |off: usize| u32::from_le(unsafe { ptr::read_volatile(base.as_ptr().add(off) as *const u32) });
        let rd16 = |off: usize| u16::from_le(unsafe { ptr::read_volatile(base.as_ptr().add(off) as *const u16) });
        if rd32(H_MAGIC) != MAGIC || rd16(H_VERSION) != LAYOUT_VERSION || rd16(H_HEADER_SIZE) as usize != HEADER_SIZE {
            return Err("bad region header".into());
        }
        let c2s_size = rd64(H_C2S_SIZE) as usize;
        let s2c_size = rd64(H_S2C_SIZE) as usize;
        check_ring(c2s_size).map_err(|e| e.to_string())?;
        check_ring(s2c_size).map_err(|e| e.to_string())?;
        if rd64(H_REGION_SIZE) as usize != len
            || rd64(H_C2S_OFF) as usize != HEADER_SIZE
            || rd64(H_S2C_OFF) as usize != HEADER_SIZE + c2s_size
            || HEADER_SIZE + c2s_size + s2c_size != len
        {
            return Err("inconsistent region layout".into());
        }
        for ctl in [CTL_C2S, CTL_S2C] {
            if rd64(ctl) != 0 || rd64(ctl + 64) != 0 {
                return Err("ring indices must start at zero".into());
            }
        }
        r.c2s_size = c2s_size;
        r.s2c_size = s2c_size;
        Ok(r)
    }

    pub(crate) fn c2s_ring(&self) -> RawRing {
        unsafe {
            RawRing::new(
                self.base.as_ptr().add(CTL_C2S),
                self.base.as_ptr().add(HEADER_SIZE),
                self.c2s_size,
            )
        }
    }

    pub(crate) fn s2c_ring(&self) -> RawRing {
        unsafe {
            RawRing::new(
                self.base.as_ptr().add(CTL_S2C),
                self.base.as_ptr().add(HEADER_SIZE + self.c2s_size),
                self.s2c_size,
            )
        }
    }

    pub fn c2s_size(&self) -> usize {
        self.c2s_size
    }

    pub fn s2c_size(&self) -> usize {
        self.s2c_size
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base.as_ptr() as *mut libc::c_void, self.len) };
    }
}

const _: () = assert!(CTL_C2S + CTL_SIZE <= CTL_S2C && CTL_S2C + CTL_SIZE <= HEADER_SIZE);

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, OwnedFd};

    fn dup(fd: RawFd) -> OwnedFd {
        unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }
            .as_fd()
            .try_clone_to_owned()
            .unwrap()
    }

    #[test]
    fn create_and_open() {
        let r = Region::create(MIN_RING, MIN_RING * 2).unwrap();
        let s = Region::open(dup(r.fd()), &RegionLimits::default()).unwrap();
        assert_eq!(s.c2s_size(), MIN_RING);
        assert_eq!(s.s2c_size(), MIN_RING * 2);
        // Both mappings share memory.
        let (mut p, mut c) = (
            crate::ring::Producer::new(r.c2s_ring()),
            crate::ring::Consumer::new(s.c2s_ring()),
        );
        assert!(p.push(9, 1, &[b"hello"]));
        p.publish();
        let rec = c.peek().unwrap().unwrap();
        assert_eq!((rec.kind, rec.len()), (9, 5));
    }

    #[test]
    fn rejects_unsealed_and_oversized() {
        let raw = unsafe { libc::memfd_create(c"x".as_ptr(), libc::MFD_CLOEXEC) };
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        unsafe { libc::ftruncate(raw, (HEADER_SIZE + 2 * MIN_RING) as libc::off_t) };
        assert!(Region::open(fd, &RegionLimits::default()).is_err());

        let r = Region::create(MIN_RING, MIN_RING).unwrap();
        let limits = RegionLimits {
            max_region: HEADER_SIZE + MIN_RING,
        };
        assert!(Region::open(dup(r.fd()), &limits).is_err());
    }

    #[test]
    fn rejects_bad_layout() {
        let r = Region::create(MIN_RING, MIN_RING).unwrap();
        unsafe {
            ptr::write(
                r.base.as_ptr().add(H_C2S_SIZE) as *mut u64,
                (MIN_RING as u64 * 2).to_le(),
            )
        };
        assert!(Region::open(dup(r.fd()), &RegionLimits::default()).is_err());
    }
}
