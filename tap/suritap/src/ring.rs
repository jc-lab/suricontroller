//! Single-producer/single-consumer byte rings in shared memory.
//!
//! Records are 8-byte aligned: `len:u32 | kind:u16 | flags:u16 | body`,
//! little-endian, where `len` counts header and body. A record never wraps:
//! when it does not fit before the end of the ring the producer first
//! writes a PAD record covering the rest. `head` and `tail` are
//! free-running byte counters stored in separate cache lines.
//!
//! Wakeups: a consumer about to sleep sets `consumer_waiting` and re-checks
//! `head`; a producer publishes `head` and then clears the flag, signalling
//! the peer's eventfd only when it was set. Both sides use sequentially
//! consistent accesses for these two words (Dekker style), so a wakeup is
//! never lost and an awake peer costs no system call. The same scheme with
//! `producer_waiting` lets a producer sleep while the ring is full.
//!
//! The peer is not trusted: the consumer validates every length against
//! the ring bounds before use and only copies bytes out of the ring.

use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::*};

pub const HEADER: usize = 8;
pub const KIND_PAD: u16 = 0;

pub(crate) const CTL_SIZE: usize = 256;
const CTL_HEAD: usize = 0;
const CTL_TAIL: usize = 64;
const CTL_CONSUMER_WAITING: usize = 128;
const CTL_PRODUCER_WAITING: usize = 192;

#[inline]
pub const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Raw view of one ring.
#[derive(Clone, Copy)]
pub(crate) struct RawRing {
    ctl: *mut u8,
    data: *mut u8,
    size: usize,
}

unsafe impl Send for RawRing {}

impl RawRing {
    /// # Safety
    /// `ctl` must point to [`CTL_SIZE`] bytes aligned to 64 and `data` to
    /// `size` bytes aligned to 8, both valid for as long as the ring is
    /// used. `size` must be a power of two of at least 64 bytes.
    pub(crate) unsafe fn new(ctl: *mut u8, data: *mut u8, size: usize) -> Self {
        debug_assert!(size.is_power_of_two() && size >= 64);
        RawRing { ctl, data, size }
    }

    #[inline]
    fn word64(&self, off: usize) -> &AtomicU64 {
        unsafe { &*(self.ctl.add(off) as *const AtomicU64) }
    }

    #[inline]
    fn word32(&self, off: usize) -> &AtomicU32 {
        unsafe { &*(self.ctl.add(off) as *const AtomicU32) }
    }

    #[inline]
    fn head(&self) -> &AtomicU64 {
        self.word64(CTL_HEAD)
    }

    #[inline]
    fn tail(&self) -> &AtomicU64 {
        self.word64(CTL_TAIL)
    }

    #[inline]
    fn consumer_waiting(&self) -> &AtomicU32 {
        self.word32(CTL_CONSUMER_WAITING)
    }

    #[inline]
    fn producer_waiting(&self) -> &AtomicU32 {
        self.word32(CTL_PRODUCER_WAITING)
    }
}

/// Writing side of a ring.
pub struct Producer {
    ring: RawRing,
    head: u64,
    tail: u64,
}

impl Producer {
    /// Rings always start empty at offset 0 (checked when a region is
    /// opened). The cursors are not reloaded from shared memory: the peer
    /// could change them after that check and misalign every access.
    pub(crate) fn new(ring: RawRing) -> Self {
        Producer { ring, head: 0, tail: 0 }
    }

    /// Size of the ring in bytes.
    pub fn capacity(&self) -> usize {
        self.ring.size
    }

    /// Largest record (header included) the ring accepts. Bounded to a
    /// quarter of the ring so a record plus padding always fits once the
    /// consumer catches up.
    pub fn max_record(&self) -> usize {
        self.ring.size / 4
    }

    fn free(&self) -> u64 {
        (self.ring.size as u64).saturating_sub(self.head.wrapping_sub(self.tail))
    }

    /// Free bytes right now (reloads the consumer's position).
    pub fn available(&mut self) -> usize {
        self.refresh(Acquire);
        self.free() as usize
    }

    fn refresh(&mut self, order: std::sync::atomic::Ordering) {
        let tail = self.ring.tail().load(order);
        // A tail outside [head - size, head] comes from a misbehaving peer;
        // ignore it, which leaves the ring looking full.
        if self.head.wrapping_sub(tail) <= self.ring.size as u64 {
            self.tail = tail;
        }
    }

    /// Bytes needed (padding included) to push a record with `body` bytes.
    pub fn need(&self, body: usize) -> usize {
        let total = align8(HEADER + body);
        let to_end = self.ring.size - (self.head as usize & (self.ring.size - 1));
        if total > to_end {
            to_end + total
        } else {
            total
        }
    }

    /// Appends a record whose body is the concatenation of `parts`. Returns
    /// false when it does not fit right now (or exceeds [`max_record`]).
    /// The record becomes visible on [`publish`].
    ///
    /// [`max_record`]: Producer::max_record
    /// [`publish`]: Producer::publish
    pub fn push(&mut self, kind: u16, flags: u16, parts: &[&[u8]]) -> bool {
        let body: usize = parts.iter().map(|p| p.len()).sum();
        let len = HEADER + body;
        if len > self.max_record() {
            return false;
        }
        let need = self.need(body) as u64;
        if self.free() < need {
            self.refresh(Acquire);
            if self.free() < need {
                return false;
            }
        }
        let mask = self.ring.size - 1;
        let total = align8(len);
        let mut pos = self.head as usize & mask;
        let to_end = self.ring.size - pos;
        unsafe {
            if total > to_end {
                self.write_header(pos, to_end as u32, KIND_PAD, 0);
                self.head += to_end as u64;
                pos = 0;
            }
            self.write_header(pos, len as u32, kind, flags);
            let mut p = self.ring.data.add(pos + HEADER);
            for part in parts {
                ptr::copy_nonoverlapping(part.as_ptr(), p, part.len());
                p = p.add(part.len());
            }
        }
        self.head += total as u64;
        true
    }

    #[inline]
    unsafe fn write_header(&self, pos: usize, len: u32, kind: u16, flags: u16) {
        let h = (len as u64) | ((kind as u64) << 32) | ((flags as u64) << 48);
        ptr::write(self.ring.data.add(pos) as *mut u64, h.to_le());
    }

    /// Makes pushed records visible. Returns true when the consumer sleeps
    /// and its eventfd must be signalled.
    pub fn publish(&mut self) -> bool {
        self.ring.head().store(self.head, SeqCst);
        self.ring.consumer_waiting().load(SeqCst) != 0 && self.ring.consumer_waiting().swap(0, SeqCst) != 0
    }

    /// Announces that the producer will sleep until `need` bytes are free.
    /// Returns false (and withdraws) if the space appeared meanwhile.
    pub fn prepare_wait(&mut self, need: usize) -> bool {
        self.ring.producer_waiting().store(1, SeqCst);
        self.refresh(SeqCst);
        if self.free() >= need as u64 {
            self.ring.producer_waiting().store(0, Relaxed);
            false
        } else {
            true
        }
    }
}

/// A record inside the ring. The body stays in shared memory and is only
/// valid until the consumer advances past it.
#[derive(Clone, Copy, Debug)]
pub struct Record {
    pub kind: u16,
    pub flags: u16,
    body: *const u8,
    len: usize,
    size: usize,
}

impl Record {
    /// A record whose body lives in a local buffer (socket transport). The
    /// record must not outlive `body`.
    pub fn from_slice(kind: u16, flags: u16, body: &[u8]) -> Record {
        Record {
            kind,
            flags,
            body: body.as_ptr(),
            len: body.len(),
            size: 0,
        }
    }

    /// Body length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copies `dst.len()` body bytes starting at `off`.
    pub fn copy_to(&self, off: usize, dst: &mut [u8]) {
        assert!(off <= self.len && dst.len() <= self.len - off);
        unsafe { ptr::copy_nonoverlapping(self.body.add(off), dst.as_mut_ptr(), dst.len()) }
    }

    /// Copies the first `N` body bytes; `None` when the body is shorter.
    pub fn prefix<const N: usize>(&self) -> Option<[u8; N]> {
        if self.len < N {
            return None;
        }
        let mut a = [0u8; N];
        self.copy_to(0, &mut a);
        Some(a)
    }

    /// Pointer to body byte `off` for zero-copy reads.
    ///
    /// # Safety
    /// The caller must stay within the body and stop using the pointer
    /// before the consumer advances.
    pub unsafe fn body_ptr(&self, off: usize) -> *const u8 {
        self.body.add(off)
    }
}

/// Error for a ring whose producer broke the format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrupt(pub &'static str);

impl std::fmt::Display for Corrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "corrupt ring: {}", self.0)
    }
}

impl std::error::Error for Corrupt {}

/// Reading side of a ring.
pub struct Consumer {
    ring: RawRing,
    tail: u64,
    head: u64,
}

impl Consumer {
    /// Starts at offset 0; see [`Producer::new`].
    pub(crate) fn new(ring: RawRing) -> Self {
        Consumer { ring, tail: 0, head: 0 }
    }

    /// Next record, `Ok(None)` when the ring is empty.
    pub fn peek(&mut self) -> Result<Option<Record>, Corrupt> {
        loop {
            if self.tail == self.head {
                self.head = self.ring.head().load(Acquire);
                if self.tail == self.head {
                    return Ok(None);
                }
            }
            let avail = self.head.wrapping_sub(self.tail);
            if avail > self.ring.size as u64 || avail % 8 != 0 {
                return Err(Corrupt("head out of range"));
            }
            let pos = self.tail as usize & (self.ring.size - 1);
            let to_end = self.ring.size - pos;
            // Read the header once; the peer may scribble on it afterwards.
            let h = u64::from_le(unsafe { ptr::read_volatile(self.ring.data.add(pos) as *const u64) });
            let len = (h & 0xffff_ffff) as usize;
            let kind = (h >> 32) as u16;
            let flags = (h >> 48) as u16;
            if kind == KIND_PAD {
                if len != to_end || len as u64 > avail {
                    return Err(Corrupt("bad padding"));
                }
                self.tail += len as u64;
                continue;
            }
            let size = align8(len);
            if len < HEADER || size > to_end || size as u64 > avail {
                return Err(Corrupt("bad record length"));
            }
            return Ok(Some(Record {
                kind,
                flags,
                body: unsafe { self.ring.data.add(pos + HEADER) },
                len: len - HEADER,
                size,
            }));
        }
    }

    /// Consumes `rec` (returned by the last [`peek`](Consumer::peek)).
    pub fn advance(&mut self, rec: &Record) {
        self.tail += rec.size as u64;
    }

    /// Returns consumed space to the producer. Returns true when the
    /// producer sleeps waiting for space and must be signalled.
    pub fn release(&mut self) -> bool {
        self.ring.tail().store(self.tail, SeqCst);
        self.ring.producer_waiting().load(SeqCst) != 0 && self.ring.producer_waiting().swap(0, SeqCst) != 0
    }

    /// True when there is nothing to read.
    pub fn is_empty(&self) -> bool {
        self.ring.head().load(Acquire) == self.tail
    }

    /// Announces that the consumer will sleep. Returns false (and withdraws)
    /// if records arrived meanwhile.
    pub fn prepare_sleep(&mut self) -> bool {
        self.ring.consumer_waiting().store(1, SeqCst);
        if self.ring.head().load(SeqCst) != self.tail {
            self.ring.consumer_waiting().store(0, Relaxed);
            false
        } else {
            true
        }
    }

    /// Withdraws a sleep announcement after waking up.
    pub fn cancel_sleep(&self) {
        self.ring.consumer_waiting().store(0, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(64))]
    struct Mem<const N: usize> {
        ctl: [u8; CTL_SIZE],
        data: [u8; N],
    }

    fn mem<const N: usize>() -> Box<Mem<N>> {
        Box::new(Mem {
            ctl: [0; CTL_SIZE],
            data: [0; N],
        })
    }

    fn pair<const N: usize>(m: &mut Mem<N>) -> (Producer, Consumer) {
        let r = unsafe { RawRing::new(m.ctl.as_mut_ptr(), m.data.as_mut_ptr(), N) };
        (Producer::new(r), Consumer::new(r))
    }

    #[test]
    fn push_peek_wrap() {
        let mut m = mem::<256>();
        let (mut p, mut c) = pair(&mut m);
        assert_eq!(p.max_record(), 64);
        let mut seen = 0u32;
        let mut sent = 0u32;
        for round in 0..200u32 {
            let body = vec![(round & 0xff) as u8; (round % 40) as usize];
            while !p.push(7, round as u16, &[&round.to_le_bytes(), &body]) {
                p.publish();
                let r = c.peek().unwrap().unwrap();
                let mut n = [0u8; 4];
                r.copy_to(0, &mut n);
                assert_eq!(u32::from_le_bytes(n), seen);
                assert_eq!(r.len(), 4 + (seen % 40) as usize);
                c.advance(&r);
                c.release();
                seen += 1;
            }
            sent += 1;
        }
        p.publish();
        while let Some(r) = c.peek().unwrap() {
            assert_eq!(r.kind, 7);
            assert_eq!(r.flags, seen as u16);
            c.advance(&r);
            seen += 1;
        }
        assert_eq!(seen, sent);
    }

    #[test]
    fn rejects_oversized_and_full() {
        let mut m = mem::<256>();
        let (mut p, _c) = pair(&mut m);
        assert!(!p.push(1, 0, &[&[0u8; 57]]));
        assert!(p.push(1, 0, &[&[0u8; 56]]));
        let mut n = 1;
        while p.push(1, 0, &[&[0u8; 56]]) {
            n += 1;
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn wakeup_flags() {
        let mut m = mem::<256>();
        let (mut p, mut c) = pair(&mut m);
        assert!(c.prepare_sleep());
        assert!(p.push(1, 0, &[]));
        assert!(p.publish(), "sleeping consumer must be woken");
        assert!(!p.publish(), "only one wakeup per sleep");
        assert!(!c.prepare_sleep(), "records pending");
    }

    #[test]
    fn corrupt_head_detected() {
        let mut m = mem::<256>();
        let (_p, mut c) = pair(&mut m);
        unsafe { ptr::write(m.ctl.as_mut_ptr() as *mut u64, 1000) };
        assert!(c.peek().is_err());
        unsafe { ptr::write(m.ctl.as_mut_ptr() as *mut u64, 8) };
        // header claims 200 bytes but only 8 are available
        unsafe { ptr::write(m.data.as_mut_ptr() as *mut u64, 200u64 | (1u64 << 32)) };
        let mut c = Consumer::new(unsafe { RawRing::new(m.ctl.as_mut_ptr(), m.data.as_mut_ptr(), 256) });
        assert_eq!(c.peek().unwrap_err(), Corrupt("bad record length"));
        // A head that is not a multiple of 8 away from our tail is rejected
        // before any (misaligned) header read.
        unsafe { ptr::write(m.ctl.as_mut_ptr() as *mut u64, 12) };
        let mut c = Consumer::new(unsafe { RawRing::new(m.ctl.as_mut_ptr(), m.data.as_mut_ptr(), 256) });
        assert_eq!(c.peek().unwrap_err(), Corrupt("head out of range"));
    }
}
