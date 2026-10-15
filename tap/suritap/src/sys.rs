//! Thin wrappers over the Linux system calls suritap needs.

use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::ptr;

/// Maximum number of file descriptors carried by one handshake message.
pub const MAX_FDS: usize = 4;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

fn cvt_size(r: libc::ssize_t) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

fn retry<T, F: FnMut() -> io::Result<T>>(mut f: F) -> io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Creates a non-blocking, close-on-exec eventfd.
pub fn eventfd() -> io::Result<OwnedFd> {
    let fd = cvt(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Signals an eventfd. A saturated counter (EAGAIN) is already signalled.
pub fn eventfd_signal(fd: RawFd) {
    if fd < 0 {
        return;
    }
    let one: u64 = 1;
    unsafe { libc::write(fd, &one as *const u64 as *const libc::c_void, 8) };
}

/// Resets an eventfd counter.
pub fn eventfd_drain(fd: RawFd) {
    let mut v: u64 = 0;
    unsafe { libc::read(fd, &mut v as *mut u64 as *mut libc::c_void, 8) };
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = (size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    Ok((addr, len))
}

fn seqpacket(nonblock: bool) -> io::Result<OwnedFd> {
    unix_socket(libc::SOCK_SEQPACKET, nonblock)
}

fn unix_socket(kind: libc::c_int, nonblock: bool) -> io::Result<OwnedFd> {
    let mut ty = kind | libc::SOCK_CLOEXEC;
    if nonblock {
        ty |= libc::SOCK_NONBLOCK;
    }
    let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, ty, 0) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Binds a non-blocking `SOCK_SEQPACKET` listener, replacing a stale socket
/// file. Access control relies on the permissions of the directory and
/// `mode`.
pub fn seqpacket_listen(path: &Path, mode: Option<u32>) -> io::Result<OwnedFd> {
    listen(libc::SOCK_SEQPACKET, path, mode)
}

/// Binds a non-blocking `SOCK_STREAM` listener (socket transport).
pub fn stream_listen(path: &Path, mode: Option<u32>) -> io::Result<OwnedFd> {
    listen(libc::SOCK_STREAM, path, mode)
}

fn listen(kind: libc::c_int, path: &Path, mode: Option<u32>) -> io::Result<OwnedFd> {
    let (addr, len) = sockaddr(path)?;
    let fd = unix_socket(kind, true)?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    cvt(unsafe { libc::bind(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) })?;
    if let Some(m) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(m))?;
    }
    cvt(unsafe { libc::listen(fd.as_raw_fd(), 128) })?;
    Ok(fd)
}

/// Connects a blocking `SOCK_SEQPACKET` socket.
pub fn seqpacket_connect(path: &Path) -> io::Result<OwnedFd> {
    let (addr, len) = sockaddr(path)?;
    let fd = seqpacket(false)?;
    retry(|| cvt(unsafe { libc::connect(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) }))?;
    Ok(fd)
}

/// Accepts one connection; `None` when none is pending.
pub fn accept(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    let r = retry(|| {
        cvt(unsafe {
            libc::accept4(
                fd,
                ptr::null_mut(),
                ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        })
    });
    match r {
        Ok(c) => Ok(Some(unsafe { OwnedFd::from_raw_fd(c) })),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

#[repr(C)]
union CmsgBuf {
    _align: libc::cmsghdr,
    buf: [u8; 64],
}

/// Sends one message carrying `fds` as SCM_RIGHTS.
pub fn send_with_fds(fd: RawFd, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
    assert!(fds.len() <= MAX_FDS);
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut cbuf = CmsgBuf { buf: [0; 64] };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        let payload = std::mem::size_of_val(fds) as u32;
        unsafe {
            msg.msg_control = cbuf.buf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = libc::CMSG_SPACE(payload) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(payload) as _;
            ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg) as *mut RawFd, fds.len());
        }
    }
    let n = retry(|| cvt_size(unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) }))?;
    if n != data.len() {
        return Err(io::Error::new(io::ErrorKind::WriteZero, "short sendmsg"));
    }
    Ok(())
}

/// Receives one message and the descriptors attached to it. Truncated
/// messages or control data are errors (received descriptors are closed).
pub fn recv_with_fds(fd: RawFd, buf: &mut [u8], fds: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cbuf = CmsgBuf { buf: [0; 64] };
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = unsafe { cbuf.buf.as_mut_ptr() } as *mut libc::c_void;
    msg.msg_controllen = 64;
    let n = retry(|| cvt_size(unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) }))?;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(cmsg) as *const RawFd;
                let count = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / size_of::<RawFd>();
                for i in 0..count {
                    fds.push(OwnedFd::from_raw_fd(ptr::read_unaligned(data.add(i))));
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        fds.clear();
        return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated message"));
    }
    Ok(n)
}

/// Non-blocking receive; `Ok(None)` when nothing is available, `Ok(Some(0))`
/// at end of stream.
pub fn recv_nb(fd: RawFd, buf: &mut [u8]) -> io::Result<Option<usize>> {
    match retry(|| {
        cvt_size(unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT) })
    }) {
        Ok(n) => Ok(Some(n)),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e),
    }
}

/// Non-blocking send; returns the bytes written (0 when the socket is full).
pub fn send_nb(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    match retry(|| {
        cvt_size(unsafe {
            libc::send(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        })
    }) {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
        Err(e) => Err(e),
    }
}

/// Credentials of the process on the other end of a UNIX socket.
pub fn peer_cred(fd: RawFd) -> io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    })?;
    Ok(cred)
}

/// Minimal epoll wrapper.
pub struct Epoll(OwnedFd);

impl Epoll {
    pub fn new() -> io::Result<Self> {
        let fd = cvt(unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) })?;
        Ok(Epoll(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn add(&self, fd: RawFd, token: u64, events: u32) -> io::Result<()> {
        let mut ev = libc::epoll_event { events, u64: token };
        cvt(unsafe { libc::epoll_ctl(self.0.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut ev) }).map(|_| ())
    }

    pub fn modify(&self, fd: RawFd, token: u64, events: u32) -> io::Result<()> {
        let mut ev = libc::epoll_event { events, u64: token };
        cvt(unsafe { libc::epoll_ctl(self.0.as_raw_fd(), libc::EPOLL_CTL_MOD, fd, &mut ev) }).map(|_| ())
    }

    pub fn delete(&self, fd: RawFd) {
        unsafe { libc::epoll_ctl(self.0.as_raw_fd(), libc::EPOLL_CTL_DEL, fd, ptr::null_mut()) };
    }

    /// Waits for events; an interrupted wait returns 0.
    pub fn wait(&self, events: &mut [libc::epoll_event], timeout_ms: i32) -> io::Result<usize> {
        let n = unsafe { libc::epoll_wait(self.0.as_raw_fd(), events.as_mut_ptr(), events.len() as i32, timeout_ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(e);
        }
        Ok(n as usize)
    }
}

/// poll(2) over a few descriptors; interrupted polls return 0.
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> io::Result<usize> {
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if n < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(e);
    }
    Ok(n as usize)
}

/// Shuts down both directions of a socket (wakes threads polling it).
pub fn shutdown(fd: RawFd) {
    unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
}
