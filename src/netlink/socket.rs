// SPDX-License-Identifier: MIT
use std::ffi::c_int;
use std::io::{Read, Write};

unsafe extern "C" {
    /* sys/socket.h */
    #[doc(hidden)]
    fn socket(__domain: c_int, __type: c_int, __protocol: c_int) -> c_int;
    #[doc(hidden)]
    fn bind(__fd: c_int, __addr: *mut sockaddr_nl, __len: u32) -> c_int;
    #[doc(hidden)]
    fn getsockname(__fd: c_int, __addr: *mut sockaddr_nl, __len: *mut u32) -> c_int;
    #[doc(hidden)]
    fn send(__fd: c_int, __buf: *const u8, __n: usize, __flags: c_int) -> usize;
    #[doc(hidden)]
    fn recv(__fd: c_int, __buf: *mut u8, __n: usize, __flags: c_int) -> usize;
    #[doc(hidden)]
    fn setsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: usize,
    ) -> i32;

    /* unistd.h */
    #[doc(hidden)]
    fn getpid() -> i32;
    #[doc(hidden)]
    fn close(__fd: i32) -> i32;
}

/// netlink socket address
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct sockaddr_nl {
    pub family: u16, /* AF_NETLINK	*/
    pub pad: u16,    /* zero		*/
    pub pid: u32,    /* port ID	*/
    pub groups: u32, /* multicast groups mask */
}

const SOCKADDR_NL_LEN: u32 = std::mem::size_of::<sockaddr_nl>() as u32;

pub const AF_NETLINK: i32 = 16;
pub const SOL_NETLINK: i32 = 270;
pub const NL_SOCKET_AUTOPID: u32 = 0;
pub const SOCK_RAW: i32 = 3;
pub const NL_SOCKET_DUMP_SIZE: usize = i16::MAX as usize + 1;
// TODO NL_SOCKET_BUFFER_SIZE (sysconf(_SC_PAGESIZE) < 8192L ? sysconf(_SC_PAGESIZE) : 8192L)

#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Debug)]
pub enum NlSocketType {
    /// Routing/device hook (for rtnetlink)
    NETLINK_ROUTE = 0,
    /// Unused number
    NETLINK_UNUSED = 1,
    /// Reserved for user mode socket protocols
    NETLINK_USERSOCK = 2,
    /// Unused number, formerly ip_queue
    NETLINK_FIREWALL = 3,
    /// Unused number, formerly ip_queue
    NETLINK_SOCK_DIAG = 4,
    /// netfilter/iptables ULOG
    NETLINK_NFLOG = 5,
    /// ipsec
    NETLINK_XFRM = 6,
    /// SELinux event notifications
    NETLINK_SELINUX = 7,
    /// Open-iSCSI
    NETLINK_ISCSI = 8,
    /// auditing
    NETLINK_AUDIT = 9,
    NETLINK_FIB_LOOKUP = 10,
    NETLINK_CONNECTOR = 11,
    ///netfilter subsystem
    NETLINK_NETFILTER = 12,
    NETLINK_IP6_FW = 13,
    /// DECnet routing messages (obsolete)
    NETLINK_DNRTMSG = 14,
    /// Kernel messages to userspace
    NETLINK_KOBJECT_UEVENT = 15,
    NETLINK_GENERIC = 16,
    /// SCSI Transports
    NETLINK_SCSITRANSPORT = 18,
    NETLINK_ECRYPTFS = 19,
    NETLINK_RDMA = 20,
    /// Crypto layer
    NETLINK_CRYPTO = 21,
    /// SMC monitoring
    NETLINK_SMC = 22,
}

/// raw netlink socket
#[derive(Debug)]
pub struct NlSocket {
    pub fd: i32,
    pub socket_address: sockaddr_nl,
}

#[derive(Debug)]
pub enum NlSocketError {
    /// errno code of libc socket function
    Socket(std::io::Error),
    /// errno code of libc bind function
    Bind(std::io::Error),
    /// errno code of libc getsockname function
    Getsockname(std::io::Error),
    /// libc getsockname function finished with a wrong socket address length
    GetsocknameAddrLen(usize),
    /// libc getsockname function finished with a wrong socket address family
    GetsocknameAddrFamily(u16),
}

impl core::fmt::Display for NlSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlSocketError::Socket(error) => write!(f, "unable to open netlink socket: {error}"),
            NlSocketError::Bind(error) => write!(f, "unable to bind netlink socket: {error}"),
            NlSocketError::Getsockname(error) => {
                write!(f, "unable to get netlink socket name: {error}")
            }
            NlSocketError::GetsocknameAddrLen(_) => write!(f, "unexpected socket address length"),
            NlSocketError::GetsocknameAddrFamily(_) => {
                write!(f, "unexpected socket address family")
            }
        }
    }
}

impl core::error::Error for NlSocketError {}

impl NlSocket {
    pub fn open(bus: NlSocketType) -> Result<NlSocket, NlSocketError> {
        Self::open_with_flags(bus, 0)
    }

    pub fn open_with_flags(bus: NlSocketType, flags: i32) -> Result<Self, NlSocketError> {
        let fd = unsafe {
            match socket(AF_NETLINK, SOCK_RAW | flags, bus as i32) {
                -1 => Err(NlSocketError::Socket(std::io::Error::last_os_error())),
                fd => Ok(fd),
            }?
        };

        Ok(NlSocket {
            fd,
            socket_address: sockaddr_nl {
                family: AF_NETLINK as u16,
                pad: 0,
                pid: unsafe { getpid() } as u32,
                groups: 0,
            },
        })
    }

    pub fn bind(&mut self) -> Result<(), NlSocketError> {
        let socket_address_ptr = std::ptr::from_mut(&mut self.socket_address);
        let mut socket_address_len = SOCKADDR_NL_LEN;
        unsafe {
            match bind(self.fd, socket_address_ptr, SOCKADDR_NL_LEN) {
                0 => Ok(()),
                _ => Err(NlSocketError::Bind(std::io::Error::last_os_error())),
            }?;
            match getsockname(
                self.fd,
                socket_address_ptr,
                std::ptr::from_mut(&mut socket_address_len),
            ) {
                0 => Ok(()),
                _ => Err(NlSocketError::Getsockname(std::io::Error::last_os_error())),
            }?;
        };

        if socket_address_len != SOCKADDR_NL_LEN {
            Err(NlSocketError::GetsocknameAddrLen(
                socket_address_len as usize,
            ))
        } else if self.socket_address.family != AF_NETLINK as u16 {
            Err(NlSocketError::GetsocknameAddrFamily(
                self.socket_address.family,
            ))
        } else {
            Ok(())
        }
    }

    /// open and bind a netlink socket
    pub fn new(bus: NlSocketType) -> Result<Self, NlSocketError> {
        let mut res = Self::open(bus)?;
        res.bind()?;
        Ok(res)
    }

    /// set strict input checking on the socket (NETLINK_GET_STRICT_CHK)
    pub fn set_strict_checking(&mut self) -> Result<(), std::io::Error> {
        const NETLINK_GET_STRICT_CHK: i32 = 12;
        let value: i32 = 1;

        unsafe {
            if setsockopt(
                self.fd,
                SOL_NETLINK,
                NETLINK_GET_STRICT_CHK,
                core::ptr::from_ref(&value).cast(),
                core::mem::size_of::<i32>(),
            ) == -1
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// send bytes from a netlink socket
    ///
    /// be carefull, you must provide the entire message here
    pub fn send(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
        const SEND_ERR: usize = -1isize as usize;
        unsafe {
            match send(self.fd, std::ptr::from_ref(buffer).cast(), buffer.len(), 0) {
                SEND_ERR => Err(std::io::Error::last_os_error()),
                len => Ok(len),
            }
        }
    }

    /// recieve bytes from a netlink socket
    ///
    /// be carefull, you must provide a big enough buffer, otherwise, you will lost part of a message
    pub fn recv(&self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
        const RECV_ERR: usize = -1isize as usize;

        unsafe {
            match recv(self.fd, std::ptr::from_mut(buffer).cast(), buffer.len(), 0) {
                RECV_ERR => Err(std::io::Error::last_os_error()),
                len => Ok(len),
            }
        }
    }

    /// explicitly close the socket (automaticly done by when drop)
    pub fn close(mut self) {
        if self.fd != 0 {
            unsafe {
                close(self.fd);
            }
            self.fd = 0;
        }
    }
}

impl Write for NlSocket {
    /// send bytes from a netlink socket
    ///
    /// be carefull, you must provide the entire message here
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send(buf)
    }

    // there is no such thing as flush here, when you write, your message is send
    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for NlSocket {
    /// recieve bytes from a netlink socket
    ///
    /// be carefull, you must provide a big enough buffer, otherwise, you will lost part of a message
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv(buf)
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        if self.fd != 0 {
            unsafe {
                close(self.fd);
            }
            self.fd = 0;
        }
    }
}
