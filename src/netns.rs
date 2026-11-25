// SPDX-License-Identifier: MIT
//! network namespaces helpers
//!
//! While [network namepaces](https://www.man7.org/linux/man-pages/man7/network_namespaces.7.html)
//! are not part of the netlink protocol, they can be usefull in the context of network manipulation.
//! Here are some helpers to use network namespaces with the crate.
//!
//! ## Executing netlink request inside a network namespace
//!
//! ```rust
//! use nlrs::{
//!     ResponseError,
//!     netlink::socket::NlSocketType,
//!     netns,
//!     rtnetlink::link::GetAllLinkMsgBuilder,
//!     socket::{NetlinkSocket, RequestBuilder},
//! };
//!
//! fn executed_in_netns(_input: ()) -> Result<(), netns::NetnsExecutionError<()>> {
//!     let mut socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE)?;
//!
//!     let mb: GetAllLinkMsgBuilder<_> = socket.message_builder(());
//!     let result = mb.call().map_err(ResponseError::into_unit)?;
//!     println!("links:\n{result:#?}");
//!
//!     Ok(())
//! }
//!
//! fn main() {
//!     match netns::create_netns("my_netns") {
//!         Ok(_) => {
//!             let result = netns::execute_into_netns("my_netns", executed_in_netns, ());
//!             println!("execution result:\n{result:#?}");
//!             _ = netns::delete_netns("my_netns");
//!         }
//!         Err(error) => {
//!             println!("netns creation failed:\n{error:?}");
//!         }
//!     }
//! }
//! ```
use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
#[cfg(feature = "tokio-netns")]
use std::task::Poll;
use std::{
    ffi::CString,
    io,
    os::{
        fd::{AsRawFd, BorrowedFd, RawFd},
        unix::{fs::OpenOptionsExt, process::ExitStatusExt},
    },
    path::Path,
    process::ExitStatus,
};

#[cfg(target_env = "musl")]
type IoctlRequest = c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = c_ulong;

unsafe extern "C" {
    /* shed.h */
    #[doc(hidden)]
    fn unshare(flags: c_int) -> c_int;
    #[doc(hidden)]
    fn setns(fd: i32, nstype: i32) -> i32;

    fn ioctl(fd: c_int, request: IoctlRequest, ...) -> c_int;

    /* sys/mount.h */
    #[doc(hidden)]
    fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    #[doc(hidden)]
    fn umount2(target: *const c_char, flags: c_int) -> c_int;

    /* unistd.h */
    #[doc(hidden)]
    fn fork() -> i32;

    /* unistd.h */
    #[doc(hidden)]
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;

    /* sys/wait.h */
    #[doc(hidden)]
    fn __errno_location() -> *mut c_int;

    /* sys/mman.h */
    #[doc(hidden)]
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: c_long,
    ) -> *mut c_void;
    #[doc(hidden)]
    fn munmap(addr: *mut c_void, length: usize) -> c_int;

    /* unistd.h */
    #[doc(hidden)]
    fn syscall(number: c_long, ...) -> c_long;
    #[doc(hidden)]
    fn close(fd: c_int) -> c_int;
    #[doc(hidden)]
    fn sysconf(name: c_int) -> c_long;

}

const CLONE_NEWNET: i32 = 0x40000000;
/// `close_range(2)`, Linux 5.9 or later; one number on every architecture.
const SYS_CLOSE_RANGE: c_long = 436;
const SC_OPEN_MAX: c_int = 4;
const MS_BIND: u64 = 4096;
const MNT_DETACH: i32 = 2;

/// `/run/netns`, path where persistent network namespaces are located
pub const NETNS_PATH: &str = "/run/netns";
/// `/proc/self/ns/net`, path where the network namespace of the current proccess is located
pub const PROC_NETNS_PATH: &str = "/proc/self/ns/net";

fn wait_for_child_status(pid: i32, options: i32) -> io::Result<Option<i32>> {
    wait_for_child_status_with(|status| match unsafe { waitpid(pid, status, options) } {
        -1 => Err(io::Error::last_os_error()),
        pid => Ok(pid),
    })
}

fn wait_for_child_status_with(
    mut wait: impl FnMut(&mut i32) -> io::Result<i32>,
) -> io::Result<Option<i32>> {
    let mut status = 0;
    loop {
        match wait(&mut status) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
            Ok(0) => return Ok(None),
            Ok(_) => {
                let status = ExitStatus::from_raw(status);
                return status.code().map(Some).ok_or_else(|| {
                    io::Error::other(format!("network namespace helper terminated ({status})"))
                });
            }
        }
    }
}

fn wait_for_child(pid: i32) -> io::Result<i32> {
    Ok(wait_for_child_status(pid, 0)?.expect("blocking waitpid reports a child"))
}

/// Close every descriptor from 3 upwards except `keep`, which is sorted and
/// deduplicated. It runs in a forked child, so it only makes system calls.
unsafe fn close_inherited_descriptors(keep: &[RawFd], close_between: unsafe fn(u32, u32)) {
    let mut first = 3u32;
    for &fd in keep {
        let Ok(fd) = u32::try_from(fd) else { continue };
        if fd < first {
            continue;
        }
        if fd > first {
            unsafe { close_between(first, fd - 1) };
        }
        first = fd.saturating_add(1);
    }
    unsafe { close_between(first, u32::MAX) };
}

/// `close_range(2)`, falling back to one `close` per descriptor below the
/// descriptor limit on kernels older than 5.9.
unsafe fn close_range_or_each(first: u32, last: u32) {
    if unsafe { syscall(SYS_CLOSE_RANGE, first, last, 0u32) } == 0 {
        return;
    }
    unsafe { close_each(first, last) }
}

unsafe fn close_each(first: u32, last: u32) {
    let limit = match unsafe { sysconf(SC_OPEN_MAX) } {
        limit if limit > 0 => u32::try_from(limit).unwrap_or(u32::MAX),
        _ => 1024,
    };
    for fd in first..=last.min(limit.saturating_sub(1)) {
        unsafe { close(fd as c_int) };
    }
}

/// error produced when creating a network namespace
#[derive(Debug)]
pub enum NetnsCreationError {
    NetnsDirCreationFailed(std::io::Error),
    NetnsFileCreationFailed(std::io::Error),
    ForkFailed(std::io::Error),
    UnshareFailed(std::io::Error),
    MountFailed(std::io::Error),
}

impl core::fmt::Display for NetnsCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetnsCreationError::NetnsDirCreationFailed(error) => {
                write!(f, "network namespace directory creation failed: {error}")
            }
            NetnsCreationError::NetnsFileCreationFailed(error) => {
                write!(f, "network namespace file creation failed: {error}")
            }
            NetnsCreationError::ForkFailed(error) => {
                write!(f, "network namespace creation helper failed: {error}")
            }
            NetnsCreationError::UnshareFailed(error) => {
                write!(
                    f,
                    "unsharing before mounting network namespace file failed: {error}"
                )
            }
            NetnsCreationError::MountFailed(error) => {
                write!(f, "mounting network namespace file failed: {error}")
            }
        }
    }
}

impl core::error::Error for NetnsCreationError {}

/// error produced when deleting a network namespace
#[derive(Debug)]
pub enum NetnsDeletionError {
    NetnsFileRemovingFailed(std::io::Error),
    UnmountFailed(std::io::Error),
}

impl core::fmt::Display for NetnsDeletionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetnsDeletionError::NetnsFileRemovingFailed(error) => {
                write!(f, "network namespace file removing failed: {error}")
            }
            NetnsDeletionError::UnmountFailed(error) => {
                write!(f, "network namespace file unmounting failed: {error}")
            }
        }
    }
}

impl core::error::Error for NetnsDeletionError {}

/// open a persistent named network namespace file, useful when a network namespace file descriptor is needed
#[inline]
pub fn open_netns_file(netns_name: &str) -> Result<std::fs::File, std::io::Error> {
    let netns_dir = Path::new(NETNS_PATH);
    let netns_path = netns_dir.join(netns_name);

    std::fs::File::open(&netns_path)
}

/// Check whether the named network namespace path exists.
#[inline]
pub fn netns_exists(netns_name: &str) -> bool {
    let netns_dir = Path::new(NETNS_PATH);
    let netns_path = netns_dir.join(netns_name);

    netns_path.exists()
}

fn wait_for_creation_child(pid: i32) -> Result<(), NetnsCreationError> {
    let status = wait_for_child(pid).map_err(NetnsCreationError::ForkFailed)?;
    if status == 0 {
        Ok(())
    } else if status < 128 {
        Err(NetnsCreationError::UnshareFailed(
            io::Error::from_raw_os_error(status),
        ))
    } else {
        Err(NetnsCreationError::MountFailed(
            io::Error::from_raw_os_error(status - 128),
        ))
    }
}

fn is_network_namespace(path: &Path) -> bool {
    // NS_GET_NSTYPE is _IO(0xb7, 3). These architectures set bit 29 for _IOC_NONE.
    #[cfg(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc",
        target_arch = "sparc64",
    ))]
    const NS_GET_NSTYPE: IoctlRequest = 0x2000_b703;
    #[cfg(not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "sparc",
        target_arch = "sparc64",
    )))]
    const NS_GET_NSTYPE: IoctlRequest = 0xb703;

    #[cfg(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
    ))]
    const O_NONBLOCK_NOCTTY: c_int = 0x0880;
    #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
    const O_NONBLOCK_NOCTTY: c_int = 0xc000;
    #[cfg(not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    )))]
    const O_NONBLOCK_NOCTTY: c_int = 0x0900;

    // Skip special files and use a nonblocking open in case a FIFO replaces the path.
    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return false;
    }

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK_NOCTTY)
        .open(path)
        .is_ok_and(|file| {
            file.metadata().is_ok_and(|metadata| metadata.is_file())
                && unsafe { ioctl(file.as_raw_fd(), NS_GET_NSTYPE) } == CLONE_NEWNET
        })
}

/// create a persistent named network namespace.
/// need root or CAP_NET_ADMIN permissions.
/// See [`create_netns_with_path`] for handling of existing paths.
pub fn create_netns(name: &str) -> Result<(), NetnsCreationError> {
    let netns_dir = Path::new(NETNS_PATH);
    if !netns_dir.exists()
        && let Err(e) = std::fs::create_dir_all(netns_dir)
    {
        return Err(NetnsCreationError::NetnsDirCreationFailed(e));
    }

    let netns_path = netns_dir.join(name);
    create_netns_with_path(&netns_path)
}

/// create a persistent network namespace file.
/// need root, CAP_NET_ADMIN or root+mount unshare permissions.
///
/// An existing path succeeds if it can be verified as a network namespace
/// using `NS_GET_NSTYPE` (Linux 4.11 or later). Other existing paths return
/// [`NetnsCreationError::NetnsFileCreationFailed`] with
/// [`std::io::ErrorKind::AlreadyExists`]. A failed creation can leave a
/// placeholder on disk. Confirm that it is stale before removing it to retry.
pub fn create_netns_with_path(netns_path: &Path) -> Result<(), NetnsCreationError> {
    if let Err(error) = std::fs::File::create_new(netns_path) {
        // An existing path may be a placeholder from a failed or active creator.
        if error.kind() == io::ErrorKind::AlreadyExists && is_network_namespace(netns_path) {
            return Ok(());
        }
        return Err(NetnsCreationError::NetnsFileCreationFailed(error));
    }

    let source = unsafe { CString::new(PROC_NETNS_PATH).unwrap_unchecked() };
    let target = CString::new(netns_path.as_os_str().as_encoded_bytes())
        .map_err(|error| NetnsCreationError::NetnsFileCreationFailed(error.into()))?;

    match unsafe { fork() } {
        -1 => Err(NetnsCreationError::ForkFailed(
            std::io::Error::last_os_error(),
        )),
        0 => {
            unsafe {
                if unshare(CLONE_NEWNET) < 0 {
                    std::process::exit(*__errno_location());
                }

                if mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    MS_BIND,
                    std::ptr::null(),
                ) == -1
                {
                    std::process::exit(*__errno_location() + 128);
                }
            }
            std::process::exit(0);
        }
        child_pid => wait_for_creation_child(child_pid),
    }
}

/// delete a persistent named network namespace.
/// need root or CAP_NET_ADMIN permissions.
pub fn delete_netns(name: &str) -> Result<(), NetnsDeletionError> {
    let netns_path = Path::new(NETNS_PATH).join(name);
    delete_netns_with_path(&netns_path)
}

/// delete a persistent network namespace file.
/// need root, CAP_NET_ADMIN or root+mount unshare permissions.
pub fn delete_netns_with_path(netns_path: &Path) -> Result<(), NetnsDeletionError> {
    if !netns_path.exists() {
        return Ok(());
    }

    let path_cstr = CString::new(netns_path.as_os_str().as_encoded_bytes()).map_err(|error| {
        NetnsDeletionError::UnmountFailed(io::Error::new(io::ErrorKind::InvalidInput, error))
    })?;

    unsafe {
        if umount2(path_cstr.as_ptr(), MNT_DETACH) < 0 {
            return Err(NetnsDeletionError::UnmountFailed(
                std::io::Error::last_os_error(),
            ));
        }
        if let Err(e) = std::fs::remove_file(netns_path) {
            return Err(NetnsDeletionError::NetnsFileRemovingFailed(e));
        }
    }

    Ok(())
}

/// main crate errors wrapper
#[derive(Debug)]
pub enum NetnsExecutionError<P> {
    NlSocketError(crate::netlink::socket::NlSocketError),
    ResponseError(crate::ResponseError<P>),
}

impl<P> core::fmt::Display for NetnsExecutionError<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetnsExecutionError::NlSocketError(nl_socket_error) => write!(f, "{nl_socket_error}"),
            NetnsExecutionError::ResponseError(response_error) => write!(f, "{response_error}"),
        }
    }
}

impl<P: core::fmt::Debug> core::error::Error for NetnsExecutionError<P> {}

impl<P> From<crate::netlink::socket::NlSocketError> for NetnsExecutionError<P> {
    fn from(value: crate::netlink::socket::NlSocketError) -> Self {
        NetnsExecutionError::NlSocketError(value)
    }
}

impl<P> From<crate::ResponseError<P>> for NetnsExecutionError<P> {
    fn from(value: crate::ResponseError<P>) -> Self {
        NetnsExecutionError::ResponseError(value)
    }
}

/// safe (size is known at compile time) struct to transport a [`std::io::Error`] between processes.
#[repr(C)]
#[allow(clippy::large_enum_variant)]
pub enum NetnsInnerIoError {
    RawOsError(i32),
    IoError(std::io::ErrorKind, [u8; Self::ERROR_STRING_BUFFER_SIZE]),
}

impl NetnsInnerIoError {
    /// size of a [`NetnsInnerIoError`] in bytes
    pub const SIZE: usize = std::mem::size_of::<NetnsInnerIoError>();

    /// maximum size of an error message transported by an [`NetnsInnerIoError`] in bytes
    pub const ERROR_STRING_BUFFER_SIZE: usize = 3072;
}

impl From<std::io::Error> for NetnsInnerIoError {
    fn from(value: std::io::Error) -> Self {
        if let Some(os_error) = value.raw_os_error() {
            NetnsInnerIoError::RawOsError(os_error)
        } else {
            let mut error_message_buffer = [0; NetnsInnerIoError::ERROR_STRING_BUFFER_SIZE];
            let error_message = value.to_string();
            error_message_buffer[..std::cmp::min(
                NetnsInnerIoError::ERROR_STRING_BUFFER_SIZE,
                error_message.len(),
            )]
                .copy_from_slice(error_message.as_bytes());

            NetnsInnerIoError::IoError(value.kind(), error_message_buffer)
        }
    }
}

impl From<NetnsInnerIoError> for std::io::Error {
    fn from(value: NetnsInnerIoError) -> Self {
        match value {
            NetnsInnerIoError::RawOsError(os_error) => std::io::Error::from_raw_os_error(os_error),
            NetnsInnerIoError::IoError(error_kind, error_message_buffer) => std::io::Error::new(
                error_kind,
                CStr::from_bytes_until_nul(&error_message_buffer)
                    .map(|e| e.to_string_lossy().to_string())
                    .unwrap_or(String::from_utf8_lossy(&error_message_buffer).to_string()),
            ),
        }
    }
}

/// safe (size is knew at compile time) struct to transport a [`NetnsExecutionError`] between processes.
#[repr(C)]
pub enum NetnsInnerExecutionError {
    NlSocketErrorSocket(NetnsInnerIoError),
    NlSocketErrorBind(NetnsInnerIoError),
    NlSocketErrorGetsockname(NetnsInnerIoError),
    NlSocketErrorGetsocknameAddrLen(usize),
    NlSocketErrorGetsocknameAddrFamily(u16),
    ResponseErrorProtocolParse,
    ResponseErrorIo(NetnsInnerIoError),
    ResponseErrorHeaderParseIo(NetnsInnerIoError),
    ResponseErrorHeaderParseNetlink(i32),
    ResponseErrorHeaderParseDataLoss,
}

impl NetnsInnerExecutionError {
    /// size of a [`NetnsInnerExecutionError`] in bytes
    pub const SIZE: usize = std::mem::size_of::<NetnsInnerExecutionError>();
}

impl From<NetnsInnerExecutionError> for NetnsExecutionError<()> {
    fn from(value: NetnsInnerExecutionError) -> Self {
        match value {
            NetnsInnerExecutionError::NlSocketErrorSocket(netns_inner_io_error) => {
                NetnsExecutionError::NlSocketError(crate::netlink::socket::NlSocketError::Socket(
                    netns_inner_io_error.into(),
                ))
            }
            NetnsInnerExecutionError::NlSocketErrorBind(netns_inner_io_error) => {
                NetnsExecutionError::NlSocketError(crate::netlink::socket::NlSocketError::Bind(
                    netns_inner_io_error.into(),
                ))
            }
            NetnsInnerExecutionError::NlSocketErrorGetsockname(netns_inner_io_error) => {
                NetnsExecutionError::NlSocketError(
                    crate::netlink::socket::NlSocketError::Getsockname(netns_inner_io_error.into()),
                )
            }
            NetnsInnerExecutionError::NlSocketErrorGetsocknameAddrLen(len) => {
                NetnsExecutionError::NlSocketError(
                    crate::netlink::socket::NlSocketError::GetsocknameAddrLen(len),
                )
            }
            NetnsInnerExecutionError::NlSocketErrorGetsocknameAddrFamily(family) => {
                NetnsExecutionError::NlSocketError(
                    crate::netlink::socket::NlSocketError::GetsocknameAddrFamily(family),
                )
            }
            NetnsInnerExecutionError::ResponseErrorProtocolParse => {
                NetnsExecutionError::ResponseError(crate::ResponseError::ProtocolParse(()))
            }
            NetnsInnerExecutionError::ResponseErrorIo(netns_inner_io_error) => {
                NetnsExecutionError::ResponseError(crate::ResponseError::Io(
                    netns_inner_io_error.into(),
                ))
            }
            NetnsInnerExecutionError::ResponseErrorHeaderParseIo(netns_inner_io_error) => {
                NetnsExecutionError::ResponseError(crate::ResponseError::HeaderParse(
                    crate::netlink::msg::NlMsgHeaderParseError::Io(netns_inner_io_error.into()),
                ))
            }
            NetnsInnerExecutionError::ResponseErrorHeaderParseNetlink(err) => {
                NetnsExecutionError::ResponseError(crate::ResponseError::HeaderParse(
                    crate::netlink::msg::NlMsgHeaderParseError::Netlink(err),
                ))
            }
            NetnsInnerExecutionError::ResponseErrorHeaderParseDataLoss => {
                NetnsExecutionError::ResponseError(crate::ResponseError::HeaderParse(
                    crate::netlink::msg::NlMsgHeaderParseError::DataLoss,
                ))
            }
        }
    }
}

impl<P> From<NetnsExecutionError<P>> for NetnsInnerExecutionError {
    fn from(value: NetnsExecutionError<P>) -> Self {
        match value {
            NetnsExecutionError::NlSocketError(nl_socket_error) => match nl_socket_error {
                crate::netlink::socket::NlSocketError::Socket(error) => {
                    NetnsInnerExecutionError::NlSocketErrorSocket(error.into())
                }
                crate::netlink::socket::NlSocketError::Bind(error) => {
                    NetnsInnerExecutionError::NlSocketErrorBind(error.into())
                }
                crate::netlink::socket::NlSocketError::Getsockname(error) => {
                    NetnsInnerExecutionError::NlSocketErrorGetsockname(error.into())
                }
                crate::netlink::socket::NlSocketError::GetsocknameAddrLen(len) => {
                    NetnsInnerExecutionError::NlSocketErrorGetsocknameAddrLen(len)
                }
                crate::netlink::socket::NlSocketError::GetsocknameAddrFamily(family) => {
                    NetnsInnerExecutionError::NlSocketErrorGetsocknameAddrFamily(family)
                }
            },
            NetnsExecutionError::ResponseError(response_error) => match response_error {
                crate::ResponseError::ProtocolParse(_) => {
                    NetnsInnerExecutionError::ResponseErrorProtocolParse
                }
                crate::ResponseError::Io(error) => {
                    NetnsInnerExecutionError::ResponseErrorIo(error.into())
                }
                crate::ResponseError::HeaderParse(nl_msg_header_parse_error) => {
                    match nl_msg_header_parse_error {
                        crate::netlink::msg::NlMsgHeaderParseError::Io(error) => {
                            NetnsInnerExecutionError::ResponseErrorHeaderParseIo(error.into())
                        }
                        crate::netlink::msg::NlMsgHeaderParseError::Netlink(err) => {
                            NetnsInnerExecutionError::ResponseErrorHeaderParseNetlink(err)
                        }
                        crate::netlink::msg::NlMsgHeaderParseError::DataLoss => {
                            NetnsInnerExecutionError::ResponseErrorHeaderParseDataLoss
                        }
                    }
                }
            },
        }
    }
}

/// error produced when entering a network namespace
#[derive(Debug)]
pub enum NetnsEnterError {
    NetnsDoesNotExist,
    NetnsFileOpenFailed(std::io::Error),
    ForkFailed(std::io::Error),
    ReadingErrorFailed(std::io::Error),
    SetNetnsFailed,
}

impl core::fmt::Display for NetnsEnterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetnsEnterError::NetnsDoesNotExist => write!(f, "network namespace does not exist"),
            NetnsEnterError::NetnsFileOpenFailed(error) => {
                write!(f, "network namespace file opening failed: {error}")
            }
            NetnsEnterError::ForkFailed(error) => {
                write!(f, "network namespace forking failed: {error}")
            }
            NetnsEnterError::ReadingErrorFailed(error) => {
                write!(
                    f,
                    "reading network namespace execution result failed: {error}"
                )
            }
            NetnsEnterError::SetNetnsFailed => {
                write!(f, "unable to set the network namespace")
            }
        }
    }
}

impl core::error::Error for NetnsEnterError {}

// When the helper exits with code 1, shared must point to its callback error.
unsafe fn execution_result(
    status: io::Result<i32>,
    shared: *const u8,
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    match status.map_err(NetnsEnterError::ReadingErrorFailed)? {
        0 => Ok(Ok(())),
        1 => {
            let mut reader =
                unsafe { core::slice::from_raw_parts(shared, NetnsInnerExecutionError::SIZE) };
            let inner_error: NetnsInnerExecutionError =
                crate::netlink::utils::transpose_read(&mut reader)
                    .map_err(NetnsEnterError::ReadingErrorFailed)?;

            Ok(Err(inner_error.into()))
        }
        2 => Err(NetnsEnterError::SetNetnsFailed),
        code => Err(NetnsEnterError::ReadingErrorFailed(io::Error::other(
            format!("network namespace helper exited with unexpected code {code}"),
        ))),
    }
}

const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;

const MAP_SHARED: c_int = 1;
const MAP_ANONYMOUS: c_int = 0x20;

#[cfg(feature = "tokio-netns")]
struct WaitPidFuture {
    pid: i32,
    sigchld: tokio::signal::unix::Signal,
}

#[cfg(feature = "tokio-netns")]
impl WaitPidFuture {
    pub fn new(pid: i32) -> Self {
        let sigchld = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .expect("signal sould be hookable");

        Self { pid, sigchld }
    }
}

#[cfg(feature = "tokio-netns")]
impl std::future::Future for WaitPidFuture {
    type Output = io::Result<i32>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
        const WNOHANG: i32 = 1;
        let pid = self.pid;
        poll_child_status(
            || wait_for_child_status(pid, WNOHANG),
            || self.sigchld.poll_recv(cx),
        )
    }
}

#[cfg(feature = "tokio-netns")]
fn poll_child_status(
    mut wait: impl FnMut() -> io::Result<Option<i32>>,
    mut poll_sigchld: impl FnMut() -> Poll<Option<()>>,
) -> Poll<io::Result<i32>> {
    loop {
        match wait() {
            Ok(Some(code)) => return Poll::Ready(Ok(code)),
            Err(error) => return Poll::Ready(Err(error)),
            Ok(None) => {
                // A notification may have arrived since waitpid checked the child.
                if poll_sigchld().is_pending() {
                    return Poll::Pending;
                }
            }
        }
    }
}

/// helper to execute a function inside a network namespace
/// need root or CAP_NET_ADMIN permissions.
///
/// The forked child inherits every descriptor of the process; see
/// [`execute_into_netns_closing_descriptors`] to close them.
pub fn execute_into_netns<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    execute_into_netns_keeping(network_namespace_name, function, function_input, None)
}

/// [`execute_into_netns`], whose child closes every descriptor it inherited
/// except stdio and `keep` before calling `function`.
///
/// A forked child holds a copy of each descriptor of the parent until it
/// exits, so without this a socket the parent closes keeps its network
/// namespace, a pipe keeps its reader from seeing end of file, and a listening
/// socket stays bound. Pass in `keep` every descriptor `function` uses. Uses
/// `close_range(2)` (Linux 5.9 or later), else one `close` per descriptor
/// below the descriptor limit.
pub fn execute_into_netns_closing_descriptors<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
    keep: &[BorrowedFd<'_>],
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    execute_into_netns_keeping(
        network_namespace_name,
        function,
        function_input,
        Some(kept_descriptors(keep)),
    )
}

fn kept_descriptors(keep: &[BorrowedFd<'_>]) -> Vec<RawFd> {
    let mut keep: Vec<RawFd> = keep.iter().map(AsRawFd::as_raw_fd).collect();
    keep.sort_unstable();
    keep.dedup();
    keep
}

fn execute_into_netns_keeping<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
    keep: Option<Vec<RawFd>>,
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    let netns_dir = Path::new(NETNS_PATH);
    if !netns_dir.exists() {
        return Err(NetnsEnterError::NetnsDoesNotExist);
    }

    let netns_path = netns_dir.join(network_namespace_name);
    if !netns_path.exists() {
        return Err(NetnsEnterError::NetnsDoesNotExist);
    }

    let netns_file =
        std::fs::File::open(&netns_path).map_err(NetnsEnterError::NetnsFileOpenFailed)?;
    let netns_fd = netns_file.as_raw_fd();

    // shared memory region to get the content of the error if the function fail
    let shared = unsafe {
        mmap(
            core::ptr::null_mut(),
            NetnsInnerExecutionError::SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut u8;

    // forking to prevent the main process to be stuck inside the network namespace
    let status = match unsafe { fork() } {
        -1 => return Err(NetnsEnterError::ForkFailed(std::io::Error::last_os_error())),
        // child process
        0 => unsafe {
            if setns(netns_fd, CLONE_NEWNET) < 0 {
                std::process::exit(2);
            }
            if let Some(keep) = &keep {
                close_inherited_descriptors(keep, close_range_or_each);
            }

            match (function)(function_input) {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(error) => {
                    let inner_error: NetnsInnerExecutionError = error.into();
                    _ = crate::netlink::utils::transpose_write(
                        &inner_error,
                        &mut core::slice::from_raw_parts_mut(
                            shared,
                            NetnsInnerExecutionError::SIZE,
                        ),
                    );
                    std::process::exit(1);
                }
            }
        },
        // parent process
        child_pid => wait_for_child(child_pid),
    };
    drop(netns_file);

    let result = unsafe { execution_result(status, shared) };

    unsafe { munmap(shared as *mut c_void, NetnsInnerExecutionError::SIZE) };

    result
}

#[cfg(feature = "tokio-netns")]
/// async helper to execute a function inside a network namespace
/// need root or CAP_NET_ADMIN permissions.
///
/// The forked child inherits every descriptor of the process; see
/// [`async_execute_into_netns_closing_descriptors`] to close them.
pub async fn async_execute_into_netns<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    async_execute_into_netns_keeping(network_namespace_name, function, function_input, None).await
}

#[cfg(feature = "tokio-netns")]
/// [`async_execute_into_netns`], whose child closes every descriptor it
/// inherited except stdio and `keep`; see
/// [`execute_into_netns_closing_descriptors`].
pub async fn async_execute_into_netns_closing_descriptors<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
    keep: &[BorrowedFd<'_>],
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    let keep = kept_descriptors(keep);
    async_execute_into_netns_keeping(network_namespace_name, function, function_input, Some(keep))
        .await
}

#[cfg(feature = "tokio-netns")]
async fn async_execute_into_netns_keeping<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
    keep: Option<Vec<RawFd>>,
) -> Result<Result<(), NetnsExecutionError<()>>, NetnsEnterError> {
    let netns_dir = Path::new(NETNS_PATH);
    if !netns_dir.exists() {
        return Err(NetnsEnterError::NetnsDoesNotExist);
    }

    let netns_path = netns_dir.join(network_namespace_name);
    if !netns_path.exists() {
        return Err(NetnsEnterError::NetnsDoesNotExist);
    }

    let netns_file =
        std::fs::File::open(&netns_path).map_err(NetnsEnterError::NetnsFileOpenFailed)?;
    let netns_fd = netns_file.as_raw_fd();

    // shared memory region to get the content of the error if the function fail
    let shared = unsafe {
        mmap(
            core::ptr::null_mut(),
            NetnsInnerExecutionError::SIZE,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut u8;

    // forking to prevent the main process to be stuck inside the network namespace
    let status = match unsafe { fork() } {
        -1 => return Err(NetnsEnterError::ForkFailed(std::io::Error::last_os_error())),
        // child process
        0 => unsafe {
            if setns(netns_fd, CLONE_NEWNET) < 0 {
                std::process::exit(2);
            }
            if let Some(keep) = &keep {
                close_inherited_descriptors(keep, close_range_or_each);
            }

            match (function)(function_input) {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(error) => {
                    let inner_error: NetnsInnerExecutionError = error.into();
                    _ = crate::netlink::utils::transpose_write(
                        &inner_error,
                        &mut core::slice::from_raw_parts_mut(
                            shared,
                            NetnsInnerExecutionError::SIZE,
                        ),
                    );
                    std::process::exit(1);
                }
            }
        },
        // parent process
        child_pid => WaitPidFuture::new(child_pid).await,
    };
    drop(netns_file);

    let result = unsafe { execution_result(status, shared) };

    unsafe { munmap(shared as *mut c_void, NetnsInnerExecutionError::SIZE) };

    result
}

#[cfg(test)]
mod tests;
