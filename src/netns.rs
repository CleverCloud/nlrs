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
use std::{ffi::CString, os::fd::AsRawFd, path::Path};

unsafe extern "C" {
    /* shed.h */
    #[doc(hidden)]
    fn unshare(flags: c_int) -> c_int;
    #[doc(hidden)]
    fn setns(fd: i32, nstype: i32) -> i32;

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

}

const CLONE_NEWNET: i32 = 0x40000000;
const MS_BIND: u64 = 4096;
const MNT_DETACH: i32 = 2;

/// `/run/netns`, path where persistent network namespaces are located
pub const NETNS_PATH: &str = "/run/netns";
/// `/proc/self/ns/net`, path where the network namespace of the current proccess is located
pub const PROC_NETNS_PATH: &str = "/proc/self/ns/net";

// see man 2 wait
#[doc(hidden)]
const fn wexitstatus(status: i32) -> i32 {
    ((status) & 0xff00) >> 8
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
                write!(
                    f,
                    "forking before mounting network namespace file failed: {error}"
                )
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

/// check if a persistent named network namespace exist
#[inline]
pub fn netns_exists(netns_name: &str) -> bool {
    let netns_dir = Path::new(NETNS_PATH);
    let netns_path = netns_dir.join(netns_name);

    netns_path.exists()
}

/// create a persistent named network namespace.
/// need root or CAP_NET_ADMIN permissions.
pub fn create_netns(name: &str) -> Result<(), NetnsCreationError> {
    let netns_dir = Path::new(NETNS_PATH);
    if !netns_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(netns_dir) {
            return Err(NetnsCreationError::NetnsDirCreationFailed(e));
        }
    }

    let netns_path = netns_dir.join(name);
    create_netns_with_path(&netns_path)
}

/// create a persistent network namespace file.
/// need root, CAP_NET_ADMIN or root+mount unshare permissions.
pub fn create_netns_with_path(netns_path: &Path) -> Result<(), NetnsCreationError> {
    if netns_path.exists() {
        return Ok(());
    }

    std::fs::File::create(netns_path).map_err(NetnsCreationError::NetnsFileCreationFailed)?;

    let source = unsafe { CString::new(PROC_NETNS_PATH).unwrap_unchecked() };
    let target = unsafe { CString::new(netns_path.to_str().unwrap_unchecked()).unwrap_unchecked() };

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
        child_pid => {
            let mut status = 0;
            unsafe { waitpid(child_pid, &mut status, 0) };
            let status = wexitstatus(status);
            if status == 0 {
                Ok(())
            } else if status < 128 {
                Err(NetnsCreationError::UnshareFailed(
                    std::io::Error::from_raw_os_error(status),
                ))
            } else {
                Err(NetnsCreationError::MountFailed(
                    std::io::Error::from_raw_os_error(status - 128),
                ))
            }
        }
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

    let path_cstr =
        unsafe { CString::new(netns_path.to_str().unwrap_unchecked()).unwrap_unchecked() };

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
                    "reading network namespace execution error failed: {error}"
                )
            }
            NetnsEnterError::SetNetnsFailed => {
                write!(f, "unable to set the network namespace")
            }
        }
    }
}

impl core::error::Error for NetnsEnterError {}

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
    type Output = i32;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        const WNOHANG: i32 = 1;
        let mut status = 0;

        let still_running = unsafe { waitpid(self.pid, &mut status, WNOHANG) };
        if still_running == 0 {
            _ = std::pin::Pin::new(&mut self.sigchld).poll_recv(cx);
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(wexitstatus(status))
        }
    }
}

/// helper to execute a function inside a network namespace
/// need root or CAP_NET_ADMIN permissions.
pub fn execute_into_netns<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
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

            match (function)(function_input) {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(error) => {
                    let inner_error: NetnsInnerExecutionError = error.into();
                    _ = crate::netlink::utils::transprose_write(
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
        child_pid => {
            let mut status = 0;
            unsafe { waitpid(child_pid, &mut status, 0) };
            wexitstatus(status)
        }
    };
    drop(netns_file);

    let result = if status == 2 {
        Err(NetnsEnterError::SetNetnsFailed)
    } else if status == 1 {
        let mut reader =
            unsafe { core::slice::from_raw_parts(shared, NetnsInnerExecutionError::SIZE) };
        let inner_error: NetnsInnerExecutionError =
            crate::netlink::utils::transpose_read(&mut reader)
                .map_err(NetnsEnterError::ReadingErrorFailed)?;

        Ok(Err(inner_error.into()))
    } else {
        Ok(Ok(()))
    };

    unsafe { munmap(shared as *mut c_void, NetnsInnerExecutionError::SIZE) };

    result
}

#[cfg(feature = "tokio-netns")]
/// async helper to execute a function inside a network namespace
/// need root or CAP_NET_ADMIN permissions.
pub async fn async_execute_into_netns<I, P>(
    network_namespace_name: &str,
    function: fn(I) -> Result<(), NetnsExecutionError<P>>,
    function_input: I,
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

            match (function)(function_input) {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(error) => {
                    let inner_error: NetnsInnerExecutionError = error.into();
                    _ = crate::netlink::utils::transprose_write(
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

    let result = if status == 2 {
        Err(NetnsEnterError::SetNetnsFailed)
    } else if status == 1 {
        let mut reader =
            unsafe { core::slice::from_raw_parts(shared, NetnsInnerExecutionError::SIZE) };
        let inner_error: NetnsInnerExecutionError =
            crate::netlink::utils::transpose_read(&mut reader)
                .map_err(NetnsEnterError::ReadingErrorFailed)?;

        Ok(Err(inner_error.into()))
    } else {
        Ok(Ok(()))
    };

    unsafe { munmap(shared as *mut c_void, NetnsInnerExecutionError::SIZE) };

    result
}
