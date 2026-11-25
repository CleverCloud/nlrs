// SPDX-License-Identifier: MIT
use super::*;
use std::{
    os::fd::AsFd,
    process::{Child, Command, Stdio},
};

struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        // The code under test normally reaps this PID with waitpid. Never
        // signal its numeric PID once it has been reaped and could be reused.
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn spawn_child(script: &str) -> TestChild {
    TestChild(
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn helper child"),
    )
}

fn child_pid(child: &TestChild) -> i32 {
    i32::try_from(child.0.id()).expect("Linux child PID fits i32")
}

#[test]
fn wait_for_child_retries_interrupted_wait() {
    const EINTR: i32 = 4;
    let mut attempts = 0;
    let status = wait_for_child_status_with(|status| {
        attempts += 1;
        if attempts == 1 {
            return Err(io::Error::from_raw_os_error(EINTR));
        }
        *status = 42 << 8;
        Ok(123)
    })
    .unwrap();
    assert_eq!(status, Some(42));
    assert_eq!(attempts, 2);
}

#[test]
fn wait_for_child_propagates_echild() {
    const ECHILD: i32 = 10;
    let own_pid = i32::try_from(std::process::id()).expect("Linux PID fits i32");
    let error = wait_for_child(own_pid).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(ECHILD));
}

#[test]
fn creation_rejects_signaled_child() {
    let child = spawn_child("kill -KILL $$");
    let error = wait_for_creation_child(child_pid(&child)).unwrap_err();
    assert!(matches!(error, NetnsCreationError::ForkFailed(error)
        if error.to_string().contains("signal: 9")));
}

#[test]
fn creation_preserves_exit_code_mappings() {
    let child = spawn_child("exit 0");
    wait_for_creation_child(child_pid(&child)).unwrap();

    let child = spawn_child("exit 1");
    let error = wait_for_creation_child(child_pid(&child)).unwrap_err();
    assert!(matches!(error, NetnsCreationError::UnshareFailed(error)
        if error.raw_os_error() == Some(1)));

    let child = spawn_child("exit 129");
    let error = wait_for_creation_child(child_pid(&child)).unwrap_err();
    assert!(matches!(error, NetnsCreationError::MountFailed(error)
        if error.raw_os_error() == Some(1)));
}

#[test]
fn creation_rejects_existing_placeholder() {
    let path = std::env::temp_dir().join(format!("nlrs-placeholder-{}", std::process::id()));
    std::fs::File::create_new(&path).expect("create placeholder");

    let result = create_netns_with_path(&path);
    std::fs::remove_file(&path).expect("placeholder is still present");

    assert!(
        matches!(&result, Err(NetnsCreationError::NetnsFileCreationFailed(error))
        if error.kind() == io::ErrorKind::AlreadyExists),
        "got {result:?}"
    );
}

#[test]
fn creation_checks_existing_namespace_type() {
    create_netns_with_path(Path::new(PROC_NETNS_PATH)).expect("accept existing network namespace");
    let result = create_netns_with_path(Path::new("/proc/self/ns/mnt"));
    assert!(
        matches!(&result, Err(NetnsCreationError::NetnsFileCreationFailed(error))
        if error.kind() == io::ErrorKind::AlreadyExists),
        "got {result:?}"
    );
}

#[test]
fn sync_execution_rejects_signaled_child() {
    let child = spawn_child("kill -KILL $$");
    let status = wait_for_child(child_pid(&child));
    let error = unsafe { execution_result(status, std::ptr::null()) }.unwrap_err();
    assert!(matches!(error, NetnsEnterError::ReadingErrorFailed(error)
        if error.to_string().contains("signal: 9")));
}

#[test]
fn sync_execution_rejects_unexpected_exit_code() {
    let child = spawn_child("exit 42");
    let status = wait_for_child(child_pid(&child));
    let error = unsafe { execution_result(status, std::ptr::null()) }.unwrap_err();
    assert!(matches!(error, NetnsEnterError::ReadingErrorFailed(error)
        if error.to_string().contains("code 42")));
}

#[test]
fn execution_preserves_exit_code_mappings() {
    let child = spawn_child("exit 0");
    let status = wait_for_child(child_pid(&child));
    assert!(matches!(
        unsafe { execution_result(status, std::ptr::null()) },
        Ok(Ok(()))
    ));

    let child = spawn_child("exit 1");
    let status = wait_for_child(child_pid(&child));
    let callback_error = NetnsInnerExecutionError::ResponseErrorProtocolParse;
    assert!(matches!(
        unsafe { execution_result(status, std::ptr::from_ref(&callback_error).cast()) },
        Ok(Err(NetnsExecutionError::ResponseError(
            crate::ResponseError::ProtocolParse(())
        )))
    ));

    let child = spawn_child("exit 2");
    let status = wait_for_child(child_pid(&child));
    assert!(matches!(
        unsafe { execution_result(status, std::ptr::null()) },
        Err(NetnsEnterError::SetNetnsFailed)
    ));
}

#[cfg(feature = "tokio-netns")]
#[test]
fn async_wait_rechecks_child_after_ready_notification() {
    use std::{
        future::{Future, poll_fn},
        pin::Pin,
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build Tokio runtime");
    let (notify, mut notification) = tokio::sync::oneshot::channel();
    let mut notify = Some(notify);
    let status = runtime.block_on(poll_fn(|cx| {
        let first_poll = poll_child_status(
            || {
                if let Some(notify) = notify.take() {
                    // WNOHANG found a running child. It exits before the signal is polled.
                    notify.send(()).expect("deliver the only notification");
                    Ok(None)
                } else {
                    Ok(Some(42))
                }
            },
            || Pin::new(&mut notification).poll(cx).map(Result::ok),
        );
        // Observe Pending as a failure immediately, since there is no second notification.
        Poll::Ready(first_poll)
    }));
    assert!(matches!(status, Poll::Ready(Ok(42))), "got {status:?}");
}

#[cfg(feature = "tokio-netns")]
fn async_execution_error(script: &str) -> NetnsEnterError {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build Tokio runtime");
    let _guard = runtime.enter();
    let mut child = spawn_child(&format!("read -r line; {script}"));
    let mut wait = std::pin::pin!(WaitPidFuture::new(child_pid(&child)));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(wait.as_mut().poll(&mut cx).is_pending());
    drop(child.0.stdin.take());

    // Drive the wait status checks independently of SIGCHLD delivery.
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Poll::Ready(status) = wait.as_mut().poll(&mut cx) {
            break status;
        }
        assert!(Instant::now() < deadline, "helper failed to exit");
        std::thread::sleep(Duration::from_millis(1));
    };
    unsafe { execution_result(status, std::ptr::null()) }.unwrap_err()
}

#[cfg(feature = "tokio-netns")]
#[test]
fn async_execution_rejects_signaled_child() {
    let error = async_execution_error("kill -KILL $$");
    assert!(matches!(error, NetnsEnterError::ReadingErrorFailed(error)
        if error.to_string().contains("signal: 9")));
}

#[cfg(feature = "tokio-netns")]
#[test]
fn async_execution_rejects_unexpected_exit_code() {
    let error = async_execution_error("exit 42");
    assert!(matches!(error, NetnsEnterError::ReadingErrorFailed(error)
        if error.to_string().contains("code 42")));
}

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn _exit(status: c_int) -> !;
}

const F_GETFD: c_int = 1;

fn is_open(fd: RawFd) -> bool {
    (unsafe { fcntl(fd, F_GETFD) }) >= 0
}

/// Forks, closes the inherited descriptors in the child with `close_between`
/// and returns the child's exit code: 0 when only stdio and the kept
/// descriptor survived.
fn closing_in_child(close_between: unsafe fn(u32, u32)) -> i32 {
    let closed = std::fs::File::open("/dev/null").expect("open /dev/null");
    let kept = std::fs::File::open("/dev/null").expect("open /dev/null");
    let after = std::fs::File::open("/dev/null").expect("open /dev/null");
    let (closed, kept, after) = (closed.as_raw_fd(), kept.as_raw_fd(), after.as_raw_fd());
    match unsafe { fork() } {
        -1 => panic!("fork: {}", io::Error::last_os_error()),
        0 => unsafe {
            close_inherited_descriptors(&[kept], close_between);
            let code = if !(0..3).all(is_open) {
                10
            } else if is_open(closed) || is_open(after) {
                11
            } else if !is_open(kept) {
                12
            } else {
                0
            };
            _exit(code)
        },
        pid => wait_for_child(pid).expect("wait for the child"),
    }
}

#[test]
fn closing_keeps_stdio_and_the_kept_descriptors_only() {
    assert_eq!(closing_in_child(close_range_or_each), 0);
}

#[test]
fn closing_one_by_one_keeps_stdio_and_the_kept_descriptors_only() {
    assert_eq!(closing_in_child(close_each), 0);
}

fn only_the_kept_descriptor_is_open(
    (closed, kept): (RawFd, RawFd),
) -> Result<(), NetnsExecutionError<()>> {
    if is_open(closed) || !is_open(kept) {
        // An exit code no helper uses, reported as `ReadingErrorFailed`.
        unsafe { _exit(42) }
    }
    Ok(())
}

/// Runs inside the `nlrs-descriptors` namespace. Needs a disposable user and
/// mount namespace, for instance:
///
/// ```sh
/// unshare -rnm --propagation private sh -c 'mount -t tmpfs none /run &&
///   mkdir /run/netns && ip netns add nlrs-descriptors &&
///   cargo test --all-features execution_closes_inherited_descriptors -- --ignored'
/// ```
#[test]
#[ignore = "needs the nlrs-descriptors network namespace"]
fn execution_closes_inherited_descriptors() {
    let closed = std::fs::File::open("/dev/null").expect("open /dev/null");
    let kept = std::fs::File::open("/dev/null").expect("open /dev/null");
    let input = (closed.as_raw_fd(), kept.as_raw_fd());
    let result = execute_into_netns_closing_descriptors(
        "nlrs-descriptors",
        only_the_kept_descriptor_is_open,
        input,
        &[kept.as_fd()],
    );
    assert!(matches!(result, Ok(Ok(()))), "got {result:?}");
    #[cfg(feature = "tokio-netns")]
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("build Tokio runtime");
        let result = runtime.block_on(async_execute_into_netns_closing_descriptors(
            "nlrs-descriptors",
            only_the_kept_descriptor_is_open,
            input,
            &[kept.as_fd()],
        ));
        assert!(matches!(result, Ok(Ok(()))), "got {result:?}");
    }
    // The plain helpers keep inheriting every descriptor.
    let result = execute_into_netns("nlrs-descriptors", only_the_kept_descriptor_is_open, input);
    assert!(
        matches!(result, Err(NetnsEnterError::ReadingErrorFailed(_))),
        "got {result:?}"
    );
}
