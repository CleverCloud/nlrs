// SPDX-License-Identifier: MIT
//! netlink message and socket helpers
//!
//! netlink messages are composed of an header and a playload.
//! playload often contain an "extra header(s)" depending on the message type.
//! the playload may also contains attributes: data prefixed with type and length.

/// helpers for netlink message playload attributes
pub mod attr;
/// helpers for netlink message
pub mod msg;
/// helpers for netlink socket
#[cfg(target_os = "linux")]
pub mod socket;
/// various utils
pub mod utils;
