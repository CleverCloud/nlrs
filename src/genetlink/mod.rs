// SPDX-License-Identifier: MIT
//! generic netlink
//!
//! [Generic Netlink](https://www.kernel.org/doc/html/latest/userspace-api/netlink/intro.html#generic-netlink)
//! is an extension of Netlink that enables dynamic registration of protocol families and operations using string-based family names rather than static IDs.
//! This allows kernel subsystems to register and expose their interfaces at runtime.
//! For example, subsystem includes ipvs, wireguard or nl80211.
//!
//! Here are some helpers to use and implement generic netlink protocols.

/// generic netlink messages
pub mod msg;
/// generic netlink socket(s)
pub mod socket;

use crate::netlink::msg::NlMsgHeader;

/// generic netlink message/request builder pattern
pub trait GenericMessageBuilder<'a>: Sized {
    type Buffer: std::io::Write;
    type Input;
    type Output;
    type ParseError;

    /// create new GenericMessageBuilder, with sequence number generated with libc time function
    fn new(
        buffer: &'a mut Self::Buffer,
        family_id: u16,
        seq: u32,
        input: Self::Input,
    ) -> (Self, u32) {
        (
            Self::new_with_header(
                buffer,
                NlMsgHeader::new_with_seq_and_pid(seq, crate::netlink::socket::NL_SOCKET_AUTOPID),
                family_id,
                input,
            ),
            seq,
        )
    }

    /// create new MessageBuilder, with custom [`NlMsgHeader`]
    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self;

    fn build(self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error>;

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>>;
}
