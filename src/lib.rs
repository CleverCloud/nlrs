// SPDX-License-Identifier: MIT
//! nlrs is a crate to craft netlink messages.
//! [netlink](https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html) is the linux kernel networking api.
//! (see ```man 7 netlink``` from [Linux man-pages](https://man7.org/linux/man-pages/man7/netlink.7.html))
//!
//! This crate provides simple apis and helpers.
//! Every part of this is public:
//! feel free to copy and modify parts of the crate if you need to.
//! Complexity is not hidden: you might shoot you in the foot.
//! However, everything is documented and examples using higher level safe helpers are provided.
//! Also, there is no dependencies by default, you can easily copy-paste this code in your project.

use crate::netlink::msg::NlMsgHeader;

pub mod genetlink;
pub mod ipvs;

pub mod netlink;
#[cfg(target_os = "linux")]
pub mod netns;
/// rtnetlink (links, routes, address, etc...)
pub mod rtnetlink;
/// netlink socket(s)
pub mod socket;

/// posix utils
#[cfg(target_family = "unix")]
pub mod posix;
pub mod wireguard;

/// netlink message/request builder pattern
pub trait MessageBuilder<'a>: Sized {
    type Buffer: std::io::Write;
    type Input;
    type Output;
    type ParseError;

    /// create new MessageBuilder, with sequence number generated with libc time function
    fn new(buffer: &'a mut Self::Buffer, seq: u32, input: Self::Input) -> (Self, u32) {
        (
            Self::new_with_header(
                buffer,
                NlMsgHeader::new_with_seq_and_pid(seq, crate::netlink::socket::NL_SOCKET_AUTOPID),
                input,
            ),
            seq,
        )
    }

    /// create new MessageBuilder, with custom [`NlMsgHeader`]
    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self;

    fn build(self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error>;

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>>;
}

/// netlink response error
#[derive(Debug)]
pub enum ResponseError<P> {
    /// underlying protocol error
    ProtocolParse(P),
    /// io error
    Io(std::io::Error),
    /// error when parsing a netlink header
    HeaderParse(crate::netlink::msg::NlMsgHeaderParseError),
}

impl<P> core::fmt::Display for ResponseError<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseError::ProtocolParse(_) => write!(f, "protocol parsing error"),
            ResponseError::Io(error) => {
                write!(f, "io error occured while performing request: {error}")
            }
            ResponseError::HeaderParse(nl_msg_header_parse_error) => {
                write!(f, "{nl_msg_header_parse_error}")
            }
        }
    }
}

impl<P: core::fmt::Debug> core::error::Error for ResponseError<P> {}

impl<P> From<std::io::Error> for ResponseError<P> {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl<P> From<crate::netlink::msg::NlMsgHeaderParseError> for ResponseError<P> {
    fn from(value: crate::netlink::msg::NlMsgHeaderParseError) -> Self {
        Self::HeaderParse(value)
    }
}

impl<P> ResponseError<P> {
    pub fn into_unit(self) -> ResponseError<()> {
        match self {
            ResponseError::ProtocolParse(_) => ResponseError::ProtocolParse(()),
            ResponseError::Io(error) => ResponseError::Io(error),
            ResponseError::HeaderParse(nl_msg_header_parse_error) => {
                ResponseError::HeaderParse(nl_msg_header_parse_error)
            }
        }
    }

    pub fn recover_os_error(self, os_error: i32) -> Result<(), ResponseError<P>> {
        match self {
            ResponseError::ProtocolParse(protocol_parsing_error) => {
                Err(ResponseError::ProtocolParse(protocol_parsing_error))
            }
            ResponseError::Io(error) => Err(ResponseError::Io(error)),
            ResponseError::HeaderParse(nl_msg_header_parse_error) => {
                match &nl_msg_header_parse_error {
                    netlink::msg::NlMsgHeaderParseError::Netlink(error) if *error == os_error => {
                        Ok(())
                    }
                    _ => Err(ResponseError::HeaderParse(nl_msg_header_parse_error)),
                }
            }
        }
    }
}
