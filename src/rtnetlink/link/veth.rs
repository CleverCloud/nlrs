// SPDX-License-Identifier: MIT
//! veth link messages builders
//!
//! ## Create a veth with its peer in a network namespace
//!
//! ```rust
//! use nlrs::{
//!     netlink::socket::NlSocketType,
//!     netns,
//!     rtnetlink::link::veth::AddVethNetnsMsgBuilder,
//!     socket::{NetlinkSocket, RequestBuilder},
//! };
//!
//! let socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE);
//!
//! if let Ok(mut socket) = socket {
//!     let fd = netns::open_netns_file("my_netns");
//!     if let Ok(fd) = fd {
//!         let input = nlrs::rtnetlink::link::veth::AddVethNetnsInput {
//!             if_name: "outer".to_string(),
//!             peer_if_name: "inner".to_string(),
//!             netns_fd: &fd,
//!         };
//!         let mb: AddVethNetnsMsgBuilder<_> = socket.message_builder(input);
//!         _ = mb.call();
//!         drop(fd);
//!     }
//! }
//! ```
use std::os::fd::AsRawFd;

use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST},
    },
};

pub mod veth_infos {
    pub const VETH_INFO_PEER: u16 = 1;
}

pub struct AddVethNetnsInput<'a> {
    pub if_name: String,
    pub peer_if_name: String,
    pub netns_fd: &'a dyn AsRawFd,
}

pub struct AddVethNetnsMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub peer_if_info_msg: super::IfInfoMsg,
    pub if_name: String,
    pub peer_if_name: String,
    pub netns_fd: &'a dyn AsRawFd,
}

pub fn add_veth_netns_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddVethNetnsMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = AddVethNetnsInput<'a>;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        add_veth_netns_nl_header(&mut nl_msg_header);

        let AddVethNetnsInput {
            if_name,
            peer_if_name,
            netns_fd,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::default(),
            peer_if_info_msg: super::IfInfoMsg::default(),
            if_name,
            peer_if_name,
            netns_fd,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        const KIND: &[u8; 4] = b"veth";
        let mut written_bytes = 0;

        let peer_infos_length = super::IfInfoMsg::SIZE
            + crate::netlink::attr::set_attr_length_aligned(4)
            + crate::netlink::attr::set_string_length_aligned(self.peer_if_name.len());

        let if_info_data_length = crate::netlink::attr::set_attr_length_aligned(peer_infos_length);

        let if_infos_length = crate::netlink::attr::set_attr_length_aligned(KIND.len())
            + crate::netlink::attr::set_attr_length_aligned(if_info_data_length);

        self.nl_msg_header.set_playload_length(
            super::IfInfoMsg::SIZE
                + crate::netlink::attr::set_string_length_aligned(self.if_name.len())
                + crate::netlink::attr::set_attr_length_aligned(if_infos_length),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            super::link_attributes::IFLA_IFNAME,
            &self.if_name,
        )?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(if_infos_length) as u16,
            r#type: super::link_attributes::IFLA_LINKINFO,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::link_info_attributes::IFLA_INFO_KIND,
            *KIND,
        )?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(if_info_data_length) as u16,
            r#type: super::link_info_attributes::IFLA_INFO_DATA,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(peer_infos_length) as u16,
            r#type: veth_infos::VETH_INFO_PEER,
        }
        .write(self.buffer)?;

        written_bytes += self.peer_if_info_msg.write(self.buffer)?;
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            super::link_attributes::IFLA_NET_NS_FD,
            self.netns_fd.as_raw_fd(),
        )?;

        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            super::link_attributes::IFLA_IFNAME,
            &self.peer_if_name,
        )?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        crate::netlink::msg::validate_ack(reader)
            .map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
    }
}
