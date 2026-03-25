// SPDX-License-Identifier: MIT
//! ipvlan link messages builders
//!
//! ipvlan interfaces share the parent's MAC address and are placed directly
//! in a target network namespace. This is useful when upstream network
//! equipment filters by MAC and a unique MAC per namespace is
//! not feasible.
//!
//! ## Create an ipvlan child in a network namespace
//!
//! ```rust
//! use nlrs::{
//!     netlink::socket::NlSocketType,
//!     netns,
//!     rtnetlink::link::ipvlan::{AddIpvlanNetnsMsgBuilder, IpvlanMode},
//!     socket::{NetlinkSocket, RequestBuilder},
//! };
//!
//! let socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE);
//!
//! if let Ok(mut socket) = socket {
//!     let fd = netns::open_netns_file("my_netns");
//!     if let Ok(fd) = fd {
//!         let input = nlrs::rtnetlink::link::ipvlan::AddIpvlanNetnsInput {
//!             if_name: "ipvl0".to_string(),
//!             parent_if_index: 2,
//!             mode: IpvlanMode::L2,
//!             netns_fd: &fd,
//!         };
//!         let mb: AddIpvlanNetnsMsgBuilder<_> = socket.message_builder(input);
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

/// ipvlan mode as defined in `linux/if_link.h`
pub mod ipvlan_infos {
    /// ipvlan operating mode (`IFLA_IPVLAN_MODE` inside `IFLA_INFO_DATA`)
    pub const IFLA_IPVLAN_MODE: u16 = 1;
    /// ipvlan flags (`IFLA_IPVLAN_FLAGS` inside `IFLA_INFO_DATA`)
    pub const IFLA_IPVLAN_FLAGS: u16 = 2;
}

/// ipvlan operating mode
///
/// See `linux/if_link.h` `IPVLAN_MODE_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum IpvlanMode {
    /// L2 mode -- frames are switched based on MAC, shares parent MAC
    L2 = 0,
    /// L3 mode -- packets are routed, no broadcast/multicast
    L3 = 1,
    /// L3S mode -- like L3 but with connection tracking (conntrack) support
    L3S = 2,
}

pub struct AddIpvlanNetnsInput<'a> {
    pub if_name: String,
    pub parent_if_index: u32,
    pub mode: IpvlanMode,
    pub netns_fd: &'a dyn AsRawFd,
}

pub struct AddIpvlanNetnsMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub if_name: String,
    pub parent_if_index: u32,
    pub mode: IpvlanMode,
    pub netns_fd: &'a dyn AsRawFd,
}

pub fn add_ipvlan_netns_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddIpvlanNetnsMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = AddIpvlanNetnsInput<'a>;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        add_ipvlan_netns_nl_header(&mut nl_msg_header);

        let AddIpvlanNetnsInput {
            if_name,
            parent_if_index,
            mode,
            netns_fd,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::default(),
            if_name,
            parent_if_index,
            mode,
            netns_fd,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        const KIND: &[u8; 6] = b"ipvlan";
        let mut written_bytes = 0;

        // IFLA_INFO_DATA contains IFLA_IPVLAN_MODE (u16, 2 bytes)
        let if_info_data_length = crate::netlink::attr::set_attr_length_aligned(2);

        // IFLA_LINKINFO contains IFLA_INFO_KIND + IFLA_INFO_DATA
        let if_infos_length = crate::netlink::attr::set_attr_length_aligned(KIND.len())
            + crate::netlink::attr::set_attr_length_aligned(if_info_data_length);

        // Total payload: IfInfoMsg + IFLA_IFNAME + IFLA_LINK + IFLA_NET_NS_FD + IFLA_LINKINFO
        self.nl_msg_header.set_playload_length(
            super::IfInfoMsg::SIZE
                + crate::netlink::attr::set_string_length_aligned(self.if_name.len())
                + crate::netlink::attr::set_attr_length_aligned(4) // IFLA_LINK (i32)
                + crate::netlink::attr::set_attr_length_aligned(4) // IFLA_NET_NS_FD (i32)
                + crate::netlink::attr::set_attr_length_aligned(if_infos_length), // IFLA_LINKINFO
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        // IFLA_IFNAME = interface name
        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            super::link_attributes::IFLA_IFNAME,
            &self.if_name,
        )?;

        // IFLA_LINK = parent interface index
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            super::link_attributes::IFLA_LINK,
            self.parent_if_index as i32,
        )?;

        // IFLA_NET_NS_FD = target network namespace file descriptor
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            super::link_attributes::IFLA_NET_NS_FD,
            self.netns_fd.as_raw_fd(),
        )?;

        // IFLA_LINKINFO (nested)
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(if_infos_length) as u16,
            r#type: super::link_attributes::IFLA_LINKINFO,
        }
        .write(self.buffer)?;

        // IFLA_INFO_KIND = "ipvlan"
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::link_info_attributes::IFLA_INFO_KIND,
            *KIND,
        )?;

        // IFLA_INFO_DATA (nested)
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(if_info_data_length) as u16,
            r#type: super::link_info_attributes::IFLA_INFO_DATA,
        }
        .write(self.buffer)?;

        // IFLA_IPVLAN_MODE = mode value
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            ipvlan_infos::IFLA_IPVLAN_MODE,
            self.mode as u16,
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
