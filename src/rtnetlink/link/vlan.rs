// SPDX-License-Identifier: MIT
//! 802.1q VLAN sub-interface creation (`RTM_NEWLINK` with
//! `IFLA_LINKINFO { IFLA_INFO_KIND = "vlan", IFLA_INFO_DATA { IFLA_VLAN_ID } }`).
//!
//! ## Create a VLAN sub-interface on a parent link
//!
//! ```rust
//! use nlrs::{
//!     netlink::socket::NlSocketType,
//!     rtnetlink::link::vlan::{AddVlanMsgBuilder, AddVlanInput},
//!     socket::{NetlinkSocket, RequestBuilder},
//! };
//!
//! let socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE);
//!
//! if let Ok(mut socket) = socket {
//!     let input = AddVlanInput {
//!         if_name: "ens4.100".to_string(),
//!         parent_if_index: 4,
//!         vlan_id: 100,
//!     };
//!     let mb: AddVlanMsgBuilder<_> = socket.message_builder(input);
//!     _ = mb.call();
//! }
//! ```
use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST},
    },
};

/// VLAN attributes as defined in `linux/if_link.h`
pub mod vlan_attributes {
    /// VLAN id (`IFLA_VLAN_ID` inside `IFLA_INFO_DATA`)
    pub const IFLA_VLAN_ID: u16 = 1;
}

/// Input for creating an 802.1q VLAN sub-interface
pub struct AddVlanInput {
    /// Name of the new VLAN interface (e.g. `"ens4.100"`)
    pub if_name: String,
    /// Index of the parent (trunk) interface
    pub parent_if_index: u32,
    /// 802.1q VLAN id (1–4094)
    pub vlan_id: u16,
}

/// Message builder for `RTM_NEWLINK` with `IFLA_LINKINFO { kind = "vlan" }`
pub struct AddVlanMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub if_name: String,
    pub parent_if_index: u32,
    pub vlan_id: u16,
}

/// Mutate a [`NlMsgHeader`] in place with the flags required for VLAN link creation.
pub fn add_vlan_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddVlanMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = AddVlanInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        add_vlan_nl_header(&mut nl_msg_header);

        let AddVlanInput {
            if_name,
            parent_if_index,
            vlan_id,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::default(),
            if_name,
            parent_if_index,
            vlan_id,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        const KIND: &[u8; 4] = b"vlan";
        let mut written_bytes = 0;

        // IFLA_INFO_DATA contains IFLA_VLAN_ID (u16, 2 bytes)
        let if_info_data_length = crate::netlink::attr::set_attr_length_aligned(2);

        // IFLA_LINKINFO contains IFLA_INFO_KIND + IFLA_INFO_DATA
        let if_infos_length = crate::netlink::attr::set_attr_length_aligned(KIND.len())
            + crate::netlink::attr::set_attr_length_aligned(if_info_data_length);

        // Total payload: IfInfoMsg + IFLA_IFNAME + IFLA_LINK + IFLA_LINKINFO
        self.nl_msg_header.set_playload_length(
            super::IfInfoMsg::SIZE
                + crate::netlink::attr::set_string_length_aligned(self.if_name.len())
                + crate::netlink::attr::set_attr_length_aligned(4) // IFLA_LINK (i32)
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

        // IFLA_LINKINFO (nested)
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(if_infos_length) as u16,
            r#type: super::link_attributes::IFLA_LINKINFO,
        }
        .write(self.buffer)?;

        // IFLA_INFO_KIND = "vlan"
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

        // IFLA_VLAN_ID = vlan identifier
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            vlan_attributes::IFLA_VLAN_ID,
            self.vlan_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MessageBuilder;
    use crate::netlink::msg::NlMsgHeader;

    #[test]
    fn build_writes_vlan_id_attribute() {
        let mut buffer: Vec<u8> = Vec::new();
        let builder = AddVlanMsgBuilder::new_with_header(
            &mut buffer,
            NlMsgHeader::new_with_seq_and_pid(0, 0),
            AddVlanInput {
                if_name: "ens4.687".to_string(),
                parent_if_index: 3,
                vlan_id: 687,
            },
        );
        let (_, written) = builder.build().expect("build should succeed");
        assert!(written > 0);
        assert!(
            buffer.windows(2).any(|w| w == 687u16.to_ne_bytes()),
            "vlan id bytes not found in message"
        );
        assert!(buffer.windows(4).any(|w| w == b"vlan"));
    }
}
