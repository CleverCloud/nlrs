// SPDX-License-Identifier: MIT
//! link master management
//!
//! Set or unset the master device of a network interface. This is used to
//! enslave an interface to a bridge, bond, or other master device.
//!
//! ## Enslave a veth interface to a bridge
//!
//! ```rust
//! use nlrs::{
//!     netlink::socket::NlSocketType,
//!     posix::interface_name_to_index,
//!     rtnetlink::link::master::{SetMasterInput, SetMasterMsgBuilder},
//!     socket::{NetlinkSocket, RequestBuilder},
//! };
//!
//! let socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE);
//!
//! if let Ok(mut socket) = socket {
//!     if let (Some(veth_index), Some(bridge_index)) = (
//!         interface_name_to_index("veth0"),
//!         interface_name_to_index("br0"),
//!     ) {
//!         let input = SetMasterInput {
//!             interface_index: veth_index as i32,
//!             master_index: bridge_index as i32,
//!         };
//!         let mb: SetMasterMsgBuilder<_> = socket.message_builder(input);
//!         _ = mb.call();
//!     }
//! }
//! ```

use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_REQUEST},
    },
};

/// Input for [`SetMasterMsgBuilder`]
pub struct SetMasterInput {
    /// Index of the interface to enslave
    pub interface_index: i32,
    /// Index of the master device (bridge, bond, etc.), or 0 to remove master
    pub master_index: i32,
}

/// Sets the master device of a network interface via `RTM_NEWLINK` with `IFLA_MASTER`.
///
/// This is the netlink equivalent of `ip link set dev <iface> master <bridge>`.
/// Setting `master_index` to 0 removes the interface from its master (nomaster).
#[derive(Debug)]
pub struct SetMasterMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub master_index: i32,
}

pub fn set_master_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for SetMasterMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = SetMasterInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        set_master_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::new(input.interface_index),
            master_index: input.master_index,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        // Payload: IfInfoMsg + IFLA_MASTER (i32)
        self.nl_msg_header.set_playload_length(
            super::IfInfoMsg::SIZE + crate::netlink::attr::set_attr_length_aligned(4),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        // IFLA_MASTER = master device interface index
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            super::link_attributes::IFLA_MASTER,
            self.master_index,
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
