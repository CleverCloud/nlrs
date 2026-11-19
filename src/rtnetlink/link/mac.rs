// SPDX-License-Identifier: MIT
//! link mac address management

use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_REQUEST},
    },
};

pub struct SetMacInput {
    pub interface_index: i32,
    pub address: Vec<u8>,
}

/// Sets the link layer address of a network interface via `RTM_NEWLINK` with `IFLA_ADDRESS`.
#[derive(Debug)]
pub struct SetMacMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub address: Vec<u8>,
}

pub fn set_mac_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for SetMacMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = SetMacInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        set_mac_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::new(input.interface_index),
            address: input.address,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        self.nl_msg_header.set_playload_length(
            super::IfInfoMsg::SIZE
                + crate::netlink::attr::set_attr_length_aligned(self.address.len()),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_slice_attr(
            self.buffer,
            super::link_attributes::IFLA_ADDRESS,
            &self.address,
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
