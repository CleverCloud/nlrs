// SPDX-License-Identifier: MIT
use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_REQUEST},
    },
};

/// set message type and flags for a RTM_NEWLINK state up request
pub fn set_state_link_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct SetUpLinkMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for SetUpLinkMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = i32;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        set_state_link_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::new_with_flags_and_change(
                input,
                super::devices_flags::IFF_UP,
                1,
            ),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header
            .set_playload_length(super::IfInfoMsg::SIZE);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        crate::netlink::msg::validate_ack(reader)
            .map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
    }
}

#[derive(Debug)]
pub struct SetDownLinkMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for SetDownLinkMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = i32;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        set_state_link_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::new_with_flags_and_change(input, 0, 1),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header
            .set_playload_length(super::IfInfoMsg::SIZE);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_info_msg.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        crate::netlink::msg::validate_ack(reader)
            .map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
    }
}
