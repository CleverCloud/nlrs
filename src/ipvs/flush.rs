// SPDX-License-Identifier: MIT
//! ipvs flush request
use crate::{
    genetlink::GenericMessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_REQUEST},
    },
};

pub const IPVS_CMD_FLUSH: u8 = 17;

/// set message type and flags for a IPVS_CMD_FLUSH request
pub fn flush_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct FlushMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a> for FlushMessageBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = ();
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        _input: Self::Input,
    ) -> Self {
        flush_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_FLUSH,
                super::IPVS_GENL_VERSION,
            ),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_generic_playload_length(0);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        crate::netlink::msg::validate_ack(reader)
            .map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
    }
}
