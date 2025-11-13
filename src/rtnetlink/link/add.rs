// SPDX-License-Identifier: MIT
use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST},
    },
};

pub struct AddLinkMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
    pub if_name: String,
    pub if_kind: String,
}

pub fn add_link_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    header.r#type = super::RTM_NEWLINK;
    header.flags = FLAGS;
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddLinkMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = (String, String);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        add_link_nl_header(&mut nl_msg_header);

        let (if_name, if_kind) = input;

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::default(),
            if_name,
            if_kind,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes = 0;

        let if_infos_length = crate::netlink::attr::set_attr_length_aligned(self.if_kind.len());

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

        written_bytes += crate::netlink::attr::write_slice_attr(
            self.buffer,
            super::link_info_attributes::IFLA_INFO_KIND,
            self.if_kind.as_bytes(),
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
