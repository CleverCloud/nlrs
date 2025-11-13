// SPDX-License-Identifier: MIT
use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_DUMP, NLM_F_REQUEST},
    },
};

#[derive(Debug)]
pub enum GetLinkParseError {
    UnknowIpFamily,
    UnparsableAddress,
    UnparsableBroadcastAddress,
    UnparsableInterfaceName,
    UnparsableMtu,
    UnparsableLink,
    UnparsableWeight,
    UnparsableOperState,
    UnparsableGroup,
    NoInterfaceName,
}

#[derive(Debug)]
pub struct RawLinkDetails {
    pub index: i32,
    pub attributes: Vec<super::LinkAttribute>,
}

#[derive(Debug)]
pub struct LinkDetails {
    pub index: i32,
    pub name: String,
    pub attributes: Vec<super::LinkAttribute>,
}

impl TryFrom<RawLinkDetails> for LinkDetails {
    type Error = GetLinkParseError;

    fn try_from(value: RawLinkDetails) -> Result<Self, Self::Error> {
        let mut interface_name = None;

        for attribute in &value.attributes {
            #[allow(clippy::single_match)]
            match attribute {
                super::LinkAttribute::InterfaceName(name) => interface_name = Some(name.clone()),
                _ => {}
            }
        }

        Ok(Self {
            index: value.index,
            name: interface_name.ok_or(GetLinkParseError::NoInterfaceName)?,
            attributes: value.attributes,
        })
    }
}

pub fn read_link_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<super::LinkAttribute, crate::ResponseError<GetLinkParseError>> {
    match attribute.r#type {
        super::link_attributes::IFLA_ADDRESS => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableAddress),
        )
        .map(super::LinkAttribute::Address),

        super::link_attributes::IFLA_BROADCAST => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableBroadcastAddress),
        )
        .map(super::LinkAttribute::BroadcastAddress),

        super::link_attributes::IFLA_IFNAME => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableInterfaceName),
        )
        .map(super::LinkAttribute::InterfaceName),

        super::link_attributes::IFLA_MTU => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableMtu),
        )
        .map(super::LinkAttribute::Mtu),

        super::link_attributes::IFLA_LINK => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableLink),
        )
        .map(super::LinkAttribute::Link),

        super::link_attributes::IFLA_WEIGHT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableWeight),
        )
        .map(super::LinkAttribute::Weight),

        super::link_attributes::IFLA_OPERSTATE => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u8_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableOperState),
        )
        .map(super::LinkAttribute::OperationalState),

        super::link_attributes::IFLA_GROUP => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetLinkParseError::UnparsableGroup),
        )
        .map(super::LinkAttribute::Group),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(super::LinkAttribute::Other(other))
        }
    }
}

pub fn read_link_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<RawLinkDetails, crate::ResponseError<GetLinkParseError>> {
    let infos = super::IfInfoMsg::read(reader)?;
    let remaining_bytes = len - super::IfInfoMsg::SIZE;

    let attributes: Result<Vec<super::LinkAttribute>, crate::ResponseError<GetLinkParseError>> =
        crate::netlink::attr::NlAttributeIter::new(reader, read_link_attr, remaining_bytes)
            .map(|e| e.map_err(|e| e.into()).and_then(|e| e))
            .collect();

    Ok(RawLinkDetails {
        index: infos.ifi_index,
        attributes: attributes?,
    })
}

fn read_get_link_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<
    R,
    Result<RawLinkDetails, crate::ResponseError<GetLinkParseError>>,
> {
    crate::netlink::msg::NlMsgIter::new(reader, read_link_msg)
}

/// set message type and flags for a RTM_GETLINK dump request
pub fn get_all_link_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = super::RTM_GETLINK;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct GetAllLinkMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_info_msg: super::IfInfoMsg,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for GetAllLinkMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = ();
    type Output = Vec<LinkDetails>;
    type ParseError = GetLinkParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        _input: Self::Input,
    ) -> Self {
        get_all_link_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_info_msg: super::IfInfoMsg::default(),
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
        read_get_link_response(reader)
            .map(|e| {
                e.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(core::convert::identity)
                    .and_then(|raw_link_details| {
                        LinkDetails::try_from(raw_link_details)
                            .map_err(crate::ResponseError::ProtocolParse)
                    })
            })
            .collect()
    }
}
