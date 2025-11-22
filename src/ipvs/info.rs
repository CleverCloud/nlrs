// SPDX-License-Identifier: MIT
//! ipvs information request
use crate::{
    genetlink::GenericMessageBuilder,
    netlink::msg::{NlMsgHeader, flags::NLM_F_REQUEST},
};

pub mod attributes {
    /// ipvs version number
    pub const IPVS_INFO_ATTR_VERSION: u16 = 1;
    /// size of connection hash table
    pub const IPVS_INFO_ATTR_CONN_TAB_SIZE: u16 = 2;
}

pub const IPVS_CMD_GET_INFO: u8 = 15;

#[derive(Debug)]
pub enum GetInfoParseError {
    NoResponse,
    NoVersion,
    NoConnectionTableSize,
    UnparsableVersion,
    UnparsableConnectionTableSize,
}

#[derive(Debug)]
pub enum GetInfoAttribute {
    Version { major: u8, minor: u8, patch: u8 },
    ConnectionTableSize(u32),
    Other(u16),
}

#[derive(Debug)]
pub struct IpvsInfos {
    pub version_major: u8,
    pub version_minor: u8,
    pub version_patch: u8,
    pub connection_table_size: u32,
}

pub fn read_get_info_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<GetInfoAttribute, crate::ResponseError<GetInfoParseError>> {
    match attribute.r#type {
        attributes::IPVS_INFO_ATTR_VERSION => {
            const IPVS_INFO_ATTR_VERSION_SIZE: usize = 4;
            if attribute.len as usize == IPVS_INFO_ATTR_VERSION_SIZE {
                let mut buff = [0u8; IPVS_INFO_ATTR_VERSION_SIZE];
                reader.read_exact(&mut buff)?;

                let major = buff[0];
                let minor = buff[1];
                let patch = buff[2];

                Ok(GetInfoAttribute::Version {
                    major,
                    minor,
                    patch,
                })
            } else {
                Err(crate::ResponseError::ProtocolParse(
                    GetInfoParseError::UnparsableVersion,
                ))
            }
        }

        attributes::IPVS_INFO_ATTR_CONN_TAB_SIZE => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetInfoParseError::UnparsableConnectionTableSize),
        )
        .map(GetInfoAttribute::ConnectionTableSize),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(GetInfoAttribute::Other(other))
        }
    }
}

pub fn read_get_info_response(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<GetInfoAttribute>, crate::ResponseError<GetInfoParseError>> {
    crate::genetlink::msg::skip_generic_netlink_header(reader)?;
    let remaining_bytes = len - crate::genetlink::msg::GeNlMsgHeader::SIZE;

    crate::netlink::attr::NlAttributeIter::new(reader, read_get_info_attr, remaining_bytes)
        .map(|e| e.map_err(Into::into).and_then(core::convert::identity))
        .collect()
}

/// set message type and flags for a IPVS_CMD_GET_INFO request
pub fn get_info_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct GetInfoMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a> for GetInfoMessageBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = ();
    type Output = IpvsInfos;
    type ParseError = GetInfoParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        _input: Self::Input,
    ) -> Self {
        get_info_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_GET_INFO,
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
        let mut message = crate::netlink::msg::NlMsgIter::new(reader, read_get_info_response);

        let mut response = match message.next() {
            Some(e) => e
                .map_err(crate::ResponseError::HeaderParse)
                .and_then(core::convert::identity),
            None => Err(crate::ResponseError::ProtocolParse(
                GetInfoParseError::NoResponse,
            )),
        }?;

        let version_pos = response
            .iter()
            .position(|a| matches!(a, GetInfoAttribute::Version { .. }))
            .ok_or(crate::ResponseError::ProtocolParse(
                GetInfoParseError::NoVersion,
            ))?;
        let (version_major, version_minor, version_patch) = match response.swap_remove(version_pos)
        {
            GetInfoAttribute::Version {
                major,
                minor,
                patch,
            } => (major, minor, patch),
            _ => unreachable!(),
        };

        let connection_table_size_pos = response
            .iter()
            .position(|a| matches!(a, GetInfoAttribute::ConnectionTableSize(_)))
            .ok_or(crate::ResponseError::ProtocolParse(
                GetInfoParseError::NoConnectionTableSize,
            ))?;
        let connection_table_size = match response.swap_remove(connection_table_size_pos) {
            GetInfoAttribute::ConnectionTableSize(s) => s,
            _ => unreachable!(),
        };

        Ok(IpvsInfos {
            version_major,
            version_minor,
            version_patch,
            connection_table_size,
        })
    }
}
