// SPDX-License-Identifier: MIT
use crate::{
    MessageBuilder,
    netlink::msg::{NlMsgHeader, flags::NLM_F_REQUEST},
};

#[derive(Debug)]
#[repr(C, packed)]
pub struct GeNlMsgHeader {
    cmd: u8,
    version: u8,
    reserved: u16,
}

impl GeNlMsgHeader {
    /// size of a [`GeNlMsgHeader`] in bytes
    pub const SIZE: usize = core::mem::size_of::<GeNlMsgHeader>();

    pub fn new(cmd: u8, version: u8) -> Self {
        Self {
            cmd,
            version,
            reserved: 0, // Reserved, set to 0
        }
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<GeNlMsgHeader, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

impl NlMsgHeader {
    #[inline]
    pub fn set_generic_playload_length(&mut self, len: usize) -> usize {
        self.set_playload_length(GeNlMsgHeader::SIZE + len)
    }
}

pub const GENL_ID_CTRL: u16 = crate::netlink::msg::NLMSG_MIN_TYPE;
pub const CTRL_CMD_GETFAMILY: u8 = 3;

pub mod attributes {
    pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
    pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    pub const CTRL_ATTR_VERSION: u16 = 3;
    pub const CTRL_ATTR_HDRSIZE: u16 = 4;
    pub const CTRL_ATTR_MAXATTR: u16 = 5;
    pub const CTRL_ATTR_OPS: u16 = 6;
}

/// set message type and flags for a GENL_ID_CTRL request
pub fn resolve_family_id_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST;
    header.r#type = GENL_ID_CTRL;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub enum ResolveFamilyIdParseError {
    NoResponse,
    NoFamilyId,
    UnparsableFamilyId,
    UnparsableFamilyString,
    UnparsableFamilyVersion,
    UnparsableFamilyHeaderSize,
    UnparsableFamilyMaxAttributes,
}

#[derive(Debug)]
pub enum GeNetlinkAttribute {
    FamilyId(u16),
    FamilyName(String),
    FamilyVersion(u32),
    FamilyHeaderSize(u32),
    MaxAttributes(u32),
    // TODO parse ops
    AttributeOps,
    Other(u16),
}

#[derive(Debug)]
pub struct FamilyResolution {
    pub family_id: u16,
    pub attributes: Vec<GeNetlinkAttribute>,
}

pub fn read_family_resolution_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<GeNetlinkAttribute, crate::ResponseError<ResolveFamilyIdParseError>> {
    match attribute.r#type {
        attributes::CTRL_ATTR_FAMILY_ID => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(ResolveFamilyIdParseError::UnparsableFamilyId),
        )
        .map(GeNetlinkAttribute::FamilyId),

        attributes::CTRL_ATTR_FAMILY_NAME => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(ResolveFamilyIdParseError::UnparsableFamilyString),
        )
        .map(GeNetlinkAttribute::FamilyName),

        attributes::CTRL_ATTR_VERSION => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(ResolveFamilyIdParseError::UnparsableFamilyVersion),
        )
        .map(GeNetlinkAttribute::FamilyVersion),

        attributes::CTRL_ATTR_HDRSIZE => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(
                ResolveFamilyIdParseError::UnparsableFamilyHeaderSize,
            ),
        )
        .map(GeNetlinkAttribute::FamilyHeaderSize),

        attributes::CTRL_ATTR_MAXATTR => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(
                ResolveFamilyIdParseError::UnparsableFamilyMaxAttributes,
            ),
        )
        .map(GeNetlinkAttribute::MaxAttributes),

        attributes::CTRL_ATTR_OPS => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(GeNetlinkAttribute::AttributeOps)
        }

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(GeNetlinkAttribute::Other(other))
        }
    }
}

pub fn read_family_resolution(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<GeNetlinkAttribute>, crate::ResponseError<ResolveFamilyIdParseError>> {
    skip_generic_netlink_header(reader)?;
    let remaining_bytes = len - GeNlMsgHeader::SIZE;

    crate::netlink::attr::NlAttributeIter::new(reader, read_family_resolution_attr, remaining_bytes)
        .map(|e| e.map_err(Into::into).and_then(core::convert::identity))
        .collect()
}

pub struct ResolveFamilyIdMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub ge_nl_msg_header: GeNlMsgHeader,
    pub family: String,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for ResolveFamilyIdMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;

    type Input = String;

    type Output = FamilyResolution;

    type ParseError = ResolveFamilyIdParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        let mut res = Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: GeNlMsgHeader::new(CTRL_CMD_GETFAMILY, 2), // version is irrelevant, set to 2
            family: input,
        };

        resolve_family_id_nl_header(&mut res.nl_msg_header);

        res
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_generic_playload_length(
            crate::netlink::attr::set_string_length_aligned(self.family.len()),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;
        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            attributes::CTRL_ATTR_FAMILY_NAME,
            &self.family,
        )?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        let mut i = crate::netlink::msg::NlMsgIter::new(reader, read_family_resolution);

        let mut attributes = match i.next() {
            Some(e) => e
                .map_err(crate::ResponseError::HeaderParse)
                .and_then(core::convert::identity),
            None => Err(crate::ResponseError::ProtocolParse(
                ResolveFamilyIdParseError::NoResponse,
            )),
        }?;

        let family_id_pos = attributes
            .iter()
            .position(|a| matches!(a, GeNetlinkAttribute::FamilyId(_)))
            .ok_or(crate::ResponseError::ProtocolParse(
                ResolveFamilyIdParseError::NoFamilyId,
            ))?;
        let family_id = match attributes.swap_remove(family_id_pos) {
            GeNetlinkAttribute::FamilyId(id) => id,
            _ => unreachable!(),
        };

        Ok(FamilyResolution {
            family_id,
            attributes,
        })
    }
}

/// helper to make a reader skip a generic netlink header
pub fn skip_generic_netlink_header(reader: &mut impl std::io::Read) -> Result<(), std::io::Error> {
    let mut sink = [0u8; GeNlMsgHeader::SIZE];

    reader.read_exact(&mut sink)
}
