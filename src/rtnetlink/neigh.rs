// SPDX-License-Identifier: MIT
//! ip neighbour management
//!
//! # Getting neighbours
//!
//! ```rust
//! use nlrs::netlink::socket::NlSocketType;
//! use nlrs::rtnetlink::neigh::GetNeighMsgBuilder;
//! use nlrs::rtnetlink::IpFamily;
//! use nlrs::socket::{NetlinkSocket, RequestBuilder};
//!
//! if let Ok(mut socket) = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE) {
//!     let req: GetNeighMsgBuilder<_> = socket.message_builder(IpFamily::AF_INET);
//!     let res = req.call();
//!
//!     println!("{res:#?}");
//! };
//!
//! ```

use crate::MessageBuilder;
use crate::netlink::msg::NlMsgHeader;
use crate::netlink::msg::flags::{NLM_F_DUMP, NLM_F_REQUEST};

use super::IpFamily;

// netlink message type to add a neighbour
pub const RTM_NEWNEIGH: u16 = 28;
// netlink message type to delete a neighbour
pub const RTM_DELNEIGH: u16 = 29;
// netlink message type to get neighbours
pub const RTM_GETNEIGH: u16 = 30;

#[derive(Debug)]
#[repr(C, packed)]
pub struct NdMsg {
    /// ip family (```AF_INET``` or ```AF_INET6```)
    pub family: u8,
    pub _pad1: u8,
    pub _pad2: u16,
    /// interface (link) index
    pub ifindex: i32,
    pub state: u16,
    pub flags: u8,
    pub r#type: u8,
}

impl NdMsg {
    /// size of a [`NdMsg`] in bytes
    pub const SIZE: usize = std::mem::size_of::<NdMsg>();

    pub fn new_with_family(family: IpFamily) -> Self {
        Self {
            family: family as u8,
            ..Default::default()
        }
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<NdMsg, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

impl Default for NdMsg {
    fn default() -> Self {
        NdMsg {
            family: IpFamily::AF_INET as u8,
            _pad1: 0,
            _pad2: 0,
            ifindex: 0,
            state: 0,
            flags: 0,
            r#type: 0,
        }
    }
}

/// set message type and flags for a RTM_GETNEIGH request
pub fn get_neigh_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = RTM_GETNEIGH;
    header.flags = FLAGS;
}

const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;
const NUD_NONE: u16 = 0x00;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum NeighbourState {
    Incomplete = 1,
    Reachable,
    Stale,
    Delay,
    Probe,
    Failed,
    Noarp,
    Permanent,
    None,
    Other(u16),
}

impl From<u16> for NeighbourState {
    fn from(d: u16) -> Self {
        match d {
            NUD_INCOMPLETE => Self::Incomplete,
            NUD_REACHABLE => Self::Reachable,
            NUD_STALE => Self::Stale,
            NUD_DELAY => Self::Delay,
            NUD_PROBE => Self::Probe,
            NUD_FAILED => Self::Failed,
            NUD_NOARP => Self::Noarp,
            NUD_PERMANENT => Self::Permanent,
            NUD_NONE => Self::None,
            _ => Self::Other(d),
        }
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct NeighbourCacheInfo {
    pub confirmed: u32,
    pub used: u32,
    pub updated: u32,
    pub refcnt: u32,
}

pub fn read_neighbour_cache_info(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<NeighbourCacheInfo>, std::io::Error> {
    if len == ::core::mem::size_of::<NeighbourCacheInfo>() {
        Ok(Some(crate::netlink::utils::transpose_read(reader)?))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub enum NeighbourAttribute {
    Destination(std::net::IpAddr),
    LinkLocalAddress([u8; 6]),
    CacheInfo(NeighbourCacheInfo),
    Probes(u32),
    Other(u16),
}

#[derive(Debug)]
pub struct Neighbour {
    pub family: super::IpFamily,
    pub ifindex: i32,
    // TODO parse flags
    pub state: NeighbourState,
    pub r#type: super::route::RouteType,
    pub attributes: Vec<NeighbourAttribute>,
}

#[derive(Debug)]
pub enum GetNeighbourParseError {
    UnknowIpFamily,
    UnparsableDestination,
    UnParsableCacheInfo,
    UnparsableLinkLocalAddrss,
    UnparsableProbes,
}

pub fn read_neighbour_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<NeighbourAttribute, crate::ResponseError<GetNeighbourParseError>> {
    // TODO put real constant here
    match attribute.r#type {
        1 => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetNeighbourParseError::UnparsableDestination),
        )
        .map(NeighbourAttribute::Destination),

        2 => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetNeighbourParseError::UnparsableLinkLocalAddrss),
        )
        .map(NeighbourAttribute::LinkLocalAddress),

        3 => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            read_neighbour_cache_info,
            crate::ResponseError::ProtocolParse(GetNeighbourParseError::UnParsableCacheInfo),
        )
        .map(NeighbourAttribute::CacheInfo),

        4 => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetNeighbourParseError::UnparsableLinkLocalAddrss),
        )
        .map(NeighbourAttribute::Probes),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(NeighbourAttribute::Other(other))
        }
    }
}

pub fn read_neighbour_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Neighbour, crate::ResponseError<GetNeighbourParseError>> {
    let ndmsg = NdMsg::read(reader)?;
    let remaining_bytes = len - NdMsg::SIZE;

    let family = ndmsg
        .family
        .try_into()
        .map_err(|_| crate::ResponseError::ProtocolParse(GetNeighbourParseError::UnknowIpFamily))?;

    let attributes: Result<Vec<NeighbourAttribute>, crate::ResponseError<GetNeighbourParseError>> =
        crate::netlink::attr::NlAttributeIter::new(reader, read_neighbour_attr, remaining_bytes)
            .map(|e| e.map_err(Into::into).and_then(core::convert::identity))
            .collect();

    Ok(Neighbour {
        family,
        ifindex: ndmsg.ifindex,
        state: ndmsg.state.into(),
        r#type: ndmsg.r#type.into(),
        attributes: attributes?,
    })
}

fn read_get_neighbour_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<
    '_,
    R,
    Result<Neighbour, crate::ResponseError<GetNeighbourParseError>>,
> {
    crate::netlink::msg::NlMsgIter::new(reader, read_neighbour_msg)
}

#[derive(Debug)]
pub struct GetNeighMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub nd_msg: NdMsg,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for GetNeighMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = IpFamily;
    type Output = Vec<Neighbour>;
    type ParseError = GetNeighbourParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        let mut res = Self {
            buffer,
            nl_msg_header,
            nd_msg: NdMsg::new_with_family(input),
        };

        get_neigh_nl_header(&mut res.nl_msg_header);

        res
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(NdMsg::SIZE);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.nd_msg.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        read_get_neighbour_response(reader)
            .map(|e| {
                e.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(core::convert::identity)
            })
            .collect()
    }
}
