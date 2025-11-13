// SPDX-License-Identifier: MIT
//! ip route management
//!
//! ## Getting routes
//!
//! ```rust
//! use nlrs::netlink::socket::NlSocketType;
//! use nlrs::rtnetlink::IpFamily;
//! use nlrs::rtnetlink::route::GetAllRouteMsgBuilder;
//! use nlrs::socket::{NetlinkSocket, RequestBuilder};
//!
//! if let Ok(mut socket) = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE) {
//!     let req: GetAllRouteMsgBuilder<_> = socket.message_builder(IpFamily::AF_INET);
//!     let res = req.call();
//!
//!     println!("{res:#?}");
//! };
//! ```
use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST},
    },
};

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

#[derive(Debug)]
#[repr(C, packed)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,

    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,

    pub rtm_flags: u32,
}

impl RtMsg {
    /// size of a [`RtMsg`] in bytes
    pub const SIZE: usize = std::mem::size_of::<RtMsg>();

    pub fn new_with_family(family: super::IpFamily) -> Self {
        Self {
            rtm_family: family as u8,
            ..Default::default()
        }
    }

    pub fn new_with_family_and_add_route_defaults(family: super::IpFamily) -> Self {
        Self {
            rtm_family: family as u8,
            rtm_dst_len: match family {
                super::IpFamily::AF_INET => 32,
                super::IpFamily::AF_INET6 => 128,
            },
            rtm_table: route_tables::RT_TABLE_MAIN,
            rtm_protocol: route_protocols::RTPROT_BOOT,
            rtm_scope: route_scopes::RT_SCOPE_LINK,
            rtm_type: route_types::RTN_UNICAST,
            ..Default::default()
        }
    }

    pub fn new_with_family_and_add_gateway_defaults(family: super::IpFamily) -> Self {
        Self {
            rtm_family: family as u8,
            rtm_table: route_tables::RT_TABLE_MAIN,
            rtm_protocol: route_protocols::RTPROT_BOOT,
            rtm_scope: route_scopes::RT_SCOPE_UNIVERSE,
            rtm_type: route_types::RTN_UNICAST,
            ..Default::default()
        }
    }

    pub fn new_with_family_and_del_route_defaults(family: super::IpFamily) -> Self {
        Self {
            rtm_family: family as u8,
            rtm_dst_len: match family {
                super::IpFamily::AF_INET => 32,
                super::IpFamily::AF_INET6 => 128,
            },
            rtm_scope: route_scopes::RT_SCOPE_NOWHERE,
            ..Default::default()
        }
    }

    pub fn new_with_family_and_del_gateway_defaults(family: super::IpFamily) -> Self {
        Self {
            rtm_family: family as u8,
            rtm_scope: route_scopes::RT_SCOPE_NOWHERE,
            ..Default::default()
        }
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<RtMsg, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

impl Default for RtMsg {
    fn default() -> Self {
        Self {
            rtm_family: super::IpFamily::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 0,
            rtm_protocol: 0,
            rtm_scope: 0,
            rtm_type: 0,
            rtm_flags: 0,
        }
    }
}

#[derive(Debug)]
pub struct RtaCacheInfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: i32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}

impl RtaCacheInfo {
    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<RtaCacheInfo, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

pub fn read_rta_cache_info(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<RtaCacheInfo>, std::io::Error> {
    if len == ::core::mem::size_of::<RtaCacheInfo>() {
        Ok(Some(crate::netlink::utils::transpose_read(reader)?))
    } else {
        Ok(None)
    }
}

pub mod route_attributes {
    pub const RTA_DST: u16 = 1;
    pub const RTA_SRC: u16 = 2;
    pub const RTA_IIF: u16 = 3;
    pub const RTA_OIF: u16 = 4;
    pub const RTA_GATEWAY: u16 = 5;
    pub const RTA_PRIORITY: u16 = 6;
    pub const RTA_PREFSRC: u16 = 7;
    pub const RTA_METRICS: u16 = 8;
    pub const RTA_MULTIPATH: u16 = 9;
    pub const RTA_FLOW: u16 = 11;
    pub const RTA_CACHEINFO: u16 = 12;
    pub const RTA_TABLE: u16 = 15;
    pub const RTA_MARK: u16 = 16;
    pub const RTA_MFC_STATS: u16 = 17;
    pub const RTA_VIA: u16 = 18;
    pub const RTA_NEWDST: u16 = 19;
    pub const RTA_PREF: u16 = 20;
    pub const RTA_ENCAP_TYPE: u16 = 21;
    pub const RTA_ENCAP: u16 = 22;
    pub const RTA_EXPIRES: u16 = 23;
    pub const RTA_PAD: u16 = 24;
    pub const RTA_UID: u16 = 25;
    pub const RTA_TTL_PROPAGATE: u16 = 26;
    pub const RTA_IP_PROTO: u16 = 27;
    pub const RTA_SPORT: u16 = 28;
    pub const RTA_DPORT: u16 = 29;
    pub const RTA_NH_ID: u16 = 30;
    pub const RTA_FLOWLABEL: u16 = 31;
}

pub mod route_tables {
    pub const RT_TABLE_COMPAT: u8 = 252;
    pub const RT_TABLE_DEFAULT: u8 = 253;
    pub const RT_TABLE_MAIN: u8 = 254;
    pub const RT_TABLE_LOCAL: u8 = 255;
}

pub mod route_protocols {
    pub const RTPROT_UNSPEC: u8 = 0;
    pub const RTPROT_REDIRECT: u8 = 1;
    pub const RTPROT_KERNEL: u8 = 2;
    pub const RTPROT_BOOT: u8 = 3;
    pub const RTPROT_STATIC: u8 = 4;
    pub const RTPROT_GATED: u8 = 8;
    pub const RTPROT_RA: u8 = 9;
    pub const RTPROT_MRT: u8 = 10;
    pub const RTPROT_ZEBRA: u8 = 11;
    pub const RTPROT_BIRD: u8 = 12;
    pub const RTPROT_DNROUTED: u8 = 13;
    pub const RTPROT_XORP: u8 = 14;
    pub const RTPROT_NTK: u8 = 15;
    pub const RTPROT_DHCP: u8 = 16;
    pub const RTPROT_MROUTED: u8 = 17;
    pub const RTPROT_KEEPALIVED: u8 = 18;
    pub const RTPROT_BABEL: u8 = 42;
    pub const RTPROT_OVN: u8 = 84;
    pub const RTPROT_OPENR: u8 = 99;
    pub const RTPROT_BGP: u8 = 186;
    pub const RTPROT_ISIS: u8 = 187;
    pub const RTPROT_OSPF: u8 = 188;
    pub const RTPROT_RIP: u8 = 189;
    pub const RTPROT_EIGRP: u8 = 192;
}

pub mod route_scopes {
    pub const RT_SCOPE_UNIVERSE: u8 = 0;
    pub const RT_SCOPE_SITE: u8 = 200;
    pub const RT_SCOPE_LINK: u8 = 253;
    pub const RT_SCOPE_HOST: u8 = 254;
    pub const RT_SCOPE_NOWHERE: u8 = 255;
}

pub mod route_types {
    pub const RTN_UNSPEC: u8 = 0;
    pub const RTN_UNICAST: u8 = 1;
    pub const RTN_LOCAL: u8 = 2;
    pub const RTN_BROADCAST: u8 = 3;
    pub const RTN_ANYCAST: u8 = 4;
    pub const RTN_MULTICAST: u8 = 5;
    pub const RTN_BLACKHOLE: u8 = 6;
    pub const RTN_UNREACHABLE: u8 = 7;
    pub const RTN_PROHIBIT: u8 = 8;
    pub const RTN_THROW: u8 = 9;
    pub const RTN_NAT: u8 = 10;
    pub const RTN_XRESOLVE: u8 = 11;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RouteTable {
    Compat,
    Default,
    Main,
    Local,
    Other(u32),
}

impl From<RouteTable> for u8 {
    fn from(value: RouteTable) -> Self {
        match value {
            RouteTable::Compat => route_tables::RT_TABLE_COMPAT,
            RouteTable::Default => route_tables::RT_TABLE_DEFAULT,
            RouteTable::Main => route_tables::RT_TABLE_MAIN,
            RouteTable::Local => route_tables::RT_TABLE_LOCAL,
            RouteTable::Other(_) => 0,
        }
    }
}

impl From<u8> for RouteTable {
    fn from(value: u8) -> Self {
        match value {
            route_tables::RT_TABLE_COMPAT => RouteTable::Compat,
            route_tables::RT_TABLE_DEFAULT => RouteTable::Default,
            route_tables::RT_TABLE_MAIN => RouteTable::Main,
            route_tables::RT_TABLE_LOCAL => RouteTable::Local,
            other => RouteTable::Other(other as u32),
        }
    }
}

impl From<u32> for RouteTable {
    fn from(value: u32) -> Self {
        match value {
            val if val == route_tables::RT_TABLE_COMPAT as u32 => RouteTable::Compat,
            val if val == route_tables::RT_TABLE_DEFAULT as u32 => RouteTable::Default,
            val if val == route_tables::RT_TABLE_MAIN as u32 => RouteTable::Main,
            val if val == route_tables::RT_TABLE_LOCAL as u32 => RouteTable::Local,
            other => RouteTable::Other(other),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum RouteProtocol {
    Unspec = route_protocols::RTPROT_UNSPEC,
    IcmpRedirect = route_protocols::RTPROT_REDIRECT,
    Kernel = route_protocols::RTPROT_KERNEL,
    Boot = route_protocols::RTPROT_BOOT,
    Static = route_protocols::RTPROT_STATIC,
    Gated = route_protocols::RTPROT_GATED,
    Ra = route_protocols::RTPROT_RA,
    Mrt = route_protocols::RTPROT_MRT,
    Zebra = route_protocols::RTPROT_ZEBRA,
    Bird = route_protocols::RTPROT_BIRD,
    DnRouted = route_protocols::RTPROT_DNROUTED,
    Xorp = route_protocols::RTPROT_XORP,
    Ntk = route_protocols::RTPROT_NTK,
    Dhcp = route_protocols::RTPROT_DHCP,
    Mrouted = route_protocols::RTPROT_MROUTED,
    KeepAlived = route_protocols::RTPROT_KEEPALIVED,
    Babel = route_protocols::RTPROT_BABEL,
    Ovn = route_protocols::RTPROT_OVN,
    OpenR = route_protocols::RTPROT_OPENR,
    Bgp = route_protocols::RTPROT_BGP,
    Isis = route_protocols::RTPROT_ISIS,
    Ospf = route_protocols::RTPROT_OSPF,
    Rip = route_protocols::RTPROT_RIP,
    Eigrp = route_protocols::RTPROT_EIGRP,
    Other(u8),
}

impl From<u8> for RouteProtocol {
    fn from(value: u8) -> Self {
        match value {
            route_protocols::RTPROT_UNSPEC => RouteProtocol::Unspec,
            route_protocols::RTPROT_REDIRECT => RouteProtocol::IcmpRedirect,
            route_protocols::RTPROT_KERNEL => RouteProtocol::Kernel,
            route_protocols::RTPROT_BOOT => RouteProtocol::Boot,
            route_protocols::RTPROT_STATIC => RouteProtocol::Static,
            route_protocols::RTPROT_GATED => RouteProtocol::Gated,
            route_protocols::RTPROT_RA => RouteProtocol::Ra,
            route_protocols::RTPROT_MRT => RouteProtocol::Mrt,
            route_protocols::RTPROT_ZEBRA => RouteProtocol::Zebra,
            route_protocols::RTPROT_BIRD => RouteProtocol::Bird,
            route_protocols::RTPROT_DNROUTED => RouteProtocol::DnRouted,
            route_protocols::RTPROT_XORP => RouteProtocol::Xorp,
            route_protocols::RTPROT_NTK => RouteProtocol::Ntk,
            route_protocols::RTPROT_DHCP => RouteProtocol::Dhcp,
            route_protocols::RTPROT_MROUTED => RouteProtocol::Mrouted,
            route_protocols::RTPROT_KEEPALIVED => RouteProtocol::KeepAlived,
            route_protocols::RTPROT_BABEL => RouteProtocol::Babel,
            route_protocols::RTPROT_OVN => RouteProtocol::Ovn,
            route_protocols::RTPROT_OPENR => RouteProtocol::OpenR,
            route_protocols::RTPROT_BGP => RouteProtocol::Bgp,
            route_protocols::RTPROT_ISIS => RouteProtocol::Isis,
            route_protocols::RTPROT_OSPF => RouteProtocol::Ospf,
            route_protocols::RTPROT_RIP => RouteProtocol::Rip,
            route_protocols::RTPROT_EIGRP => RouteProtocol::Eigrp,
            other => RouteProtocol::Other(other),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RouteScope {
    Universe = route_scopes::RT_SCOPE_UNIVERSE,
    Other(u8),
    Site = route_scopes::RT_SCOPE_SITE,
    Link = route_scopes::RT_SCOPE_LINK,
    Host = route_scopes::RT_SCOPE_HOST,
    NoWhere = route_scopes::RT_SCOPE_NOWHERE,
}

impl From<u8> for RouteScope {
    fn from(value: u8) -> Self {
        match value {
            route_scopes::RT_SCOPE_UNIVERSE => RouteScope::Universe,
            route_scopes::RT_SCOPE_SITE => RouteScope::Site,
            route_scopes::RT_SCOPE_LINK => RouteScope::Link,
            route_scopes::RT_SCOPE_HOST => RouteScope::Host,
            route_scopes::RT_SCOPE_NOWHERE => RouteScope::NoWhere,
            other => RouteScope::Other(other),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RouteType {
    /// unknown
    Unspec = route_types::RTN_UNSPEC,
    /// gateway or direct route
    Unicast = route_types::RTN_UNICAST,
    /// accept locally
    Local = route_types::RTN_LOCAL,
    /// accept locally as broadcast, send as broadcast
    Broadcast = route_types::RTN_BROADCAST,
    /// accept locally as broadcast, but send as unicast
    Anycast = route_types::RTN_ANYCAST,
    /// multicast route
    Multicast = route_types::RTN_MULTICAST,
    /// drop
    BlackHole = route_types::RTN_BLACKHOLE,
    /// destination is unreachable
    Unreachable = route_types::RTN_UNREACHABLE,
    /// administratively prohibited
    Prohibit = route_types::RTN_PROHIBIT,
    /// not in this table
    Throw = route_types::RTN_THROW,
    /// translate this address
    Nat = route_types::RTN_NAT,
    /// use external resolver
    ExternalResolve = route_types::RTN_XRESOLVE,
    Other(u8),
}

impl From<u8> for RouteType {
    fn from(d: u8) -> Self {
        match d {
            route_types::RTN_UNSPEC => Self::Unspec,
            route_types::RTN_UNICAST => Self::Unicast,
            route_types::RTN_LOCAL => Self::Local,
            route_types::RTN_BROADCAST => Self::Broadcast,
            route_types::RTN_ANYCAST => Self::Anycast,
            route_types::RTN_MULTICAST => Self::Multicast,
            route_types::RTN_BLACKHOLE => Self::BlackHole,
            route_types::RTN_UNREACHABLE => Self::Unreachable,
            route_types::RTN_PROHIBIT => Self::Prohibit,
            route_types::RTN_THROW => Self::Throw,
            route_types::RTN_NAT => Self::Nat,
            route_types::RTN_XRESOLVE => Self::ExternalResolve,
            _ => Self::Other(d),
        }
    }
}

#[derive(Debug)]
pub enum RouteAttribute {
    Destination(std::net::IpAddr),
    OutInterface(i32),
    Gateway(std::net::IpAddr),
    Priority(u32),
    PreferedSource(std::net::IpAddr),
    CacheInfo(RtaCacheInfo),
    Table(RouteTable),
    Preference(u8),
    Other(u16),
}

#[derive(Debug)]
pub struct RouteDetails {
    pub destination_prefix_length: u8,
    pub tos: u8,
    pub table: RouteTable,
    pub protocol: RouteProtocol,
    pub scope: RouteScope,
    pub r#type: RouteType,
    pub attributes: Vec<RouteAttribute>,
}

#[derive(Debug)]
pub enum GetRouteParseError {
    UnparsableDestination,
    UnparsableOutInterface,
    UnparsableGateway,
    UnparsablePriority,
    UnparsablePreferedSource,
    UnparsableCacheInfo,
    UnparsableTable,
    UnparsablePreference,
}

pub fn read_route_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<RouteAttribute, crate::ResponseError<GetRouteParseError>> {
    match attribute.r#type {
        route_attributes::RTA_DST => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsableDestination),
        )
        .map(RouteAttribute::Destination),

        route_attributes::RTA_OIF => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_i32_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsableOutInterface),
        )
        .map(RouteAttribute::OutInterface),

        route_attributes::RTA_GATEWAY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsableGateway),
        )
        .map(RouteAttribute::Gateway),

        route_attributes::RTA_PRIORITY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsablePriority),
        )
        .map(RouteAttribute::Priority),

        route_attributes::RTA_PREFSRC => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsablePreferedSource),
        )
        .map(RouteAttribute::PreferedSource),

        route_attributes::RTA_CACHEINFO => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            read_rta_cache_info,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsableCacheInfo),
        )
        .map(RouteAttribute::CacheInfo),

        route_attributes::RTA_TABLE => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsableTable),
        )
        .map(RouteTable::from)
        .map(RouteAttribute::Table),

        route_attributes::RTA_PREF => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u8_attr,
            crate::ResponseError::ProtocolParse(GetRouteParseError::UnparsablePreference),
        )
        .map(RouteAttribute::Preference),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(RouteAttribute::Other(other))
        }
    }
}

pub fn read_route_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<RouteDetails, crate::ResponseError<GetRouteParseError>> {
    let header = RtMsg::read(reader)?;
    let remaining_bytes = len - RtMsg::SIZE;

    let attributes: Result<Vec<RouteAttribute>, crate::ResponseError<GetRouteParseError>> =
        crate::netlink::attr::NlAttributeIter::new(reader, read_route_attr, remaining_bytes)
            .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
            .collect();

    Ok(RouteDetails {
        destination_prefix_length: header.rtm_dst_len,
        tos: header.rtm_tos,
        table: RouteTable::from(header.rtm_table),
        protocol: RouteProtocol::from(header.rtm_protocol),
        scope: RouteScope::from(header.rtm_scope),
        r#type: RouteType::from(header.rtm_type),
        attributes: attributes?,
    })
}

fn read_get_route_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<R, Result<RouteDetails, crate::ResponseError<GetRouteParseError>>>
{
    crate::netlink::msg::NlMsgIter::new(reader, read_route_msg)
}

/// set message type and flags for a RTM_GETROUTE dump request
pub fn get_all_route_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = RTM_GETROUTE;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct GetAllRouteMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub rt_msg: RtMsg,
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for GetAllRouteMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = super::IpFamily;
    type Output = Vec<RouteDetails>;
    type ParseError = GetRouteParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        get_all_route_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            rt_msg: RtMsg::new_with_family(input),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(RtMsg::SIZE);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.rt_msg.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        read_get_route_response(reader)
            .map(|e| {
                e.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(core::convert::identity)
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteInput {
    pub ip_address: std::net::IpAddr,
    pub interface: i32,
}

impl RouteInput {
    pub fn new(ip_address: std::net::IpAddr, interface: i32) -> Self {
        RouteInput {
            ip_address,
            interface,
        }
    }
}

/// set message type and flags for a RTM_NEWROUTE request
pub fn add_route_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    header.r#type = RTM_NEWROUTE;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct AddRouteMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub rt_msg: RtMsg,
    pub ip_address: std::net::IpAddr,
    pub interface: i32,
}

impl<'a, Buffer: std::io::Write> AddRouteMsgBuilder<'a, Buffer> {
    /// set cidr network mask without bound check
    ///
    /// # Safety
    ///
    /// use only if network mask is a valid cidr mask
    #[inline]
    pub unsafe fn set_mask_unchecked(&mut self, cidr_mask: u8) {
        self.rt_msg.rtm_dst_len = cidr_mask;
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddRouteMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = RouteInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: RouteInput,
    ) -> Self {
        add_route_nl_header(&mut nl_msg_header);

        let RouteInput {
            ip_address,
            interface,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            rt_msg: RtMsg::new_with_family_and_add_route_defaults(super::IpFamily::from(
                &ip_address,
            )),
            ip_address,
            interface,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            RtMsg::SIZE
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.ip_address)
                + crate::netlink::attr::set_attr_length_aligned(4),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.rt_msg.write(self.buffer)?;
        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            route_attributes::RTA_DST,
            &self.ip_address,
        )?;
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            route_attributes::RTA_OIF,
            self.interface,
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

/// set message type and flags for a RTM_NEWROUTE request
pub fn del_route_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = RTM_DELROUTE;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct DelRouteMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub rt_msg: RtMsg,
    pub ip_address: std::net::IpAddr,
    pub interface: i32,
}

impl<'a, Buffer: std::io::Write> DelRouteMsgBuilder<'a, Buffer> {
    /// set cidr network mask without bound check
    ///
    /// # Safety
    ///
    /// use only if network mask is a valid cidr mask
    #[inline]
    pub unsafe fn set_mask_unchecked(&mut self, cidr_mask: u8) {
        self.rt_msg.rtm_dst_len = cidr_mask;
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for DelRouteMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = RouteInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: RouteInput,
    ) -> Self {
        del_route_nl_header(&mut nl_msg_header);

        let RouteInput {
            ip_address,
            interface,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            rt_msg: RtMsg::new_with_family_and_del_route_defaults(super::IpFamily::from(
                &ip_address,
            )),
            ip_address,
            interface,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            RtMsg::SIZE
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.ip_address)
                + crate::netlink::attr::set_attr_length_aligned(4),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.rt_msg.write(self.buffer)?;
        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            route_attributes::RTA_DST,
            &self.ip_address,
        )?;
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            route_attributes::RTA_OIF,
            self.interface,
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

#[derive(Debug)]
pub struct AddGatewayMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub rt_msg: RtMsg,
    pub gateway_address: std::net::IpAddr,
    pub pref_source_address: Option<std::net::IpAddr>,
    pub destination_address: Option<std::net::IpAddr>,
    pub interface: i32,
}

impl<'a, Buffer: std::io::Write> AddGatewayMsgBuilder<'a, Buffer> {
    /// set prefered source ip address without ip version check
    ///
    /// # Safety
    ///
    /// use only if prefered source ip address version match with the gateway address
    #[inline]
    pub unsafe fn set_prefered_source_address_unchecked(
        &mut self,
        pref_source_address: std::net::IpAddr,
    ) {
        self.pref_source_address = Some(pref_source_address)
    }

    /// set destination ip address/subnet without ip version check and mask bound check
    ///
    /// # Safety
    ///
    /// use only if destination ip address version match with the gateway address and mask bounds has been checked
    #[inline]
    pub unsafe fn set_destination_address_unchecked(
        &mut self,
        destination_address: std::net::IpAddr,
        mask: Option<u8>,
    ) {
        self.destination_address = Some(destination_address);
        if let Some(mask) = mask {
            self.rt_msg.rtm_dst_len = mask;
        } else {
            self.rt_msg.rtm_dst_len = match destination_address {
                std::net::IpAddr::V4(_ipv4_addr) => 32,
                std::net::IpAddr::V6(_ipv6_addr) => 128,
            };
        }
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddGatewayMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = RouteInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: RouteInput,
    ) -> Self {
        add_route_nl_header(&mut nl_msg_header);

        let RouteInput {
            ip_address,
            interface,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            rt_msg: RtMsg::new_with_family_and_add_gateway_defaults(super::IpFamily::from(
                &ip_address,
            )),
            interface,
            gateway_address: ip_address,
            pref_source_address: None,
            destination_address: None,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            RtMsg::SIZE
                + self
                    .destination_address
                    .as_ref()
                    .map(crate::netlink::attr::set_ip_address_attr_length_aligned)
                    .unwrap_or(0)
                + self
                    .pref_source_address
                    .as_ref()
                    .map(crate::netlink::attr::set_ip_address_attr_length_aligned)
                    .unwrap_or(0)
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.gateway_address)
                + crate::netlink::attr::set_attr_length_aligned(4),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.rt_msg.write(self.buffer)?;
        if let Some(destination_address) = self.destination_address {
            written_bytes += crate::netlink::attr::write_ip_address_attr(
                self.buffer,
                route_attributes::RTA_DST,
                &destination_address,
            )?;
        }
        if let Some(pref_source_address) = self.pref_source_address {
            written_bytes += crate::netlink::attr::write_ip_address_attr(
                self.buffer,
                route_attributes::RTA_PREFSRC,
                &pref_source_address,
            )?;
        }
        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            route_attributes::RTA_GATEWAY,
            &self.gateway_address,
        )?;
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            route_attributes::RTA_OIF,
            self.interface,
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

#[derive(Debug)]
pub struct DelGatewayMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub rt_msg: RtMsg,
    pub gateway_address: std::net::IpAddr,
    pub pref_source_address: Option<std::net::IpAddr>,
    pub destination_address: Option<std::net::IpAddr>,
    pub interface: i32,
}

impl<'a, Buffer: std::io::Write> DelGatewayMsgBuilder<'a, Buffer> {
    /// set prefered source ip address without ip version check
    ///
    /// # Safety
    ///
    /// use only if prefered source ip address version match with the gateway address
    #[inline]
    pub unsafe fn set_prefered_source_address_unchecked(
        &mut self,
        pref_source_address: std::net::IpAddr,
    ) {
        self.pref_source_address = Some(pref_source_address)
    }

    /// set destination ip address/subnet without ip version check and mask bound check
    ///
    /// # Safety
    ///
    /// use only if destination ip address version match with the gateway address and mask bounds has been checked
    #[inline]
    pub unsafe fn set_destination_address_unchecked(
        &mut self,
        destination_address: std::net::IpAddr,
        mask: Option<u8>,
    ) {
        self.destination_address = Some(destination_address);
        if let Some(mask) = mask {
            self.rt_msg.rtm_dst_len = mask;
        } else {
            self.rt_msg.rtm_dst_len = match destination_address {
                std::net::IpAddr::V4(_ipv4_addr) => 32,
                std::net::IpAddr::V6(_ipv6_addr) => 128,
            };
        }
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for DelGatewayMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = RouteInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: RouteInput,
    ) -> Self {
        del_route_nl_header(&mut nl_msg_header);

        let RouteInput {
            ip_address,
            interface,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            rt_msg: RtMsg::new_with_family_and_del_gateway_defaults(super::IpFamily::from(
                &ip_address,
            )),
            interface,
            gateway_address: ip_address,
            pref_source_address: None,
            destination_address: None,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            RtMsg::SIZE
                + self
                    .destination_address
                    .as_ref()
                    .map(crate::netlink::attr::set_ip_address_attr_length_aligned)
                    .unwrap_or(0)
                + self
                    .pref_source_address
                    .as_ref()
                    .map(crate::netlink::attr::set_ip_address_attr_length_aligned)
                    .unwrap_or(0)
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.gateway_address)
                + crate::netlink::attr::set_attr_length_aligned(4),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.rt_msg.write(self.buffer)?;
        if let Some(destination_address) = self.destination_address {
            written_bytes += crate::netlink::attr::write_ip_address_attr(
                self.buffer,
                route_attributes::RTA_DST,
                &destination_address,
            )?;
        }
        if let Some(pref_source_address) = self.pref_source_address {
            written_bytes += crate::netlink::attr::write_ip_address_attr(
                self.buffer,
                route_attributes::RTA_PREFSRC,
                &pref_source_address,
            )?;
        }
        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            route_attributes::RTA_GATEWAY,
            &self.gateway_address,
        )?;
        written_bytes += crate::netlink::attr::write_i32_attr(
            self.buffer,
            route_attributes::RTA_OIF,
            self.interface,
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
