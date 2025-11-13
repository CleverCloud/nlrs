// SPDX-License-Identifier: MIT
//! ipvs destination's (backend) configuration messages

use crate::{
    genetlink::GenericMessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST},
    },
};

pub mod dest_attributes {
    /// real server address
    pub const IPVS_DEST_ATTR_ADDR: u16 = 1;
    /// real server port
    pub const IPVS_DEST_ATTR_PORT: u16 = 2;
    /// forwarding method
    pub const IPVS_DEST_ATTR_FWD_METHOD: u16 = 3;
    /// destination weight
    pub const IPVS_DEST_ATTR_WEIGHT: u16 = 4;
    /// upper threshold
    pub const IPVS_DEST_ATTR_U_THRESH: u16 = 5;
    /// lower threshold
    pub const IPVS_DEST_ATTR_L_THRESH: u16 = 6;
    /// active connections
    pub const IPVS_DEST_ATTR_ACTIVE_CONNS: u16 = 7;
    /// inactive connections
    pub const IPVS_DEST_ATTR_INACT_CONNS: u16 = 8;
    /// persistent connections
    pub const IPVS_DEST_ATTR_PERSIST_CONNS: u16 = 9;
    /// nested attribute for dest stats
    pub const IPVS_DEST_ATTR_STATS: u16 = 10;
    /// address family of address
    pub const IPVS_DEST_ATTR_ADDR_FAMILY: u16 = 11;
    /// nested attribute for dest stats (64bit)
    pub const IPVS_DEST_ATTR_STATS64: u16 = 12;
    /// tunnel type
    pub const IPVS_DEST_ATTR_TUN_TYPE: u16 = 13;
    /// tunnel port
    pub const IPVS_DEST_ATTR_TUN_PORT: u16 = 14;
    /// tunnel flags
    pub const IPVS_DEST_ATTR_TUN_FLAGS: u16 = 15;
}

pub mod forward_methods {
    /// masquerading/NAT
    pub const IP_VS_CONN_F_MASQ: u32 = 0;
    /// local node
    pub const IP_VS_CONN_F_LOCALNODE: u32 = 1;
    /// tunneling
    pub const IP_VS_CONN_F_TUNNEL: u32 = 2;
    /// direct routing
    pub const IP_VS_CONN_F_DROUTE: u32 = 3;
    /// cache bypass
    pub const IP_VS_CONN_F_BYPASS: u32 = 4;
}

pub const IPVS_CMD_NEW_DEST: u8 = 5;
pub const IPVS_CMD_SET_DEST: u8 = 6;
pub const IPVS_CMD_DEL_DEST: u8 = 7;
pub const IPVS_CMD_GET_DEST: u8 = 8;

#[derive(Debug)]
pub enum GetDestinationParseError {
    NoResponse,
    UnexpectedCmdAttribute(u16),
    UnexpectedForwardMethod(u32),
    UnparsableAddress,
    UnparsablePort,
    UnparsableForwardingMethod,
    UnparsableWeight,
    UnparsableUpperThreshold,
    UnparsableLowerThreshold,
    UnparsableActiveConns,
    UnparsableInactiveConns,
    UnparsablePersistentConns,
    UnparsableAddressFamily,
    UnparsableTunnelType,
    UnparsableTunnelPort,
    UnparsableTunnelFlags,
    NoAddressFamily,
    NoAddress,
    NoPort,
    NoForwardMethod,
    NoWeight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestinationAttribute {
    Address([u8; 16]),
    Port(u16),
    ForwardingMethod(u32),
    Weight(u32),
    UpperThreshold(u32),
    LowerThreshold(u32),
    ActiveConns(u32),
    InactiveConns(u32),
    PersistentConns(u32),
    // TODO: Stats(),
    AddressFamily(u16),
    // TODO: Stats64(),
    // TODO: TunnelType(),
    TunnelPort(u16),
    // TODO TunnelFlags(),
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum IpvsForwardMethod {
    /// masquerading/NAT
    Masquerade = forward_methods::IP_VS_CONN_F_MASQ,
    /// local node
    Local = forward_methods::IP_VS_CONN_F_LOCALNODE,
    /// tunneling
    Tunnel = forward_methods::IP_VS_CONN_F_TUNNEL,
    /// direct routing
    DirectRoute = forward_methods::IP_VS_CONN_F_DROUTE,
    /// cache bypass
    Bypass = forward_methods::IP_VS_CONN_F_BYPASS,
}

impl TryFrom<u32> for IpvsForwardMethod {
    type Error = GetDestinationParseError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            forward_methods::IP_VS_CONN_F_MASQ => Ok(IpvsForwardMethod::Masquerade),
            forward_methods::IP_VS_CONN_F_LOCALNODE => Ok(IpvsForwardMethod::Local),
            forward_methods::IP_VS_CONN_F_TUNNEL => Ok(IpvsForwardMethod::Tunnel),
            forward_methods::IP_VS_CONN_F_DROUTE => Ok(IpvsForwardMethod::DirectRoute),
            forward_methods::IP_VS_CONN_F_BYPASS => Ok(IpvsForwardMethod::Bypass),
            other => Err(GetDestinationParseError::UnexpectedForwardMethod(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpvsDestination {
    pub destination_address: core::net::SocketAddr,
    pub weight: u32,
    pub forward_method: IpvsForwardMethod,
    pub attributes: Vec<DestinationAttribute>,
}

impl TryFrom<Vec<DestinationAttribute>> for IpvsDestination {
    type Error = GetDestinationParseError;

    fn try_from(attributes: Vec<DestinationAttribute>) -> Result<Self, Self::Error> {
        let mut address_family = None;
        let mut address = None;
        let mut port = None;
        let mut forward_method = None;
        let mut weight = None;

        let mut other_attributes = Vec::new();
        for attribute in attributes {
            match attribute {
                DestinationAttribute::Address(addr) => address = Some(addr),
                DestinationAttribute::Port(p) => port = Some(p),
                DestinationAttribute::ForwardingMethod(fw) => forward_method = Some(fw),
                DestinationAttribute::Weight(w) => weight = Some(w),
                DestinationAttribute::AddressFamily(f) => address_family = Some(f),
                other => other_attributes.push(other),
            }
        }

        let address_family = address_family.ok_or(GetDestinationParseError::NoAddressFamily)?;
        let address = address.ok_or(GetDestinationParseError::NoAddress)?;
        let port = port.ok_or(GetDestinationParseError::NoPort)?;
        let forward_method = forward_method.ok_or(GetDestinationParseError::NoForwardMethod)?;
        let weight = weight.ok_or(GetDestinationParseError::NoWeight)?;

        let address_family: super::IpFamily = address_family
            .try_into()
            .map_err(|_| GetDestinationParseError::UnparsableAddressFamily)?;

        let ip_address = match address_family {
            super::IpFamily::AF_INET => {
                let address: &[u8] = &address[0..4];
                let address: &[u8; 4] = address.try_into().expect("slice with incorrect length");

                std::net::IpAddr::from(*address)
            }
            super::IpFamily::AF_INET6 => std::net::IpAddr::from(address),
        };

        let forward_method = forward_method.try_into()?;

        Ok(IpvsDestination {
            destination_address: core::net::SocketAddr::new(ip_address, port),
            forward_method,
            weight,
            attributes: other_attributes,
        })
    }
}

pub fn read_get_dest_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<DestinationAttribute, crate::ResponseError<GetDestinationParseError>> {
    match attribute.r#type {
        dest_attributes::IPVS_DEST_ATTR_ADDR => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableAddress),
        )
        .map(DestinationAttribute::Address),

        dest_attributes::IPVS_DEST_ATTR_PORT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_be_u16_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsablePort),
        )
        .map(DestinationAttribute::Port),

        dest_attributes::IPVS_DEST_ATTR_FWD_METHOD => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(
                GetDestinationParseError::UnparsableForwardingMethod,
            ),
        )
        .map(DestinationAttribute::ForwardingMethod),

        dest_attributes::IPVS_DEST_ATTR_WEIGHT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableWeight),
        )
        .map(DestinationAttribute::Weight),

        dest_attributes::IPVS_DEST_ATTR_U_THRESH => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableUpperThreshold),
        )
        .map(DestinationAttribute::UpperThreshold),

        dest_attributes::IPVS_DEST_ATTR_L_THRESH => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableLowerThreshold),
        )
        .map(DestinationAttribute::LowerThreshold),

        dest_attributes::IPVS_DEST_ATTR_ACTIVE_CONNS => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableActiveConns),
        )
        .map(DestinationAttribute::ActiveConns),

        dest_attributes::IPVS_DEST_ATTR_INACT_CONNS => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableInactiveConns),
        )
        .map(DestinationAttribute::InactiveConns),

        dest_attributes::IPVS_DEST_ATTR_PERSIST_CONNS => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(
                GetDestinationParseError::UnparsablePersistentConns,
            ),
        )
        .map(DestinationAttribute::PersistentConns),

        dest_attributes::IPVS_DEST_ATTR_ADDR_FAMILY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableAddressFamily),
        )
        .map(DestinationAttribute::AddressFamily),

        dest_attributes::IPVS_DEST_ATTR_TUN_PORT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetDestinationParseError::UnparsableTunnelPort),
        )
        .map(DestinationAttribute::TunnelPort),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(DestinationAttribute::Other(other))
        }
    }
}

pub fn read_get_destination_cmd_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<Vec<DestinationAttribute>, crate::ResponseError<GetDestinationParseError>> {
    if attribute.r#type == super::cmd_attributes::IPVS_CMD_ATTR_DEST {
        crate::netlink::attr::NlAttributeIter::new(
            reader,
            read_get_dest_attr,
            attribute.len as usize,
        )
        .map(|e| e.map_err(|e| e.into()).and_then(|e| e))
        .collect()
    } else {
        crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
        Err(crate::ResponseError::ProtocolParse(
            GetDestinationParseError::UnexpectedCmdAttribute(attribute.r#type),
        ))
    }
}

pub fn read_get_destination_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<DestinationAttribute>, crate::ResponseError<GetDestinationParseError>> {
    crate::genetlink::msg::skip_generic_netlink_header(reader)?;
    let remaining_bytes = len - crate::genetlink::msg::GeNlMsgHeader::SIZE;

    crate::netlink::attr::NlAttributeIter::new(
        reader,
        read_get_destination_cmd_attr,
        remaining_bytes,
    )
    .map(|e| e.map_err(|e| e.into()).and_then(|e| e))
    .next()
    .unwrap_or(Err(crate::ResponseError::ProtocolParse(
        GetDestinationParseError::NoResponse,
    )))
}

pub fn read_get_destination_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<
    R,
    Result<Vec<DestinationAttribute>, crate::ResponseError<GetDestinationParseError>>,
> {
    crate::netlink::msg::NlMsgIter::new(reader, read_get_destination_msg)
}

/// set message type and flags for a IPVS_CMD_GET_DEST request
pub fn get_destination_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct GetDestinationMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub service_selector: super::IpvsService,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for GetDestinationMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = super::IpvsService;
    type Output = Vec<IpvsDestination>;
    type ParseError = GetDestinationParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        get_destination_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_GET_DEST,
                super::IPVS_GENL_VERSION,
            ),
            service_selector: input,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        const NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2)
            + crate::netlink::attr::set_attr_length_aligned(2)
            + crate::netlink::attr::set_attr_length_aligned(16)
            + crate::netlink::attr::set_attr_length_aligned(2);

        self.nl_msg_header
            .set_generic_playload_length(crate::netlink::attr::set_attr_length_aligned(NESTED_LEN));

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_SERVICE
                | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        let super::IpvsService {
            service_address,
            protocol,
        } = self.service_selector;

        let mut address_buffer = [0u8; 16];
        let address_family = match service_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                _ = &mut address_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                _ = &mut address_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_AF,
            address_family as u16,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PROTOCOL,
            protocol as u16,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_ADDR,
            address_buffer,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PORT,
            service_address.port(),
        )?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        read_get_destination_response(reader)
            .map(|res| {
                res.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(core::convert::identity)
                    .and_then(|attrs| {
                        IpvsDestination::try_from(attrs)
                            .map_err(crate::ResponseError::ProtocolParse)
                    })
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

/// set message type and flags for a IPVS_CMD_NEW_DEST request
pub fn new_destination_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct NewDestinationMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub service_selector: super::IpvsService,

    pub address_family: u16,
    pub address: [u8; 16],
    pub port: u16,
    pub forward_method: u32,
    pub weight: u32,
    pub uthreshold: u32,
    pub lthreshold: u32,
    pub tun_type: u8,
    pub tun_port: u16,
    pub tun_flags: u16,
}

impl<'a, Buffer: std::io::Write> NewDestinationMessageBuilder<'a, Buffer> {
    pub fn new_with_default(
        buffer: &'a mut Buffer,
        nl_msg_header: NlMsgHeader,
        service_selector: super::IpvsService,
        destination_address: std::net::SocketAddr,
    ) -> Self {
        let mut address_buffer = [0u8; 16];
        let address_family = match destination_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                _ = &mut address_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                _ = &mut address_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_NEW_DEST,
                super::IPVS_GENL_VERSION,
            ),
            address_family: address_family as u16,
            address: address_buffer,
            port: destination_address.port(),
            service_selector,
            forward_method: IpvsForwardMethod::DirectRoute as u32,
            weight: 1,
            uthreshold: 0,
            lthreshold: 0,
            tun_type: 0,
            tun_port: 0,
            tun_flags: 0,
        }
    }

    // set ipvs destination forward method
    #[inline]
    pub fn set_forwarding_method(&mut self, forward_method: IpvsForwardMethod) {
        self.forward_method = forward_method as u32;
    }

    // set ipvs destination weight
    #[inline]
    pub fn set_weight(&mut self, weight: u32) {
        self.weight = weight;
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for NewDestinationMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = (super::IpvsService, std::net::SocketAddr);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        new_destination_nl_header(&mut nl_msg_header, family);

        Self::new_with_default(buffer, nl_msg_header, input.0, input.1)
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        // lengths for nested attributes
        const SERVICE_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(2) + // PROTOCOL
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2); // PORT

        const DEST_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2) + // PORT
        crate::netlink::attr::set_attr_length_aligned(4) + // FWD
        crate::netlink::attr::set_attr_length_aligned(4) + // WEIGHT
        crate::netlink::attr::set_attr_length_aligned(4) + // UTHRESH
        crate::netlink::attr::set_attr_length_aligned(4); // LTHRESH

        let total_nested_len = crate::netlink::attr::set_attr_length_aligned(SERVICE_NESTED_LEN)
            + crate::netlink::attr::set_attr_length_aligned(DEST_NESTED_LEN);

        self.nl_msg_header.set_generic_playload_length(
            crate::netlink::attr::set_attr_length_aligned(total_nested_len),
        );
        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        // service nested attribute
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(SERVICE_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_SERVICE
                | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        let super::IpvsService {
            service_address,
            protocol,
        } = self.service_selector;

        let mut service_addr_buffer = [0u8; 16];
        let service_af = match service_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                service_addr_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                service_addr_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_AF,
            service_af as u16,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PROTOCOL,
            protocol as u16,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_ADDR,
            service_addr_buffer,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PORT,
            service_address.port(),
        )?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(DEST_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_DEST | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR_FAMILY,
            self.address_family,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR,
            self.address,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_PORT,
            self.port,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_FWD_METHOD,
            self.forward_method,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_WEIGHT,
            self.weight,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_U_THRESH,
            self.uthreshold,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_L_THRESH,
            self.lthreshold,
        )?;
        written_bytes += crate::netlink::attr::write_u8_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_TYPE,
            self.tun_type,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_PORT,
            self.tun_port,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_FLAGS,
            self.tun_flags,
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

/// set message type and flags for a IPVS_CMD_DEL_DEST request
pub fn del_destination_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct DelDestinationMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub service_selector: super::IpvsService,

    pub address_family: u16,
    pub address: [u8; 16],
    pub port: u16,
}

impl<'a, Buffer: std::io::Write> DelDestinationMessageBuilder<'a, Buffer> {
    pub fn new_with_address(
        buffer: &'a mut Buffer,
        nl_msg_header: NlMsgHeader,
        service_selector: super::IpvsService,
        destination_address: std::net::SocketAddr,
    ) -> Self {
        let mut address_buffer = [0u8; 16];
        let address_family = match destination_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                _ = &mut address_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                _ = &mut address_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_DEL_DEST,
                super::IPVS_GENL_VERSION,
            ),
            address_family: address_family as u16,
            address: address_buffer,
            port: destination_address.port(),
            service_selector,
        }
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for DelDestinationMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = (super::IpvsService, std::net::SocketAddr);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        del_destination_nl_header(&mut nl_msg_header, family);

        Self::new_with_address(buffer, nl_msg_header, input.0, input.1)
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        // lengths for nested attributes
        const SERVICE_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(2) + // PROTOCOL
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2); // PORT

        const DEST_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2); // PORT

        const TOTAL_NESTED_LEN: usize =
            crate::netlink::attr::set_attr_length_aligned(SERVICE_NESTED_LEN)
                + crate::netlink::attr::set_attr_length_aligned(DEST_NESTED_LEN);

        self.nl_msg_header
            .set_generic_playload_length(TOTAL_NESTED_LEN);
        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        // service nested attribute
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(SERVICE_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_SERVICE
                | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        let super::IpvsService {
            service_address,
            protocol,
        } = self.service_selector;

        let mut service_addr_buffer = [0u8; 16];
        let service_af = match service_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                service_addr_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                service_addr_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_AF,
            service_af as u16,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PROTOCOL,
            protocol as u16,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_ADDR,
            service_addr_buffer,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PORT,
            service_address.port(),
        )?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(DEST_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_DEST | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR,
            self.address,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_PORT,
            self.port,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR_FAMILY,
            self.address_family,
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

/// Set message type and flags for an IPVS_CMD_SET_DEST request
pub fn set_destination_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct SetDestinationMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub service_selector: super::IpvsService,

    pub address_family: u16,
    pub address: [u8; 16],
    pub port: u16,
    pub forward_method: u32,
    pub weight: u32,
    pub uthreshold: u32,
    pub lthreshold: u32,
    pub tun_type: u8,
    pub tun_port: u16,
    pub tun_flags: u16,
}

impl<'a, Buffer: std::io::Write> SetDestinationMessageBuilder<'a, Buffer> {
    pub fn new_with_default(
        buffer: &'a mut Buffer,
        nl_msg_header: NlMsgHeader,
        service_selector: super::IpvsService,
        destination_address: std::net::SocketAddr,
    ) -> Self {
        let mut address_buffer = [0u8; 16];
        let address_family = match destination_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                _ = &mut address_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                _ = &mut address_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_SET_DEST,
                super::IPVS_GENL_VERSION,
            ),
            address_family: address_family as u16,
            address: address_buffer,
            port: destination_address.port(),
            service_selector,
            forward_method: IpvsForwardMethod::DirectRoute as u32,
            weight: 1,
            uthreshold: 0,
            lthreshold: 0,
            tun_type: 0,
            tun_port: 0,
            tun_flags: 0,
        }
    }

    // set ipvs destination forward method
    #[inline]
    pub fn set_forwarding_method(&mut self, forward_method: IpvsForwardMethod) {
        self.forward_method = forward_method as u32;
    }

    // set ipvs destination weight
    #[inline]
    pub fn set_weight(&mut self, weight: u32) {
        self.weight = weight;
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for SetDestinationMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = (super::IpvsService, std::net::SocketAddr);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        set_destination_nl_header(&mut nl_msg_header, family);

        Self::new_with_default(buffer, nl_msg_header, input.0, input.1)
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        // lengths for nested attributes
        const SERVICE_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(2) + // PROTOCOL
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2); // PORT

        const DEST_NESTED_LEN: usize = crate::netlink::attr::set_attr_length_aligned(2) + // AF
        crate::netlink::attr::set_attr_length_aligned(16) + // ADDR
        crate::netlink::attr::set_attr_length_aligned(2) + // PORT
        crate::netlink::attr::set_attr_length_aligned(4) + // FWD
        crate::netlink::attr::set_attr_length_aligned(4) + // WEIGHT
        crate::netlink::attr::set_attr_length_aligned(4) + // UTHRESH
        crate::netlink::attr::set_attr_length_aligned(4); // LTHRESH

        let total_nested_len = crate::netlink::attr::set_attr_length_aligned(SERVICE_NESTED_LEN)
            + crate::netlink::attr::set_attr_length_aligned(DEST_NESTED_LEN);

        self.nl_msg_header.set_generic_playload_length(
            crate::netlink::attr::set_attr_length_aligned(total_nested_len),
        );
        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        // service nested attribute
        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(SERVICE_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_SERVICE
                | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        let super::IpvsService {
            service_address,
            protocol,
        } = self.service_selector;

        let mut service_addr_buffer = [0u8; 16];
        let service_af = match service_address.ip() {
            std::net::IpAddr::V4(ipv4_addr) => {
                service_addr_buffer[0..4].copy_from_slice(&ipv4_addr.octets());
                super::IpFamily::AF_INET
            }
            std::net::IpAddr::V6(ipv6_addr) => {
                service_addr_buffer.copy_from_slice(&ipv6_addr.octets());
                super::IpFamily::AF_INET6
            }
        };

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_AF,
            service_af as u16,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PROTOCOL,
            protocol as u16,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_ADDR,
            service_addr_buffer,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            super::service::service_attributes::IPVS_SVC_ATTR_PORT,
            service_address.port(),
        )?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(DEST_NESTED_LEN) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_DEST | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR_FAMILY,
            self.address_family,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_ADDR,
            self.address,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_PORT,
            self.port,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_FWD_METHOD,
            self.forward_method,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_WEIGHT,
            self.weight,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_U_THRESH,
            self.uthreshold,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_L_THRESH,
            self.lthreshold,
        )?;
        written_bytes += crate::netlink::attr::write_u8_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_TYPE,
            self.tun_type,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_PORT,
            self.tun_port,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            dest_attributes::IPVS_DEST_ATTR_TUN_FLAGS,
            self.tun_flags,
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
