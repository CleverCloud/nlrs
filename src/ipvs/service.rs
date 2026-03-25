// SPDX-License-Identifier: MIT
//! ipvs service's (frontend) configuration messages

use crate::{
    genetlink::GenericMessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST},
    },
};

pub mod service_attributes {
    /// address family
    pub const IPVS_SVC_ATTR_AF: u16 = 1;
    /// virtual service protocol
    pub const IPVS_SVC_ATTR_PROTOCOL: u16 = 2;
    /// virtual service address
    pub const IPVS_SVC_ATTR_ADDR: u16 = 3;
    /// virtual service port
    pub const IPVS_SVC_ATTR_PORT: u16 = 4;
    /// firewall mark of service
    pub const IPVS_SVC_ATTR_FWMARK: u16 = 5;
    /// name of scheduler
    pub const IPVS_SVC_ATTR_SCHED_NAME: u16 = 6;
    /// virtual service flags
    pub const IPVS_SVC_ATTR_FLAGS: u16 = 7;
    /// persistent timeout
    pub const IPVS_SVC_ATTR_TIMEOUT: u16 = 8;
    /// persistent netmask
    pub const IPVS_SVC_ATTR_NETMASK: u16 = 9;
    /// nested attribute for service stats
    pub const IPVS_SVC_ATTR_STATS: u16 = 10;
    /// name of ct retriever
    pub const IPVS_SVC_ATTR_PE_NAME: u16 = 11;
    /// nested attribute for service stats (64bit)
    pub const IPVS_SVC_ATTR_STATS64: u16 = 12;
}

pub const IPVS_CMD_NEW_SERVICE: u8 = 1;
pub const IPVS_CMD_SET_SERVICE: u8 = 2;
pub const IPVS_CMD_DEL_SERVICE: u8 = 3;
pub const IPVS_CMD_GET_SERVICE: u8 = 4;

pub const DEFAULT_SCHED_NAME: &str = "wlc";

#[derive(Debug)]
pub enum GetServiceParseError {
    NoResponse,
    UnexpectedCmdAttribute(u16),
    UnparsableAddressFamily,
    UnparsableProtocol,
    UnparsableAddress,
    UnparsablePort,
    UnparsableFwMark,
    UnparsableScheduler,
    UnparsableTimeout,
    UnparsableNetmask,
    UnparsablePersistenceEngine,
    NoAddressFamily,
    NoProtocol,
    NoAddress,
    NoPort,
    NoScheduler,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceAttribute {
    AddressFamily(u16),
    Protocol(u16),
    Address([u8; 16]),
    Port(u16),
    FwMark(u32),
    Scheduler(String),
    // TODO Flags(),
    Timeout(u32),
    Netmask(u32),
    // TODO Stats(),
    PersistenceEngine(String),
    // TODO Stats64(),
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpvsServiceDetails {
    pub service_address: std::net::SocketAddr,
    pub protocol: super::Protocol,
    pub scheduler: String,
    pub attributes: Vec<ServiceAttribute>,
}

pub fn read_get_service_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<ServiceAttribute, crate::ResponseError<GetServiceParseError>> {
    match attribute.r#type {
        service_attributes::IPVS_SVC_ATTR_AF => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableAddressFamily),
        )
        .map(ServiceAttribute::AddressFamily),

        service_attributes::IPVS_SVC_ATTR_PROTOCOL => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableProtocol),
        )
        .map(ServiceAttribute::Protocol),

        service_attributes::IPVS_SVC_ATTR_ADDR => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableAddress),
        )
        .map(ServiceAttribute::Address),

        service_attributes::IPVS_SVC_ATTR_PORT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_be_u16_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsablePort),
        )
        .map(ServiceAttribute::Port),

        service_attributes::IPVS_SVC_ATTR_FWMARK => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableFwMark),
        )
        .map(ServiceAttribute::FwMark),

        service_attributes::IPVS_SVC_ATTR_SCHED_NAME => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableScheduler),
        )
        .map(ServiceAttribute::Scheduler),

        service_attributes::IPVS_SVC_ATTR_TIMEOUT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableTimeout),
        )
        .map(ServiceAttribute::Timeout),

        service_attributes::IPVS_SVC_ATTR_NETMASK => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableNetmask),
        )
        .map(ServiceAttribute::Netmask),

        service_attributes::IPVS_SVC_ATTR_PE_NAME => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsablePersistenceEngine),
        )
        .map(ServiceAttribute::PersistenceEngine),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(ServiceAttribute::Other(other))
        }
    }
}

pub fn read_get_service_cmd_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<Vec<ServiceAttribute>, crate::ResponseError<GetServiceParseError>> {
    if attribute.r#type == super::cmd_attributes::IPVS_CMD_ATTR_SERVICE {
        crate::netlink::attr::NlAttributeIter::new(
            reader,
            read_get_service_attr,
            attribute.len as usize,
        )
        .map(|e| e.map_err(|e| e.into()).and_then(|e| e))
        .collect()
    } else {
        crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
        Err(crate::ResponseError::ProtocolParse(
            GetServiceParseError::UnexpectedCmdAttribute(attribute.r#type),
        ))
    }
}

pub fn read_get_service_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<ServiceAttribute>, crate::ResponseError<GetServiceParseError>> {
    crate::genetlink::msg::skip_generic_netlink_header(reader)?;
    let remaining_bytes = len - crate::genetlink::msg::GeNlMsgHeader::SIZE;

    crate::netlink::attr::NlAttributeIter::new(reader, read_get_service_cmd_attr, remaining_bytes)
        .map(|e| e.map_err(|e| e.into()).and_then(|e| e))
        .next()
        .unwrap_or(Err(crate::ResponseError::ProtocolParse(
            GetServiceParseError::NoResponse,
        )))
}

pub fn read_get_service_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<
    '_,
    R,
    Result<Vec<ServiceAttribute>, crate::ResponseError<GetServiceParseError>>,
> {
    crate::netlink::msg::NlMsgIter::new(reader, read_get_service_msg)
}

/// set message type and flags for a IPVS_CMD_GET_SERVICE request
pub fn get_service_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct GetServiceMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for GetServiceMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = ();
    type Output = Vec<IpvsServiceDetails>;
    type ParseError = GetServiceParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        _input: Self::Input,
    ) -> Self {
        get_service_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_GET_SERVICE,
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
        let services = read_get_service_response(reader)
            .map(|e| {
                e.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(|e| e)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut result = Vec::with_capacity(services.len());
        for mut attributes in services {
            let mut address_family_pos: Option<usize> = None;
            let mut protocol_pos: Option<usize> = None;
            let mut address_pos: Option<usize> = None;
            let mut port_pos: Option<usize> = None;
            let mut scheduler_pos: Option<usize> = None;

            for (index, attribute) in attributes.iter().enumerate() {
                match attribute {
                    ServiceAttribute::AddressFamily(_) => address_family_pos = Some(index),
                    ServiceAttribute::Protocol(_) => protocol_pos = Some(index),
                    ServiceAttribute::Address(_) => address_pos = Some(index),
                    ServiceAttribute::Port(_) => port_pos = Some(index),
                    ServiceAttribute::Scheduler(_) => scheduler_pos = Some(index),
                    _ => {}
                }
            }

            let address_family_pos = address_family_pos.ok_or(
                crate::ResponseError::ProtocolParse(GetServiceParseError::NoAddressFamily),
            )?;
            let protocol_pos = protocol_pos.ok_or(crate::ResponseError::ProtocolParse(
                GetServiceParseError::NoProtocol,
            ))?;
            let address_pos = address_pos.ok_or(crate::ResponseError::ProtocolParse(
                GetServiceParseError::NoAddress,
            ))?;
            let port_pos = port_pos.ok_or(crate::ResponseError::ProtocolParse(
                GetServiceParseError::NoPort,
            ))?;
            let scheduler_pos = scheduler_pos.ok_or(crate::ResponseError::ProtocolParse(
                GetServiceParseError::NoScheduler,
            ))?;

            let address_family = match attributes.swap_remove(address_family_pos) {
                ServiceAttribute::AddressFamily(f) => f,
                _ => unreachable!(),
            };
            let protocol = match attributes.swap_remove(protocol_pos) {
                ServiceAttribute::Protocol(p) => p,
                _ => unreachable!(),
            };
            let address = match attributes.swap_remove(address_pos) {
                ServiceAttribute::Address(addr) => addr,
                _ => unreachable!(),
            };
            let port = match attributes.swap_remove(port_pos) {
                ServiceAttribute::Port(p) => p,
                _ => unreachable!(),
            };
            let scheduler = match attributes.swap_remove(scheduler_pos) {
                ServiceAttribute::Scheduler(s) => s,
                _ => unreachable!(),
            };

            let address_family: super::IpFamily = address_family.try_into().map_err(|_| {
                crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableAddressFamily)
            })?;

            let ip_address = match address_family {
                super::IpFamily::AF_INET => {
                    let address: &[u8] = &address[0..4];
                    let address: &[u8; 4] =
                        address.try_into().expect("slice with incorrect length");

                    std::net::IpAddr::from(*address)
                }
                super::IpFamily::AF_INET6 => std::net::IpAddr::from(address),
            };

            let protocol = protocol.try_into().map_err(|_| {
                crate::ResponseError::ProtocolParse(GetServiceParseError::UnparsableProtocol)
            })?;

            result.push(IpvsServiceDetails {
                service_address: std::net::SocketAddr::new(ip_address, port),
                protocol,
                scheduler,
                attributes,
            });
        }

        Ok(result)
    }
}

/// set message type and flags for a IPVS_CMD_NEW_SERVICE request
pub fn new_service_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct NewServiceMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,

    pub address_family: u16,
    pub protocol: u16,
    pub address: [u8; 16],
    pub port: u16,
    pub sched_name: String,
    pub flags: u32,
    pub timeout: u32,
    pub netmask: [u8; 4],
}

impl<'a, Buffer: std::io::Write> NewServiceMessageBuilder<'a, Buffer> {
    pub fn new_with_default(
        buffer: &'a mut Buffer,
        nl_msg_header: NlMsgHeader,
        service_address: std::net::SocketAddr,
        protocol: super::Protocol,
    ) -> Self {
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

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_NEW_SERVICE,
                super::IPVS_GENL_VERSION,
            ),
            address_family: address_family as u16,
            protocol: protocol as u16,
            address: address_buffer,
            port: service_address.port(),
            sched_name: String::from(DEFAULT_SCHED_NAME),
            flags: 0,
            timeout: 0,
            netmask: [0xff, 0xff, 0xff, 0xff],
        }
    }

    /// set ipvs service timeout in seconds
    #[inline]
    pub fn set_timeout(&mut self, timeout: u32) {
        self.timeout = timeout;
    }

    /// set ipvs service network mask
    #[inline]
    pub fn set_netmask(&mut self, netmask: [u8; 4]) {
        self.netmask = netmask;
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for NewServiceMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = super::IpvsService;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        new_service_nl_header(&mut nl_msg_header, family);

        let super::IpvsService {
            service_address,
            protocol,
        } = input;

        Self::new_with_default(buffer, nl_msg_header, service_address, protocol)
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        let attributes_len: usize = crate::netlink::attr::set_attr_length_aligned(2)
            + crate::netlink::attr::set_attr_length_aligned(2)
            + crate::netlink::attr::set_attr_length_aligned(16)
            + crate::netlink::attr::set_attr_length_aligned(2)
            + crate::netlink::attr::set_string_length_aligned(self.sched_name.len())
            + crate::netlink::attr::set_attr_length_aligned(4)
            + crate::netlink::attr::set_attr_length_aligned(4)
            + crate::netlink::attr::set_attr_length_aligned(4);

        self.nl_msg_header.set_generic_playload_length(
            crate::netlink::attr::set_attr_length_aligned(attributes_len),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::NlAttribute {
            len: crate::netlink::attr::set_attr_length(attributes_len) as u16,
            r#type: super::cmd_attributes::IPVS_CMD_ATTR_SERVICE
                | crate::netlink::attr::NLA_F_NESTED,
        }
        .write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_AF,
            self.address_family,
        )?;
        written_bytes += crate::netlink::attr::write_u16_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_PROTOCOL,
            self.protocol,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_ADDR,
            self.address,
        )?;
        written_bytes += crate::netlink::attr::write_be_u16_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_PORT,
            self.port,
        )?;
        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_SCHED_NAME,
            &self.sched_name,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_FLAGS,
            self.flags,
        )?;
        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_TIMEOUT,
            self.timeout,
        )?;
        written_bytes += crate::netlink::attr::write_array_attr(
            self.buffer,
            service_attributes::IPVS_SVC_ATTR_NETMASK,
            self.netmask,
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

/// set message type and flags for a IPVS_CMD_DEL_SERVICE request
pub fn del_service_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct DeleteServiceMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub service_selector: super::IpvsService,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for DeleteServiceMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = super::IpvsService;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: crate::netlink::msg::NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        del_service_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                IPVS_CMD_DEL_SERVICE,
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
        crate::netlink::msg::validate_ack(reader)
            .map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
    }
}
