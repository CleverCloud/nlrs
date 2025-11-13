// SPDX-License-Identifier: MIT
//! ip address management
//!
//! ## Getting addresses
//!
//! ```rust
//! use nlrs::netlink::socket::NlSocketType;
//! use nlrs::rtnetlink::addr::GetAllAddressMsgBuilder;
//! use nlrs::socket::{NetlinkSocket, RequestBuilder};
//!
//! if let Ok(mut socket) = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE) {
//!     let req: GetAllAddressMsgBuilder<_> = socket.message_builder(());
//!     let res = req.call();
//!
//!     println!("{res:#?}");
//! };
//! ```
//!
//! ## Adding an address
//!
//! require to be root or [CAP_NET_ADMIN](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
//!
//! ```rust
//! use nlrs::netlink::socket::NlSocketType;
//! use nlrs::rtnetlink::addr::{AddAddressMsgBuilder, AddressInput};
//! use nlrs::socket::{NetlinkSocket, RequestBuilder};
//!
//! if let Ok(mut socket) = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE) {
//!     let req: AddAddressMsgBuilder<_> = socket.message_builder(AddressInput {
//!         ip_address: core::net::IpAddr::from([127, 0, 0, 2]),
//!         interface_index: 1,
//!     });
//!     _ = req.call();
//! };
//! ```
//!
//! ## Deleting an address
//!
//! require to be root or [CAP_NET_ADMIN](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
//!
//! ```rust
//! use nlrs::netlink::socket::NlSocketType;
//! use nlrs::rtnetlink::addr::{DelAddressMsgBuilder, AddressInput};
//! use nlrs::socket::{NetlinkSocket, RequestBuilder};
//!
//! if let Ok(mut socket) = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE) {
//!     let req: DelAddressMsgBuilder<_> = socket.message_builder(AddressInput {
//!         ip_address: core::net::IpAddr::from([127, 0, 0, 2]),
//!         interface_index: 1,
//!     });
//!     _ = req.call();
//! };
//! ```

use crate::{
    MessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST},
    },
};

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;

#[derive(Debug, Default)]
#[repr(C, packed)]
pub struct IfAddrMsg {
    pub ifa_family: u8,
    pub ifa_prefixlen: u8,
    pub ifa_flags: u8,
    pub ifa_scope: u8,
    pub ifa_index: u32,
}

impl IfAddrMsg {
    /// size of a [`IfAddrMsg`] in bytes
    pub const SIZE: usize = std::mem::size_of::<IfAddrMsg>();

    pub fn new_with_interface_and_family(interface_index: u32, family: super::IpFamily) -> Self {
        IfAddrMsg {
            ifa_index: interface_index,
            ifa_family: family as u8,
            ifa_prefixlen: match family {
                super::IpFamily::AF_INET => 32,
                super::IpFamily::AF_INET6 => 128,
            },
            ..Default::default()
        }
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<IfAddrMsg, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

pub mod address_attributes {
    pub const IFA_ADDRESS: u16 = 1;
    pub const IFA_LOCAL: u16 = 2;
    pub const IFA_LABEL: u16 = 3;
    pub const IFA_BROADCAST: u16 = 4;
    pub const IFA_ANYCAST: u16 = 5;
    pub const IFA_CACHEINFO: u16 = 6;
    pub const IFA_MULTICAST: u16 = 7;
    pub const IFA_FLAGS: u16 = 8;
    pub const IFA_RT_PRIORITY: u16 = 9;
    pub const IFA_TARGET_NETNSID: u16 = 10;
    pub const IFA_PROTO: u16 = 11;
}

#[derive(Debug)]
pub enum AddressAttribute {
    Address(std::net::IpAddr),
    Local(std::net::IpAddr),
    Label(String),
    Broadcast(std::net::IpAddr),
    Other(u16),
}

#[derive(Debug)]
pub enum GetAddressParseError {
    UnparsableAddress,
    UnparsableLocal,
    UnparsableLabel,
    UnparsableBroadcast,
    NoAddress,
}

#[derive(Debug)]
pub struct RawAddressDetails {
    pub interface_index: u32,
    pub mask: u8,
    pub attributes: Vec<AddressAttribute>,
}

#[derive(Debug)]
pub struct AddressDetails {
    pub interface_index: u32,
    pub ip_address: std::net::IpAddr,
    pub attributes: Vec<AddressAttribute>,
}

impl TryFrom<RawAddressDetails> for AddressDetails {
    type Error = GetAddressParseError;

    fn try_from(value: RawAddressDetails) -> Result<Self, Self::Error> {
        let mut local_ip_address: Option<std::net::IpAddr> = None;
        let mut ip_address: Option<std::net::IpAddr> = None;

        for attribute in value.attributes.iter() {
            match attribute {
                AddressAttribute::Address(ip_addr) => ip_address = Some(*ip_addr),
                AddressAttribute::Local(ip_addr) => local_ip_address = Some(*ip_addr),
                _ => {}
            }
        }

        Ok(AddressDetails {
            interface_index: value.interface_index,
            ip_address: local_ip_address
                .unwrap_or(ip_address.ok_or(GetAddressParseError::NoAddress)?),
            attributes: value.attributes,
        })
    }
}

pub fn read_addr_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<AddressAttribute, crate::ResponseError<GetAddressParseError>> {
    match attribute.r#type {
        address_attributes::IFA_ADDRESS => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetAddressParseError::UnparsableAddress),
        )
        .map(AddressAttribute::Address),

        address_attributes::IFA_LOCAL => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetAddressParseError::UnparsableLocal),
        )
        .map(AddressAttribute::Local),

        address_attributes::IFA_LABEL => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(GetAddressParseError::UnparsableLabel),
        )
        .map(AddressAttribute::Label),

        address_attributes::IFA_BROADCAST => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetAddressParseError::UnparsableBroadcast),
        )
        .map(AddressAttribute::Broadcast),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(AddressAttribute::Other(other))
        }
    }
}

pub fn read_addr_msg(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<RawAddressDetails, crate::ResponseError<GetAddressParseError>> {
    // TODO parse flags and scope
    let infos = IfAddrMsg::read(reader)?;
    let remaining_bytes = len - IfAddrMsg::SIZE;

    let attributes: Result<Vec<AddressAttribute>, crate::ResponseError<GetAddressParseError>> =
        crate::netlink::attr::NlAttributeIter::new(reader, read_addr_attr, remaining_bytes)
            .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
            .collect();

    Ok(RawAddressDetails {
        interface_index: infos.ifa_index,
        mask: infos.ifa_prefixlen,
        attributes: attributes?,
    })
}

fn read_get_addr_response<R: std::io::Read>(
    reader: &mut R,
) -> crate::netlink::msg::NlMsgIter<
    R,
    Result<RawAddressDetails, crate::ResponseError<GetAddressParseError>>,
> {
    crate::netlink::msg::NlMsgIter::new(reader, read_addr_msg)
}

/// set message type and flags for a RTM_GETADDR dump request
pub fn get_all_addr_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = RTM_GETADDR;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct GetAllAddressMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_addr_msg: IfAddrMsg,
}

impl<'a, Buffer: std::io::Write> GetAllAddressMsgBuilder<'a, Buffer> {
    /// filter by interface index
    /// only work if strict input check has been activated
    /// see [`crate::netlink::socket::NlSocket::set_strict_checking`]
    #[inline]
    pub fn filter_by_interface(&mut self, ifa_index: u32) {
        self.if_addr_msg.ifa_index = ifa_index;
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for GetAllAddressMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = ();
    type Output = Vec<AddressDetails>;
    type ParseError = GetAddressParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        _input: Self::Input,
    ) -> Self {
        get_all_addr_nl_header(&mut nl_msg_header);

        Self {
            buffer,
            nl_msg_header,
            if_addr_msg: IfAddrMsg::default(),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(IfAddrMsg::SIZE);

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_addr_msg.write(self.buffer)?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        read_get_addr_response(reader)
            .map(|e| {
                e.map_err(crate::ResponseError::<Self::ParseError>::HeaderParse)
                    .and_then(core::convert::identity)
                    .and_then(|raw_address_details| {
                        AddressDetails::try_from(raw_address_details)
                            .map_err(crate::ResponseError::ProtocolParse)
                    })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AddressInput {
    pub ip_address: std::net::IpAddr,
    pub interface_index: u32,
}

impl AddressInput {
    pub fn new(ip_address: std::net::IpAddr, interface_index: u32) -> Self {
        AddressInput {
            ip_address,
            interface_index,
        }
    }
}

/// set message type and flags for a RTM_NEWADDR request
pub fn add_addr_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    header.r#type = RTM_NEWADDR;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct AddAddressMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_addr_msg: IfAddrMsg,
    pub ip_address: std::net::IpAddr,
    pub is_local_address: bool,
}

impl<'a, Buffer: std::io::Write> AddAddressMsgBuilder<'a, Buffer> {
    /// set cidr network mask without bound check
    ///
    /// # Safety
    ///
    /// use only if network mask is a valid cidr mask
    #[inline]
    pub unsafe fn set_mask_unchecked(&mut self, cidr_mask: u8) {
        self.if_addr_msg.ifa_prefixlen = cidr_mask;
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for AddAddressMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = AddressInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        add_addr_nl_header(&mut nl_msg_header);

        let AddressInput {
            ip_address,
            interface_index,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            if_addr_msg: IfAddrMsg::new_with_interface_and_family(
                interface_index,
                super::IpFamily::from(&ip_address),
            ),
            ip_address,
            is_local_address: ip_address.is_ipv4(),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            IfAddrMsg::SIZE
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.ip_address),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_addr_msg.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            if self.is_local_address {
                address_attributes::IFA_LOCAL
            } else {
                address_attributes::IFA_ADDRESS
            },
            &self.ip_address,
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

/// set message type and flags for a RTM_DELADDR request
pub fn del_addr_nl_header(header: &mut NlMsgHeader) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = RTM_DELADDR;
    header.flags = FLAGS;
}

#[derive(Debug)]
pub struct DelAddressMsgBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: NlMsgHeader,
    pub if_addr_msg: IfAddrMsg,
    pub ip_address: std::net::IpAddr,
    pub is_local_address: bool,
}

impl<'a, Buffer: std::io::Write> DelAddressMsgBuilder<'a, Buffer> {
    /// set cidr network mask without bound check
    ///
    /// # Safety
    ///
    /// use only if network mask is a valid cidr mask
    #[inline]
    pub unsafe fn set_mask_unchecked(&mut self, cidr_mask: u8) {
        self.if_addr_msg.ifa_prefixlen = cidr_mask;
    }
}

impl<'a, Buffer: std::io::Write> MessageBuilder<'a> for DelAddressMsgBuilder<'a, Buffer> {
    type Buffer = Buffer;
    type Input = AddressInput;
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        input: Self::Input,
    ) -> Self {
        del_addr_nl_header(&mut nl_msg_header);

        let AddressInput {
            ip_address,
            interface_index,
        } = input;

        Self {
            buffer,
            nl_msg_header,
            if_addr_msg: IfAddrMsg::new_with_interface_and_family(
                interface_index,
                super::IpFamily::from(&ip_address),
            ),
            ip_address,
            is_local_address: ip_address.is_ipv4(),
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_playload_length(
            IfAddrMsg::SIZE
                + crate::netlink::attr::set_ip_address_attr_length_aligned(&self.ip_address),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.if_addr_msg.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_ip_address_attr(
            self.buffer,
            if self.is_local_address {
                address_attributes::IFA_LOCAL
            } else {
                address_attributes::IFA_ADDRESS
            },
            &self.ip_address,
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
