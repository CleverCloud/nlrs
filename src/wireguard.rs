// SPDX-License-Identifier: MIT
//! wireguard control messages
//!
//! [WireGuard](https://www.wireguard.com/) is a VPN mesh protocol and a linux kernel module designed for secure, fast, and efficient point-to-point encrypted networking.
//! WireGuard is controllable via the generic netlink interface.
//!
//! The main implementation of WireGuard control messages via generic netlink is [wireguard-tools](https://git.zx2c4.com/wireguard-tools/)
//!
//! Be carefull, user sending WireGuard control messages need to be root or CAP_NET_ADMIN.
//!
//! ## Getting started
//!
//! Here is an example to setup and see the configuration of a WireGuard interface:
//!
//! ```rust
//! use base64::{Engine, prelude::BASE64_STANDARD};
//! use nlrs::{
//!     genetlink::socket::{GenericNetlinkSocket, GenericRequestBuilder},
//!     netlink::socket::NlSocketType,
//!     rtnetlink::link::AddLinkMsgBuilder,
//!     socket::{NetlinkSocket, RequestBuilder},
//!     wireguard::{
//!         GetDeviceByNameMessageBuilder, SetDeviceByNameMessageBuilder, WIREGUARD_FAMILY,
//!         WireguardAllowedIp, WireguardConfig, WireguardPeerConfig,
//!     },
//! };
//!
//! let wireguard_interface = format!("wg42");
//!
//! // Creating the wireguard interface
//! let mut route_socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_ROUTE).unwrap();
//! let add_link: AddLinkMsgBuilder<_> =
//!     route_socket.message_builder((wireguard_interface.clone(), "wireguard".to_owned()));
//! _ = add_link.call();
//!
//! // Opening a generic netlink wireguard socket
//! let generic_socket = NetlinkSocket::new_vectored(NlSocketType::NETLINK_GENERIC).unwrap();
//! let mut wireguard_socket =
//!     GenericNetlinkSocket::from_netlink_socket(generic_socket, WIREGUARD_FAMILY.to_string())
//!         .unwrap();
//!
//! // Creating wireguard config
//! let allowed_ip = WireguardAllowedIp {
//!     ip_address: "10.0.0.2".parse().unwrap(),
//!     cidr: 32,
//! };
//!
//! let peer_config = WireguardPeerConfig::add(
//!     BASE64_STANDARD
//!         .decode("081akZ7xT6T7b0wwi4UGhoqBb+JnWf2RqOCi1GHmtAU=")
//!         .unwrap()
//!         .try_into()
//!         .unwrap(),
//!     vec![allowed_ip],
//! );
//!
//! let wg_config = WireguardConfig {
//!     private_key: BASE64_STANDARD
//!         .decode("MI9OcqwtGwQoBjKvVyN1vDBbNynUz2xyEryz0fOdUUc=")
//!         .unwrap()
//!         .try_into()
//!         .unwrap(),
//!     listen_port: 0,
//!     peers: vec![peer_config],
//! };
//!
//! // Applying wireguard config
//! let set_device: SetDeviceByNameMessageBuilder<_> =
//!     wireguard_socket.message_builder((wireguard_interface.clone(), wg_config));
//! _ = set_device.call();
//!
//! // Seeing the result
//! let get_device: GetDeviceByNameMessageBuilder<_> =
//!     wireguard_socket.message_builder(wireguard_interface);
//! let res = get_device.call();
//!
//! println!("{res:#?}");
//! ```
use crate::{
    genetlink::GenericMessageBuilder,
    netlink::msg::{
        NlMsgHeader,
        flags::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST},
    },
};

/// `wireguard`, the generic netlink family name
pub const WIREGUARD_FAMILY: &str = "wireguard";
/// `1`, the generic netlink wireguard protocol version
pub const WIREGUARD_GENL_VERSION: u8 = 1;

pub const WG_CMD_GET_DEVICE: u8 = 0;
pub const WG_CMD_SET_DEVICE: u8 = 1;

pub const WG_KEY_LEN: usize = 32;

pub mod wgdevice_attributes {
    pub const WGDEVICE_A_IFINDEX: u16 = 1;
    pub const WGDEVICE_A_IFNAME: u16 = 2;
    pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
    pub const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
    pub const WGDEVICE_A_FLAGS: u16 = 5;
    pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
    pub const WGDEVICE_A_FWMARK: u16 = 7;
    pub const WGDEVICE_A_PEERS: u16 = 8;

    pub const NESTED_WGDEVICE_A_PEERS: u16 = crate::netlink::attr::nl_nest(WGDEVICE_A_PEERS);
}

pub mod wgpeer_attributes {
    pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
    pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
    pub const WGPEER_A_FLAGS: u16 = 3;
    pub const WGPEER_A_ENDPOINT: u16 = 4;
    pub const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
    pub const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
    pub const WGPEER_A_RX_BYTES: u16 = 7;
    pub const WGPEER_A_TX_BYTES: u16 = 8;
    pub const WGPEER_A_ALLOWEDIPS: u16 = 9;
    pub const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

    pub const NESTED_WGPEER_A_ALLOWEDIPS: u16 = crate::netlink::attr::nl_nest(WGPEER_A_ALLOWEDIPS);
}

pub mod wgallowedip_attributes {
    pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
    pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
    pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;
}

#[derive(Debug)]
pub enum WireguardAllowedIpAttribute {
    IpFamily(u16),
    IpAddress(std::net::IpAddr),
    Cidr(u8),
}

#[derive(Debug)]
pub enum WireguardPeerAttribute {
    PublicKey([u8; WG_KEY_LEN]),
    PreSharedKey([u8; WG_KEY_LEN]),
    Endpoint(core::net::SocketAddr),
    PersitentKeepaliveInterval(u16),
    LastHandshakeTime,
    RxBytes(u64),
    TxBytes(u64),
    AllowedIps(Vec<WireguardAllowedIp>),
    ProtocolVersion(u32),
}

#[derive(Debug)]
pub enum WireguardDeviceAttribute {
    InterfaceIndex(u32),
    InterfaceName(String),
    PrivateKey([u8; WG_KEY_LEN]),
    PublicKey([u8; WG_KEY_LEN]),
    ListenPort(u16),
    FwMark(u32),
    Peers(Vec<WireguardPeer>),
}

#[derive(Debug)]
pub enum GetDeviceParseError {
    NoResponse,
    NoInterfaceIndex,
    NoInterfaceName,
    NoPrivateKey,
    NoPublicKey,
    NoListenPort,
    NoPeerPublicKey,
    NoPeerPresharedKey,
    NoPersitentKeepaliveInterval,
    NoPeerRxBytes,
    NoPeerTxBytes,
    NoAllowedIpaddress,
    UnknowAttribute(u16),
    UnknowPeerAttribute(u16),
    UnknowAllowedIpAttribute(u16),
    UnparsableInterfaceIndex,
    UnparsableInterfaceName,
    UnparsablePrivateKey,
    UnparsablePublicKey,
    UnparsableListenPort,
    UnparsableFwMark,
    UnparsablePreSharedKey,
    UnparsableEndpoint,
    UnparsablePersitentKeepaliveInterval,
    UnparsableRxBytes,
    UnparsableTxBytes,
    UnparsableProtocolVersion,
    UnparsableIpFamily,
    UnparsableIpAddress,
    UnparsableCidr,
}

#[derive(Debug, Clone, Hash)]
pub struct WireguardAllowedIp {
    pub ip_address: std::net::IpAddr,
    pub cidr: u8,
}

impl TryFrom<Vec<WireguardAllowedIpAttribute>> for WireguardAllowedIp {
    type Error = GetDeviceParseError;

    fn try_from(value: Vec<WireguardAllowedIpAttribute>) -> Result<Self, Self::Error> {
        let mut ip_address = None;
        let mut cidr = None;

        for attribute in value {
            match attribute {
                WireguardAllowedIpAttribute::IpFamily(_) => {}
                WireguardAllowedIpAttribute::IpAddress(address) => ip_address = Some(address),
                WireguardAllowedIpAttribute::Cidr(c) => cidr = Some(c),
            }
        }

        let ip_address = ip_address.ok_or(GetDeviceParseError::NoAllowedIpaddress)?;
        let cidr = cidr.unwrap_or(match &ip_address {
            std::net::IpAddr::V4(_) => 32,
            std::net::IpAddr::V6(_) => 128,
        });
        Ok(WireguardAllowedIp { ip_address, cidr })
    }
}

#[derive(Debug)]
pub struct WireguardPeer {
    pub public_key: [u8; WG_KEY_LEN],
    pub pre_shared_key: [u8; WG_KEY_LEN],
    pub endpoint: Option<core::net::SocketAddr>,
    pub persistent_keepalive_interval: u16,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed_ips: Vec<WireguardAllowedIp>,
}

impl TryFrom<Vec<WireguardPeerAttribute>> for WireguardPeer {
    type Error = GetDeviceParseError;

    fn try_from(value: Vec<WireguardPeerAttribute>) -> Result<Self, Self::Error> {
        let mut public_key = None;
        let mut pre_shared_key = None;
        let mut endpoint = None;
        let mut persistent_keepalive_interval = None;
        let mut rx_bytes = None;
        let mut tx_bytes = None;
        let mut allowed_ips = None;

        for attribute in value {
            match attribute {
                WireguardPeerAttribute::PublicKey(key) => public_key = Some(key),
                WireguardPeerAttribute::PreSharedKey(key) => pre_shared_key = Some(key),
                WireguardPeerAttribute::Endpoint(e) => endpoint = Some(e),
                WireguardPeerAttribute::PersitentKeepaliveInterval(interval) => {
                    persistent_keepalive_interval = Some(interval)
                }
                WireguardPeerAttribute::LastHandshakeTime => {}
                WireguardPeerAttribute::RxBytes(bytes) => rx_bytes = Some(bytes),
                WireguardPeerAttribute::TxBytes(bytes) => tx_bytes = Some(bytes),
                WireguardPeerAttribute::AllowedIps(ips) => allowed_ips = Some(ips),
                WireguardPeerAttribute::ProtocolVersion(_) => {}
            }
        }

        Ok(WireguardPeer {
            public_key: public_key.ok_or(GetDeviceParseError::NoPeerPublicKey)?,
            pre_shared_key: pre_shared_key.ok_or(GetDeviceParseError::NoPeerPresharedKey)?,
            endpoint,
            persistent_keepalive_interval: persistent_keepalive_interval
                .ok_or(GetDeviceParseError::NoPersitentKeepaliveInterval)?,
            rx_bytes: rx_bytes.ok_or(GetDeviceParseError::NoPeerRxBytes)?,
            tx_bytes: tx_bytes.ok_or(GetDeviceParseError::NoPeerTxBytes)?,
            allowed_ips: allowed_ips.unwrap_or_default(),
        })
    }
}

#[derive(Debug)]
pub struct WireguardDevice {
    pub interface_index: u32,
    pub interface_name: String,
    pub private_key: [u8; WG_KEY_LEN],
    pub public_key: [u8; WG_KEY_LEN],
    pub listen_port: u16,
    pub peers: Vec<WireguardPeer>,
}

impl TryFrom<Vec<WireguardDeviceAttribute>> for WireguardDevice {
    type Error = GetDeviceParseError;

    fn try_from(value: Vec<WireguardDeviceAttribute>) -> Result<Self, Self::Error> {
        let mut interface_index = None;
        let mut interface_name = None;
        let mut private_key = None;
        let mut public_key = None;
        let mut listen_port = None;
        let mut peers = None;

        for attribute in value {
            match attribute {
                WireguardDeviceAttribute::InterfaceIndex(index) => interface_index = Some(index),
                WireguardDeviceAttribute::InterfaceName(name) => interface_name = Some(name),
                WireguardDeviceAttribute::PrivateKey(key) => private_key = Some(key),
                WireguardDeviceAttribute::PublicKey(key) => public_key = Some(key),
                WireguardDeviceAttribute::ListenPort(port) => listen_port = Some(port),
                WireguardDeviceAttribute::Peers(wireguard_peers) => peers = Some(wireguard_peers),
                WireguardDeviceAttribute::FwMark(_) => {}
            }
        }

        Ok(WireguardDevice {
            interface_index: interface_index.ok_or(GetDeviceParseError::NoInterfaceIndex)?,
            interface_name: interface_name.ok_or(GetDeviceParseError::NoInterfaceName)?,
            private_key: private_key.ok_or(GetDeviceParseError::NoPrivateKey)?,
            public_key: public_key.ok_or(GetDeviceParseError::NoPublicKey)?,
            listen_port: listen_port.ok_or(GetDeviceParseError::NoListenPort)?,
            peers: peers.unwrap_or_default(),
        })
    }
}

pub fn read_wg_allowed_ip_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<WireguardAllowedIpAttribute, crate::ResponseError<GetDeviceParseError>> {
    match attribute.r#type {
        wgallowedip_attributes::WGALLOWEDIP_A_FAMILY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableIpFamily),
        )
        .map(WireguardAllowedIpAttribute::IpFamily),

        wgallowedip_attributes::WGALLOWEDIP_A_IPADDR => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_ip_address_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableIpAddress),
        )
        .map(WireguardAllowedIpAttribute::IpAddress),

        wgallowedip_attributes::WGALLOWEDIP_A_CIDR_MASK => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u8_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableCidr),
        )
        .map(WireguardAllowedIpAttribute::Cidr),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Err(crate::ResponseError::ProtocolParse(
                GetDeviceParseError::UnknowAllowedIpAttribute(other),
            ))
        }
    }
}

pub fn read_wg_peer_allowed_ip(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<WireguardAllowedIp, crate::ResponseError<GetDeviceParseError>> {
    let attributes: Result<
        Vec<WireguardAllowedIpAttribute>,
        crate::ResponseError<GetDeviceParseError>,
    > = crate::netlink::attr::NlAttributeIter::new(
        reader,
        read_wg_allowed_ip_attr,
        attribute.len as usize,
    )
    .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
    .collect();

    attributes?
        .try_into()
        .map_err(crate::ResponseError::ProtocolParse)
}

pub fn read_wg_peer_allowed_ips(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<WireguardAllowedIp>, crate::ResponseError<GetDeviceParseError>> {
    crate::netlink::attr::NlAttributeIter::new(reader, read_wg_peer_allowed_ip, len)
        .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
        .collect()
}

#[repr(C, packed)]
#[doc(hidden)]
struct SockaddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

#[repr(C, packed)]
#[doc(hidden)]
struct SockaddrIn6 {
    pub sin6_family: u16,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u8; 16],
    pub sin6_scope_id: u32,
}

fn write_socket_address_attr(
    writter: &mut impl std::io::Write,
    r#type: u16,
    socket_address: core::net::SocketAddr,
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;

    match socket_address {
        core::net::SocketAddr::V4(socket_addr_v4) => {
            written_bytes += crate::netlink::attr::NlAttribute {
                len: crate::netlink::attr::set_attr_length(core::mem::size_of::<SockaddrIn>())
                    as u16,
                r#type,
            }
            .write(writter)?;

            let socket_address = SockaddrIn {
                sin_family: 2,
                sin_port: socket_addr_v4.port().to_be(),
                sin_addr: socket_addr_v4.ip().octets(),
                sin_zero: [0; 8],
            };
            written_bytes += crate::netlink::utils::transprose_write(&socket_address, writter)?;
        }
        core::net::SocketAddr::V6(socket_addr_v6) => {
            written_bytes += crate::netlink::attr::NlAttribute {
                len: crate::netlink::attr::set_attr_length(core::mem::size_of::<SockaddrIn6>())
                    as u16,
                r#type,
            }
            .write(writter)?;

            let socket_address = SockaddrIn6 {
                sin6_family: 10,
                sin6_port: socket_addr_v6.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: socket_addr_v6.ip().octets(),
                sin6_scope_id: 0,
            };
            written_bytes += crate::netlink::utils::transprose_write(&socket_address, writter)?;
        }
    };

    Ok(written_bytes)
}

fn read_socket_address_attr(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Option<core::net::SocketAddr>, std::io::Error> {
    if len == core::mem::size_of::<SockaddrIn>() {
        let addr: SockaddrIn = crate::netlink::utils::transpose_read(reader)?;

        Ok(Some(core::net::SocketAddr::new(
            core::net::IpAddr::from(addr.sin_addr),
            u16::from_be(addr.sin_port),
        )))
    } else if len == core::mem::size_of::<SockaddrIn6>() {
        let addr: SockaddrIn6 = crate::netlink::utils::transpose_read(reader)?;

        Ok(Some(core::net::SocketAddr::new(
            core::net::IpAddr::from(addr.sin6_addr),
            u16::from_be(addr.sin6_port),
        )))
    } else {
        Ok(None)
    }
}

pub fn read_wg_peer_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<WireguardPeerAttribute, crate::ResponseError<GetDeviceParseError>> {
    match attribute.r#type {
        wgpeer_attributes::WGPEER_A_PUBLIC_KEY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsablePublicKey),
        )
        .map(WireguardPeerAttribute::PublicKey),

        wgpeer_attributes::WGPEER_A_PRESHARED_KEY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsablePreSharedKey),
        )
        .map(WireguardPeerAttribute::PreSharedKey),

        wgpeer_attributes::WGPEER_A_ENDPOINT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            read_socket_address_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableEndpoint),
        )
        .map(WireguardPeerAttribute::Endpoint),

        wgpeer_attributes::WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL => {
            crate::netlink::attr::recover_read(
                reader,
                attribute.len as usize,
                crate::netlink::attr::read_u16_attr,
                crate::ResponseError::ProtocolParse(
                    GetDeviceParseError::UnparsablePersitentKeepaliveInterval,
                ),
            )
            .map(WireguardPeerAttribute::PersitentKeepaliveInterval)
        }

        // TODO parse
        wgpeer_attributes::WGPEER_A_LAST_HANDSHAKE_TIME => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Ok(WireguardPeerAttribute::LastHandshakeTime)
        }

        wgpeer_attributes::WGPEER_A_RX_BYTES => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u64_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableRxBytes),
        )
        .map(WireguardPeerAttribute::RxBytes),

        wgpeer_attributes::WGPEER_A_TX_BYTES => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u64_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableTxBytes),
        )
        .map(WireguardPeerAttribute::TxBytes),

        wgpeer_attributes::WGPEER_A_PROTOCOL_VERSION => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableProtocolVersion),
        )
        .map(WireguardPeerAttribute::ProtocolVersion),

        wgpeer_attributes::WGPEER_A_ALLOWEDIPS | wgpeer_attributes::NESTED_WGPEER_A_ALLOWEDIPS => {
            read_wg_peer_allowed_ips(reader, attribute.len as usize)
                .map(WireguardPeerAttribute::AllowedIps)
        }

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Err(crate::ResponseError::ProtocolParse(
                GetDeviceParseError::UnknowPeerAttribute(other),
            ))
        }
    }
}

pub fn read_wg_peer(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<WireguardPeer, crate::ResponseError<GetDeviceParseError>> {
    let attributes: Result<Vec<WireguardPeerAttribute>, crate::ResponseError<GetDeviceParseError>> =
        crate::netlink::attr::NlAttributeIter::new(
            reader,
            read_wg_peer_attr,
            attribute.len as usize,
        )
        .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
        .collect();

    attributes?
        .try_into()
        .map_err(crate::ResponseError::ProtocolParse)
}

pub fn read_wg_peers(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<WireguardPeer>, crate::ResponseError<GetDeviceParseError>> {
    crate::netlink::attr::NlAttributeIter::new(reader, read_wg_peer, len)
        .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
        .collect()
}

pub fn read_get_device_attr(
    reader: &mut impl std::io::Read,
    attribute: crate::netlink::attr::NlAttribute,
) -> Result<WireguardDeviceAttribute, crate::ResponseError<GetDeviceParseError>> {
    match attribute.r#type {
        wgdevice_attributes::WGDEVICE_A_IFINDEX => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableInterfaceIndex),
        )
        .map(WireguardDeviceAttribute::InterfaceIndex),

        wgdevice_attributes::WGDEVICE_A_IFNAME => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_string_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableInterfaceName),
        )
        .map(WireguardDeviceAttribute::InterfaceName),

        wgdevice_attributes::WGDEVICE_A_PRIVATE_KEY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsablePrivateKey),
        )
        .map(WireguardDeviceAttribute::PrivateKey),

        wgdevice_attributes::WGDEVICE_A_PUBLIC_KEY => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_array_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsablePublicKey),
        )
        .map(WireguardDeviceAttribute::PublicKey),

        wgdevice_attributes::WGDEVICE_A_LISTEN_PORT => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u16_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableListenPort),
        )
        .map(WireguardDeviceAttribute::ListenPort),

        wgdevice_attributes::WGDEVICE_A_FWMARK => crate::netlink::attr::recover_read(
            reader,
            attribute.len as usize,
            crate::netlink::attr::read_u32_attr,
            crate::ResponseError::ProtocolParse(GetDeviceParseError::UnparsableFwMark),
        )
        .map(WireguardDeviceAttribute::FwMark),

        wgdevice_attributes::WGDEVICE_A_PEERS | wgdevice_attributes::NESTED_WGDEVICE_A_PEERS => Ok(
            WireguardDeviceAttribute::Peers(read_wg_peers(reader, attribute.len as usize)?),
        ),

        other => {
            crate::netlink::utils::skip_n_bytes(reader, attribute.len as usize)?;
            Err(crate::ResponseError::ProtocolParse(
                GetDeviceParseError::UnknowAttribute(other),
            ))
        }
    }
}

pub fn read_get_device_response(
    reader: &mut impl std::io::Read,
    len: usize,
) -> Result<Vec<WireguardDeviceAttribute>, crate::ResponseError<GetDeviceParseError>> {
    crate::genetlink::msg::skip_generic_netlink_header(reader)?;
    let remaining_bytes = len - crate::genetlink::msg::GeNlMsgHeader::SIZE;

    crate::netlink::attr::NlAttributeIter::new(reader, read_get_device_attr, remaining_bytes)
        .map(|result| result.map_err(Into::into).and_then(core::convert::identity))
        .collect()
}

/// set message type and flags for a WG_CMD_GET_DEVICE request
pub fn get_device_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_DUMP;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct GetDeviceByIndexMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub if_index: u32,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for GetDeviceByIndexMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = u32;
    type Output = WireguardDevice;
    type ParseError = GetDeviceParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        get_device_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                WG_CMD_GET_DEVICE,
                WIREGUARD_GENL_VERSION,
            ),
            if_index: input,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header
            .set_generic_playload_length(crate::netlink::attr::set_attr_length_aligned(4));

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            wgdevice_attributes::WGDEVICE_A_IFINDEX,
            self.if_index,
        )?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        let mut message = crate::netlink::msg::NlMsgIter::new(reader, read_get_device_response);

        match message.next() {
            Some(e) => e
                .map_err(crate::ResponseError::HeaderParse)
                .and_then(core::convert::identity)
                .and_then(|attributes| {
                    WireguardDevice::try_from(attributes)
                        .map_err(crate::ResponseError::ProtocolParse)
                }),
            None => Err(crate::ResponseError::ProtocolParse(
                GetDeviceParseError::NoResponse,
            )),
        }
    }
}

pub struct GetDeviceByNameMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub if_name: String,
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for GetDeviceByNameMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = String;
    type Output = WireguardDevice;
    type ParseError = GetDeviceParseError;

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        get_device_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                WG_CMD_GET_DEVICE,
                WIREGUARD_GENL_VERSION,
            ),
            if_name: input,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;
        self.nl_msg_header.set_generic_playload_length(
            crate::netlink::attr::set_string_length_aligned(self.if_name.len()),
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            wgdevice_attributes::WGDEVICE_A_IFNAME,
            &self.if_name,
        )?;

        Ok((self.buffer, written_bytes))
    }

    fn parse_response(
        reader: &mut impl std::io::Read,
    ) -> Result<Self::Output, crate::ResponseError<Self::ParseError>> {
        let mut message = crate::netlink::msg::NlMsgIter::new(reader, read_get_device_response);

        match message.next() {
            Some(e) => e
                .map_err(crate::ResponseError::HeaderParse)
                .and_then(core::convert::identity)
                .and_then(|attributes| {
                    WireguardDevice::try_from(attributes)
                        .map_err(crate::ResponseError::ProtocolParse)
                }),
            None => Err(crate::ResponseError::ProtocolParse(
                GetDeviceParseError::NoResponse,
            )),
        }
    }
}

#[derive(Debug, Clone, Hash)]
#[repr(u32)]
pub enum WireGuardPeerFlag {
    RemoveMe = 1 << 0,
    ReplaceAllowedIps = 1 << 1,
    UpdateOnly = 1 << 2,
}

#[derive(Debug, Clone, Hash)]
pub struct WireguardPeerConfig {
    pub public_key: [u8; WG_KEY_LEN],
    pub pre_shared_key: Option<[u8; WG_KEY_LEN]>,
    pub flag: WireGuardPeerFlag,
    pub endpoint: Option<core::net::SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Vec<WireguardAllowedIp>,
}

impl WireguardPeerConfig {
    #[inline]
    pub fn new(
        public_key: [u8; WG_KEY_LEN],
        allowed_ips: Vec<WireguardAllowedIp>,
        flag: WireGuardPeerFlag,
    ) -> Self {
        WireguardPeerConfig {
            public_key,
            pre_shared_key: None,
            flag,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips,
        }
    }

    #[inline]
    pub fn delete(public_key: [u8; WG_KEY_LEN], allowed_ips: Vec<WireguardAllowedIp>) -> Self {
        Self::new(public_key, allowed_ips, WireGuardPeerFlag::RemoveMe)
    }

    #[inline]
    pub fn add(public_key: [u8; WG_KEY_LEN], allowed_ips: Vec<WireguardAllowedIp>) -> Self {
        Self::new(
            public_key,
            allowed_ips,
            WireGuardPeerFlag::ReplaceAllowedIps,
        )
    }

    #[inline]
    pub fn update(public_key: [u8; WG_KEY_LEN], allowed_ips: Vec<WireguardAllowedIp>) -> Self {
        Self::new(public_key, allowed_ips, WireGuardPeerFlag::UpdateOnly)
    }
}

impl From<WireguardPeer> for WireguardPeerConfig {
    fn from(value: WireguardPeer) -> Self {
        WireguardPeerConfig {
            public_key: value.public_key,
            pre_shared_key: if value
                .pre_shared_key
                .iter()
                .fold(true, |acc, e| *e == 0 && acc)
            {
                None
            } else {
                Some(value.pre_shared_key)
            },
            flag: WireGuardPeerFlag::UpdateOnly,
            endpoint: value.endpoint,
            persistent_keepalive_interval: if value.persistent_keepalive_interval == 0 {
                None
            } else {
                Some(value.persistent_keepalive_interval)
            },
            allowed_ips: value.allowed_ips,
        }
    }
}

#[derive(Debug, Clone, Hash)]
pub struct WireguardConfig {
    pub private_key: [u8; WG_KEY_LEN],
    pub listen_port: u16,
    pub peers: Vec<WireguardPeerConfig>,
}

impl From<WireguardDevice> for WireguardConfig {
    fn from(value: WireguardDevice) -> Self {
        WireguardConfig {
            private_key: value.private_key,
            listen_port: value.listen_port,
            peers: value.peers.into_iter().map(Into::into).collect(),
        }
    }
}

fn calculate_peers_lengths(peers: &[WireguardPeerConfig]) -> (usize, Vec<(usize, usize)>) {
    let mut peers_len: usize = 0;
    let mut peers_lengths = Vec::with_capacity(1);

    for p in peers {
        let mut peer_len = crate::netlink::attr::NlAttribute::SIZE;

        // WGPEER_A_PUBLIC_KEY
        peer_len += crate::netlink::attr::set_attr_length_aligned(WG_KEY_LEN);

        // WGPEER_A_PRESHARED_KEY
        if p.pre_shared_key.is_some() {
            peer_len += crate::netlink::attr::set_attr_length_aligned(WG_KEY_LEN);
        }

        // WGPEER_A_FLAGS
        peer_len += crate::netlink::attr::set_attr_length_aligned(4);

        // WGPEER_A_ENDPOINT
        if let Some(endpoint) = p.endpoint {
            peer_len += crate::netlink::attr::set_attr_length_aligned(match endpoint {
                core::net::SocketAddr::V4(_) => core::mem::size_of::<SockaddrIn>(),
                core::net::SocketAddr::V6(_) => core::mem::size_of::<SockaddrIn6>(),
            });
        }

        // WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL
        if p.persistent_keepalive_interval.is_some() {
            peer_len += crate::netlink::attr::set_attr_length_aligned(2);
        }

        // WGPEER_A_ALLOWEDIPS
        let mut allowed_ips_len = crate::netlink::attr::NlAttribute::SIZE;
        for a in &p.allowed_ips {
            allowed_ips_len += crate::netlink::attr::NlAttribute::SIZE;
            // WGALLOWEDIP_A_FAMILY
            allowed_ips_len += crate::netlink::attr::set_attr_length_aligned(2);
            // WGALLOWEDIP_A_IPADDR
            allowed_ips_len += crate::netlink::attr::set_attr_length_aligned(match &a.ip_address {
                core::net::IpAddr::V4(_) => 4,
                core::net::IpAddr::V6(_) => 16,
            });
            // WGALLOWEDIP_A_CIDR_MASK
            allowed_ips_len += crate::netlink::attr::set_attr_length_aligned(1);
        }

        peer_len += allowed_ips_len;

        peers_len += peer_len;
        peers_lengths.push((peer_len, allowed_ips_len));
    }

    (peers_len, peers_lengths)
}

fn set_wireguard_set_message_length(
    netlink_message_header: &mut NlMsgHeader,
    first_attribute_length: usize,
    peers_length: usize,
) {
    netlink_message_header.set_generic_playload_length(
        first_attribute_length
            // WGDEVICE_A_PRIVATE_KEY
            + crate::netlink::attr::set_attr_length_aligned(WG_KEY_LEN)
            // WGDEVICE_A_FLAGS
            + crate::netlink::attr::set_attr_length_aligned(4)
            // WGDEVICE_A_LISTEN_PORT
            + crate::netlink::attr::set_attr_length_aligned(2)
            // WGDEVICE_A_PEERS
            + crate::netlink::attr::set_attr_length_aligned(peers_length),
    );
}

fn write_wireguard_set_message<B: std::io::Write>(
    buffer: &mut B,
    config: WireguardConfig,
    replace_peers: bool,
    peers_length: usize,
    peers_lengths: &[(usize, usize)],
) -> Result<usize, std::io::Error> {
    let mut written_bytes = 0;

    written_bytes += crate::netlink::attr::write_array_attr(
        buffer,
        wgdevice_attributes::WGDEVICE_A_PRIVATE_KEY,
        config.private_key,
    )?;

    written_bytes += crate::netlink::attr::write_u32_attr(
        buffer,
        wgdevice_attributes::WGDEVICE_A_FLAGS,
        if replace_peers { 1 } else { 0 },
    )?;

    written_bytes += crate::netlink::attr::write_u16_attr(
        buffer,
        wgdevice_attributes::WGDEVICE_A_LISTEN_PORT,
        config.listen_port,
    )?;

    written_bytes += crate::netlink::attr::NlAttribute {
        len: crate::netlink::attr::set_attr_length(peers_length) as u16,
        r#type: wgdevice_attributes::NESTED_WGDEVICE_A_PEERS,
    }
    .write(buffer)?;

    for (i, p) in config.peers.into_iter().enumerate() {
        written_bytes += crate::netlink::attr::NlAttribute {
            len: peers_lengths[i].0 as u16,
            r#type: crate::netlink::attr::NLA_F_NESTED,
        }
        .write(buffer)?;

        written_bytes += crate::netlink::attr::write_array_attr(
            buffer,
            wgpeer_attributes::WGPEER_A_PUBLIC_KEY,
            p.public_key,
        )?;

        if let Some(pre_shared_key) = p.pre_shared_key {
            written_bytes += crate::netlink::attr::write_array_attr(
                buffer,
                wgpeer_attributes::WGPEER_A_PRESHARED_KEY,
                pre_shared_key,
            )?;
        }

        written_bytes += crate::netlink::attr::write_u32_attr(
            buffer,
            wgpeer_attributes::WGPEER_A_FLAGS,
            p.flag as u32,
        )?;

        if let Some(endpoint) = p.endpoint {
            written_bytes +=
                write_socket_address_attr(buffer, wgpeer_attributes::WGPEER_A_ENDPOINT, endpoint)?;
        }

        if let Some(persistent_keepalive_interval) = p.persistent_keepalive_interval {
            written_bytes += crate::netlink::attr::write_u16_attr(
                buffer,
                wgpeer_attributes::WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
                persistent_keepalive_interval,
            )?;
        }

        written_bytes += crate::netlink::attr::NlAttribute {
            len: peers_lengths[i].1 as u16,
            r#type: wgpeer_attributes::NESTED_WGPEER_A_ALLOWEDIPS,
        }
        .write(buffer)?;

        for a in p.allowed_ips {
            match a.ip_address {
                std::net::IpAddr::V4(_) => {
                    written_bytes += crate::netlink::attr::NlAttribute {
                        len: crate::netlink::attr::set_attr_length_aligned(
                            // WGALLOWEDIP_A_FAMILY
                            crate::netlink::attr::set_attr_length_aligned(2)
                                // WGALLOWEDIP_A_IPADDR
                                + crate::netlink::attr::set_attr_length_aligned(4)
                                // WGALLOWEDIP_A_CIDR_MASK
                                + crate::netlink::attr::set_attr_length_aligned(1),
                        ) as u16,
                        r#type: crate::netlink::attr::NLA_F_NESTED,
                    }
                    .write(buffer)?;

                    written_bytes += crate::netlink::attr::write_u16_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_FAMILY,
                        2,
                    )?;

                    written_bytes += crate::netlink::attr::write_ip_address_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_IPADDR,
                        &a.ip_address,
                    )?;

                    written_bytes += crate::netlink::attr::write_u8_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_CIDR_MASK,
                        a.cidr,
                    )?;
                }
                std::net::IpAddr::V6(_) => {
                    written_bytes += crate::netlink::attr::NlAttribute {
                        len: crate::netlink::attr::set_attr_length_aligned(
                            // WGALLOWEDIP_A_FAMILY
                            crate::netlink::attr::set_attr_length_aligned(2)
                                // WGALLOWEDIP_A_IPADDR
                                + crate::netlink::attr::set_attr_length_aligned(16)
                                // WGALLOWEDIP_A_CIDR_MASK
                                + crate::netlink::attr::set_attr_length_aligned(1),
                        ) as u16,
                        r#type: crate::netlink::attr::NLA_F_NESTED,
                    }
                    .write(buffer)?;

                    written_bytes += crate::netlink::attr::write_u16_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_FAMILY,
                        10,
                    )?;

                    written_bytes += crate::netlink::attr::write_ip_address_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_IPADDR,
                        &a.ip_address,
                    )?;

                    written_bytes += crate::netlink::attr::write_u8_attr(
                        buffer,
                        wgallowedip_attributes::WGALLOWEDIP_A_CIDR_MASK,
                        a.cidr,
                    )?;
                }
            }
        }
    }

    Ok(written_bytes)
}

/// set message type and flags for a WG_CMD_SET_DEVICE request
pub fn set_device_nl_header(header: &mut NlMsgHeader, family: u16) {
    const FLAGS: u16 = NLM_F_REQUEST | NLM_F_ACK;
    header.r#type = family;
    header.flags = FLAGS;
}

pub struct SetDeviceByIndexMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub if_index: u32,
    pub config: WireguardConfig,
    pub replace_peers: bool,
}

impl<'a, Buffer: std::io::Write> SetDeviceByIndexMessageBuilder<'a, Buffer> {
    #[inline]
    pub fn replace_peers(&mut self, replace_peers: bool) {
        self.replace_peers = replace_peers;
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for SetDeviceByIndexMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = (u32, WireguardConfig);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        set_device_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                WG_CMD_SET_DEVICE,
                WIREGUARD_GENL_VERSION,
            ),
            if_index: input.0,
            config: input.1,
            replace_peers: true,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        let (peers_length, peers_lengths) = calculate_peers_lengths(&self.config.peers);

        set_wireguard_set_message_length(
            &mut self.nl_msg_header,
            crate::netlink::attr::set_attr_length_aligned(4),
            peers_length,
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_u32_attr(
            self.buffer,
            wgdevice_attributes::WGDEVICE_A_IFINDEX,
            self.if_index,
        )?;

        written_bytes += write_wireguard_set_message(
            self.buffer,
            self.config,
            self.replace_peers,
            peers_length,
            &peers_lengths,
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

pub struct SetDeviceByNameMessageBuilder<'a, Buffer: std::io::Write> {
    pub buffer: &'a mut Buffer,
    pub nl_msg_header: crate::netlink::msg::NlMsgHeader,
    pub ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader,
    pub if_name: String,
    pub config: WireguardConfig,
    pub replace_peers: bool,
}

impl<'a, Buffer: std::io::Write> SetDeviceByNameMessageBuilder<'a, Buffer> {
    #[inline]
    pub fn replace_peers(&mut self, replace_peers: bool) {
        self.replace_peers = replace_peers;
    }
}

impl<'a, Buffer: std::io::Write> GenericMessageBuilder<'a>
    for SetDeviceByNameMessageBuilder<'a, Buffer>
{
    type Buffer = Buffer;
    type Input = (String, WireguardConfig);
    type Output = ();
    type ParseError = ();

    fn new_with_header(
        buffer: &'a mut Self::Buffer,
        mut nl_msg_header: NlMsgHeader,
        family: u16,
        input: Self::Input,
    ) -> Self {
        set_device_nl_header(&mut nl_msg_header, family);

        Self {
            buffer,
            nl_msg_header,
            ge_nl_msg_header: crate::genetlink::msg::GeNlMsgHeader::new(
                WG_CMD_SET_DEVICE,
                WIREGUARD_GENL_VERSION,
            ),
            if_name: input.0,
            config: input.1,
            replace_peers: true,
        }
    }

    fn build(mut self) -> Result<(&'a mut Self::Buffer, usize), std::io::Error> {
        let mut written_bytes: usize = 0;

        let (peers_length, peers_lengths) = calculate_peers_lengths(&self.config.peers);

        set_wireguard_set_message_length(
            &mut self.nl_msg_header,
            crate::netlink::attr::set_string_length_aligned(self.if_name.len()),
            peers_length,
        );

        written_bytes += self.nl_msg_header.write(self.buffer)?;
        written_bytes += self.ge_nl_msg_header.write(self.buffer)?;

        written_bytes += crate::netlink::attr::write_string_attr(
            self.buffer,
            wgdevice_attributes::WGDEVICE_A_IFNAME,
            &self.if_name,
        )?;

        written_bytes += write_wireguard_set_message(
            self.buffer,
            self.config,
            self.replace_peers,
            peers_length,
            &peers_lengths,
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
