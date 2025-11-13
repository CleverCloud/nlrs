// SPDX-License-Identifier: MIT
//! ipvs control messages
//!
//! [ipvs (IP Virtual Server)](https://kb.linuxvirtualserver.org/wiki/IPVS) is a Linux kernel module designed for load balancing at Layer 4 (the transport layer).
//!
//! ipvs can distribute incoming TCP and UDP connections across multiple real servers,
//! making a cluster of servers appear as a single virtual service exposed on one IP address.
//! This allows for scalable and highly available network services.
//!
//! ipvs is controllable via the generic netlink interface.
//! The main implementation of ipvs control messages via generic netlink is [ipvsadm](https://git.kernel.org/pub/scm/utils/kernel/ipvsadm/ipvsadm.git)
//!
//! Be carefull, user sending ipvs control messages need to be root or [CAP_NET_ADMIN](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
//!
//! ## Getting started
//!
//! Here is a simple example getting ipvs informations:
//!
//! ```rust
//! use nlrs::{
//!     genetlink::socket::{GenericNetlinkSocket, GenericRequestBuilder},
//!     ipvs::{IPVS_FAMILY, info::GetInfoMessageBuilder},
//!     socket::NetlinkSocket,
//! };
//!
//! // creating a classic netlink socket
//! let netlink_socket =
//!     NetlinkSocket::new_vectored(nlrs::netlink::socket::NlSocketType::NETLINK_GENERIC);
//!
//! if let Ok(netlink_socket) = netlink_socket {
//!     // upgrading to a generic netlink socket to send ipvs message
//!     let generic_netlink_socket =
//!         GenericNetlinkSocket::from_netlink_socket(netlink_socket, IPVS_FAMILY.to_string());
//!
//!     if let Ok(mut ipvs_socket) = generic_netlink_socket {
//!         // getting ipvs module infos
//!         let message_builder: GetInfoMessageBuilder<_> = ipvs_socket.message_builder(());
//!
//!         // request can fail (example: user is not allowed to use ipvs)
//!         if let Ok(ipvs_infos) = message_builder.call() {
//!             println!(
//!                 "IP Virtual Server version {}.{}.{} (size={})",
//!                 ipvs_infos.version_major,
//!                 ipvs_infos.version_minor,
//!                 ipvs_infos.version_patch,
//!                 ipvs_infos.connection_table_size
//!             );
//!         } else {
//!             println!("ipvs info request has failed")
//!         }
//!     }
//! }
//! ```
pub mod destination;
pub mod flush;
pub mod info;
pub mod service;

/// `IPVS`, the generic netlink family name
pub const IPVS_FAMILY: &str = "IPVS";
/// `1`, the generic netlink ipvs protocol version
pub const IPVS_GENL_VERSION: u8 = 1;

/// layer 4 protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Protocol {
    TCP = 6,
    UDP = 17,
}

impl TryFrom<u16> for Protocol {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            val if val == Protocol::TCP as u16 => Ok(Self::TCP),
            val if val == Protocol::UDP as u16 => Ok(Self::UDP),
            _ => Err(()),
        }
    }
}

/// ip address family (ipv4 or ipv6)
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum IpFamily {
    /// ipv4
    AF_INET = 2,
    /// ipv6
    AF_INET6 = 10,
}

impl TryFrom<u16> for IpFamily {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            val if val == IpFamily::AF_INET as u16 => Ok(IpFamily::AF_INET),
            val if val == IpFamily::AF_INET6 as u16 => Ok(IpFamily::AF_INET6),
            _ => Err(()),
        }
    }
}

/// an ipvs service (frontend)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpvsService {
    pub service_address: std::net::SocketAddr,
    pub protocol: Protocol,
}

/// ipvs nested attributes numbers
pub mod cmd_attributes {
    /// nested service attribute
    pub const IPVS_CMD_ATTR_SERVICE: u16 = 1;
    /// nested destination attribute
    pub const IPVS_CMD_ATTR_DEST: u16 = 2;
    /// nested sync daemon attribute
    pub const IPVS_CMD_ATTR_DAEMON: u16 = 3;
    /// TCP connection timeout
    pub const IPVS_CMD_ATTR_TIMEOUT_TCP: u16 = 4;
    /// TCP FIN wait timeout
    pub const IPVS_CMD_ATTR_TIMEOUT_TCP_FIN: u16 = 5;
    /// UDP timeout
    pub const IPVS_CMD_ATTR_TIMEOUT_UDP: u16 = 6;
}
