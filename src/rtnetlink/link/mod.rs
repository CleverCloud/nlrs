// SPDX-License-Identifier: MIT
//! ip link management
mod add;
mod del;
mod get;
pub mod ipvlan;
pub mod master;
mod state;
pub mod veth;

pub use add::*;
pub use del::*;
pub use get::*;
pub use state::*;

pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;

#[derive(Debug)]
#[repr(C, packed)]
pub struct IfInfoMsg {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

impl IfInfoMsg {
    /// size of a [`IfInfoMsg`] in bytes
    pub const SIZE: usize = std::mem::size_of::<IfInfoMsg>();

    pub fn new(interface_index: i32) -> Self {
        IfInfoMsg {
            ifi_index: interface_index,
            ..Default::default()
        }
    }

    pub fn new_with_flags_and_change(interface_index: i32, flags: u32, change: u32) -> Self {
        IfInfoMsg {
            ifi_index: interface_index,
            ifi_flags: flags,
            ifi_change: change,
            ..Default::default()
        }
    }

    #[inline]
    pub fn write(&self, writer: &mut impl std::io::Write) -> Result<usize, std::io::Error> {
        crate::netlink::utils::transprose_write(self, writer)
    }

    #[inline]
    pub fn read(reader: &mut impl std::io::Read) -> Result<IfInfoMsg, std::io::Error> {
        crate::netlink::utils::transpose_read(reader)
    }
}

pub const AF_PACKET: u8 = 17;

impl Default for IfInfoMsg {
    fn default() -> Self {
        IfInfoMsg {
            ifi_family: AF_PACKET,
            _ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        }
    }
}

pub mod devices_flags {
    pub const IFF_UP: u32 = 1 << 0;
    pub const IFF_BROADCAST: u32 = 1 << 1;
    pub const IFF_DEBUG: u32 = 1 << 2;
    pub const IFF_LOOPBACK: u32 = 1 << 3;
    pub const IFF_POINTOPOINT: u32 = 1 << 4;
    pub const IFF_NOTRAILERS: u32 = 1 << 5;
    pub const IFF_RUNNING: u32 = 1 << 6;
    pub const IFF_NOARP: u32 = 1 << 7;
    pub const IFF_PROMISC: u32 = 1 << 8;
    pub const IFF_ALLMULTI: u32 = 1 << 9;
    pub const IFF_MASTER: u32 = 1 << 10;
    pub const IFF_SLAVE: u32 = 1 << 11;
    pub const IFF_MULTICAST: u32 = 1 << 12;
    pub const IFF_PORTSEL: u32 = 1 << 13;
    pub const IFF_AUTOMEDIA: u32 = 1 << 14;
    pub const IFF_DYNAMIC: u32 = 1 << 15;
    pub const IFF_LOWER_UP: u32 = 1 << 16;
    pub const IFF_DORMANT: u32 = 1 << 17;
    pub const IFF_ECHO: u32 = 1 << 18;
}

pub mod link_attributes {
    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFLA_LINK: u16 = 5;
    pub const IFLA_QDISC: u16 = 6;
    pub const IFLA_STATS: u16 = 7;
    pub const IFLA_COST: u16 = 8;
    pub const IFLA_PRIORITY: u16 = 9;
    pub const IFLA_MASTER: u16 = 10;
    pub const IFLA_WIRELESS: u16 = 11;
    pub const IFLA_PROTINFO: u16 = 12;
    pub const IFLA_TXQLEN: u16 = 13;
    pub const IFLA_MAP: u16 = 14;
    pub const IFLA_WEIGHT: u16 = 15;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKMODE: u16 = 17;
    pub const IFLA_LINKINFO: u16 = 18;
    pub const IFLA_NET_NS_PID: u16 = 19;
    pub const IFLA_IFALIAS: u16 = 20;
    pub const IFLA_NUM_VF: u16 = 21;
    pub const IFLA_VFINFO_LIST: u16 = 22;
    pub const IFLA_STATS64: u16 = 23;
    pub const IFLA_VF_PORTS: u16 = 24;
    pub const IFLA_PORT_SELF: u16 = 25;
    pub const IFLA_AF_SPEC: u16 = 26;
    pub const IFLA_GROUP: u16 = 27;
    pub const IFLA_NET_NS_FD: u16 = 28;
    pub const IFLA_EXT_MASK: u16 = 29;
    pub const IFLA_PROMISCUITY: u16 = 30;
}

pub mod link_info_attributes {
    pub const IFLA_INFO_KIND: u16 = 1;
    pub const IFLA_INFO_DATA: u16 = 2;
    pub const IFLA_INFO_XSTATS: u16 = 3;
    pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
    pub const IFLA_INFO_SLAVE_DATA: u16 = 5;
}

#[derive(Debug)]
pub enum LinkAttribute {
    Address([u8; 6]),
    BroadcastAddress([u8; 6]),
    InterfaceName(String),
    Mtu(u32),
    Link(u32),
    Other(u16),
    Weight(u32),
    OperationalState(u8),
    Group(u32),
}
