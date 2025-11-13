// SPDX-License-Identifier: MIT
pub mod addr;
pub mod link;
pub mod neigh;
pub mod route;

/// ipv4 or ipv6
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum IpFamily {
    AF_INET = 2,
    AF_INET6 = 10,
}

impl TryFrom<u8> for IpFamily {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(IpFamily::AF_INET),
            10 => Ok(IpFamily::AF_INET6),
            _ => Err(()),
        }
    }
}

impl From<&std::net::IpAddr> for IpFamily {
    fn from(value: &std::net::IpAddr) -> Self {
        if value.is_ipv4() {
            IpFamily::AF_INET
        } else {
            IpFamily::AF_INET6
        }
    }
}
