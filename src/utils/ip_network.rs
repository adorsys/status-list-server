//! CIDR networks for the trusted-proxy list.

use std::{fmt, net::IpAddr, str::FromStr};

/// An IP network in CIDR notation, such as `10.0.0.0/8` or `fd00::/8`. A bare
/// address is a single-host network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Whether `ip` lies in this network. An IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is compared as the IPv4 address it carries, since
    /// dual-stack listeners report IPv4 peers that way.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_matches(
                u128::from(net.to_bits()),
                u128::from(ip.to_bits()),
                self.prefix,
                32,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_matches(net.to_bits(), ip.to_bits(), self.prefix, 128)
            }
            _ => false,
        }
    }
}

fn prefix_matches(net: u128, ip: u128, prefix: u8, width: u8) -> bool {
    let host_bits = u32::from(width - prefix);
    net.checked_shr(host_bits).unwrap_or(0) == ip.checked_shr(host_bits).unwrap_or(0)
}

impl FromStr for IpNetwork {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| format!("`{value}` is not an IP address or CIDR network"))?
            .to_canonical();
        let width = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= width)
                .ok_or_else(|| format!("`{value}` has a prefix length above {width}"))?,
        };
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(value: &str) -> IpNetwork {
        value.parse().unwrap()
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn matches_addresses_inside_the_prefix_only() {
        let private = net("10.0.0.0/8");
        assert!(private.contains(ip("10.255.0.1")));
        assert!(!private.contains(ip("11.0.0.1")));
        assert!(net("fd00::/8").contains(ip("fd12::1")));
        assert!(!net("fd00::/8").contains(ip("fe80::1")));
        assert!(net("0.0.0.0/0").contains(ip("203.0.113.9")));
        assert!(net("::/0").contains(ip("2001:db8::1")));
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        assert!(net("192.0.2.7").contains(ip("192.0.2.7")));
        assert!(!net("192.0.2.7").contains(ip("192.0.2.8")));
        assert_eq!(net("2001:db8::1").to_string(), "2001:db8::1/128");
    }

    #[test]
    fn ipv4_mapped_peers_match_ipv4_networks() {
        assert!(net("10.0.0.0/8").contains(ip("::ffff:10.1.2.3")));
        // IPv4-compatible (`::a.b.c.d`), not IPv4-mapped: stays IPv6.
        assert!(!net("10.0.0.0/8").contains(ip("::10.1.2.3")));
    }

    #[test]
    fn rejects_malformed_networks() {
        for value in [
            "",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/x",
            "example.com/8",
        ] {
            assert!(value.parse::<IpNetwork>().is_err(), "{value}");
        }
    }
}
