//! IP address utilities — CIDR matching, subnet calculation, classification, and anonymization.
//!
//! This crate provides tools for working with IPv4 and IPv6 addresses using only the
//! standard library. Features include CIDR range parsing and matching, subnet calculations,
//! IP classification (private, loopback, CGNAT, etc.), anonymization for GDPR compliance,
//! and CIDR aggregation.
//!
//! # Examples
//!
//! ```
//! use philiprehberger_ip_utils::{Cidr, IpClassify, anonymize};
//! use std::net::IpAddr;
//!
//! let cidr = Cidr::parse("192.168.1.0/24").unwrap();
//! let ip: IpAddr = "192.168.1.100".parse().unwrap();
//! assert!(cidr.contains(ip));
//!
//! assert!(ip.is_private());
//! assert!(!ip.is_global_ip());
//!
//! let anon = anonymize(ip, 8);
//! assert_eq!(anon.to_string(), "192.168.1.0");
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Error type for CIDR parsing and construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The input string is not in valid CIDR notation (e.g., missing `/`).
    InvalidFormat(String),
    /// The address portion could not be parsed.
    InvalidAddress(String),
    /// The prefix length exceeds the maximum for the address family.
    InvalidPrefixLen {
        /// The provided prefix length.
        len: u8,
        /// The maximum allowed prefix length (32 for IPv4, 128 for IPv6).
        max: u8,
    },
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::InvalidFormat(s) => write!(f, "invalid CIDR format: {s}"),
            CidrError::InvalidAddress(s) => write!(f, "invalid IP address: {s}"),
            CidrError::InvalidPrefixLen { len, max } => {
                write!(f, "prefix length {len} exceeds maximum {max}")
            }
        }
    }
}

impl std::error::Error for CidrError {}

/// A CIDR range representing a network prefix.
///
/// Supports both IPv4 and IPv6 addresses. The address stored is the network address
/// (all host bits zeroed).
///
/// # Examples
///
/// ```
/// use philiprehberger_ip_utils::Cidr;
///
/// let cidr = Cidr::parse("10.0.0.0/8").unwrap();
/// assert!(cidr.contains("10.1.2.3".parse().unwrap()));
/// assert!(!cidr.contains("192.168.1.1".parse().unwrap()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Parse a CIDR string such as `"10.0.0.0/8"` or `"fe80::/10"`.
    ///
    /// Returns an error if the format is invalid, the address cannot be parsed,
    /// or the prefix length is out of range.
    pub fn parse(s: &str) -> Result<Cidr, CidrError> {
        s.parse()
    }

    /// Create a new CIDR from an address and prefix length.
    ///
    /// The prefix length must be 0-32 for IPv4 or 0-128 for IPv6.
    /// The stored address is normalized to the network address (host bits zeroed).
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Cidr, CidrError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(CidrError::InvalidPrefixLen {
                len: prefix_len,
                max,
            });
        }
        let network = apply_mask(addr, prefix_len);
        Ok(Cidr {
            addr: network,
            prefix_len,
        })
    }

    /// Returns the network address of this CIDR.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Returns the prefix length.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Check if an IP address falls within this CIDR range.
    ///
    /// Returns `false` if the IP address family does not match the CIDR family.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (&self.addr, &ip) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
            _ => apply_mask(ip, self.prefix_len) == self.addr,
        }
    }

    /// Returns the network address (first address in the range).
    pub fn network_address(&self) -> IpAddr {
        self.addr
    }

    /// Returns the broadcast address (last address in the range).
    ///
    /// Only applicable to IPv4; returns `None` for IPv6.
    pub fn broadcast_address(&self) -> Option<IpAddr> {
        match self.addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let host_bits = 32 - self.prefix_len;
                let broadcast = if host_bits == 32 {
                    u32::MAX
                } else {
                    bits | ((1u32 << host_bits) - 1)
                };
                Some(IpAddr::V4(Ipv4Addr::from(broadcast)))
            }
            IpAddr::V6(_) => None,
        }
    }

    /// Returns the number of addresses in this CIDR range.
    pub fn host_count(&self) -> u128 {
        match self.addr {
            IpAddr::V4(_) => 1u128 << (32 - self.prefix_len as u32),
            IpAddr::V6(_) => 1u128 << (128 - self.prefix_len as u32),
        }
    }

    /// Returns the wildcard mask (inverse of subnet mask).
    ///
    /// Only applicable to IPv4; returns `None` for IPv6.
    pub fn wildcard_mask(&self) -> Option<Ipv4Addr> {
        match self.addr {
            IpAddr::V4(_) => {
                let mask = ipv4_mask(self.prefix_len);
                Some(Ipv4Addr::from(!u32::from(mask)))
            }
            IpAddr::V6(_) => None,
        }
    }

    /// Returns the subnet mask.
    ///
    /// Only applicable to IPv4; returns `None` for IPv6.
    pub fn subnet_mask(&self) -> Option<Ipv4Addr> {
        match self.addr {
            IpAddr::V4(_) => Some(ipv4_mask(self.prefix_len)),
            IpAddr::V6(_) => None,
        }
    }

    /// Returns `true` if this is an IPv4 CIDR.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Returns `true` if this is an IPv6 CIDR.
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Check if this CIDR overlaps with another.
    ///
    /// Two CIDRs overlap if either contains the network address of the other.
    /// Returns `false` if the address families differ.
    pub fn overlaps(&self, other: &Cidr) -> bool {
        match (&self.addr, &other.addr) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
            _ => self.contains(other.addr) || other.contains(self.addr),
        }
    }

    /// Returns an iterator over all IPv4 addresses in this CIDR range.
    ///
    /// Returns `None` for IPv6 CIDRs or if the prefix length is less than 16
    /// (to prevent accidentally iterating over more than 65536 addresses).
    pub fn iter_v4(&self) -> Option<CidrIter> {
        match self.addr {
            IpAddr::V4(v4) => {
                if self.prefix_len < 16 {
                    return None;
                }
                let start = u32::from(v4);
                let count = 1u32 << (32 - self.prefix_len as u32);
                Some(CidrIter {
                    current: start,
                    end: start.saturating_add(count),
                })
            }
            IpAddr::V6(_) => None,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| CidrError::InvalidFormat(s.to_string()))?;

        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| CidrError::InvalidAddress(addr_str.to_string()))?;

        let prefix_len: u8 = prefix_str
            .parse()
            .map_err(|_| CidrError::InvalidFormat(format!("invalid prefix: {prefix_str}")))?;

        Cidr::new(addr, prefix_len)
    }
}

/// Iterator over IPv4 addresses in a CIDR range.
pub struct CidrIter {
    current: u32,
    end: u32,
}

impl Iterator for CidrIter {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.end {
            let addr = Ipv4Addr::from(self.current);
            self.current = self.current.saturating_add(1);
            Some(addr)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.current) as usize;
        (remaining, Some(remaining))
    }
}

/// IP address classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    /// Loopback address (127.0.0.0/8, ::1).
    Loopback,
    /// Private address (10/8, 172.16/12, 192.168/16, fc00::/7).
    Private,
    /// Link-local address (169.254/16, fe80::/10).
    LinkLocal,
    /// Carrier-grade NAT (100.64.0.0/10).
    Cgnat,
    /// Documentation range (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32).
    Documentation,
    /// Reserved address (240.0.0.0/4).
    Reserved,
    /// Globally routable address.
    Global,
}

/// Extension trait for classifying IP addresses.
///
/// Provides methods to check whether an IP address belongs to a specific category
/// (private, loopback, link-local, etc.).
pub trait IpClassify {
    /// Returns `true` if this is a private address.
    ///
    /// IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
    /// IPv6: fc00::/7 (unique local addresses).
    fn is_private(&self) -> bool;

    /// Returns `true` if this is a loopback address.
    ///
    /// IPv4: 127.0.0.0/8. IPv6: ::1.
    fn is_loopback_ip(&self) -> bool;

    /// Returns `true` if this is a CGNAT (Carrier-Grade NAT) address.
    ///
    /// IPv4: 100.64.0.0/10. Not applicable to IPv6.
    fn is_cgnat(&self) -> bool;

    /// Returns `true` if this is a documentation address.
    ///
    /// IPv4: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
    /// IPv6: 2001:db8::/32.
    fn is_documentation(&self) -> bool;

    /// Returns `true` if this is a reserved address.
    ///
    /// IPv4: 240.0.0.0/4. Not applicable to IPv6.
    fn is_reserved(&self) -> bool;

    /// Returns `true` if this is a link-local address.
    ///
    /// IPv4: 169.254.0.0/16. IPv6: fe80::/10.
    fn is_link_local(&self) -> bool;

    /// Returns `true` if this is a globally routable address.
    ///
    /// An address is global if it is not private, loopback, link-local, CGNAT,
    /// documentation, or reserved.
    fn is_global_ip(&self) -> bool;

    /// Returns the classification of this IP address.
    fn classify(&self) -> IpClass;
}

impl IpClassify for IpAddr {
    fn is_private(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(v6) => {
                // fc00::/7
                let segments = v6.segments();
                (segments[0] & 0xfe00) == 0xfc00
            }
        }
    }

    fn is_loopback_ip(&self) -> bool {
        match self {
            IpAddr::V4(v4) => v4.octets()[0] == 127,
            IpAddr::V6(v6) => *v6 == Ipv6Addr::LOCALHOST,
        }
    }

    fn is_cgnat(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 100.64.0.0/10
                octets[0] == 100 && (octets[1] & 0xc0) == 64
            }
            IpAddr::V6(_) => false,
        }
    }

    fn is_documentation(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 192.0.2.0/24
                (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                // 198.51.100.0/24
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                // 203.0.113.0/24
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            }
            IpAddr::V6(v6) => {
                // 2001:db8::/32
                let segments = v6.segments();
                segments[0] == 0x2001 && segments[1] == 0x0db8
            }
        }
    }

    fn is_reserved(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                // 240.0.0.0/4
                v4.octets()[0] & 0xf0 == 240
            }
            IpAddr::V6(_) => false,
        }
    }

    fn is_link_local(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 169.254.0.0/16
                octets[0] == 169 && octets[1] == 254
            }
            IpAddr::V6(v6) => {
                // fe80::/10
                let segments = v6.segments();
                (segments[0] & 0xffc0) == 0xfe80
            }
        }
    }

    fn is_global_ip(&self) -> bool {
        !self.is_private()
            && !self.is_loopback_ip()
            && !self.is_link_local()
            && !self.is_cgnat()
            && !IpClassify::is_documentation(self)
            && !self.is_reserved()
    }

    fn classify(&self) -> IpClass {
        if self.is_loopback_ip() {
            IpClass::Loopback
        } else if self.is_link_local() {
            IpClass::LinkLocal
        } else if self.is_private() {
            IpClass::Private
        } else if self.is_cgnat() {
            IpClass::Cgnat
        } else if IpClassify::is_documentation(self) {
            IpClass::Documentation
        } else if self.is_reserved() {
            IpClass::Reserved
        } else {
            IpClass::Global
        }
    }
}

/// Anonymize an IP address by zeroing the last `mask_bits` bits.
///
/// Useful for GDPR compliance. For example, `anonymize(ip, 8)` on an IPv4 address
/// zeros the last octet.
///
/// # Examples
///
/// ```
/// use philiprehberger_ip_utils::anonymize;
/// use std::net::IpAddr;
///
/// let ip: IpAddr = "192.168.1.100".parse().unwrap();
/// let anon = anonymize(ip, 8);
/// assert_eq!(anon.to_string(), "192.168.1.0");
/// ```
pub fn anonymize(ip: IpAddr, mask_bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask_bits = mask_bits.min(32);
            if mask_bits == 32 {
                IpAddr::V4(Ipv4Addr::from(0u32))
            } else {
                let mask = !((1u32 << mask_bits) - 1);
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask_bits = mask_bits.min(128);
            if mask_bits == 128 {
                IpAddr::V6(Ipv6Addr::from(0u128))
            } else {
                let mask = !((1u128 << mask_bits) - 1);
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }
}

/// Merge overlapping or adjacent CIDRs into a minimal set.
///
/// CIDRs that are contained within a larger CIDR are removed. Adjacent CIDRs
/// with the same prefix length that can be combined into a single larger CIDR
/// are merged.
///
/// Only merges CIDRs of the same address family. IPv4 and IPv6 CIDRs are
/// processed separately.
///
/// # Examples
///
/// ```
/// use philiprehberger_ip_utils::{Cidr, aggregate};
///
/// let cidrs = vec![
///     Cidr::parse("10.0.0.0/8").unwrap(),
///     Cidr::parse("10.1.0.0/16").unwrap(),
/// ];
/// let merged = aggregate(&cidrs);
/// assert_eq!(merged.len(), 1);
/// assert_eq!(merged[0].to_string(), "10.0.0.0/8");
/// ```
pub fn aggregate(cidrs: &[Cidr]) -> Vec<Cidr> {
    let mut v4: Vec<(u32, u8)> = Vec::new();
    let mut v6: Vec<(u128, u8)> = Vec::new();

    for cidr in cidrs {
        match cidr.addr {
            IpAddr::V4(addr) => v4.push((u32::from(addr), cidr.prefix_len)),
            IpAddr::V6(addr) => v6.push((u128::from(addr), cidr.prefix_len)),
        }
    }

    // Sort by network address, then by prefix length
    v4.sort();
    v6.sort();

    let mut result = Vec::new();

    // Merge IPv4
    let merged_v4 = merge_ranges_v4(&v4);
    for (addr, prefix) in merged_v4 {
        result.push(Cidr {
            addr: IpAddr::V4(Ipv4Addr::from(addr)),
            prefix_len: prefix,
        });
    }

    // Merge IPv6
    let merged_v6 = merge_ranges_v6(&v6);
    for (addr, prefix) in merged_v6 {
        result.push(Cidr {
            addr: IpAddr::V6(Ipv6Addr::from(addr)),
            prefix_len: prefix,
        });
    }

    result
}

fn merge_ranges_v4(ranges: &[(u32, u8)]) -> Vec<(u32, u8)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut result: Vec<(u32, u8)> = Vec::new();

    for &(addr, prefix) in ranges {
        let end = if prefix == 0 {
            u64::from(u32::MAX)
        } else {
            u64::from(addr) + (1u64 << (32 - prefix)) - 1
        };

        let mut contained = false;
        for &(ra, rp) in &result {
            let rend = if rp == 0 {
                u64::from(u32::MAX)
            } else {
                u64::from(ra) + (1u64 << (32 - rp)) - 1
            };
            if u64::from(addr) >= u64::from(ra) && end <= rend {
                contained = true;
                break;
            }
        }
        if !contained {
            // Remove any entries contained within this new one
            result.retain(|&(ra, rp)| {
                let rend = if rp == 0 {
                    u64::from(u32::MAX)
                } else {
                    u64::from(ra) + (1u64 << (32 - rp)) - 1
                };
                !(u64::from(ra) >= u64::from(addr) && rend <= end)
            });
            result.push((addr, prefix));
        }
    }

    // Try merging adjacent same-prefix CIDRs
    loop {
        let mut merged = false;
        let mut next: Vec<(u32, u8)> = Vec::new();
        let mut skip = vec![false; result.len()];

        for i in 0..result.len() {
            if skip[i] {
                continue;
            }
            let (a1, p1) = result[i];
            let mut found = false;
            for j in (i + 1)..result.len() {
                if skip[j] {
                    continue;
                }
                let (a2, p2) = result[j];
                if p1 == p2 && p1 > 0 {
                    let parent_prefix = p1 - 1;
                    let mask = if parent_prefix == 0 {
                        0u32
                    } else {
                        !((1u32 << (32 - parent_prefix)) - 1)
                    };
                    if (a1 & mask) == (a2 & mask) {
                        next.push((a1 & mask, parent_prefix));
                        skip[j] = true;
                        found = true;
                        merged = true;
                        break;
                    }
                }
            }
            if !found {
                next.push((a1, p1));
            }
        }
        result = next;
        if !merged {
            break;
        }
    }

    result.sort();
    result
}

fn merge_ranges_v6(ranges: &[(u128, u8)]) -> Vec<(u128, u8)> {
    if ranges.is_empty() {
        return Vec::new();
    }

    let mut result: Vec<(u128, u8)> = Vec::new();

    for &(addr, prefix) in ranges {
        let size = if prefix == 0 {
            u128::MAX
        } else {
            (1u128 << (128 - prefix)) - 1
        };
        let end = addr.saturating_add(size);

        let mut contained = false;
        for &(ra, rp) in &result {
            let rsize = if rp == 0 {
                u128::MAX
            } else {
                (1u128 << (128 - rp)) - 1
            };
            let rend = ra.saturating_add(rsize);
            if addr >= ra && end <= rend {
                contained = true;
                break;
            }
        }
        if !contained {
            result.retain(|&(ra, rp)| {
                let rsize = if rp == 0 {
                    u128::MAX
                } else {
                    (1u128 << (128 - rp)) - 1
                };
                let rend = ra.saturating_add(rsize);
                !(ra >= addr && rend <= end)
            });
            result.push((addr, prefix));
        }
    }

    result.sort();
    result
}

/// Compute an IPv4 subnet mask from a prefix length.
fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        Ipv4Addr::from(0u32)
    } else {
        Ipv4Addr::from(!((1u32 << (32 - prefix_len)) - 1))
    }
}

/// Apply a prefix mask to an IP address, zeroing host bits.
fn apply_mask(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            if prefix_len == 0 {
                IpAddr::V4(Ipv4Addr::from(0u32))
            } else if prefix_len >= 32 {
                IpAddr::V4(v4)
            } else {
                let mask = !((1u32 << (32 - prefix_len)) - 1);
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            if prefix_len == 0 {
                IpAddr::V6(Ipv6Addr::from(0u128))
            } else if prefix_len >= 128 {
                IpAddr::V6(v6)
            } else {
                let mask = !((1u128 << (128 - prefix_len)) - 1);
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_ipv4() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(cidr.addr(), "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len(), 8);

        let cidr = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(cidr.addr(), "192.168.1.0".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len(), 24);
    }

    #[test]
    fn test_parse_valid_ipv6() {
        let cidr = Cidr::parse("::1/128").unwrap();
        assert_eq!(cidr.addr(), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len(), 128);

        let cidr = Cidr::parse("fe80::/10").unwrap();
        assert_eq!(cidr.addr(), "fe80::".parse::<IpAddr>().unwrap());
        assert_eq!(cidr.prefix_len(), 10);
    }

    #[test]
    fn test_parse_normalizes_network_address() {
        let cidr = Cidr::parse("192.168.1.100/24").unwrap();
        assert_eq!(cidr.addr(), "192.168.1.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_parse_invalid_no_slash() {
        assert!(Cidr::parse("10.0.0.0").is_err());
    }

    #[test]
    fn test_parse_invalid_address() {
        assert!(Cidr::parse("999.999.999.999/8").is_err());
    }

    #[test]
    fn test_parse_invalid_prefix() {
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
    }

    #[test]
    fn test_prefix_len_too_large_v4() {
        let err = Cidr::new("10.0.0.0".parse().unwrap(), 33).unwrap_err();
        assert_eq!(
            err,
            CidrError::InvalidPrefixLen { len: 33, max: 32 }
        );
    }

    #[test]
    fn test_prefix_len_too_large_v6() {
        let err = Cidr::new("::1".parse().unwrap(), 129).unwrap_err();
        assert_eq!(
            err,
            CidrError::InvalidPrefixLen { len: 129, max: 128 }
        );
    }

    #[test]
    fn test_contains_ipv4() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.0.0.1".parse().unwrap()));
        assert!(cidr.contains("10.255.255.255".parse().unwrap()));
        assert!(!cidr.contains("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_contains_ipv6() {
        let cidr = Cidr::parse("fe80::/10").unwrap();
        assert!(cidr.contains("fe80::1".parse().unwrap()));
        assert!(cidr.contains("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!cidr.contains("ff00::1".parse().unwrap()));
    }

    #[test]
    fn test_contains_family_mismatch() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!cidr.contains("::1".parse().unwrap()));
    }

    #[test]
    fn test_network_address() {
        let cidr = Cidr::parse("192.168.1.100/24").unwrap();
        assert_eq!(
            cidr.network_address(),
            "192.168.1.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_broadcast_address() {
        let cidr = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(
            cidr.broadcast_address(),
            Some("192.168.1.255".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_broadcast_address_ipv6_none() {
        let cidr = Cidr::parse("fe80::/10").unwrap();
        assert_eq!(cidr.broadcast_address(), None);
    }

    #[test]
    fn test_host_count() {
        let cidr24 = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(cidr24.host_count(), 256);

        let cidr32 = Cidr::parse("10.0.0.1/32").unwrap();
        assert_eq!(cidr32.host_count(), 1);

        let cidr0 = Cidr::parse("0.0.0.0/0").unwrap();
        assert_eq!(cidr0.host_count(), 1u128 << 32);
    }

    #[test]
    fn test_subnet_mask() {
        let cidr24 = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(
            cidr24.subnet_mask(),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );

        let cidr16 = Cidr::parse("172.16.0.0/16").unwrap();
        assert_eq!(cidr16.subnet_mask(), Some(Ipv4Addr::new(255, 255, 0, 0)));

        let cidr8 = Cidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(cidr8.subnet_mask(), Some(Ipv4Addr::new(255, 0, 0, 0)));
    }

    #[test]
    fn test_subnet_mask_ipv6_none() {
        let cidr = Cidr::parse("fe80::/10").unwrap();
        assert_eq!(cidr.subnet_mask(), None);
    }

    #[test]
    fn test_wildcard_mask() {
        let cidr = Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(cidr.wildcard_mask(), Some(Ipv4Addr::new(0, 0, 0, 255)));
    }

    #[test]
    fn test_overlaps() {
        let a = Cidr::parse("10.0.0.0/8").unwrap();
        let b = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));

        let c = Cidr::parse("192.168.0.0/16").unwrap();
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_is_ipv4_ipv6() {
        let v4 = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(v4.is_ipv4());
        assert!(!v4.is_ipv6());

        let v6 = Cidr::parse("fe80::/10").unwrap();
        assert!(v6.is_ipv6());
        assert!(!v6.is_ipv4());
    }

    #[test]
    fn test_classify_private() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(ip.is_private());
        assert_eq!(ip.classify(), IpClass::Private);

        let ip: IpAddr = "172.16.5.1".parse().unwrap();
        assert!(ip.is_private());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip.is_private());
    }

    #[test]
    fn test_classify_global() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ip.is_global_ip());
        assert_eq!(ip.classify(), IpClass::Global);
    }

    #[test]
    fn test_classify_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(ip.is_loopback_ip());
        assert_eq!(ip.classify(), IpClass::Loopback);
    }

    #[test]
    fn test_classify_link_local() {
        let ip: IpAddr = "169.254.1.1".parse().unwrap();
        assert!(ip.is_link_local());
        assert_eq!(ip.classify(), IpClass::LinkLocal);
    }

    #[test]
    fn test_classify_cgnat() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        assert!(ip.is_cgnat());
        assert_eq!(ip.classify(), IpClass::Cgnat);
    }

    #[test]
    fn test_classify_documentation() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(IpClassify::is_documentation(&ip));
        assert_eq!(ip.classify(), IpClass::Documentation);

        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(IpClassify::is_documentation(&ip));

        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(IpClassify::is_documentation(&ip));
    }

    #[test]
    fn test_classify_reserved() {
        let ip: IpAddr = "240.0.0.1".parse().unwrap();
        assert!(ip.is_reserved());
        assert_eq!(ip.classify(), IpClass::Reserved);
    }

    #[test]
    fn test_classify_ipv6_private() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(ip.is_private());
    }

    #[test]
    fn test_classify_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(ip.is_link_local());
    }

    #[test]
    fn test_classify_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(ip.is_loopback_ip());
    }

    #[test]
    fn test_anonymize_ipv4() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let anon = anonymize(ip, 8);
        assert_eq!(anon.to_string(), "192.168.1.0");
    }

    #[test]
    fn test_anonymize_ipv4_16_bits() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let anon = anonymize(ip, 16);
        assert_eq!(anon.to_string(), "192.168.0.0");
    }

    #[test]
    fn test_anonymize_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let anon = anonymize(ip, 80);
        assert_eq!(anon.to_string(), "2001:db8::");
    }

    #[test]
    fn test_aggregate_contained() {
        let cidrs = vec![
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("10.1.0.0/16").unwrap(),
        ];
        let merged = aggregate(&cidrs);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_aggregate_non_overlapping() {
        let cidrs = vec![
            Cidr::parse("10.0.0.0/8").unwrap(),
            Cidr::parse("192.168.0.0/16").unwrap(),
        ];
        let merged = aggregate(&cidrs);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn test_aggregate_adjacent() {
        let cidrs = vec![
            Cidr::parse("10.0.0.0/25").unwrap(),
            Cidr::parse("10.0.0.128/25").unwrap(),
        ];
        let merged = aggregate(&cidrs);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn test_iter_v4_slash30() {
        let cidr = Cidr::parse("192.168.1.0/30").unwrap();
        let addrs: Vec<Ipv4Addr> = cidr.iter_v4().unwrap().collect();
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(addrs[1], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addrs[2], Ipv4Addr::new(192, 168, 1, 2));
        assert_eq!(addrs[3], Ipv4Addr::new(192, 168, 1, 3));
    }

    #[test]
    fn test_iter_v4_too_large() {
        let cidr = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.iter_v4().is_none());
    }

    #[test]
    fn test_iter_v4_ipv6_returns_none() {
        let cidr = Cidr::parse("fe80::/10").unwrap();
        assert!(cidr.iter_v4().is_none());
    }

    #[test]
    fn test_display_roundtrip() {
        let original = "192.168.1.0/24";
        let cidr = Cidr::parse(original).unwrap();
        let displayed = cidr.to_string();
        assert_eq!(displayed, original);

        let roundtrip: Cidr = displayed.parse().unwrap();
        assert_eq!(roundtrip, cidr);
    }

    #[test]
    fn test_display_roundtrip_ipv6() {
        let cidr = Cidr::parse("fe80::/10").unwrap();
        let displayed = cidr.to_string();
        let roundtrip: Cidr = displayed.parse().unwrap();
        assert_eq!(roundtrip, cidr);
    }

    #[test]
    fn test_fromstr() {
        let cidr: Cidr = "10.0.0.0/8".parse().unwrap();
        assert_eq!(cidr.prefix_len(), 8);
    }

    #[test]
    fn test_cidr_error_display() {
        let err = CidrError::InvalidFormat("bad".to_string());
        assert_eq!(err.to_string(), "invalid CIDR format: bad");

        let err = CidrError::InvalidAddress("nope".to_string());
        assert_eq!(err.to_string(), "invalid IP address: nope");

        let err = CidrError::InvalidPrefixLen { len: 33, max: 32 };
        assert_eq!(err.to_string(), "prefix length 33 exceeds maximum 32");
    }

    #[test]
    fn test_host_count_ipv6() {
        let cidr = Cidr::parse("fe80::/128").unwrap();
        assert_eq!(cidr.host_count(), 1);

        let cidr = Cidr::parse("fe80::/120").unwrap();
        assert_eq!(cidr.host_count(), 256);
    }

    #[test]
    fn test_overlaps_different_families() {
        let v4 = Cidr::parse("10.0.0.0/8").unwrap();
        let v6 = Cidr::parse("fe80::/10").unwrap();
        assert!(!v4.overlaps(&v6));
    }

    #[test]
    fn test_aggregate_empty() {
        let merged = aggregate(&[]);
        assert!(merged.is_empty());
    }
}
