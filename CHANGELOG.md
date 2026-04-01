# Changelog

## 0.1.2 (2026-03-31)

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility

## 0.1.1 (2026-03-27)

- Add GitHub issue templates, PR template, and dependabot configuration
- Update README badges and add Support section

## 0.1.0 (2026-03-19)

- Initial release
- Cidr struct for IPv4 and IPv6 CIDR ranges
- Contains check for IP-in-CIDR matching
- Subnet calculations: network address, broadcast, host count, wildcard mask
- IP classification: private, loopback, CGNAT, documentation, reserved, link-local
- CIDR iteration over all addresses in a range
- IP anonymization for GDPR compliance
- CIDR aggregation (merge overlapping ranges)
