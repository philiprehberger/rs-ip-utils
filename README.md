# rs-ip-utils

[![CI](https://github.com/philiprehberger/rs-ip-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-ip-utils/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-ip-utils.svg)](https://crates.io/crates/philiprehberger-ip-utils)
[![GitHub release](https://img.shields.io/github/v/release/philiprehberger/rs-ip-utils)](https://github.com/philiprehberger/rs-ip-utils/releases)
[![Last updated](https://img.shields.io/github/last-commit/philiprehberger/rs-ip-utils)](https://github.com/philiprehberger/rs-ip-utils/commits/main)
[![License](https://img.shields.io/github/license/philiprehberger/rs-ip-utils)](LICENSE)
[![Bug Reports](https://img.shields.io/github/issues/philiprehberger/rs-ip-utils/bug)](https://github.com/philiprehberger/rs-ip-utils/issues?q=is%3Aissue+is%3Aopen+label%3Abug)
[![Feature Requests](https://img.shields.io/github/issues/philiprehberger/rs-ip-utils/enhancement)](https://github.com/philiprehberger/rs-ip-utils/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
[![Sponsor](https://img.shields.io/badge/sponsor-GitHub%20Sponsors-ec6cb9)](https://github.com/sponsors/philiprehberger)

IP address utilities — CIDR matching, subnet calculation, classification, and anonymization

## Installation

```toml
[dependencies]
philiprehberger-ip-utils = "0.1.1"
```

## Usage

```rust
use philiprehberger_ip_utils::{Cidr, IpClassify};
use std::net::IpAddr;

// CIDR matching
let cidr = Cidr::parse("192.168.1.0/24").unwrap();
let ip: IpAddr = "192.168.1.100".parse().unwrap();
assert!(cidr.contains(ip));

// Subnet info
assert_eq!(cidr.network_address(), "192.168.1.0".parse::<IpAddr>().unwrap());
assert_eq!(cidr.host_count(), 256);
```

### IP classification

```rust
use philiprehberger_ip_utils::IpClassify;
use std::net::IpAddr;

let ip: IpAddr = "10.0.0.1".parse().unwrap();
assert!(ip.is_private());
assert!(!ip.is_global_ip());

let public: IpAddr = "8.8.8.8".parse().unwrap();
assert!(public.is_global_ip());
```

### Anonymization

```rust
use philiprehberger_ip_utils::anonymize;

let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
let anon = anonymize(ip, 8); // zero last 8 bits
assert_eq!(anon.to_string(), "192.168.1.0");
```

## API

| Function / Type | Description |
|----------------|-------------|
| `Cidr::parse(s)` | Parse CIDR notation |
| `.contains(ip)` | Check if IP is in range |
| `.network_address()` | First address in range |
| `.broadcast_address()` | Last address (IPv4) |
| `.host_count()` | Number of addresses |
| `.subnet_mask()` | Subnet mask (IPv4) |
| `.overlaps(other)` | Check if CIDRs overlap |
| `IpClassify` trait | IP classification methods |
| `anonymize(ip, bits)` | Zero last N bits |
| `aggregate(cidrs)` | Merge overlapping CIDRs |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## Support

If you find this package useful, consider giving it a star on GitHub — it helps motivate continued maintenance and development.

[![LinkedIn](https://img.shields.io/badge/Philip%20Rehberger-LinkedIn-0A66C2?logo=linkedin)](https://www.linkedin.com/in/philiprehberger)
[![More packages](https://img.shields.io/badge/more-open%20source%20packages-blue)](https://philiprehberger.com/open-source-packages)

## License

[MIT](LICENSE)
