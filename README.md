# DSMap: Uncovering the Dual-Stack Internet via TLS-Assisted Hierarchical Fingerprinting

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**DSMap** is a dual-stack host discovery framework that identifies IPv4/IPv6 sibling hosts through TLS-assisted hierarchical fingerprinting. It significantly outperforms state-of-the-art methods (Trilink, SSH+BGP, SNMPv3, TCP Clock) in host yield, AS coverage, and country coverage.

## Overview

Precise perception of Internet topology requires identifying dual-stack hosts — machines that simultaneously support IPv4 and IPv6 protocol stacks. Existing methods face two critical bottlenecks:

1. **Candidate Scarcity**: Heavy reliance on passive DNS or IPv4-embedded IPv6 addresses (which account for <1% of active IPv6 hitlists)
2. **Rigid Matching**: Multi-protocol intersection constraints that miss hosts with sparse service exposure

DSMap addresses these challenges through two key innovations:

- **TLS Certificate-Associated Mining**: Extracts domains from TLS certificates on IPv6 interfaces and uses DNS forward queries to actively generate high-probability dual-stack candidate pairs, bypassing passive DNS dependencies.
- **Entropy-Driven Hierarchical Fingerprinting**: Classifies protocol fingerprints into strong (SSH, TLS — high entropy) and weak (HTTP, FTP, MySQL — low entropy) tiers. Strong fingerprints enable early-termination validation; weak fingerprints provide joint probability cross-validation for sparse-service hosts.

In Internet-wide measurements spanning 92 million domain names and 32 million IPv6 addresses, DSMap discovered **91.27% ∼ 2705.53% more** dual-stack hosts compared to existing methods, while expanding AS and country coverage by **81.04% ∼ 849.79%** and **19.64% ∼ 247.41%** respectively.

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │  Phase 1: Candidate Dual-Stack Mining    │
                    │                                          │
  Domain Names ────►│  DNS Resolution  ──► IPv4 + IPv6 Addrs   │
                    │                     (cross-product pairs) │
  IPv6 Hitlist ────►│  IPv4-Embedded IID Parsing               │
                    │  TLS Certificate Domain Association      │
                    │  (SAN/CN → Filter → DNS Forward)         │
                    └──────────────────┬───────────────────────┘
                                       │ Candidate Pairs
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  Phase 2: Hierarchical Verification      │
                    │                                          │
  Candidate Pairs ─►│  AS/Geo Pre-Filtering                    │
                    │       │                                  │
                    │       ▼                                  │
                    │  Port Scanning (22, 443, 21, 80, 3306)   │
                    │       │                                  │
                    │       ▼                                  │
                    │  Strong Fingerprints (SSH, TLS)          │
                    │    Match → Early Termination ✓           │
                    │    No Match → Fall Through               │
                    │       │                                  │
                    │       ▼                                  │
                    │  Weak Fingerprints (HTTP, FTP, MySQL)    │
                    │    Joint Validation → ✓ / ✗              │
                    └──────────────────┬───────────────────────┘
                                       │ Verified Pairs
                                       ▼
                    ┌──────────────────────────────────────────┐
                    │  Phase 3: Host Aggregation               │
                    │  Union-Find Clustering → Physical Hosts  │
                    │  (Anomaly filter: |Ci| > 10 discarded)   │
                    └──────────────────────────────────────────┘
```

## Fingerprint Entropy Classification

| Protocol | Field(s)                                                            | IPv4 Entropy | IPv6 Entropy | Tier  |
|----------|---------------------------------------------------------------------|-------------|-------------|-------|
| SSH      | server_id, kex_algorithms, server_host_key                         | 0.9912      | 0.9758      | Strong |
| TLS      | spki_subject_fingerprint                                            | 0.9360      | 0.9343      | Strong |
| FTP      | banner (elevated by IP/hostname embedding rules)                    | 0.5584      | 0.5391      | Weak† |
| MySQL    | server_version                                                      | 0.4718      | 0.4145      | Weak  |
| HTTP     | etag, last_modified, body_sha256                                    | 0.2826      | 0.7050      | Weak  |

† FTP banners embedding cross-protocol IPs or specific hostnames are elevated to strong fingerprints.

## Directory Structure

```
DSMap/
├── dsmap/                    # Core package
│   ├── __init__.py           # Package metadata
│   ├── candidate_miner.py    # Candidate dual-stack address mining
│   ├── fingerprint.py        # Protocol fingerprint extraction
│   ├── verifier.py           # Hierarchical verification pipeline
│   ├── aggregator.py         # Host clustering (Union-Find)
│   └── dsmap.py              # Main orchestrator
├── main.py                   # Command-line entry point
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

## Installation

```bash
# Clone the repository
git clone <repo-url> DSMap
cd DSMap

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

- `scapy` — Packet manipulation
- `cryptography` — X.509 certificate parsing
- `geoip2` — MaxMind GeoLite2 AS/Geo databases (optional, for AS/Geo filtering)
- `tqdm` — Progress bars

## Usage

### Command-Line Interface

```bash
# From domain name list
python main.py --domains top1m_domains.txt --output results.json

# From IPv6 hitlist (extract IPv4-embedded addresses)
python main.py --ipv6-hitlist ipv6_hitlist.txt --output results.json

# From IPv6 hitlist with TLS certificate mining
python main.py --ipv6-hitlist ipv6_hitlist.txt --tls-scan --output results.json

# With AS/Geo filtering (requires MaxMind databases)
python main.py --domains domains.txt \
    --asn-db GeoLite2-ASN.mmdb \
    --geo-db GeoLite2-City.mmdb \
    --output results.json \
    --ptr-check
```

### Output Format

```json
{
  "candidate_pairs": [
    {"ipv4": "192.0.2.1", "ipv6": "2001:db8::1"}
  ],
  "verified_pairs": [
    {"ipv4": "192.0.2.1", "ipv6": "2001:db8::1"}
  ],
  "host_clusters": [
    ["192.0.2.1", "192.0.2.2", "2001:db8::1"]
  ],
  "stats": {
    "candidate_pairs": 12345,
    "verified_pairs": 1234,
    "total_hosts": 567,
    "total_ipv4": 567,
    "total_ipv6": 623,
    "avg_cluster_size": 2.1,
    "max_cluster_size": 8,
    "min_cluster_size": 1,
    "discovery_rate": 12.34,
    "elapsed_seconds": 45.9
  }
}
```

## License

MIT License
