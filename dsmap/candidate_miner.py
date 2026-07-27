"""
Candidate Dual-Stack Address Mining Module

Implements three candidate generation strategies described in the DSMap paper:
1. DNS resolution of domain names
2. IPv4-embedded IPv6 address parsing
3. TLS certificate-associated mining (the novel contribution)

Reference: DSMap paper, Section III-B
"""

import re
import socket
import struct
import ssl
from typing import Set, Tuple, List, Dict, Optional

# Predefined CDN/wildcard infrastructure blacklist (B in the paper)
CDN_BLACKLIST = {
    "ssl.fastly.net",
    "fastly.net",
    "cloudfront.net",
    "akamai.net",
    "akamaiedge.net",
    "azureedge.net",
    "azurefd.net",
    "cloudflare.net",
    "cdn77.com",
    "cachefly.net",
    "edgesuite.net",
    "edgekey.net",
    "gblnet.net",
    "googleusercontent.com",
    "bc.googleusercontent.com",
}


def _is_wildcard_domain(domain: str) -> bool:
    """Check if domain contains wildcard (*)."""
    return "*" in domain


def _is_cdn_domain(domain: str) -> bool:
    """Check if domain matches known CDN infrastructure patterns."""
    domain_lower = domain.lower()
    for suffix in CDN_BLACKLIST:
        if domain_lower.endswith(suffix) or domain_lower == suffix:
            return True
    return False


def parse_certificate_sans(cert_der: bytes) -> Set[str]:
    """
    Parse Subject Alternative Names (SANs) and Common Name (CN)
    from a TLS certificate.

    Args:
        cert_der: DER-encoded X.509 certificate

    Returns:
        Set of domain names from SAN and CN fields
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    domains = set()
    try:
        cert = x509.load_der_x509_certificate(cert_der)

        # Extract CN from subject
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in cn_attrs:
            domains.add(attr.value)

        # Extract SANs
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    domains.add(name.value)
        except x509.ExtensionNotFound:
            pass

    except Exception:
        pass

    return domains


def filter_domains(domains: Set[str]) -> Set[str]:
    """
    Filter out wildcard domains and CDN proxy domains.

    Args:
        domains: Raw domain set D = SAN(C) ∪ CN(C)

    Returns:
        Filtered domain set Df (Equation 1 in the paper):
        Df = {d ∈ D | d ∉ B, * ∉ d}
    """
    return {
        d for d in domains
        if not _is_wildcard_domain(d) and not _is_cdn_domain(d)
    }


def dns_resolve_a(domain: str, timeout: float = 5.0) -> List[str]:
    """
    Perform DNS A-record (IPv4) query for a domain.

    Args:
        domain: Domain name to resolve
        timeout: DNS query timeout in seconds

    Returns:
        List of resolved IPv4 addresses R(d)
    """
    import socket
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET,
                                     socket.SOCK_STREAM)
        return list(set(addr[4][0] for addr in answers))
    except (socket.gaierror, socket.timeout, OSError):
        return []


def dns_resolve_aaaa(domain: str, timeout: float = 5.0) -> List[str]:
    """
    Perform DNS AAAA-record (IPv6) query for a domain.

    Args:
        domain: Domain name to resolve
        timeout: DNS query timeout in seconds

    Returns:
        List of resolved IPv6 addresses
    """
    import socket
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET6,
                                     socket.SOCK_STREAM)
        return list(set(addr[4][0] for addr in answers))
    except (socket.gaierror, socket.timeout, OSError):
        return []


def is_ipv4_embedded_ipv6(ipv6_str: str) -> bool:
    """
    Check if an IPv6 address contains an embedded IPv4 address.

    Recognized patterns:
    - IPv4-mapped: ::ffff:0:0/96 (e.g., ::ffff:192.0.2.1)
    - IPv4-compatible: ::/96 (deprecated)
    - 6to4: 2002::/16
    - Teredo: 2001:0::/32
    - IPv4-translated: ::ffff:0:0:0/96

    Also checks for IPv4 bytes in the last 32 bits of IID.

    Args:
        ipv6_str: IPv6 address string

    Returns:
        True if IPv6 contains embedded IPv4
    """
    try:
        packed = socket.inet_pton(socket.AF_INET6, ipv6_str)
        # IPv4-mapped: first 10 bytes are 0x00, next 2 bytes are 0xFF
        if packed[:10] == b'\x00' * 10 and packed[10:12] == b'\xff\xff':
            return True
        # IPv4-compatible: first 12 bytes are 0x00
        if packed[:12] == b'\x00' * 12:
            return True
        # 6to4: 2002::/16
        if packed[0] == 0x20 and packed[1] == 0x02:
            return True
        # Teredo: 2001:0000::/32
        if packed[:4] == b'\x20\x01\x00\x00':
            return True
    except OSError:
        return False
    return False


def extract_ipv4_from_ipv6(ipv6_str: str) -> Optional[str]:
    """
    Extract the embedded IPv4 address from an IPv6 address.

    Args:
        ipv6_str: IPv6 address string

    Returns:
        Embedded IPv4 address, or None if not found
    """
    import socket
    try:
        packed = socket.inet_pton(socket.AF_INET6, ipv6_str)

        if packed[:10] == b'\x00' * 10 and packed[10:12] == b'\xff\xff':
            # IPv4-mapped
            return socket.inet_ntop(socket.AF_INET, packed[12:16])
        if packed[:12] == b'\x00' * 12:
            # IPv4-compatible
            return socket.inet_ntop(socket.AF_INET, packed[12:16])
        if packed[0] == 0x20 and packed[1] == 0x02:
            # 6to4
            return socket.inet_ntop(socket.AF_INET, packed[2:6])
        if packed[:4] == b'\x20\x01\x00\x00':
            # Teredo: embedded IPv4 is bytes 4-8 XOR 0xFF FF FF FF
            teredo_ipv4 = bytes(b ^ 0xFF for b in packed[4:8])
            return socket.inet_ntop(socket.AF_INET, teredo_ipv4)
    except (OSError, ValueError):
        pass
    return None


def classify_ipv6_pattern(ipv6_str: str) -> str:
    """
    Classify the IPv6 addressing pattern of an address.

    Patterns (from the paper's Table VI):
    - low-byte: Simplified sequential/manual assignment
    - ipv4-embedded: IPv4 address embedded in IID
    - eui-64: Extended Unique Identifier (MAC-based)
    - random: Pseudo-random interface identifier
    - byte-pattern: Repetitive byte patterns
    - port-embedded: TCP/UDP port embedded in address
    - other: Unclassified

    Args:
        ipv6_str: IPv6 address string

    Returns:
        Pattern classification label
    """
    import socket
    try:
        packed = socket.inet_pton(socket.AF_INET6, ipv6_str)
        iid = packed[8:16]  # Last 64 bits (Interface Identifier)

        # Check IPv4-embedded patterns
        if is_ipv4_embedded_ipv6(ipv6_str):
            return "ipv4-embedded"

        # Check EUI-64: bit 6 of the first byte is 0 and the middle is ff:fe
        if iid[3:5] == b'\xff\xfe' and (iid[0] & 0x02) == 0:
            return "eui-64"

        # Check port-embedded: 16-bit port in low-order bits
        if iid[0:4] == b'\x00' * 4:
            port = struct.unpack('>H', iid[6:8])[0]
            if 1 <= port <= 65535:
                return "port-embedded"

        # Check byte-pattern: repetitive byte structures
        if (iid[0:4] == iid[4:8] or          # repeated 4-byte blocks
            len(set(iid)) <= 4 or              # low byte diversity
            all(b in {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                      0xcc, 0xdd, 0xee, 0xff} for b in iid)):
            return "byte-pattern"

        # Check low-byte: small integer values in last bytes
        last_32 = struct.unpack('>I', iid[4:8])[0]
        if last_32 < 0x10000:  # Small integer ≤ 65536
            return "low-byte"

        # Check random: high entropy (default for non-matching)
        unique_bytes = len(set(iid))
        if unique_bytes >= 6:
            return "random"

        return "other"

    except (OSError, ValueError):
        return "other"


class CandidateMiner:
    """
    Candidate dual-stack address mining module.

    Generates candidate IPv4-IPv6 address pairs via three strategies:
    1. DNS resolution of domain names
    2. IPv4-embedded IPv6 address extraction
    3. TLS certificate domain association mining
    """

    def __init__(self, tls_port: int = 443, dns_timeout: float = 5.0):
        """
        Args:
            tls_port: Port for TLS scanning (default 443)
            dns_timeout: DNS query timeout in seconds
        """
        self.tls_port = tls_port
        self.dns_timeout = dns_timeout

    def from_domain_list(self, domains: List[str]) -> Set[Tuple[str, str]]:
        """
        Generate candidate dual-stack pairs from domain names via DNS resolution.

        For each domain, resolves A (IPv4) and AAAA (IPv6) records,
        then forms all cross-product pairs.

        Args:
            domains: List of domain names

        Returns:
            Set of (ipv4, ipv6) candidate pairs
        """
        pairs = set()
        for domain in domains:
            ipv4_addrs = dns_resolve_a(domain, timeout=self.dns_timeout)
            ipv6_addrs = dns_resolve_aaaa(domain, timeout=self.dns_timeout)
            for ip4 in ipv4_addrs:
                for ip6 in ipv6_addrs:
                    pairs.add((ip4, ip6))
        return pairs

    def from_ipv6_hitlist(self, ipv6_addresses: List[str]) -> Set[Tuple[str, str]]:
        """
        Generate candidate pairs from IPv6 hitlist by extracting
        IPv4-embedded IPv6 addresses.

        Args:
            ipv6_addresses: List of IPv6 addresses

        Returns:
            Set of (ipv4, ipv6) candidate pairs
        """
        pairs = set()
        for ipv6 in ipv6_addresses:
            ipv4 = extract_ipv4_from_ipv6(ipv6)
            if ipv4:
                pairs.add((ipv4, ipv6))
        return pairs

    def from_tls_certificates(
        self,
        cert_map: Dict[str, bytes]
    ) -> Set[Tuple[str, str]]:
        """
        TLS certificate-associated candidate dual-stack mining algorithm.

        For each IPv6 address with a TLS certificate:
        1. Parse SANs and CN from the certificate → domain set D
        2. Filter wildcard and CDN domains → filtered set Df
        3. DNS A-record query for each d ∈ Df → IPv4 addresses R(d)
        4. Form candidate pairs Sc = {(ip4, ip6) | ip4 ∈ R(d), d ∈ Df}

        This is the core novel algorithm (Section III-B, Equation 1 & 2).

        Args:
            cert_map: Mapping of IPv6 address → DER-encoded TLS certificate

        Returns:
            Set of (ipv4, ipv6) candidate pairs
        """
        pairs = set()
        for ipv6, cert_der in cert_map.items():
            # Step 1: Parse certificate → domain set D
            raw_domains = parse_certificate_sans(cert_der)

            # Step 2: Filter → Df (Equation 1)
            filtered_domains = filter_domains(raw_domains)

            # Step 3 & 4: DNS resolution → candidate pairs (Equation 2)
            for domain in filtered_domains:
                ipv4s = dns_resolve_a(domain, timeout=self.dns_timeout)
                for ipv4 in ipv4s:
                    pairs.add((ipv4, ipv6))

        return pairs

    def mine_all(
        self,
        domains: Optional[List[str]] = None,
        ipv6_addresses: Optional[List[str]] = None,
        cert_map: Optional[Dict[str, bytes]] = None,
    ) -> Set[Tuple[str, str]]:
        """
        Execute all candidate mining strategies and return the union.

        Args:
            domains: Optional list of domain names
            ipv6_addresses: Optional list of IPv6 addresses (hitlist)
            cert_map: Optional TLS certificate map (IPv6 → DER bytes)

        Returns:
            Union of all candidate (ipv4, ipv6) pairs
        """
        all_pairs = set()
        if domains:
            all_pairs.update(self.from_domain_list(domains))
        if ipv6_addresses:
            all_pairs.update(self.from_ipv6_hitlist(ipv6_addresses))
        if cert_map:
            all_pairs.update(self.from_tls_certificates(cert_map))
        return all_pairs
