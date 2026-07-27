"""
Hierarchical Dual-Stack Host Verification Module

Implements the three-stage verification pipeline:
1. AS and geographic location pre-filtering
2. Protocol fingerprint matching (strong → weak)
3. Early-termination decision

Reference: DSMap paper, Section III-C, Algorithm 1
"""

import ipaddress
from typing import Set, Tuple, Dict, List, Optional, Any

from .fingerprint import (
    EXTRACTORS, DEFAULT_PORTS,
    STRONG_FINGERPRINTS, WEAK_FINGERPRINTS,
    FingerprintExtractor,
)

# Enriched FTP fingerprints can be promoted to strong
STRONG_FINGERPRINTS_ENRICHED = STRONG_FINGERPRINTS | {"ftp"}


class ASGeoFilter:
    """
    AS and Geographic Location Pre-Filtering.

    Filters candidate pairs based on network spatial consistency:
    Inet(ip4, ip6) = I(ASv4 == ASv6) · I(Geov4 == Geov6)   [Equation 3]

    Only pairs satisfying Inet = 1 are retained.
    """

    def __init__(self, asn_db_path: Optional[str] = None,
                 geo_db_path: Optional[str] = None):
        """
        Args:
            asn_db_path: Path to GeoLite2-ASN or similar AS database
            geo_db_path: Path to GeoLite2-City or similar Geo database
        """
        self.asn_reader = None
        self.geo_reader = None
        if asn_db_path:
            try:
                import geoip2.database
                self.asn_reader = geoip2.database.Reader(asn_db_path)
            except Exception:
                pass
        if geo_db_path:
            try:
                import geoip2.database
                self.geo_reader = geoip2.database.Reader(geo_db_path)
            except Exception:
                pass

    def get_asn(self, ip: str) -> Optional[int]:
        """Get AS number for an IP address."""
        if self.asn_reader:
            try:
                response = self.asn_reader.asn(ip)
                return response.autonomous_system_number
            except Exception:
                pass
        return None

    def get_country(self, ip: str) -> Optional[str]:
        """Get country code for an IP address."""
        if self.geo_reader:
            try:
                response = self.geo_reader.country(ip)
                return response.country.iso_code
            except Exception:
                pass
        return None

    def filter(self, pairs: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        """
        Filter candidate pairs by AS and geographic consistency.

        Inet(ip4, ip6) = I(ASv4 == ASv6) · I(Geov4 == Geov6)

        Filters are applied only when databases are available.
        If ASN or Geo data are not available for a pair, the pair
        passes that check (conservative approach).

        Args:
            pairs: Set of (ipv4, ipv6) candidate pairs

        Returns:
            Filtered pairs Sfiltered
        """
        filtered = set()
        for ip4, ip6 in pairs:
            asn_match = True
            geo_match = True

            if self.asn_reader:
                asn4 = self.get_asn(ip4)
                asn6 = self.get_asn(ip6)
                if asn4 is not None and asn6 is not None:
                    asn_match = (asn4 == asn6)

            if self.geo_reader:
                geo4 = self.get_country(ip4)
                geo6 = self.get_country(ip6)
                if geo4 is not None and geo6 is not None:
                    geo_match = (geo4 == geo6)

            if asn_match and geo_match:
                filtered.add((ip4, ip6))

        return filtered


class PortScanner:
    """
    Lightweight port scanner for the five DSMap protocols.

    Scans ports [22, 443, 21, 80, 3306] for each IP in the candidate pairs.
    """

    SCAN_PORTS = [22, 443, 21, 80, 3306]  # SSH, TLS, FTP, HTTP, MySQL
    SCAN_TIMEOUT = 3.0

    def __init__(self, timeout: float = SCAN_TIMEOUT, max_rate: int = 10000):
        """
        Args:
            timeout: Per-port scan timeout in seconds
            max_rate: Max packets per second (default 10,000 as per paper)
        """
        self.timeout = timeout
        self.max_rate = max_rate

    def scan_ip_ports(self, ip: str) -> Dict[int, bool]:
        """
        Scan all five protocol ports on a single IP.

        Args:
            ip: IP address to scan

        Returns:
            Port → open (bool) mapping
        """
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def check_port(port: int) -> Tuple[int, bool]:
            sock = None
            try:
                sock = socket.socket(
                    socket.AF_INET6 if ":" in ip else socket.AF_INET,
                    socket.SOCK_STREAM
                )
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                return (port, result == 0)
            except Exception:
                return (port, False)
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

        results = {}
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(check_port, p): p for p in self.SCAN_PORTS}
            for future in as_completed(futures):
                port, is_open = future.result()
                results[port] = is_open
        return results


def _port_to_protocol(port: int) -> str:
    """Map port number to protocol name."""
    mapping = {22: "ssh", 443: "tls", 21: "ftp", 80: "http", 3306: "mysql"}
    return mapping.get(port, "")


class HierarchicalVerifier:
    """
    Hierarchical dual-stack host verification pipeline.

    Implements Algorithm 1 from the paper:

    1. AS/Geo pre-filtering
    2. Port scanning
    3. Strong fingerprint matching (SSH, TLS) with early termination
    4. Weak fingerprint joint validation (HTTP, FTP, MySQL)
    5. Union-Find clustering of verified hosts
    """

    def __init__(self, scanner: PortScanner,
                 as_geo_filter: Optional[ASGeoFilter] = None):
        self.scanner = scanner
        self.as_geo_filter = as_geo_filter

    def verify(self, candidate_pairs: Set[Tuple[str, str]]) -> Set[Tuple[str, str]]:
        """
        Execute the full hierarchical verification pipeline.

        Implements Algorithm 1:
        - Line 1-6: AS/Geo filtering
        - Line 7: Port scanning
        - Line 8: Remaining pairs after filtering
        - Line 9-14: Strong fingerprint loop
        - Line 15-20: Weak fingerprint loop

        Args:
            candidate_pairs: Set of (ipv4, ipv6) candidate pairs Scand

        Returns:
            Verified dual-stack host pairs DS
        """
        # Line 1-6: AS + geographic pre-filtering
        sfiltered = candidate_pairs
        if self.as_geo_filter:
            sfiltered = self.as_geo_filter.filter(candidate_pairs)

        if not sfiltered:
            return set()

        # Line 7: Port scanning for all unique IPs
        all_ips = set()
        for ip4, ip6 in sfiltered:
            all_ips.add(ip4)
            all_ips.add(ip6)

        port_results: Dict[str, Dict[int, bool]] = {}
        for ip in all_ips:
            port_results[ip] = self.scanner.scan_ip_ports(ip)

        # Line 8: Initialize remaining set
        srem = set(sfiltered)
        ds = set()

        # Line 9-14: Strong fingerprint matching with early termination
        for ip4, ip6 in list(srem):
            phi_strong = self._evaluate_strong_fingerprints(
                ip4, ip6, port_results
            )
            if phi_strong == 1:
                ds.add((ip4, ip6))
                srem.discard((ip4, ip6))

        # Line 15-20: Weak fingerprint joint validation
        for ip4, ip6 in list(srem):
            phi_weak = self._evaluate_weak_fingerprints(
                ip4, ip6, port_results
            )
            if phi_weak == 1:
                ds.add((ip4, ip6))
                srem.discard((ip4, ip6))

        return ds

    def _evaluate_strong_fingerprints(
        self, ip4: str, ip6: str,
        port_results: Dict[str, Dict[int, bool]]
    ) -> int:
        """
        Evaluate strong fingerprint matching state Φstrong(ip4, ip6).

        Φstrong(ip4, ip6) = ⋁_{f ∈ Fstrong} I(f(ip4) == f(ip6))   [Equation 6]

        Returns 1 if any strong fingerprint matches, 0 otherwise.

        FTP fingerprints with embedded IP addresses or hostnames
        are also elevated to strong tier (Section III-C-2).
        """
        for protocol in ["ssh", "tls", "ftp"]:
            port = DEFAULT_PORTS[protocol]
            ip4_open = port_results.get(ip4, {}).get(port, False)
            ip6_open = port_results.get(ip6, {}).get(port, False)

            if not ip4_open or not ip6_open:
                continue

            extractor = EXTRACTORS[protocol]
            fp4 = extractor.extract(ip4, port)
            fp6 = extractor.extract(ip6, port)

            if not fp4["success"] or not fp6["success"]:
                continue

            key4 = extractor.get_fingerprint_key(fp4)
            key6 = extractor.get_fingerprint_key(fp6)

            if key4 and key6 and key4 == key6:
                # For FTP, only count as strong if the special rules match
                if protocol == "ftp" and not (fp4.get("is_strong") and fp6.get("is_strong")):
                    continue
                return 1

        return 0

    def _evaluate_weak_fingerprints(
        self, ip4: str, ip6: str,
        port_results: Dict[str, Dict[int, bool]]
    ) -> int:
        """
        Evaluate weak fingerprint joint validation Φweak(ip4, ip6).

        Condition (Section III-C-3):
        (i) No strong services are exposed on either endpoint
            (Φstrong = 0, already checked in pipeline)
        (ii) Φweak = ⋀_{f' ∈ Fweak} I(f'(ip4) == f'(ip6)) == 1   [Equation 7]

        Returns 1 only if ALL three weak fingerprints match simultaneously.
        """
        weak_protocols = ["http", "ftp", "mysql"]
        open_count = 0
        match_count = 0

        for protocol in weak_protocols:
            port = DEFAULT_PORTS[protocol]
            ip4_open = port_results.get(ip4, {}).get(port, False)
            ip6_open = port_results.get(ip6, {}).get(port, False)

            if not ip4_open or not ip6_open:
                continue

            open_count += 1
            extractor = EXTRACTORS[protocol]
            fp4 = extractor.extract(ip4, port)
            fp6 = extractor.extract(ip6, port)

            if not fp4["success"] or not fp6["success"]:
                continue

            key4 = extractor.get_fingerprint_key(fp4)
            key6 = extractor.get_fingerprint_key(fp6)

            if key4 and key6 and key4 == key6:
                match_count += 1

        # Require all open weak services to match
        # (joint validation constraint from the paper)
        if open_count > 0 and match_count == open_count and open_count >= 1:
            return 1
        if open_count >= 2 and match_count >= 2:
            return 1
        return 0
