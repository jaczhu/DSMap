"""
DSMap: Dual-Stack Host Discovery Framework

Main orchestrator that coordinates the two-phase pipeline:
1. Candidate Dual-Stack Address Mining
2. Hierarchical Dual-Stack Host Verification

Reference: DSMap paper (RAID 2025), Fig. 1, Section III
"""

import json
import time
import logging
from typing import Set, Tuple, List, Dict, Optional

from .candidate_miner import CandidateMiner
from .fingerprint import STRONG_FINGERPRINTS, WEAK_FINGERPRINTS
from .verifier import PortScanner, ASGeoFilter, HierarchicalVerifier
from .aggregator import HostAggregator

logger = logging.getLogger(__name__)


class DSMap:
    """
    DSMap: Uncovering the Dual-Stack Internet via
    TLS-Assisted Hierarchical Fingerprinting.

    Usage:
        dsmap = DSMap(asn_db="GeoLite2-ASN.mmdb", geo_db="GeoLite2-City.mmdb")
        dsmap.add_domains(["example.com", "test.org"])
        dsmap.add_ipv6_hitlist(["2001:db8::1", "::ffff:192.0.2.1"])
        dsmap.add_tls_certs(ipv6_cert_map)
        results = dsmap.run()
        dsmap.save_results(results, "output.json")
    """

    def __init__(
        self,
        asn_db: Optional[str] = None,
        geo_db: Optional[str] = None,
        max_rate: int = 10000,
        scan_timeout: float = 5.0,
        max_cluster_size: int = 10,
    ):
        """
        Args:
            asn_db: Path to GeoLite2-ASN MaxMind database
            geo_db: Path to GeoLite2-City MaxMind database
            max_rate: Max scanning packets per second (default 10,000)
            scan_timeout: Per-service scan timeout in seconds
            max_cluster_size: Max cluster size γ for host aggregation
        """
        self.candidate_miner = CandidateMiner()
        self.scanner = PortScanner(timeout=scan_timeout, max_rate=max_rate)
        self.as_geo_filter = ASGeoFilter(asn_db_path=asn_db, geo_db_path=geo_db)
        self.verifier = HierarchicalVerifier(self.scanner, self.as_geo_filter)
        self.aggregator = HostAggregator(max_cluster_size=max_cluster_size)

        # Input data accumulators
        self._domains: List[str] = []
        self._ipv6_addresses: List[str] = []
        self._cert_map: Dict[str, bytes] = {}

        # Statistics
        self.stats: Dict[str, any] = {}

    def add_domains(self, domains: List[str]):
        """Add domain names for DNS-based candidate generation."""
        self._domains.extend(domains)

    def add_ipv6_hitlist(self, ipv6_addresses: List[str]):
        """Add IPv6 addresses from a hitlist."""
        self._ipv6_addresses.extend(ipv6_addresses)

    def add_tls_certs(self, cert_map: Dict[str, bytes]):
        """Add TLS certificates obtained from IPv6 scanning.
        Args:
            cert_map: Mapping of IPv6 address → DER-encoded certificate bytes
        """
        self._cert_map.update(cert_map)

    def run_certificate_scan(
        self, ipv6_addresses: List[str], port: int = 443,
        max_workers: int = 100
    ) -> Dict[str, bytes]:
        """
        Scan IPv6 addresses on TLS port to collect certificates.

        This is the first step of the TLS certificate-associated mining
        algorithm (Section III-B).

        Args:
            ipv6_addresses: IPv6 addresses to scan
            port: TLS port (default 443)
            max_workers: Max concurrent scanning threads

        Returns:
            IPv6 → DER certificate bytes mapping
        """
        import ssl
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        cert_map = {}

        def scan_one(ip6: str) -> Tuple[str, Optional[bytes]]:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                sock.connect((ip6, port))
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    return (ip6, cert_der)
            except Exception:
                return (ip6, None)
            finally:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_one, ip6): ip6
                      for ip6 in ipv6_addresses}
            for future in as_completed(futures):
                ip6, cert_der = future.result()
                if cert_der:
                    cert_map[ip6] = cert_der

        self._cert_map.update(cert_map)
        return cert_map

    def run(self) -> Dict[str, any]:
        """
        Execute the full DSMap pipeline:

        Phase 1: Candidate dual-stack address mining
        Phase 2: Hierarchical dual-stack host verification
        Phase 3: Host address aggregation

        Returns:
            Results dictionary with:
            - candidate_pairs: List of (ipv4, ipv6) candidate pairs
            - verified_pairs: List of verified dual-stack pairs
            - host_clusters: List of host clusters (each a set of IPs)
            - stats: Aggregation statistics
            - elapsed_time: Pipeline duration in seconds
        """
        t_start = time.time()

        # ========== Phase 1: Candidate Mining ==========
        logger.info("Phase 1: Mining candidate dual-stack address pairs...")
        t1 = time.time()

        candidate_pairs = self.candidate_miner.mine_all(
            domains=self._domains if self._domains else None,
            ipv6_addresses=self._ipv6_addresses if self._ipv6_addresses else None,
            cert_map=self._cert_map if self._cert_map else None,
        )

        t1_end = time.time()
        logger.info(f"  Found {len(candidate_pairs)} candidate pairs "
                    f"({t1_end - t1:.1f}s)")

        # ========== Phase 2: Hierarchical Verification ==========
        logger.info("Phase 2: Hierarchical dual-stack host verification...")
        t2 = time.time()

        verified_pairs = self.verifier.verify(candidate_pairs)

        t2_end = time.time()
        logger.info(f"  Verified {len(verified_pairs)} dual-stack pairs "
                    f"({t2_end - t2:.1f}s)")

        # ========== Phase 3: Host Aggregation ==========
        logger.info("Phase 3: Aggregating dual-stack host clusters...")
        t3 = time.time()

        host_clusters = self.aggregator.aggregate(verified_pairs)
        cluster_stats = self.aggregator.get_cluster_stats(host_clusters)

        t_end = time.time()

        logger.info(f"  Aggregated into {cluster_stats['total_hosts']} hosts "
                    f"({t_end - t3:.1f}s)")

        # Compile results
        t_total = t_end - t_start
        discovery_rate = (
            cluster_stats["total_hosts"] / t_total
            if t_total > 0 else 0
        )

        self.stats = {
            "candidate_pairs": len(candidate_pairs),
            "verified_pairs": len(verified_pairs),
            **cluster_stats,
            "discovery_rate": discovery_rate,  # vdisc (Equation 11)
            "elapsed_seconds": t_total,
        }

        return {
            "candidate_pairs": [
                {"ipv4": p[0], "ipv6": p[1]}
                for p in sorted(candidate_pairs)
            ],
            "verified_pairs": [
                {"ipv4": p[0], "ipv6": p[1]}
                for p in sorted(verified_pairs)
            ],
            "host_clusters": [
                sorted(list(c)) for c in host_clusters
            ],
            "stats": self.stats,
        }

    def save_results(self, results: Dict[str, any], filepath: str):
        """Save results to a JSON file."""
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2, sort_keys=True)
        logger.info(f"Results saved to {filepath}")

    def compute_ptr_consistency(
        self, verified_pairs: List[Dict[str, str]]
    ) -> Dict[str, any]:
        """
        Compute PTR-based precision metric (Equation 10).

        PPTR = |{(ip4,ip6) ∈ Sptr | PTR(ip4) == PTR(ip6)}| / |Sptr|

        where Sptr is the subset of DS where both addresses
        have valid PTR records.

        Args:
            verified_pairs: List of verified dual-stack pairs

        Returns:
            PTR consistency statistics
        """
        import socket

        sptr_pairs = []
        consistent = 0

        for pair in verified_pairs:
            ip4, ip6 = pair["ipv4"], pair["ipv6"]
            try:
                ptr4 = socket.gethostbyaddr(ip4)[0]
                ptr6 = socket.gethostbyaddr(ip6)[0]
                sptr_pairs.append((ip4, ip6))
                if ptr4 == ptr6:
                    consistent += 1
            except (socket.herror, socket.gaierror, OSError):
                pass

        pptr = consistent / len(sptr_pairs) if sptr_pairs else 0.0
        coverage = len(sptr_pairs) / len(verified_pairs) if verified_pairs else 0.0

        return {
            "ptr_coverage": round(coverage, 4),
            "ptr_consistent_pairs": consistent,
            "ptr_total_pairs": len(sptr_pairs),
            "pptr": round(pptr, 4),  # PPTR (Equation 10)
        }
