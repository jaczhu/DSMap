#!/usr/bin/env python3
"""
DSMap: Uncovering the Dual-Stack Internet via
TLS-Assisted Hierarchical Fingerprinting

Command-line entry point.

Usage:
    # From domain names
    python main.py --domains domains.txt --output results.json

    # From IPv6 hitlist
    python main.py --ipv6-hitlist hitlist.txt --output results.json

    # From IPv6 hitlist with TLS certificate mining
    python main.py --ipv6-hitlist hitlist.txt --tls-scan --output results.json

    # With AS/Geo filtering
    python main.py --domains domains.txt \
        --asn-db GeoLite2-ASN.mmdb \
        --geo-db GeoLite2-City.mmdb \
        --output results.json

Reference: DSMap paper, Section III
"""

import argparse
import logging
import sys
from pathlib import Path

from dsmap.dsmap import DSMap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dsmap")


def read_lines(filepath: str) -> list:
    """Read newline-separated items from a file."""
    lines = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="DSMap: Dual-Stack Host Discovery Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --domains top1m.txt -o results.json
  python main.py --ipv6-hitlist ipv6.txt --tls-scan -o results.json
  python main.py --domains domains.txt --asn-db GeoLite2-ASN.mmdb -o results.json
        """,
    )

    # Input sources
    input_group = parser.add_argument_group("Input Sources")
    input_group.add_argument(
        "--domains", type=str,
        help="File containing domain names (one per line)"
    )
    input_group.add_argument(
        "--ipv6-hitlist", type=str,
        help="File containing IPv6 addresses (one per line)"
    )

    # TLS certificate mining
    tls_group = parser.add_argument_group("TLS Certificate Mining")
    tls_group.add_argument(
        "--tls-scan", action="store_true",
        help="Run TLS scanning on IPv6 hitlist to mine certificates"
    )
    tls_group.add_argument(
        "--tls-port", type=int, default=443,
        help="TLS scanning port (default: 443)"
    )
    tls_group.add_argument(
        "--tls-workers", type=int, default=100,
        help="Concurrent TLS scan workers (default: 100)"
    )

    # AS/Geo filtering
    filter_group = parser.add_argument_group("AS/Geo Filtering")
    filter_group.add_argument(
        "--asn-db", type=str,
        help="Path to MaxMind GeoLite2-ASN .mmdb database"
    )
    filter_group.add_argument(
        "--geo-db", type=str,
        help="Path to MaxMind GeoLite2-City .mmdb database"
    )

    # Scanning parameters
    scan_group = parser.add_argument_group("Scanning Parameters")
    scan_group.add_argument(
        "--max-rate", type=int, default=10000,
        help="Max packets per second (default: 10000)"
    )
    scan_group.add_argument(
        "--timeout", type=float, default=5.0,
        help="Per-service scan timeout in seconds (default: 5.0)"
    )
    scan_group.add_argument(
        "--max-cluster-size", type=int, default=10,
        help="Max host cluster size γ (default: 10)"
    )

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output", type=str, default="dsmap_results.json",
        help="Output JSON file path (default: dsmap_results.json)"
    )
    output_group.add_argument(
        "--ptr-check", action="store_true",
        help="Compute PTR consistency metric on verified pairs"
    )

    args = parser.parse_args()

    if not args.domains and not args.ipv6_hitlist:
        parser.error("At least one of --domains or --ipv6-hitlist is required")

    # Initialize DSMap
    dsmap = DSMap(
        asn_db=args.asn_db,
        geo_db=args.geo_db,
        max_rate=args.max_rate,
        scan_timeout=args.timeout,
        max_cluster_size=args.max_cluster_size,
    )

    # Load inputs
    if args.domains:
        domains = read_lines(args.domains)
        logger.info(f"Loaded {len(domains)} domain names from {args.domains}")
        dsmap.add_domains(domains)

    if args.ipv6_hitlist:
        ipv6_addrs = read_lines(args.ipv6_hitlist)
        logger.info(f"Loaded {len(ipv6_addrs)} IPv6 addresses from {args.ipv6_hitlist}")
        dsmap.add_ipv6_hitlist(ipv6_addrs)

    # TLS certificate mining (if enabled)
    if args.tls_scan and args.ipv6_hitlist:
        logger.info(
            f"Running TLS certificate scan on {len(ipv6_addrs)} "
            f"IPv6 addresses (port {args.tls_port})..."
        )
        cert_map = dsmap.run_certificate_scan(
            ipv6_addrs,
            port=args.tls_port,
            max_workers=args.tls_workers,
        )
        logger.info(
            f"Collected {len(cert_map)} certificates "
            f"from {len(ipv6_addrs)} addresses"
        )

    # Run DSMap pipeline
    logger.info("Starting DSMap pipeline...")
    results = dsmap.run()

    # PTR consistency check
    if args.ptr_check and results["verified_pairs"]:
        logger.info("Computing PTR consistency metric...")
        ptr_stats = dsmap.compute_ptr_consistency(results["verified_pairs"])
        results["ptr_stats"] = ptr_stats
        logger.info(
            f"  PTR coverage: {ptr_stats['ptr_coverage']:.2%}, "
            f"consistency (PPTR): {ptr_stats['pptr']:.2%}"
        )

    # Save results
    dsmap.save_results(results, args.output)

    # Print summary
    stats = results["stats"]
    print("\n" + "=" * 60)
    print("DSMap Pipeline Summary")
    print("=" * 60)
    print(f"  Candidate pairs:    {stats['candidate_pairs']:>10,}")
    print(f"  Verified pairs:      {stats['verified_pairs']:>10,}")
    print(f"  Discovered hosts:    {stats['total_hosts']:>10,}")
    print(f"    - IPv4 addresses:  {stats['total_ipv4']:>10,}")
    print(f"    - IPv6 addresses:  {stats['total_ipv6']:>10,}")
    print(f"  Elapsed time:        {stats['elapsed_seconds']:>10.1f}s")
    print(f"  Discovery rate:      {stats['discovery_rate']:>10.2f} hosts/s")
    print(f"  Results saved to:    {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
