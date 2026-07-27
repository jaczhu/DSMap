"""
Dual-Stack Host Address Aggregation Module

Models verified address pairs as an undirected graph and uses
Union-Find (Disjoint-Set Union) to identify distinct physical hosts.

Reference: DSMap paper, Section III-D, Equation 8 & 9
"""

from typing import Set, Tuple, Dict, List


class DisjointSetUnion:
    """
    Disjoint-Set Union (Union-Find) with path compression
    and union-by-rank.
    """

    def __init__(self):
        self.parent: Dict[str, str] = {}
        self.rank: Dict[str, int] = {}

    def make_set(self, x: str):
        """Initialize a singleton set for element x."""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: str) -> str:
        """Find the representative of x's set (with path compression)."""
        if x not in self.parent:
            self.make_set(x)
            return x
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: str, y: str):
        """Union the sets containing x and y (with union-by-rank)."""
        rx = self.find(x)
        ry = self.find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            self.parent[rx] = ry
        elif self.rank[rx] > self.rank[ry]:
            self.parent[ry] = rx
        else:
            self.parent[ry] = rx
            self.rank[rx] += 1


class HostAggregator:
    """
    Dual-stack host address aggregation via graph clustering.

    Constructs an undirected graph G = (V, E) where:
    - V = Vv4 ∪ Vv6 (all validated IPv4 and IPv6 addresses)
    - E = DS (verified dual-stack links)

    Uses Union-Find to identify connected components, with a
    cluster size threshold γ to filter out public gateway anomalies.

    Reference: Equation 8 & 9, Section III-D
    """

    def __init__(self, max_cluster_size: int = 10):
        """
        Args:
            max_cluster_size: Maximum allowed cluster size γ.
                Clusters larger than this are flagged as public
                gateway anomalies and excluded from host analysis.
                (Default 10, as per the paper)
        """
        self.max_cluster_size = max_cluster_size

    def aggregate(
        self, verified_pairs: Set[Tuple[str, str]]
    ) -> List[Set[str]]:
        """
        Aggregate verified dual-stack pairs into host clusters.

        Steps:
        1. Build graph G = (V, E) from verified pairs
        2. Compute connected components using Union-Find
        3. Filter out components with size > max_cluster_size
           (public gateway / NAT / proxy anomalies)
        4. Return valid host clusters

        Each cluster Ci = {v ∈ V | ∃ path between v and u, ∀u ∈ Ci}
        satisfies:
        - Ci ∩ Cj = ∅ (∀i ≠ j)
        - ∪Ci = V (after anomaly removal)

        Args:
            verified_pairs: Set of verified (ipv4, ipv6) pairs

        Returns:
            List of host clusters, each cluster is a set of IP addresses
        """
        if not verified_pairs:
            return []

        dsu = DisjointSetUnion()

        # Build graph from verified pairs (edges)
        for ip4, ip6 in verified_pairs:
            dsu.make_set(f"v4:{ip4}")
            dsu.make_set(f"v6:{ip6}")
            dsu.union(f"v4:{ip4}", f"v6:{ip6}")

        # Collect components
        components: Dict[str, Set[str]] = {}
        for ip4, ip6 in verified_pairs:
            root4 = dsu.find(f"v4:{ip4}")
            root6 = dsu.find(f"v6:{ip6}")
            # Both should have the same root since they were unioned
            root = root4
            if root not in components:
                components[root] = set()
            components[root].add(ip4)
            components[root].add(ip6)

        # Filter out anomaly clusters (size > γ)
        host_clusters = []
        for root, ips in components.items():
            if len(ips) <= self.max_cluster_size:
                host_clusters.append(ips)

        return host_clusters

    def get_cluster_stats(
        self, clusters: List[Set[str]]
    ) -> Dict[str, any]:
        """
        Compute statistics on the discovered host clusters.

        Args:
            clusters: List of host clusters

        Returns:
            Dictionary with cluster statistics
        """
        if not clusters:
            return {
                "total_hosts": 0,
                "total_ipv4": 0,
                "total_ipv6": 0,
                "avg_cluster_size": 0.0,
                "max_cluster_size": 0,
                "min_cluster_size": 0,
            }

        sizes = [len(c) for c in clusters]
        total_ipv4 = sum(
            1 for c in clusters
            for ip in c if ":" not in ip
        )
        total_ipv6 = sum(
            1 for c in clusters
            for ip in c if ":" in ip
        )

        return {
            "total_hosts": len(clusters),
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "avg_cluster_size": sum(sizes) / len(sizes),
            "max_cluster_size": max(sizes),
            "min_cluster_size": min(sizes),
        }
