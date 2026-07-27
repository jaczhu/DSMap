"""
Protocol Fingerprint Extraction Module

Extracts device-unique fingerprints from five network protocols:
SSH, TLS, HTTP, FTP, and MySQL.

Fingerprint classification is based on normalized information entropy,
as detailed in Table I of the paper:

    Protocol  | IPv4 entropy ratio | IPv6 entropy ratio | Tier
    ----------|-------------------|-------------------|------
    SSH       | 0.9912            | 0.9758            | Strong
    TLS       | 0.9360            | 0.9343            | Strong
    FTP       | 0.5584            | 0.5391            | Weak (elevated by rules)
    MySQL     | 0.4718            | 0.4145            | Weak
    HTTP      | 0.2826            | 0.7050            | Weak

Reference: DSMap paper, Section III-C-2
"""

import hashlib
import re
import struct
import socket
import ssl
from typing import Dict, Optional, Any
from abc import ABC, abstractmethod


class FingerprintExtractor(ABC):
    """Base class for protocol fingerprint extractors."""

    @abstractmethod
    def extract(self, ip: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Extract fingerprint from a target host.

        Returns:
            Dictionary with 'success' (bool) and protocol-specific fields
        """
        pass

    @abstractmethod
    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        """
        Generate a comparable fingerprint key string.
        Returns None if fingerprint is invalid/incomplete.
        """
        pass


class SSHFingerprintExtractor(FingerprintExtractor):
    """
    SSH fingerprint extraction.

    Extracts:
    - server_id: SSH version identification string
    - kex_algorithms: Key exchange algorithm list
    - server_host_key: Server public key fingerprint (SHA-256)

    Entropy ratio: ~0.98 (Strong)
    """

    SSH_DEFAULT_PORT = 22

    def extract(self, ip: str, port: int = SSH_DEFAULT_PORT,
                timeout: float = 5.0) -> Dict[str, Any]:
        result = {
            "success": False,
            "server_id": None,
            "kex_algorithms": None,
            "server_host_key": None,
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Read server identification string (SSH banner)
            sock.settimeout(timeout)
            data = b""
            while b"\n" not in data and len(data) < 8192:
                try:
                    chunk = sock.recv(1)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            server_id = data.decode("ascii", errors="ignore").strip()
            if server_id.startswith("SSH-"):
                result["server_id"] = server_id
                result["success"] = True
            else:
                return result

            # kex_algorithms and host key require deep SSH handshake
            # In practice, this requires paramiko or similar SSH library.
            # Here we note these require full SSH key extraction.
            # For production use, integrate with paramiko to complete the handshake
            # and extract kex_algorithms + server_host_key.

            # Placeholder for full SSH protocol handshake integration point
            result["kex_algorithms"] = None
            result["server_host_key"] = None

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return result

    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        if not fp.get("success") or not fp.get("server_id"):
            return None
        parts = [
            fp.get("server_id", ""),
            fp.get("kex_algorithms") or "",
            fp.get("server_host_key") or "",
        ]
        combined = "|".join(parts)
        return hashlib.sha256(combined.encode()).hexdigest()


class TLSFingerprintExtractor(FingerprintExtractor):
    """
    TLS certificate fingerprint extraction.

    Extracts:
    - spki_subject_fingerprint: SHA-256 hash of the certificate's
      SubjectPublicKeyInfo (SPKI) field

    Entropy ratio: ~0.93 (Strong)

    This is the core strong fingerprint used for early-termination
    in the hierarchical verification pipeline.
    """

    TLS_DEFAULT_PORT = 443

    def extract(self, ip: str, port: int = TLS_DEFAULT_PORT,
                timeout: float = 5.0) -> Dict[str, Any]:
        result = {
            "success": False,
            "spki_subject_fingerprint": None,
            "cert_der": None,
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if cert_der:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(cert_der)
                    spki_bytes = cert.subject_public_key_info.public_bytes(
                        encoding=x509.Encoding.DER,
                        format=x509.PublicFormat.SubjectPublicKeyInfo
                    )
                    spki_hash = hashlib.sha256(spki_bytes).hexdigest()
                    result["spki_subject_fingerprint"] = spki_hash
                    result["cert_der"] = cert_der
                    result["success"] = True

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return result

    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        if not fp.get("success"):
            return None
        return fp.get("spki_subject_fingerprint")


class HTTPFingerprintExtractor(FingerprintExtractor):
    """
    HTTP fingerprint extraction.

    Extracts:
    - etag: Entity tag header
    - last_modified: Last-Modified header
    - body_sha256: SHA-256 hash of response body

    Entropy ratio: ~0.28 (IPv4) / ~0.70 (IPv6) — Weak
    """

    HTTP_DEFAULT_PORT = 80

    def extract(self, ip: str, port: int = HTTP_DEFAULT_PORT,
                timeout: float = 5.0) -> Dict[str, Any]:
        result = {
            "success": False,
            "etag": None,
            "last_modified": None,
            "body_sha256": None,
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: [{ip}]\r\n"
                f"User-Agent: DSMap/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.sendall(request.encode())

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 1024 * 1024:  # 1MB cap
                        break
                except socket.timeout:
                    break

            if response:
                parts = response.split(b"\r\n\r\n", 1)
                headers_raw = parts[0].decode("ascii", errors="ignore")
                body = parts[1] if len(parts) > 1 else b""

                # Parse headers
                for line in headers_raw.split("\r\n"):
                    line_lower = line.lower()
                    if line_lower.startswith("etag:"):
                        result["etag"] = line.split(":", 1)[1].strip()
                    elif line_lower.startswith("last-modified:"):
                        result["last_modified"] = line.split(":", 1)[1].strip()

                result["body_sha256"] = hashlib.sha256(body).hexdigest()
                result["success"] = True

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return result

    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        if not fp.get("success"):
            return None
        parts = [
            fp.get("etag") or "",
            fp.get("last_modified") or "",
            fp.get("body_sha256") or "",
        ]
        combined = "|".join(parts)
        return hashlib.sha256(combined.encode()).hexdigest()


class FTPFingerprintExtractor(FingerprintExtractor):
    """
    FTP fingerprint extraction.

    Extracts:
    - banner: FTP server welcome banner

    Entropy ratio: ~0.55 (Weak)
    Special rule: banners containing IP addresses or hostnames
    are elevated to strong fingerprints (Section III-C-2).

    Strong FTP banner conditions:
    (i) Banners that directly embed the target's cross-protocol IP address
    (ii) Banners containing highly specific local hostnames or software
         release versions
    """

    FTP_DEFAULT_PORT = 21

    def extract(self, ip: str, port: int = FTP_DEFAULT_PORT,
                timeout: float = 5.0) -> Dict[str, Any]:
        result = {
            "success": False,
            "banner": None,
            "is_strong": False,
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            data = b""
            while b"\n" not in data and len(data) < 4096:
                try:
                    chunk = sock.recv(1)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            banner = data.decode("ascii", errors="ignore").strip()
            if banner:
                result["banner"] = banner
                result["success"] = True

                # Check strong FTP rules
                result["is_strong"] = self._check_strong_rules(banner, ip)

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return result

    def _check_strong_rules(self, banner: str, ip: str) -> bool:
        """
        Check if FTP banner qualifies as strong fingerprint.

        Rules (Section III-C-2):
        (i) Banner embeds the target's cross-protocol IP address
        (ii) Banner contains highly specific local hostname or version
        """
        # Rule (i): banner contains the target IP
        if ip in banner:
            return True

        # Rule (ii): highly specific hostname or version patterns
        # e.g., "220 ftp-server-01.example.com FTP server ready"
        hostname_pattern = re.search(
            r'[\w-]+\.[\w.-]+\.\w{2,}', banner
        )
        if hostname_pattern:
            return True

        return False

    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        if not fp.get("success"):
            return None
        return hashlib.sha256(fp["banner"].encode()).hexdigest()


class MySQLFingerprintExtractor(FingerprintExtractor):
    """
    MySQL fingerprint extraction.

    Extracts:
    - server_version: Database server version string

    Entropy ratio: ~0.45 (Weak)
    """

    MYSQL_DEFAULT_PORT = 3306

    def extract(self, ip: str, port: int = MYSQL_DEFAULT_PORT,
                timeout: float = 5.0) -> Dict[str, Any]:
        result = {
            "success": False,
            "server_version": None,
        }
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # MySQL server sends an Initial Handshake Packet on connect
            data = sock.recv(1024)
            if len(data) >= 5:
                # Parse MySQL protocol handshake (version 10)
                # Packet format: [length:3][sequence:1][payload]
                payload_length = data[0] | (data[1] << 8) | (data[2] << 16)
                if len(data) >= 5 + payload_length:
                    payload = data[4:4 + payload_length]
                else:
                    payload = data[4:]

                # Check it's a valid MySQL handshake (protocol version 10)
                if len(payload) > 0 and payload[0] == 0x0a:
                    # Server version is a null-terminated string at offset 1
                    null_pos = payload.find(b'\x00', 1)
                    if null_pos > 1:
                        version = payload[1:null_pos].decode(
                            "ascii", errors="ignore"
                        )
                        result["server_version"] = version
                        result["success"] = True

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        return result

    def get_fingerprint_key(self, fp: Dict[str, Any]) -> Optional[str]:
        if not fp.get("success"):
            return None
        return fp.get("server_version")


# Canonical fingerprint type definitions matching the paper
STRONG_FINGERPRINTS = {"ssh", "tls"}
WEAK_FINGERPRINTS = {"http", "ftp", "mysql"}

# Extractors keyed by protocol name
EXTRACTORS: Dict[str, FingerprintExtractor] = {
    "ssh": SSHFingerprintExtractor(),
    "tls": TLSFingerprintExtractor(),
    "http": HTTPFingerprintExtractor(),
    "ftp": FTPFingerprintExtractor(),
    "mysql": MySQLFingerprintExtractor(),
}

# Default ports for each protocol
DEFAULT_PORTS = {
    "ssh": 22,
    "tls": 443,
    "http": 80,
    "ftp": 21,
    "mysql": 3306,
}


def compute_entropy_ratio(fingerprints: list, total_addresses: int) -> float:
    """
    Compute the normalized Shannon entropy ratio RH(F) for a fingerprint.

    RH(F) = H(F) / log2(MF)

    where:
    - H(F) = -Σ P(vj) * log2(P(vj))
    - MF is the total number of responsive IP addresses

    Args:
        fingerprints: List of fingerprint values across all addresses
        total_addresses: Total number of responsive IPs (MF)

    Returns:
        Normalized entropy ratio in [0, 1]

    Reference: Equation 4 and 5 in the paper.
    """
    from collections import Counter
    from math import log2

    if not fingerprints or total_addresses <= 1:
        return 0.0

    counter = Counter(fingerprints)
    total = len(fingerprints)

    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * log2(p)

    max_entropy = log2(min(total_addresses, len(counter)))
    if max_entropy == 0:
        return 0.0

    return entropy / max_entropy
