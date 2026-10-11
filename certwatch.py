#!/usr/bin/env python3
"""Remember a TLS endpoint's leaf-certificate SHA-256 fingerprint.

Exit codes:
  0: first observation or unchanged certificate
  1: certificate fingerprint changed
  2: connection, TLS, or database error

Methods:
  tls:      connect with TLS immediately
  xmpp-tls: negotiate XMPP STARTTLS (RFC 6120), then upgrade to TLS

Both methods disable certificate trust-chain and hostname validation: the
goal is to fingerprint the certificate, not to judge its trustworthiness.
"""

import argparse
import hashlib
import ipaddress
import socket
import sqlite3
import ssl
import sys
import xml.etree.ElementTree as ET

XMPP_TLS_NS = "urn:ietf:params:xml:ns:xmpp-tls"
XMPP_STREAMS_NS = "http://etherx.jabber.org/streams"
MAX_STREAM_BUFFER = 65536  # Refuse to buffer more than this per stanza read.


def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect changes to a server's TLS leaf certificate."
    )
    parser.add_argument("--host", required=True, help="Hostname or IP address")
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="TCP port (default: 443)",
    )
    parser.add_argument(
        "--method",
        choices=("tls", "xmpp-tls"),
        default="tls",
        help="TLS connection method (default: tls)",
    )
    parser.add_argument(
        "--db",
        default="certwatch.sqlite3",
        help="SQLite database path (default: certwatch.sqlite3)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Connection and handshake timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    return args


def get_certificate_sha256(host, port, timeout):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        ipaddress.ip_address(host)
        server_hostname = None  # IP literals are not DNS SNI names.
    except ValueError:
        server_hostname = host  # Send SNI for DNS hostnames.

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        with context.wrap_socket(
            raw_sock, server_hostname=server_hostname
        ) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)

    if not cert_der:
        raise RuntimeError("TLS peer did not provide a certificate")

    return hashlib.sha256(cert_der).hexdigest()


class StreamBuffer:
    """Byte buffer that extracts complete top-level stream elements.

    The XMPP stream is a single XML document whose root <stream:stream> stays
    open for the connection's lifetime, so it cannot be parsed as a standalone
    document. Instead, scan the buffered bytes for the end of each top-level
    child element (stanza) and keep any bytes read past it for later use.
    """

    def __init__(self, sock, timeout, max_size=MAX_STREAM_BUFFER):
        self.sock = sock
        self.timeout = timeout
        self.max_size = max_size
        self.buffer = b""

    def _recv(self):
        chunk = self.sock.recv(4096)
        if not chunk:
            raise RuntimeError("XMPP stream closed by server")
        if len(self.buffer) + len(chunk) > self.max_size:
            raise RuntimeError("XMPP stream input exceeds buffer limit")
        self.buffer += chunk

    def read_element(self):
        """Read until one complete top-level element is buffered, return its
        XML element. Bytes after the element's closing tag are preserved."""
        while True:
            before = len(self.buffer)
            element = self._try_extract()
            if element is not None:
                return element
            if len(self.buffer) == before:
                self._recv()  # No progress; wait for more bytes.

    def _try_extract(self):
        # Discard any text before the next element start.
        if not self.buffer.startswith(b"<"):
            lt = self.buffer.find(b"<")
            self.buffer = self.buffer[lt:] if lt != -1 else b""
            return None
        close = self.buffer.find(b">")
        if close == -1:
            return None
        tag = self.buffer[: close + 1]
        if tag.startswith(b"<?") or tag.startswith(b"<!"):
            self.buffer = self.buffer[close + 1 :]
            return None
        if tag.endswith(b"/>"):
            # Self-closing top-level element.
            raw, self.buffer = self.buffer[: close + 1], self.buffer[close + 1 :]
            return self._parse(raw)
        name = tag[1:-1].split()[0]
        if name == b"stream:stream":
            # The open root itself; keep the remainder and look for children.
            self.buffer = self.buffer[close + 1 :]
            return None
        closer = b"</" + name + b">"
        end = self.buffer.find(closer, close + 1)
        if end == -1:
            return None
        end += len(closer)
        raw, self.buffer = self.buffer[:end], self.buffer[end:]
        return self._parse(raw)

    @staticmethod
    def _parse(raw):
        # Declared namespaces are present on the root <stream:stream>, but a
        # single extracted stanza depends on undeclared prefixes. Inject the
        # stream namespace declaration so ElementTree can resolve it.
        if b"stream:" in raw and XMPP_STREAMS_NS.encode() not in raw:
            close = raw.find(b">")
            raw = raw[:close] + f" xmlns:stream='{XMPP_STREAMS_NS}'".encode() + raw[close:]
        try:
            return ET.fromstring(raw)
        except ET.ParseError as exc:
            raise RuntimeError(f"Malformed XMPP XML: {exc}") from exc


def get_certificate_sha256_xmpp(host, port, timeout):
    """Retrieve the leaf certificate via XMPP STARTTLS (RFC 6120)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        ipaddress.ip_address(host)
        server_hostname = None  # IP literals are not DNS SNI names.
    except ValueError:
        server_hostname = host  # Send SNI even though validation is off.

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        stream = StreamBuffer(raw_sock, timeout)

        raw_sock.sendall(
            (
                "<?xml version='1.0'?>"
                f"<stream:stream to='{host}' version='1.0' "
                "xmlns='jabber:client' "
                f"xmlns:stream='{XMPP_STREAMS_NS}'>"
            ).encode("utf-8")
        )

        # Read stanzas until we see the server's stream features. The
        # features stanza may or may not be the first stanza received.
        features = None
        while features is None:
            element = stream.read_element()
            if element.tag == f"{{{XMPP_STREAMS_NS}}}error":
                raise RuntimeError(f"XMPP stream error: {ET.tostring(element)!r}")
            if element.tag == f"{{{XMPP_STREAMS_NS}}}features":
                features = element

        if features.find(f"{{{XMPP_TLS_NS}}}starttls") is None:
            raise RuntimeError("XMPP server does not advertise STARTTLS")

        raw_sock.sendall(f"<starttls xmlns='{XMPP_TLS_NS}'/>".encode("utf-8"))

        response = stream.read_element()
        if response.tag == f"{{{XMPP_TLS_NS}}}failure":
            raise RuntimeError("XMPP STARTTLS failed: server returned <failure/>")
        if response.tag != f"{{{XMPP_TLS_NS}}}proceed":
            raise RuntimeError(
                f"XMPP STARTTLS failed: unexpected stanza {ET.tostring(response)!r}"
            )

        # Upgrade the existing socket in place; do not reconnect.
        with context.wrap_socket(
            raw_sock, server_hostname=server_hostname
        ) as tls_sock:
            cert_der = tls_sock.getpeercert(binary_form=True)

    if not cert_der:
        raise RuntimeError("TLS peer did not provide a certificate")

    return hashlib.sha256(cert_der).hexdigest()


METHODS = {
    "tls": get_certificate_sha256,
    "xmpp-tls": get_certificate_sha256_xmpp,
}


def record_and_compare(db_path, key, current_sha):
    with sqlite3.connect(db_path, timeout=10) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                key TEXT PRIMARY KEY,
                last_sha TEXT NOT NULL
            )
            """)
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT last_sha FROM certificates WHERE key = ?", (key,)
        ).fetchone()

        if row is None:
            db.execute(
                "INSERT INTO certificates (key, last_sha) VALUES (?, ?)",
                (key, current_sha),
            )
            return "first", None

        previous_sha = row[0]
        if previous_sha == current_sha:
            return "same", previous_sha

        db.execute(
            "UPDATE certificates SET last_sha = ? WHERE key = ?",
            (current_sha, key),
        )
        return "changed", previous_sha


def main():
    args = parse_args()
    key = f"{args.host.lower()}:{args.port}:{args.method}"

    try:
        current_sha = METHODS[args.method](
            args.host, args.port, args.timeout
        )
        status, previous_sha = record_and_compare(args.db, key, current_sha)
    except (
        OSError,
        ssl.SSLError,
        sqlite3.Error,
        RuntimeError,
        ValueError,
    ) as exc:
        print(f"ERROR {key}: {exc}", file=sys.stderr)
        return 2

    if status == "changed":
        print(f"CHANGED {key}", file=sys.stderr)
        print(f"old_sha256={previous_sha}", file=sys.stderr)
        print(f"new_sha256={current_sha}", file=sys.stderr)
        return 1

    # Deliberately silent on first observation and when unchanged.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
