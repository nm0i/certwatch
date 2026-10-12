#!/usr/bin/env python3
"""Remember a TLS endpoint's leaf-certificate SHA-256 fingerprint.

Exit codes:
  0: first observation or unchanged certificate
  1: certificate fingerprint changed
  2: connection, TLS, or database error

Methods:
  tls:      connect with TLS immediately
  xmpp-tls: negotiate XMPP STARTTLS (RFC 6120), then upgrade to TLS
  smtp-tls: negotiate SMTP STARTTLS (RFC 3207), then upgrade to TLS
  imap-tls: negotiate IMAP STARTTLS (RFC 2595), then upgrade to TLS

All methods disable certificate trust-chain and hostname validation: the
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
MAX_LINE_BUFFER = 8192  # Refuse to buffer more than this per protocol line.


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
        choices=("tls", "xmpp-tls", "smtp-tls", "imap-tls"),
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


def make_client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def sni_hostname(host):
    try:
        ipaddress.ip_address(host)
        return None  # IP literals are not DNS SNI names.
    except ValueError:
        return host  # Send SNI for DNS hostnames.


def read_line(sock, timeout, buffer=b"", max_size=MAX_LINE_BUFFER):
    """Read one CRLF/LF-terminated line, return it without the terminator.

    `buffer` carries bytes read past the previous line's terminator (empty
    on the first call); bytes past this line's terminator are returned too,
    so the caller can chain calls without losing pipelined data.
    """
    line = bytearray(buffer)
    while b"\n" not in line:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("Connection closed while reading a line")
        line += chunk
        if b"\n" in line:
            break
        if len(line) > max_size:
            raise RuntimeError("Protocol input exceeds line length limit")
    end = line.index(b"\n")
    if end > max_size:  # Line content alone (terminator excluded) is too long.
        raise RuntimeError("Protocol input exceeds line length limit")
    tail = bytes(line[end + 1 :])  # Bytes read past the terminator, if any.
    return bytes(line[:end]).rstrip(b"\r"), tail


def starttls_sha256(raw_sock, server_hostname):
    """Upgrade an existing socket to TLS and hash the leaf certificate."""
    with make_client_context().wrap_socket(
        raw_sock, server_hostname=server_hostname
    ) as tls_sock:
        cert_der = tls_sock.getpeercert(binary_form=True)

    if not cert_der:
        raise RuntimeError("TLS peer did not provide a certificate")

    return hashlib.sha256(cert_der).hexdigest()


def get_certificate_sha256(host, port, timeout):
    server_hostname = sni_hostname(host)

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)
        return starttls_sha256(raw_sock, server_hostname)


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
    server_hostname = sni_hostname(host)

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
        return starttls_sha256(raw_sock, server_hostname)


def get_certificate_sha256_smtp(host, port, timeout):
    """Retrieve the leaf certificate via SMTP STARTTLS (RFC 3207)."""
    server_hostname = sni_hostname(host)

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)

        code, _, pending = smtp_reply(raw_sock, timeout)  # Greeting.
        if code != "220":
            raise RuntimeError(f"SMTP greeting failed: {code}")

        raw_sock.sendall(b"EHLO certwatch\r\n")
        code, lines, pending = smtp_reply(raw_sock, timeout, buffer=pending)
        if code != "250":
            raise RuntimeError(f"SMTP EHLO failed: {code}")

        # Send STARTTLS without requiring its advertisement: some servers
        # (e.g. high-volume relays) accept STARTTLS but omit it from EHLO.
        raw_sock.sendall(b"STARTTLS\r\n")
        code, _, pending = smtp_reply(raw_sock, timeout, buffer=pending)
        if code != "220":
            raise RuntimeError(f"SMTP STARTTLS failed: {code}")

        # Upgrade the existing socket in place; do not reconnect.
        return starttls_sha256(raw_sock, server_hostname)


def smtp_reply(sock, timeout, buffer=b""):
    """Read one SMTP reply (RFC 5321 section 4.2); return (code, lines, tail).

    A reply is one or more lines, each 'ddd' followed by '-' (more lines
    follow) or ' ' (this is the final line) and text. `buffer` carries bytes
    read past the previous reply, `tail` those read past this one.
    """
    code, lines, pending = None, [], buffer
    while True:
        line, pending = read_line(sock, timeout, buffer=pending)
        text = line.decode("utf-8", "replace")
        if len(text) < 4 or not text[:3].isdigit() or text[3] not in " -":
            raise RuntimeError(f"Malformed SMTP reply: {text!r}")
        if code is None:
            code = text[:3]
        lines.append(text[4:])
        if text[3] == " ":
            return code, lines, pending


def get_certificate_sha256_imap(host, port, timeout):
    """Retrieve the leaf certificate via IMAP STARTTLS (RFC 2595)."""
    server_hostname = sni_hostname(host)

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        raw_sock.settimeout(timeout)

        tag = "cw0"
        line, pending = read_line(raw_sock, timeout)  # Server greeting.
        if not line.upper().startswith(b"* OK"):
            raise RuntimeError(f"IMAP server rejected the session: {line!r}")

        raw_sock.sendall(f"{tag} STARTTLS\r\n".encode("utf-8"))
        while True:
            line, pending = read_line(raw_sock, timeout, buffer=pending)
            if line.upper().startswith(b"* BYE"):
                raise RuntimeError("IMAP server closed the session")
            if not line.startswith(tag.encode("utf-8") + b" "):
                continue  # Untagged response; wait for the tagged one.
            parts = line.split()
            if len(parts) < 2 or parts[1].upper() != b"OK":
                raise RuntimeError(
                    f"IMAP STARTTLS failed: {line.decode('utf-8', 'replace')}"
                )
            break

        # Upgrade the existing socket in place; do not reconnect.
        return starttls_sha256(raw_sock, server_hostname)


METHODS = {
    "tls": get_certificate_sha256,
    "xmpp-tls": get_certificate_sha256_xmpp,
    "smtp-tls": get_certificate_sha256_smtp,
    "imap-tls": get_certificate_sha256_imap,
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
