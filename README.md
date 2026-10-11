# certwatch

`certwatch.py` monitors a server's TLS leaf certificate and reports when its
SHA-256 fingerprint changes. It runs as a one-shot check (e.g. from cron),
storing the fingerprint in SQLite keyed by `host:port:method` and printing a
report to stderr only when the certificate changes or an error occurs.

## Usage

```
usage: certwatch.py [-h] --host HOST [--port PORT] [--method {tls,xmpp-tls}]
                    [--db DB] [--timeout TIMEOUT]

Detect changes to a server's TLS leaf certificate.

options:
  -h, --help            show this help message and exit
  --host HOST           Hostname or IP address
  --port PORT           TCP port (default: 443)
  --method {tls,xmpp-tls}
                        TLS connection method (default: tls)
  --db DB               SQLite database path (default: certwatch.sqlite3)
  --timeout TIMEOUT     Connection and handshake timeout in seconds (default:
                        10)
```

Exit codes: `0` first observation or unchanged certificate, `1` certificate
changed, `2` error. Certificate trust, expiry, and hostname are not validated
(the fingerprint is what matters); SNI is sent for DNS names but not IP
literals.

## How it works

With `--method tls` the script connects and performs a TLS handshake directly.
With `--method xmpp-tls` it first performs the RFC 6120 STARTTLS negotiation:
it opens an XMPP stream, waits for `<stream:features/>`, requires the
`urn:ietf:params:xml:ns:xmpp-tls` STARTTLS feature, sends `<starttls/>`, and
requires `<proceed/>` before upgrading the existing socket to TLS. The
XMPP stream is a single XML document that never closes, so stanzas are
extracted from a byte buffer that reassembles fragmented reads and preserves
bytes read past a stanza boundary.

After the handshake, the peer's DER-encoded leaf certificate is hashed with
SHA-256. The hash is compared against the previous value in the SQLite
database (written inside a `BEGIN IMMEDIATE` transaction so concurrent runs
are safe); on a mismatch a `CHANGED` report with the old and new fingerprints
is printed to stderr.
