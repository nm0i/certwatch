# certwatch

`certwatch.py` monitors a server's TLS leaf certificate and reports
when its SHA-256 fingerprint changes.

It runs as a one-shot check  (e.g. from cron), storing the fingerprint
in  SQLite printing  a  report  to stderr  only  when the  certificate
changes or an error occurs.

## Why

This monitoring tool should help circumvent 'malicious hoster' attack
within CA forum-based trust chains, essentially making it ssh-like.

## E-mail notifications via cron

cron mails a job's  output  (stdout  and  stderr)  to the  local user,
or  to  `MAILTO`  when set.  `certwatch.py`  prints  a  report  to  stderr
only  when  the  certificate  changes  (exit  `1`)  or  an  error  occurs
(exit  `2`),  so  a  plain  crontab  entry  is  a  complete  notification
setup: no mail while the fingerprint stays the same, mail the moment it
changes or a check fails.

```crontab
MAILTO=you@example.com
# Check every 30 minutes. Use an absolute --db path: cron does not run
# the job in the script's directory, so a relative path would create
# the database in $HOME.
30 */12 * * * /usr/local/bin/certwatch.py --host example.com --db /var/lib/certwatch/certwatch.sqlite3
```

A  sendmail-compatible  MTA  (postfix,  exim,  msmtp,  ...)  must  be
installed  and  configured  for  cron  to  deliver  mail.  Add  one  line
per endpoint; the  database key is `host:port:method`, so  separate cron
lines can safely share a single database file.

### With chronic

`chronic`  (from  moreutils)  runs  a  command  and  discards  its output
unless it exits non-zero, which is exactly  certwatch's  exit-code
contract  (`1` changed, `2` error). Useful  outside  cron, or  inside  a
crontab  to  keep  the  success  path  quiet  no matter what:

```sh
chronic certwatch.py --host example.com --db ~/.certwatch.sqlite3
```

or, in crontab:

``` crontab
30 */12 * * * chronic /usr/local/bin/certwatch.py --host example.com --db /var/lib/certwatch/certwatch.sqlite3
```

## Usage

```
usage: certwatch.py [-h] --host HOST [--port PORT]
                    [--method {tls,xmpp-tls,smtp-tls,imap-tls}] [--db DB]
                    [--timeout TIMEOUT]

Detect changes to a server's TLS leaf certificate.

options:
  -h, --help            show this help message and exit
  --host HOST           Hostname or IP address
  --port PORT           TCP port (default: 443)
  --method {tls,xmpp-tls,smtp-tls,imap-tls}
                        TLS connection method (default: tls)
  --db DB               SQLite database path (default: certwatch.sqlite3)
  --timeout TIMEOUT     Connection and handshake timeout in seconds (default:
                        10)
```

Exit  codes:  `0`  first  observation or  unchanged  certificate,  `1`
certificate  changed,  `2`  error.   Certificate  trust,  expiry,  and
hostname are not  validated (the fingerprint is what  matters); SNI is
sent for DNS names but not IP literals.

## Dependencies

python3.6+ standard library covers required dependencies.

## How it works

With `--method tls` the script connects and performs a TLS handshake
directly. 

With  `--method xmpp-tls`  it  first performs  the  RFC 6120  STARTTLS
negotiation: it opens an  XMPP stream, waits for `<stream:features/>`,
requires the `urn:ietf:params:xml:ns:xmpp-tls` STARTTLS feature, sends
`<starttls/>`, and requires `<proceed/>` before upgrading the existing
socket to  TLS. The XMPP  stream is a  single XML document  that never
closes, so stanzas  are extracted from a byte  buffer that reassembles
fragmented reads and preserves bytes read past a stanza boundary.

With `--method smtp-tls` it performs  the RFC 3207  STARTTLS  handshake:
it reads the `220` greeting, sends `EHLO`, requires `STARTTLS` among the
advertised extensions, sends `STARTTLS`, and requires a `220` reply.

With `--method imap-tls` it performs the RFC 2595 STARTTLS handshake: it
requires an untagged `* OK` greeting, sends a tagged `STARTTLS` command,
skips  untagged responses, and requires  a tagged  `OK` before upgrading
the existing socket to TLS.

After the handshake, the peer's DER-encoded leaf certificate is hashed
with SHA-256. The  hash is compared against the previous  value in the
SQLite  database (written  inside a  `BEGIN IMMEDIATE`  transaction so
concurrent runs are  safe); on a mismatch a `CHANGED`  report with the
old and new fingerprints is printed to stderr.
