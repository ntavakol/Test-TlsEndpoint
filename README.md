# Test-TlsEndpoint

Single-file TLS diagnostics for any TCP service, in **PowerShell** and **Bash**.

| Script | Runtime | Dependencies |
|---|---|---|
| `Test-TlsEndpoint.ps1` | Windows PowerShell 5.1, or PowerShell 7+ on Windows, Linux, macOS | none (OpenSSL only for `-ShowWireChain`) |
| `test-tlsendpoint.sh` | Bash 3.2+ on Linux, macOS, WSL, Git Bash | `openssl` |

Both report the same findings in the same order. Pick whichever matches the box
you are standing on. No modules to install, no admin rights.

## Why

Most TLS test tools abort the handshake when a certificate fails validation,
which tells you that something is wrong but not what. These scripts deliberately
accept any certificate so they can inspect and report the problem: hostname
mismatch, expiry, clock skew, an incomplete chain, or an untrusted issuer.

They also distinguish the chain your operating system *builds* from the chain
the server actually *sends*. Those differ more often than people expect, and
that gap is what breaks appliances, IoT devices and embedded agents that have
no intermediate cache and do not fetch via AIA.

---

## PowerShell

```powershell
# basic check
.\Test-TlsEndpoint.ps1 -ComputerName syslog.example.com -Port 6514

# positional also works
.\Test-TlsEndpoint.ps1 syslog.example.com 6514

# prompts for both if omitted
.\Test-TlsEndpoint.ps1
```

### Common scenarios

```powershell
# does the server send its intermediates, or only the leaf?
.\Test-TlsEndpoint.ps1 mail.example.com 465 -ShowWireChain

# connect by IP but validate a named certificate
.\Test-TlsEndpoint.ps1 -ComputerName 192.0.2.10 -Port 636 -SniName dc01.example.com

# does the server still accept TLS 1.0?
.\Test-TlsEndpoint.ps1 www.example.com 443 -TlsVersion Tls

# send a real RFC 5424 message with RFC 5425 octet framing
.\Test-TlsEndpoint.ps1 syslog.example.com 6514 -SendSyslog -Message 'events connectivity test'

# three messages over one connection, to catch collectors that drop on reuse
.\Test-TlsEndpoint.ps1 syslog.example.com 6514 -SendSyslog -Count 3

# arbitrary payload and response
.\Test-TlsEndpoint.ps1 www.example.com 443 -SendRaw "GET / HTTP/1.1`r`nHost: www.example.com`r`nConnection: close`r`n`r`n" -ReadResponse
```

### Bulk reporting

```powershell
'host-a.example.com','host-b.example.com' |
    .\Test-TlsEndpoint.ps1 -Port 443 -Quiet -PassThru |
    Select-Object ComputerName, DaysLeft, NameMatch, ChainValid |
    Format-Table

# endpoints.csv with ComputerName and Port columns
Import-Csv .\endpoints.csv |
    .\Test-TlsEndpoint.ps1 -Quiet -PassThru |
    Export-Csv .\tls-report.csv -NoTypeInformation
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `ComputerName` | prompts | Host or IP. Aliases: `HostName`, `Server`, `Target` |
| `Port` | prompts | TCP port |
| `SniName` | `ComputerName` | SNI value and the name validated against the SAN |
| `TlsVersion` | `Auto` | `Auto`, `Tls`, `Tls11`, `Tls12`, `Tls13` |
| `TimeoutMs` | `5000` | Connect and read timeout |
| `ExpiryWarningDays` | `30` | Threshold for the expiry warning |
| `ShowWireChain` | off | Use OpenSSL to show what the server actually presents |
| `SendSyslog` | off | Send an RFC 5424 message with RFC 5425 framing |
| `Message` | test string | Syslog MSG body only, no PRI |
| `SyslogHost` | local hostname | Syslog HOSTNAME field |
| `AppName` | `tlstest` | Syslog APP-NAME field |
| `Priority` | `134` | PRI value, local0.info |
| `Count` | `1` | Messages to send over one connection |
| `SendRaw` | none | Arbitrary string to write to the session |
| `ReadResponse` | off | Read and print the server's reply |
| `PassThru` | off | Emit a result object |
| `Quiet` | off | Suppress console output |

---

## Bash

```bash
chmod +x test-tlsendpoint.sh

# basic check
./test-tlsendpoint.sh syslog.example.com 6514

# prompts for both if omitted
./test-tlsendpoint.sh
```

### Common scenarios

```bash
# full detail of every certificate the server sends
./test-tlsendpoint.sh mail.example.com 465 --show-wire-chain

# connect by IP but validate a named certificate
./test-tlsendpoint.sh 192.0.2.10 636 --sni dc01.example.com

# does the server still accept TLS 1.0?
./test-tlsendpoint.sh www.example.com 443 --tls-version 1.0

# send a real RFC 5424 message with RFC 5425 octet framing
./test-tlsendpoint.sh syslog.example.com 6514 --send-syslog --message 'events connectivity test'

# three messages over one connection, to catch collectors that drop on reuse
./test-tlsendpoint.sh syslog.example.com 6514 --send-syslog --count 3

# arbitrary payload and response
./test-tlsendpoint.sh www.example.com 443 --read-response \
    --send-raw 'GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n'
```

### Bulk reporting

`--targets` takes a file of `host port` or `host:port` lines, `#` comments and
blank lines allowed. Use `-` to read from stdin. With `--json` each target
produces one JSON object per line, ready for `jq`. Write IPv6 targets in the
space-separated form (`2001:db8::1 443`), since the `host:port` form cannot be
split unambiguously.

```bash
printf 'host-a.example.com 443\nhost-b.example.com 443\n' > endpoints.txt

./test-tlsendpoint.sh --targets endpoints.txt --quiet --json > report.jsonl

jq -r '[.host, .daysLeft, .nameMatch, .chainValid] | @tsv' report.jsonl

# anything expiring inside 30 days
jq -r 'select(.daysLeft != null and .daysLeft < 30) | .host' report.jsonl
```

### Options

| Option | Default | Purpose |
|---|---|---|
| `<host> <port>` | prompts | Positional target |
| `--sni NAME` | `<host>` | SNI value and the name validated against the SAN |
| `--tls-version VER` | `auto` | `auto`, `1.0`, `1.1`, `1.2`, `1.3` |
| `--timeout SECONDS` | `5` | Connect and read timeout |
| `--expiry-warning-days N` | `30` | Threshold for the expiry warning |
| `--show-wire-chain` | off | Print every certificate the server sends, in full |
| `--send-syslog` | off | Send an RFC 5424 message with RFC 5425 framing |
| `--message TEXT` | test string | Syslog MSG body only, no PRI |
| `--syslog-host NAME` | local hostname | Syslog HOSTNAME field |
| `--app-name NAME` | `tlstest` | Syslog APP-NAME field |
| `--priority N` | `134` | PRI value, local0.info |
| `--count N` | `1` | Messages to send over one connection |
| `--send-raw TEXT` | none | Arbitrary string to write; understands `\n`, `\r`, `\t`, `\\` |
| `--read-response` | off | Read and print the server's reply |
| `--json` | off | Emit one JSON object per target |
| `--quiet` | off | Suppress the human-readable report |
| `--color WHEN` | `auto` | `auto`, `always`, `never` (also honours `NO_COLOR`) |
| `--targets FILE` | none | Sweep many targets; `-` reads stdin |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no problems found |
| 1 | Usage error |
| 2 | TCP connect failed |
| 3 | TLS handshake failed |
| 4 | Certificate problem: expired, not yet valid, no SAN, name mismatch, or chain did not validate |

With `--targets`, the exit code is the highest code any target produced.

### Differences from the PowerShell version

- The wire chain is free with OpenSSL, so the certificate count and its
  interpretation are always shown. `--show-wire-chain` adds per-certificate
  detail rather than enabling the check.
- A payload sent with `--send-syslog` or `--send-raw` rides a second
  connection, so the inspection transcript stays clean. All `--count` messages
  still share one connection, which is what the flag is for.
- A self-signed root in the presented chain is detected by testing whether the
  last certificate issues itself, rather than by counting certificates. The
  PowerShell version still uses the count, which misreports a cross-signed
  intermediate as a root.
- Fingerprints are SHA-256, not the SHA-1 thumbprint .NET reports.
- `--timeout` is in seconds; `-TimeoutMs` is in milliseconds.
- The RFC 5424 timestamp omits the optional fractional seconds, because no
  single `date` invocation produces them on both GNU and BSD systems.

---

## Reading the output

**`Verify return code: 0 (ok)`** / **`SslPolicyErrors: None`** means your local
trust store validated the chain. That is not a guarantee the far-end client
will, because the OS may have supplied intermediates it already had cached.

**`Certificates sent by server: 1`** means the server is serving the leaf only.
Browsers usually cope, appliances usually do not. Rebuild the server
certificate as leaf followed by intermediates.

**A chain ending in a self-signed root** means the server is sending a
certificate the client either already trusts or never will. Harmless for most
clients, but some embedded TLS stacks reject it. Note that a three-certificate
chain is not evidence of this on its own: cross-signed intermediates are common
and entirely correct. The Bash version tests whether the last certificate issues
itself; the PowerShell version still infers it from the count.

**SAN does not match** is the single most common cause of a client connecting,
completing the TCP handshake, then immediately resetting. If a device is
configured with an IP or an alias that is not in the certificate's SAN list,
the handshake dies at certificate validation.

## Interpreting a failed handshake in a packet capture

If the client completes the TCP handshake, receives the server's certificate,
sends about 7 bytes and then resets, that is a TLS alert. The client rejected
the certificate before ever sending ClientKeyExchange. Common alert codes:

| Code | Meaning | Usual cause |
|---|---|---|
| 42 | bad_certificate | malformed, or hostname mismatch |
| 45 | certificate_expired | often clock skew rather than real expiry |
| 46 | certificate_unknown | generic validation failure |
| 47 | illegal_parameter | frequently a name mismatch |
| 48 | unknown_ca | cannot build a path to a trusted root |
| 51 | decrypt_error | signature verification failed |

## Security note

Both scripts accept any server certificate without validation. That is
deliberate: a rejected certificate cannot be inspected, and inspection is the
point. Findings are reported, never enforced.

Do not copy that pattern into production code. In PowerShell, returning `$true`
from a `RemoteCertificateValidationCallback` disables certificate validation
entirely and defeats the security guarantees of TLS.

## Notes

The PowerShell script contains no backtick line continuations, so it can be
pasted into a terminal without breaking. TLS 1.3 is offered only where the
runtime supports it; Windows PowerShell 5.1 on .NET Framework generally tops
out at TLS 1.2.

The Bash script targets Bash 3.2, so it runs on the version macOS still ships.
It uses `timeout` or `gtimeout` when present and a watchdog subshell when
neither is.

## License

MIT
