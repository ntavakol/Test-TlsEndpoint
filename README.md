# Test-TlsEndpoint

A single-file PowerShell script for diagnosing TLS problems on any TCP service.

No modules to install, no admin rights, no OpenSSL required. Works on Windows
PowerShell 5.1 and PowerShell 7+ on Windows, Linux and macOS.

## Why

Most TLS test tools abort the handshake when a certificate fails validation,
which tells you that something is wrong but not what. This script deliberately
accepts any certificate so it can inspect and report the problem: hostname
mismatch, expiry, clock skew, an incomplete chain, or an untrusted issuer.

It also distinguishes the chain your operating system *builds* from the chain
the server actually *sends*. Those differ more often than people expect, and
that gap is what breaks appliances, IoT devices and embedded agents that have
no intermediate cache and do not fetch via AIA.

## Usage

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

## Parameters

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

## Reading the output

**`SslPolicyErrors: None`** means your local trust store validated the chain.
That is not a guarantee the far-end client will, because the OS may have
supplied intermediates it already had cached.

**`Certificates sent by server: 1`** means the server is serving the leaf only.
Browsers usually cope, appliances usually do not. Rebuild the server
certificate as leaf followed by intermediates.

**`Certificates sent by server: 3`** usually means a self-signed root is
included. Harmless for most clients, but some embedded TLS stacks reject it.

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

## Requirements

- Windows PowerShell 5.1, or PowerShell 7+ on any platform
- OpenSSL on PATH, only for `-ShowWireChain`

## Notes

The script contains no backtick line continuations, so it can be pasted into a
terminal without breaking.

TLS 1.3 is offered only where the runtime supports it. Windows PowerShell 5.1
on .NET Framework generally tops out at TLS 1.2.

## License

MIT
