<#
.SYNOPSIS
    Tests any TLS-wrapped TCP service: reachability, negotiated protocol and
    cipher, leaf certificate detail, hostname/SAN match, chain validation, and
    what the server actually presents on the wire.

.DESCRIPTION
    Diagnoses TLS problems on arbitrary TCP services (syslog over TLS, LDAPS,
    SMTPS, HTTPS, MQTT, custom collectors) without needing openssl installed.

    Client-side certificate validation is deliberately bypassed so that a
    failing certificate can still be inspected and reported, rather than the
    handshake aborting with a generic error.

    Optionally sends a test payload so you can confirm the far end parses what
    you send, including RFC 5424/5425 syslog framing.

.NOTES SECURITY
    This script accepts ANY server certificate without validation. That is
    deliberate: a rejected certificate cannot be inspected, and inspection is
    the point. Findings are reported rather than enforced.

    Do not copy the RemoteCertificateValidationCallback pattern from this
    script into production code. Returning $true unconditionally disables
    certificate validation and defeats the security guarantees of TLS.

.PARAMETER ComputerName
    Hostname or IP of the service to test. Prompts if omitted.

.PARAMETER Port
    TCP port of the service. Prompts if omitted.

.PARAMETER SniName
    Server name to send in the TLS SNI extension and to validate the
    certificate against. Defaults to ComputerName. Set this when connecting by
    IP to a host that serves a named certificate.

.PARAMETER DnsServer
    Resolve ComputerName against this DNS server rather than the system
    resolver. Takes an IP address. The hosts file and the system resolver
    are bypassed, and the connect is made to the address this server
    returns, so the whole test reflects that one server's answer.

.PARAMETER Compare
    Resolve through the system resolver as well and report both answers
    side by side. Needs DnsServer. The endpoint tested is still the one
    DnsServer points at.

.PARAMETER TlsVersion
    Protocol to offer. Auto offers everything the platform supports.

.PARAMETER SendSyslog
    Send an RFC 5424 message using RFC 5425 octet-counted framing.

.PARAMETER SendRaw
    Send an arbitrary string over the established TLS session.

.PARAMETER ReadResponse
    Wait for and display bytes returned by the server after sending.

.PARAMETER PassThru
    Emit a result object instead of only writing to the console.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -ComputerName syslog.example.com -Port 6514

    Basic check of a TLS syslog collector.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -ComputerName mail.example.com -Port 465 -ShowWireChain

    Verify the server presents a complete certificate chain, not just the leaf.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -ComputerName 192.0.2.10 -Port 636 -SniName dc01.example.com

    Connect to an LDAPS server by IP while validating its named certificate.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -ComputerName syslog.example.com -Port 6514 -SendSyslog -Message 'events connectivity test' -Count 3

    Send three octet-counted RFC 5424 messages to confirm the collector parses
    them and does not drop on connection reuse.

.EXAMPLE
    .\Test-TlsEndpoint.ps1 -ComputerName www.example.com -Port 443 -TlsVersion Tls12 -SendRaw "GET / HTTP/1.1$([char]13)$([char]10)Host: www.example.com$([char]13)$([char]10)Connection: close$([char]13)$([char]10)$([char]13)$([char]10)" -ReadResponse

    Force TLS 1.2, issue a raw HTTP request and print the response.

.EXAMPLE
    'host-a.example.com', 'host-b.example.com' |
        .\Test-TlsEndpoint.ps1 -Port 443 -Quiet -PassThru |
        Select-Object ComputerName, DaysLeft, NameMatch, ChainValid |
        Format-Table

    Bulk certificate expiry and validation sweep across many hosts.

.EXAMPLE
    Import-Csv .\endpoints.csv | .\Test-TlsEndpoint.ps1 -Quiet -PassThru |
        Export-Csv .\tls-report.csv -NoTypeInformation

    Read ComputerName and Port columns from a CSV and export a report.

.NOTES
    Windows PowerShell 5.1 and PowerShell 7+. No modules. No admin rights.
    ShowWireChain is the only feature requiring openssl on PATH.

    Contains no backtick line continuations, so it survives copy and paste
    into a terminal.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true,
               ValueFromPipelineByPropertyName = $true,
               HelpMessage = 'Hostname or IP of the TLS service to test')]
    [Alias('HostName', 'Server', 'Target')]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,

    [Parameter(Mandatory = $true, Position = 1,
               ValueFromPipelineByPropertyName = $true,
               HelpMessage = 'TCP port of the TLS service')]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [string]$SniName,

    [string]$DnsServer,

    [switch]$Compare,

    [ValidateSet('Auto', 'Tls', 'Tls11', 'Tls12', 'Tls13')]
    [string]$TlsVersion = 'Auto',

    [ValidateRange(100, 120000)]
    [int]$TimeoutMs = 5000,

    [ValidateRange(0, 3650)]
    [int]$ExpiryWarningDays = 30,

    [switch]$ShowWireChain,

    # --- optional payload ---------------------------------------------------
    [switch]$SendSyslog,
    [string]$Message = 'tls endpoint connectivity test',
    [string]$SyslogHost = $env:COMPUTERNAME,
    [string]$AppName = 'tlstest',
    [ValidateRange(0, 191)]
    [int]$Priority = 134,          # facility 16 (local0), severity 6 (info)
    [ValidateRange(1, 1000)]
    [int]$Count = 1,

    [string]$SendRaw,
    [switch]$ReadResponse,

    [switch]$PassThru,
    [switch]$Quiet
)

begin {

    function Write-Line {
        param([string]$Text, [string]$Colour)
        if ($Quiet) { return }
        if ($Colour) { Write-Host $Text -ForegroundColor $Colour }
        else         { Write-Host $Text }
    }

    # Addresses for a name, or a throw explaining why there are none.
    # Dns.GetHostAddresses goes through getaddrinfo, so the hosts file and the
    # configured resolvers are honoured exactly as the connect that follows
    # will honour them. The async form is used only to bound the wait; the
    # synchronous overload takes no timeout.
    function Resolve-TargetAddress {
        param([string]$Name, [int]$TimeoutMs, [string]$Server)

        if (-not $Server) {
            $task = [Net.Dns]::GetHostAddressesAsync($Name)
            if (-not $task.Wait($TimeoutMs)) {
                throw "timed out after $TimeoutMs ms"
            }
            $addresses = @($task.Result | ForEach-Object { $_.IPAddressToString })
        }
        else {
            if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
                throw 'asking a named server needs Resolve-DnsName, which is Windows only'
            }
            # Resolve-DnsName has no timeout of its own, so it is driven in a
            # runspace that can be abandoned, keeping -TimeoutMs meaningful
            # on this path too.
            $shell    = [PowerShell]::Create()
            $timedOut = $false
            try {
                $null = $shell.AddCommand('Resolve-DnsName').
                    AddParameter('Name',        $Name).
                    AddParameter('Server',      $Server).
                    AddParameter('Type',        'A_AAAA').
                    AddParameter('DnsOnly',     $true).
                    AddParameter('NoHostsFile', $true)
                $async = $shell.BeginInvoke()
                if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                    # Stop() and Dispose() both block until the query gives up,
                    # which is the wait -TimeoutMs exists to cut short. Stop it
                    # asynchronously and dispose from the callback, so a sweep
                    # against a dead server does not pile up runspaces.
                    $timedOut = $true
                    $doomed   = $shell
                    $null = $doomed.BeginStop({
                        param($ar)
                        try { $doomed.EndStop($ar) } catch { }
                        try { $doomed.Dispose() }   catch { }
                    }, $null)
                    throw "timed out after $TimeoutMs ms"
                }
                $records = $shell.EndInvoke($async)
                # the fault is on the error stream, where it reads as itself
                if ($shell.Streams.Error.Count) {
                    throw $shell.Streams.Error[0].Exception.Message
                }
            }
            finally { if (-not $timedOut) { $shell.Dispose() } }
            $addresses = @($records | Where-Object { $_.IPAddress } |
                           ForEach-Object { $_.IPAddress })
        }

        if ($addresses.Count -eq 0) {
            throw 'the resolver returned no addresses'
        }
        return $addresses
    }

    function Get-SslProtocolSet {
        param([string]$Requested)

        $wanted = if ($Requested -eq 'Auto') {
            @('Tls13', 'Tls12', 'Tls11', 'Tls')
        } else {
            @($Requested)
        }

        $value = 0
        foreach ($name in $wanted) {
            try { $value = $value -bor [int][Security.Authentication.SslProtocols]$name }
            catch { }   # not supported by this runtime, skip it
        }

        if ($value -eq 0) {
            throw "None of the requested TLS versions are supported by this PowerShell runtime."
        }
        return [Security.Authentication.SslProtocols]$value
    }

    function Get-CertKeySize {
        param($Certificate)
        try {
            $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
            if ($rsa) { return $rsa.KeySize }
        } catch { }
        try {
            $ec = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
            if ($ec) { return $ec.KeySize }
        } catch { }
        try { return $Certificate.PublicKey.Key.KeySize } catch { }
        return $null
    }

    function Test-NameMatch {
        param([string[]]$Names, [string]$Expected)

        foreach ($n in $Names) {
            if ($n -ieq $Expected) { return $true }

            if ($n.StartsWith('*.')) {
                $suffix = $n.Substring(1)                 # ".example.com"
                if ($Expected.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
                    $label = $Expected.Substring(0, $Expected.Length - $suffix.Length)
                    # a wildcard covers exactly one label, and that label must exist
                    if ($label -and $label -notmatch '\.') { return $true }
                }
            }
        }
        return $false
    }

    function Find-OpenSsl {
        $cmd = Get-Command openssl -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }

        $candidates = @(
            'C:\Program Files\Git\usr\bin\openssl.exe',
            'C:\Program Files\Git\mingw64\bin\openssl.exe',
            'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
        )
        if ($env:LOCALAPPDATA) {
            $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\Git\usr\bin\openssl.exe')
        }

        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { return $c }
        }
        return $null
    }
}

process {

    if (-not $SniName) { $SniName = $ComputerName }

    $target = "${ComputerName}:${Port}"
    $sep    = '-' * 68

    # chain data must be copied out inside the validation callback, because
    # .NET disposes the X509Chain object as soon as the callback returns
    $script:ChainInfo    = @()
    $script:ChainStatus  = @()
    $script:PolicyErrors = $null

    $result = [PSCustomObject]@{
        ComputerName    = $ComputerName
        Port            = $Port
        SniName         = $SniName
        DnsServer       = $DnsServer
        Resolved        = @()
        SystemResolved  = @()
        ResolversAgree  = $null
        TcpOpen         = $false
        TlsProtocol     = $null
        Cipher          = $null
        CipherBits      = $null
        KeyExchange     = $null
        Subject         = $null
        Issuer          = $null
        NotBefore       = $null
        NotAfter        = $null
        DaysLeft        = $null
        SignatureAlg    = $null
        KeySize         = $null
        Thumbprint      = $null
        SubjectAltNames = @()
        NameMatch       = $false
        ChainValid      = $false
        PolicyErrors    = $null
        WireCertCount   = $null
        Sent            = 0
        Error           = $null
    }

    # ------------------------------------------------------------- DNS first
    # A name that does not resolve can never connect, and reporting that as a
    # refused connection sends the reader after a firewall that is not there.
    if ($DnsServer) {
        $probe = $null
        if (-not [Net.IPAddress]::TryParse($DnsServer, [ref]$probe)) {
            throw "-DnsServer takes an IP address, not '$DnsServer'"
        }
        if ($probe.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
            $probe.ToString() -ne $DnsServer) {
            throw "-DnsServer '$DnsServer' is not a full IPv4 address; it would be read as $probe"
        }
    }
    if ($Compare -and -not $DnsServer) {
        throw '-Compare needs -DnsServer: it compares that server against the system resolver'
    }

    $via       = if ($DnsServer) { " via $DnsServer" } else { '' }
    $connectTo = $ComputerName
    $ipLiteral = $null
    if (-not [Net.IPAddress]::TryParse($ComputerName, [ref]$ipLiteral)) {
        $addresses = $null
        $failure   = $null
        try {
            $addresses = Resolve-TargetAddress -Name $ComputerName -TimeoutMs $TimeoutMs -Server $DnsServer
        } catch {
            $reason = $_.Exception
            while ($reason.InnerException) { $reason = $reason.InnerException }
            $failure = $reason.Message
        }
        $result.Resolved = @($addresses)

        # The comparison runs whether or not the named server answered. One
        # resolver failing where the other does not is the case most worth
        # seeing, so it cannot sit behind the early return below.
        if ($Compare) {
            $sysAddresses = $null
            try {
                $sysAddresses = Resolve-TargetAddress -Name $ComputerName -TimeoutMs $TimeoutMs
            } catch {
                $sysAddresses = $null
            }
            $result.SystemResolved = @($sysAddresses)
            if ($sysAddresses -and $addresses) {
                $result.ResolversAgree =
                    (($sysAddresses | Sort-Object) -join ',') -eq (($addresses | Sort-Object) -join ',')
            }
            else {
                # neither answering is agreement; one answering is not
                $result.ResolversAgree = (-not $sysAddresses) -and (-not $addresses)
            }

            if (-not $Quiet) {
                $shownSys = if ($sysAddresses) { $sysAddresses -join ', ' } else { 'did not resolve' }
                $shownSrv = if ($addresses)    { $addresses -join ', ' }    else { 'did not resolve' }
                Write-Host ''
                Write-Host $sep
                Write-Host 'Resolver comparison'
                Write-Host $sep
                Write-Line ('  {0,-22} {1}' -f 'system resolver', $shownSys)
                Write-Line ('  {0,-22} {1}' -f $DnsServer, $shownSrv)
                if ($result.ResolversAgree) {
                    Write-Line 'The two resolvers agree.' 'Green'
                } elseif ($addresses) {
                    Write-Line "The two resolvers disagree. The endpoint tested below is the one $DnsServer points at." 'Yellow'
                } else {
                    Write-Line "The two resolvers disagree, and $DnsServer is the one that failed." 'Yellow'
                }
            }
        }

        if ($failure) {
            $result.Error = "DNS resolution failed: '$ComputerName' did not resolve$via"
            Write-Line "DNS resolution for '$ComputerName'$via failed: $failure" 'Red'
            Write-Line 'The name did not resolve, so the service was never contacted.' 'Red'
            if ($DnsServer) {
                Write-Line "That is the answer from $DnsServer alone. Another resolver may well differ." 'Yellow'
            } else {
                Write-Line 'Check the resolver rather than the endpoint: the host, the search domain, or a split-horizon zone.' 'Yellow'
            }
            if ($PassThru) { $result }
            return
        }

        if (-not $Compare) {
            Write-Line ("Resolved {0}{1} to {2}" -f $ComputerName, $via, ($result.Resolved -join ', '))
        }

        # A named server is only really honoured if its answer is the one
        # connected to. Leaving the connect to the system resolver would let
        # it quietly overrule the flag. IPv4 is preferred because a host
        # with no IPv6 route fails confusingly.
        if ($DnsServer) {
            $v4 = @($result.Resolved | Where-Object { $_ -notmatch ':' })
            $connectTo = if ($v4.Count) { $v4[0] } else { $result.Resolved[0] }
            $target    = "${connectTo}:${Port}"
            Write-Line ("Connecting to {0}, validating the name '{1}'" -f $connectTo, $SniName)
        }
    }

    # ------------------------------------------------------------ TCP connect
    # The parameterless constructor makes an IPv4-only socket, which refuses
    # every IPv6 literal with a socket address family error before a packet is
    # sent. Match the socket to the target instead: a literal gets its own
    # family, a name gets a dual-mode socket that accepts either.
    $ipTarget = $null
    if ([Net.IPAddress]::TryParse($connectTo, [ref]$ipTarget)) {
        $tcp = New-Object Net.Sockets.TcpClient($ipTarget.AddressFamily)
    }
    else {
        try {
            $tcp = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6)
            $tcp.Client.DualMode = $true
        }
        catch {
            # no IPv6 stack at all, so IPv4 is the only thing left to try
            $tcp = New-Object Net.Sockets.TcpClient
        }
    }
    try {
        $iar = $tcp.BeginConnect($connectTo, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            throw "timed out after $TimeoutMs ms"
        }
        $tcp.EndConnect($iar)
    } catch {
        $result.Error = "TCP connect failed: $($_.Exception.Message)"
        Write-Line "TCP connect to $target failed: $($_.Exception.Message)" 'Red'
        $tcp.Close()
        if ($PassThru) { $result }
        return
    }

    $result.TcpOpen = $true
    Write-Line "TCP $target open" 'Green'

    # ----------------------------------------------------------- TLS handshake
    $callback = [Net.Security.RemoteCertificateValidationCallback]{
        param($sender, $certificate, $chain, $sslPolicyErrors)

        $script:PolicyErrors = $sslPolicyErrors

        if ($chain) {
            $info = @()
            foreach ($element in $chain.ChainElements) {
                $elementStatus = ($element.ChainElementStatus | ForEach-Object { $_.Status }) -join ','
                $info += [PSCustomObject]@{
                    Subject = $element.Certificate.Subject
                    Issuer  = $element.Certificate.Issuer
                    Expires = $element.Certificate.NotAfter
                    Status  = $elementStatus
                }
            }
            $script:ChainInfo = $info

            $statuses = @()
            foreach ($s in $chain.ChainStatus) {
                $statuses += ("{0}: {1}" -f $s.Status, $s.StatusInformation.Trim())
            }
            $script:ChainStatus = $statuses
        }

        # accept unconditionally so a bad certificate can still be inspected
        return $true
    }

    try {
        $protocols = Get-SslProtocolSet -Requested $TlsVersion
    } catch {
        $result.Error = $_.Exception.Message
        Write-Line $_.Exception.Message 'Red'
        $tcp.Close()
        if ($PassThru) { $result }
        return
    }

    $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $callback)
    try {
        $ssl.AuthenticateAsClient($SniName, $null, $protocols, $false)
    } catch {
        $result.Error = "TLS handshake failed: $($_.Exception.Message)"
        Write-Line "TLS handshake failed: $($_.Exception.Message)" 'Red'
        Write-Line "The server may require a client certificate, or offers no protocol in common." 'Yellow'
        $ssl.Dispose()
        $tcp.Close()
        if ($PassThru) { $result }
        return
    }

    $result.TlsProtocol = $ssl.SslProtocol.ToString()
    $result.Cipher      = $ssl.CipherAlgorithm.ToString()
    $result.CipherBits  = $ssl.CipherStrength
    $result.KeyExchange = $ssl.KeyExchangeAlgorithm.ToString()

    Write-Line ("Negotiated: {0} / {1} {2}-bit / KeyExchange {3}" -f $ssl.SslProtocol, $ssl.CipherAlgorithm, $ssl.CipherStrength, $ssl.KeyExchangeAlgorithm) 'Green'

    if ($ssl.SslProtocol -eq [Security.Authentication.SslProtocols]::Tls -or
        $ssl.SslProtocol -eq [Security.Authentication.SslProtocols]::Tls11) {
        Write-Line "Server negotiated a deprecated protocol. TLS 1.2 is the practical minimum." 'Yellow'
    }

    # ------------------------------------------------------- leaf certificate
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    $daysLeft = [int](($cert.NotAfter - (Get-Date)).TotalDays)

    $result.Subject      = $cert.Subject
    $result.Issuer       = $cert.Issuer
    $result.NotBefore    = $cert.NotBefore
    $result.NotAfter     = $cert.NotAfter
    $result.DaysLeft     = $daysLeft
    $result.SignatureAlg = $cert.SignatureAlgorithm.FriendlyName
    $result.KeySize      = Get-CertKeySize -Certificate $cert
    $result.Thumbprint   = $cert.Thumbprint

    if (-not $Quiet) {
        Write-Host ''
        Write-Host $sep
        Write-Host 'Leaf certificate'
        Write-Host $sep
        [PSCustomObject]@{
            Subject    = $result.Subject
            Issuer     = $result.Issuer
            NotBefore  = $result.NotBefore
            NotAfter   = $result.NotAfter
            DaysLeft   = $result.DaysLeft
            SigAlg     = $result.SignatureAlg
            KeySize    = $result.KeySize
            Thumbprint = $result.Thumbprint
        } | Format-List
    }

    if ($daysLeft -lt 0) {
        Write-Line "Certificate EXPIRED $([Math]::Abs($daysLeft)) days ago." 'Red'
    } elseif ($daysLeft -lt $ExpiryWarningDays) {
        Write-Line "Certificate expires in $daysLeft days." 'Yellow'
    }

    if ($cert.NotBefore -gt (Get-Date)) {
        Write-Line "Certificate is not valid until $($cert.NotBefore). Check clock sync on the client." 'Red'
    }

    # -------------------------------------------------------- SAN name match
    $sanExtension = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }

    if (-not $sanExtension) {
        Write-Line "No Subject Alternative Name extension. Most modern clients will reject this certificate." 'Red'
    } else {
        $sanText = $sanExtension.Format($false)
        Write-Line "SAN: $sanText"

        $names = @()
        foreach ($part in ($sanText -split ',\s*')) {
            if ($part -match '^(DNS Name|IP Address)\s*=\s*(.+)$') {
                $names += $Matches[2].Trim()
            }
        }
        $result.SubjectAltNames = $names
        $result.NameMatch = Test-NameMatch -Names $names -Expected $SniName

        if ($result.NameMatch) {
            Write-Line "SAN matches '$SniName'" 'Green'
        } else {
            Write-Line "SAN does NOT match '$SniName'. Clients validating hostname will reject this." 'Red'
        }
    }

    # ----------------------------------------------------- chain as validated
    if (-not $Quiet) {
        Write-Host ''
        Write-Host $sep
        Write-Host 'Chain built by the local trust store'
        Write-Host $sep
    }

    if ($script:ChainInfo.Count -eq 0) {
        Write-Line "No chain data returned." 'Yellow'
    } else {
        $index = 0
        foreach ($element in $script:ChainInfo) {
            Write-Line ("[{0}] {1}" -f $index, $element.Subject)
            Write-Line ("     issuer  : {0}" -f $element.Issuer)
            Write-Line ("     expires : {0}" -f $element.Expires)
            if ($element.Status -and $element.Status -ne 'NoError') {
                Write-Line ("     status  : {0}" -f $element.Status) 'Yellow'
            }
            $index++
        }
    }

    $result.PolicyErrors = "$script:PolicyErrors"
    $result.ChainValid   = ($script:ChainStatus.Count -eq 0 -and "$script:PolicyErrors" -eq 'None')

    if ($script:ChainStatus.Count -gt 0) {
        foreach ($s in $script:ChainStatus) { Write-Line "Chain status: $s" 'Yellow' }
    } else {
        Write-Line "Chain validates against this host's trust store." 'Green'
    }

    Write-Line "SslPolicyErrors: $script:PolicyErrors"
    Write-Line "Note: the local OS may supply intermediates from its own cache or fetch them via AIA."
    Write-Line "      A constrained client (appliance, IoT, embedded agent) often will not."
    Write-Line "      Use -ShowWireChain to see what the server actually sends."

    # -------------------------------------- what the server sends on the wire
    if ($ShowWireChain) {
        if (-not $Quiet) {
            Write-Host ''
            Write-Host $sep
            Write-Host 'Certificates presented on the wire'
            Write-Host $sep
        }

        $opensslPath = Find-OpenSsl
        if (-not $opensslPath) {
            Write-Line "openssl not found on PATH. Skipping wire chain check." 'Yellow'
        } else {
            $output = '' | & $opensslPath s_client -connect $target -servername $SniName -showcerts 2>$null

            $lines = $output | Select-String -Pattern '^\s*\d+\s+[si]:|^\s*[si]:'
            if ($lines) {
                foreach ($l in $lines) { Write-Line $l.Line.Trim() }
            }

            $wireCount = ($output | Select-String -SimpleMatch '-----BEGIN CERTIFICATE-----').Count
            $result.WireCertCount = $wireCount
            Write-Line "Certificates sent by server: $wireCount"

            if ($wireCount -le 1) {
                Write-Line "Leaf only. Clients that do not fetch intermediates via AIA cannot build a path." 'Yellow'
                Write-Line "Rebuild the server certificate as leaf followed by intermediates." 'Yellow'
            } elseif ($wireCount -ge 3) {
                Write-Line "A self-signed root appears to be included. Harmless for most clients, but" 'Yellow'
                Write-Line "some embedded stacks reject it. Leaf plus intermediates is the correct form." 'Yellow'
            } else {
                Write-Line "Leaf plus intermediate presented." 'Green'
            }
        }
    }

    # ------------------------------------------------------- optional payload
    if (($SendSyslog -or $SendRaw) -and -not $Quiet) {
        Write-Host ''
        Write-Host $sep
        Write-Host 'Test payload'
        Write-Host $sep
    }

    if ($SendSyslog) {

        if ($Message -match '^\s*<\d{1,3}>') {
            Write-Line "-Message must not begin with a PRI value such as <134>." 'Red'
            Write-Line "The RFC 5424 header is generated for you. Pass the MSG body only." 'Red'
        } else {
            for ($n = 1; $n -le $Count; $n++) {

                $stamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.ffzzz'
                $body  = $Message
                if ($Count -gt 1) { $body = "$Message [$n of $Count]" }

                # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
                $syslogMessage = "<$Priority>1 $stamp $SyslogHost $AppName - - - $body"

                # RFC 5425 octet counting, based on byte length not character count
                $msgBytes = [Text.Encoding]::UTF8.GetBytes($syslogMessage)
                $prefix   = [Text.Encoding]::UTF8.GetBytes("$($msgBytes.Length) ")
                $payload  = New-Object byte[] ($prefix.Length + $msgBytes.Length)
                [Array]::Copy($prefix,   0, $payload, 0,              $prefix.Length)
                [Array]::Copy($msgBytes, 0, $payload, $prefix.Length, $msgBytes.Length)

                try {
                    $ssl.Write($payload, 0, $payload.Length)
                    $ssl.Flush()
                    $result.Sent++
                    Write-Line ("Sent [{0}/{1}] {2} bytes: {3}" -f $n, $Count, $msgBytes.Length, $syslogMessage) 'Green'
                } catch {
                    Write-Line ("Send [{0}/{1}] failed: {2}" -f $n, $Count, $_.Exception.Message) 'Red'
                    break
                }

                if ($n -lt $Count) { Start-Sleep -Milliseconds 250 }
            }

            Write-Line "Filter the receiver on host=$SyslogHost app=$AppName to confirm arrival."
        }
    }

    if ($SendRaw) {
        $rawBytes = [Text.Encoding]::UTF8.GetBytes($SendRaw)
        try {
            $ssl.Write($rawBytes, 0, $rawBytes.Length)
            $ssl.Flush()
            $result.Sent++
            Write-Line "Sent $($rawBytes.Length) raw bytes." 'Green'
        } catch {
            Write-Line "Raw send failed: $($_.Exception.Message)" 'Red'
        }
    }

    if ($ReadResponse) {
        try {
            $ssl.ReadTimeout = $TimeoutMs
            $buffer = New-Object byte[] 8192
            $read = $ssl.Read($buffer, 0, $buffer.Length)
            if ($read -gt 0) {
                Write-Line ''
                Write-Line "Received $read bytes:"
                Write-Line ([Text.Encoding]::UTF8.GetString($buffer, 0, $read))
            } else {
                Write-Line "Server closed the connection without sending data." 'Yellow'
            }
        } catch {
            Write-Line "No response within $TimeoutMs ms: $($_.Exception.Message)" 'Yellow'
        }
    }

    $ssl.Dispose()
    $tcp.Close()

    if ($PassThru) { $result }
}
