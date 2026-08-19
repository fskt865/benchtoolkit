# =====================================================================
# 2_MailDiagnostics.ps1 - BenchToolkit mail path diagnostic
# ---------------------------------------------------------------------
# Replaces the manual openssl s_client workflow for diagnosing SMTP
# STARTTLS stripping and IMAP TLS health against a mail provider
# (default: mobile.charter.net, Spectrum legacy / rr.com addresses).
#
# Pure Windows PowerShell 5.1, zero third-party dependencies
# (System.Net.Sockets.TcpClient + System.Net.Security.SslStream).
#
# Read-only against the machine and the network, EXCEPT the optional
# credential test, which never runs unless you opt in at the prompt.
#
# Usage (from the toolkit drive, any machine):
#   powershell -ExecutionPolicy Bypass -File 2_MailDiagnostics.ps1
#   powershell -ExecutionPolicy Bypass -File 2_MailDiagnostics.ps1 -MailHost smtp.example.com
#   powershell -ExecutionPolicy Bypass -File 2_MailDiagnostics.ps1 -SkipCredentialTest
#
# Report: reports\MailDiag_<computer>_<timestamp>.txt next to this
# script (lands on the stick when run from the stick).
# =====================================================================
[CmdletBinding()]
param(
    [string]$MailHost = "mobile.charter.net",
    [int[]]$Ports = @(25, 143, 465, 587, 993, 995),
    [switch]$SkipCredentialTest,
    [string]$ReportDir = ""
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------- setup
if ($ReportDir -eq "") { $ReportDir = Join-Path $PSScriptRoot "reports" }
if (-not (Test-Path -LiteralPath $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ReportDir ("MailDiag_" + $env:COMPUTERNAME + "_" + $Stamp + ".txt")

$script:Flags = New-Object System.Collections.ArrayList
$script:Outcome = @{
    Dns      = "NOT RUN"
    Hosts    = "NOT RUN"
    Smtp587  = "NOT RUN"
    SmtpCert = "NOT RUN"
    Imap993  = "NOT RUN"
    Cred     = "NOT RUN"
}
$script:TlsPolicyErrors = $null

function Write-Log {
    param([string]$Text = "")
    Write-Host $Text
    Add-Content -LiteralPath $ReportFile -Value $Text
}

function Write-Section {
    param([string]$Title)
    Write-Log ""
    Write-Log ("=" * 70)
    Write-Log ("  " + $Title)
    Write-Log ("=" * 70)
}

function Add-Flag {
    param([string]$Severity, [string]$Text)
    [void]$script:Flags.Add("[" + $Severity + "] " + $Text)
    Write-Log ("  >> [" + $Severity + "] " + $Text)
}

# A validation callback that never rejects: we WANT to complete the
# handshake with an interceptor so we can print the cert it presents.
# The real policy errors are recorded and reported instead.
$script:CertCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
    param($senderObj, $cert, $chain, $errors)
    $script:TlsPolicyErrors = $errors
    return $true
}

function Write-CertDetails {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [System.Net.Security.SslStream]$Ssl
    )
    Write-Log ("    Subject     : " + $Cert.Subject)
    Write-Log ("    Issuer      : " + $Cert.Issuer)
    Write-Log ("    Thumbprint  : " + $Cert.Thumbprint)
    Write-Log ("    Valid       : " + $Cert.NotBefore.ToString("yyyy-MM-dd") + " to " + $Cert.NotAfter.ToString("yyyy-MM-dd"))
    $sanText = ""
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq "2.5.29.17") {
            $sanText = $ext.Format($false)
            Write-Log ("    SAN         : " + $sanText)
        }
    }
    Write-Log ("    TLS proto   : " + $Ssl.SslProtocol)
    Write-Log ("    Cipher      : " + $Ssl.CipherAlgorithm.ToString() + " / hash " + $Ssl.HashAlgorithm.ToString())
    if ($null -ne $script:TlsPolicyErrors) {
        if ($script:TlsPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
            Write-Log "    Chain check : PASSED (certificate chains to a trusted root)"
        } else {
            Write-Log ("    Chain check : FAILED - " + $script:TlsPolicyErrors.ToString())
            Add-Flag "WARN" ("Certificate did not validate cleanly: " + $script:TlsPolicyErrors.ToString())
        }
    }
    # Identity check: does this look like the provider's own cert?
    $idText = $Cert.Subject + " " + $sanText
    $issuer = $Cert.Issuer
    if ($idText -match '(?i)charter|spectrum|twc|\.rr\.com') {
        Write-Log "    Identity    : subject/SAN matches Charter/Spectrum - looks like the real server"
        return "OK"
    }
    $interceptors = '(?i)avast|avg|bitdefender|eset|kaspersky|norton|mcafee|webroot|sophos|fortinet|fortigate|sonicwall|watchguard|zscaler|untangle|netgear|cisco|meraki|firepower'
    if (($idText -match $interceptors) -or ($issuer -match $interceptors)) {
        Add-Flag "CRITICAL" ("TLS INTERCEPTED: certificate is issued by a security product/appliance, not the mail provider. Subject: " + $Cert.Subject + " Issuer: " + $issuer)
        return "INTERCEPTED"
    }
    Add-Flag "CRITICAL" ("Certificate subject/SAN does NOT match Charter/Spectrum: " + $Cert.Subject + " - possible TLS interception on this path")
    return "MISMATCH"
}

function Read-SmtpReply {
    # Reads one (possibly multiline) SMTP reply. Relies on ReadTimeout
    # set on the underlying NetworkStream; a timeout returns whatever
    # arrived so far.
    param([System.IO.StreamReader]$Reader, [int]$MaxLines = 60)
    $lines = New-Object System.Collections.ArrayList
    try {
        for ($i = 0; $i -lt $MaxLines; $i++) {
            $line = $Reader.ReadLine()
            if ($null -eq $line) { break }
            [void]$lines.Add($line)
            if ($line -match '^\d{3} ') { break }
            if ($line -notmatch '^\d{3}-') { break }
        }
    } catch {
        # read timeout or connection killed mid-reply - keep what we have
    }
    return @($lines)
}

function Read-ImapReply {
    param([System.IO.StreamReader]$Reader, [string]$Tag, [int]$MaxLines = 40)
    $lines = New-Object System.Collections.ArrayList
    try {
        for ($i = 0; $i -lt $MaxLines; $i++) {
            $line = $Reader.ReadLine()
            if ($null -eq $line) { break }
            [void]$lines.Add($line)
            if ($line -like ($Tag + " *")) { break }
        }
    } catch { }
    return @($lines)
}

function Test-SuspiciousIp {
    param([string]$Ip)
    if ($Ip -match '^(127\.|10\.|0\.)') { return $true }
    if ($Ip -match '^192\.168\.') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { return $true }
    if ($Ip -match '^169\.254\.') { return $true }
    return $false
}

# ---------------------------------------------------------------- header
Write-Log ("BenchToolkit mail diagnostic - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Log ("Computer : " + $env:COMPUTERNAME + "   User: " + $env:USERNAME)
Write-Log ("Target   : " + $MailHost)
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Log ("OS       : " + $osInfo.Caption + " build " + $osInfo.BuildNumber)
} catch { }
Write-Log ("Report   : " + $ReportFile)

# ---------------------------------------------------------------- DNS
Write-Section "DNS RESOLUTION (system vs 1.1.1.1 vs 8.8.8.8)"

function Get-ARecordSet {
    param([string]$Name, [string]$Server)
    $out = New-Object PSObject -Property @{ Ok = $false; Addresses = @(); Error = "" }
    try {
        if ($Server -ne "") {
            $ans = Resolve-DnsName -Name $Name -Type A -Server $Server -DnsOnly -ErrorAction Stop
        } else {
            $ans = Resolve-DnsName -Name $Name -Type A -ErrorAction Stop
        }
        $addrs = @($ans | Where-Object { $_.Type -eq "A" } | ForEach-Object { $_.IPAddress })
        $out.Ok = $true
        $out.Addresses = @($addrs | Sort-Object -Unique)
    } catch {
        $out.Error = $_.Exception.Message
    }
    return $out
}

$dnsSystem = Get-ARecordSet -Name $MailHost -Server ""
$dnsCf     = Get-ARecordSet -Name $MailHost -Server "1.1.1.1"
$dnsGoog   = Get-ARecordSet -Name $MailHost -Server "8.8.8.8"

foreach ($pair in @(
        @("System resolver", $dnsSystem),
        @("1.1.1.1 (Cloudflare)", $dnsCf),
        @("8.8.8.8 (Google)", $dnsGoog))) {
    $label = $pair[0]
    $res = $pair[1]
    if ($res.Ok) {
        Write-Log ("  " + $label.PadRight(22) + ": " + ($res.Addresses -join ", "))
    } else {
        Write-Log ("  " + $label.PadRight(22) + ": FAILED - " + $res.Error)
    }
}

$script:Outcome.Dns = "OK"
if ($dnsSystem.Ok) {
    foreach ($ip in $dnsSystem.Addresses) {
        if (Test-SuspiciousIp -Ip $ip) {
            Add-Flag "CRITICAL" ("System DNS returns a private/loopback address for " + $MailHost + ": " + $ip + " - local redirection (hosts file, malware, or router DNS hijack)")
            $script:Outcome.Dns = "HIJACKED"
        }
    }
    $publicSet = @()
    if ($dnsCf.Ok) { $publicSet = $publicSet + $dnsCf.Addresses }
    if ($dnsGoog.Ok) { $publicSet = $publicSet + $dnsGoog.Addresses }
    $publicSet = @($publicSet | Sort-Object -Unique)
    if ($publicSet.Count -gt 0 -and $script:Outcome.Dns -eq "OK") {
        $overlap = @($dnsSystem.Addresses | Where-Object { $publicSet -contains $_ })
        if ($overlap.Count -eq 0) {
            Add-Flag "WARN" ("System DNS answers share NO addresses with public resolvers. Can be CDN rotation, but with mail symptoms treat as possible DNS redirection.")
            $script:Outcome.Dns = "MISMATCH"
        } else {
            Write-Log "  System answers overlap public resolvers - no sign of DNS tampering."
        }
    }
    if ((-not $dnsCf.Ok) -and (-not $dnsGoog.Ok)) {
        Add-Flag "INFO" "Direct queries to 1.1.1.1 and 8.8.8.8 both failed - this network blocks or redirects outbound DNS, so the cross-check could not run. Common on ISP routers; not itself a mail fault."
    }
} else {
    if ($dnsCf.Ok -or $dnsGoog.Ok) {
        Add-Flag "WARN" ("System resolver cannot resolve " + $MailHost + " but public resolvers can - local DNS problem or filtering.")
        $script:Outcome.Dns = "SYSTEM-FAIL"
    } else {
        Add-Flag "WARN" "No resolver could resolve the host - check basic connectivity first."
        $script:Outcome.Dns = "ALL-FAIL"
    }
}

# ---------------------------------------------------------------- hosts file
Write-Section "HOSTS FILE CHECK"
$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$script:Outcome.Hosts = "CLEAN"
if (Test-Path -LiteralPath $hostsPath) {
    $hostLines = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue)
    $hits = @($hostLines | Where-Object {
        ($_ -notmatch '^\s*#') -and ($_ -match '(?i)charter|spectrum|twc\.com|rr\.com')
    })
    if ($hits.Count -gt 0) {
        foreach ($h in $hits) { Write-Log ("  OVERRIDE: " + $h.Trim()) }
        Add-Flag "CRITICAL" "Hosts file contains overrides for the mail provider's domains - remove/inspect these lines."
        $script:Outcome.Hosts = "OVERRIDDEN"
    } else {
        Write-Log "  No charter/spectrum/twc/rr.com entries in the hosts file."
    }
    $activeCount = @($hostLines | Where-Object { ($_ -notmatch '^\s*#') -and ($_.Trim() -ne "") }).Count
    Write-Log ("  Active (non-comment) hosts entries total: " + $activeCount)
} else {
    Write-Log "  Hosts file not found (unusual but not itself a mail problem)."
}

# ---------------------------------------------------------------- TCP reachability
Write-Section "TCP REACHABILITY"

function Test-TcpPort {
    param([string]$TargetHost, [int]$Port, [int]$TimeoutMs = 5000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
        $done = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $done) {
            $client.Close()
            return "TIMEOUT (filtered/dropped)"
        }
        $client.EndConnect($iar)
        $client.Close()
        return "OPEN"
    } catch {
        $msg = $_.Exception.Message
        if ($null -ne $_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        $client.Close()
        return ("CLOSED (" + $msg.Trim() + ")")
    }
}

$portNames = @{ 25 = "SMTP relay"; 143 = "IMAP plain"; 465 = "SMTPS implicit"; 587 = "SMTP submission"; 993 = "IMAPS implicit"; 995 = "POP3S implicit" }
$portState = @{}
foreach ($p in $Ports) {
    $state = Test-TcpPort -TargetHost $MailHost -Port $p
    $portState[$p] = $state
    $label = ""
    if ($portNames.ContainsKey($p)) { $label = $portNames[$p] }
    Write-Log ("  Port " + $p.ToString().PadRight(5) + $label.PadRight(16) + ": " + $state)
}
Write-Log ""
Write-Log "  Interpretation notes:"
Write-Log "   - Port 25 blocked/timeout is NORMAL on residential ISPs."
Write-Log "   - Spectrum does not listen on 465; CLOSED there matches known config."

# ---------------------------------------------------------------- SMTP 587
Write-Section "SMTP PORT 587 SESSION (greeting / EHLO / STARTTLS)"

$smtpClient = $null
$script:Outcome.Smtp587 = "NO_TCP"
try {
    $smtpClient = New-Object System.Net.Sockets.TcpClient
    $smtpClient.ReceiveTimeout = 8000
    $smtpClient.SendTimeout = 8000
    $iar = $smtpClient.BeginConnect($MailHost, 587, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(8000, $false)) { throw "TCP connect timed out" }
    $smtpClient.EndConnect($iar)

    $netStream = $smtpClient.GetStream()
    # Generous first wait: inspection devices and tarpits can delay the
    # greeting well past a normal server's response time.
    $netStream.ReadTimeout = 20000
    $netStream.WriteTimeout = 8000
    $reader = New-Object System.IO.StreamReader($netStream, [System.Text.Encoding]::ASCII)
    $writer = New-Object System.IO.StreamWriter($netStream, [System.Text.Encoding]::ASCII)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true

    Write-Log "  Waiting up to 20 s for the server greeting..."
    $greeting = Read-SmtpReply -Reader $reader
    $netStream.ReadTimeout = 8000
    if ($greeting.Count -eq 0) {
        Write-Log "  TCP connected but NO greeting arrived within 20 s."
        Add-Flag "CRITICAL" "Port 587 accepts the connection but stays silent - classic interception black-hole (or a tarpit)."
        $script:Outcome.Smtp587 = "NO_RESPONSE"
    } else {
        foreach ($g in $greeting) { Write-Log ("  S: " + $g) }

        Write-Log "  C: EHLO benchtoolkit.local"
        $writer.WriteLine("EHLO benchtoolkit.local")
        $capLines = Read-SmtpReply -Reader $reader
        foreach ($c in $capLines) { Write-Log ("  S: " + $c) }

        $allText = (($greeting + $capLines) -join "`n")
        $hasStartTls = ($capLines -join "`n") -match '(?im)^250[- ]STARTTLS'
        $masked = ($allText -match 'X{4,}' -or $allText -match '\*{4,}')

        if ($capLines.Count -eq 0) {
            Add-Flag "CRITICAL" "Greeting arrived but EHLO got NO reply - session is being interfered with mid-stream."
            $script:Outcome.Smtp587 = "NO_RESPONSE"
        } elseif ($masked) {
            Add-Flag "CRITICAL" "Banner/capabilities are MASKED (XXXX/****) - signature of Cisco ESMTP inspection (ASA/Firepower 'fixup smtp') on the path."
            $script:Outcome.Smtp587 = "MASKED"
        } elseif (-not $hasStartTls) {
            Add-Flag "CRITICAL" "EHLO capability list does NOT advertise STARTTLS. Spectrum's submission server is known to offer it, so something on the path is stripping it."
            $script:Outcome.Smtp587 = "STARTTLS_ABSENT"
        } else {
            Write-Log "  STARTTLS is advertised - attempting the TLS upgrade..."
            Write-Log "  C: STARTTLS"
            $writer.WriteLine("STARTTLS")
            $stResp = Read-SmtpReply -Reader $reader
            foreach ($r in $stResp) { Write-Log ("  S: " + $r) }
            if ($stResp.Count -gt 0 -and $stResp[0] -match '^220') {
                $script:TlsPolicyErrors = $null
                $ssl = New-Object System.Net.Security.SslStream($netStream, $false, $script:CertCallback)
                try {
                    $protos = [System.Security.Authentication.SslProtocols]([System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls)
                    $ssl.AuthenticateAsClient($MailHost, $null, $protos, $false)
                    Write-Log "  TLS handshake SUCCEEDED. Server certificate:"
                    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                    $certVerdict = Write-CertDetails -Cert $cert2 -Ssl $ssl
                    $script:Outcome.SmtpCert = $certVerdict
                    $script:Outcome.Smtp587 = "STARTTLS_OK"

                    # EHLO again inside TLS to show the real capability list (AUTH etc.)
                    $sslWriter = New-Object System.IO.StreamWriter($ssl, [System.Text.Encoding]::ASCII)
                    $sslWriter.NewLine = "`r`n"
                    $sslWriter.AutoFlush = $true
                    $sslReader = New-Object System.IO.StreamReader($ssl, [System.Text.Encoding]::ASCII)
                    Write-Log "  C: EHLO benchtoolkit.local   (inside TLS)"
                    $sslWriter.WriteLine("EHLO benchtoolkit.local")
                    $tlsCaps = Read-SmtpReply -Reader $sslReader
                    foreach ($c in $tlsCaps) { Write-Log ("  S: " + $c) }
                    $sslWriter.WriteLine("QUIT")
                } catch {
                    Add-Flag "CRITICAL" ("STARTTLS advertised and accepted, but the TLS HANDSHAKE WAS KILLED: " + $_.Exception.Message + " - classic STARTTLS-stripping interceptor that panics at the ClientHello.")
                    $script:Outcome.Smtp587 = "UPGRADE_KILLED"
                }
            } else {
                Add-Flag "CRITICAL" "STARTTLS advertised but the STARTTLS command was refused or unanswered - interference mid-session."
                $script:Outcome.Smtp587 = "UPGRADE_KILLED"
            }
        }
    }
} catch {
    Write-Log ("  Could not establish TCP to " + $MailHost + ":587 - " + $_.Exception.Message)
    $script:Outcome.Smtp587 = "NO_TCP"
} finally {
    if ($null -ne $smtpClient) { try { $smtpClient.Close() } catch { } }
}

# ---------------------------------------------------------------- IMAP 993
Write-Section "IMAP PORT 993 (implicit TLS handshake + banner)"

$imapClient = $null
$imapSslReader = $null
$imapSslWriter = $null
$imapConnected = $false
$script:Outcome.Imap993 = "FAILED"
try {
    $imapClient = New-Object System.Net.Sockets.TcpClient
    $imapClient.ReceiveTimeout = 8000
    $imapClient.SendTimeout = 8000
    $iar = $imapClient.BeginConnect($MailHost, 993, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(8000, $false)) { throw "TCP connect timed out" }
    $imapClient.EndConnect($iar)

    $imapNet = $imapClient.GetStream()
    $imapNet.ReadTimeout = 8000
    $imapNet.WriteTimeout = 8000
    $script:TlsPolicyErrors = $null
    $imapSsl = New-Object System.Net.Security.SslStream($imapNet, $false, $script:CertCallback)
    $protos = [System.Security.Authentication.SslProtocols]([System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls)
    $imapSsl.AuthenticateAsClient($MailHost, $null, $protos, $false)
    Write-Log "  TLS handshake SUCCEEDED. Server certificate:"
    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($imapSsl.RemoteCertificate)
    [void](Write-CertDetails -Cert $cert2 -Ssl $imapSsl)

    $imapSslReader = New-Object System.IO.StreamReader($imapSsl, [System.Text.Encoding]::ASCII)
    $imapSslWriter = New-Object System.IO.StreamWriter($imapSsl, [System.Text.Encoding]::ASCII)
    $imapSslWriter.NewLine = "`r`n"
    $imapSslWriter.AutoFlush = $true

    $banner = $imapSslReader.ReadLine()
    if ($null -ne $banner) {
        Write-Log ("  S: " + $banner)
        if ($banner -match '(?i)InterMail') {
            Write-Log "  Banner shows InterMail - consistent with the known-good Spectrum/Charter backend."
        }
        $script:Outcome.Imap993 = "OK"
        $imapConnected = $true
    } else {
        Add-Flag "WARN" "TLS came up on 993 but no IMAP banner arrived."
        $script:Outcome.Imap993 = "TLS-OK-NO-BANNER"
    }
} catch {
    Add-Flag "WARN" ("IMAP 993 TLS session failed: " + $_.Exception.Message)
    $script:Outcome.Imap993 = "FAILED"
}

# ---------------------------------------------------------------- optional credential test
Write-Section "OPTIONAL CREDENTIAL TEST (IMAP LOGIN)"
if ($SkipCredentialTest) {
    Write-Log "  Skipped (-SkipCredentialTest)."
} elseif (-not $imapConnected) {
    Write-Log "  Skipped - no working IMAP TLS session to test against."
} else {
    Write-Log "  WARNING: Spectrum throttles and can LOCK accounts after failed logins"
    Write-Log "  (INVALIDCREDENTIALS / TEMPORARILYUNAVAILABLE responses). Only run this"
    Write-Log "  AFTER the password has just been verified at webmail.spectrum.net."
    $ans = ""
    try { $ans = Read-Host "  Attempt credential test now? (y/N)" } catch { $ans = "" }
    if ($ans -match '^[Yy]') {
        $confirm = ""
        try { $confirm = Read-Host "  Type YES to confirm the password was just verified in webmail" } catch { $confirm = "" }
        if ($confirm -cne "YES") {
            Write-Log "  Credential test skipped (not confirmed)."
        } else {
            $imapUser = ""
            try { $imapUser = Read-Host "  Email address (full address)" } catch { $imapUser = "" }
            if ($imapUser.Trim() -eq "") {
                Write-Log "  No username entered - skipped."
            } else {
                $secPass = $null
                try { $secPass = Read-Host "  Password" -AsSecureString } catch { $secPass = $null }
                if ($null -eq $secPass) {
                    Write-Log "  No password entered - skipped."
                } else {
                    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secPass)
                    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                    $userEsc = $imapUser -replace '\\', '\\' -replace '"', '\"'
                    $passEsc = $plain -replace '\\', '\\' -replace '"', '\"'
                    Write-Log ("  C: a1 LOGIN " + $imapUser + " ********")
                    $imapSslWriter.WriteLine('a1 LOGIN "' + $userEsc + '" "' + $passEsc + '"')
                    $plain = $null
                    $passEsc = $null
                    $loginReply = Read-ImapReply -Reader $imapSslReader -Tag "a1"
                    foreach ($l in $loginReply) { Write-Log ("  S: " + $l) }
                    $final = ""
                    foreach ($l in $loginReply) { if ($l -like "a1 *") { $final = $l } }
                    if ($final -match '^a1 OK') {
                        Write-Log "  LOGIN SUCCEEDED - credentials and account are fine; the problem is not auth."
                        $script:Outcome.Cred = "OK"
                    } elseif ($final -match '^a1 NO') {
                        $script:Outcome.Cred = "REFUSED"
                        if ($final -match '(?i)TEMPORARILYUNAVAILABLE|UNAVAILABLE|THROTTL|TOO MANY') {
                            Add-Flag "WARN" "Login refused with a throttle/temporary marker - account is rate-limited or locked. STOP retrying; wait and verify via webmail later."
                        } elseif ($final -match '(?i)INVALIDCREDENTIALS|AUTHENTICATIONFAILED') {
                            Add-Flag "WARN" "Login refused as invalid credentials. Note Spectrum also returns this while an account is lockout-throttled, so it does not prove the password is wrong."
                        } else {
                            Add-Flag "WARN" ("Login refused: " + $final)
                        }
                    } elseif ($final -match '^a1 BAD') {
                        Write-Log "  Server rejected the command syntax. Passwords with unusual characters may need a manual client test instead."
                        $script:Outcome.Cred = "SYNTAX"
                    } else {
                        Write-Log "  No tagged reply arrived - connection may have been dropped."
                        $script:Outcome.Cred = "NO-REPLY"
                    }
                }
            }
        }
    } else {
        Write-Log "  Credential test skipped."
    }
}
if ($imapConnected) {
    try { $imapSslWriter.WriteLine("a9 LOGOUT") } catch { }
}
if ($null -ne $imapClient) { try { $imapClient.Close() } catch { } }

# ---------------------------------------------------------------- verdict
Write-Section "VERDICT"

switch ($script:Outcome.Smtp587) {
    "STARTTLS_OK" {
        if ($script:Outcome.SmtpCert -eq "OK") {
            Write-Log "  SMTP 587: CLEAN on this path. Greeting, EHLO, STARTTLS and the TLS"
            Write-Log "  upgrade all completed against the provider's own certificate."
        } else {
            Write-Log "  SMTP 587: TLS completes but the CERTIFICATE IS NOT THE PROVIDER'S."
            Write-Log "  Something is man-in-the-middling TLS on this path (see flags)."
        }
    }
    "UPGRADE_KILLED" {
        Write-Log "  SMTP 587: STARTTLS INTERFERENCE CONFIRMED. The upgrade is being killed"
        Write-Log "  in-flight. An interceptor between this machine and the server is"
        Write-Log "  breaking TLS on the submission port."
    }
    "STARTTLS_ABSENT" {
        Write-Log "  SMTP 587: STARTTLS STRIPPING SIGNATURE. The server reachable from here"
        Write-Log "  does not advertise STARTTLS, which the real Spectrum server does."
        Write-Log "  An in-path device is editing the EHLO capability list."
    }
    "MASKED" {
        Write-Log "  SMTP 587: capabilities are masked (XXXX/****) - Cisco ESMTP inspection"
        Write-Log "  (ASA/Firepower) is active on this path and is the likely mail breaker."
    }
    "NO_RESPONSE" {
        Write-Log "  SMTP 587: TCP opens but SMTP dies (no greeting or no EHLO reply)."
        Write-Log "  Consistent with an interception proxy holding the socket."
    }
    "NO_TCP" {
        Write-Log "  SMTP 587: not reachable at TCP level from this machine/network."
    }
}
Write-Log ""
if ($script:Outcome.Imap993 -eq "OK") {
    Write-Log "  IMAP 993: healthy. Implicit TLS + banner work, so RECEIVING mail is fine;"
    Write-Log "  whatever is wrong is specific to the 587 submission path."
} else {
    Write-Log ("  IMAP 993: " + $script:Outcome.Imap993 + " - both directions are affected; suspect broader interception or connectivity.")
}
Write-Log ""
if ($script:Flags.Count -gt 0) {
    Write-Log "  All flags raised this run:"
    foreach ($f in $script:Flags) { Write-Log ("    " + $f) }
} else {
    Write-Log "  No flags raised this run."
}

Write-Log ""
Write-Log "  NEXT STEP - SPLIT MACHINE vs NETWORK:"
Write-Log "  Run this same script from the stick on a SECOND machine on the SAME network."
Write-Log "    - Both machines show the same 587 failure -> network-side interception"
Write-Log "      (router/UTM/security appliance, ISP, or upstream middlebox)."
Write-Log "    - Only this unit fails -> machine-side interception (AV mail shield,"
Write-Log "      Winsock LSP, WFP filter, proxy, malware). Run 3_SystemInspection.ps1"
Write-Log "      on the unit next."
Write-Log "    - If possible also test the unit on a different network (hotspot):"
Write-Log "      failing everywhere -> strongly machine-side or account-side."
Write-Log ""
Write-Log ("Report saved to: " + $ReportFile)
