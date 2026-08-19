# =====================================================================
# 3_SystemInspection.ps1 - BenchToolkit interception / malware hunt
# ---------------------------------------------------------------------
# Run ON THE CUSTOMER UNIT (as Administrator) after 2_MailDiagnostics
# points at a machine-side cause. Read-only: this script changes
# nothing on the machine; it only inventories the places where mail
# interception and persistence live.
#
# Covers: AV registration, proxy config, Winsock catalog (LSP hunt),
# WFP filters (non-Microsoft providers + port 587 references),
# non-Microsoft services / scheduled tasks / Run keys with signature
# flagging, netstat snapshot, and a filesystem+registry search for a
# configurable string.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File 3_SystemInspection.ps1
#   ... -SearchString "somename"     (default: rogueyoutube)
#   ... -Quick                       (skip the slow deep searches)
#
# Report: reports\SystemInspection_<computer>_<timestamp>.txt
# =====================================================================
[CmdletBinding()]
param(
    [string]$SearchString = "rogueyoutube",
    [switch]$Quick,
    [string]$ReportDir = ""
)

$ErrorActionPreference = "Continue"

if ($ReportDir -eq "") { $ReportDir = Join-Path $PSScriptRoot "reports" }
if (-not (Test-Path -LiteralPath $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ReportDir ("SystemInspection_" + $env:COMPUTERNAME + "_" + $Stamp + ".txt")

$script:Flags = New-Object System.Collections.ArrayList

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

function Get-ExeFromCommand {
    # Pulls the executable path out of a service/task/runkey command line.
    param([string]$Command)
    if ($null -eq $Command -or $Command.Trim() -eq "") { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    if ($c.StartsWith('"')) {
        if ($c -match '^"([^"]+)"') { return $matches[1] }
        return $null
    }
    # Unquoted path, possibly with spaces: take everything up to the
    # first executable extension ("C:\Program Files\App\app.exe -flag").
    if ($c -match '^(.+?\.(exe|dll|sys|cmd|bat))(\s|$)') { return $matches[1] }
    if ($c -match '^(\S+)') { return $matches[1] }
    return $null
}

function Get-SigInfo {
    param([string]$ExePath)
    if ($null -eq $ExePath -or $ExePath -eq "") { return "NO PATH" }
    if (-not (Test-Path -LiteralPath $ExePath)) { return ("FILE NOT FOUND: " + $ExePath) }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction Stop
        if ($sig.Status -eq "Valid") {
            $signer = ""
            if ($null -ne $sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
            return ("Signed: " + $signer)
        }
        return ("SIGNATURE " + $sig.Status.ToString().ToUpper())
    } catch {
        return ("SIG CHECK FAILED: " + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- header
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
$IsAdmin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Log ("BenchToolkit system inspection - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Log ("Computer : " + $env:COMPUTERNAME + "   User: " + $env:USERNAME)
Write-Log ("Search   : '" + $SearchString + "'   Quick mode: " + $Quick.IsPresent)
Write-Log ("Admin    : " + $IsAdmin)
if (-not $IsAdmin) {
    Add-Flag "WARN" "NOT elevated - WFP export and netstat -b will be skipped. Rerun as Administrator for full coverage."
}
Write-Log ("Report   : " + $ReportFile)

# ---------------------------------------------------------------- OS + AV
Write-Section "OS AND REGISTERED SECURITY PRODUCTS"
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Log ("  OS       : " + $os.Caption + " (" + $os.OSArchitecture + ")")
    Write-Log ("  Version  : " + $os.Version + " build " + $os.BuildNumber)
    $dispVer = ""
    try { $dispVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop).DisplayVersion } catch { }
    if ($dispVer) { Write-Log ("  Feature  : " + $dispVer) }
    Write-Log ("  Booted   : " + $os.LastBootUpTime)
} catch {
    Write-Log ("  OS query failed: " + $_.Exception.Message)
}
Write-Log ""
foreach ($cls in @("AntiVirusProduct", "AntiSpywareProduct", "FirewallProduct")) {
    try {
        $prods = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName $cls -ErrorAction Stop)
        foreach ($p in $prods) {
            $hex = "{0:X6}" -f $p.productState
            $rt = "unknown"
            if ($hex.Length -ge 4) {
                $b = $hex.Substring(2, 2)
                if ($b -eq "10" -or $b -eq "11") { $rt = "enabled" }
                if ($b -eq "00" -or $b -eq "01") { $rt = "disabled" }
            }
            Write-Log ("  " + $cls.PadRight(20) + ": " + $p.displayName + "  state=0x" + $hex + " (realtime " + $rt + " - decode is approximate)")
            if ($p.pathToSignedProductExe) { Write-Log ("      exe: " + $p.pathToSignedProductExe) }
            if ($cls -eq "AntiVirusProduct" -and $p.displayName -notmatch '(?i)defender') {
                Add-Flag "INFO" ("Third-party AV registered: " + $p.displayName + " - AV mail shields are the top machine-side STARTTLS breaker. Check its mail/SSL scanning module.")
            }
        }
        if ($prods.Count -eq 0) { Write-Log ("  " + $cls.PadRight(20) + ": none registered") }
    } catch {
        Write-Log ("  " + $cls.PadRight(20) + ": query failed (server SKU has no SecurityCenter2) - " + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- proxy
Write-Section "PROXY CONFIGURATION"
Write-Log "  netsh winhttp show proxy:"
$winhttp = netsh winhttp show proxy
foreach ($l in @($winhttp)) { Write-Log ("    " + ("" + $l).Trim()) }
Write-Log ""
Write-Log "  Per-user (HKCU Internet Settings):"
try {
    $is = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop
    $pe = 0
    if ($null -ne $is.ProxyEnable) { $pe = $is.ProxyEnable }
    Write-Log ("    ProxyEnable   : " + $pe)
    Write-Log ("    ProxyServer   : " + ("" + $is.ProxyServer))
    Write-Log ("    AutoConfigURL : " + ("" + $is.AutoConfigURL))
    if ($pe -ne 0 -and $is.ProxyServer) {
        Add-Flag "WARN" ("A per-user proxy is SET: " + $is.ProxyServer + " - all mail-over-HTTP and possibly more is being routed through it.")
    }
    if ($is.AutoConfigURL) {
        Add-Flag "WARN" ("A PAC script is configured: " + $is.AutoConfigURL + " - PAC files are a classic silent interception vector.")
    }
    if ($pe -eq 0 -and -not $is.ProxyServer -and -not $is.AutoConfigURL) {
        Write-Log "    No user proxy or PAC configured."
    }
} catch {
    Write-Log ("    Query failed: " + $_.Exception.Message)
}

# ---------------------------------------------------------------- winsock
Write-Section "WINSOCK CATALOG (LSP / provider hunt)"
Write-Log "  Providers parsed from the registry catalog. Anything outside"
Write-Log "  \Windows\System32 or \Windows\SysWOW64 is flagged."
Write-Log ""
$catalogRoots = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64"
)
$wsCount = 0
$wsFlagged = 0
foreach ($root in $catalogRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $entries = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)
    foreach ($e in $entries) {
        try {
            $item = (Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction Stop).PackedCatalogItem
            if ($null -eq $item) { continue }
            $z = [Array]::IndexOf($item, [byte]0)
            if ($z -le 0) { continue }
            $dllPath = [System.Text.Encoding]::ASCII.GetString($item, 0, $z)
            $expanded = [Environment]::ExpandEnvironmentVariables($dllPath)
            $wsCount++
            if ($expanded -notmatch '(?i)\\windows\\(system32|syswow64)\\') {
                $wsFlagged++
                Add-Flag "CRITICAL" ("Winsock provider OUTSIDE system32: " + $expanded + "  (" + $e.PSChildName + " in " + $root.Split('\')[-1] + ") - LSP-style interception candidate. Sig: " + (Get-SigInfo -ExePath $expanded))
            }
        } catch { }
    }
}
# Namespace providers keep their path in a plain value.
$nsRoots = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries",
    "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64"
)
foreach ($root in $nsRoots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    $entries = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)
    foreach ($e in $entries) {
        try {
            $p = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction Stop
            $lib = "" + $p.LibraryPath
            if ($lib -eq "") { continue }
            $expanded = [Environment]::ExpandEnvironmentVariables($lib)
            $wsCount++
            if ($expanded -notmatch '(?i)\\windows\\(system32|syswow64)\\') {
                $wsFlagged++
                Add-Flag "CRITICAL" ("Winsock NAMESPACE provider outside system32: " + $expanded + " (" + ("" + $p.DisplayString) + ") Sig: " + (Get-SigInfo -ExePath $expanded))
            }
        } catch { }
    }
}
Write-Log ("  Catalog entries inspected: " + $wsCount + "   flagged: " + $wsFlagged)
if ($wsFlagged -eq 0) { Write-Log "  Winsock catalog is clean (all providers under the Windows directory)." }
Write-Log ""
Write-Log "  Raw catalog (netsh winsock show catalog):"
$wsRaw = netsh winsock show catalog
foreach ($l in @($wsRaw)) { Write-Log ("    " + ("" + $l)) }

# ---------------------------------------------------------------- WFP
Write-Section "WINDOWS FILTERING PLATFORM (WFP)"
if (-not $IsAdmin) {
    Write-Log "  Skipped - WFP export needs elevation. Rerun as Administrator."
} else {
    $wfpFilters = Join-Path $env:TEMP ("wfp_filters_" + $Stamp + ".xml")
    $wfpState = Join-Path $env:TEMP ("wfp_state_" + $Stamp + ".xml")
    Write-Log "  Exporting filters and state (state export can take a minute)..."
    netsh wfp show filters file="$wfpFilters" | Out-Null
    netsh wfp show state file="$wfpState" | Out-Null

    $provName = @{}
    if (Test-Path -LiteralPath $wfpState) {
        try {
            [xml]$stateDoc = Get-Content -LiteralPath $wfpState -Raw
            foreach ($p in $stateDoc.SelectNodes("//providers/item")) {
                $k = "" + $p.providerKey
                $n = ""
                if ($null -ne $p.displayData) { $n = "" + $p.displayData.name }
                if ($k -ne "") { $provName[$k] = $n }
            }
            Write-Log ("  Providers registered: " + $provName.Count)
            foreach ($k in $provName.Keys) {
                $n = $provName[$k]
                if ($n -ne "" -and $n -notmatch '(?i)microsoft|windows') {
                    Add-Flag "WARN" ("Non-Microsoft WFP provider registered: '" + $n + "' " + $k + " - this product can silently drop/redirect traffic.")
                } else {
                    Write-Log ("    " + $k + "  " + $n)
                }
            }
        } catch {
            Write-Log ("  Could not parse state XML: " + $_.Exception.Message)
        }
    } else {
        Write-Log "  State export did not produce a file."
    }

    if (Test-Path -LiteralPath $wfpFilters) {
        try {
            [xml]$fDoc = Get-Content -LiteralPath $wfpFilters -Raw
            $items = $fDoc.SelectNodes("//item[filterKey]")
            Write-Log ("  Active filters: " + $items.Count)
            $port587 = New-Object System.Collections.ArrayList
            $foreign = New-Object System.Collections.ArrayList
            foreach ($it in $items) {
                $x = $it.OuterXml
                $fname = ""
                if ($null -ne $it.displayData) { $fname = "" + $it.displayData.name }
                $pk = "" + $it.providerKey
                $pn = ""
                if ($pk -ne "" -and $provName.ContainsKey($pk)) { $pn = $provName[$pk] }
                $action = ""
                if ($null -ne $it.action) { $action = "" + $it.action.type }
                if (($x -match 'PORT') -and ($x -match '>587<')) {
                    [void]$port587.Add(("    [" + $action + "] '" + $fname + "'  provider: " + $pn + " " + $pk))
                }
                if ($pn -ne "" -and $pn -notmatch '(?i)microsoft|windows') {
                    [void]$foreign.Add(("    [" + $action + "] '" + $fname + "'  provider: " + $pn))
                }
            }
            Write-Log ""
            Write-Log ("  Filters referencing port 587: " + $port587.Count)
            foreach ($l in @($port587 | Select-Object -First 50)) { Write-Log $l }
            if ($port587.Count -gt 0) {
                Add-Flag "CRITICAL" ("WFP has " + $port587.Count + " filter(s) that reference port 587 - direct evidence of submission-port tampering. See list in report.")
            }
            Write-Log ""
            Write-Log ("  Filters owned by non-Microsoft providers: " + $foreign.Count + " (first 100 listed)")
            foreach ($l in @($foreign | Select-Object -First 100)) { Write-Log $l }
            if ($foreign.Count -gt 200) { Write-Log ("    ...and " + ($foreign.Count - 100) + " more - see the XML export.") }
        } catch {
            Write-Log ("  Could not parse filters XML: " + $_.Exception.Message)
            Write-Log "  Falling back to raw text search for '587':"
            $raw = @(Select-String -LiteralPath $wfpFilters -Pattern '587' -Context 4, 4 | Select-Object -First 10)
            foreach ($m in $raw) { Write-Log ("    line " + $m.LineNumber + ": " + $m.Line.Trim()) }
        }
    } else {
        Write-Log "  Filter export did not produce a file."
    }
    Write-Log ""
    Write-Log ("  Full XML exports kept for evidence: " + $wfpFilters)
    Write-Log ("                                      " + $wfpState)
}

# ---------------------------------------------------------------- services
Write-Section "NON-MICROSOFT SERVICES (binary outside \Windows)"
$svcFlagged = 0
try {
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop)
    foreach ($s in $svcs) {
        $exe = Get-ExeFromCommand -Command $s.PathName
        if ($null -eq $exe) { continue }
        if ($exe -like ($env:windir + "\*")) { continue }
        $sig = Get-SigInfo -ExePath $exe
        Write-Log ("  " + $s.Name + " (" + $s.State + ", " + $s.StartMode + ")")
        Write-Log ("      cmd : " + $s.PathName)
        Write-Log ("      sig : " + $sig)
        if ($sig -notlike "Signed:*") {
            $svcFlagged++
            Add-Flag "WARN" ("Service '" + $s.Name + "' binary is not validly signed: " + $exe + " (" + $sig + ")")
        }
    }
    Write-Log ("  Non-Windows-dir services listed above. Unsigned flagged: " + $svcFlagged)
} catch {
    Write-Log ("  Service enumeration failed: " + $_.Exception.Message)
}

# ---------------------------------------------------------------- scheduled tasks
Write-Section "NON-MICROSOFT SCHEDULED TASKS"
try {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike "\Microsoft\*" })
    Write-Log ("  Tasks outside \Microsoft\: " + $tasks.Count)
    foreach ($t in $tasks) {
        Write-Log ("  " + $t.TaskPath + $t.TaskName + "  (" + $t.State + ")")
        foreach ($a in @($t.Actions)) {
            $execProp = $a.PSObject.Properties["Execute"]
            if ($null -eq $execProp -or $null -eq $execProp.Value -or $execProp.Value -eq "") { continue }
            $exe = Get-ExeFromCommand -Command $execProp.Value
            $argProp = $a.PSObject.Properties["Arguments"]
            $argText = ""
            if ($null -ne $argProp -and $null -ne $argProp.Value) { $argText = $argProp.Value }
            $sig = Get-SigInfo -ExePath $exe
            Write-Log ("      run : " + $execProp.Value + " " + $argText)
            Write-Log ("      sig : " + $sig)
            if ($sig -notlike "Signed:*" -and $sig -ne "NO PATH") {
                Add-Flag "WARN" ("Task '" + $t.TaskName + "' runs a binary that is not validly signed: " + $exe + " (" + $sig + ")")
            }
        }
    }
} catch {
    Write-Log ("  Task enumeration failed: " + $_.Exception.Message)
}

# ---------------------------------------------------------------- run keys
Write-Section "RUN / RUNONCE KEYS"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($rk in $runKeys) {
    if (-not (Test-Path -LiteralPath $rk)) { continue }
    Write-Log ("  " + $rk)
    try {
        $props = Get-ItemProperty -LiteralPath $rk -ErrorAction Stop
        $any = $false
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $any = $true
            $exe = Get-ExeFromCommand -Command ("" + $p.Value)
            $sig = Get-SigInfo -ExePath $exe
            Write-Log ("      " + $p.Name + " = " + $p.Value)
            Write-Log ("          sig : " + $sig)
            if ($sig -notlike "Signed:*" -and $sig -ne "NO PATH") {
                Add-Flag "WARN" ("Run entry '" + $p.Name + "' is not validly signed: " + $exe + " (" + $sig + ")")
            }
        }
        if (-not $any) { Write-Log "      (empty)" }
    } catch {
        Write-Log ("      read failed: " + $_.Exception.Message)
    }
}

# ---------------------------------------------------------------- netstat
Write-Section "NETSTAT SNAPSHOT"
if ($IsAdmin) {
    Write-Log "  netstat -abno (owning process names included):"
    $ns = netstat -abno
} else {
    Write-Log "  netstat -ano (rerun elevated to get process names via -b):"
    $ns = netstat -ano
}
foreach ($l in @($ns)) { Write-Log ("  " + ("" + $l)) }

# ---------------------------------------------------------------- targeted search
Write-Section ("TARGETED SEARCH: '" + $SearchString + "'")
$pat = [regex]::Escape($SearchString)

Write-Log "  --- Windows Firewall rules ---"
try {
    $fwRules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
        ($_.DisplayName -match $pat) -or ($_.Name -match $pat) -or ($_.Description -match $pat)
    })
    if ($fwRules.Count -eq 0) {
        Write-Log "  No firewall rules match."
    }
    foreach ($r in $fwRules) {
        Write-Log ("  RULE: '" + $r.DisplayName + "'  enabled=" + $r.Enabled + " dir=" + $r.Direction + " action=" + $r.Action + " profile=" + $r.Profile)
        try {
            $app = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop
            Write-Log ("        program: " + $app.Program)
            $exe = [Environment]::ExpandEnvironmentVariables("" + $app.Program)
            if ($exe -and $exe -ne "Any") {
                Write-Log ("        sig    : " + (Get-SigInfo -ExePath $exe))
            }
        } catch { }
        Add-Flag "CRITICAL" ("Firewall rule matching '" + $SearchString + "' found: '" + $r.DisplayName + "' (" + $r.Direction + "/" + $r.Action + ")")
    }
} catch {
    Write-Log ("  Firewall query failed: " + $_.Exception.Message)
}

Write-Log ""
Write-Log "  --- Registry: targeted hives ---"
$targetedKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    "HKLM:\SYSTEM\CurrentControlSet\Services"
)
$regHits = 0
foreach ($tk in $targetedKeys) {
    if (-not (Test-Path -LiteralPath $tk)) { continue }
    # Values directly on the key (FirewallRules stores rules as values).
    try {
        $base = Get-Item -LiteralPath $tk -ErrorAction Stop
        foreach ($vn in $base.GetValueNames()) {
            $vv = "" + $base.GetValue($vn)
            if (($vn -match $pat) -or ($vv -match $pat)) {
                $regHits++
                Write-Log ("  HIT " + $tk)
                Write-Log ("      " + $vn + " = " + $vv)
            }
        }
    } catch { }
    # One level of subkeys (uninstall entries, service keys).
    $subs = @(Get-ChildItem -Path $tk -ErrorAction SilentlyContinue)
    foreach ($sk in $subs) {
        try {
            if ($sk.PSChildName -match $pat) {
                $regHits++
                Write-Log ("  HIT (key name) " + $sk.Name)
            }
            foreach ($vn in $sk.GetValueNames()) {
                $vv = "" + $sk.GetValue($vn)
                if (($vn -match $pat) -or ($vv -match $pat)) {
                    $regHits++
                    Write-Log ("  HIT " + $sk.Name)
                    Write-Log ("      " + $vn + " = " + $vv)
                }
            }
        } catch { }
    }
}
if ($regHits -eq 0) { Write-Log "  No hits in targeted hives." }
else { Add-Flag "CRITICAL" ("Registry search found " + $regHits + " hit(s) for '" + $SearchString + "' in targeted hives - see report body.") }

if (-not $Quick) {
    Write-Log ""
    Write-Log "  --- Registry: deep search of HKLM:\SOFTWARE and HKCU:\Software ---"
    Write-Log "  (key names and string values; this can take several minutes)"
    $deepHits = 0
    foreach ($root in @("HKLM:\SOFTWARE", "HKCU:\Software")) {
        $keys = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue
        foreach ($k in $keys) {
            if ($deepHits -ge 200) { break }
            try {
                if ($k.PSChildName -match $pat) {
                    $deepHits++
                    Write-Log ("  HIT (key) " + $k.Name)
                }
                foreach ($vn in $k.GetValueNames()) {
                    $vv = "" + $k.GetValue($vn)
                    if (($vn -match $pat) -or ($vv -match $pat)) {
                        $deepHits++
                        Write-Log ("  HIT " + $k.Name)
                        Write-Log ("      " + $vn + " = " + $vv)
                    }
                }
            } catch { }
        }
    }
    if ($deepHits -eq 0) { Write-Log "  No hits in the deep registry search." }
    elseif ($deepHits -ge 200) { Write-Log "  Stopped at 200 hits (search string too broad?)." }
} else {
    Write-Log ""
    Write-Log "  Deep registry search skipped (-Quick)."
}

Write-Log ""
Write-Log "  --- Filesystem search (file/folder NAMES, not contents) ---"
$fsRoots = New-Object System.Collections.ArrayList
[void]$fsRoots.Add($env:ProgramData)
[void]$fsRoots.Add($env:ProgramFiles)
$pf86 = [Environment]::GetFolderPath("ProgramFilesX86")
if ($pf86) { [void]$fsRoots.Add($pf86) }
if (-not $Quick) {
    $usersRoot = Join-Path $env:SystemDrive "Users"
    if (Test-Path -LiteralPath $usersRoot) { [void]$fsRoots.Add($usersRoot) }
}
$fsHits = 0
foreach ($root in $fsRoots) {
    if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
    Write-Log ("  searching " + $root + " ...")
    $found = @(Get-ChildItem -Path $root -Recurse -Force -Filter ("*" + $SearchString + "*") -ErrorAction SilentlyContinue | Select-Object -First 100)
    foreach ($f in $found) {
        $fsHits++
        $kind = "FILE"
        if ($f.PSIsContainer) { $kind = "DIR " }
        Write-Log ("  HIT " + $kind + " " + $f.FullName)
        Write-Log ("      created " + $f.CreationTime + "   modified " + $f.LastWriteTime)
        if (-not $f.PSIsContainer -and $f.Extension -match '(?i)^\.(exe|dll|sys)$') {
            Write-Log ("      sig     : " + (Get-SigInfo -ExePath $f.FullName))
        }
    }
}
if ($fsHits -eq 0) { Write-Log "  No filesystem name hits." }
else { Add-Flag "CRITICAL" ("Filesystem search found " + $fsHits + " item(s) matching '" + $SearchString + "' - see report body. Use 4_AclInvestigate.ps1 on any access-denied folder.") }

# ---------------------------------------------------------------- summary
Write-Section "FLAG SUMMARY"
if ($script:Flags.Count -eq 0) {
    Write-Log "  No flags raised. If mail is still broken machine-side, the next"
    Write-Log "  suspects are inside the AV product's own config (mail/SSL scanning)"
    Write-Log "  or require offline inspection with the Sysinternals tools."
} else {
    foreach ($f in $script:Flags) { Write-Log ("  " + $f) }
}
Write-Log ""
Write-Log "  Reading the results:"
Write-Log "   - Winsock provider outside system32  -> LSP interception; research the DLL before removal."
Write-Log "   - WFP filters on port 587            -> the smoking gun for submission tampering; the provider name tells you whose."
Write-Log "   - Third-party AV registered          -> check its email/SSL-scanning module first; it is the most common cause."
Write-Log "   - PAC/proxy set                      -> follow the URL/server; malware PACs are usually local files or private IPs."
Write-Log ""
Write-Log ("Report saved to: " + $ReportFile)
