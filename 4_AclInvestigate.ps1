# =====================================================================
# 4_AclInvestigate.ps1 - BenchToolkit locked-folder investigation
# ---------------------------------------------------------------------
# For folders that deny access even to Administrators (e.g. a suspicious
# program directory protected by its own ACL). Runs ON THE UNIT as
# Administrator.
#
# Phase 1 (always, read-only): current ACL, owner, raw icacls view,
#   listing attempt.
# Phase 2 (only after you type TAKEOWN): takeown /R + icacls grant to
#   the Administrators group (by SID, locale-safe).
# Phase 3 (after a successful phase 2): full listing, alternate data
#   streams, Zone.Identifier contents, SHA256 of every file for
#   VirusTotal HASH lookup from another machine.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File 4_AclInvestigate.ps1 "C:\suspect\folder"
#   ... -ReadOnly     (never offer the takeown step)
#
# Report: reports\AclInvestigate_<computer>_<timestamp>.txt
# =====================================================================
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetPath,
    [switch]$ReadOnly,
    [string]$ReportDir = ""
)

$ErrorActionPreference = "Continue"

if ($ReportDir -eq "") { $ReportDir = Join-Path $PSScriptRoot "reports" }
if (-not (Test-Path -LiteralPath $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ReportDir ("AclInvestigate_" + $env:COMPUTERNAME + "_" + $Stamp + ".txt")

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

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
$IsAdmin = $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Log ("BenchToolkit ACL investigation - " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Write-Log ("Computer : " + $env:COMPUTERNAME + "   User: " + $env:USERNAME + "   Admin: " + $IsAdmin)
Write-Log ("Target   : " + $TargetPath)
Write-Log ("Report   : " + $ReportFile)
if (-not $IsAdmin) {
    Write-Log ""
    Write-Log "  WARNING: not elevated. Phase 1 may fail and phase 2 WILL fail."
    Write-Log "  Rerun from an elevated PowerShell."
}

# ---------------------------------------------------------------- phase 1
Write-Section "PHASE 1 - READ-ONLY INSPECTION"

$exists = Test-Path -LiteralPath $TargetPath
Write-Log ("  Test-Path: " + $exists)
if (-not $exists) {
    Write-Log "  Note: Test-Path returns False both for 'missing' and for 'access"
    Write-Log "  denied at a parent'. Continuing with direct queries."
}

try {
    $item = Get-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
    Write-Log ("  Attributes : " + $item.Attributes)
    Write-Log ("  Created    : " + $item.CreationTime)
    Write-Log ("  Modified   : " + $item.LastWriteTime)
} catch {
    Write-Log ("  Get-Item failed: " + $_.Exception.Message)
}

Write-Log ""
Write-Log "  --- Get-Acl ---"
$aclReadable = $false
try {
    $acl = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop
    $aclReadable = $true
    Write-Log ("  Owner : " + $acl.Owner)
    Write-Log ("  Group : " + $acl.Group)
    Write-Log "  Access entries:"
    foreach ($ace in $acl.Access) {
        $inh = "explicit"
        if ($ace.IsInherited) { $inh = "inherited" }
        Write-Log ("    " + $ace.AccessControlType.ToString().PadRight(6) + " " + $ace.IdentityReference.ToString().PadRight(35) + " " + $ace.FileSystemRights + "  (" + $inh + ")")
        if ($ace.AccessControlType -eq "Deny" -and $ace.IdentityReference -match '(?i)administrators|everyone|users') {
            Write-Log "      ^^ DENY entry against a broad principal - this is what locks admins out."
        }
    }
    Write-Log ("  SDDL  : " + $acl.Sddl)
} catch {
    Write-Log ("  Get-Acl FAILED: " + $_.Exception.Message)
    Write-Log "  An ACL that admins cannot even READ is itself a finding: normal"
    Write-Log "  software rarely removes READ_CONTROL from Administrators."
}

Write-Log ""
Write-Log "  --- icacls (raw view) ---"
$ic = icacls "$TargetPath"
foreach ($l in @($ic)) { Write-Log ("    " + ("" + $l)) }
Write-Log ("    icacls exit code: " + $LASTEXITCODE)

Write-Log ""
Write-Log "  --- Listing attempt ---"
try {
    $kids = @(Get-ChildItem -LiteralPath $TargetPath -Force -ErrorAction Stop)
    Write-Log ("  Listing OK - " + $kids.Count + " entries (details in phase 3 section).")
} catch {
    Write-Log ("  Listing FAILED: " + $_.Exception.Message)
}

# ---------------------------------------------------------------- phase 2
Write-Section "PHASE 2 - TAKE OWNERSHIP (opt-in)"

$tookOwnership = $false
if ($ReadOnly) {
    Write-Log "  Skipped (-ReadOnly)."
} elseif (-not $IsAdmin) {
    Write-Log "  Skipped - requires elevation."
} else {
    Write-Log "  This will run, recursively on the target:"
    Write-Log ("    takeown /F `"" + $TargetPath + "`" /R /D Y")
    Write-Log ("    icacls `"" + $TargetPath + "`" /grant *S-1-5-32-544:(OI)(CI)F /T")
    Write-Log "  (S-1-5-32-544 = local Administrators group, locale-safe)"
    Write-Log ""
    Write-Log "  NOTE: this permanently changes the folder's owner and ACL. If this"
    Write-Log "  job might need untouched evidence later, image/copy first and stop"
    Write-Log "  here - ownership changes cannot be un-taken."
    $answer = ""
    try { $answer = Read-Host "  Type TAKEOWN to proceed, anything else to stop" } catch { $answer = "" }
    if ($answer -cne "TAKEOWN") {
        Write-Log "  Not confirmed - stopping at the read-only phase."
    } else {
        Write-Log ""
        Write-Log "  --- takeown output ---"
        $to = takeown /F "$TargetPath" /R /D Y
        foreach ($l in @($to)) { Write-Log ("    " + ("" + $l)) }
        Write-Log ("    takeown exit code: " + $LASTEXITCODE)
        $toOk = ($LASTEXITCODE -eq 0)

        Write-Log ""
        Write-Log "  --- icacls grant output ---"
        $ig = icacls "$TargetPath" /grant "*S-1-5-32-544:(OI)(CI)F" /T
        foreach ($l in @($ig)) { Write-Log ("    " + ("" + $l)) }
        Write-Log ("    icacls exit code: " + $LASTEXITCODE)
        if ($LASTEXITCODE -eq 0 -and $toOk) {
            $tookOwnership = $true
        } else {
            Write-Log "  One of the commands reported errors - results below may be partial."
            $tookOwnership = $true
        }

        Write-Log ""
        Write-Log "  --- ACL after the change ---"
        try {
            $acl2 = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop
            Write-Log ("  Owner now: " + $acl2.Owner)
        } catch {
            Write-Log ("  Still cannot read ACL: " + $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------- phase 3
Write-Section "PHASE 3 - CONTENTS AND HASHES"

$files = @()
try {
    $all = @(Get-ChildItem -LiteralPath $TargetPath -Recurse -Force -ErrorAction Stop)
    Write-Log ("  Entries found: " + $all.Count)
    foreach ($e in $all) {
        $kind = "FILE"
        if ($e.PSIsContainer) { $kind = "DIR " }
        $size = ""
        if (-not $e.PSIsContainer) { $size = "  " + $e.Length + " bytes" }
        Write-Log ("  " + $kind + " " + $e.FullName + $size)
        Write-Log ("        created " + $e.CreationTime + "   modified " + $e.LastWriteTime + "   attrs " + $e.Attributes)
        if (-not $e.PSIsContainer) { $files = $files + @($e) }
    }
} catch {
    Write-Log ("  Recursive listing failed: " + $_.Exception.Message)
    if (-not $tookOwnership -and -not $ReadOnly) {
        Write-Log "  (Run again and confirm TAKEOWN in phase 2 to unlock it.)"
    }
}

if ($files.Count -gt 0) {
    Write-Log ""
    Write-Log "  --- Alternate data streams ---"
    $adsAny = $false
    foreach ($f in $files) {
        try {
            $streams = @(Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction Stop | Where-Object { $_.Stream -ne ':$DATA' })
            foreach ($s in $streams) {
                $adsAny = $true
                Write-Log ("  ADS: " + $f.FullName + " :: " + $s.Stream + " (" + $s.Length + " bytes)")
                if ($s.Stream -eq "Zone.Identifier") {
                    $zi = @(Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue)
                    foreach ($zl in $zi) { Write-Log ("       " + $zl) }
                    Write-Log "       (HostUrl/ReferrerUrl above = where this file was downloaded from)"
                }
            }
        } catch { }
    }
    if (-not $adsAny) { Write-Log "  None found." }

    Write-Log ""
    Write-Log "  --- SHA256 hashes (for VirusTotal lookup) ---"
    foreach ($f in $files) {
        if ($f.Length -gt 500MB) {
            Write-Log ("  SKIPPED (over 500 MB): " + $f.FullName)
            continue
        }
        try {
            $h = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop
            Write-Log ("  " + $h.Hash + "  " + $f.FullName)
        } catch {
            Write-Log ("  HASH FAILED (" + $_.Exception.Message.Trim() + "): " + $f.FullName)
        }
    }
    Write-Log ""
    Write-Log "  Next: on ANOTHER machine, search these hashes at virustotal.com"
    Write-Log "  (hash search only - do not upload files that could contain the"
    Write-Log "  customer's personal data; a hash lookup discloses nothing)."
    Write-Log "  Do NOT execute anything from this folder."
}

Write-Log ""
Write-Log ("Report saved to: " + $ReportFile)
