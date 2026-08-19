=======================================================================
BenchToolkit - portable mail / interception diagnostics
=======================================================================
Pure Windows PowerShell 5.1, zero third-party dependencies. Every
script writes a timestamped report to reports\ next to the scripts
(i.e. onto this stick when run from the stick).

LAYOUT
  1_DownloadTools.cmd      tool fetcher            - runs on the BENCH PC
  2_MailDiagnostics.ps1    mail path probe         - runs on ANY machine
  3_SystemInspection.ps1   interception hunt       - runs on the UNIT
  4_AclInvestigate.ps1     locked-folder digger    - runs on the UNIT
  Tools\Sysinternals\      populated by script 1
  reports\                 all output lands here

HOW TO RUN A SCRIPT
  Open PowerShell AS ADMINISTRATOR, then:
    powershell -ExecutionPolicy Bypass -File X:\BenchToolkit\2_MailDiagnostics.ps1
  (replace X: with whatever letter the stick gets on that machine;
  $PSScriptRoot handles the rest, reports always land on the stick)

USAGE ORDER FOR A "MAIL WON'T SEND / STARTTLS" TICKET
  0. Once, on the bench PC (online): run 1_DownloadTools.cmd to fill
     Tools\Sysinternals. Never run this on a customer unit.
  1. On the customer unit: 2_MailDiagnostics.ps1
     - It probes DNS (system vs 1.1.1.1 vs 8.8.8.8), the hosts file,
       TCP 25/143/465/587/993/995, does a full EHLO/STARTTLS attempt on
       587 with certificate details, and an implicit-TLS check on 993.
  2. On a SECOND machine on the SAME network: run script 2 again.
     - Both fail the same way  -> network-side (router/UTM/appliance/ISP)
     - Only the unit fails     -> machine-side  -> go to step 3
     - If possible, also try the unit on a hotspot: fails everywhere
       -> strongly machine-side or account-side.
  3. On the unit, elevated: 3_SystemInspection.ps1
     - AV registration, proxy/PAC, Winsock LSPs, WFP filters (including
       anything referencing port 587), non-Microsoft services / tasks /
       Run keys with signature flags, netstat, and a name search
       (default string: rogueyoutube; override with -SearchString).
  4. If a suspicious folder denies access even to admins:
     4_AclInvestigate.ps1 "C:\path\to\folder"
     - Read-only first; it only runs takeown/icacls after you type
       TAKEOWN. Ends with SHA256 hashes for VirusTotal lookup.

REMINDERS
  * Run everything from an ELEVATED PowerShell. Scripts 2 and 4 warn
    but continue degraded; script 3 loses WFP export and netstat -b
    without elevation.
  * CREDENTIAL TEST (script 2): only after the password has JUST been
    verified at webmail.spectrum.net. Spectrum throttles and locks
    accounts on failed logins (INVALIDCREDENTIALS /
    TEMPORARILYUNAVAILABLE). The test is opt-in at a prompt and needs
    a typed YES; when in doubt, skip it.
  * Port 25 timing out is normal on residential ISPs. Spectrum does
    not listen on 465 - "refused" there is expected, not a fault.
  * The scripts are read-only except: the opt-in credential test
    (script 2) and the opt-in TAKEOWN phase (script 4). Nothing else
    writes to the customer machine; reports go to the stick.
  * Sysinternals tools need -accepteula on first run, e.g.:
      Tools\Sysinternals\autorunsc.exe -accepteula -a *
    Useful here: autorunsc, procexp, sigcheck, streams, accesschk,
    tcpview.
  * Reports may contain machine names and account identifiers -
    treat the stick's reports\ folder as customer data: keep it on
    the stick, do not sync it anywhere.
=======================================================================
