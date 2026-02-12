#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Hardens native Windows Defender (built-in antimalware) with configurable protection levels.

.DESCRIPTION
    This script configures Windows Defender using only the built-in, free antimalware
    engine included with Windows 10/11. No paid licenses or additional products required.

    Three protection levels are available:

    STANDARD  - Strong daily-use baseline. Enables all core protections, ASR rules,
                network protection, and exploit mitigations. Cloud blocking at High,
                Controlled Folder Access in Audit mode. Suitable for long-term use
                on production machines.

    HIGH      - Elevated protection for environments with heightened risk. Increases
                cloud blocking to High+, tightens ASR rules, increases scan frequency.
                Good for environments that have been through an incident and want
                sustained strong posture.

    MAX       - Maximum aggression. Cloud blocking at Zero Tolerance (blocks ALL
                unknown executables until cloud confirms safe), Controlled Folder
                Access in Block mode. ONLY use this during an active incident while
                threats are being removed from the network. This level WILL cause
                false positives and may block legitimate applications.

    IMPORTANT: This does NOT require Microsoft Defender for Endpoint (paid product).
    This hardens the standard Windows Defender that ships with every Windows installation.

.NOTES
    Version: 2.0
    Date:    February 2026
    License: MIT

    Inspired by ConfigureDefender (https://github.com/AndyFul/ConfigureDefender)

    EDITION REQUIREMENTS:
    - Core AV settings work on ALL editions (Home, Pro, Enterprise, Education)
    - ASR rules require Pro, Enterprise, or Education
    - Network Protection requires Pro, Enterprise, or Education
    - Exploit Protection works on ALL editions

    DEPLOYMENT OPTIONS:
    1. Run locally (as Administrator):
       .\Harden-WindowsDefender.ps1 -ProtectionLevel Standard

    2. GPO Startup Script:
       Computer Configuration > Policies > Windows Settings > Scripts > Startup
       Point to a NETLOGON or network share copy of this script.

    3. PowerShell Remoting (immediate push to multiple machines):
       $targets = Get-Content "C:\targets.txt"
       Invoke-Command -ComputerName $targets -FilePath ".\Harden-WindowsDefender.ps1"

    4. Remote pull via IEX (no infrastructure, just internet):
       IEX (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/<org>/<repo>/main/Harden-WindowsDefender.ps1' -UseBasicParsing).Content

    5. PDQ Deploy: Create package with PowerShell step, deploy to targets.

    6. Intune: Devices > Scripts > Upload .ps1, assign to device group.

    7. USB: Copy to drive, run from elevated PowerShell on each machine.

    8. SCCM/MECM: Package + Program, deploy to device collection.
       NOTE: PSExec/WMI ASR rule is set to Audit (not Block) to avoid SCCM conflicts.

.PARAMETER ProtectionLevel
    The protection level to apply. Valid values: Standard, High, Max.
    Defaults to Standard.

    Standard - Strong daily-use baseline
    High     - Elevated protection for heightened risk environments
    Max      - Active incident response ONLY (will cause false positives)
#>

param(
    [ValidateSet("Standard", "High", "Max")]
    [string]$ProtectionLevel = "Standard"
)

$ErrorActionPreference = "Continue"

# -------------------------------------------------------------------
# PROTECTION LEVEL CONFIGURATION
# -------------------------------------------------------------------
# Settings that vary by protection level are defined here.
# Everything else is the same across all levels.

$levelConfig = @{
    Standard = @{
        CloudBlockLevel       = 2       # High
        CloudExtendedTimeout  = 30      # +30 seconds cloud analysis
        CFA                   = 2       # Audit mode
        ASRCloudReputation    = 2       # Audit (less false positives)
        ScanCPULimit          = 50      # 50% CPU during scans
        BatteryScan           = $false  # Don't drain battery
        SignatureInterval     = 3       # Every 3 hours
        QuarantinePurge       = 90      # Auto-delete after 90 days
    }
    High = @{
        CloudBlockLevel       = 4       # High+
        CloudExtendedTimeout  = 50      # +50 seconds cloud analysis
        CFA                   = 2       # Audit mode
        ASRCloudReputation    = 1       # Block
        ScanCPULimit          = 60      # 60% CPU during scans
        BatteryScan           = $true   # Scan on battery
        SignatureInterval     = 1       # Every hour
        QuarantinePurge       = 0       # Never auto-delete
    }
    Max = @{
        CloudBlockLevel       = 6       # ZeroTolerance -- blocks ALL unknown executables
        CloudExtendedTimeout  = 50      # +50 seconds cloud analysis
        CFA                   = 1       # Block mode -- may block legitimate apps
        ASRCloudReputation    = 1       # Block
        ScanCPULimit          = 70      # 70% CPU during scans
        BatteryScan           = $true   # Scan on battery
        SignatureInterval     = 1       # Every hour
        QuarantinePurge       = 0       # Never auto-delete (preserve for forensics)
    }
}

$config = $levelConfig[$ProtectionLevel]

$cloudBlockNames = @{ 0 = "Default (0)"; 1 = "Moderate (1)"; 2 = "High (2)"; 4 = "High+ (4)"; 6 = "ZeroTolerance (6)" }
$cfaNames        = @{ 0 = "Disabled"; 1 = "BLOCK (active protection)"; 2 = "AUDIT (logging only)" }

# -------------------------------------------------------------------
# HEADER
# -------------------------------------------------------------------

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Windows Defender Hardening Script v2.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

switch ($ProtectionLevel) {
    "Standard" {
        Write-Host "[LEVEL] STANDARD - Strong daily-use baseline" -ForegroundColor Green
        Write-Host "  Recommended for long-term use on production machines." -ForegroundColor Gray
    }
    "High" {
        Write-Host "[LEVEL] HIGH - Elevated protection for heightened risk" -ForegroundColor Yellow
        Write-Host "  Increased cloud blocking and scan frequency." -ForegroundColor Gray
    }
    "Max" {
        Write-Host "[LEVEL] MAX - Active incident response" -ForegroundColor Red
        Write-Host ""
        Write-Host "  WARNING: This level is designed ONLY for use during an active" -ForegroundColor Red
        Write-Host "  security incident while threats are being removed from the" -ForegroundColor Red
        Write-Host "  network. It blocks ALL unknown executables and prevents" -ForegroundColor Red
        Write-Host "  untrusted applications from writing to protected folders." -ForegroundColor Red
        Write-Host "  This WILL cause false positives." -ForegroundColor Red
        Write-Host ""
        Write-Host "  After the incident is contained, re-run with:" -ForegroundColor Yellow
        Write-Host "    .\Harden-WindowsDefender.ps1 -ProtectionLevel High" -ForegroundColor Yellow
    }
}
Write-Host ""

# -------------------------------------------------------------------
# STEP 1: Force-enable Windows Defender service
# -------------------------------------------------------------------
Write-Host "[1/10] Verifying Windows Defender service is running..." -ForegroundColor Green

$defenderService = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
if ($defenderService) {
    if ($defenderService.Status -ne 'Running') {
        try {
            Start-Service -Name WinDefend -ErrorAction Stop
            Write-Host "  - WinDefend service started" -ForegroundColor White
        } catch {
            Write-Host "  - WARNING: Could not start WinDefend. Third-party AV may be installed." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  - WinDefend service is running" -ForegroundColor White
    }
} else {
    Write-Host "  - WARNING: WinDefend service not found" -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# STEP 2: Core protection settings (same across all levels)
# -------------------------------------------------------------------
Write-Host "[2/10] Configuring core protection settings..." -ForegroundColor Green

$coreParams = @{
    DisableRealtimeMonitoring           = $false
    DisableBehaviorMonitoring           = $false
    DisableIOAVProtection               = $false
    DisableScriptScanning               = $false
    DisableBlockAtFirstSeen             = $false
    RealTimeScanDirection               = 0          # Scan both incoming and outgoing
    PUAProtection                       = 1          # Block Potentially Unwanted Apps
}

try {
    Set-MpPreference @coreParams
    Write-Host "  - Real-time protection: ENABLED" -ForegroundColor White
    Write-Host "  - Behavior monitoring: ENABLED" -ForegroundColor White
    Write-Host "  - IOAV protection (downloads/attachments): ENABLED" -ForegroundColor White
    Write-Host "  - Script scanning (AMSI): ENABLED" -ForegroundColor White
    Write-Host "  - Block at First Seen: ENABLED" -ForegroundColor White
    Write-Host "  - PUA Protection: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting core params: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------------------------------------------
# STEP 3: Cloud-delivered protection
# -------------------------------------------------------------------
Write-Host "[3/10] Configuring cloud-delivered protection..." -ForegroundColor Green

$cloudParams = @{
    MAPSReporting           = 2                             # Advanced telemetry to Microsoft
    SubmitSamplesConsent    = 3                             # Send all samples automatically
    CloudBlockLevel         = $config.CloudBlockLevel
    CloudExtendedTimeout    = $config.CloudExtendedTimeout
}

try {
    Set-MpPreference @cloudParams
    Write-Host "  - MAPS Reporting: ADVANCED" -ForegroundColor White
    Write-Host "  - Sample Submission: ALL SAMPLES" -ForegroundColor White
    Write-Host "  - Cloud Block Level: $($cloudBlockNames[$config.CloudBlockLevel])" -ForegroundColor White
    Write-Host "  - Cloud Extended Timeout: +$($config.CloudExtendedTimeout) seconds" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting cloud params: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------------------------------------------
# STEP 4: Network protection and traffic inspection (same across all levels)
# -------------------------------------------------------------------
Write-Host "[4/10] Configuring network protection..." -ForegroundColor Green

$networkParams = @{
    EnableNetworkProtection             = 1          # Block malicious domains/IPs
    DisableHttpParsing                  = $false
    DisableTlsParsing                   = $false
    DisableDnsParsing                   = $false
    DisableDnsOverTcpParsing            = $false
    DisableFtpParsing                   = $false
    DisableSmtpParsing                  = $false
    DisableSshParsing                   = $false
    DisableRdpParsing                   = $false
    DisableInboundConnectionFiltering   = $false
    EnableDnsSinkhole                   = $true
}

try {
    Set-MpPreference @networkParams
    Write-Host "  - Network Protection: ENABLED (blocks malicious domains)" -ForegroundColor White
    Write-Host "  - Traffic inspection: ALL protocols enabled" -ForegroundColor White
    Write-Host "  - DNS Sinkhole: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - NOTE: Network Protection requires Pro/Enterprise/Education edition" -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# STEP 5: Attack Surface Reduction (ASR) rules
# -------------------------------------------------------------------
Write-Host "[5/10] Configuring Attack Surface Reduction rules..." -ForegroundColor Green

# ASR Rule GUIDs -- Block across all levels
$asrBlockRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block Office child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential theft from LSASS"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executables from email"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JS/VBS launching executables"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office creating executables"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office code injection"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Outlook child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block WMI persistence"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted USB executables"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block impersonated system tools"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API from macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Advanced ransomware protection"
    "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block Safe Mode reboot"
}

# Rules with variable action by level
$cloudReputationGuid = "01443614-cd74-433a-b99e-2ecdc07bfc25"  # Block unknown executables
$psexecWmiGuid       = "d1e49aac-8f56-4280-b9ba-993a6d77406c"  # PSExec/WMI - always Audit

# Build rule arrays
$ruleIds     = @($asrBlockRules.Keys)
$ruleActions = @($asrBlockRules.Keys | ForEach-Object { 1 })  # 1 = Block

# Cloud reputation rule -- varies by level
$ruleIds     += $cloudReputationGuid
$ruleActions += $config.ASRCloudReputation

# PSExec/WMI -- always Audit to avoid breaking SCCM/MECM
$ruleIds     += $psexecWmiGuid
$ruleActions += 2  # Audit

$actionNames = @{ 1 = "BLOCK"; 2 = "AUDIT" }

try {
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions
    foreach ($guid in $asrBlockRules.Keys) {
        Write-Host "  - BLOCK: $($asrBlockRules[$guid])" -ForegroundColor White
    }
    Write-Host "  - $($actionNames[$config.ASRCloudReputation]): Block unknown executables (cloud reputation)" -ForegroundColor $(if ($config.ASRCloudReputation -eq 1) { "White" } else { "Yellow" })
    Write-Host "  - AUDIT: Block PSExec/WMI process creation (safe default for SCCM)" -ForegroundColor Yellow
} catch {
    Write-Host "  - NOTE: ASR rules require Pro/Enterprise/Education edition" -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# STEP 6: Controlled Folder Access (ransomware protection)
# -------------------------------------------------------------------
Write-Host "[6/10] Configuring Controlled Folder Access..." -ForegroundColor Green

try {
    Set-MpPreference -EnableControlledFolderAccess $config.CFA
    Write-Host "  - Controlled Folder Access: $($cfaNames[$config.CFA])" -ForegroundColor White
    if ($config.CFA -eq 1) {
        Write-Host "  - NOTE: Legitimate apps may be blocked from writing to Documents, Pictures, etc." -ForegroundColor Yellow
        Write-Host "  - To whitelist an app: Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\path\to\app.exe'" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  - ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------------------------------------------
# STEP 7: Scan configuration
# -------------------------------------------------------------------
Write-Host "[7/10] Configuring scan settings..." -ForegroundColor Green

$scanParams = @{
    ScanParameters                                  = 2                      # Full scan for scheduled
    ScanScheduleDay                                 = 0                      # Every day
    ScanScheduleQuickScanTime                       = 720                    # Quick scan at noon
    CheckForSignaturesBeforeRunningScan              = $true
    ScanOnlyIfIdleEnabled                           = $false                 # Scan even if in use
    DisableArchiveScanning                          = $false
    DisableEmailScanning                            = $false
    DisableRemovableDriveScanning                   = $false
    DisableScanningMappedNetworkDrivesForFullScan   = $false
    DisableScanningNetworkFiles                     = $false
    ScanAvgCPULoadFactor                            = $config.ScanCPULimit
    DisableCatchupFullScan                          = $false
    DisableCatchupQuickScan                         = $false
    EnableFullScanOnBatteryPower                    = $config.BatteryScan
}

try {
    Set-MpPreference @scanParams
    Write-Host "  - Daily full scan: ENABLED" -ForegroundColor White
    Write-Host "  - Quick scan at noon: ENABLED" -ForegroundColor White
    Write-Host "  - Archive/email/USB/network scanning: ENABLED" -ForegroundColor White
    Write-Host "  - CPU limit during scan: $($config.ScanCPULimit)%" -ForegroundColor White
    Write-Host "  - Scan on battery: $(if ($config.BatteryScan) { 'YES' } else { 'NO' })" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting scan params: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------------------------------------------
# STEP 8: Signature updates
# -------------------------------------------------------------------
Write-Host "[8/10] Configuring signature updates..." -ForegroundColor Green

$sigParams = @{
    SignatureUpdateInterval                          = $config.SignatureInterval
    SignatureUpdateCatchupInterval                   = 1          # Catch up after 1 day
    SignatureFallbackOrder                           = "MicrosoftUpdateServer|MMPC"
    SignatureDisableUpdateOnStartupWithoutEngine     = $false
    MeteredConnectionUpdates                         = $true      # Update on hotspots too
}

try {
    Set-MpPreference @sigParams
    Write-Host "  - Signature check interval: Every $($config.SignatureInterval) hour(s)" -ForegroundColor White
    Write-Host "  - Metered connection updates: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting signature params: $($_.Exception.Message)" -ForegroundColor Red
}

# Force an immediate signature update
Write-Host "  - Forcing immediate signature update..." -ForegroundColor White
try {
    Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
    Write-Host "  - Signatures updated successfully" -ForegroundColor White
} catch {
    Write-Host "  - NOTE: Could not update signatures. Will retry on next interval." -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# STEP 9: Threat action defaults and forensic settings
# -------------------------------------------------------------------
Write-Host "[9/10] Configuring threat actions and forensic settings..." -ForegroundColor Green

$threatParams = @{
    SevereThreatDefaultAction           = 2          # Quarantine (preserve for analysis)
    HighThreatDefaultAction             = 2
    ModerateThreatDefaultAction         = 2
    LowThreatDefaultAction              = 2
    UnknownThreatDefaultAction          = 2
    QuarantinePurgeItemsAfterDelay      = $config.QuarantinePurge
    EnableFileHashComputation           = $true       # Compute file hashes for forensics
    DisableAutoExclusions               = $true       # Don't auto-exclude paths
    OobeEnableRtpAndSigUpdate           = $true
}

$purgeText = if ($config.QuarantinePurge -eq 0) { "NEVER (preserve for forensics)" } else { "After $($config.QuarantinePurge) days" }

try {
    Set-MpPreference @threatParams
    Write-Host "  - All threat levels: QUARANTINE" -ForegroundColor White
    Write-Host "  - Quarantine purge: $purgeText" -ForegroundColor White
    Write-Host "  - File hash computation: ENABLED" -ForegroundColor White
    Write-Host "  - Auto-exclusions: DISABLED" -ForegroundColor White
} catch {
    Write-Host "  - ERROR setting threat params: $($_.Exception.Message)" -ForegroundColor Red
}

# -------------------------------------------------------------------
# STEP 10: Exploit Protection (system-wide mitigations, same across all levels)
# -------------------------------------------------------------------
Write-Host "[10/10] Configuring Exploit Protection mitigations..." -ForegroundColor Green

try {
    Set-ProcessMitigation -System -Enable DEP,EmulateAtlThunks
    Write-Host "  - DEP (Data Execution Prevention): ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - DEP: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable SEHOP
    Write-Host "  - SEHOP: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - SEHOP: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable ForceRelocateImages
    Write-Host "  - Mandatory ASLR: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - Mandatory ASLR: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable BottomUp
    Write-Host "  - Bottom-up ASLR: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - Bottom-up ASLR: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable HighEntropy
    Write-Host "  - High-entropy ASLR: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - High-entropy ASLR: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable CFG
    Write-Host "  - Control Flow Guard: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - CFG: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

try {
    Set-ProcessMitigation -System -Enable TerminateOnHeapError
    Write-Host "  - Heap integrity validation: ENABLED" -ForegroundColor White
} catch {
    Write-Host "  - Heap integrity: Could not set ($($_.Exception.Message))" -ForegroundColor Yellow
}

# -------------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------------
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " HARDENING COMPLETE - $($ProtectionLevel.ToUpper()) LEVEL" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "What was configured:" -ForegroundColor White
Write-Host "  - Core AV protection (real-time, behavior, script, IOAV)" -ForegroundColor White
Write-Host "  - Cloud protection (MAPS Advanced, $($cloudBlockNames[$config.CloudBlockLevel]))" -ForegroundColor White
Write-Host "  - Network protection (malicious domain blocking, traffic inspection)" -ForegroundColor White
Write-Host "  - 18 ASR rules configured" -ForegroundColor White
Write-Host "  - Controlled Folder Access: $($cfaNames[$config.CFA])" -ForegroundColor White
Write-Host "  - Scan schedule (daily full + noon quick, $($config.ScanCPULimit)% CPU)" -ForegroundColor White
Write-Host "  - Signature updates every $($config.SignatureInterval) hour(s)" -ForegroundColor White
Write-Host "  - Exploit Protection mitigations (DEP, ASLR, SEHOP, CFG)" -ForegroundColor White
Write-Host ""

Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Enable Tamper Protection manually: Windows Security > Virus & threat protection > Manage settings" -ForegroundColor White
Write-Host "  2. Monitor for false positives - whitelist legitimate apps as needed:" -ForegroundColor White
Write-Host "     Add-MpPreference -ControlledFolderAccessAllowedApplications 'C:\path\to\app.exe'" -ForegroundColor Gray
Write-Host "     Add-MpPreference -ExclusionProcess 'appname.exe'" -ForegroundColor Gray

if ($ProtectionLevel -eq "Max") {
    Write-Host "" -ForegroundColor White
    Write-Host "  IMPORTANT: You are running at MAX level. After the incident is" -ForegroundColor Red
    Write-Host "  contained, step down to High or Standard:" -ForegroundColor Red
    Write-Host "    .\Harden-WindowsDefender.ps1 -ProtectionLevel High" -ForegroundColor Yellow
    Write-Host "    .\Harden-WindowsDefender.ps1 -ProtectionLevel Standard" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Verify settings: .\Verify-DefenderHardening.ps1 -ProtectionLevel $ProtectionLevel" -ForegroundColor White
Write-Host ""
Write-Host "For more information, see the README in the repository." -ForegroundColor Cyan
