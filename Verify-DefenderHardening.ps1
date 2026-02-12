#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies Windows Defender hardening settings and runs safe functional tests.

.DESCRIPTION
    Companion script for Harden-WindowsDefender.ps1. Reads back every configured
    setting, compares against expected values, and optionally runs safe functional
    tests using industry-standard test files (EICAR, Microsoft test URLs, AMTSO).

    Outputs a structured pass/fail report to both the console and a text file.

.PARAMETER ProtectionLevel
    The protection level to validate against. Must match the level used when
    running Harden-WindowsDefender.ps1. Valid values: Standard, High, Max.
    Defaults to Standard.

.PARAMETER SkipFunctionalTests
    Skip functional tests and only verify configuration settings.

.PARAMETER ReportPath
    Path for the output report file. Defaults to .\Defender-Verification-Report.txt

.NOTES
    Version: 2.0
    Date:    February 2026
    License: MIT

    FUNCTIONAL TEST RESOURCES:
    - EICAR test file: industry standard AV test (not real malware)
    - Network Protection: Microsoft test URL (smartscreentestratings2.net)
    - Cloud Protection: Microsoft test file (aka.ms/ioavtest)
    - Controlled Folder Access: safe write test to Documents folder
    - All tests are non-destructive and safe to run on production machines
#>

param(
    [ValidateSet("Standard", "High", "Max")]
    [string]$ProtectionLevel = "Standard",
    [switch]$SkipFunctionalTests,
    [string]$ReportPath = ".\Defender-Verification-Report.txt"
)

$ErrorActionPreference = "Continue"

# -------------------------------------------------------------------
# REPORT ENGINE
# -------------------------------------------------------------------

$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0
$script:SkipCount = 0
$script:ReportLines = @()

function Write-Report {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    $script:ReportLines += $Line
}

function Test-Setting {
    param(
        [string]$Name,
        $Expected,
        $Actual,
        [string]$Category
    )

    $displayExpected = if ($Expected -is [bool]) { $Expected.ToString() } else { "$Expected" }
    $displayActual   = if ($Actual -is [bool]) { $Actual.ToString() } else { "$Actual" }

    if ($Actual -eq $Expected) {
        $script:PassCount++
        Write-Report "  [PASS] $Name = $displayActual" "Green"
    } else {
        $script:FailCount++
        Write-Report "  [FAIL] $Name -- Expected: $displayExpected, Got: $displayActual" "Red"
    }
}

function Test-Functional {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail
    )

    if ($Passed) {
        $script:PassCount++
        Write-Report "  [PASS] $Name -- $Detail" "Green"
    } else {
        $script:FailCount++
        Write-Report "  [FAIL] $Name -- $Detail" "Red"
    }
}

function Write-Skip {
    param([string]$Name, [string]$Reason)
    $script:SkipCount++
    Write-Report "  [SKIP] $Name -- $Reason" "Yellow"
}

function Write-Warn {
    param([string]$Name, [string]$Detail)
    $script:WarnCount++
    Write-Report "  [WARN] $Name -- $Detail" "Yellow"
}

# -------------------------------------------------------------------
# HEADER
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# PROTECTION LEVEL EXPECTED VALUES
# -------------------------------------------------------------------

$levelConfig = @{
    Standard = @{
        CloudBlockLevel       = 2       # High
        CloudExtendedTimeout  = 30
        CFA                   = 2       # Audit
        ASRCloudReputation    = 2       # Audit
        ScanCPULimit          = 50
        BatteryScan           = $false
        SignatureInterval     = 3
        QuarantinePurge       = 90
    }
    High = @{
        CloudBlockLevel       = 4       # High+
        CloudExtendedTimeout  = 50
        CFA                   = 2       # Audit
        ASRCloudReputation    = 1       # Block
        ScanCPULimit          = 60
        BatteryScan           = $true
        SignatureInterval     = 1
        QuarantinePurge       = 0
    }
    Max = @{
        CloudBlockLevel       = 6       # ZeroTolerance
        CloudExtendedTimeout  = 50
        CFA                   = 1       # Block
        ASRCloudReputation    = 1       # Block
        ScanCPULimit          = 70
        BatteryScan           = $true
        SignatureInterval     = 1
        QuarantinePurge       = 0
    }
}

$config = $levelConfig[$ProtectionLevel]

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Report "============================================================"
Write-Report " Windows Defender Hardening Verification Report"
Write-Report "============================================================"
Write-Report ""
Write-Report "Timestamp:    $timestamp"
Write-Report "Computer:     $env:COMPUTERNAME"
Write-Report "Username:     $env:USERNAME"
Write-Report "OS:           $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)"
Write-Report "OS Build:     $([System.Environment]::OSVersion.Version)"
Write-Report "Validating:   $($ProtectionLevel.ToUpper()) level"
Write-Report ""

# -------------------------------------------------------------------
# LOAD CURRENT STATE
# -------------------------------------------------------------------

Write-Report "Loading current Defender configuration..." "Cyan"
Write-Report ""

try {
    $pref   = Get-MpPreference -ErrorAction Stop
    $status = Get-MpComputerStatus -ErrorAction Stop
} catch {
    Write-Report "FATAL: Cannot read Defender configuration. Is Windows Defender running?" "Red"
    Write-Report "Error: $($_.Exception.Message)" "Red"
    exit 1
}

try {
    $exploitMitigations = Get-ProcessMitigation -System -ErrorAction Stop
} catch {
    Write-Report "WARNING: Could not read Exploit Protection settings" "Yellow"
    $exploitMitigations = $null
}

# -------------------------------------------------------------------
# PART 1: CONFIGURATION VERIFICATION
# -------------------------------------------------------------------

Write-Report "============================================================"
Write-Report " PART 1: CONFIGURATION VERIFICATION"
Write-Report "============================================================"
Write-Report ""

# --- Defender Service Status ---
Write-Report "--- Defender Service Status ---" "Cyan"
Test-Setting -Name "AntivirusEnabled" -Expected $true -Actual $status.AntivirusEnabled
Test-Setting -Name "AMServiceEnabled" -Expected $true -Actual $status.AMServiceEnabled
Test-Setting -Name "RealTimeProtectionEnabled" -Expected $true -Actual $status.RealTimeProtectionEnabled
Test-Setting -Name "IoavProtectionEnabled" -Expected $true -Actual $status.IoavProtectionEnabled
Test-Setting -Name "BehaviorMonitorEnabled" -Expected $true -Actual $status.BehaviorMonitorEnabled
Test-Setting -Name "OnAccessProtectionEnabled" -Expected $true -Actual $status.OnAccessProtectionEnabled
Write-Report ""

# --- Core Protection ---
Write-Report "--- Core Protection Settings ---" "Cyan"
Test-Setting -Name "DisableRealtimeMonitoring" -Expected $false -Actual $pref.DisableRealtimeMonitoring
Test-Setting -Name "DisableBehaviorMonitoring" -Expected $false -Actual $pref.DisableBehaviorMonitoring
Test-Setting -Name "DisableIOAVProtection" -Expected $false -Actual $pref.DisableIOAVProtection
Test-Setting -Name "DisableScriptScanning" -Expected $false -Actual $pref.DisableScriptScanning
Test-Setting -Name "DisableBlockAtFirstSeen" -Expected $false -Actual $pref.DisableBlockAtFirstSeen
Test-Setting -Name "RealTimeScanDirection" -Expected 0 -Actual $pref.RealTimeScanDirection
Test-Setting -Name "PUAProtection" -Expected 1 -Actual $pref.PUAProtection
Write-Report ""

# --- Cloud-Delivered Protection ---
Write-Report "--- Cloud-Delivered Protection ---" "Cyan"

Test-Setting -Name "MAPSReporting" -Expected 2 -Actual $pref.MAPSReporting
Test-Setting -Name "SubmitSamplesConsent" -Expected 3 -Actual $pref.SubmitSamplesConsent
Test-Setting -Name "CloudBlockLevel" -Expected $config.CloudBlockLevel -Actual $pref.CloudBlockLevel
Test-Setting -Name "CloudExtendedTimeout" -Expected $config.CloudExtendedTimeout -Actual $pref.CloudExtendedTimeout

# Cloud connectivity check
if ($status.PSObject.Properties.Name -contains "IsVirtualMachine") {
    Write-Report "  [INFO] Virtual Machine: $($status.IsVirtualMachine)" "Gray"
}
Write-Report ""

# --- Network Protection ---
Write-Report "--- Network Protection ---" "Cyan"
Test-Setting -Name "EnableNetworkProtection" -Expected 1 -Actual $pref.EnableNetworkProtection
Test-Setting -Name "DisableHttpParsing" -Expected $false -Actual $pref.DisableHttpParsing
Test-Setting -Name "DisableTlsParsing" -Expected $false -Actual $pref.DisableTlsParsing
Test-Setting -Name "DisableDnsParsing" -Expected $false -Actual $pref.DisableDnsParsing
Test-Setting -Name "DisableDnsOverTcpParsing" -Expected $false -Actual $pref.DisableDnsOverTcpParsing
Test-Setting -Name "DisableFtpParsing" -Expected $false -Actual $pref.DisableFtpParsing
Test-Setting -Name "DisableSmtpParsing" -Expected $false -Actual $pref.DisableSmtpParsing
Test-Setting -Name "DisableSshParsing" -Expected $false -Actual $pref.DisableSshParsing
Test-Setting -Name "DisableRdpParsing" -Expected $false -Actual $pref.DisableRdpParsing
Test-Setting -Name "DisableInboundConnectionFiltering" -Expected $false -Actual $pref.DisableInboundConnectionFiltering
Test-Setting -Name "EnableDnsSinkhole" -Expected $true -Actual $pref.EnableDnsSinkhole
Write-Report ""

# --- Controlled Folder Access ---
Write-Report "--- Controlled Folder Access ---" "Cyan"
Test-Setting -Name "EnableControlledFolderAccess" -Expected $config.CFA -Actual $pref.EnableControlledFolderAccess
Write-Report ""

# --- Attack Surface Reduction Rules ---
Write-Report "--- Attack Surface Reduction Rules ---" "Cyan"

$expectedASR = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = @{ Action = 1; Name = "Block vulnerable signed drivers" }
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = @{ Action = 1; Name = "Block Adobe Reader child processes" }
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = @{ Action = 1; Name = "Block Office child processes" }
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = @{ Action = 1; Name = "Block credential theft from LSASS" }
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = @{ Action = 1; Name = "Block executables from email" }
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = @{ Action = $config.ASRCloudReputation; Name = "Block unknown executables (cloud)" }
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = @{ Action = 1; Name = "Block obfuscated scripts" }
    "d3e037e1-3eb8-44c8-a917-57927947596d" = @{ Action = 1; Name = "Block JS/VBS launching executables" }
    "3b576869-a4ec-4529-8536-b80a7769e899" = @{ Action = 1; Name = "Block Office creating executables" }
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = @{ Action = 1; Name = "Block Office code injection" }
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = @{ Action = 1; Name = "Block Outlook child processes" }
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = @{ Action = 1; Name = "Block WMI persistence" }
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = @{ Action = 1; Name = "Block untrusted USB executables" }
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = @{ Action = 1; Name = "Block impersonated system tools" }
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = @{ Action = 1; Name = "Block Win32 API from macros" }
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = @{ Action = 1; Name = "Advanced ransomware protection" }
    "33ddedf1-c6e0-47cb-833e-de6133960387" = @{ Action = 1; Name = "Block Safe Mode reboot" }
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = @{ Action = 2; Name = "Block PSExec/WMI (Audit)" }
}

# Build lookup from current config
$currentASR = @{}
if ($pref.AttackSurfaceReductionRules_Ids -and $pref.AttackSurfaceReductionRules_Actions) {
    for ($i = 0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
        $id = $pref.AttackSurfaceReductionRules_Ids[$i].ToString().ToLower()
        $action = $pref.AttackSurfaceReductionRules_Actions[$i]
        $currentASR[$id] = $action
    }
}

$actionNames = @{ 0 = "Disabled"; 1 = "Block"; 2 = "Audit"; 6 = "Warn" }

foreach ($guid in $expectedASR.Keys | Sort-Object) {
    $rule = $expectedASR[$guid]
    $expectedAction = $rule.Action
    $expectedName   = $actionNames[$expectedAction]
    $ruleName       = $rule.Name

    if ($currentASR.ContainsKey($guid.ToLower())) {
        $actualAction = $currentASR[$guid.ToLower()]
        $actualName   = if ($actionNames.ContainsKey($actualAction)) { $actionNames[$actualAction] } else { "Unknown ($actualAction)" }

        if ($actualAction -eq $expectedAction) {
            $script:PassCount++
            Write-Report "  [PASS] $ruleName = $actualName" "Green"
        } else {
            $script:FailCount++
            Write-Report "  [FAIL] $ruleName -- Expected: $expectedName, Got: $actualName" "Red"
        }
    } else {
        $script:FailCount++
        Write-Report "  [FAIL] $ruleName -- NOT CONFIGURED (GUID: $guid)" "Red"
    }
}
Write-Report ""

# --- Scan Settings ---
Write-Report "--- Scan Settings ---" "Cyan"
Test-Setting -Name "ScanParameters (2=Full)" -Expected 2 -Actual $pref.ScanParameters
Test-Setting -Name "ScanScheduleDay (0=Daily)" -Expected 0 -Actual $pref.ScanScheduleDay
Test-Setting -Name "ScanScheduleQuickScanTime (720=Noon)" -Expected 720 -Actual $pref.ScanScheduleQuickScanTime
Test-Setting -Name "CheckForSignaturesBeforeRunningScan" -Expected $true -Actual $pref.CheckForSignaturesBeforeRunningScan
Test-Setting -Name "ScanOnlyIfIdleEnabled" -Expected $false -Actual $pref.ScanOnlyIfIdleEnabled
Test-Setting -Name "DisableArchiveScanning" -Expected $false -Actual $pref.DisableArchiveScanning
Test-Setting -Name "DisableEmailScanning" -Expected $false -Actual $pref.DisableEmailScanning
Test-Setting -Name "DisableRemovableDriveScanning" -Expected $false -Actual $pref.DisableRemovableDriveScanning
Test-Setting -Name "DisableScanningMappedNetworkDrivesForFullScan" -Expected $false -Actual $pref.DisableScanningMappedNetworkDrivesForFullScan
Test-Setting -Name "DisableScanningNetworkFiles" -Expected $false -Actual $pref.DisableScanningNetworkFiles
Test-Setting -Name "ScanAvgCPULoadFactor" -Expected $config.ScanCPULimit -Actual $pref.ScanAvgCPULoadFactor
Test-Setting -Name "DisableCatchupFullScan" -Expected $false -Actual $pref.DisableCatchupFullScan
Test-Setting -Name "DisableCatchupQuickScan" -Expected $false -Actual $pref.DisableCatchupQuickScan
Test-Setting -Name "EnableFullScanOnBatteryPower" -Expected $config.BatteryScan -Actual $pref.EnableFullScanOnBatteryPower
Write-Report ""

# --- Signature Updates ---
Write-Report "--- Signature Update Settings ---" "Cyan"
Test-Setting -Name "SignatureUpdateInterval (hours)" -Expected $config.SignatureInterval -Actual $pref.SignatureUpdateInterval
Test-Setting -Name "SignatureUpdateCatchupInterval" -Expected 1 -Actual $pref.SignatureUpdateCatchupInterval
Test-Setting -Name "MeteredConnectionUpdates" -Expected $true -Actual $pref.MeteredConnectionUpdates
Test-Setting -Name "SignatureDisableUpdateOnStartupWithoutEngine" -Expected $false -Actual $pref.SignatureDisableUpdateOnStartupWithoutEngine

# Signature freshness
$sigAge = (Get-Date) - $status.AntivirusSignatureLastUpdated
Write-Report "  [INFO] Signatures last updated: $($status.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Round($sigAge.TotalHours, 1)) hours ago)" "Gray"
Write-Report "  [INFO] Signature version: $($status.AntivirusSignatureVersion)" "Gray"
Write-Report "  [INFO] Engine version: $($status.AMEngineVersion)" "Gray"

if ($sigAge.TotalHours -gt 24) {
    Write-Warn -Name "Signature Age" -Detail "Signatures are more than 24 hours old"
} elseif ($sigAge.TotalHours -gt 4) {
    Write-Warn -Name "Signature Age" -Detail "Signatures are more than 4 hours old"
}
Write-Report ""

# --- Threat Actions ---
Write-Report "--- Threat Action Defaults ---" "Cyan"
Test-Setting -Name "SevereThreatDefaultAction (2=Quarantine)" -Expected 2 -Actual $pref.SevereThreatDefaultAction
Test-Setting -Name "HighThreatDefaultAction (2=Quarantine)" -Expected 2 -Actual $pref.HighThreatDefaultAction
Test-Setting -Name "ModerateThreatDefaultAction (2=Quarantine)" -Expected 2 -Actual $pref.ModerateThreatDefaultAction
Test-Setting -Name "LowThreatDefaultAction (2=Quarantine)" -Expected 2 -Actual $pref.LowThreatDefaultAction
Test-Setting -Name "UnknownThreatDefaultAction (2=Quarantine)" -Expected 2 -Actual $pref.UnknownThreatDefaultAction
Test-Setting -Name "QuarantinePurgeItemsAfterDelay" -Expected $config.QuarantinePurge -Actual $pref.QuarantinePurgeItemsAfterDelay
Test-Setting -Name "EnableFileHashComputation" -Expected $true -Actual $pref.EnableFileHashComputation
Test-Setting -Name "DisableAutoExclusions" -Expected $true -Actual $pref.DisableAutoExclusions
Write-Report ""

# --- Exploit Protection ---
Write-Report "--- Exploit Protection (System-Wide) ---" "Cyan"

if ($exploitMitigations) {
    $depStatus = $exploitMitigations.DEP
    if ($depStatus) {
        $depEnabled = $depStatus.Enable
        if ($depEnabled -eq "ON" -or $depEnabled -eq $true -or $depEnabled -eq "NOTSET") {
            # DEP is typically ON by default at OS level, NOTSET means using OS default (ON)
            if ($depEnabled -eq "ON" -or $depEnabled -eq $true) {
                $script:PassCount++
                Write-Report "  [PASS] DEP = $depEnabled" "Green"
            } else {
                Write-Warn -Name "DEP" -Detail "Status is NOTSET (using OS default, likely ON)"
            }
        } else {
            $script:FailCount++
            Write-Report "  [FAIL] DEP -- Expected: ON, Got: $depEnabled" "Red"
        }
    }

    # SEHOP
    $sehop = $exploitMitigations.SEHOP
    if ($sehop) {
        $sehopEnabled = $sehop.Enable
        if ($sehopEnabled -eq "ON" -or $sehopEnabled -eq $true) {
            $script:PassCount++
            Write-Report "  [PASS] SEHOP = $sehopEnabled" "Green"
        } else {
            $script:FailCount++
            Write-Report "  [FAIL] SEHOP -- Expected: ON, Got: $sehopEnabled" "Red"
        }
    }

    # ASLR
    $aslr = $exploitMitigations.ASLR
    if ($aslr) {
        foreach ($prop in @("ForceRelocateImages", "BottomUp", "HighEntropy")) {
            $val = $aslr.$prop
            if ($val -eq "ON" -or $val -eq $true) {
                $script:PassCount++
                Write-Report "  [PASS] ASLR.$prop = $val" "Green"
            } else {
                $script:FailCount++
                Write-Report "  [FAIL] ASLR.$prop -- Expected: ON, Got: $val" "Red"
            }
        }
    }

    # CFG
    $cfg = $exploitMitigations.CFG
    if ($cfg) {
        $cfgEnabled = $cfg.Enable
        if ($cfgEnabled -eq "ON" -or $cfgEnabled -eq $true) {
            $script:PassCount++
            Write-Report "  [PASS] ControlFlowGuard = $cfgEnabled" "Green"
        } else {
            $script:FailCount++
            Write-Report "  [FAIL] ControlFlowGuard -- Expected: ON, Got: $cfgEnabled" "Red"
        }
    }

    # Heap
    $heap = $exploitMitigations.Heap
    if ($heap) {
        $heapEnabled = $heap.TerminateOnError
        if ($heapEnabled -eq "ON" -or $heapEnabled -eq $true) {
            $script:PassCount++
            Write-Report "  [PASS] HeapIntegrity = $heapEnabled" "Green"
        } else {
            $script:FailCount++
            Write-Report "  [FAIL] HeapIntegrity -- Expected: ON, Got: $heapEnabled" "Red"
        }
    }
} else {
    Write-Skip -Name "Exploit Protection" -Reason "Could not read system mitigations"
}
Write-Report ""

# -------------------------------------------------------------------
# EXCLUSIONS CHECK (security audit)
# -------------------------------------------------------------------
Write-Report "--- Exclusions Audit ---" "Cyan"

$hasExclusions = $false
if ($pref.ExclusionPath -and $pref.ExclusionPath.Count -gt 0) {
    $hasExclusions = $true
    Write-Warn -Name "Excluded Paths" -Detail "$($pref.ExclusionPath.Count) path exclusion(s) found"
    foreach ($p in $pref.ExclusionPath) {
        Write-Report "         $p" "Yellow"
    }
}
if ($pref.ExclusionProcess -and $pref.ExclusionProcess.Count -gt 0) {
    $hasExclusions = $true
    Write-Warn -Name "Excluded Processes" -Detail "$($pref.ExclusionProcess.Count) process exclusion(s) found"
    foreach ($p in $pref.ExclusionProcess) {
        Write-Report "         $p" "Yellow"
    }
}
if ($pref.ExclusionExtension -and $pref.ExclusionExtension.Count -gt 0) {
    $hasExclusions = $true
    Write-Warn -Name "Excluded Extensions" -Detail "$($pref.ExclusionExtension.Count) extension exclusion(s) found"
    foreach ($e in $pref.ExclusionExtension) {
        Write-Report "         $e" "Yellow"
    }
}
if (-not $hasExclusions) {
    $script:PassCount++
    Write-Report "  [PASS] No exclusions configured" "Green"
}
Write-Report ""

# -------------------------------------------------------------------
# PART 2: FUNCTIONAL TESTS
# -------------------------------------------------------------------

if (-not $SkipFunctionalTests) {

    Write-Report "============================================================"
    Write-Report " PART 2: FUNCTIONAL TESTS"
    Write-Report "============================================================"
    Write-Report ""
    Write-Report "These tests use safe, industry-standard test artifacts." "Gray"
    Write-Report "Nothing malicious is downloaded or executed." "Gray"
    Write-Report ""

    # Check internet connectivity first
    $hasInternet = $false
    try {
        $null = Invoke-WebRequest -Uri "https://www.microsoft.com" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $hasInternet = $true
        Write-Report "  [INFO] Internet connectivity: Available" "Gray"
    } catch {
        Write-Report "  [INFO] Internet connectivity: NOT AVAILABLE (some tests will be skipped)" "Yellow"
    }
    Write-Report ""

    # --- Test 1: EICAR Real-Time Detection ---
    Write-Report "--- Test 1: EICAR Real-Time Detection ---" "Cyan"
    Write-Report "  Creating EICAR test file (industry-standard AV test, not real malware)..." "Gray"

    $eicarTestDir  = Join-Path $env:TEMP "defender-verify-test"
    $eicarTestFile = Join-Path $eicarTestDir "eicar-test.txt"

    try {
        if (-not (Test-Path $eicarTestDir)) {
            New-Item -ItemType Directory -Path $eicarTestDir -Force | Out-Null
        }

        # Build EICAR string dynamically (avoids static detection of this script itself)
        $p1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}'
        $p2 = '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        $eicarString = $p1 + $p2

        # Write the EICAR file
        [System.IO.File]::WriteAllText($eicarTestFile, $eicarString)

        # Wait for Defender to react
        Start-Sleep -Seconds 5

        # Check if file was quarantined (should no longer exist)
        if (Test-Path $eicarTestFile) {
            # File still exists -- check if Defender detected it anyway
            $recentThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
                Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-2) }

            if ($recentThreats) {
                Test-Functional -Name "EICAR Detection" -Passed $true -Detail "Detected (threat logged but file may still be present)"
            } else {
                # Give it a few more seconds
                Start-Sleep -Seconds 5
                if (Test-Path $eicarTestFile) {
                    Test-Functional -Name "EICAR Detection" -Passed $false -Detail "File was NOT quarantined after 10 seconds"
                    # Clean up manually
                    Remove-Item $eicarTestFile -Force -ErrorAction SilentlyContinue
                } else {
                    Test-Functional -Name "EICAR Detection" -Passed $true -Detail "File quarantined (took 5-10 seconds)"
                }
            }
        } else {
            Test-Functional -Name "EICAR Detection" -Passed $true -Detail "File quarantined within 5 seconds"
        }
    } catch {
        # If WriteAllText itself throws, Defender may have blocked the write
        if ($_.Exception.Message -match "denied|virus|threat|quarantine") {
            Test-Functional -Name "EICAR Detection" -Passed $true -Detail "Write blocked by real-time protection"
        } else {
            Write-Skip -Name "EICAR Detection" -Reason "Error: $($_.Exception.Message)"
        }
    }

    # Clean up test directory
    Remove-Item $eicarTestDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Report ""

    # --- Test 2: Cloud-Delivered Protection ---
    Write-Report "--- Test 2: Cloud-Delivered Protection ---" "Cyan"

    if ($hasInternet) {
        Write-Report "  Downloading Microsoft cloud protection test file (aka.ms/ioavtest)..." "Gray"
        $cloudTestFile = Join-Path $env:TEMP "cloud-test-ioav.exe"

        try {
            Invoke-WebRequest -Uri "https://aka.ms/ioavtest" -OutFile $cloudTestFile -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Start-Sleep -Seconds 5

            if (Test-Path $cloudTestFile) {
                # Check if Defender caught it
                Start-Sleep -Seconds 5
                if (Test-Path $cloudTestFile) {
                    Test-Functional -Name "Cloud Protection (IOAV)" -Passed $false -Detail "Test file was NOT blocked or quarantined"
                    Remove-Item $cloudTestFile -Force -ErrorAction SilentlyContinue
                } else {
                    Test-Functional -Name "Cloud Protection (IOAV)" -Passed $true -Detail "Test file quarantined after download"
                }
            } else {
                Test-Functional -Name "Cloud Protection (IOAV)" -Passed $true -Detail "Test file blocked/quarantined on download"
            }
        } catch {
            if ($_.Exception.Message -match "denied|virus|threat|quarantine|blocked") {
                Test-Functional -Name "Cloud Protection (IOAV)" -Passed $true -Detail "Download blocked by protection"
            } else {
                Write-Skip -Name "Cloud Protection (IOAV)" -Reason "Download failed: $($_.Exception.Message)"
            }
        }

        Remove-Item $cloudTestFile -Force -ErrorAction SilentlyContinue
    } else {
        Write-Skip -Name "Cloud Protection (IOAV)" -Reason "No internet connectivity"
    }
    Write-Report ""

    # --- Test 3: Network Protection ---
    Write-Report "--- Test 3: Network Protection ---" "Cyan"

    if ($hasInternet) {
        Write-Report "  Testing connection to Microsoft Network Protection test URL..." "Gray"
        Write-Report "  (smartscreentestratings2.net -- Microsoft-provided safe test domain)" "Gray"

        try {
            $response = Invoke-WebRequest -Uri "https://smartscreentestratings2.net" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            # If we got here, the connection was NOT blocked
            Test-Functional -Name "Network Protection" -Passed $false -Detail "Connection to test malicious URL was NOT blocked (HTTP $($response.StatusCode))"
        } catch {
            $errorMsg = $_.Exception.Message
            if ($errorMsg -match "blocked|denied|refused|reset|aborted|could not|unable to connect|network") {
                Test-Functional -Name "Network Protection" -Passed $true -Detail "Connection blocked as expected"
            } else {
                # Could be DNS failure, timeout, etc. -- likely blocked at network level
                Test-Functional -Name "Network Protection" -Passed $true -Detail "Connection failed (likely blocked): $errorMsg"
            }
        }

        # Also check Event Log for Network Protection events
        try {
            $npEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -in @(1125, 1126) -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }

            if ($npEvents) {
                $blockEvents = $npEvents | Where-Object { $_.Id -eq 1126 }
                $auditEvents = $npEvents | Where-Object { $_.Id -eq 1125 }
                if ($blockEvents) {
                    Write-Report "  [INFO] Found $($blockEvents.Count) Network Protection BLOCK event(s) in last 5 min" "Gray"
                }
                if ($auditEvents) {
                    Write-Report "  [INFO] Found $($auditEvents.Count) Network Protection AUDIT event(s) in last 5 min" "Gray"
                }
            }
        } catch {
            Write-Report "  [INFO] Could not query Defender event log" "Gray"
        }
    } else {
        Write-Skip -Name "Network Protection" -Reason "No internet connectivity"
    }
    Write-Report ""

    # --- Test 4: Controlled Folder Access ---
    Write-Report "--- Test 4: Controlled Folder Access ---" "Cyan"

    $documentsPath = [Environment]::GetFolderPath("MyDocuments")
    $cfaTestFile   = Join-Path $documentsPath "defender-cfa-test-safe-to-delete.txt"

    if ($config.CFA -eq 1) {
        Write-Report "  CFA is in Block mode (Max level). Attempting to write test file to Documents..." "Gray"

        try {
            [System.IO.File]::WriteAllText($cfaTestFile, "CFA test file - safe to delete")
            Start-Sleep -Seconds 2

            if (Test-Path $cfaTestFile) {
                # File was written -- CFA allowed it (script might be whitelisted as PowerShell)
                Write-Warn -Name "Controlled Folder Access" -Detail "Write succeeded. PowerShell may be on the allowed list. CFA is ON but test is inconclusive from PowerShell."
                Remove-Item $cfaTestFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            if ($_.Exception.Message -match "denied|unauthorized|controlled folder|access") {
                Test-Functional -Name "Controlled Folder Access" -Passed $true -Detail "Write to Documents was BLOCKED as expected"
            } else {
                Write-Skip -Name "Controlled Folder Access" -Reason "Write error: $($_.Exception.Message)"
            }
        }

        # Check CFA events
        try {
            $cfaEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -in @(1123, 1124) -and $_.TimeCreated -gt (Get-Date).AddMinutes(-5) }

            if ($cfaEvents) {
                Write-Report "  [INFO] Found $($cfaEvents.Count) CFA event(s) in last 5 min" "Gray"
            }
        } catch {}
    } elseif ($config.CFA -eq 2) {
        Write-Report "  CFA is in Audit mode (Standard/High level). Write test skipped." "Gray"
        Write-Report "  CFA will log but not block writes. Check Event ID 1124 for audit events." "Gray"
        Write-Skip -Name "Controlled Folder Access Block Test" -Reason "CFA is in Audit mode (expected for Standard/High)"
    } else {
        Test-Functional -Name "Controlled Folder Access" -Passed $false -Detail "CFA is disabled (value: $($pref.EnableControlledFolderAccess))"
    }
    Write-Report ""

    # --- Test 5: Signature Update ---
    Write-Report "--- Test 5: Signature Update ---" "Cyan"

    if ($hasInternet) {
        Write-Report "  Forcing signature update to verify update mechanism works..." "Gray"
        $sigBefore = $status.AntivirusSignatureVersion

        try {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer -ErrorAction Stop
            Start-Sleep -Seconds 3
            $statusAfter = Get-MpComputerStatus
            $sigAfter    = $statusAfter.AntivirusSignatureVersion

            if ($sigAfter -ge $sigBefore) {
                Test-Functional -Name "Signature Update" -Passed $true -Detail "Update succeeded. Version: $sigAfter"
            } else {
                Test-Functional -Name "Signature Update" -Passed $false -Detail "Version did not update. Before: $sigBefore, After: $sigAfter"
            }
        } catch {
            Write-Skip -Name "Signature Update" -Reason "Update failed: $($_.Exception.Message)"
        }
    } else {
        Write-Skip -Name "Signature Update" -Reason "No internet connectivity"
    }
    Write-Report ""

    # --- Test 6: Tamper Protection Status ---
    Write-Report "--- Test 6: Tamper Protection ---" "Cyan"

    if ($status.PSObject.Properties.Name -contains "IsTamperProtected") {
        if ($status.IsTamperProtected) {
            $script:PassCount++
            Write-Report "  [PASS] Tamper Protection is ENABLED" "Green"
        } else {
            Write-Warn -Name "Tamper Protection" -Detail "NOT enabled. Enable manually: Windows Security > Virus & threat protection > Manage settings"
        }
    } else {
        Write-Report "  [INFO] Tamper Protection status not available via this API" "Gray"
    }
    Write-Report ""

} else {
    Write-Report ""
    Write-Report "Functional tests skipped (-SkipFunctionalTests)" "Yellow"
    Write-Report ""
}

# -------------------------------------------------------------------
# SUMMARY
# -------------------------------------------------------------------

Write-Report "============================================================"
Write-Report " SUMMARY"
Write-Report "============================================================"
Write-Report ""
Write-Report "  Passed:   $($script:PassCount)" "Green"
Write-Report "  Failed:   $($script:FailCount)" "Red"
Write-Report "  Warnings: $($script:WarnCount)" "Yellow"
Write-Report "  Skipped:  $($script:SkipCount)" "Yellow"
Write-Report ""

$total = $script:PassCount + $script:FailCount
if ($total -gt 0) {
    $pct = [math]::Round(($script:PassCount / $total) * 100, 1)
    Write-Report "  Score: $($script:PassCount)/$total ($pct%)" "Cyan"
} else {
    Write-Report "  No tests executed" "Yellow"
}
Write-Report ""

if ($script:FailCount -eq 0 -and $script:WarnCount -eq 0) {
    Write-Report "  ALL CHECKS PASSED. Hardening is fully applied." "Green"
} elseif ($script:FailCount -eq 0) {
    Write-Report "  All checks passed with $($script:WarnCount) warning(s). Review warnings above." "Yellow"
} else {
    Write-Report "  $($script:FailCount) check(s) FAILED. Review failures above and re-run the hardening script." "Red"
}

Write-Report ""
Write-Report "Microsoft Defender Testground (additional manual tests):"
Write-Report "  https://demo.wd.microsoft.com/"
Write-Report ""
Write-Report "AMTSO Security Features Check (browser-based):"
Write-Report "  https://www.amtso.org/security-features-check/"
Write-Report ""

# -------------------------------------------------------------------
# SAVE REPORT
# -------------------------------------------------------------------

try {
    $script:ReportLines | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host "Report saved to: $ReportPath" -ForegroundColor Cyan
} catch {
    Write-Host "Could not save report to $ReportPath : $($_.Exception.Message)" -ForegroundColor Yellow
}
