# Windows Defender Hardening Script

A PowerShell script that configures the native Windows Defender antimalware engine to its maximum protection settings. No paid licenses, no additional products, no third-party tools required.

This script uses only built-in Windows components (`Set-MpPreference`, `Set-ProcessMitigation`, `Update-MpSignature`) to significantly improve endpoint security posture.

## Inspiration

This project was inspired by [ConfigureDefender](https://github.com/AndyFul/ConfigureDefender), an excellent portable GUI application by AndyFul that configures Windows Defender with four protection levels (Default, High, Interactive, MAX). ConfigureDefender is a portable application that requires no installation -- download and run `ConfigureDefender.exe` on any Windows 32-bit or 64-bit system.

This project takes the same approach and puts it into a PowerShell script that can be deployed at scale across an organization via Group Policy, PowerShell Remoting, Intune, PDQ Deploy, SCCM, or USB -- without requiring someone to sit at each machine.

## Why This Exists

Most organizations have Windows Defender running on every endpoint but are only using a fraction of its capabilities. Out of the box, many of its most powerful features are either disabled by default or set to passive/audit mode.

Microsoft Defender Antivirus is not just a basic antivirus. It is a full **Endpoint Protection Platform (EPP)** with behavioral analysis, cloud-based machine learning, exploit mitigations, attack surface reduction, network-level protection, and ransomware prevention built in. This script enables and configures all of it.

Everything this script does is documented by Microsoft. Every capability referenced below links directly to official Microsoft Learn documentation so you can verify it yourself.

> **"Microsoft Defender Antivirus uses multiple detection and prevention technologies delivered through the cloud, machine learning, and behavior analysis."**
> -- [Microsoft Defender Antivirus overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)

---

## What Windows Defender Actually Is

The table below shows what native Windows Defender (the free, built-in engine) is capable of when properly configured. Each capability links to official Microsoft documentation.

| Capability | What It Does | Documentation |
|------------|-------------|---------------|
| **Real-Time Protection** | Continuously monitors all file and process activity on the system. Detects and blocks threats as they appear, not just during scheduled scans. | [Configure real-time protection](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus) |
| **Cloud-Delivered Protection** | Sends metadata about suspicious files to Microsoft's cloud for analysis using machine learning and automated detonation. Can identify new malware within seconds, even if no signature exists yet. Also known as Microsoft Active Protection Service (MAPS). | [Cloud protection overview](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-defender-antivirus) |
| **Block at First Sight** | When an unknown file is encountered, Defender holds it and queries the cloud backend. If the cloud determines it is malicious, the file is blocked within seconds. This provides near-instant protection against brand-new malware. | [Configure Block at First Sight](https://learn.microsoft.com/en-us/defender-endpoint/configure-block-at-first-sight-microsoft-defender-antivirus) |
| **Cloud Block Level** | Controls how aggressively the cloud engine blocks unknown files. Can be set from Default all the way up to Zero Tolerance, which blocks ALL unknown executables until the cloud confirms they are safe. | [Specify cloud protection level](https://learn.microsoft.com/en-us/defender-endpoint/specify-cloud-protection-level-microsoft-defender-antivirus) |
| **Behavior Monitoring** | Monitors process behavior in real time, including file system activity, registry changes, and inter-process interactions. Detects threats based on what software *does*, not just what it looks like. This catches malware that signatures miss. Part of the "always-on protection" alongside real-time protection and heuristics. | [Real-time protection overview](https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus) / [Behavior monitoring details](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor) |
| **AMSI (Antimalware Scan Interface)** | A Windows interface that inspects scripts at runtime before they execute. Covers PowerShell, VBScript, JavaScript, and Office VBA macros. Even if a script is obfuscated or encrypted on disk, AMSI sees the deobfuscated version in memory. | [AMSI overview](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) |
| **Attack Surface Reduction (ASR) Rules** | 18 configurable rules that block specific attack techniques commonly used by malware and threat actors. Includes blocking Office macro abuse, credential theft from LSASS, obfuscated script execution, email-based executable delivery, WMI persistence, and more. | [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction) / [Full rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) |
| **Network Protection** | Blocks outbound connections to known malicious domains and IP addresses. Extends Microsoft Defender SmartScreen beyond the browser to cover all HTTP/HTTPS traffic from any process on the system. | [Network protection](https://learn.microsoft.com/en-us/defender-endpoint/network-protection) |
| **Controlled Folder Access** | Prevents untrusted applications from modifying files in protected directories (Documents, Pictures, Desktop, etc.). Only applications on an approved list can write to these folders. This is direct ransomware protection. | [Controlled folder access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders) |
| **Exploit Protection** | System-level memory mitigations that prevent exploitation techniques. Includes DEP (Data Execution Prevention), ASLR (Address Space Layout Randomization), SEHOP, Control Flow Guard, and heap integrity validation. Successor to Microsoft's EMET toolkit. | [Exploit protection](https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection) |
| **PUA Protection** | Detects and blocks Potentially Unwanted Applications including adware, bundleware, browser toolbars, and crypto miners. | [PUA protection](https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus) |
| **Tamper Protection** | Prevents malware or threat actors from disabling Defender itself. Blocks changes to real-time protection, behavior monitoring, cloud protection, and signature updates, even by local administrators. | [Tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) |

### What This Script Does NOT Cover

This script configures **Microsoft Defender Antivirus**, the free engine built into Windows. It does not configure or require **Microsoft Defender for Endpoint**, which is a separate paid product that adds:

- Centralized management dashboard
- Cross-endpoint threat correlation and hunting
- Automated investigation and remediation
- Security Operations Center (SOC) integration

The protection capabilities above are entirely free and built into every Windows 10 and Windows 11 installation.

---

## Protection Levels

The script supports three protection levels via the `-ProtectionLevel` parameter:

```powershell
.\Harden-WindowsDefender.ps1 -ProtectionLevel Standard   # Daily use (default)
.\Harden-WindowsDefender.ps1 -ProtectionLevel High        # Elevated risk environments
.\Harden-WindowsDefender.ps1 -ProtectionLevel Max         # Active incident response ONLY
```

### What Changes Between Levels

All three levels enable the same core protections (real-time, behavior monitoring, AMSI, network protection, exploit mitigations, and 16 ASR rules in Block mode). The differences are in how aggressively the system treats unknown files and how much system resources are dedicated to scanning:

| Setting | Standard | High | Max |
|---------|----------|------|-----|
| Cloud Block Level | High (2) | High+ (4) | **Zero Tolerance (6)** |
| Cloud Extended Timeout | +30 seconds | +50 seconds | +50 seconds |
| Controlled Folder Access | Audit | Audit | **Block** |
| ASR: Unknown executables (cloud reputation) | Audit | Block | Block |
| ASR: PSExec/WMI | Audit | Audit | Audit |
| Scan CPU limit | 50% | 60% | 70% |
| Scan on battery | No | Yes | Yes |
| Signature update interval | 3 hours | 1 hour | 1 hour |
| Quarantine auto-purge | 90 days | Never | Never |

> **WARNING: Max level is designed ONLY for use during an active security incident** while threats are being actively removed from the network. Zero Tolerance cloud blocking will block ALL unknown executables until Microsoft's cloud confirms they are safe. Controlled Folder Access in Block mode will prevent untrusted applications from writing to Documents, Pictures, and other protected folders. This WILL cause false positives and may block legitimate applications. After the incident is contained, step down to High or Standard.

### Choosing a Level

| Situation | Recommended Level |
|-----------|-------------------|
| Long-term daily use on production machines | **Standard** |
| Post-incident environment, ongoing elevated risk | **High** |
| Active incident, threats being removed from network | **Max** |

### Stepping Down After an Incident

After an incident is contained, re-run the script at a lower level. Settings are overwritten, not cumulative:

```powershell
.\Harden-WindowsDefender.ps1 -ProtectionLevel High       # Step down from Max
.\Harden-WindowsDefender.ps1 -ProtectionLevel Standard    # Step down to daily baseline
```

---

## What This Script Configures

The script enables and configures all of the capabilities listed above. The following settings are applied at **all** protection levels:

### Core Protection
- Real-time protection: **ON**
- Behavior monitoring: **ON**
- Script scanning (AMSI integration): **ON**
- Downloaded file/attachment scanning (IOAV): **ON**
- PUA Protection: **ON**
- Block at First Seen: **ON**

### Cloud-Delivered Protection
- Microsoft Active Protection Service (MAPS): **Advanced**
- Automatic sample submission: **All samples**
- Cloud block level and timeout: **Varies by protection level** (see table above)

### Attack Surface Reduction
- 16 ASR rules set to **Block** mode at all levels
- 2 ASR rules vary by level (see table above)
- Covers: Office macro abuse, credential theft, obfuscated scripts, email-based executables, USB threats, ransomware behavior, WMI persistence, vulnerable driver abuse, and more

### Network Protection
- Network Protection: **ON** (blocks malicious domains/IPs across all processes)
- Traffic inspection: HTTP, TLS, DNS, FTP, SMTP, SSH, RDP
- DNS sinkholing: **ON**

### Exploit Protection (System-Wide)
- DEP (Data Execution Prevention): **ON**
- SEHOP (Structured Exception Handler Overwrite Protection): **ON**
- Mandatory ASLR: **ON**
- Bottom-up ASLR: **ON**
- High-entropy ASLR: **ON**
- Control Flow Guard: **ON**
- Heap integrity validation: **ON**

### Scan and Signature Management
- Daily full scan with noon quick scan
- Archive, email, USB, and network drive scanning: **ON**
- Signature update interval, CPU limit, battery scan: **Varies by protection level**
- Missed scan catch-up: **ON**

### Threat Response
- All threat levels (severe, high, moderate, low, unknown): **Quarantine**
- Quarantine auto-purge: **Varies by protection level** (90 days at Standard, never at High/Max)
- File hash computation: **ON** (enables forensic analysis)

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

### Edition Compatibility

| Feature | Home | Pro | Enterprise | Education |
|---------|------|-----|------------|-----------|
| Core AV settings | Yes | Yes | Yes | Yes |
| Cloud protection | Yes | Yes | Yes | Yes |
| ASR rules | No | Yes | Yes | Yes |
| Network Protection | No | Yes | Yes | Yes |
| Controlled Folder Access | Yes | Yes | Yes | Yes |
| Exploit Protection | Yes | Yes | Yes | Yes |

On Home edition, ASR rules and Network Protection commands will execute without error but will not enforce. All other settings work on every edition.

---

## Deployment

### Run Locally

```powershell
# Open PowerShell as Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
.\Harden-WindowsDefender.ps1 -ProtectionLevel Standard
```

### GPO Startup Script

1. Copy the script to `\\<DC>\NETLOGON\Security\Harden-WindowsDefender.ps1`
2. Group Policy Management Console > Create new GPO
3. Computer Configuration > Policies > Windows Settings > Scripts > Startup
4. Add the script, link GPO to target OU
5. `gpupdate /force` or wait for next refresh cycle

### PowerShell Remoting

```powershell
# Single machine
Invoke-Command -ComputerName "WORKSTATION01" -FilePath ".\Harden-WindowsDefender.ps1"

# Multiple machines from a text file
$targets = Get-Content "C:\targets.txt"
Invoke-Command -ComputerName $targets -FilePath ".\Harden-WindowsDefender.ps1" -ThrottleLimit 20

# All domain computers
$targets = (Get-ADComputer -Filter 'OperatingSystem -like "*Windows*"').Name
Invoke-Command -ComputerName $targets -FilePath ".\Harden-WindowsDefender.ps1" -ThrottleLimit 20
```

### Remote Pull (IEX)

```powershell
# Harden at Standard level (default)
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CyberPools-Resources/windows-defender-hardening/main/Harden-WindowsDefender.ps1' -UseBasicParsing).Content

# Harden at a specific level
Set-ExecutionPolicy Bypass -Scope Process -Force
$script = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CyberPools-Resources/windows-defender-hardening/main/Harden-WindowsDefender.ps1' -UseBasicParsing).Content
Invoke-Expression "& { $script } -ProtectionLevel Max"

# Pull and run the verification script
Set-ExecutionPolicy Bypass -Scope Process -Force
$script = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/CyberPools-Resources/windows-defender-hardening/main/Verify-DefenderHardening.ps1' -UseBasicParsing).Content
Invoke-Expression "& { $script } -ProtectionLevel Max"
```

### PDQ Deploy

1. Create new deployment package
2. Add PowerShell step with the script
3. Set "Run As" to Local System
4. Target machines by AD OU, hostname list, or inventory scan

### Microsoft Intune

1. Intune admin center > Devices > Scripts
2. Upload `Harden-WindowsDefender.ps1`
3. Run as SYSTEM, 64-bit PowerShell
4. Assign to device group

### SCCM / MECM

1. Create Package with script as source
2. Create Program: `powershell.exe -ExecutionPolicy Bypass -File Harden-WindowsDefender.ps1`
3. Deploy to device collection as Required

**Note:** The PSExec/WMI ASR rule is set to Audit mode by default to avoid conflicts with SCCM/MECM, which relies on WMI commands for endpoint management.

### USB (Offline Machines)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& "E:\Harden-WindowsDefender.ps1"
```

---

## ASR Rules Reference

The script enables the following [Attack Surface Reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) in Block mode:

| Rule | GUID |
|------|------|
| Block abuse of exploited vulnerable signed drivers | `56a863a9-875e-4185-98a7-b882c64b5ce5` |
| Block Adobe Reader child processes | `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` |
| Block all Office apps from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block credential stealing from LSASS | `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` |
| Block executable content from email/webmail | `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` |
| Block unknown executables (cloud reputation) | `01443614-cd74-433a-b99e-2ecdc07bfc25` |
| Block obfuscated scripts | `5beb7efe-fd9a-4556-801d-275e5ffc04cc` |
| Block JS/VBS launching executables | `d3e037e1-3eb8-44c8-a917-57927947596d` |
| Block Office creating executable content | `3b576869-a4ec-4529-8536-b80a7769e899` |
| Block Office code injection | `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` |
| Block Outlook child processes | `26190899-1602-49e8-8b27-eb1d0a1ce869` |
| Block WMI event subscription persistence | `e6db77e5-3df2-4cf1-b95a-636979351e5b` |
| Block untrusted/unsigned USB executables | `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` |
| Block copied/impersonated system tools | `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Advanced ransomware protection | `c1db55ab-c21a-4637-bb3f-a12568109d35` |
| Block Safe Mode reboot | `33ddedf1-c6e0-47cb-833e-de6133960387` |
| Block PSExec/WMI process creation *(Audit mode)* | `d1e49aac-8f56-4280-b9ba-993a6d77406c` |

---

## Verification and Testing

A companion script (`Verify-DefenderHardening.ps1`) validates that every setting was applied correctly and runs safe functional tests.

### Configuration Verification

Reads back every setting using `Get-MpPreference`, `Get-MpComputerStatus`, and `Get-ProcessMitigation` and compares against expected values. Outputs a pass/fail report.

```powershell
# Verify Standard level settings (default)
.\Verify-DefenderHardening.ps1

# Verify High level settings
.\Verify-DefenderHardening.ps1 -ProtectionLevel High

# Verify Max level settings
.\Verify-DefenderHardening.ps1 -ProtectionLevel Max

# Configuration check only (skip functional tests)
.\Verify-DefenderHardening.ps1 -SkipFunctionalTests

# Save report to a specific path
.\Verify-DefenderHardening.ps1 -ProtectionLevel High -ReportPath "C:\Reports\defender-report.txt"
```

### Functional Tests

The script also runs safe, non-destructive tests using industry-standard test artifacts:

| Test | What It Validates | Test Artifact |
|------|-------------------|---------------|
| EICAR Detection | Real-time protection catches known threats | [EICAR standard test file](https://www.eicar.org/download-anti-malware-testfile/) (not real malware) |
| Cloud Protection | Cloud analysis blocks test samples | [Microsoft IOAV test file](https://learn.microsoft.com/en-us/defender-endpoint/validate-antimalware) |
| Network Protection | Malicious URL connections are blocked | [Microsoft test URL](https://learn.microsoft.com/en-us/defender-endpoint/evaluate-network-protection) |
| Controlled Folder Access | Unauthorized writes to protected folders are blocked | Safe write attempt to Documents folder |
| Signature Update | Update mechanism is functional | Forces an update and verifies version |
| Tamper Protection | Defender cannot be disabled by malware | Reads protection status |

Tests that require internet will be skipped automatically on offline machines.

### Additional Manual Tests

Microsoft provides a browser-based test platform for further validation:

- **Microsoft Defender Testground:** [demo.wd.microsoft.com](https://demo.wd.microsoft.com/) -- tests for cloud protection, Block at First Sight, ASR rules, PUA, Network Protection, and more
- **AMTSO Security Features Check:** [amtso.org/security-features-check](https://www.amtso.org/security-features-check/) -- industry-standard AV validation tests

---

## Post-Deployment

After running the script:

1. **Run the verification script** to confirm all settings applied correctly:
   ```powershell
   .\Verify-DefenderHardening.ps1
   ```

2. **Enable Tamper Protection** manually in Windows Security > Virus & threat protection > Manage settings. This cannot be set via PowerShell and prevents malware from disabling Defender. [Learn more](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)

3. **Monitor for false positives.** Incident Mode uses aggressive cloud blocking that may flag legitimate applications. Whitelist as needed:
   ```powershell
   Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Path\To\App.exe"
   Add-MpPreference -ExclusionProcess "appname.exe"
   ```

4. **A reboot is recommended** but not strictly required. Most settings take effect immediately.

---

## PowerShell Reference

The script uses these built-in cmdlets:

| Cmdlet | Purpose | Documentation |
|--------|---------|---------------|
| `Set-MpPreference` | Configures all Defender preferences (AV, cloud, ASR, network, scans) | [Reference](https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference) |
| `Set-ProcessMitigation` | Configures exploit protection mitigations (DEP, ASLR, CFG) | [Reference](https://learn.microsoft.com/en-us/powershell/module/processmitigations/set-processmitigation) |
| `Update-MpSignature` | Forces immediate signature definition update | [Reference](https://learn.microsoft.com/en-us/powershell/module/defender/update-mpsignature) |

---

## License

MIT
