# ISAAC ESD No. 5 - Endpoint Protection Options

**Prepared by:** CyberPools - Cyber Toolkit Program
**Date:** February 2026
**Status:** Active incident response - immediate protection needed
**Budget:** Zero - all options must be free

---

## Situation

Isaac ESD No. 5 is managing an active security incident. They currently have no EDR or EPP deployed on any endpoints. The district attempted to acquire CrowdStrike Falcon licenses through the DHS/CISA free K-12 program, but DHS has exhausted its available licenses.

The district is a state-takeover school with no available budget for security tools. They need protection now while they remediate compromised systems.

**IT Contact:** Berto Perez, Director of Technology (wperez@isaacschools.org, 602.442.3000)

---

## Option 1: Harden Native Windows Defender (Immediate, Zero Infrastructure)

**What:** Configure the Windows Defender that already exists on every Windows machine to its maximum protection level using a PowerShell script deployed via GPO.

**Time to deploy:** 30 minutes to 1 hour across the entire domain

**What it does:**
- Enables real-time protection, behavior monitoring, and script scanning
- Turns on cloud-delivered protection at maximum aggression (blocks unknown files until the cloud confirms they are safe)
- Enables all 18 Attack Surface Reduction rules (blocks Office macro abuse, credential theft, obfuscated scripts, USB threats, ransomware behavior, etc.)
- Enables Controlled Folder Access (prevents ransomware from encrypting Documents, Pictures, etc.)
- Enables Network Protection (blocks connections to known malicious domains)
- Enables Exploit Protection mitigations (DEP, ASLR, SEHOP, Control Flow Guard)
- Forces hourly signature updates

**What it does NOT do:**
- No central management console or alerting dashboard
- No visibility into what is happening across all endpoints at once
- No incident investigation or forensic capability
- Limited to what Windows Defender can detect on its own

**Recommendation:** Deploy this TODAY as the baseline. It is the fastest path to meaningful protection. Everything else builds on top of this.

**Deliverable:** `Harden-WindowsDefender.ps1` - ready to deploy via GPO or Invoke-Command.

---

## Option 2: Wazuh (Free Open-Source SIEM + XDR)

**What:** Open-source unified security platform that provides real-time monitoring, alerting, and active response across all endpoints from a central dashboard. Most widely adopted open-source security platform in this category.

**Time to deploy:** 2-4 hours for server setup, then 2-4 hours for agent rollout

**What it does:**
- Real-time log analysis and threat detection across every endpoint
- File integrity monitoring (detects unauthorized file changes)
- Rootkit and malware detection
- Vulnerability assessment (cross-references installed software against CVE databases)
- Active response (can automatically isolate threats, kill processes, block IPs)
- Central web-based dashboard for visibility across the entire fleet
- Integrates with Sysmon for deep endpoint telemetry

**What it requires:**
- One Linux server (Ubuntu 22.04 recommended): 4 vCPU, 8 GB RAM, 100 GB disk
- Can run on a repurposed desktop or a $20/month cloud VM
- Wazuh agent installed on each Windows endpoint (lightweight, ~35 MB RAM)
- Agent deployment via GPO or manual MSI install

**Why it matters:** This is the single biggest upgrade for a district with zero security visibility. It turns "we have no idea what is happening on our endpoints" into "we can see everything from one screen."

**Cost:** Free and open source (wazuh.com)

---

## Option 3: Velociraptor (Free Forensic Investigation Tool)

**What:** Open-source endpoint visibility and digital forensics platform maintained by Rapid7. Lets you dig into specific machines to investigate compromises in real time.

**Time to deploy:** 1-2 hours for server + agents on suspect machines

**What it does:**
- Query any endpoint in real time (running processes, network connections, file system changes, registry, etc.)
- Hunt for indicators of compromise across all machines simultaneously
- Collect forensic artifacts (memory, event logs, prefetch, shimcache) for investigation
- Deploy response actions (isolate host, collect triage packages)

**What it requires:**
- One server (Linux or Windows): 8 GB RAM handles 1,000+ endpoints
- Velociraptor agent on target machines (single binary, MSI available)
- GPO deployment or targeted manual install

**Why it matters:** During active incident remediation, this is how you answer "which other machines are compromised?" and "has the attacker moved laterally?" Wazuh watches for new threats. Velociraptor investigates existing ones.

**Cost:** Free and open source (docs.velociraptor.app)

---

## Option 4: Sysmon (Free Microsoft Telemetry Tool)

**What:** Free Microsoft Sysinternals tool that logs detailed system activity (process creation, network connections, file changes, registry modifications, DLL loading) to the Windows Event Log.

**Time to deploy:** 30 minutes to 1 hour via GPO

**What it does:**
- Massively increases the detail of what Windows logs about system activity
- Tracks process creation chains (which process launched which)
- Logs network connections with process context
- Detects DLL side-loading and other stealth techniques
- Feeds directly into Wazuh for centralized analysis and alerting

**What it requires:**
- Sysmon binary + XML configuration file deployed via GPO
- Use the SwiftOnSecurity Sysmon configuration as a starting template (github.com/SwiftOnSecurity/sysmon-config)
- No server infrastructure on its own (logs to Windows Event Log, consumed by Wazuh)

**Why it matters:** Without Sysmon, Windows logs very little about process behavior. With Sysmon, you can trace exactly what happened on a machine, step by step. This is critical for understanding how the attacker got in and what they did.

**Cost:** Free (Microsoft Sysinternals)

---

## Option 5: Government Free Resources

### CISA Cyber Hygiene Services
- Free external vulnerability scanning of all internet-facing IPs (weekly reports)
- Free web application scanning (OWASP Top 10)
- Available to all K-12 organizations at no cost
- **Enroll:** Email vulnerability@cisa.dhs.gov with subject "Requesting Cyber Hygiene Services"

### MS-ISAC (Multi-State Information Sharing and Analysis Center)
- Free membership for K-12 gives 24/7 Security Operations Center access
- Threat alerts, incident response assistance, and free security tools
- **Enroll:** cisecurity.org/ms-isac

### K12 SIX (K-12 Security Information Exchange)
- K-12 specific threat intelligence, IOCs, and TTPs
- Incident response runbooks designed specifically for school districts
- **Enroll:** k12six.org

---

## Recommended Deployment Priority

| Priority | Action | Time | Impact |
|----------|--------|------|--------|
| **1 - TODAY** | Deploy Harden-WindowsDefender.ps1 via GPO | 1 hour | Immediate endpoint protection, blocks common attack vectors |
| **2 - TODAY** | Deploy Sysmon via GPO (SwiftOnSecurity config) | 1 hour | Immediate detailed telemetry on all endpoints |
| **3 - Day 1-2** | Stand up Wazuh server + deploy agents | 4-8 hours | Central visibility and alerting across entire fleet |
| **4 - Day 2-3** | Deploy Velociraptor on suspect machines | 2-3 hours | Deep forensic investigation capability |
| **5 - Day 1** | Enroll in CISA Cyber Hygiene + MS-ISAC + K12 SIX | 30 min | External scanning, 24/7 SOC support, threat intelligence |

**Total infrastructure needed:** One Linux box (repurposed desktop or cheap cloud VM) for Wazuh, one server (Linux or Windows) for Velociraptor. Total cost: $0 if repurposing existing hardware.

---

## Deployment Methods for the Hardening Script

The `Harden-WindowsDefender.ps1` script needs to run as Administrator on every Windows endpoint. Below are all viable deployment methods, ordered from most scalable to most manual.

### Method 1: Active Directory Group Policy (GPO) - Recommended for Domain-Joined Machines

Best option if ISAAC has Active Directory and all machines are domain-joined.

**Steps:**
1. Copy `Harden-WindowsDefender.ps1` to a network share accessible by all domain computers (e.g., `\\dc01\NETLOGON\Security\Harden-WindowsDefender.ps1`)
2. Open Group Policy Management Console (gpmc.msc)
3. Create a new GPO (e.g., "Defender Hardening - Incident Response")
4. Navigate to: Computer Configuration > Policies > Windows Settings > Scripts > Startup
5. Add the PowerShell script, point to the network share path
6. Link the GPO to the appropriate OU (or the entire domain for full coverage)
7. Force immediate application: `gpupdate /force` on target machines, or wait for the next Group Policy refresh cycle (default 90 minutes)

**Pros:** Covers every domain-joined machine automatically, including new machines that join the domain. Runs at startup with SYSTEM privileges (no local admin needed).
**Cons:** Requires Active Directory. Only applies at next startup or gpupdate cycle.

### Method 2: PowerShell Remoting (Invoke-Command) - Fast Targeted Push

Best for pushing to a known list of machines immediately without waiting for GPO refresh.

**Steps:**
1. Ensure WinRM is enabled on target machines (typically on by default in domain environments)
2. From an admin workstation, run:

```powershell
# Single machine
Invoke-Command -ComputerName "PC-LAB01" -FilePath ".\Harden-WindowsDefender.ps1"

# Multiple machines from a list
$computers = Get-Content "C:\targets.txt"
Invoke-Command -ComputerName $computers -FilePath ".\Harden-WindowsDefender.ps1" -ThrottleLimit 20

# All domain computers (use with caution)
$computers = (Get-ADComputer -Filter 'OperatingSystem -like "*Windows*"').Name
Invoke-Command -ComputerName $computers -FilePath ".\Harden-WindowsDefender.ps1" -ThrottleLimit 20
```

**Pros:** Immediate execution, no reboot required, can target specific machines.
**Cons:** Requires WinRM enabled and network access to targets. May hit firewall rules.

### Method 3: PDQ Deploy - GUI-Based Mass Deployment

Best if ISAAC already has PDQ Deploy (free version available) or is willing to install it.

**Steps:**
1. Download PDQ Deploy Free from pdq.com (no cost for basic functionality)
2. Create a new deployment package
3. Add a PowerShell step with the script content or path
4. Ensure "Run As" is set to Deploy User (local admin) or SYSTEM
5. Target machines by Active Directory OU, computer name list, or PDQ Inventory scan
6. Deploy immediately or schedule

**Pros:** Visual interface, progress tracking per machine, retry failed deployments, built-in reporting.
**Cons:** Requires installing PDQ Deploy on an admin workstation. Free version has limitations on scheduling.

### Method 4: Microsoft Intune - For Cloud-Managed Devices

Best if ISAAC manages any devices through Intune/Endpoint Manager (Azure AD joined or hybrid).

**Steps:**
1. In the Intune admin center (intune.microsoft.com), go to Devices > Scripts
2. Add a new PowerShell script
3. Upload `Harden-WindowsDefender.ps1`
4. Set "Run this script using the logged-on credentials" to No (runs as SYSTEM)
5. Set "Run script in 64-bit PowerShell host" to Yes
6. Assign to a device group (All Devices or a targeted group)

**Pros:** Works for cloud-managed and remote devices not on the school network. Persists across reimages if the device re-enrolls.
**Cons:** Requires Intune licensing and device enrollment. Script runs once by default (must delete and re-add to re-run).

### Method 5: Remote Pull via IEX (Invoke-Expression) - No Infrastructure Needed

Best for machines that are not domain-joined, not on the network, or need a quick manual fix. The script is hosted on GitHub and pulled directly.

**Steps (on each target machine, run PowerShell as Administrator):**

```powershell
# Pull and execute directly from GitHub
Set-ExecutionPolicy Bypass -Scope Process -Force
IEX (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/<org>/<repo>/main/Harden-WindowsDefender.ps1' -UseBasicParsing).Content
```

Or if Invoke-WebRequest is blocked:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
$script = (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/<org>/<repo>/main/Harden-WindowsDefender.ps1')
IEX $script
```

**Pros:** Zero infrastructure. Works on any machine with internet access. One-liner.
**Cons:** Requires internet access. Must be run manually on each machine (or scripted into a batch file on a USB). Execution policy must allow it.

### Method 6: USB Drive - Air-Gapped or Offline Machines

Best for machines with no network access or machines being rebuilt from clean media.

**Steps:**
1. Copy `Harden-WindowsDefender.ps1` to a USB drive
2. On the target machine, open PowerShell as Administrator
3. Run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
& "E:\Harden-WindowsDefender.ps1"
```

(Replace E: with the USB drive letter)

**Pros:** Works on completely isolated machines. No network or internet needed.
**Cons:** Manual per-machine process. Does not scale. Signature updates in the script will fail without internet.

### Method 7: SCCM/MECM (Microsoft Endpoint Configuration Manager)

Best if ISAAC uses ConfigMgr for endpoint management.

**Steps:**
1. Create a new Package with the script as the source
2. Create a Program that runs: `powershell.exe -ExecutionPolicy Bypass -File Harden-WindowsDefender.ps1`
3. Distribute to a distribution point
4. Deploy to a device collection (All Systems or targeted)
5. Set purpose to Required for automatic deployment

**Note:** If using SCCM, the PSExec/WMI ASR rule is set to Audit mode in the script to avoid conflicts. Do NOT change it to Block while SCCM is in use.

### Deployment Decision Matrix

| Scenario | Recommended Method |
|----------|-------------------|
| Domain-joined PCs, need full coverage | GPO (Method 1) |
| Need it on 50 machines right now | PowerShell Remoting (Method 2) |
| Non-technical staff deploying | PDQ Deploy (Method 3) |
| Cloud-managed devices (Azure AD) | Intune (Method 4) |
| Standalone machines, have internet | IEX Pull (Method 5) |
| No network, rebuilding from scratch | USB (Method 6) |
| SCCM environment | SCCM Package (Method 7) |
| Mix of the above | Combine methods as needed |

---

## What We Can Help With

CyberPools can assist ISAAC with:
1. The hardening script is ready to deploy (attached)
2. Guidance on Wazuh server setup and agent deployment
3. Sysmon configuration tuned for K-12 environments
4. Ongoing monitoring support through the Cyber Toolkit program

**Contact:** cyber@cyberpools.org
