# VORYNEX — Enterprise Exposure Intelligence Framework

```
██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗██╗  ██╗
██║   ██║██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝╚██╗██╔╝
██║   ██║██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║█████╗   ╚███╔╝
╚██╗ ██╔╝██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║██╔══╝   ██╔██╗
 ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ██║ ╚████║███████╗██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**Enterprise Exposure Intelligence Framework**

| Tool | Version | Scope | Author |
|------|---------|-------|--------|
| VERTEX | v1.0.0 | Network + Endpoint | Anas Labrini |
| VORTEX | v2.0.0 | Deep Endpoint Intel | Anas Labrini |

> **FOR AUTHORIZED ASSESSMENT USE ONLY.**
> This framework is intended exclusively for authorized Purple Team engagements, internal security assessments, and penetration tests conducted under valid written authorization from the asset owner.

---

## Table of Contents

1. [Framework Overview](#1-framework-overview)
2. [Platform Compatibility & Requirements](#2-platform-compatibility--requirements)
3. [VERTEX — Visual Exposure & Risk Topology EXaminer](#3-vertex--visual-exposure--risk-topology-examiner)
4. [VORTEX — Vulnerability & Operational Risk Telemetry EXtraction](#4-vortex--vulnerability--operational-risk-telemetry-extraction)
5. [Usage Reference](#5-usage-reference)
6. [Operational Flow Maps](#6-operational-flow-maps)
7. [Authorized Use & Legal Notice](#7-authorized-use--legal-notice)

---

## 1. Framework Overview

VORYNEX is a self-contained Enterprise Exposure Intelligence Framework composed of two independent assessment engines: **VERTEX** and **VORTEX**. Both tools are designed for Purple Team practitioners, security engineers, and authorized assessors.

The framework is orchestrated through a unified entry point (`main.py`) that presents a menu-driven interface and routes execution to either engine based on operator selection. Each engine runs independently, maintains its own collection pipeline, and produces structured output in JSON and HTML formats without dependency on the other.

### 1.1 Framework Architecture

| Component | Module | Role |
|-----------|--------|------|
| `main.py` | Orchestration Layer | Menu-driven launcher. Routes to VERTEX or VORTEX, handles errors and keyboard interrupts globally. |
| `vertex.py` | VERTEX Engine v1.0.0 | Network topology mapping, service scanning, exposure analysis, identity audit, correlated HTML/JSON report. |
| `vortex.py` | VORTEX Engine v2.0.0 | Deep endpoint intelligence across 11 collection domains, multi-axis risk scoring, artifact correlation, HTML/JSON/LOG report. |

### 1.2 Entry Point: main.py

`main.py` serves as the unified launcher for the framework. It imports both engines from the `vorynex` package and exposes a numbered menu:

```
[1] VERTEX  —  Visual Exposure & Risk Topology EXaminer
[2] VORTEX  —  Vulnerability & Operational Risk Telemetry EXtraction
[0] Exit
```

**Execution flow:** The operator selects a tool number. `main.py` invokes the corresponding `executionstart()` function inside the selected module, wraps execution in a structured `try/except/finally` block (catching `KeyboardInterrupt` and arbitrary exceptions), then pauses for output review before returning to the menu. The loop runs until the operator selects Exit or sends SIGINT at the menu level.

---

## 2. Platform Compatibility & Requirements

### 2.1 Operating System Support Matrix

| Capability | Win 10 | Win 11 | Win Server 2016+ | Linux | macOS |
|-----------|--------|--------|-----------------|-------|-------|
| VERTEX — Full Mode | Full | Full | Full | Degraded* | Degraded* |
| VERTEX — Network Scan | Full | Full | Full | Partial** | Partial** |
| VERTEX — Identity Audit | Full | Full | Full | N/A | N/A |
| VERTEX — Hardening Inspector | Full | Full | Full | N/A | N/A |
| VORTEX — All Domains | Full | Full | Full | Not Supported | Not Supported |
| VORTEX — Registry Access | Full | Full | Full | Not Supported | Not Supported |
| VORTEX — WinRM / SMB | Full | Full | Full | Not Supported | Not Supported |
| Report Generation (HTML/JSON) | Full | Full | Full | Full | Full |

> `*` **Degraded mode on Linux/macOS:** The VERTEX network scan and topology mapping function, but the Identity Auditor and Hardening Inspector stages require Windows APIs and are skipped automatically.
>
> `**` **Partial on Linux:** ARP table, subnet detection, and live-host sweep operate. Some banner probes and service fingerprinting depend on Windows-specific command formatting.

VORTEX imports `winreg` directly at module load time. Attempting to run VORTEX on Linux or macOS results in an `ImportError` before execution begins.

### 2.2 Privilege Requirements

| Function | Standard User | Administrator / Elevated |
|----------|--------------|--------------------------|
| Network scan, ARP, DNS | Supported | Supported (faster) |
| SMB share enumeration (VERTEX) | Limited | Full access |
| Identity audit — local accounts | Supported | Supported |
| Hardening inspection — writable services | Partial | Full |
| VORTEX — Registry HKLM enumeration | Denied / Partial | Full (HKLM + HKCU) |
| VORTEX — Process intelligence (psutil) | Own processes only | All processes |
| VORTEX — Security Event Log (Event ID 4624) | Denied | Full read |
| VORTEX — WMI Subscriptions | Partial | Full |

### 2.3 Runtime Dependencies

| Package | Required By | Install | Notes |
|---------|------------|---------|-------|
| Python Standard Library | Both | Built-in | `socket`, `subprocess`, `ipaddress`, `ctypes`, `winreg`, `concurrent.futures`, `threading`, `logging`, `re`, `json`, `hashlib`, `datetime`, `pathlib`, `argparse` |
| `colorama` | Both | Auto-installed at startup | Provides ANSI color support on Windows terminals. Gracefully disabled if unavailable. |
| `Jinja2` | VERTEX | Auto-installed at startup | Used for HTML report template rendering. |
| `psutil` | VORTEX (D03) | `pip install psutil` | Optional. If absent, domain D03 is skipped entirely with status `SKIP`. |
| `winreg` | VORTEX | Built-in (Windows only) | Part of the Python standard library on Windows. Not available on Linux/macOS. Enables all registry-based domains. |

---

## 3. VERTEX — Visual Exposure & Risk Topology EXaminer

```
  ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Version:** 1.0.0 | **Author:** Anis El Brini | **Classification:** Purple Team Assessment Platform

VERTEX is a multi-stage network and endpoint assessment engine. It performs correlated topology mapping, service fingerprinting, identity auditing, hardening inspection, and risk scoring from a single execution. It supports three operational modes and outputs a structured JSON file, a fully rendered HTML report, and a timestamped debug log.

### 3.1 Operational Modes

| Mode | Active Stages | Description |
|------|--------------|-------------|
| `network` | 1, 2, 3, 5, 7, 8, 9 | Topology mapping, subnet discovery, live-host sweep, service scanning, SMB exposure analysis. |
| `endpoint` | 1, 4, 6, 7, 8, 9 | Local identity audit, privilege detection, hardening inspection of services and scheduled tasks. |
| `full` *(default)* | 1 through 9 | Complete correlated assessment combining all network and endpoint stages. |

### 3.2 Nine-Stage Collection Pipeline

Each stage is independently wrapped in a `try/except` block. Stages report status as `OK`, `PARTIAL`, `FAILED`, or `SKIPPED`. The pipeline never halts on individual stage failure. Per-stage timeout defaults to **120 seconds**.

---

#### Stage 1 — EnvironmentProbe

**Scope:** All modes

Collects baseline host context before any network activity:

- OS name, version, release, architecture, and Python version
- Hostname via `socket.gethostname()`
- Current user and privilege level — elevated detection via `ctypes.windll.shell32.IsUserAnAdmin()` on Windows, `os.getuid() == 0` on Linux/macOS
- Active network interfaces enumerated via `socket.getaddrinfo()` and `ipconfig /all` (Windows) or `ip route` (Linux)
- IPv4 addresses, subnet masks, default gateways, and MAC addresses per adapter

---

#### Stage 2 — TopologyMapper

**Scope:** `network`, `full`

Discovers the network topology around the host:

- Subnet CIDR ranges derived from interface IP and mask pairs
- ARP table read via `arp -a` (Windows) or `arp -n` (Linux) — maps IP to MAC addresses, filters broadcast and zero MACs
- Live-host sweep: TCP connect probe on 9 ports (`80, 443, 22, 445, 3389, 8080, 8443, 135, 139`) across all hosts in detected subnets using **200 concurrent threads** (`ThreadPoolExecutor`)
- Subnets larger than `/16` are skipped to prevent excessive scan duration
- Reverse DNS resolution for all live hosts via `socket.gethostbyaddr()` using 50 concurrent threads
- Fallback subnet: if detection fails, defaults to `<local_ip_prefix>.0/24`

---

#### Stage 3 — HostServiceScanner

**Scope:** `network`, `full`

Performs service discovery on every live host discovered in Stage 2:

- TCP connect scan across **60+ classified ports** using **40 concurrent threads per host**
- Connect timeout: **1.5 seconds** per port; banner capture timeout: **2.0 seconds**
- Banner capture: sends protocol-specific probes per port (HTTP HEAD, Redis PING, RTSP OPTIONS, PJL for printers, etc.)
- Service name resolution from a built-in port-to-name table (60+ entries)
- **Device fingerprinting** via banner regex matching against **30+ vendor signatures** including HP/Ricoh/Epson/Canon/Lexmark/Brother/Konica Minolta printers, Hikvision/Dahua/Axis/Bosch IP cameras, Windows Server (IIS, WinRM), Linux servers (OpenSSH), Cisco/Juniper/MikroTik network devices, Fortinet/pfSense firewalls, Apache/Nginx/Lighttpd web servers, Microsoft Exchange, VMware ESXi, Synology/QNAP/TrueNAS NAS, and Modbus/BACnet industrial controllers
- **MAC OUI vendor lookup** from a built-in table covering HP, Hikvision, Dahua, Axis, Cisco, MikroTik, VMware, VirtualBox, Google, Ubiquiti, Synology, QNAP, and others
- OS hint derivation from banner content

---

#### Stage 4 — IdentityAuditor

**Scope:** `endpoint`, `full`

Audits the local identity surface:

- Local user accounts enumeration
- Local group memberships — Administrators group members
- Active interactive sessions via `quser`
- Domain name and domain controller list
- Cached logon count from the registry (`CachedLogonsCount`)

---

#### Stage 5 — ExposureAnalyzer

**Scope:** `network`, `full`

Analyzes SMB exposure across discovered hosts:

- SMB share enumeration per host
- Detection of anonymously accessible shares (null session test)
- Classification of exposed vs. authenticated-only shares

---

#### Stage 6 — HardeningInspector

**Scope:** `endpoint`, `full`

Inspects local hardening posture:

- Writable Windows service binary paths — potential privilege escalation vectors
- Non-Microsoft scheduled tasks
- Legacy daemon detection
- Service binary path analysis for misconfigured ACLs

---

#### Stage 7 — RiskEngine

**Scope:** All modes

Applies risk classification to all discovered hosts and services:

| Port | Risk Level | Reason |
|------|-----------|--------|
| 23 | CRITICAL | Telnet — plaintext protocol exposed |
| 502 | CRITICAL | Modbus — industrial control protocol exposed |
| 47808 | CRITICAL | BACnet — building automation system exposed |
| 21 | HIGH | FTP — plaintext credential transmission |
| 161 | HIGH | SNMP — potential information disclosure |
| 5900 | HIGH | VNC — unauthenticated remote access risk |
| 5985 | HIGH | WinRM HTTP — lateral movement surface |
| 9200 | HIGH | Elasticsearch — commonly unauthenticated |
| 27017 | HIGH | MongoDB — commonly unauthenticated |
| 6379 | HIGH | Redis — commonly unauthenticated |
| 3389 | MEDIUM | RDP — remote desktop exposed to network segment |
| 445 | MEDIUM | SMB — file sharing lateral movement surface |
| 389 | MEDIUM | LDAP unencrypted — credential interception risk |

---

#### Stage 8 — CorrelationBuilder

**Scope:** All modes

Constructs an entity relationship graph from all collected data:

**Node types:** `Host`, `User`, `Service`, `Device`, `Subnet`

**Edge types:**

| Relation | Meaning |
|----------|---------|
| `CONNECTS_TO` | Network connectivity between hosts |
| `HOSTS_SERVICE` | Host exposes a service on a port |
| `HAS_ACCOUNT` | Host has a local user account |
| `EXPOSES_SHARE` | Host exposes an SMB share (anonymously or authenticated) |
| `RESOLVES_TO` | IP resolves to a hostname via reverse DNS |
| `MEMBER_OF` | User is a member of a group |
| `TRUSTS` | Domain trust relationship |
| `SESSION_ON` | Active user session on a host |

---

#### Stage 9 — ReportComposer

**Scope:** All modes

Compiles all collected data into structured output:

- `vertex_report_<timestamp>.html` — Fully rendered interactive HTML report, auto-opened in the default browser on completion
- `vertex_report_<timestamp>.json` — Complete structured JSON schema covering all stage results, host records, and the entity graph
- `vertex_<timestamp>.log` — DEBUG-level rotating log with timestamps, stage events, and error traces

---

### 3.3 Service Taxonomy

VERTEX classifies all scanned ports into 13 service categories:

| Category | Ports |
|----------|-------|
| `remote_access` | 22, 23, 3389, 5900, 5985, 5986, 4899 |
| `file_transfer` | 21, 445, 139, 2049, 548, 990 |
| `web` | 80, 443, 8080, 8443, 8000, 8888, 3000, 9090 |
| `directory` | 389, 636, 88, 464 |
| `database` | 1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984 |
| `network_infra` | 53, 67, 68, 123, 161, 162, 179, 520 |
| `printing` | 515, 631, 9100 |
| `surveillance` | 554, 8554, 37777, 34567 |
| `industrial` | 102, 502, 47808, 4840, 1911 |
| `messaging` | 25, 110, 143, 465, 587, 993, 995, 1883, 8883 |
| `monitoring` | 199, 10050, 10051, 9090, 3000 |
| `vpn` | 500, 1194, 1723, 4500 |
| `management` | 623, 664, 3790, 7547 |

### 3.4 VERTEX Limitations

- Does not perform authenticated vulnerability scanning. No CVE checks or patch-level assessment.
- Does not capture or decode network traffic. All probes are TCP connect-based only.
- SMB enumeration is performed via unauthenticated null session; shares requiring credentials are not enumerated.
- Live-host sweep skips subnets larger than `/16` to prevent excessive scan duration.
- Banner capture is passive; no exploit payloads are sent.
- Domain join detection queries `USERDOMAIN` and WMI only; does not enumerate Active Directory structure.
- IP camera and industrial device detection is banner-based only; no protocol-level interaction is performed.

---

## 4. VORTEX — Vulnerability & Operational Risk Telemetry EXtraction

```
  ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Version:** 2.0.0 | **Author:** Anas Labrini | **Platform:** Windows Only

VORTEX is a deep endpoint intelligence engine designed exclusively for Windows environments. It collects telemetry across 11 structured domains, correlates artifacts into attack-chain hypotheses, computes a multi-axis risk score, and emits a JSON report, a rendered HTML dashboard, and a timestamped log. Each domain executes with a configurable per-domain timeout (default: 180 seconds) and gracefully degrades on access denial or missing dependencies.

### 4.1 Operational Modes

| Mode | Active Domains | Use Case |
|------|---------------|----------|
| `endpoint` | D01–D08, D10, D11 | Focused workstation or server assessment without network context. |
| `network` | D01, D09 | Local network context: ARP cache, Wi-Fi profiles, RDP history, mapped drives. |
| `full` *(default)* | D01–D11 (all) | Complete correlated endpoint and network intelligence. |

### 4.2 Eleven Collection Domains

All domains inherit from `BaseDomain` and share common utilities: PowerShell execution via `subprocess`, registry enumeration via `winreg`, command-line subprocess calls, SHA-256 binary hashing, and structured finding emission with severity tagging.

---

#### D01 — System Identity

**Windows only** | Standard user sufficient

- Hostname, OS version, OS release, architecture
- Total RAM and CPU model via `Win32_ComputerSystem`
- BIOS serial number and UUID via `Win32_BIOS`
- Domain join status and domain name
- Virtualization detection (VMware, VirtualBox, Hyper-V, QEMU, KVM) via hardware profile strings
- System uptime in hours
- Timezone ID
- OS install date

---

#### D02 — User & Session Intelligence

**Windows only** | Standard user sufficient (Event Log requires elevation)

- Current username, domain, and profile path from environment variables
- Active interactive sessions via `quser`
- Local Administrators group members via `Get-LocalGroupMember`
- Flags admin density: MEDIUM finding if more than 3 members, HIGH finding if more than 5
- Cached logon count from `HKLM\...\Winlogon\CachedLogonsCount`
- Active RDP client process count via `Get-Process mstsc`
- Last 5 Security Event Log entries (Event ID 4624 — successful logon)

---

#### D03 — Process Intelligence

**Windows only** | Requires `psutil` | Elevated recommended for full process list

- Enumerates all non-system processes via `psutil.process_iter()`
- Collected per process: PID, name, executable path, username, parent PID, status, network connection count, SHA-256 hash of the binary
- Filters noise (svchost, lsass, csrss, smss, etc.) from output
- Flags notable processes by name and assigns category and severity:

| Process | Category | Severity |
|---------|----------|----------|
| `anydesk.exe`, `teamviewer.exe`, `rustdesk.exe` | Remote Access | HIGH |
| `wireshark.exe`, `tshark.exe` | Traffic Capture | HIGH |
| `nmap.exe` | Network Scanner | HIGH |
| `burpsuite.jar` | Proxy / Intercept | HIGH |
| `psexec.exe` | Lateral Movement | HIGH |
| `mimikatz.exe` | Credential Tool | CRITICAL |
| `vnc.exe` | Remote Access | MEDIUM |
| `x64dbg.exe` | Debugger | MEDIUM |
| `procmon.exe` | Sysinternals | LOW |
| `python.exe`, `powershell.exe`, `cmd.exe` | Scripting / Shell | LOW |

---

#### D04 — Software Inventory

**Windows only** | Standard user sufficient for HKCU; elevation for full HKLM

- Reads all installed software from three registry paths:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- Collected per entry: name, version, publisher, install date
- Categorizes software into 8 groups: `security`, `remote`, `dev_tools`, `cloud`, `monitoring`, `database`, `vpn`, `virtualization`
- Flags **Remote Access Without EDR** (HIGH) if remote access tools are present but no security software is detected

---

#### D05 — Filesystem Surface

**Windows only** | Standard user sufficient

- Enumerates up to 80 entries from each of: Desktop, Downloads, Documents
- Collected per entry: name, type (file/dir), size in KB, last modified date
- Classifies files: executables (`.exe`, `.bat`, `.ps1`, `.vbs`, `.hta`), archives (`.zip`, `.rar`, `.7z`, `.tar`, `.gz`), PDFs, Office documents
- Flags executables found in user-facing folders as **MEDIUM** risk

---

#### D06 — Persistence Mechanisms

**Windows only** | Elevation recommended for full coverage

- Registry Run and RunOnce keys (HKLM + HKCU): `SOFTWARE\Microsoft\Windows\CurrentVersion\Run[Once]`
- Startup folder entries: per-user (`%APPDATA%\...\Startup`) and per-machine (`%PROGRAMDATA%\...\StartUp`)
- Non-Microsoft scheduled tasks via `Get-ScheduledTask` (filters `\Microsoft*` paths)
- PowerShell profile files (`$PROFILE` paths for both Windows PowerShell and PowerShell 7)
- WMI Event Subscriptions via `Get-WMIObject -Namespace root/subscription -Class __EventFilter` — flags as **HIGH** if any subscriptions are detected

---

#### D07 — Security & Telemetry

**Windows only** | Standard user sufficient for most checks; elevation for Event Log

- PowerShell version — flags PSv2 as **HIGH** (PSv2 lacks AMSI and script block logging)
- Execution policy — flags `Bypass` or `Unrestricted` as **HIGH**
- PowerShell logging status (registry-checked):
  - Script Block Logging (`EnableScriptBlockLogging`) — flags disabled as MEDIUM
  - Module Logging (`EnableModuleLogging`) — flags disabled as MEDIUM
  - Transcription (`EnableTranscripting`) — flags disabled as MEDIUM
- Windows Defender status via `Get-MpComputerStatus`: RealTimeProtectionEnabled, AntivirusEnabled, BehaviorMonitorEnabled, AMServiceEnabled
- Sysmon service status
- EDR detection via service name matching against 30+ vendors including CrowdStrike, SentinelOne, Carbon Black, Cylance, Defender ATP, Symantec, McAfee, Sophos, Trend Micro, and others
- UAC registry settings

---

#### D08 — Service Landscape

**Windows only** | Elevation recommended

- Enumerates all non-system Windows services via PowerShell
- Collected per service: name, display name, status, start type, binary path, service account
- Detects **writable service binary paths** — configurations where non-administrator users can replace the service binary (privilege escalation path)

---

#### D09 — Network Context

**Windows only** | Standard user sufficient

- Active TCP and UDP connections via `netstat`
- Network interface configuration via `ipconfig`
- Local DNS cache
- Proxy settings from registry (`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
- ARP cache (up to 50 entries) via `arp -a`
- Saved Wi-Fi profiles (SSID names only) via `netsh wlan show profiles`
- Mapped network drives via `Get-PSDrive -PSProvider FileSystem`
- RDP connection history from `HKCU\Software\Microsoft\Terminal Server Client\Servers`

---

#### D10 — Credential Surface

**Windows only** | Standard user sufficient

Detection is **path-based only**. VORTEX identifies credential artifact locations. It does not read, decrypt, transmit, or store credential content.

| Artifact | Path | Severity if Found |
|----------|------|------------------|
| SSH private keys | `~/.ssh/*` (non-`.pub`) | HIGH |
| AWS credentials | `~/.aws/credentials` | CRITICAL |
| Azure profile JSON | `~/.azure/*.json` | HIGH |
| Git credentials | `~/.git-credentials` | CRITICAL |
| VPN config files | `.ovpn`, `.conf`, `.vpn` in 6 search directories | MEDIUM |
| KeePass databases | `*.kdbx` in Documents, Desktop, Downloads, home | INFO |
| Browser profiles | Chrome, Edge, Firefox, Brave profile paths | INFO |

An internal **exposure score** is computed (sum of weighted artifact detections). Scores of 5 or higher tag the host as `high-credential-exposure`.

---

#### D11 — Dev & Admin Environment

**Windows only** | Standard user sufficient

- Installed developer tools and versions: Python, Node.js, Git, Docker, kubectl, Terraform
- Active WSL distributions via `wsl --list --quiet`
- Detected IDEs: VS Code (`code.exe`), PyCharm (`pycharm64.exe`), IntelliJ IDEA (`idea64.exe`), WebStorm (`webstorm64.exe`), Rider (`rider64.exe`)
- Hypervisor service status: Hyper-V (`vmms`), VMware (`VMwareAuthd`), VirtualBox (`VBoxSVC`)

---

### 4.3 Artifact Correlation Engine

After all domains complete, VORTEX runs `run_correlation()` which cross-references findings across domains to construct attack-chain hypotheses:

| Chain ID | Title | Trigger Conditions | Confidence |
|----------|-------|--------------------|-----------|
| `CHAIN-CRED-01` | Multi-Vector Credential Exposure | 2 or more present: SSH keys + AWS credentials + Git credentials + KeePass databases | HIGH |
| `CHAIN-ACCESS-01` | Unmonitored Remote Access Vector | Remote access software (D04) present AND no EDR detected (D07) | HIGH |
| `CHAIN-PS-01` | PowerShell Attack Surface Elevated | 2 or more: PSv2 present + No Script Block Logging + Unrestricted execution policy | HIGH |
| `CHAIN-LAT-01` | Lateral Movement Indicators | Domain-joined host (D01) AND (mapped drives OR RDP history) present (D09) | MEDIUM |

In addition, VORTEX cross-validates tool presence across three evidence sources (running process, installed service, installed software) and flags tools confirmed by two or more sources as **multi-confirmed artifacts**.

### 4.4 Multi-Axis Risk Scoring

The risk score is computed across six axes, each capped at 20 points. The overall score is the sum of all axes, adjusted upward by 3 points per active correlation chain:

| Risk Axis | Key Scoring Factors | Max |
|-----------|-------------------|-----|
| Detection Risk | No Script Block Logging (+7), No Module Logging (+4), No Transcription (+4), Sysmon not running (+5) | 20 |
| Security Maturity | Defender RTP disabled (+12), Behavior Monitor off (+5), Unrestricted PS policy (+8) | 20 |
| Admin Density | More than 5 local admins (+15), more than 3 local admins (+8) | 20 |
| Credential Exposure | Exposure score × 3 (from D10 artifacts) | 20 |
| Lateral Movement Ready | Domain-joined (+5), Mapped drives (+5), RDP history (+4) | 20 |
| Monitoring Visibility | EDR detected (+2), No EDR present (+10) | 20 |

**Risk Rating Scale:**

| Score | Rating | Interpretation |
|-------|--------|---------------|
| 0 – 29 | LOW | Minimal risk posture |
| 30 – 49 | MEDIUM | Moderate risk, attention recommended |
| 50 – 69 | HIGH | Significant risk, remediation required |
| 70 – 100 | CRITICAL | Critical exposure, immediate action required |

### 4.5 Output Files

| File | Format | Contents |
|------|--------|----------|
| `VORTEX_<session_id>.json` | JSON | Complete report: metadata, risk profile, all 11 domain data sets and findings, correlation chains |
| `VORTEX_<session_id>.html` | HTML | Interactive dashboard with risk gauge, 6-axis bar chart, domain cards, correlation chain cards, searchable findings |
| `VORTEX_<session_id>.log` | Plain text | Timestamped INFO/WARNING/ERROR log, per-domain execution results, correlation count, overall risk rating |

**Session ID format:**

```
VORTEX_<HOSTNAME>_<YYYYMMDD>_<HHMMSS>
Example: VORTEX_WORKSTATION01_20250524_143022
```

### 4.6 VORTEX Limitations

- Exclusively Windows-compatible. `winreg` is imported at module load; execution on Linux or macOS fails immediately with `ImportError`.
- Process intelligence (D03) requires `psutil`. Without it, domain D03 is skipped entirely.
- Security Event Log (Event ID 4624) access requires administrative privilege.
- Registry enumeration for HKLM keys may be incomplete without elevated privileges.
- Credential surface detection (D10) is path-based only. No credential content is read or extracted.
- Wi-Fi profile enumeration lists SSID names only; passwords are not retrieved.
- Software inventory (D04) reflects registry-registered applications only; portable executables not listed in Add/Remove Programs are not captured.
- VORTEX does not perform network scanning, lateral movement, or any active probing beyond the local host.

---

## 5. Usage Reference

### 5.1 Launching via main.py (Recommended)

```bash
python main.py
```

Then select from the interactive menu:

```
[1] VERTEX  —  Visual Exposure & Risk Topology EXaminer
[2] VORTEX  —  Vulnerability & Operational Risk Telemetry EXtraction
[0] Exit
```

### 5.2 Direct Invocation — VERTEX

```bash
# Default full assessment
python vertex.py

# Network-only mode
python vertex.py --mode network

# Endpoint-only mode
python vertex.py --mode endpoint

# Full correlated assessment (explicit)
python vertex.py --mode full
```

### 5.3 Direct Invocation — VORTEX

```bash
# Default full assessment
python VORTEX.py

# Full assessment with custom output directory
python VORTEX.py --mode full --output ./reports

# Network context only, JSON output, 60-second timeout
python VORTEX.py --mode network --json-only --timeout 60

# Endpoint mode, verbose output, no ANSI colors
python VORTEX.py --mode endpoint --no-color --verbose
```

### 5.4 VORTEX CLI Arguments

| Argument | Values | Default | Effect |
|----------|--------|---------|--------|
| `--mode` | `endpoint` \| `network` \| `full` | `full` | Assessment scope |
| `--output` | Directory path | `./VORTEX_output` | Report output directory (created if absent) |
| `--timeout` | Integer (seconds) | `180` | Per-domain execution timeout |
| `--json-only` | Flag | `False` | Skip HTML report generation, emit JSON only |
| `--no-color` | Flag | `False` | Disable ANSI colors (useful for log redirection) |
| `--verbose` | Flag | `False` | Print top 5 findings per domain inline during execution |

---

## 6. Operational Flow Maps

### 6.1 VERTEX — Execution Flow

```
main.py [Option 1]
    └── vertex.executionstart()
            └── _parse_args()
                    └── AssessmentEngine(mode=args.mode).execute()
                            │
                            ├── [ALL MODES]
                            │   └── Stage 1: EnvironmentProbe.execute()
                            │       Input:  System APIs, ipconfig/ip, ENV vars
                            │       Output: env_data dict  ──────────────────────┐
                            │                                                     │
                            ├── [network | full]                                  │
                            │   └── Stage 2: TopologyMapper.execute()             │
                            │       Input:  env_data (interface IPs)  ◄───────────┘
                            │       Output: live_hosts[], arp_table{}, dns_map{}
                            │                                                     │
                            ├── [network | full]                                  │
                            │   └── Stage 3: HostServiceScanner.scan(ip, mac)     │
                            │       Input:  live_hosts[] (200 threads)  ◄─────────┘
                            │       Output: HostRecord[] with services[], banners, device_class
                            │
                            ├── [endpoint | full]
                            │   └── Stage 4: IdentityAuditor.execute()
                            │       Input:  Windows APIs
                            │       Output: local_accounts[], admin_members[], sessions[], domain
                            │
                            ├── [network | full]
                            │   └── Stage 5: ExposureAnalyzer.execute(records)
                            │       Input:  HostRecord[] from Stage 3
                            │       Output: shares[], exposed_shares[] appended to each HostRecord
                            │
                            ├── [endpoint | full]
                            │   └── Stage 6: HardeningInspector.execute()
                            │       Input:  Windows service APIs
                            │       Output: hardening{} with findings[]
                            │
                            ├── [ALL MODES]
                            │   └── Stage 7: RiskEngine.evaluate(records, identity)
                            │       Input:  All HostRecord[], identity data
                            │       Output: risk_findings[] written to each HostRecord in-place
                            │
                            ├── [ALL MODES]
                            │   └── Stage 8: CorrelationBuilder.build(...)
                            │       Input:  env_data, topology, records, identity, hardening
                            │       Output: CorrelationGraph(nodes[], edges[])
                            │
                            └── [ALL MODES]
                                └── Stage 9: ReportComposer.compose(...)
                                    Input:  All data from all prior stages
                                    Output: vertex_report_<ts>.html
                                            vertex_report_<ts>.json
                                            vertex_<ts>.log
                                            └── Auto-open HTML in default browser
```

**Error handling:** Each stage is wrapped in `_run_guarded()` which enforces a 120-second timeout and returns `StageResult(status=FAILED)` on exception, then continues to the next stage.

---

### 6.2 VORTEX — Execution Flow

```
main.py [Option 2]
    └── vortex.executionstart()
            └── _build_args()
                    └── Context(mode, output_dir, timeout, json_only, verbose)
                            │   Initializes: hostname, os_platform, start_time,
                            │               is_windows, is_elevated, session_id
                            │
                            └── Orchestrator(ctx).run()
                                    │
                                    ├── [COLLECTION PIPELINE]
                                    │   Iterates domain_classes = MODE_DOMAINS[mode]
                                    │   Each domain:  instance.collect()  ──► _execute() with timeout
                                    │                 Returns DomainResult(status, data, findings, tags)
                                    │
                                    │   ┌─────────────────────────────────────────────────────┐
                                    │   │  D01  SystemIdentity      Win32_* WMI, PS cmdlets    │
                                    │   │  D02  UserSession         quser, Get-LocalGroupMember│
                                    │   │  D03  ProcessIntel        psutil.process_iter()       │
                                    │   │  D04  SoftwareInventory   Registry Uninstall keys     │
                                    │   │  D05  FilesystemSurface   Path.iterdir() on user dirs │
                                    │   │  D06  PersistenceMap      Run keys, tasks, WMI subs   │
                                    │   │  D07  SecurityTelemetry   PS logging, Defender, EDR   │
                                    │   │  D08  ServiceLandscape    Get-Service, ACL checks      │
                                    │   │  D09  NetworkContext      netstat, arp, Wi-Fi, RDP hist│
                                    │   │  D10  CredentialSurface   ~/.ssh, ~/.aws, .git-creds   │
                                    │   │  D11  DevAdminEnvironment Dev tools, WSL, IDEs, VMs    │
                                    │   └─────────────────────────────────────────────────────┘
                                    │
                                    ├── [CORRELATION ENGINE]
                                    │   run_correlation(domains)
                                    │   Cross-references D01, D04, D06, D07, D09, D10
                                    │   Output: correlation_chains[]       (CHAIN-CRED-01, etc.)
                                    │           high_confidence_findings[]
                                    │           medium_confidence_findings[]
                                    │           multi_confirmed_tools[]
                                    │
                                    ├── [RISK ENGINE]
                                    │   compute_risk(domains, correlation)
                                    │   Scores 6 axes (0–20 each) from D02, D07, D09, D10
                                    │   Adjusts overall score +3 per active correlation chain
                                    │   Output: RiskProfile(overall, rating, axes{}, factors[])
                                    │
                                    └── [REPORT GENERATION]
                                        write_json(report, output_dir)
                                            └── VORTEX_<session_id>.json
                                        write_html(report, output_dir)
                                            └── VORTEX_<session_id>.html
                                        RunLogger.finalize()
                                            └── VORTEX_<session_id>.log
```

**Error handling:** Each domain is executed inside `_execute()` using a single-thread `ThreadPoolExecutor` with `future.result(timeout=ctx.timeout)`. On `TimeoutError` the domain is marked `SKIP`. On any other exception it is marked `FAIL`. The pipeline always continues to the next domain.

---

### 6.3 Session ID Format

```
VERTEX  →  SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
           Output files: vertex_report_20250524_143022.html / .json / .log

VORTEX  →  session_id = f"{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
           Output files: VORTEX_WORKSTATION01_20250524_143022.json / .html / .log
```

---

## 7. Authorized Use & Legal Notice

> **RESTRICTED USE:** The VORYNEX framework is designed exclusively for authorized security assessments, internal Red/Purple Team engagements, and penetration tests conducted under valid written authorization from the asset owner. Use of this framework against systems without explicit written authorization is prohibited and may constitute a criminal offense under applicable cybercrime and computer fraud laws.

- VERTEX and VORTEX are passive assessment tools. They do not exploit vulnerabilities, modify system state, or exfiltrate data beyond the local report files.
- Credential surface detection (VORTEX D10) is path-based only. No credential content is read, decrypted, transmitted, or stored outside the local report files.
- All network probes performed by VERTEX are TCP connect-only. No exploit payloads are sent to any host.
- Report files (HTML, JSON, LOG) are written to the local filesystem only. No data is transmitted to any external endpoint.
- Operators are solely responsible for ensuring all assessments are conducted within authorized scope boundaries.

### Authors

| Tool | Author |
|------|--------|
| VERTEX v1.0.0 | Anas Labrini |
| VORTEX v2.0.0 | Anas Labrini |

---

*VORYNEX — Enterprise Exposure Intelligence Framework*
