# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                                                                              ║
# ║   ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗                        ║
# ║   ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝                        ║
# ║   ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝                         ║
# ║   ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗                         ║
# ║    ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗                        ║
# ║     ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                        ║
# ║                                                                              ║
# ║   Vulnerability & Operational Risk Telemetry EXtraction                      ║
# ║   Purple Team Exposure Analysis Platform  ·  v2.0.0                          ║
# ║   Engineered by Anas Labrini                                                 ║
# ║                                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
"""
VORTEX — Vulnerability & Operational Risk Telemetry EXtraction

Single-file, self-contained security assessment platform for Windows environments.
Performs deep endpoint intelligence gathering across 11 collection domains,
correlates artifacts, scores operational risk, and emits structured JSON + HTML reports.

Usage:
    python VORTEX.py
    python VORTEX.py --mode endpoint
    python VORTEX.py --mode network
    python VORTEX.py --mode full --output ./reports
    python VORTEX.py --json-only --timeout 90
"""

from __future__ import annotations

# ── Standard library ──────────────────────────────────────────────────────────
import argparse
import concurrent.futures
import ctypes
import datetime
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback
import winreg
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

try:
    import colorama
    colorama.init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

class T:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    WHT  = "\033[97m"
    BLU  = "\033[94m"
    CYN  = "\033[96m"
    YLW  = "\033[93m"
    RED  = "\033[91m"
    GRN  = "\033[92m"

_COLOR_ON = True

def _c(code: str, text: str) -> str:
    return f"{code}{text}{T.RST}" if _COLOR_ON else text

def blu(t): return _c(T.BLU + T.BOLD, t)
def cyn(t): return _c(T.CYN,           t)
def wht(t): return _c(T.WHT,           t)
def dim(t): return _c(T.DIM,           t)
def red(t): return _c(T.RED + T.BOLD,  t)
def ylw(t): return _c(T.YLW,           t)
def grn(t): return _c(T.GRN,           t)
def bld(t): return _c(T.BOLD,          t)

BANNER = r"""
  ██╗   ██╗ ██████╗ ██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

def print_banner():
    print()
    print(blu(BANNER))
    sep = cyn("  " + "─" * 56)
    print(sep)
    print(f"  {wht('Vulnerability & Operational Risk Telemetry EXtraction')}")
    print(f"  {dim('Purple Team Exposure Analysis Platform  ·  v2.0.0')}")
    print(f"  {dim('Engineered by Anas Labrini')}")
    print(sep)
    print()

def section_header(title: str, idx: int, total: int):
    bar = cyn("  " + "━" * 56)
    print(f"\n{bar}")
    print(f"  {blu(f'[{idx:02d}/{total:02d}]')}  {bld(title)}")
    print(bar)

def status_ok(label: str, value: str):
    print(f"    {cyn('◆')}  {dim(label + ':'):<28}{wht(str(value))}")

def status_warn(label: str, value: str):
    print(f"    {ylw('▲')}  {dim(label + ':'):<28}{ylw(str(value))}")

def status_crit(label: str, value: str):
    print(f"    {red('●')}  {dim(label + ':'):<28}{red(str(value))}")

def status_dim(label: str, value: str):
    print(f"    {dim('◇')}  {dim(label + ':'):<28}{dim(str(value))}")

def collector_row(name: str, status: str, count: int, elapsed: float):
    pad = max(0, 36 - len(name))
    s = grn("PASS") if status == "pass" else (ylw("SKIP") if status == "skip" else red("FAIL"))
    print(f"    {wht(name)}{' ' * pad}{s}  {dim(str(count) + ' items')}  {dim(f'{elapsed:.1f}s')}")

def risk_bar(score: int) -> str:
    filled = int(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    if score < 30:   return grn(bar)
    elif score < 50: return ylw(bar)
    else:            return red(bar)

def risk_label(score: int) -> str:
    if score < 30:   return grn(f"LOW ({score})")
    elif score < 50: return ylw(f"MEDIUM ({score})")
    elif score < 70: return red(f"HIGH ({score})")
    else:            return red(f"CRITICAL ({score})")

@dataclass
class DomainResult:
    domain_id: str
    display_name: str
    status: str = "pass"
    error: Optional[str] = None
    elapsed: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @property
    def item_count(self) -> int:
        return len(self.findings) + sum(
            len(v) if isinstance(v, list) else (1 if v else 0)
            for v in self.data.values()
        )

    def to_dict(self) -> dict:
        return {
            "domain_id": self.domain_id,
            "display_name": self.display_name,
            "status": self.status,
            "error": self.error,
            "elapsed_seconds": round(self.elapsed, 2),
            "item_count": self.item_count,
            "tags": self.tags,
            "data": self.data,
            "findings": self.findings,
        }


@dataclass
class RiskProfile:
    overall: int = 0
    rating: str = "LOW"
    axes: Dict[str, int] = field(default_factory=dict)
    factors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_score": self.overall,
            "rating": self.rating,
            "axes": self.axes,
            "contributing_factors": self.factors,
        }


@dataclass
class VortexReport:
    session_id: str
    hostname: str
    os_platform: str
    mode: str
    privilege: str
    start_time: str
    end_time: str
    domains: List[DomainResult] = field(default_factory=list)
    correlation: Dict[str, Any] = field(default_factory=dict)
    risk: RiskProfile = field(default_factory=RiskProfile)

    def to_dict(self) -> dict:
        return {
            "meta": {
                "tool": "VORTEX",
                "version": "2.0.0",
                "author": "Anas Labrini",
                "session_id": self.session_id,
                "hostname": self.hostname,
                "platform": self.os_platform,
                "mode": self.mode,
                "privilege": self.privilege,
                "start_time": self.start_time,
                "end_time": self.end_time,
            },
            "risk_profile": self.risk.to_dict(),
            "correlation": self.correlation,
            "domains": [d.to_dict() for d in self.domains],
        }


@dataclass
class Context:
    mode: str
    output_dir: str
    timeout: int
    json_only: bool
    verbose: bool

    hostname: str = field(init=False)
    os_platform: str = field(init=False)
    start_time: datetime.datetime = field(init=False)
    is_windows: bool = field(init=False)
    is_elevated: bool = field(init=False)

    def __post_init__(self):
        self.hostname    = socket.gethostname()
        self.os_platform = platform.system()
        self.start_time  = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        self.is_windows  = platform.system() == "Windows"
        self.is_elevated = self._check_elevation()
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

    def _check_elevation(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin()) if self.is_windows else os.geteuid() == 0
        except Exception:
            return False

    @property
    def session_id(self) -> str:
        return f"{self.hostname}_{self.start_time.strftime('%Y%m%d_%H%M%S')}"

    @property
    def privilege_label(self) -> str:
        return "ELEVATED" if self.is_elevated else "STANDARD"


class BaseDomain:
    domain_id: str = ""
    display_name: str = ""
    requires_elevation: bool = False
    windows_only: bool = True

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._r = DomainResult(domain_id=self.domain_id, display_name=self.display_name)

    def collect(self) -> DomainResult:
        if self.windows_only and not self.ctx.is_windows:
            self._r.status = "skip"
            self._r.error  = "Windows-only domain"
            return self._r
        if self.requires_elevation and not self.ctx.is_elevated:
            self._r.status = "skip"
            self._r.error  = "Requires elevated privileges"
            return self._r
        try:
            self._gather()
        except PermissionError as e:
            self._r.status = "skip"
            self._r.error  = f"Access denied: {e}"
        except Exception as e:
            self._r.status = "fail"
            self._r.error  = str(e)
        return self._r

    def _gather(self): pass

    def _set(self, k: str, v: Any): self._r.data[k] = v
    def _tag(self, *tags: str):
        for t in tags:
            if t not in self._r.tags: self._r.tags.append(t)
    def _finding(self, title: str, detail: str, severity: str = "info", tags: List[str] = None):
        self._r.findings.append({"title": title, "detail": detail, "severity": severity, "tags": tags or []})

    @staticmethod
    def _cmd(args: List[str], timeout: int = 15) -> str:
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
            return r.stdout.strip()
        except Exception: return ""

    @staticmethod
    def _ps(script: str, timeout: int = 20) -> str:
        try:
            r = subprocess.run(
                ["powershell", "-NonInteractive", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=timeout, errors="replace"
            )
            return r.stdout.strip()
        except Exception: return ""

    @staticmethod
    def _reg_read(hive, path: str) -> Optional[winreg.HKEYType]:
        try: return winreg.OpenKey(hive, path)
        except Exception: return None

    @staticmethod
    def _reg_values(key) -> List[Tuple[str, Any]]:
        results = []
        if not key: return results
        i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(key, i)
                results.append((name, data))
                i += 1
            except OSError: break
        return results

    @staticmethod
    def _reg_subkeys(key) -> List[str]:
        keys = []
        if not key: return keys
        i = 0
        while True:
            try:
                keys.append(winreg.EnumKey(key, i))
                i += 1
            except OSError: break
        return keys

    @staticmethod
    def _sha256(path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
            return h.hexdigest()
        except Exception: return ""



class D01_SystemIdentity(BaseDomain):
    domain_id    = "D01_system_identity"
    display_name = "System Identity"

    def _gather(self):
        self._set("hostname",       socket.gethostname())
        self._set("os_version",     platform.version())
        self._set("os_release",     platform.release())
        self._set("architecture",   platform.machine())
        self._set("processor",      platform.processor())
        self._set("python_version", platform.python_version())

        sb = self._ps("Confirm-SecureBootUEFI 2>$null")
        self._set("secure_boot",    sb if sb else "Unknown")

        domain_info = self._ps("(Get-WmiObject Win32_ComputerSystem).PartOfDomain")
        self._set("domain_joined",  domain_info.strip().lower() == "true")
        if domain_info.strip().lower() == "true":
            dn = self._ps("(Get-WmiObject Win32_ComputerSystem).Domain")
            self._set("domain_name", dn)
            self._tag("domain-joined")

        vm_raw = self._ps(
            "(Get-WmiObject Win32_ComputerSystem).Manufacturer + '|' + "
            "(Get-WmiObject Win32_ComputerSystem).Model"
        )
        vm_indicators = ["vmware", "virtualbox", "hyper-v", "kvm", "xen", "qemu", "microsoft corporation"]
        vm_str = vm_raw.lower()
        is_vm  = any(i in vm_str for i in vm_indicators)
        self._set("virtualization_detected", is_vm)
        self._set("hardware_vendor",         vm_raw.split("|")[0] if "|" in vm_raw else vm_raw)
        if is_vm:
            self._tag("virtual-machine")
            self._finding("Virtualization Detected", f"Hardware profile: {vm_raw}", "info", ["vm"])

        boot = self._ps(
            "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime | "
            "Select-Object -ExpandProperty TotalHours"
        )
        self._set("uptime_hours", round(float(boot), 1) if boot.replace(".", "").isdigit() else None)

        tz = self._ps("(Get-TimeZone).Id")
        self._set("timezone", tz)

        inst = self._ps("(gcim Win32_OperatingSystem).InstallDate.ToString('yyyy-MM-dd')")
        self._set("install_date", inst)


class D02_UserSession(BaseDomain):
    domain_id    = "D02_user_session"
    display_name = "User & Session Intelligence"

    def _gather(self):
        self._set("current_user",  os.environ.get("USERNAME", ""))
        self._set("user_domain",   os.environ.get("USERDOMAIN", ""))
        self._set("user_profile",  os.environ.get("USERPROFILE", ""))

        quser = self._cmd(["quser"], timeout=10)
        sessions = []
        for line in quser.splitlines()[1:]:
            parts = line.split()
            if parts: sessions.append({"raw": line.strip()})
        self._set("active_sessions", sessions)

        admins_raw = self._ps(
            "Get-LocalGroupMember -Group Administrators | "
            "Select-Object -ExpandProperty Name"
        )
        admins = [a.strip() for a in admins_raw.splitlines() if a.strip()]
        self._set("local_administrators", admins)
        if len(admins) > 3:
            self._finding(
                "Elevated Admin Density",
                f"{len(admins)} accounts in local Administrators group",
                "medium", ["admin-density"]
            )
            self._tag("high-admin-count")

        cached = self._ps(
            r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').CachedLogonsCount"
        )
        self._set("cached_logon_count", cached)

        rdp_raw = self._ps(
            "Get-Process -Name mstsc -ErrorAction SilentlyContinue | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        self._set("active_rdp_clients", rdp_raw)

        events_raw = self._ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 5 "
            "-ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,Message | ConvertTo-Json -Compress 2>$null"
        )
        self._set("recent_logon_events_raw", events_raw[:500] if events_raw else "")


class D03_ProcessIntel(BaseDomain):
    domain_id    = "D03_process_intel"
    display_name = "Process Intelligence"

    NOISE = {"svchost.exe","lsass.exe","csrss.exe","smss.exe","wininit.exe","winlogon.exe",
              "services.exe","spoolsv.exe","dwm.exe","fontdrvhost.exe","sihost.exe",
              "taskhostw.exe","explorer.exe","conhost.exe","dllhost.exe","ctfmon.exe"}

    INTEREST = {
        "anydesk.exe":   ("Remote Access",    "high"),
        "teamviewer.exe":("Remote Access",    "high"),
        "rustdesk.exe":  ("Remote Access",    "high"),
        "vnc.exe":       ("Remote Access",    "medium"),
        "wireshark.exe": ("Traffic Capture",  "high"),
        "tshark.exe":    ("Traffic Capture",  "high"),
        "burpsuite.jar": ("Proxy/Intercept",  "high"),
        "nmap.exe":      ("Network Scanner",  "high"),
        "x64dbg.exe":    ("Debugger",         "medium"),
        "procmon.exe":   ("Sysinternals",     "low"),
        "mimikatz.exe":  ("Credential Tool",  "critical"),
        "psexec.exe":    ("Lateral Movement", "high"),
        "python.exe":    ("Scripting",        "low"),
        "powershell.exe":("Scripting",        "low"),
        "cmd.exe":       ("Shell",            "low"),
    }

    def _gather(self):
        if not _HAS_PSUTIL:
            self._r.status = "skip"
            self._r.error  = "psutil not installed"
            return

        processes = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "ppid", "status"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                if name in self.NOISE: continue

                exe  = info.get("exe") or ""
                entry = {
                    "pid":      info["pid"],
                    "name":     info.get("name", ""),
                    "exe":      exe,
                    "username": info.get("username", ""),
                    "ppid":     info.get("ppid", 0),
                    "status":   info.get("status", ""),
                }

                try:
                    conns = proc.net_connections()
                    entry["connections"] = len(conns)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    entry["connections"] = -1

                if exe and os.path.isfile(exe):
                    entry["sha256"] = self._sha256(exe)

                base_name = os.path.basename(exe).lower() if exe else name
                if base_name in self.INTEREST:
                    cat, sev = self.INTEREST[base_name]
                    entry["category"] = cat
                    entry["severity"]  = sev
                    self._finding(
                        f"Notable Process: {info.get('name','')}",
                        f"Category: {cat} | PID: {info['pid']} | Path: {exe}",
                        sev, [cat.lower().replace(" ", "-")]
                    )
                    self._tag(cat.lower().replace(" ", "-"))

                processes.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._set("non_system_processes", processes)
        self._set("process_count",        len(processes))


class D04_SoftwareInventory(BaseDomain):
    domain_id    = "D04_software_inventory"
    display_name = "Software Inventory"

    REG_PATHS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    CATEGORIES = {
        "security":    ["crowdstrike","sentinelone","defender","carbon black","sysmon","wireshark","nessus","qualys"],
        "remote":      ["anydesk","teamviewer","rustdesk","vnc","chrome remote","splashtop"],
        "dev_tools":   ["visual studio","vscode","git","docker","python","nodejs","intellij","pycharm"],
        "cloud":       ["aws","azure","google cloud","dropbox","onedrive","s3"],
        "monitoring":  ["grafana","datadog","splunk","zabbix","elastic","kibana"],
        "database":    ["mysql","postgresql","mongodb","redis","mssql","oracle"],
        "vpn":         ["openvpn","wireguard","tailscale","nordvpn","fortivpn","cisco vpn","pulse"],
        "virtualization":["vmware","virtualbox","docker desktop","hyper-v"],
    }

    def _gather(self):
        software: Dict[str, List[dict]] = {cat: [] for cat in self.CATEGORIES}
        software["other"] = []
        all_sw = []

        seen = set()
        for hive, path in self.REG_PATHS:
            key = self._reg_read(hive, path)
            if not key: continue
            for subkey_name in self._reg_subkeys(key):
                try:
                    sk = winreg.OpenKey(key, subkey_name)
                    vals = dict(self._reg_values(sk))
                    name = vals.get("DisplayName", "")
                    if not name or name in seen: continue
                    seen.add(name)
                    entry = {
                        "name":      name,
                        "version":   vals.get("DisplayVersion", ""),
                        "publisher": vals.get("Publisher", ""),
                        "install_date": vals.get("InstallDate", ""),
                    }
                    all_sw.append(entry)
                    name_lower = name.lower()
                    matched = False
                    for cat, keywords in self.CATEGORIES.items():
                        if any(kw in name_lower for kw in keywords):
                            software[cat].append(entry)
                            matched = True
                            break
                    if not matched:
                        software["other"].append(entry)
                except Exception:
                    continue

        for cat in self.CATEGORIES:
            self._set(f"category_{cat}", software[cat])
            if software[cat] and cat in ("remote", "security", "monitoring"):
                for sw in software[cat]:
                    self._finding(
                        f"[{cat.upper()}] {sw['name']}",
                        f"Version: {sw['version']} | Publisher: {sw['publisher']}",
                        "info", [cat]
                    )

        self._set("total_installed", len(all_sw))
        self._set("all_software",    all_sw)

        if software["remote"] and not software["security"]:
            self._finding(
                "Remote Access Without EDR",
                "Remote access tools present but no security software detected",
                "high", ["remote", "security-gap"]
            )
            self._tag("remote-access-exposed")


class D05_FilesystemSurface(BaseDomain):
    domain_id    = "D05_filesystem_surface"
    display_name = "Filesystem Surface"

    def _gather(self):
        profile = Path(os.environ.get("USERPROFILE", Path.home()))
        self._set("profile_root", str(profile))

        for folder_name, rel_path in [("desktop", "Desktop"), ("downloads", "Downloads"), ("documents", "Documents")]:
            folder = profile / rel_path
            if not folder.exists():
                self._set(folder_name, [])
                continue
            entries = []
            for item in sorted(folder.iterdir())[:80]:
                try:
                    stat = item.stat()
                    entry = {
                        "name":     item.name,
                        "type":     "dir" if item.is_dir() else "file",
                        "size_kb":  round(stat.st_size / 1024, 1),
                        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d"),
                    }
                    if item.is_file():
                        suffix = item.suffix.lower()
                        if suffix in (".exe", ".bat", ".ps1", ".vbs", ".hta"):
                            entry["category"] = "executable"
                            self._finding(f"Executable in {rel_path}", str(item), "medium", ["executable"])
                        elif suffix in (".zip", ".rar", ".7z", ".tar", ".gz"):
                            entry["category"] = "archive"
                        elif suffix in (".pdf",):
                            entry["category"] = "pdf"
                        elif suffix in (".docx", ".doc", ".xlsx", ".xls", ".pptx"):
                            entry["category"] = "office"
                        else:
                            entry["category"] = "other"
                    entries.append(entry)
                except Exception:
                    continue
            self._set(folder_name, entries)


class D06_PersistenceMap(BaseDomain):
    domain_id    = "D06_persistence_map"
    display_name = "Persistence Mechanisms"

    RUN_KEYS = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def _gather(self):
        run_entries = []
        for hive, path in self.RUN_KEYS:
            key = self._reg_read(hive, path)
            if not key: continue
            for name, data in self._reg_values(key):
                entry = {"name": name, "command": str(data), "hive": path.split("\\")[0]}
                run_entries.append(entry)
                self._finding("Registry Run Key", f"{name} → {str(data)[:120]}", "info", ["registry-run"])
        self._set("run_keys", run_entries)

        startup_entries = []
        for startup_path in [
            Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
            Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/StartUp",
        ]:
            if startup_path.exists():
                for f in startup_path.iterdir():
                    entry = {"name": f.name, "path": str(f)}
                    startup_entries.append(entry)
                    self._finding("Startup Folder Entry", str(f), "medium", ["startup-folder"])
        self._set("startup_folder_items", startup_entries)

        tasks_raw = self._ps(
            "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft*'} | "
            "Select-Object TaskName,TaskPath,State | ConvertTo-Json -Compress 2>$null"
        )
        try:
            tasks = json.loads(tasks_raw) if tasks_raw else []
            if isinstance(tasks, dict): tasks = [tasks]
        except Exception:
            tasks = []
        self._set("scheduled_tasks", tasks)
        if tasks:
            for t in tasks[:20]:
                self._finding(
                    "Non-Microsoft Scheduled Task",
                    f"{t.get('TaskPath','')}{t.get('TaskName','')} [{t.get('State','')}]",
                    "info", ["scheduled-task"]
                )

        ps_profiles = []
        for profile_path in [
            Path(os.environ.get("USERPROFILE","")) / "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
            Path(os.environ.get("USERPROFILE","")) / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",
        ]:
            if profile_path.exists():
                ps_profiles.append(str(profile_path))
                self._finding("PowerShell Profile Exists", str(profile_path), "medium", ["ps-profile"])
        self._set("powershell_profiles", ps_profiles)

        wmi_raw = self._ps(
            "Get-WMIObject -Namespace root/subscription -Class __EventFilter 2>$null | "
            "Select-Object Name,Query | ConvertTo-Json -Compress 2>$null"
        )
        self._set("wmi_subscriptions_raw", wmi_raw[:300] if wmi_raw else "")
        if wmi_raw and len(wmi_raw) > 10:
            self._finding("WMI Event Subscriptions Detected", "Non-standard WMI persistence may be present", "high", ["wmi"])
            self._tag("wmi-persistence")


class D07_SecurityTelemetry(BaseDomain):
    domain_id    = "D07_security_telemetry"
    display_name = "Security & Telemetry"

    def _gather(self):
        ps_ver = self._ps("$PSVersionTable.PSVersion.ToString()")
        self._set("powershell_version", ps_ver)
        if ps_ver and ps_ver.startswith("2."):
            self._finding("Downgrade Risk: PowerShell v2", "PSv2 is present and lacks logging/AMSI", "high", ["ps-downgrade"])
            self._tag("ps2-risk")

        ep = self._ps("Get-ExecutionPolicy")
        self._set("execution_policy", ep)
        if ep.lower() in ("bypass", "unrestricted"):
            self._finding("Permissive Execution Policy", f"ExecutionPolicy is {ep}", "high", ["exec-policy"])
            self._tag("unrestricted-policy")

        for log_type, reg_path, val_name in [
            ("script_block_logging",
             r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),
            ("module_logging",
             r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging"),
            ("transcription",
             r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting"),
        ]:
            key = self._reg_read(winreg.HKEY_LOCAL_MACHINE, reg_path)
            enabled = False
            if key:
                for name, data in self._reg_values(key):
                    if name == val_name:
                        enabled = bool(data)
            self._set(f"ps_logging_{log_type}", enabled)
            if not enabled:
                self._finding(
                    f"PowerShell Logging Disabled: {log_type.replace('_',' ').title()}",
                    "Reduces detection capability for malicious PowerShell",
                    "medium", ["ps-logging"]
                )

        defender_raw = self._ps(
            "Get-MpComputerStatus 2>$null | Select-Object RealTimeProtectionEnabled,"
            "AntivirusEnabled,BehaviorMonitorEnabled,AMServiceEnabled | ConvertTo-Json -Compress"
        )
        try:
            defender = json.loads(defender_raw) if defender_raw else {}
        except Exception:
            defender = {}
        self._set("defender_status", defender)
        if not defender.get("RealTimeProtectionEnabled"):
            self._finding("Defender Real-Time Protection Disabled", "", "critical", ["defender-off"])
            self._tag("defender-disabled")

        sysmon = self._ps("Get-Service -Name Sysmon* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
        self._set("sysmon_status", sysmon if sysmon else "Not Installed")
        if not sysmon:
            self._finding("Sysmon Not Detected", "No Sysmon service found; event telemetry limited", "medium", ["sysmon"])

        edr_solutions = {
            "CrowdStrike":   ["CSFalconService", "csagent"],
            "SentinelOne":   ["SentinelAgent"],
            "Carbon Black":  ["CbDefense", "CarbonBlack"],
            "Elastic":       ["Elastic Agent"],
            "Sophos":        ["Sophos", "SAVService"],
            "Cylance":       ["CylanceSvc"],
        }
        detected_edrs = []
        for edr_name, svc_names in edr_solutions.items():
            for svc in svc_names:
                raw = self._ps(f"Get-Service -Name '{svc}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
                if raw:
                    detected_edrs.append({"name": edr_name, "service": svc, "status": raw})
                    break
        self._set("detected_edr", detected_edrs)
        if not detected_edrs:
            self._finding("No EDR/XDR Detected", "No known endpoint detection agents found", "high", ["no-edr"])
            self._tag("no-edr")


class D08_ServiceLandscape(BaseDomain):
    domain_id    = "D08_service_landscape"
    display_name = "Service Landscape"

    SYSTEM_NOISE = {"wuauserv","bits","themes","spooler","schedule","eventlog","plugplay",
                    "cryptsvc","winmgmt","lsass","netlogon","rpcss","samss"}

    VENDOR_MAP = {
        "elastic":       "Elastic",
        "crowdstrike":   "CrowdStrike",
        "sentinelone":   "SentinelOne",
        "anydesk":       "AnyDesk",
        "teamviewer":    "TeamViewer",
        "docker":        "Docker",
        "mysql":         "MySQL",
        "postgresql":    "PostgreSQL",
        "mongodb":       "MongoDB",
        "grafana":       "Grafana",
        "datadog":       "Datadog",
        "splunkd":       "Splunk",
        "sysmon":        "Sysmon (Microsoft)",
        "openvpn":       "OpenVPN",
        "wireguard":     "WireGuard",
    }

    def _gather(self):
        ps_script = (
            "$svcMap = @{}; "
            "Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | "
            "ForEach-Object { $svcMap[$_.Name] = $_.PathName }; "
            "Get-Service | Select-Object Name,DisplayName,Status,StartType,"
            "@{N='Path';E={$svcMap[$_.Name]}} | ConvertTo-Json -Compress 2>$null"
        )
        raw = self._ps(ps_script, timeout=30)
        try:
            services = json.loads(raw) if raw else []
            if isinstance(services, dict): services = [services]
        except Exception:
            services = []

        if not services:
            sc_raw = self._cmd(["sc", "query", "type=", "all", "state=", "all"], timeout=15)
            cur = {}
            for line in sc_raw.splitlines():
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    cur = {"Name": line.split(":",1)[1].strip(), "DisplayName": "", "Status": "?", "StartType": "?", "Path": ""}
                elif line.startswith("DISPLAY_NAME:"):
                    cur["DisplayName"] = line.split(":",1)[1].strip()
                elif line.startswith("STATE") and ":" in line:
                    parts = line.split()
                    cur["Status"] = parts[-1] if parts else "?"
                    if cur.get("Name"):
                        services.append(dict(cur))

        filtered = []
        for svc in services:
            name = (svc.get("Name") or "").lower()
            if any(n in name for n in self.SYSTEM_NOISE): continue

            vendor = "Unknown"
            for kw, label in self.VENDOR_MAP.items():
                if kw in name:
                    vendor = label
                    break

            status_raw = svc.get("Status", "")
            if isinstance(status_raw, int):
                status_str = {1:"Stopped",2:"StartPending",3:"StopPending",4:"Running"}.get(status_raw, str(status_raw))
            else:
                status_str = str(status_raw)

            start_raw = svc.get("StartType", "")
            if isinstance(start_raw, int):
                start_str = {0:"Boot",1:"System",2:"Automatic",3:"Manual",4:"Disabled"}.get(start_raw, str(start_raw))
            else:
                start_str = str(start_raw)

            entry = {
                "name":       svc.get("Name", ""),
                "display":    svc.get("DisplayName", ""),
                "status":     status_str,
                "start_type": start_str,
                "path":       svc.get("Path") or "",
                "vendor":     vendor,
            }
            filtered.append(entry)

            if vendor != "Unknown" and status_str == "Running":
                self._finding(f"Known Service Running: {vendor}", entry["display"], "info", ["service"])

        self._set("non_system_services", filtered)
        self._set("service_count",       len(filtered))


class D09_NetworkContext(BaseDomain):
    domain_id    = "D09_network_context"
    display_name = "Network Context"

    def _gather(self):
        interfaces = []
        for iface, addrs in (psutil.net_if_addrs().items() if _HAS_PSUTIL else {}.items()):
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    interfaces.append({"name": iface, "ip": addr.address, "netmask": addr.netmask})
        if not interfaces:
            raw = self._ps("Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress | ConvertTo-Json -Compress 2>$null")
            try:
                interfaces = json.loads(raw) if raw else []
            except Exception: interfaces = []
        self._set("network_interfaces", interfaces)

        dns_raw = self._ps("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json -Compress 2>$null")
        try: self._set("dns_servers", json.loads(dns_raw) if dns_raw else [])
        except Exception: self._set("dns_servers", [])

        proxy_key = self._reg_read(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        proxy_enabled = False
        proxy_server  = ""
        if proxy_key:
            for name, data in self._reg_values(proxy_key):
                if name == "ProxyEnable": proxy_enabled = bool(data)
                if name == "ProxyServer": proxy_server  = str(data)
        self._set("proxy_enabled", proxy_enabled)
        self._set("proxy_server",  proxy_server)
        if proxy_enabled:
            self._finding("Proxy Configured", f"Server: {proxy_server}", "info", ["proxy"])
            self._tag("proxy-active")

        arp_raw = self._cmd(["arp", "-a"])
        arp_entries = []
        for line in arp_raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                arp_entries.append({"ip": parts[0], "mac": parts[1] if len(parts) > 1 else ""})
        self._set("arp_cache", arp_entries[:50])
        self._set("arp_neighbor_count", len(arp_entries))

        wifi_raw = self._cmd(["netsh", "wlan", "show", "profiles"])
        wifi_profiles = re.findall(r"All User Profile\s*:\s*(.+)", wifi_raw)
        self._set("wifi_profiles", [w.strip() for w in wifi_profiles])

        drives_raw = self._ps(
            "Get-PSDrive -PSProvider FileSystem | Where-Object {$_.DisplayRoot} | "
            "Select-Object Name,DisplayRoot | ConvertTo-Json -Compress 2>$null"
        )
        try: self._set("mapped_drives", json.loads(drives_raw) if drives_raw else [])
        except Exception: self._set("mapped_drives", [])

        rdp_key = self._reg_read(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Terminal Server Client\Servers")
        rdp_history = []
        if rdp_key:
            for server in self._reg_subkeys(rdp_key):
                rdp_history.append(server)
        self._set("rdp_history", rdp_history)
        if rdp_history:
            self._finding("RDP Connection History", f"{len(rdp_history)} server(s): {', '.join(rdp_history[:5])}", "info", ["rdp"])
            self._tag("rdp-history")


class D10_CredentialSurface(BaseDomain):
    domain_id    = "D10_credential_surface"
    display_name = "Credential Surface"

    def _gather(self):
        profile = Path(os.environ.get("USERPROFILE", Path.home()))
        exposed_count = 0

        ssh_dir = profile / ".ssh"
        ssh_keys = []
        if ssh_dir.exists():
            for f in ssh_dir.iterdir():
                if f.is_file() and f.suffix not in (".pub",):
                    ssh_keys.append({"file": f.name, "size_bytes": f.stat().st_size})
                    self._finding("SSH Private Key Found", str(f), "high", ["ssh-key"])
                    exposed_count += 1
        self._set("ssh_keys", ssh_keys)

        aws_cred = profile / ".aws" / "credentials"
        aws_conf = profile / ".aws" / "config"
        aws_data = {"credentials_exist": aws_cred.exists(), "config_exists": aws_conf.exists()}
        if aws_cred.exists():
            self._finding("AWS Credentials File Found", str(aws_cred), "critical", ["aws-creds"])
            exposed_count += 2
        self._set("aws_profile", aws_data)

        azure_dir = profile / ".azure"
        azure_profiles = []
        if azure_dir.exists():
            for f in azure_dir.glob("*.json"):
                azure_profiles.append(f.name)
                self._finding("Azure Profile JSON Found", str(f), "high", ["azure-creds"])
                exposed_count += 1
        self._set("azure_profiles", azure_profiles)

        git_config = profile / ".gitconfig"
        git_creds  = profile / ".git-credentials"
        self._set("git_config_exists",      git_config.exists())
        self._set("git_credentials_exists", git_creds.exists())
        if git_creds.exists():
            self._finding("Git Credentials File Found", str(git_creds), "critical", ["git-creds"])
            exposed_count += 2

        vpn_search_dirs = [
            profile / "AppData" / "Roaming" / "OpenVPN",
            profile / "AppData" / "Local" / "OpenVPN",
            profile / "AppData" / "Roaming" / "WireGuard",
            profile / "Documents",
            profile / "Desktop",
            profile / "Downloads",
        ]
        vpn_extensions = (".ovpn", ".conf", ".vpn")
        vpn_files = []
        for search_dir in vpn_search_dirs:
            if not search_dir.exists(): continue
            for ext in vpn_extensions:
                for f in search_dir.glob(f"**/*{ext}"):
                    if len(vpn_files) >= 20: break
                    vpn_files.append(str(f))
                    self._finding("VPN Configuration File", str(f), "medium", ["vpn-config"])
                    exposed_count += 1
        self._set("vpn_config_files", vpn_files)

        kdbx_search_dirs = [profile / "Documents", profile / "Desktop", profile / "Downloads", profile]
        kdbx_files = []
        for search_dir in kdbx_search_dirs:
            if not search_dir.exists(): continue
            for f in search_dir.glob("*.kdbx"):
                kdbx_files.append(f)
                if len(kdbx_files) >= 10: break
        kdbx_files = kdbx_files[:10]
        self._set("keepass_databases", [str(f) for f in kdbx_files])
        if kdbx_files:
            self._finding("KeePass Database Found", f"{len(kdbx_files)} .kdbx file(s)", "info", ["keepass"])

        browsers = {
            "Chrome": profile / "AppData/Local/Google/Chrome/User Data/Default",
            "Edge":   profile / "AppData/Local/Microsoft/Edge/User Data/Default",
            "Firefox":profile / "AppData/Roaming/Mozilla/Firefox/Profiles",
            "Brave":  profile / "AppData/Local/BraveSoftware/Brave-Browser/User Data/Default",
        }
        browser_data = {}
        for browser, path in browsers.items():
            browser_data[browser] = path.exists()
            if path.exists():
                self._finding(f"Browser Profile: {browser}", f"Profile path: {path}", "info", ["browser"])
        self._set("browser_profiles", browser_data)

        self._set("total_exposure_score", exposed_count)
        if exposed_count >= 5:
            self._tag("high-credential-exposure")


class D11_DevAdminEnvironment(BaseDomain):
    domain_id    = "D11_dev_admin_env"
    display_name = "Dev & Admin Environment"

    def _gather(self):
        tools_found = {}

        py = self._cmd(["python", "--version"])
        tools_found["python"] = py.replace("Python ", "").strip() if py else None

        node = self._cmd(["node", "--version"])
        tools_found["nodejs"] = node.strip() if node else None

        git  = self._cmd(["git", "--version"])
        tools_found["git"] = git.strip() if git else None

        docker = self._cmd(["docker", "--version"])
        tools_found["docker"] = docker.strip() if docker else None

        kube = self._cmd(["kubectl", "version", "--client", "--short"])
        tools_found["kubectl"] = kube.strip() if kube else None

        tf = self._cmd(["terraform", "--version"])
        tools_found["terraform"] = tf.splitlines()[0].strip() if tf else None

        self._set("installed_dev_tools", tools_found)

        wsl_raw = self._cmd(["wsl", "--list", "--quiet"])
        wsl_distros = [d.strip() for d in wsl_raw.splitlines() if d.strip()] if wsl_raw else []
        self._set("wsl_distributions", wsl_distros)
        if wsl_distros:
            self._finding("WSL Distributions Active", ", ".join(wsl_distros), "info", ["wsl"])
            self._tag("wsl-active")

        ide_names = {
            "code.exe":      "VS Code",
            "pycharm64.exe": "PyCharm",
            "idea64.exe":    "IntelliJ IDEA",
            "webstorm64.exe":"WebStorm",
            "rider64.exe":   "Rider",
        }
        detected_ides = []
        for exe, name in ide_names.items():
            raw = self._ps(f"Get-Command {exe} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source")
            if raw:
                detected_ides.append({"ide": name, "path": raw})
        self._set("detected_ides", detected_ides)

        hypervisors = {}
        for svc, label in [("vmms", "Hyper-V"), ("VMwareAuthd", "VMware"), ("VBoxSVC", "VirtualBox")]:
            raw = self._ps(f"Get-Service -Name {svc} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status")
            hypervisors[label] = raw if raw else None
        self._set("hypervisor_services", {k: v for k, v in hypervisors.items() if v})


TRACKED_TOOLS = [
    "AnyDesk","TeamViewer","RustDesk","Docker","OpenVPN","WireGuard",
    "Tailscale","Elastic","CrowdStrike","SentinelOne","Python","Node.js",
    "Git","Grafana","MySQL","PostgreSQL","MongoDB","VMware","VirtualBox",
]

def run_correlation(domains: Dict[str, DomainResult]) -> dict:
    chains     = []
    high_conf  = []
    medium_conf= []

    d10 = domains.get("D10_credential_surface")
    if d10:
        exp = d10.data.get("total_exposure_score", 0)
        has_aws   = d10.data.get("aws_profile", {}).get("credentials_exist", False)
        has_ssh   = bool(d10.data.get("ssh_keys", []))
        has_git   = d10.data.get("git_credentials_exists", False)
        has_keepass = bool(d10.data.get("keepass_databases", []))
        if sum([has_aws, has_ssh, has_git, has_keepass]) >= 2:
            chains.append({
                "id":         "CHAIN-CRED-01",
                "title":      "Multi-Vector Credential Exposure",
                "confidence": "high",
                "artifacts":  ["SSH Keys", "AWS Credentials", "Git Credentials", "KeePass"],
                "detail":     f"Exposure score: {exp}",
            })
            high_conf.append("Multi-vector credential exposure")

    d07 = domains.get("D07_security_telemetry")
    d04 = domains.get("D04_software_inventory")
    if d07 and d04:
        no_edr    = not d07.data.get("detected_edr", [])
        has_remote = bool(d04.data.get("category_remote", []))
        if no_edr and has_remote:
            chains.append({
                "id":         "CHAIN-ACCESS-01",
                "title":      "Unmonitored Remote Access Vector",
                "confidence": "high",
                "artifacts":  ["Remote Tools", "No EDR"],
                "detail":     "Remote access software operating without endpoint detection",
            })
            high_conf.append("Unmonitored remote access vector")

    if d07:
        ps2   = "ps2-risk" in (d07.tags or [])
        no_sb = not d07.data.get("ps_logging_script_block_logging", True)
        unres = "unrestricted-policy" in (d07.tags or [])
        if sum([ps2, no_sb, unres]) >= 2:
            chains.append({
                "id":         "CHAIN-PS-01",
                "title":      "PowerShell Attack Surface Elevated",
                "confidence": "high",
                "artifacts":  ["PS v2 present", "No Script Block Logging", "Permissive Policy"],
                "detail":     "Combination of factors enables evasive PowerShell execution",
            })
            high_conf.append("PowerShell attack surface elevated")

    d09 = domains.get("D09_network_context")
    d01 = domains.get("D01_system_identity")
    if d09 and d01:
        domain_joined = d01.data.get("domain_joined", False)
        mapped_drives = bool(d09.data.get("mapped_drives", []))
        rdp_history   = bool(d09.data.get("rdp_history", []))
        d06 = domains.get("D06_persistence_map")
        wmi_present   = bool(d06 and d06.data.get("wmi_subscriptions_raw", ""))
        if domain_joined and (mapped_drives or rdp_history):
            chains.append({
                "id":         "CHAIN-LAT-01",
                "title":      "Lateral Movement Indicators",
                "confidence": "medium",
                "artifacts":  ["Domain Join", "Mapped Drives", "RDP History"],
                "detail":     "Domain-joined host with network pivot points",
            })
            medium_conf.append("Lateral movement indicators present")

    confirmed_tools = []
    for tool in TRACKED_TOOLS:
        tool_lower = tool.lower().replace(".", "")
        confirmed_by = []
        d03 = domains.get("D03_process_intel")
        d08 = domains.get("D08_service_landscape")
        if d03:
            procs = d03.data.get("non_system_processes", [])
            if any(tool_lower in (p.get("name","") or "").lower() for p in procs):
                confirmed_by.append("process")
        if d08:
            svcs = d08.data.get("non_system_services", [])
            if any(tool_lower in (s.get("vendor","") or "").lower() for s in svcs):
                confirmed_by.append("service")
        if d04:
            sw_all = d04.data.get("all_software", [])
            if any(tool_lower in (s.get("name","") or "").lower() for s in sw_all):
                confirmed_by.append("installed")
        if len(confirmed_by) >= 2:
            confirmed_tools.append({"tool": tool, "confirmed_by": confirmed_by})

    return {
        "correlation_chains":      chains,
        "high_confidence_findings": high_conf,
        "medium_confidence_findings": medium_conf,
        "multi_confirmed_tools":   confirmed_tools,
    }

def compute_risk(domains: Dict[str, DomainResult], correlation: dict) -> RiskProfile:
    axes = {
        "Detection Risk":         0,
        "Security Maturity":      0,
        "Admin Density":          0,
        "Credential Exposure":    0,
        "Lateral Movement Ready": 0,
        "Monitoring Visibility":  0,
    }
    factors = []

    d07 = domains.get("D07_security_telemetry")
    if d07:
        if not d07.data.get("ps_logging_script_block_logging"):
            axes["Detection Risk"] += 7; factors.append("No PS Script Block Logging")
        if not d07.data.get("ps_logging_module_logging"):
            axes["Detection Risk"] += 4
        if not d07.data.get("ps_logging_transcription"):
            axes["Detection Risk"] += 4
        if not d07.data.get("sysmon_status","").lower().startswith("running"):
            axes["Detection Risk"] += 5; factors.append("Sysmon not running")

    if d07:
        defender = d07.data.get("defender_status", {})
        if not defender.get("RealTimeProtectionEnabled"):
            axes["Security Maturity"] += 12; factors.append("Defender RTP disabled")
        if not defender.get("BehaviorMonitorEnabled"):
            axes["Security Maturity"] += 5
        if "unrestricted-policy" in (d07.tags or []):
            axes["Security Maturity"] += 8; factors.append("Unrestricted PS policy")

    d02 = domains.get("D02_user_session")
    if d02:
        admins = d02.data.get("local_administrators", [])
        count  = len(admins)
        if count > 5:
            axes["Admin Density"] += 15; factors.append(f"{count} local admins")
        elif count > 3:
            axes["Admin Density"] += 8

    d10 = domains.get("D10_credential_surface")
    if d10:
        score = d10.data.get("total_exposure_score", 0)
        axes["Credential Exposure"] = min(20, score * 3)
        if score >= 3: factors.append("Multiple credential artifacts exposed")

    d09 = domains.get("D09_network_context")
    d01 = domains.get("D01_system_identity")
    if d01 and d01.data.get("domain_joined"):
        axes["Lateral Movement Ready"] += 5; factors.append("Domain-joined host")
    if d09:
        if d09.data.get("mapped_drives"):
            axes["Lateral Movement Ready"] += 5
        if d09.data.get("rdp_history"):
            axes["Lateral Movement Ready"] += 4

    if d07:
        if d07.data.get("detected_edr"):
            axes["Monitoring Visibility"] = 2
        else:
            axes["Monitoring Visibility"] = 10; factors.append("No EDR detected")

    for k in axes:
        axes[k] = min(axes[k], 20)

    overall = sum(axes.values())

    if overall < 30:   rating = "LOW"
    elif overall < 50: rating = "MEDIUM"
    elif overall < 70: rating = "HIGH"
    else:              rating = "CRITICAL"

    chain_count = len(correlation.get("correlation_chains", []))
    if chain_count >= 2:
        overall = min(100, overall + chain_count * 3)
        factors.append(f"{chain_count} multi-artifact correlation chains")

    return RiskProfile(overall=overall, rating=rating, axes=axes, factors=factors)

def write_json(report: VortexReport, output_dir: str) -> str:
    fname = f"VORTEX_{report.session_id}.json"
    path  = os.path.join(output_dir, fname)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)
    return path

def _html_severity_badge(sev: str) -> str:
    colors = {"critical": "#ff2d55", "high": "#ff6b35", "medium": "#ffd60a", "info": "#00d4ff", "low": "#39d353"}
    color = colors.get(sev.lower(), "#aaa")
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}44">{sev.upper()}</span>'

def _render_findings(findings: list) -> str:
    if not findings: return '<div class="empty">No notable findings in this domain.</div>'
    html = ""
    for f in findings:
        sev   = f.get("severity", "info")
        badge = _html_severity_badge(sev)
        tags  = "".join(f'<span class="tag">#{t}</span>' for t in f.get("tags", []))
        html += f"""
        <div class="finding finding-{sev}">
          <div class="finding-header">{badge} <strong>{f.get('title','')}</strong> {tags}</div>
          <div class="finding-detail">{f.get('detail','')}</div>
        </div>"""
    return html

def write_html(report: VortexReport, output_dir: str) -> str:
    fname = f"VORTEX_{report.session_id}.html"
    path  = os.path.join(output_dir, fname)
    meta  = report.to_dict()["meta"]
    risk  = report.risk

    gauge_color = "#39d353" if risk.overall < 30 else ("#ffd60a" if risk.overall < 50 else "#ff6b35" if risk.overall < 70 else "#ff2d55")
    gauge_pct   = min(100, risk.overall)

    all_findings = [f for d in report.domains for f in d.findings]
    sev_counts   = {}
    for f in all_findings:
        sev_counts[f.get("severity","info")] = sev_counts.get(f.get("severity","info"), 0) + 1

    domain_sections = ""
    for d in report.domains:
        status_icon = "✓" if d.status == "pass" else ("⚠" if d.status == "skip" else "✗")
        status_cls  = "pass" if d.status == "pass" else ("skip" if d.status == "skip" else "fail")
        findings_html = _render_findings(d.findings)
        data_json = json.dumps(d.data, indent=2, default=str)[:4000]
        domain_sections += f"""
        <div class="domain-card">
          <div class="domain-header" onclick="toggle(this)">
            <div class="domain-title">
              <span class="status-icon {status_cls}">{status_icon}</span>
              <span>{d.display_name}</span>
            </div>
            <div class="domain-meta">
              <span class="dim">{d.item_count} items · {d.elapsed:.1f}s</span>
              <span class="chevron">›</span>
            </div>
          </div>
          <div class="domain-body">
            <div class="findings-section">
              <div class="sub-title">Findings</div>
              {findings_html}
            </div>
            <div class="data-section">
              <div class="sub-title">Raw Data <span class="dim">(truncated)</span></div>
              <pre class="data-pre">{data_json}</pre>
            </div>
          </div>
        </div>"""

    chains_html = ""
    for ch in report.correlation.get("correlation_chains", []):
        arts = ", ".join(ch.get("artifacts", []))
        conf = ch.get("confidence","")
        conf_color = "#ff2d55" if conf == "high" else "#ffd60a"
        chains_html += f"""
        <div class="chain-card">
          <div class="chain-id">{ch.get('id','')}</div>
          <div class="chain-title">{ch.get('title','')}</div>
          <div class="chain-meta">
            <span style="color:{conf_color}">● {conf.upper()} CONFIDENCE</span>
            <span class="dim">Artifacts: {arts}</span>
          </div>
          <div class="chain-detail">{ch.get('detail','')}</div>
        </div>"""

    axes_html = ""
    for axis, score in risk.axes.items():
        pct   = int((score / 20) * 100)
        acolor= "#39d353" if score < 7 else ("#ffd60a" if score < 13 else "#ff6b35")
        axes_html += f"""
        <div class="axis-row">
          <div class="axis-label">{axis}</div>
          <div class="axis-bar-bg"><div class="axis-bar" style="width:{pct}%;background:{acolor}"></div></div>
          <div class="axis-score" style="color:{acolor}">{score}/20</div>
        </div>"""

    factors_html = "".join(f'<li>{f}</li>' for f in risk.factors)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VORTEX Report — {meta['hostname']}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root {{
  --bg:       #050810;
  --bg2:      #080d18;
  --bg3:      #0d1526;
  --border:   #1a2540;
  --blue:     #0094ff;
  --blue-dim: #0094ff22;
  --cyan:     #00d4ff;
  --text:     #c8d8f0;
  --dim:      #4a5f80;
  --white:    #eaf2ff;
  --mono:     'JetBrains Mono', monospace;
  --sans:     'Syne', sans-serif;
}}

*,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0; }}

body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.6;
  min-height: 100vh;
}}

/* ── Grid background ── */
body::before {{
  content:'';
  position:fixed;
  inset:0;
  background:
    linear-gradient(var(--border) 1px,transparent 1px),
    linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size: 40px 40px;
  opacity:.25;
  pointer-events:none;
  z-index:0;
}}

.wrap {{ position:relative; z-index:1; max-width:1200px; margin:0 auto; padding:40px 24px; }}

/* ── Header ── */
.header {{
  border-bottom: 1px solid var(--border);
  padding-bottom: 32px;
  margin-bottom: 40px;
}}

.logo {{
  font-family: var(--sans);
  font-weight: 800;
  font-size: 42px;
  letter-spacing: 8px;
  background: linear-gradient(135deg, var(--cyan) 0%, var(--blue) 60%, #5b6fff 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: 4px;
}}

.logo-sub {{
  font-size: 11px;
  letter-spacing: 3px;
  color: var(--dim);
  text-transform: uppercase;
  margin-bottom: 24px;
}}

.meta-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 12px;
}}

.meta-item {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
}}

.meta-label {{ font-size: 10px; letter-spacing: 2px; color: var(--dim); text-transform: uppercase; }}
.meta-value {{ color: var(--white); font-weight: 600; margin-top: 2px; }}

/* ── Search ── */
.search-bar {{
  width: 100%;
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 16px;
  color: var(--white);
  font-family: var(--mono);
  font-size: 13px;
  margin-bottom: 32px;
  outline: none;
  transition: border-color .2s;
}}
.search-bar:focus {{ border-color: var(--blue); }}
.search-bar::placeholder {{ color: var(--dim); }}

/* ── Risk overview ── */
.risk-overview {{
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 24px;
  margin-bottom: 40px;
  align-items: start;
}}

.risk-gauge-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 28px;
  text-align: center;
}}

.gauge-ring {{
  width: 140px;
  height: 140px;
  margin: 0 auto 16px;
  position: relative;
}}

.gauge-svg {{ transform: rotate(-90deg); }}

.gauge-bg {{ fill: none; stroke: var(--border); stroke-width: 12; }}
.gauge-fill {{
  fill: none;
  stroke: {gauge_color};
  stroke-width: 12;
  stroke-linecap: round;
  stroke-dasharray: {int(gauge_pct * 3.39)} 339;
  filter: drop-shadow(0 0 8px {gauge_color});
  transition: stroke-dasharray 1s ease;
}}

.gauge-label {{
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}}

.gauge-score {{
  font-family: var(--sans);
  font-size: 36px;
  font-weight: 800;
  color: {gauge_color};
  line-height: 1;
}}

.gauge-rating {{
  font-size: 10px;
  letter-spacing: 2px;
  color: {gauge_color};
  margin-top: 4px;
}}

.sev-summary {{
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  margin-top: 16px;
}}

.sev-chip {{
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
}}

.risk-detail-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 28px;
}}

.section-title {{
  font-family: var(--sans);
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 3px;
  text-transform: uppercase;
  color: var(--cyan);
  margin-bottom: 20px;
}}

.axis-row {{ display:flex; align-items:center; gap:12px; margin-bottom:10px; }}
.axis-label {{ width:200px; font-size:11px; color:var(--text); flex-shrink:0; }}
.axis-bar-bg {{ flex:1; background:var(--bg3); border-radius:3px; height:6px; overflow:hidden; }}
.axis-bar {{ height:100%; border-radius:3px; transition:width .8s ease; }}
.axis-score {{ width:40px; text-align:right; font-size:11px; font-weight:600; }}

.factors-list {{ list-style:none; }}
.factors-list li {{
  padding: 6px 0;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  font-size:12px;
}}
.factors-list li::before {{ content:'→ '; color:var(--blue); }}

/* ── Section headings ── */
.page-section {{ margin-bottom: 40px; }}
.page-section-title {{
  font-family: var(--sans);
  font-weight: 800;
  font-size: 18px;
  color: var(--white);
  border-left: 3px solid var(--blue);
  padding-left: 14px;
  margin-bottom: 20px;
  letter-spacing: 1px;
}}

/* ── Domain cards ── */
.domain-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
  overflow: hidden;
  transition: border-color .2s;
}}

.domain-card:hover {{ border-color: #2a3a5e; }}

.domain-header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 20px;
  cursor: pointer;
  user-select: none;
}}

.domain-title {{
  display: flex;
  align-items: center;
  gap: 12px;
  font-weight: 600;
  color: var(--white);
}}

.status-icon {{
  width: 22px; height: 22px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700;
  flex-shrink: 0;
}}
.status-icon.pass {{ background: #39d35322; color: #39d353; border: 1px solid #39d35344; }}
.status-icon.skip {{ background: #ffd60a22; color: #ffd60a; border: 1px solid #ffd60a44; }}
.status-icon.fail {{ background: #ff2d5522; color: #ff2d55; border: 1px solid #ff2d5544; }}

.domain-meta {{ display:flex; align-items:center; gap:16px; }}
.chevron {{ color:var(--dim); font-size:18px; transition:transform .2s; }}
.domain-header.open .chevron {{ transform:rotate(90deg); }}

.domain-body {{ display:none; border-top:1px solid var(--border); }}
.domain-header.open + .domain-body {{ display:block; }}

.findings-section, .data-section {{ padding: 20px; }}
.data-section {{ border-top: 1px solid var(--border); }}
.sub-title {{ font-size:10px; letter-spacing:2px; color:var(--dim); text-transform:uppercase; margin-bottom:12px; }}

.finding {{
  padding: 10px 14px;
  border-radius: 6px;
  border: 1px solid var(--border);
  margin-bottom: 8px;
  background: var(--bg3);
}}
.finding-critical {{ border-left: 3px solid #ff2d55; }}
.finding-high     {{ border-left: 3px solid #ff6b35; }}
.finding-medium   {{ border-left: 3px solid #ffd60a; }}
.finding-info     {{ border-left: 3px solid #00d4ff; }}
.finding-low      {{ border-left: 3px solid #39d353; }}

.finding-header {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:4px; }}
.finding-detail {{ font-size:11px; color:var(--dim); word-break:break-all; }}

.badge {{
  padding: 2px 7px;
  border-radius: 3px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 1px;
  text-transform: uppercase;
}}

.tag {{
  font-size: 10px;
  color: var(--blue);
  background: var(--blue-dim);
  padding: 1px 6px;
  border-radius: 3px;
}}

.data-pre {{
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  overflow-x: auto;
  font-size: 11px;
  color: var(--text);
  white-space: pre;
  max-height: 300px;
  overflow-y: auto;
}}

.empty {{ color:var(--dim); font-size:12px; padding:8px 0; }}

/* ── Correlation chains ── */
.chain-card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--cyan);
  border-radius: 8px;
  padding: 18px 20px;
  margin-bottom: 12px;
}}
.chain-id {{ font-size:10px; letter-spacing:2px; color:var(--dim); margin-bottom:4px; }}
.chain-title {{ font-weight:700; color:var(--white); font-size:14px; margin-bottom:8px; }}
.chain-meta {{ display:flex; gap:20px; font-size:11px; margin-bottom:6px; }}
.chain-detail {{ font-size:12px; color:var(--dim); }}

/* ── Stat chips ── */
.stats-row {{ display:flex; flex-wrap:wrap; gap:12px; margin-bottom:40px; }}
.stat-chip {{
  background:var(--bg2);
  border:1px solid var(--border);
  border-radius:8px;
  padding:16px 20px;
  min-width:120px;
  text-align:center;
}}
.stat-chip .num {{ font-family:var(--sans); font-size:28px; font-weight:800; color:var(--white); }}
.stat-chip .lbl {{ font-size:10px; letter-spacing:2px; color:var(--dim); text-transform:uppercase; margin-top:4px; }}

.dim {{ color:var(--dim); }}

/* ── Footer ── */
.footer {{
  margin-top: 60px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
  text-align: center;
  color: var(--dim);
  font-size: 11px;
  letter-spacing: 1px;
}}
.footer strong {{ color:var(--blue); }}

/* ── Responsive ── */
@media(max-width:700px){{
  .risk-overview {{ grid-template-columns:1fr; }}
  .logo {{ font-size:28px; }}
}}
</style>
</head>
<body>
<div class="wrap">

  <!-- HEADER -->
  <header class="header">
    <div class="logo">VORTEX</div>
    <div class="logo-sub">Vulnerability &amp; Operational Risk Telemetry EXtraction &nbsp;·&nbsp; v2.0.0</div>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Session ID</div><div class="meta-value">{meta['session_id']}</div></div>
      <div class="meta-item"><div class="meta-label">Hostname</div><div class="meta-value">{meta['hostname']}</div></div>
      <div class="meta-item"><div class="meta-label">Platform</div><div class="meta-value">{meta['platform']}</div></div>
      <div class="meta-item"><div class="meta-label">Mode</div><div class="meta-value">{meta['mode'].upper()}</div></div>
      <div class="meta-item"><div class="meta-label">Privilege</div><div class="meta-value">{meta['privilege']}</div></div>
      <div class="meta-item"><div class="meta-label">Start Time</div><div class="meta-value">{meta['start_time']}</div></div>
      <div class="meta-item"><div class="meta-label">End Time</div><div class="meta-value">{meta['end_time']}</div></div>
      <div class="meta-item"><div class="meta-label">Author</div><div class="meta-value">{meta['author']}</div></div>
    </div>
  </header>

  <!-- SEARCH -->
  <input class="search-bar" type="text" placeholder="Search findings, domains, tags..." oninput="search(this.value)">

  <!-- STATS ROW -->
  <div class="stats-row">
    <div class="stat-chip"><div class="num">{len(all_findings)}</div><div class="lbl">Total Findings</div></div>
    <div class="stat-chip"><div class="num" style="color:#ff2d55">{sev_counts.get('critical',0)}</div><div class="lbl">Critical</div></div>
    <div class="stat-chip"><div class="num" style="color:#ff6b35">{sev_counts.get('high',0)}</div><div class="lbl">High</div></div>
    <div class="stat-chip"><div class="num" style="color:#ffd60a">{sev_counts.get('medium',0)}</div><div class="lbl">Medium</div></div>
    <div class="stat-chip"><div class="num">{len(report.domains)}</div><div class="lbl">Domains</div></div>
    <div class="stat-chip"><div class="num">{len(report.correlation.get('correlation_chains',[]))}</div><div class="lbl">Chains</div></div>
  </div>

  <!-- RISK OVERVIEW -->
  <div class="risk-overview">
    <div class="risk-gauge-card">
      <div class="gauge-ring">
        <svg class="gauge-svg" viewBox="0 0 120 120" width="140" height="140">
          <circle class="gauge-bg"   cx="60" cy="60" r="54"/>
          <circle class="gauge-fill" cx="60" cy="60" r="54"/>
        </svg>
        <div class="gauge-label">
          <div class="gauge-score">{risk.overall}</div>
          <div class="gauge-rating">{risk.rating}</div>
        </div>
      </div>
      <div style="color:var(--dim);font-size:11px;letter-spacing:1px">OVERALL RISK SCORE</div>
    </div>

    <div class="risk-detail-card">
      <div class="section-title">Risk Axes</div>
      {axes_html}
      <div class="section-title" style="margin-top:24px">Contributing Factors</div>
      <ul class="factors-list">{factors_html if factors_html else '<li>No critical factors identified</li>'}</ul>
    </div>
  </div>

  <!-- CORRELATION CHAINS -->
  <div class="page-section" id="chains-section">
    <div class="page-section-title">Artifact Correlation Chains</div>
    {chains_html if chains_html else '<div class="empty" style="padding:16px">No multi-artifact chains detected.</div>'}
  </div>

  <!-- DOMAIN RESULTS -->
  <div class="page-section" id="domains-section">
    <div class="page-section-title">Domain Intelligence</div>
    {domain_sections}
  </div>

  <!-- FOOTER -->
  <div class="footer">
    VORTEX &nbsp;·&nbsp; Purple Team Exposure Analysis Platform &nbsp;·&nbsp; v2.0.0<br>
    Engineered by <strong>Anas Labrini</strong>
  </div>

</div>

<script>
function toggle(el) {{
  el.classList.toggle('open');
}}

function search(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('.domain-card').forEach(card => {{
    const text = card.innerText.toLowerCase();
    card.style.display = text.includes(q) ? '' : 'none';
  }});
  document.querySelectorAll('.chain-card').forEach(card => {{
    card.style.display = card.innerText.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path

class RunLogger:
    def __init__(self, ctx: Context):
        self.path = os.path.join(ctx.output_dir, f"VORTEX_{ctx.session_id}.log")
        logging.basicConfig(
            filename=self.path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        self._log = logging.getLogger("vortex")

    def info(self, msg: str):  self._log.info(msg)
    def warn(self, msg: str):  self._log.warning(msg)
    def error(self, msg: str): self._log.error(msg)

    def domain(self, r: DomainResult):
        self._log.info(
            f"DOMAIN {r.domain_id} | status={r.status} | items={r.item_count} | "
            f"elapsed={r.elapsed:.2f}s | findings={len(r.findings)}"
        )
        if r.error:
            self._log.warning(f"  ERROR: {r.error}")

    def finalize(self) -> str:
        self._log.info("Assessment complete.")
        return self.path

ENDPOINT_DOMAINS = [
    D01_SystemIdentity, D02_UserSession, D03_ProcessIntel, D04_SoftwareInventory,
    D05_FilesystemSurface, D06_PersistenceMap, D07_SecurityTelemetry,
    D08_ServiceLandscape, D10_CredentialSurface, D11_DevAdminEnvironment,
]

NETWORK_DOMAINS = [
    D01_SystemIdentity, D09_NetworkContext,
]

FULL_DOMAINS = [
    D01_SystemIdentity, D02_UserSession, D03_ProcessIntel, D04_SoftwareInventory,
    D05_FilesystemSurface, D06_PersistenceMap, D07_SecurityTelemetry,
    D08_ServiceLandscape, D09_NetworkContext, D10_CredentialSurface,
    D11_DevAdminEnvironment,
]

MODE_DOMAINS = {"endpoint": ENDPOINT_DOMAINS, "network": NETWORK_DOMAINS, "full": FULL_DOMAINS}


class Orchestrator:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.log = RunLogger(ctx)
        self._domains: Dict[str, DomainResult] = {}

    def run(self) -> int:
        self._preamble()
        domain_classes = MODE_DOMAINS[self.ctx.mode]
        total = len(domain_classes)

        print(f"\n  {cyn('━' * 56)}")
        print(f"  {bld('COLLECTION PIPELINE')}")
        print(f"  {cyn('━' * 56)}\n")

        for idx, cls in enumerate(domain_classes, 1):
            instance = cls(self.ctx)
            section_header(instance.display_name, idx, total)
            result = self._execute(instance)
            self._domains[instance.domain_id] = result
            collector_row(instance.display_name, result.status, result.item_count, result.elapsed)
            self.log.domain(result)
            if self.ctx.verbose and result.findings:
                for f in result.findings[:5]:
                    print(f"      {dim('['+f['severity'].upper()+']')} {f['title']}")

        print(f"\n  {dim('Running artifact correlation ...')}")
        correlation = run_correlation(self._domains)
        self.log.info(f"Correlation: {len(correlation['correlation_chains'])} chains")

        print(f"  {dim('Computing risk scores ...')}")
        risk = compute_risk(self._domains, correlation)
        self.log.info(f"Risk: {risk.rating} ({risk.overall})")

        report = VortexReport(
            session_id=self.ctx.session_id,
            hostname=self.ctx.hostname,
            os_platform=self.ctx.os_platform,
            mode=self.ctx.mode,
            privilege=self.ctx.privilege_label,
            start_time=self.ctx.start_time.isoformat() + "Z",
            end_time=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
            domains=list(self._domains.values()),
            correlation=correlation,
            risk=risk,
        )

        print(f"\n  {cyn('━' * 56)}")
        print(f"  {bld('REPORT GENERATION')}\n")
        json_path = write_json(report, self.ctx.output_dir)
        print(f"    {dim('JSON')}   {wht(json_path)}")
        if not self.ctx.json_only:
            html_path = write_html(report, self.ctx.output_dir)
            print(f"    {dim('HTML')}   {wht(html_path)}")
        log_path = self.log.finalize()
        print(f"    {dim('LOG')}    {wht(log_path)}")

        self._footer(risk)
        return 0

    def _execute(self, domain: BaseDomain) -> DomainResult:
        t0 = time.monotonic()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(domain.collect)
                result = future.result(timeout=self.ctx.timeout)
            result.elapsed = time.monotonic() - t0
            return result
        except concurrent.futures.TimeoutError:
            return DomainResult(
                domain_id=domain.domain_id, display_name=domain.display_name,
                status="skip", error="Timeout", elapsed=time.monotonic() - t0
            )
        except Exception as exc:
            self.log.error(f"{domain.domain_id}: {traceback.format_exc()}")
            return DomainResult(
                domain_id=domain.domain_id, display_name=domain.display_name,
                status="fail", error=str(exc), elapsed=time.monotonic() - t0
            )

    def _preamble(self):
        ctx = self.ctx
        print(f"  {dim('Session')}    {wht(ctx.session_id)}")
        print(f"  {dim('Host')}       {wht(ctx.hostname)}")
        print(f"  {dim('Platform')}   {wht(ctx.os_platform)}")
        print(f"  {dim('Mode')}       {wht(ctx.mode.upper())}")
        print(f"  {dim('Privilege')}  {wht(ctx.privilege_label)}")
        print(f"  {dim('Output')}     {wht(ctx.output_dir)}")

    def _footer(self, risk: RiskProfile):
        elapsed = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - self.ctx.start_time).total_seconds()
        print(f"\n  {cyn('━' * 56)}")
        print(f"  {bld('Overall Risk Rating')}   {risk_label(risk.overall)}")
        for axis, score in risk.axes.items():
            print(f"    {dim(axis.ljust(26))}  {risk_bar(score)}  {risk_label(score)}")
        print(f"\n  {dim('Completed in')}  {wht(f'{elapsed:.1f}s')}")
        print(f"  {cyn('━' * 56)}")
        print(f"\n  {dim('VORTEX  ·  Engineered by Anas Labrini')}\n")

def _build_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="VORTEX",
        description="VORTEX — Vulnerability & Operational Risk Telemetry EXtraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Execution Modes:
  endpoint    Endpoint-focused intelligence (default)
  network     Network context and exposure mapping
  full        Full correlated assessment (all domains)

Examples:
  python VORTEX.py
  python VORTEX.py --mode full --output ./reports
  python VORTEX.py --mode network --json-only --timeout 60
  python VORTEX.py --mode endpoint --no-color --verbose
        """
    )
    p.add_argument("--mode",     choices=["endpoint","network","full"], default="full")
    p.add_argument("--output",   default="./VORTEX_output", metavar="DIR")
    p.add_argument("--timeout",  type=int, default=180, metavar="SEC")
    p.add_argument("--json-only",action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--verbose",  action="store_true")
    return p.parse_args()

def main() -> int:
    global _COLOR_ON
    args = _build_args()
    _COLOR_ON = not args.no_color

    print_banner()

    ctx = Context(
        mode=args.mode,
        output_dir=args.output,
        timeout=args.timeout,
        json_only=args.json_only,
        verbose=args.verbose,
    )

    return Orchestrator(ctx).run()

def executionstart():
    sys.exit(main())