"""
 ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗
 ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
 ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝
 ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗
  ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  VERTEX  —  Visual Exposure & Risk Topology EXaminer
  Purple Team Assessment Platform  v1.0.0
  Engineered by Anas Labrini

  Usage   : python vertex.py [--mode network|endpoint|full]
  Output  : vertex_report_<timestamp>.html
            vertex_report_<timestamp>.json
            vertex_<timestamp>.log
  Platform: Windows 10 / 11 / Server 2016+ (degraded mode on Linux/macOS)

  COLLECTOR PIPELINE
  ──────────────────
  Stage 1  │  EnvironmentProbe     OS · hostname · privileges · interfaces
  Stage 2  │  TopologyMapper       subnets · ARP · live-host sweep · DNS
  Stage 3  │  ServiceScanner       TCP connect · banner capture · fingerprint
  Stage 4  │  IdentityAuditor      local accounts · groups · sessions · domain
  Stage 5  │  ExposureAnalyzer     SMB shares · anonymous access detection
  Stage 6  │  HardeningInspector   writable services · tasks · legacy daemons
  Stage 7  │  RiskEngine           per-host scoring · flag classification
  Stage 8  │  CorrelationBuilder   entity graph (nodes + typed edges)
  Stage 9  │  ReportComposer       JSON schema · HTML report · console output

  All stages:  wrapped in try/except · honour per-stage timeouts
               mark themselves PARTIAL/FAILED on error · never halt pipeline
"""

import sys, subprocess, importlib, os, platform

_IS_WINDOWS = platform.system() == "Windows"

_OPTIONAL_PACKAGES = {
    "colorama": "colorama",
    "jinja2":   "Jinja2",
}

def _bootstrap_package(module_name: str, pip_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        pass
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pip_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        importlib.import_module(module_name)
        return True
    except Exception:
        return False

for _m, _p in _OPTIONAL_PACKAGES.items():
    _bootstrap_package(_m, _p)

import re, json, socket, struct, threading, logging, traceback
import ipaddress, datetime, time, hashlib, ctypes, argparse
import concurrent.futures
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple, Set
from pathlib import Path
from enum import Enum

try:
    import colorama; colorama.init(autoreset=True)
    from colorama import Fore, Style
except ImportError:
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()

try:
    from jinja2 import Template as _JinjaTemplate
    _JINJA_AVAILABLE = True
except ImportError:
    _JINJA_AVAILABLE = False

PLATFORM_VERSION  = "1.0.0"
PLATFORM_NAME     = "VERTEX — Visual Exposure & Risk Topology EXaminer"
PLATFORM_AUTHOR   = "Anas Labrini"
SESSION_START     = datetime.datetime.now()
SESSION_ID        = SESSION_START.strftime("%Y%m%d_%H%M%S")

SCAN_TIMEOUT_CONNECT = 1.5
SCAN_TIMEOUT_BANNER  = 2.0
WORKERS_HOST         = 200
WORKERS_PORT         = 40
STAGE_TIMEOUT_SEC    = 120

SERVICE_TAXONOMY: Dict[str, List[int]] = {
    "remote_access":  [22, 23, 3389, 5900, 5985, 5986, 4899],
    "file_transfer":  [21, 445, 139, 2049, 548, 990],
    "web":            [80, 443, 8080, 8443, 8000, 8888, 3000, 9090],
    "directory":      [389, 636, 88, 464],
    "database":       [1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984],
    "network_infra":  [53, 67, 68, 123, 161, 162, 179, 520],
    "printing":       [515, 631, 9100],
    "surveillance":   [554, 8554, 37777, 34567],
    "industrial":     [102, 502, 47808, 4840, 1911],
    "messaging":      [25, 110, 143, 465, 587, 993, 995, 1883, 8883],
    "monitoring":     [199, 10050, 10051, 9090, 3000],
    "vpn":            [500, 1194, 1723, 4500],
    "management":     [623, 664, 3790, 7547],
}
ALL_SCAN_PORTS = sorted({p for ps in SERVICE_TAXONOMY.values() for p in ps})

DEVICE_SIGNATURES: List[Tuple[str, str, str]] = [
    (r"HP (LaserJet|OfficeJet|Color|DeskJet)",  "printer",        "Printer — HP"),
    (r"RICOH|Ricoh",                             "printer",        "Printer — Ricoh"),
    (r"EPSON|Epson",                             "printer",        "Printer — Epson"),
    (r"Canon",                                   "printer",        "Printer — Canon"),
    (r"Lexmark",                                 "printer",        "Printer — Lexmark"),
    (r"Brother",                                 "printer",        "Printer — Brother"),
    (r"Konica Minolta",                          "printer",        "Printer — Konica Minolta"),
    (r"Hikvision",                               "camera",         "IP Camera — Hikvision"),
    (r"Dahua",                                   "camera",         "IP Camera — Dahua"),
    (r"Axis Communications",                     "camera",         "IP Camera — Axis"),
    (r"Bosch Security",                          "camera",         "IP Camera — Bosch"),
    (r"RTSP/1\.[01]",                            "camera",         "IP Camera — Generic RTSP"),
    (r"Microsoft-IIS",                           "server",         "Windows Server (IIS)"),
    (r"Windows PowerShell",                      "server",         "Windows Host — WinRM"),
    (r"Ubuntu|Debian|CentOS|Rocky|AlmaLinux",    "server",         "Linux Server"),
    (r"OpenSSH",                                 "server",         "SSH Host — Linux/Unix"),
    (r"Cisco IOS|Cisco Adaptive",                "network_device", "Network Device — Cisco"),
    (r"Juniper",                                 "network_device", "Network Device — Juniper"),
    (r"MikroTik",                                "network_device", "Network Device — MikroTik"),
    (r"FortiGate|Fortinet",                      "network_device", "Firewall — Fortinet"),
    (r"pfSense",                                 "network_device", "Firewall — pfSense"),
    (r"Apache/",                                 "server",         "Web Server — Apache"),
    (r"nginx/",                                  "server",         "Web Server — Nginx"),
    (r"lighttpd",                                "server",         "Web Server — Lighttpd"),
    (r"Microsoft Exchange",                      "server",         "Mail Server — Exchange"),
    (r"VMware ESXi|ESXi",                        "server",         "Hypervisor — VMware ESXi"),
    (r"Synology",                                "storage",        "NAS — Synology"),
    (r"QNAP",                                    "storage",        "NAS — QNAP"),
    (r"TrueNAS|FreeNAS",                         "storage",        "NAS — TrueNAS"),
    (r"Modbus",                                  "industrial",     "Industrial Device — Modbus"),
    (r"BACnet",                                  "industrial",     "Building Automation — BACnet"),
]

PORT_RISK_TABLE: Dict[int, Tuple[str, str]] = {
    23:    ("CRITICAL", "Telnet — plaintext protocol exposed"),
    21:    ("HIGH",     "FTP — plaintext credential transmission"),
    161:   ("HIGH",     "SNMP — potential information disclosure"),
    502:   ("CRITICAL", "Modbus — industrial control protocol exposed"),
    47808: ("CRITICAL", "BACnet — building automation system exposed"),
    5900:  ("HIGH",     "VNC — unauthenticated remote access risk"),
    3389:  ("MEDIUM",   "RDP — remote desktop exposed to network segment"),
    5985:  ("HIGH",     "WinRM HTTP — lateral movement surface"),
    445:   ("MEDIUM",   "SMB — file sharing lateral movement surface"),
    389:   ("MEDIUM",   "LDAP unencrypted — credential interception risk"),
    9200:  ("HIGH",     "Elasticsearch — commonly unauthenticated"),
    27017: ("HIGH",     "MongoDB — commonly unauthenticated"),
    6379:  ("HIGH",     "Redis — commonly unauthenticated"),
}

_OUI_TABLE: Dict[str, str] = {
    "3c5a37": "HP Inc.",       "d4ae52": "HP Inc.",       "a0d3c1": "HP Inc.",
    "a45630": "Hikvision",     "c8f7a5": "Hikvision",     "44194b": "Dahua",
    "00306e": "Axis Comm.",    "accc8e": "Axis Comm.",
    "00000c": "Cisco Systems", "0011ba": "Cisco Systems",  "2c3ecf": "Cisco Systems",
    "001ec9": "MikroTik",      "4c5e0c": "MikroTik",
    "00155d": "Microsoft",     "000569": "VMware Inc.",
    "080027": "VirtualBox",    "525400": "QEMU/KVM",
    "001a11": "Google Inc.",   "f4f5d8": "Google Inc.",
    "dc4f22": "Ubiquiti",      "00156d": "Ubiquiti",
    "b4fbe4": "Synology",      "001132": "Synology",
}

def resolve_mac_vendor(mac: str) -> str:
    if mac in ("N/A", ""):
        return "N/A"
    prefix = mac.replace(":", "").lower()[:6]
    return _OUI_TABLE.get(prefix, "Unknown Vendor")

class EntityType(str, Enum):
    HOST    = "Host"
    USER    = "User"
    SERVICE = "Service"
    DEVICE  = "Device"
    SUBNET  = "Subnet"

class RelationType(str, Enum):
    CONNECTS_TO     = "CONNECTS_TO"
    HOSTS_SERVICE   = "HOSTS_SERVICE"
    HAS_ACCOUNT     = "HAS_ACCOUNT"
    EXPOSES_SHARE   = "EXPOSES_SHARE"
    RESOLVES_TO     = "RESOLVES_TO"
    MEMBER_OF       = "MEMBER_OF"
    TRUSTS          = "TRUSTS"
    SESSION_ON      = "SESSION_ON"

@dataclass
class EntityNode:
    id:         str
    type:       str
    label:      str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EntityEdge:
    source:     str
    target:     str
    relation:   str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ServiceRecord:
    port:      int
    protocol:  str  = "tcp"
    open:      bool = False
    name:      str  = ""
    banner:    str  = ""
    category:  str  = ""
    risk:      str  = "INFO"
    risk_desc: str  = ""

@dataclass
class HostRecord:
    ip:           str
    hostname:     str                   = "N/A"
    mac:          str                   = "N/A"
    vendor:       str                   = "N/A"
    os_hint:      str                   = "Unknown"
    device_class: str                   = "unknown"
    device_label: str                   = "Unknown Device"
    role:         str                   = "unknown"
    domain_joined: bool                 = False
    domain_info:  Dict[str, Any]        = field(default_factory=dict)
    services:     List[ServiceRecord]   = field(default_factory=list)
    shares:       List[str]             = field(default_factory=list)
    exposed_shares: List[str]           = field(default_factory=list)
    accounts:     List[str]             = field(default_factory=list)
    sessions:     List[str]             = field(default_factory=list)
    risk_findings: List[Dict[str, str]] = field(default_factory=list)
    scan_time:    str                   = ""
    reachable:    bool                  = True

@dataclass
class StageResult:
    name:     str
    status:   str   = "OK"       # OK | PARTIAL | FAILED | SKIPPED
    duration: float = 0.0
    errors:   List[str]  = field(default_factory=list)
    data:     Any        = None

@dataclass
class CorrelationGraph:
    nodes: List[EntityNode] = field(default_factory=list)
    edges: List[EntityEdge] = field(default_factory=list)

    def add_node(self, node: EntityNode):
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)

    def add_edge(self, edge: EntityEdge):
        self.edges.append(edge)

    def serialize(self) -> dict:
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }

_LOG_PATH = Path(f"vertex_{SESSION_ID}.log")
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(_LOG_PATH, encoding="utf-8")],
)
_logger = logging.getLogger("VERTEX")

_PRINT_LOCK = threading.Lock()

def _emit(msg: str):
    with _PRINT_LOCK:
        print(msg, flush=True)

def stage_header(title: str):
    bar = "─" * 72
    _emit(f"\n{Fore.CYAN}{bar}")
    _emit(f"{Fore.CYAN}  ▸  {title}")
    _emit(f"{Fore.CYAN}{bar}{Style.RESET_ALL}")

def emit_ok(msg: str):   _emit(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def emit_warn(msg: str): _emit(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def emit_fail(msg: str): _emit(f"  {Fore.RED}[-]{Style.RESET_ALL} {msg}")
def emit_info(msg: str): _emit(f"  {Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def emit_dim(msg: str):  _emit(f"  {Style.DIM}{msg}{Style.RESET_ALL}")

def draw_progress(done: int, total: int, width: int = 44):
    pct    = done / total if total else 0
    filled = int(width * pct)
    bar    = "█" * filled + "░" * (width - filled)
    with _PRINT_LOCK:
        print(
            f"\r  {Fore.CYAN}[{bar}]{Style.RESET_ALL} {done}/{total} ({pct*100:.1f}%)",
            end="", flush=True,
        )

class EnvironmentProbe:

    def execute(self) -> StageResult:
        t0 = time.time()
        result = StageResult(name="EnvironmentProbe")
        errors: List[str] = []
        data: Dict[str, Any] = {}

        try:
            data["os"]           = platform.system()
            data["os_release"]   = platform.release()
            data["os_version"]   = platform.version()
            data["architecture"] = platform.machine()
            data["python_ver"]   = platform.python_version()
            data["hostname"]     = socket.gethostname()
        except Exception as e:
            errors.append(f"OS metadata: {e}")

        try:
            data["current_user"] = os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
            data["is_elevated"]  = self._detect_privilege()
            data["user_domain"]  = os.environ.get("USERDOMAIN", "N/A")
        except Exception as e:
            errors.append(f"User context: {e}")

        try:
            data["interfaces"] = self._enumerate_interfaces()
        except Exception as e:
            errors.append(f"Interfaces: {e}")
            data["interfaces"] = []

        result.data     = data
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

    def _detect_privilege(self) -> bool:
        try:
            if _IS_WINDOWS:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.getuid() == 0
        except Exception:
            return False

    def _enumerate_interfaces(self) -> List[Dict[str, str]]:
        ifaces: List[Dict[str, str]] = []

        try:
            seen: Set[str] = set()
            for addr in socket.getaddrinfo(socket.gethostname(), None):
                ip = addr[4][0]
                if ip not in seen and not ip.startswith("127.") and ":" not in ip:
                    seen.add(ip)
                    ifaces.append({"ip": ip, "family": "IPv4"})
        except Exception:
            pass

        if _IS_WINDOWS:
            try:
                out = subprocess.check_output(
                    ["ipconfig", "/all"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=10,
                )
                current: Dict[str, str] = {}
                for line in out.splitlines():
                    line = line.strip()
                    if line.endswith(":") and not line.startswith("Windows"):
                        if current and "ip" in current:
                            ifaces.append(current)
                        current = {"adapter": line.rstrip(":")}
                    m_ip   = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
                    m_mask = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
                    m_gw   = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", line)
                    m_mac  = re.search(r"Physical Address[^:]*:\s*([0-9A-F-]{17})", line)
                    if m_ip:   current["ip"]      = m_ip.group(1)
                    if m_mask: current["mask"]    = m_mask.group(1)
                    if m_gw:   current["gateway"] = m_gw.group(1)
                    if m_mac:  current["mac"]     = m_mac.group(1).replace("-", ":").lower()
                if current and "ip" in current:
                    ifaces.append(current)
            except Exception:
                pass

        return ifaces

class TopologyMapper:

    def __init__(self, env_data: Dict[str, Any]):
        self.env = env_data

    def execute(self) -> StageResult:
        t0 = time.time()
        result = StageResult(name="TopologyMapper")
        errors: List[str] = []
        data: Dict[str, Any] = {
            "subnets": [], "arp_table": {}, "live_hosts": [], "dns_map": {}
        }

        try:
            data["subnets"] = self._detect_subnets()
        except Exception as e:
            errors.append(f"Subnet detection: {e}")
            data["subnets"] = self._fallback_subnet()

        try:
            data["arp_table"] = self._read_arp_table()
        except Exception as e:
            errors.append(f"ARP table: {e}")

        all_ips: List[str] = []
        for cidr in data["subnets"]:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                if net.prefixlen >= 16:
                    all_ips.extend(str(h) for h in net.hosts())
                else:
                    emit_warn(f"Skipping large network {cidr} (prefix < /16)")
            except Exception as e:
                errors.append(f"CIDR expansion {cidr}: {e}")

        data["probe_targets"] = len(all_ips)
        emit_info(f"Probing {len(all_ips)} addresses for live hosts …")

        try:
            data["live_hosts"] = self._sweep_live_hosts(all_ips)
        except Exception as e:
            errors.append(f"Host sweep: {e}")

        try:
            data["dns_map"] = self._reverse_dns_batch(data["live_hosts"])
        except Exception as e:
            errors.append(f"Reverse DNS: {e}")

        result.data     = data
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

    def _detect_subnets(self) -> List[str]:
        subnets: List[str] = []
        if _IS_WINDOWS:
            out = subprocess.check_output(
                ["ipconfig"], encoding="utf-8", errors="replace",
                stderr=subprocess.DEVNULL, timeout=10,
            )
            ips   = re.findall(r"IPv4[^:]+:\s+([\d.]+)", out)
            masks = re.findall(r"Subnet Mask[^:]+:\s+([\d.]+)", out)
            for ip, mask in zip(ips, masks):
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    subnets.append(str(net))
                except ValueError:
                    pass
        else:
            out = subprocess.check_output(
                ["ip", "route"], encoding="utf-8", errors="replace",
                stderr=subprocess.DEVNULL, timeout=10,
            )
            for line in out.splitlines():
                m = re.match(r"([\d./]+)\s+dev\s+\S+\s+proto\s+kernel", line)
                if m:
                    try:
                        ipaddress.IPv4Network(m.group(1))
                        subnets.append(m.group(1))
                    except ValueError:
                        pass
        return list(dict.fromkeys(subnets))

    def _fallback_subnet(self) -> List[str]:
        try:
            ip = socket.gethostbyname(socket.gethostname())
            parts = ip.split(".")
            return [f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"]
        except Exception:
            return ["192.168.1.0/24"]

    def _read_arp_table(self) -> Dict[str, str]:
        table: Dict[str, str] = {}
        cmd = ["arp", "-a"] if _IS_WINDOWS else ["arp", "-n"]
        out = subprocess.check_output(
            cmd, encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, timeout=10,
        )
        pat = re.compile(
            r"([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})"
            r".*?([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]"
            r"[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-]"
            r"[0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
        )
        for m in pat.finditer(out):
            mac = m.group(2).replace("-", ":").lower()
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                table[m.group(1)] = mac
        return table

    def _sweep_live_hosts(self, ips: List[str]) -> List[str]:
        PROBE_PORTS = [80, 443, 22, 445, 3389, 8080, 8443, 135, 139]
        live: List[str] = []
        done = 0
        total = len(ips)
        lock  = threading.Lock()

        def probe(ip: str) -> Optional[str]:
            for port in PROBE_PORTS:
                try:
                    with socket.create_connection((ip, port), timeout=SCAN_TIMEOUT_CONNECT):
                        return ip
                except Exception:
                    pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS_HOST) as pool:
            futures = {pool.submit(probe, ip): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futures):
                with lock:
                    done += 1
                    draw_progress(done, total)
                try:
                    r = fut.result()
                    if r:
                        with lock:
                            live.append(r)
                except Exception:
                    pass
        print()
        return live

    def _reverse_dns_batch(self, ips: List[str]) -> Dict[str, str]:
        dns_map: Dict[str, str] = {}

        def lookup(ip: str) -> Tuple[str, str]:
            try:
                return ip, socket.gethostbyaddr(ip)[0]
            except Exception:
                return ip, "N/A"

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            for ip, name in pool.map(lookup, ips):
                dns_map[ip] = name
        return dns_map

_SERVICE_PROBES: Dict[int, bytes] = {
    21:    b"",
    22:    b"",
    23:    b"",
    25:    b"EHLO vertex\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    110:   b"",
    143:   b"",
    389:   b"",
    443:   None,
    445:   None,
    515:   b"\x04",
    554:   b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    631:   b"GET / HTTP/1.0\r\n\r\n",
    3306:  b"",
    3389:  None,
    5432:  b"",
    6379:  b"*1\r\n$4\r\nPING\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n",
    8443:  None,
    9100:  b"\x1b%-12345X@PJL INFO ID\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    27017: b"",
}

_SERVICE_NAMES: Dict[int, str] = {
    21: "FTP",       22: "SSH",        23: "Telnet",     25: "SMTP",
    53: "DNS",       67: "DHCP",       80: "HTTP",       88: "Kerberos",
    110: "POP3",     123: "NTP",       135: "MSRPC",     139: "NetBIOS",
    143: "IMAP",     161: "SNMP",      389: "LDAP",      443: "HTTPS",
    445: "SMB",      464: "Kpasswd",   465: "SMTPS",     502: "Modbus",
    515: "LPD",      554: "RTSP",      587: "SMTP",      631: "IPP",
    636: "LDAPS",    993: "IMAPS",     995: "POP3S",     1433: "MSSQL",
    1521: "Oracle",  3306: "MySQL",    3389: "RDP",       5432: "PostgreSQL",
    5900: "VNC",     5985: "WinRM",    5986: "WinRM-TLS",
    6379: "Redis",   8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9100: "JetDirect", 9200: "Elasticsearch",
    27017: "MongoDB", 47808: "BACnet",
}


class HostServiceScanner:

    def scan(self, ip: str, mac: str) -> HostRecord:
        rec = HostRecord(
            ip=ip,
            mac=mac,
            vendor=resolve_mac_vendor(mac),
            scan_time=datetime.datetime.now().isoformat(timespec="seconds"),
        )
        open_services: List[ServiceRecord] = []
        all_banners:   List[str]           = []

        def probe_port(port: int) -> Optional[ServiceRecord]:
            try:
                with socket.create_connection((ip, port), timeout=SCAN_TIMEOUT_CONNECT):
                    pass
                svc = ServiceRecord(port=port, open=True)
                svc.category = self._classify_port_category(port)
                risk, rdesc  = PORT_RISK_TABLE.get(port, ("INFO", ""))
                svc.risk     = risk
                svc.risk_desc = rdesc
                return svc
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS_PORT) as pool:
            for svc in pool.map(probe_port, ALL_SCAN_PORTS):
                if svc:
                    open_services.append(svc)

        for svc in open_services:
            banner = self._capture_banner(ip, svc.port)
            svc.banner = banner
            svc.name   = _SERVICE_NAMES.get(svc.port, str(svc.port))
            if banner:
                all_banners.append(banner)

        rec.services = open_services

        dev_class, dev_label = self._fingerprint_device(
            all_banners, [s.port for s in open_services]
        )
        rec.device_class = dev_class
        rec.device_label = dev_label
        rec.role         = self._infer_role(dev_class, open_services)
        return rec

    def _capture_banner(self, ip: str, port: int) -> str:
        if port in (443, 8443, 3389, 445):
            return ""
        probe = _SERVICE_PROBES.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(SCAN_TIMEOUT_BANNER)
            sock.connect((ip, port))
            if probe:
                sock.sendall(probe)
            raw = sock.recv(2048)
            sock.close()
            return raw.decode("utf-8", errors="replace").strip()[:768]
        except Exception:
            return ""

    def _classify_port_category(self, port: int) -> str:
        for cat, ports in SERVICE_TAXONOMY.items():
            if port in ports:
                return cat
        return "other"

    def _fingerprint_device(self, banners: List[str], ports: List[int]) -> Tuple[str, str]:
        combined = " ".join(banners)
        for pattern, cls, label in DEVICE_SIGNATURES:
            if re.search(pattern, combined, re.IGNORECASE):
                return cls, label
        if {9100, 515, 631} & set(ports):
            return "printer",  "Printer — Generic"
        if {554, 8554} & set(ports):
            return "camera",   "IP Camera — Generic"
        if {502} & set(ports):
            return "industrial", "Industrial Device — Modbus"
        if {47808} & set(ports):
            return "industrial", "Building Automation — BACnet"
        if {445, 3389} <= set(ports):
            return "workstation", "Windows Workstation / Server"
        if {445} & set(ports) and {22} & set(ports):
            return "server",    "Linux/Windows Mixed Host"
        if {445} & set(ports):
            return "server",    "Windows / Samba Host"
        if {22} & set(ports):
            return "server",    "SSH-Accessible Host"
        if {80, 443} & set(ports):
            return "server",    "Web-Accessible Device"
        return "unknown", "Unknown Device"

    def _infer_role(self, device_class: str, services: List[ServiceRecord]) -> str:
        port_set = {s.port for s in services}
        if 88 in port_set and 389 in port_set:
            return "domain_controller"
        if device_class in ("printer", "camera", "industrial"):
            return device_class
        if device_class == "network_device":
            return "network_device"
        if {3389, 445} <= port_set:
            return "windows_host"
        if 22 in port_set and 80 not in port_set:
            return "linux_server"
        if {80, 443} & port_set:
            return "web_server"
        return "endpoint"


class ServiceScanOrchestrator:

    def execute(
        self,
        live_hosts: List[str],
        dns_map:    Dict[str, str],
        arp_table:  Dict[str, str],
    ) -> StageResult:
        t0 = time.time()
        result = StageResult(name="ServiceScanner")
        errors:  List[str]       = []
        records: List[HostRecord] = []
        scanner  = HostServiceScanner()
        done     = 0
        total    = len(live_hosts)
        lock     = threading.Lock()

        emit_info(f"Scanning services on {total} live hosts …")

        def scan_one(ip: str) -> Optional[HostRecord]:
            try:
                mac = arp_table.get(ip, "N/A")
                rec = scanner.scan(ip, mac)
                rec.hostname = dns_map.get(ip, "N/A")
                return rec
            except Exception as e:
                _logger.warning(f"scan error {ip}: {e}")
                return HostRecord(ip=ip, hostname=dns_map.get(ip, "N/A"), reachable=False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS_HOST) as pool:
            futures = {pool.submit(scan_one, ip): ip for ip in live_hosts}
            for fut in concurrent.futures.as_completed(futures):
                with lock:
                    done += 1
                    draw_progress(done, total)
                try:
                    rec = fut.result()
                    if rec:
                        with lock:
                            records.append(rec)
                except Exception as e:
                    errors.append(str(e))
        print()

        result.data     = records
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

class IdentityAuditor:


    def execute(self) -> StageResult:
        t0 = time.time()
        result = StageResult(name="IdentityAuditor")
        errors: List[str] = []
        data: Dict[str, Any] = {
            "local_accounts":  [],
            "admin_members":   [],
            "active_sessions": [],
            "domain":          None,
            "domain_controllers": [],
        }

        for key, fn in [
            ("local_accounts",  self._enumerate_accounts),
            ("admin_members",   self._enumerate_admin_group),
            ("active_sessions", self._enumerate_sessions),
        ]:
            try:
                data[key] = fn()
            except Exception as e:
                errors.append(f"{key}: {e}")

        try:
            data["domain"]             = os.environ.get("USERDNSDOMAIN", None)
            data["domain_controllers"] = self._locate_domain_controllers()
        except Exception as e:
            errors.append(f"Domain context: {e}")

        result.data     = data
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

    def _enumerate_accounts(self) -> List[Dict[str, str]]:
        accounts = []
        if _IS_WINDOWS:
            out = subprocess.check_output(
                ["net", "user"],
                encoding="utf-8", errors="replace",
                stderr=subprocess.DEVNULL, timeout=10,
            )
            recording = False
            names: List[str] = []
            for line in out.splitlines():
                if "---" in line:
                    recording = True
                    continue
                if recording and line.strip():
                    names.extend(re.findall(r"(\S+)", line))
            for name in names[:30]:
                try:
                    ud = subprocess.check_output(
                        ["net", "user", name],
                        encoding="utf-8", errors="replace",
                        stderr=subprocess.DEVNULL, timeout=6,
                    )
                    active = "Yes" if re.search(r"Account active\s+Yes", ud) else "No"
                    last   = ""
                    m = re.search(r"Last logon\s+(.+)", ud)
                    if m: last = m.group(1).strip()
                    accounts.append({"username": name, "active": active, "last_logon": last})
                except Exception:
                    accounts.append({"username": name, "active": "?", "last_logon": "?"})
        else:
            out = subprocess.check_output(
                ["cut", "-d:", "-f1,7", "/etc/passwd"],
                encoding="utf-8", errors="replace", timeout=5,
            )
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) == 2 and "nologin" not in parts[1] and "false" not in parts[1]:
                    accounts.append({"username": parts[0], "active": "?", "last_logon": "?"})
        return accounts

    def _enumerate_admin_group(self) -> List[str]:
        members: List[str] = []
        if _IS_WINDOWS:
            out = subprocess.check_output(
                ["net", "localgroup", "Administrators"],
                encoding="utf-8", errors="replace",
                stderr=subprocess.DEVNULL, timeout=10,
            )
            recording = False
            for line in out.splitlines():
                if "---" in line:
                    recording = True
                    continue
                if recording and line.strip() and not line.startswith("The command"):
                    members.append(line.strip())
        else:
            try:
                out = subprocess.check_output(
                    ["getent", "group", "sudo"],
                    encoding="utf-8", errors="replace", timeout=5,
                )
                parts = out.strip().split(":")
                if len(parts) >= 4:
                    members = [u for u in parts[3].split(",") if u]
            except Exception:
                pass
        return members

    def _enumerate_sessions(self) -> List[Dict[str, str]]:
        sessions: List[Dict[str, str]] = []
        if _IS_WINDOWS:
            try:
                out = subprocess.check_output(
                    ["query", "session"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=10,
                )
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        sessions.append({
                            "session": parts[0].strip(">"),
                            "user":    parts[1] if len(parts) > 1 else "",
                            "state":   parts[3] if len(parts) > 3 else "",
                        })
            except Exception:
                pass
        else:
            try:
                out = subprocess.check_output(
                    ["who"], encoding="utf-8", errors="replace", timeout=5,
                )
                for line in out.splitlines():
                    parts = line.split()
                    if parts:
                        sessions.append({
                            "user":    parts[0],
                            "tty":     parts[1] if len(parts) > 1 else "",
                            "state":   "Active",
                        })
            except Exception:
                pass
        return sessions

    def _locate_domain_controllers(self) -> List[str]:
        dcs: List[str] = []
        if _IS_WINDOWS:
            try:
                out = subprocess.check_output(
                    ["nltest", "/dclist:"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=10,
                )
                for m in re.finditer(r"\\\\(\S+)", out):
                    dcs.append(m.group(1))
            except Exception:
                pass
            try:
                out = subprocess.check_output(
                    ["nslookup", "-type=SRV", "_ldap._tcp.dc._msdcs"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=8,
                )
                for m in re.finditer(r"svr hostname\s*=\s*(\S+)", out, re.I):
                    dcs.append(m.group(1).rstrip("."))
            except Exception:
                pass
        return list(dict.fromkeys(dcs))

class ExposureAnalyzer:

    _HIGH_RISK_SHARE_NAMES = {
        "share", "public", "everyone", "open", "data", "files",
        "temp", "backup", "archive", "common", "users",
    }

    def execute(self, records: List[HostRecord]) -> StageResult:
        t0 = time.time()
        result = StageResult(name="ExposureAnalyzer")
        errors: List[str] = []

        smb_targets = [r for r in records if any(s.port in (445, 139) for s in r.services)]
        emit_info(f"Analyzing SMB exposure on {len(smb_targets)} hosts …")

        def analyze_one(rec: HostRecord):
            try:
                self._enumerate_smb(rec)
            except Exception as e:
                errors.append(f"{rec.ip}: {e}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
            pool.map(analyze_one, smb_targets)

        result.data     = {"analyzed": len(smb_targets)}
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

    def _enumerate_smb(self, rec: HostRecord):
        if _IS_WINDOWS:
            try:
                out = subprocess.check_output(
                    ["net", "view", f"\\\\{rec.ip}", "/all"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=8,
                )
                shares = re.findall(r"^(\S+)\s+Disk", out, re.MULTILINE)
                rec.shares         = shares
                rec.exposed_shares = [s for s in shares if s.lower() in self._HIGH_RISK_SHARE_NAMES]
            except Exception:
                pass
        else:
            try:
                out = subprocess.check_output(
                    ["smbclient", "-L", rec.ip, "-N"],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=8,
                )
                shares = re.findall(r"^\s+(\S+)\s+Disk", out, re.MULTILINE)
                rec.shares         = shares
                rec.exposed_shares = [s for s in shares if s.lower() in self._HIGH_RISK_SHARE_NAMES]
            except Exception:
                pass

class HardeningInspector:

    def execute(self) -> StageResult:
        t0 = time.time()
        result = StageResult(name="HardeningInspector")
        errors:   List[str]           = []
        findings: List[Dict[str, str]] = []

        for check_fn, label in [
            (self._inspect_service_binaries, "Service binary ACLs"),
            (self._inspect_scheduled_tasks,  "Scheduled task ACLs"),
            (self._inspect_legacy_daemons,   "Legacy daemon inventory"),
        ]:
            try:
                findings.extend(check_fn())
            except Exception as e:
                errors.append(f"{label}: {e}")

        result.data     = {"findings": findings}
        result.errors   = errors
        result.status   = "PARTIAL" if errors else "OK"
        result.duration = round(time.time() - t0, 2)
        return result

    def _is_world_writable(self, path: str) -> bool:
        try:
            if _IS_WINDOWS:
                out = subprocess.check_output(
                    ["icacls", path],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=5,
                )
                return bool(re.search(r"(Everyone|BUILTIN\\Users|Tous).*(F|M|W)", out))
            return bool(os.stat(path).st_mode & 0o002)
        except Exception:
            return False

    def _inspect_service_binaries(self) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        if not _IS_WINDOWS:
            return findings
        out = subprocess.check_output(
            ["sc", "query", "type=", "all", "state=", "all"],
            encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, timeout=15,
        )
        for svc in re.findall(r"SERVICE_NAME:\s+(\S+)", out)[:60]:
            try:
                info_out = subprocess.check_output(
                    ["sc", "qc", svc],
                    encoding="utf-8", errors="replace",
                    stderr=subprocess.DEVNULL, timeout=5,
                )
                m = re.search(r"BINARY_PATH_NAME\s+:\s+(.+)", info_out)
                if not m:
                    continue
                bpath     = m.group(1).strip()
                exec_path = (bpath.split(".exe")[0] + ".exe").strip('"').strip("'")
                if os.path.exists(exec_path) and self._is_world_writable(exec_path):
                    findings.append({
                        "type":     "WRITABLE_SERVICE_BINARY",
                        "severity": "HIGH",
                        "service":  svc,
                        "path":     exec_path,
                        "detail":   "Service binary writable — privilege escalation surface",
                    })
            except Exception:
                pass
        return findings

    def _inspect_scheduled_tasks(self) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        if not _IS_WINDOWS:
            return findings
        out = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, timeout=20,
        )
        for line in out.splitlines()[1:]:
            parts = line.split('","')
            if len(parts) < 9:
                continue
            task_name = parts[1].strip('"')
            run_as    = parts[2].strip('"') if len(parts) > 2 else ""
            task_run  = parts[8].strip('"') if len(parts) > 8 else ""
            if run_as.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM"):
                if task_run and not task_run.startswith("%System"):
                    exec_path = task_run.split()[0].strip('"')
                    if os.path.exists(exec_path) and self._is_world_writable(exec_path):
                        findings.append({
                            "type":     "WRITABLE_TASK_BINARY",
                            "severity": "HIGH",
                            "task":     task_name,
                            "path":     exec_path,
                            "run_as":   run_as,
                            "detail":   "Scheduled task binary writable by low-privilege account",
                        })
        return findings

    def _inspect_legacy_daemons(self) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        if not _IS_WINDOWS:
            return findings
        out = subprocess.check_output(
            ["sc", "query", "type=", "all", "state=", "all"],
            encoding="utf-8", errors="replace",
            stderr=subprocess.DEVNULL, timeout=15,
        )
        legacy_set = {"telnet", "tftp", "ftp", "snmptrap", "rsh", "rexec"}
        for svc in re.findall(r"SERVICE_NAME:\s+(\S+)", out):
            if svc.lower() in legacy_set:
                findings.append({
                    "type":     "LEGACY_SERVICE_ENABLED",
                    "severity": "HIGH",
                    "service":  svc,
                    "detail":   f"Legacy/insecure service '{svc}' is active",
                })
        return findings

class RiskEngine:

    _SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def evaluate(self, records: List[HostRecord], identity: Dict[str, Any]):
        for rec in records:
            self._score_host(rec, identity)

    def _score_host(self, rec: HostRecord, identity: Dict[str, Any]):
        findings: List[Dict[str, str]] = []
        port_set = {s.port for s in rec.services}

        for port, (sev, desc) in PORT_RISK_TABLE.items():
            if port in port_set:
                findings.append({"severity": sev, "desc": desc, "port": str(port)})

        for share in rec.exposed_shares:
            findings.append({
                "severity": "HIGH",
                "desc":     f"Anonymously accessible SMB share: {share}",
                "port":     "445",
            })

        for svc in rec.services:
            if re.search(r"(admin|default|password|root|guest)\s*[:=]",
                         svc.banner, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "desc":     "Banner exposes likely default credential reference",
                    "port":     str(svc.port),
                })
                break

        if "Camera" in rec.device_label:
            findings.append({
                "severity": "MEDIUM",
                "desc":     "IP Camera — verify firmware version and default credentials",
                "port":     "",
            })
        if "Printer" in rec.device_label and 80 in port_set:
            findings.append({
                "severity": "MEDIUM",
                "desc":     "Printer web interface exposed — verify access controls",
                "port":     "80",
            })

        rec.risk_findings = findings

    @staticmethod
    def worst_severity(findings: List[Dict[str, str]]) -> str:
        rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return max(
            (f["severity"] for f in findings),
            key=lambda s: rank.get(s, 0),
            default="OK",
        )

class CorrelationBuilder:

    def build(
        self,
        env_data:  Dict[str, Any],
        topology:  Dict[str, Any],
        records:   List[HostRecord],
        identity:  Dict[str, Any],
        hardening: Dict[str, Any],
    ) -> CorrelationGraph:
        graph = CorrelationGraph()

        for cidr in topology.get("subnets", []):
            graph.add_node(EntityNode(
                id=f"subnet:{cidr}",
                type=EntityType.SUBNET,
                label=cidr,
                properties={"cidr": cidr},
            ))

        for rec in records:
            hid = f"host:{rec.ip}"
            graph.add_node(EntityNode(
                id=hid, type=EntityType.HOST, label=rec.ip,
                properties={
                    "ip":            rec.ip,
                    "hostname":      rec.hostname,
                    "mac":           rec.mac,
                    "vendor":        rec.vendor,
                    "device_class":  rec.device_class,
                    "device_label":  rec.device_label,
                    "role":          rec.role,
                    "os_hint":       rec.os_hint,
                    "open_ports":    [s.port for s in rec.services],
                    "risk_count":    len(rec.risk_findings),
                    "high_risk":     any(f["severity"] in ("CRITICAL", "HIGH")
                                         for f in rec.risk_findings),
                    "shares":        rec.shares,
                    "exposed_shares": rec.exposed_shares,
                },
            ))

            for svc in rec.services:
                sid = f"service:{rec.ip}:{svc.port}"
                graph.add_node(EntityNode(
                    id=sid, type=EntityType.SERVICE,
                    label=svc.name or str(svc.port),
                    properties={
                        "port":      svc.port,
                        "name":      svc.name,
                        "banner":    svc.banner[:128] if svc.banner else "",
                        "category":  svc.category,
                        "risk":      svc.risk,
                        "risk_desc": svc.risk_desc,
                    },
                ))
                graph.add_edge(EntityEdge(
                    source=hid, target=sid, relation=RelationType.HOSTS_SERVICE,
                ))

            if rec.hostname and rec.hostname != "N/A":
                dns_id = f"dns:{rec.hostname}"
                graph.add_node(EntityNode(
                    id=dns_id, type=EntityType.HOST, label=rec.hostname,
                    properties={"type": "dns_name"},
                ))
                graph.add_edge(EntityEdge(
                    source=hid, target=dns_id, relation=RelationType.RESOLVES_TO,
                ))

            for cidr in topology.get("subnets", []):
                try:
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    if ipaddress.IPv4Address(rec.ip) in net:
                        graph.add_edge(EntityEdge(
                            source=hid,
                            target=f"subnet:{cidr}",
                            relation=RelationType.CONNECTS_TO,
                        ))
                        break
                except Exception:
                    pass

            if rec.shares:
                share_id = f"share:{rec.ip}"
                graph.add_node(EntityNode(
                    id=share_id, type=EntityType.DEVICE, label=f"Shares@{rec.ip}",
                    properties={"shares": rec.shares, "exposed_shares": rec.exposed_shares},
                ))
                graph.add_edge(EntityEdge(
                    source=hid, target=share_id, relation=RelationType.EXPOSES_SHARE,
                ))

        local_host_id = (
            f"host:{env_data.get('interfaces', [{}])[0].get('ip', 'localhost')}"
            if env_data.get("interfaces") else "host:localhost"
        )
        for acct in identity.get("local_accounts", []):
            uname = acct.get("username", "?") if isinstance(acct, dict) else str(acct)
            uid   = f"user:{uname}"
            graph.add_node(EntityNode(
                id=uid, type=EntityType.USER, label=uname,
                properties={
                    "username":   uname,
                    "active":     acct.get("active", "?") if isinstance(acct, dict) else "?",
                    "last_logon": acct.get("last_logon", "?") if isinstance(acct, dict) else "?",
                    "is_admin":   uname in identity.get("admin_members", []),
                },
            ))
            graph.add_edge(EntityEdge(
                source=local_host_id, target=uid, relation=RelationType.HAS_ACCOUNT,
            ))

        return graph


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VERTEX — Assessment Report</title>
<style>
:root {
  --bg:        #080c18;
  --card:      #0d1322;
  --card2:     #121928;
  --border:    #1a2540;
  --accent:    #00c8f0;
  --accent2:   #0050a0;
  --highlight: #00e5ff;
  --green:     #20d472;
  --red:       #f04848;
  --orange:    #f07820;
  --yellow:    #e8b820;
  --text:      #dce8f8;
  --muted:     #4a6080;
  --font:      'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  padding: 32px 28px;
  font-size: 13px;
  line-height: 1.65;
}

/* ── Header ── */
.v-header {
  background: linear-gradient(135deg, #060c1a 0%, #0a1530 60%, #0c1a40 100%);
  border: 1px solid #1a3060;
  border-radius: 14px;
  padding: 30px 36px;
  margin-bottom: 30px;
  display: flex;
  align-items: flex-start;
  gap: 28px;
}
.v-wordmark {
  font-size: 2.6rem;
  font-weight: 900;
  letter-spacing: -2px;
  background: linear-gradient(90deg, var(--highlight), var(--accent), #6080ff);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  line-height: 1;
}
.v-tagline {
  font-size: 0.8rem;
  color: var(--accent);
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-top: 5px;
}
.v-meta {
  font-size: 0.75rem;
  color: var(--muted);
  margin-top: 8px;
  line-height: 1.8;
}
.v-meta span { color: var(--text); }
.v-badge-auth {
  margin-left: auto;
  align-self: flex-start;
  background: #100308;
  border: 1px solid #400010;
  color: #f08090;
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  padding: 5px 12px;
  border-radius: 20px;
  text-transform: uppercase;
  white-space: nowrap;
}

/* ── KPI Grid ── */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin-bottom: 30px;
}
.kpi-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 18px 16px 14px;
  text-align: center;
}
.kpi-value {
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: -1px;
  line-height: 1;
}
.kpi-label {
  font-size: 0.65rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 5px;
}
.kv-blue   { color: var(--accent); }
.kv-red    { color: var(--red); }
.kv-orange { color: var(--orange); }
.kv-green  { color: var(--green); }
.kv-muted  { color: #7090b0; }

/* ── Section ── */
.section { margin-bottom: 36px; }
.section-title {
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-title::before {
  content: '';
  display: inline-block;
  width: 3px;
  height: 14px;
  background: var(--accent);
  border-radius: 2px;
}

/* ── Pipeline cards ── */
.pipeline-grid { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
.stage-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 16px;
  font-size: 0.76rem;
  min-width: 160px;
}
.stage-name { font-weight: 700; margin-bottom: 2px; }
.stage-meta { color: var(--muted); font-size: 0.68rem; }
.stage-ok   { border-left: 3px solid var(--green); }
.stage-partial { border-left: 3px solid var(--yellow); }
.stage-failed  { border-left: 3px solid var(--red); }
.stage-skipped { border-left: 3px solid var(--muted); }

/* ── Tables ── */
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
}
th {
  background: var(--card2);
  padding: 9px 13px;
  text-align: left;
  color: var(--muted);
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
}
td {
  padding: 8px 13px;
  border-bottom: 1px solid #10182e;
  vertical-align: top;
  font-size: 0.78rem;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: #0b1226; }

/* ── Badges ── */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.65rem;
  font-weight: 700;
  letter-spacing: 0.04em;
}
.b-green  { background: #041a0e; color: #30e870; }
.b-red    { background: #1e0404; color: #f07070; }
.b-orange { background: #1e0e04; color: #f09050; }
.b-yellow { background: #1e1804; color: #e8c840; }
.b-blue   { background: #041028; color: #60c0f8; }
.b-purple { background: #100428; color: #c090f8; }
.b-gray   { background: #101830; color: #8090b0; }

/* ── Risk flags ── */
.risk-tag {
  display: inline-block;
  font-size: 0.68rem;
  padding: 3px 8px;
  border-radius: 4px;
  margin: 2px 1px;
  font-weight: 600;
}
.r-CRITICAL { background: #280000; color: #ff8080; border: 1px solid #600000; }
.r-HIGH     { background: #1e0a00; color: #ffb060; border: 1px solid #602000; }
.r-MEDIUM   { background: #1a1400; color: #ffe060; border: 1px solid #604000; }
.r-LOW      { background: #001810; color: #60e890; border: 1px solid #004020; }
.r-INFO     { background: #000e28; color: #70c0ff; border: 1px solid #002060; }

/* ── Utilities ── */
.mono  { font-family: 'Consolas', 'Courier New', monospace; font-size: 0.76rem; }
.muted { color: var(--muted); }
.ports { font-family: 'Consolas', monospace; font-size: 0.70rem; color: var(--accent); }

/* ── Search ── */
.search-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
}
.search-bar input {
  flex: 1;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  padding: 7px 12px;
  font-size: 0.78rem;
  outline: none;
}
.search-bar input:focus { border-color: var(--accent); }

/* ── Collapsible ── */
details > summary {
  cursor: pointer;
  padding: 10px 14px;
  background: var(--card2);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 600;
  color: var(--accent);
  list-style: none;
  user-select: none;
  margin-bottom: 10px;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: '▸ ';
  color: var(--muted);
}
details[open] > summary::before { content: '▾ '; }

/* ── Footer ── */
footer {
  text-align: center;
  color: var(--muted);
  font-size: 0.68rem;
  margin-top: 48px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
  line-height: 2;
}
footer .author { color: var(--accent); font-weight: 600; }

@media (max-width: 700px) {
  .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  table { font-size: 0.72rem; }
  body  { padding: 16px; }
}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────── -->
<div class="v-header">
  <div>
    <div class="v-wordmark">VERTEX</div>
    <div class="v-tagline">Visual Exposure &amp; Risk Topology EXaminer</div>
    <div class="v-meta">
      Generated&nbsp;<span>{{ timestamp }}</span>&nbsp;&nbsp;|&nbsp;&nbsp;
      Host&nbsp;<span>{{ hostname }}</span>&nbsp;&nbsp;|&nbsp;&nbsp;
      Context&nbsp;<span>{{ current_user }}</span>
      <span class="badge b-{% if is_elevated %}orange{% else %}gray{% endif %}" style="margin-left:8px;">
        {{ "Elevated" if is_elevated else "Standard" }}
      </span>
    </div>
  </div>
  <div class="v-badge-auth">Authorized Assessment Only</div>
</div>

<!-- ── KPI Grid ────────────────────────────────────────────── -->
<div class="kpi-grid">
  <div class="kpi-card"><div class="kpi-value kv-blue">{{ total_hosts }}</div><div class="kpi-label">Hosts Discovered</div></div>
  <div class="kpi-card"><div class="kpi-value kv-red">{{ critical_hosts }}</div><div class="kpi-label">Critical Risk</div></div>
  <div class="kpi-card"><div class="kpi-value kv-orange">{{ high_hosts }}</div><div class="kpi-label">High Risk</div></div>
  <div class="kpi-card"><div class="kpi-value kv-green">{{ safe_hosts }}</div><div class="kpi-label">No Findings</div></div>
  <div class="kpi-card"><div class="kpi-value kv-blue">{{ total_services }}</div><div class="kpi-label">Services Found</div></div>
  <div class="kpi-card"><div class="kpi-value kv-orange">{{ exposed_shares }}</div><div class="kpi-label">Exposed Shares</div></div>
  <div class="kpi-card"><div class="kpi-value kv-muted">{{ graph_nodes }}</div><div class="kpi-label">Graph Nodes</div></div>
  <div class="kpi-card"><div class="kpi-value kv-muted">{{ graph_edges }}</div><div class="kpi-label">Graph Edges</div></div>
</div>

<!-- ── Pipeline Status ─────────────────────────────────────── -->
<div class="section">
  <div class="section-title">Assessment Pipeline</div>
  <div class="pipeline-grid">
    {% for stage in stages %}
    <div class="stage-card stage-{{ stage.status|lower }}">
      <div class="stage-name">
        {% if stage.status == "OK" %}✔{% elif stage.status == "PARTIAL" %}⚠{% elif stage.status == "FAILED" %}✘{% else %}—{% endif %}
        &nbsp;{{ stage.name }}
      </div>
      <div class="stage-meta">{{ stage.duration }}s &nbsp;·&nbsp; {{ stage.status }}
        {% if stage.errors %}&nbsp;·&nbsp; <span style="color:var(--red);">{{ stage.errors|length }} error(s)</span>{% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
</div>

<!-- ── Host Inventory ──────────────────────────────────────── -->
<div class="section">
  <div class="section-title">Host Inventory ({{ records|length }})</div>
  <div class="search-bar">
    <input type="text" id="host-search" placeholder="Filter hosts by IP, hostname, device, or port …" oninput="filterHosts(this.value)">
  </div>
  <table id="host-table">
    <thead>
      <tr>
        <th>Address</th>
        <th>Device Profile</th>
        <th>Hardware</th>
        <th>Services</th>
        <th>Shares</th>
        <th>Risk Findings</th>
        <th>Scanned</th>
      </tr>
    </thead>
    <tbody>
    {% for r in records %}
    <tr>
      <td>
        <span class="mono">{{ r.ip }}</span><br>
        <span class="muted" style="font-size:0.68rem;">{{ r.hostname }}</span>
      </td>
      <td>
        <span class="badge
          {% if r.device_class == 'camera' %}b-red
          {% elif r.device_class == 'printer' %}b-yellow
          {% elif r.device_class == 'server' %}b-blue
          {% elif r.device_class == 'industrial' %}b-orange
          {% elif r.device_class == 'network_device' %}b-purple
          {% elif r.device_class == 'workstation' %}b-blue
          {% else %}b-gray{% endif %}">
          {{ r.device_label|truncate(28) }}
        </span><br>
        <span class="muted" style="font-size:0.65rem;">{{ r.role }}</span>
      </td>
      <td class="mono muted">{{ r.mac }}<br>{{ r.vendor }}</td>
      <td class="ports">
        {% for s in r.services[:12] %}{{ s.port }}/{{ s.name }} {% endfor %}
        {% if r.services|length > 12 %}
          <span class="muted">+{{ r.services|length - 12 }} more</span>
        {% endif %}
      </td>
      <td>
        {% if r.exposed_shares %}
          {% for sh in r.exposed_shares %}
            <span class="badge b-red">{{ sh }}</span>
          {% endfor %}
        {% elif r.shares %}
          <span class="muted">{{ r.shares|length }} private</span>
        {% else %}
          <span class="muted">—</span>
        {% endif %}
      </td>
      <td>
        {% for f in r.risk_findings %}
          <div class="risk-tag r-{{ f.severity }}">[{{ f.severity }}] {{ f.desc|truncate(55) }}</div>
        {% endfor %}
        {% if not r.risk_findings %}
          <span class="badge b-green">✔ Clean</span>
        {% endif %}
      </td>
      <td class="muted" style="font-size:0.65rem;white-space:nowrap;">{{ r.scan_time }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<!-- ── Identity & Sessions ─────────────────────────────────── -->
<div class="section">
  <div class="section-title">Identity &amp; Session Inventory</div>
  <details open>
    <summary>Local Accounts ({{ identity.local_accounts|length }})</summary>
    <table>
      <thead><tr><th>Username</th><th>Active</th><th>Last Logon</th><th>Privilege</th></tr></thead>
      <tbody>
        {% for u in identity.local_accounts[:30] %}
        <tr>
          <td class="mono">{{ u.username if u is mapping else u }}</td>
          <td>{{ u.active   if u is mapping else '?' }}</td>
          <td class="muted">{{ u.last_logon if u is mapping else '?' }}</td>
          <td>
            {% set uname = u.username if u is mapping else u %}
            {% if uname in identity.admin_members %}
              <span class="badge b-orange">Administrator</span>
            {% else %}
              <span class="badge b-gray">Standard</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </details>
  {% if identity.domain %}
  <p style="margin-top:12px; font-size:0.76rem; color:var(--accent);">
    Domain: <strong>{{ identity.domain }}</strong>
    {% if identity.domain_controllers %}
    &nbsp;·&nbsp; Controllers: {{ identity.domain_controllers|join(', ') }}
    {% endif %}
  </p>
  {% endif %}
</div>

<!-- ── Hardening Findings ──────────────────────────────────── -->
{% if hardening_findings %}
<div class="section">
  <div class="section-title">Hardening Findings ({{ hardening_findings|length }})</div>
  <table>
    <thead><tr><th>Type</th><th>Severity</th><th>Detail</th><th>Target</th></tr></thead>
    <tbody>
      {% for f in hardening_findings %}
      <tr>
        <td class="mono">{{ f.type }}</td>
        <td>
          <span class="badge {% if f.severity == 'CRITICAL' %}b-red{% elif f.severity == 'HIGH' %}b-orange{% else %}b-yellow{% endif %}">
            {{ f.severity }}
          </span>
        </td>
        <td>{{ f.detail }}</td>
        <td class="mono muted">{{ f.get('path', f.get('service', '—')) }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<!-- ── Correlation Graph Summary ───────────────────────────── -->
<div class="section">
  <div class="section-title">Correlation Graph</div>
  <table>
    <thead><tr><th>Entity / Relation Type</th><th>Count</th></tr></thead>
    <tbody>
      {% for k, v in graph_summary.items() %}
      <tr><td class="mono">{{ k }}</td><td><strong>{{ v }}</strong></td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<!-- ── Footer ─────────────────────────────────────────────── -->
<footer>
  <div>
    VERTEX Platform &nbsp;v{{ version }}
    &nbsp;&nbsp;|&nbsp;&nbsp;
    Purple Team Assessment Suite
    &nbsp;&nbsp;|&nbsp;&nbsp;
    Engineered by <span class="author">{{ author }}</span>
  </div>
  <div style="margin-top:4px;">
    {{ timestamp }}
    &nbsp;&nbsp;|&nbsp;&nbsp;
    Authorized use only — do not distribute assessment output
  </div>
</footer>

<script>
function filterHosts(query) {
  const q   = query.toLowerCase();
  const rows = document.querySelectorAll('#host-table tbody tr');
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


class ReportComposer:
    def compose(
        self,
        env_data:  Dict[str, Any],
        topology:  Dict[str, Any],
        records:   List[HostRecord],
        identity:  Dict[str, Any],
        hardening: Dict[str, Any],
        graph:     CorrelationGraph,
        stages:    List[StageResult],
    ) -> Tuple[Path, Path]:

        ts        = SESSION_ID
        html_path = Path(f"vertex_report_{ts}.html")
        json_path = Path(f"vertex_report_{ts}.json")

        schema_doc = {
            "schema_version": "1.0",
            "platform": {
                "name":      PLATFORM_NAME,
                "version":   PLATFORM_VERSION,
                "author":    PLATFORM_AUTHOR,
                "generated": datetime.datetime.now().isoformat(),
            },
            "assessment_context": {
                "hostname":   env_data.get("hostname", ""),
                "user":       env_data.get("current_user", ""),
                "elevated":   env_data.get("is_elevated", False),
                "os":         env_data.get("os", ""),
                "os_release": env_data.get("os_release", ""),
            },
            "pipeline_summary": [
                {
                    "stage":    s.name,
                    "status":   s.status,
                    "duration": s.duration,
                    "errors":   s.errors,
                }
                for s in stages
            ],
            "topology": {
                "subnets":       topology.get("subnets", []),
                "probe_targets": topology.get("probe_targets", 0),
                "live_hosts":    topology.get("live_hosts", []),
            },
            "hosts": [asdict(r) for r in records],
            "identity": identity,
            "hardening": hardening,
            "graph": graph.serialize(),
        }
        json_path.write_text(
            json.dumps(schema_doc, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        critical_hosts = sum(
            1 for r in records
            if any(f["severity"] == "CRITICAL" for f in r.risk_findings)
        )
        high_hosts = sum(
            1 for r in records
            if any(f["severity"] == "HIGH" for f in r.risk_findings)
            and not any(f["severity"] == "CRITICAL" for f in r.risk_findings)
        )
        safe_hosts     = sum(1 for r in records if not r.risk_findings)
        total_services = sum(len(r.services) for r in records)
        exposed_sh     = sum(len(r.exposed_shares) for r in records)

        node_counts: Dict[str, int] = {}
        edge_counts: Dict[str, int] = {}
        for n in graph.nodes:
            node_counts[n.type] = node_counts.get(n.type, 0) + 1
        for e in graph.edges:
            edge_counts[e.relation] = edge_counts.get(e.relation, 0) + 1
        graph_summary = {**node_counts, **edge_counts}

        hardening_findings = (
            hardening.get("findings", []) if isinstance(hardening, dict) else []
        )

        if _JINJA_AVAILABLE:
            html = _JinjaTemplate(_HTML_TEMPLATE).render(
                timestamp         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                hostname          = env_data.get("hostname", ""),
                current_user      = env_data.get("current_user", ""),
                is_elevated       = env_data.get("is_elevated", False),
                version           = PLATFORM_VERSION,
                author            = PLATFORM_AUTHOR,
                total_hosts       = len(records),
                critical_hosts    = critical_hosts,
                high_hosts        = high_hosts,
                safe_hosts        = safe_hosts,
                total_services    = total_services,
                exposed_shares    = exposed_sh,
                graph_nodes       = len(graph.nodes),
                graph_edges       = len(graph.edges),
                stages            = stages,
                records           = records,
                identity          = identity,
                hardening_findings= hardening_findings,
                graph_summary     = graph_summary,
            )
        else:
            rows = "".join(
                f"<tr><td>{r.ip}</td><td>{r.hostname}</td><td>{r.device_label}</td>"
                f"<td>{'; '.join(f['desc'] for f in r.risk_findings)}</td></tr>"
                for r in records
            )
            html = (
                "<html><body style='background:#080c18;color:#dce8f8;font-family:sans-serif;padding:20px'>"
                "<h1>VERTEX Assessment Report</h1>"
                "<table border='1'><tr><th>IP</th><th>Hostname</th><th>Device</th><th>Findings</th></tr>"
                f"{rows}</table></body></html>"
            )

        html_path.write_text(html, encoding="utf-8")

        stage_header("Assessment Summary")

        print(f"\n  {Fore.CYAN}Discovery Statistics{Style.RESET_ALL}")
        print(f"  {'─'*52}")
        print(f"  Hosts discovered   : {Fore.CYAN}{len(records)}{Style.RESET_ALL}")
        print(f"  Services found     : {Fore.CYAN}{total_services}{Style.RESET_ALL}")
        print(f"  Critical risk      : {Fore.RED}{critical_hosts}{Style.RESET_ALL}")
        print(f"  High risk          : {Fore.YELLOW}{high_hosts}{Style.RESET_ALL}")
        print(f"  Clean hosts        : {Fore.GREEN}{safe_hosts}{Style.RESET_ALL}")
        print(f"  Exposed shares     : {Fore.YELLOW}{exposed_sh}{Style.RESET_ALL}")
        print(f"  Graph nodes/edges  : {Fore.CYAN}{len(graph.nodes)}{Style.RESET_ALL} / "
              f"{Fore.CYAN}{len(graph.edges)}{Style.RESET_ALL}")

        if records:
            print(f"\n  {Fore.CYAN}Host Risk Summary{Style.RESET_ALL}")
            print(f"  {'─'*52}")
            _rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            sorted_recs = sorted(
                records,
                key=lambda r: -(max((_rank.get(f["severity"], 0) for f in r.risk_findings), default=0))
            )
            _sev_color = {
                "CRITICAL": Fore.RED, "HIGH": Fore.YELLOW,
                "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN, "INFO": Fore.CYAN,
            }
            for r in sorted_recs:
                worst = RiskEngine.worst_severity(r.risk_findings)
                color = _sev_color.get(worst, Fore.GREEN)
                ports_str = ",".join(str(s.port) for s in r.services[:10])
                if len(r.services) > 10:
                    ports_str += f"+{len(r.services)-10}"
                print(
                    f"  {color}{r.ip:<17}{Style.RESET_ALL}"
                    f"{r.hostname[:28]:<30}"
                    f"{r.device_label[:28]:<30}"
                    f"{color}[{worst}]{Style.RESET_ALL}"
                    f"  {Fore.CYAN}{ports_str}{Style.RESET_ALL}"
                )

        if hardening_findings:
            print(f"\n  {Fore.RED}Hardening Findings ({len(hardening_findings)}){Style.RESET_ALL}")
            print(f"  {'─'*52}")
            for f in hardening_findings[:20]:
                print(f"  {Fore.RED}[{f.get('severity','?')}]{Style.RESET_ALL} "
                      f"{f.get('type','?')} — {f.get('detail','')}")

        print(f"\n  {Fore.CYAN}Pipeline Results{Style.RESET_ALL}")
        print(f"  {'─'*52}")
        for s in stages:
            if s.status == "OK":
                color, icon = Fore.GREEN, "✔"
            elif s.status == "PARTIAL":
                color, icon = Fore.YELLOW, "⚠"
            elif s.status == "FAILED":
                color, icon = Fore.RED, "✘"
            else:
                color, icon = Style.DIM, "—"
            print(f"  {color}[{icon}]{Style.RESET_ALL} {s.name:<28} {s.status:<10} {s.duration}s"
                  + (f"  ({len(s.errors)} error(s))" if s.errors else ""))

        print(f"\n  {Fore.CYAN}Output Files{Style.RESET_ALL}")
        print(f"  {'─'*52}")
        emit_ok(f"HTML Report  : {html_path.resolve()}")
        emit_ok(f"JSON Schema  : {json_path.resolve()}")
        emit_ok(f"Execution Log: {_LOG_PATH.resolve()}")

        return html_path, json_path

class AssessmentEngine:

    def __init__(self, mode: str = "full"):
        self.mode      = mode          # network | endpoint | full
        self.stages:   List[StageResult]  = []
        self.env_data: Dict[str, Any]     = {}
        self.topology: Dict[str, Any]     = {}
        self.records:  List[HostRecord]   = []
        self.identity: Dict[str, Any]     = {}
        self.hardening: Dict[str, Any]    = {}
        self.graph:    CorrelationGraph   = CorrelationGraph()

    def _run_guarded(self, fn, timeout: int = STAGE_TIMEOUT_SEC) -> Any:
        holder: List[Any] = [None]
        exc:    List[Any] = [None]

        def _run():
            try:
                holder[0] = fn()
            except Exception as e:
                exc[0] = e

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        if thread.is_alive():
            raise TimeoutError(f"Stage exceeded {timeout}s limit")
        if exc[0]:
            raise exc[0]
        return holder[0]

    def execute(self):
        self._print_banner()

        run_network  = self.mode in ("network",  "full")
        run_endpoint = self.mode in ("endpoint", "full")

        stage_header("Stage 1 — Environment Probe")
        try:
            result = self._run_guarded(EnvironmentProbe().execute)
            self.env_data = result.data or {}
            self.stages.append(result)
            emit_ok(f"OS       : {self.env_data.get('os')} {self.env_data.get('os_release')}")
            emit_ok(f"Hostname : {self.env_data.get('hostname')}")
            emit_ok(
                f"Context  : {self.env_data.get('current_user')} "
                f"({'Elevated' if self.env_data.get('is_elevated') else 'Standard'})"
            )
            for iface in self.env_data.get("interfaces", []):
                if isinstance(iface, dict) and "ip" in iface:
                    emit_info(f"Interface: {iface.get('adapter','?')} → {iface.get('ip')} / {iface.get('mask','?')}")
        except Exception as e:
            emit_fail(f"EnvironmentProbe failed: {e}")
            self.stages.append(StageResult(name="EnvironmentProbe", status="FAILED", errors=[str(e)]))

        if run_network:
            stage_header("Stage 2 — Topology Mapper")
            try:
                result = self._run_guarded(
                    lambda: TopologyMapper(self.env_data).execute(),
                    timeout=300,
                )
                self.topology = result.data or {}
                self.stages.append(result)
                emit_ok(f"Subnets    : {self.topology.get('subnets')}")
                emit_ok(f"Live hosts : {len(self.topology.get('live_hosts', []))}")
                emit_ok(f"ARP entries: {len(self.topology.get('arp_table', {}))}")
            except Exception as e:
                emit_fail(f"TopologyMapper failed: {e}")
                self.stages.append(StageResult(name="TopologyMapper", status="FAILED", errors=[str(e)]))
                self.topology = {"subnets": [], "live_hosts": [], "arp_table": {}, "dns_map": {}}

        if run_network:
            stage_header("Stage 3 — Service Scanner")
            live_hosts = self.topology.get("live_hosts", [])
            if not live_hosts:
                emit_warn("No live hosts — skipping service scan")
                self.stages.append(StageResult(
                    name="ServiceScanner", status="SKIPPED",
                    errors=["No live hosts available"],
                ))
            else:
                try:
                    result = self._run_guarded(
                        lambda: ServiceScanOrchestrator().execute(
                            live_hosts,
                            self.topology.get("dns_map", {}),
                            self.topology.get("arp_table", {}),
                        ),
                        timeout=600,
                    )
                    self.records = result.data or []
                    self.stages.append(result)
                    emit_ok(f"Hosts scanned    : {len(self.records)}")
                    emit_ok(f"Services detected: {sum(len(r.services) for r in self.records)}")
                except Exception as e:
                    emit_fail(f"ServiceScanner failed: {e}")
                    _logger.error(traceback.format_exc())
                    self.stages.append(StageResult(name="ServiceScanner", status="FAILED", errors=[str(e)]))

        if run_endpoint:
            stage_header("Stage 4 — Identity Auditor")
            try:
                result = self._run_guarded(IdentityAuditor().execute)
                self.identity = result.data or {}
                self.stages.append(result)
                emit_ok(f"Local accounts : {len(self.identity.get('local_accounts', []))}")
                emit_ok(f"Admin members  : {self.identity.get('admin_members', [])}")
                emit_ok(f"Active sessions: {len(self.identity.get('active_sessions', []))}")
                if self.identity.get("domain"):
                    emit_ok(f"Domain         : {self.identity['domain']}")
                if self.identity.get("domain_controllers"):
                    emit_ok(f"Controllers    : {self.identity['domain_controllers']}")
            except Exception as e:
                emit_fail(f"IdentityAuditor failed: {e}")
                self.stages.append(StageResult(name="IdentityAuditor", status="FAILED", errors=[str(e)]))
                self.identity = {
                    "local_accounts": [], "admin_members": [],
                    "active_sessions": [], "domain": None, "domain_controllers": [],
                }

        if run_network and self.records:
            stage_header("Stage 5 — Exposure Analyzer")
            try:
                result = self._run_guarded(
                    lambda: ExposureAnalyzer().execute(self.records),
                    timeout=120,
                )
                self.stages.append(result)
                total_shares   = sum(len(r.shares) for r in self.records)
                exposed_shares = sum(len(r.exposed_shares) for r in self.records)
                emit_ok(f"Total shares    : {total_shares}")
                if exposed_shares:
                    emit_warn(f"Exposed shares  : {exposed_shares}")
                else:
                    emit_ok("No anonymously exposed shares detected")
            except Exception as e:
                emit_fail(f"ExposureAnalyzer failed: {e}")
                self.stages.append(StageResult(name="ExposureAnalyzer", status="FAILED", errors=[str(e)]))

        if run_endpoint:
            stage_header("Stage 6 — Hardening Inspector")
            try:
                result = self._run_guarded(HardeningInspector().execute)
                self.hardening = result.data or {}
                self.stages.append(result)
                findings = self.hardening.get("findings", [])
                if findings:
                    emit_warn(f"{len(findings)} hardening finding(s)")
                    for f in findings[:5]:
                        emit_warn(f"  [{f.get('severity')}] {f.get('type')} — {f.get('detail','')}")
                else:
                    emit_ok("No hardening findings on local host")
            except Exception as e:
                emit_fail(f"HardeningInspector failed: {e}")
                self.stages.append(StageResult(name="HardeningInspector", status="FAILED", errors=[str(e)]))
                self.hardening = {"findings": []}

        stage_header("Stage 7 — Risk Engine")
        try:
            RiskEngine().evaluate(self.records, self.identity)
            flagged = sum(1 for r in self.records if r.risk_findings)
            emit_ok(f"Hosts with findings: {flagged} / {len(self.records)}")
        except Exception as e:
            emit_fail(f"RiskEngine error: {e}")

        stage_header("Stage 8 — Correlation Builder")
        try:
            self.graph = CorrelationBuilder().build(
                self.env_data, self.topology,
                self.records, self.identity, self.hardening,
            )
            self.stages.append(StageResult(
                name="CorrelationBuilder", status="OK", duration=0,
                data={"nodes": len(self.graph.nodes), "edges": len(self.graph.edges)},
            ))
            emit_ok(f"Graph: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")
        except Exception as e:
            emit_fail(f"CorrelationBuilder failed: {e}")
            _logger.error(traceback.format_exc())
            self.stages.append(StageResult(name="CorrelationBuilder", status="FAILED", errors=[str(e)]))

        stage_header("Stage 9 — Report Composer")
        try:
            html_path, json_path = ReportComposer().compose(
                self.env_data, self.topology, self.records,
                self.identity, self.hardening, self.graph, self.stages,
            )
            self.stages.append(StageResult(name="ReportComposer", status="OK"))
            self._open_report(html_path)
        except Exception as e:
            emit_fail(f"ReportComposer failed: {e}")
            _logger.error(traceback.format_exc())

        elapsed = round(time.time() - SESSION_START.timestamp(), 1)
        print(f"\n  {Fore.CYAN}Total assessment time: {elapsed}s{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Assessment complete. Stay secure.{Style.RESET_ALL}\n")

    def _open_report(self, path: Path):
        try:
            if _IS_WINDOWS:
                os.startfile(str(path.resolve()))
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception:
            pass

    def _print_banner(self):
        print(Fore.CYAN + r"""
  ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗
  ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
  ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝
  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗
   ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
    ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""" + Style.RESET_ALL)
        print(f"  {Fore.CYAN}Visual Exposure & Risk Topology EXaminer  v{PLATFORM_VERSION}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Purple Team Assessment Platform{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Engineered by {PLATFORM_AUTHOR}{Style.RESET_ALL}")
        print(f"\n  {Fore.YELLOW}⚠  For authorized assessment use only.{Style.RESET_ALL}")
        print(f"  Mode: {Fore.CYAN}{self.mode.upper()}{Style.RESET_ALL}\n")

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vertex",
        description="VERTEX — Purple Team Assessment Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""
  Execution Modes:
    network   — Topology mapping + service scanning + exposure analysis
    endpoint  — Local identity audit + hardening inspection
    full      — Complete correlated assessment (default)

  Examples:
    python vertex.py
    python vertex.py --mode network
    python vertex.py --mode endpoint
    python vertex.py --mode full

  Engineered by {PLATFORM_AUTHOR}
"""),
    )
    parser.add_argument(
        "--mode",
        choices=["network", "endpoint", "full"],
        default="full",
        help="Assessment scope (default: full)",
    )
    return parser.parse_args()

import textwrap

def executionstart():
    args = _parse_args()
    try:
        AssessmentEngine(mode=args.mode).execute()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}  [!] Assessment interrupted. Partial output may be saved.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception:
        _logger.critical("Unhandled fatal error:\n" + traceback.format_exc())
        print(f"\n{Fore.RED}  [-] Fatal error — see {_LOG_PATH} for details.{Style.RESET_ALL}")
        sys.exit(1)
