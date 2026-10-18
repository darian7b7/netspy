#!/usr/bin/env python3
# =====================================================================
#  NetSpy v1.0 - Live Per-Process Network Monitor & Connection Inspector
#  (Lightweight edition - bounded memory, no per-packet OS lookups)
# =====================================================================
# 
# EDUCATIONAL STRUCTURE:
# This script is organized into logical sections for learning purposes:
# 
# 1. IMPORTS & CONFIGURATION - Dependencies and global settings
# 2. UTILITY FUNCTIONS - Display formatting and helper functions  
# 3. NETWORK CORE - Packet capture, DNS resolution, connection tracking
# 4. BEACON DETECTION - Behavioral analysis for suspicious patterns
# 5. PROCESS ANALYSIS - File classification, risk assessment, LOLBins
# 6. FIREWALL INTEGRATION - Windows firewall rule management
# 7. UI COMPONENTS - Display panels and view builders
# 8. KEYBOARD HANDLING - User input processing
# 9. MAIN ENTRY POINT - Application initialization
#
# NETSPY DATA FLOW (HYBRID ARCHITECTURE):
# BASIC (default):   Windows ETW events (process, network send/recv, DNS) → account_traffic() → stats
#                     no capture driver, and NetSpy itself sends nothing over the network
# ADVANCED (--advanced): Npcap raw frames → handle_frame() → dpkt → packet_queue → consume_packets_loop()
#                     → account_traffic(); TLS ClientHello parse (SNI, ALPN, version); online lookups
# 
# PERFORMANCE OPTIMIZATIONS:
# - dpkt for fast path parsing (IP, TCP, UDP, ports, bytes)
# - Scapy only as a fallback parser when dpkt is unavailable
# - BPF filtering to reduce kernel-to-userspace packet load
# - Every packet counted (exact byte totals; queue overflow shown as "dropped")
#
# VIEWS NAVIGATION:
# Main → Enter → Connection Investigation → Enter → File Investigation
# Main → F → Firewall → I/U → Running Processes/All Apps → Enter → App Details
# ====================================================================
import argparse
import base64
import collections
import ctypes
import functools
import hashlib
import ipaddress
import os
import queue as queue_mod
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    print("Missing dependency: psutil")
    print("Install it with:  pip install psutil")
    sys.exit(1)

try:
    from rich import box
    from rich.console import Console, Group
    from rich.live import Live
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.tree import Tree
except ImportError:
    print("Missing dependency: rich")
    print("Install it with:  pip install rich")
    sys.exit(1)

SCAPY_AVAILABLE = True
SCAPY_IMPORT_ERROR = None
try:
    from scapy.all import ICMP, IP, IPv6, TCP, UDP
except Exception as e:
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(e)

DPKT_AVAILABLE = True
try:
    import dpkt
except Exception:
    DPKT_AVAILABLE = False

try:
    import msvcrt

    HAVE_MSVCRT = True
except ImportError:
    HAVE_MSVCRT = False

IS_WINDOWS = sys.platform.startswith("win")
VERSION = "1.0"

# ============================================================================
# 1. IMPORTS & CONFIGURATION - Dependencies and global settings
# ============================================================================

# ============================================================================
# CENTRALIZED CONFIGURATION CONSTANTS
# ============================================================================

# String constants for process attribution
UNKNOWN_PROCESS_NAME = "System / Unknown"

def unresolved_process_label(proto, port):
    return f"Unknown ({proto} :{port})"

DEVELOPER_MODE = False

# Directory path constants
PROGRAM_FILES = os.environ.get("PROGRAMFILES", "C:\\Program Files")
PROGRAM_FILES_X86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
WINDIR = os.environ.get("WINDIR", "C:\\Windows")
SYSTEM32 = os.path.join(WINDIR, "System32")
SYSWOW64 = os.path.join(WINDIR, "SysWOW64")
DOWNLOADS_DIR = os.path.join(os.environ.get("USERPROFILE", ""), "Downloads")
DEFENDER_DIR = os.path.join(
    os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "Microsoft", "Windows Defender"
)
DEFENDER_PLATFORM_GLOB = os.path.join(
    os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "Microsoft", "Windows Defender", "Platform", "*"
)

# Timeout constants (seconds)
DNS_QUEUE_TIMEOUT = 1.0
PACKET_QUEUE_TIMEOUT = 0.5
PROCESS_LOOKUP_TIMEOUT = 10
SIGNATURE_CHECK_TIMEOUT = 5
FIREWALL_RULE_TIMEOUT = 30
NETSH_TIMEOUT = 60
DEFAULT_OUTBOUND_ACTION_TIMEOUT = 15
POWERSHELL_DEFAULT_TIMEOUT = 30

# Test traffic timeouts
NSLOOKUP_TIMEOUT = 6
PING_TIMEOUT = 8
CURL_TIMEOUT = 10
POWERSHELL_WEB_TIMEOUT = 14
TEST_WEB_TIMEOUT = 8
WINGET_TIMEOUT = 25
WINDOWS_UPDATE_TIMEOUT = 20
W32TM_TIMEOUT = 10

# Test traffic targets
TEST_WEB_URL = "https://example.com"
TEST_NETCONNECTION_TARGET = "1.1.1.1"
TEST_NETCONNECTION_PORT = 443
TEST_PING_COUNT = 2

# Performance and resource limits
DNS_CACHE_MAX = 512
DNS_QUEUE_MAX = 128
PACKET_QUEUE_MAX = 20000
BEACON_MAX_ENTITIES = 300
BEACON_SAMPLES_PER_ENTITY = 50
TIMELINE_MAX_EVENTS = 100
MAX_CONNECTIONS_PER_PROCESS = 100
MAX_TREE_CHILDREN = 8
TEST_LOG_MAX_ENTRIES = 14

# Retention and TTL constants (seconds)
DNS_SUCCESS_TTL = 3600.0
DNS_FAILURE_TTL = 300.0
PROC_INFO_TTL = 5.0
CONN_STATE_TTL = 0.5
LOOPBACK_LISTENER_TTL = 1.5
APP_INVENTORY_TTL = 30.0
FIREWALL_RULES_TTL = 30.0
DEFAULT_ACTION_TTL = 300.0
BEACON_ENTITY_RETENTION = 3600.0
TIMELINE_RETENTION = 300.0
CONNECTION_RETENTION = 120.0
CONN_CACHE_TTL = 12.0
MISS_RETRY_COOLDOWN = 1.0
STATS_CLEANUP_INTERVAL = 5.0

# Packet processing
ENABLE_TLS_PARSING = True
RATE_SAMPLE_INTERVAL = 1.0

# Beacon detection thresholds
BEACON_MIN_SAMPLES = 3
BEACON_MIN_INTERVAL = 2.0
JITTER_HIGHLY_REGULAR = 5
JITTER_REGULAR = 15
JITTER_MIXED = 50

# UI constants
FLASH_WINDOW = 1.5
CONN_REFRESH_INTERVAL = 0.3
ETW_CONN_REFRESH_INTERVAL = 1.5  # ETW already reports connections as they happen
MIN_CONN_ROWS = 6
CONN_PANEL_CHROME = 4
HEADER_PANEL_HEIGHT = 4


# ============================================================================
# END CENTRALIZED CONFIGURATION
# ============================================================================

# TTLCache helper for consistent time-based caching
class TTLCache:
    """A dict-backed cache with per-entry expiry, replacing the ~8
    hand-rolled (dict + Lock + 'now - ts < TTL' check) patterns that
    had accumulated across proc info, ancestry, children, connection
    state, PID names, DNS, loopback listeners, and app inventory."""

    def __init__(self, ttl):
        self.ttl = ttl
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._data.get(key)
            if entry and time.time() - entry[1] < self.ttl:
                return entry[0]
            return None

    def set(self, key, value):
        with self._lock:
            self._data[key] = (value, time.time())

    def get_or_compute(self, key, compute_fn):
        """Return the cached value, or call compute_fn() once, cache it, and return it."""
        cached = self.get(key)
        if cached is not None:
            return cached
        value = compute_fn()
        self.set(key, value)
        return value

    def prune(self):
        """Drop expired entries - get() would ignore them anyway."""
        now = time.time()
        with self._lock:
            for k in [k for k, (_, ts) in self._data.items() if now - ts >= self.ttl]:
                del self._data[k]

# Well-known port numbers for service identification
WELL_KNOWN_PORTS = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-server",
    68: "DHCP-client",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS-name",
    138: "NetBIOS-dgram",
    139: "NetBIOS-session",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-sub",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1900: "SSDP",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}


# Display formatting labels for connection attribution confidence
ATTRIBUTION_LABELS = {
    "exact": "[green]exact[/]",
    "live": "[yellow]live?[/]",
    "port": "[yellow]port~[/]",
    "unknown": "[red]none[/]",
    "n/a": "[dim]-[/]",
    None: "[dim]-[/]",
}


# ============================================================================
# 2. UTILITY FUNCTIONS - Display formatting and helper functions
# ============================================================================

# Network display formatters
def format_attribution(match_type):
    """
    EDUCATIONAL: Connection attribution confidence levels
    - 'exact': Process-PID mapping confirmed via live connection
    - 'live': Connection is currently active (high confidence)
    - 'port': Matched by port number only (medium confidence)
    - 'unknown': Cannot reliably attribute (low confidence)
    """
    return ATTRIBUTION_LABELS.get(match_type or "unknown")


def port_label(port):
    """
    EDUCATIONAL: Port numbers identify specific network services
    Well-known ports: 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS, etc.
    This function adds service names to port numbers for better readability
    """
    if port is None:
        return "-"
    svc = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({svc})" if svc else str(port)


def bytes_fmt(n):
    """Format byte count into human-readable format (B, KB, MB, GB, TB, PB)."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def age_fmt(seconds_ago):
    """Format time difference into human-readable age format (s ago, m ago, h ago)."""
    if seconds_ago is None:
        return "-"
    if seconds_ago < 60:
        return f"{seconds_ago:.1f}s ago"
    if seconds_ago < 3600:
        return f"{seconds_ago / 60:.1f}m ago"
    return f"{seconds_ago / 3600:.1f}h ago"


def duration_fmt(seconds):
    if seconds is None:
        return "-"

    seconds = int(seconds)

    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    parts = []

    if days:
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    if secs and not days:
        parts.append(f"{secs}s")

    return " ".join(parts) if parts else "0s"



def clock_fmt(ts):
    """HH:MM:SS for today, 'YYYY-MM-DD HH:MM:SS' for older timestamps."""
    if not ts:
        return "-"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%H:%M:%S" if dt.date() == datetime.now().date() else "%Y-%m-%d %H:%M:%S")


def is_admin():
    """Check if the script is running with administrator/root privileges."""
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def get_local_ips():
    """Get all local IP addresses from network interfaces."""
    ips = set()
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    addr = a.address.split("%")[0]
                    try:
                        addr = ipaddress.ip_address(addr).compressed  # match inet_ntop form
                    except ValueError:
                        pass
                    ips.add(addr)
    except Exception:
        pass
    ips.add("127.0.0.1")
    ips.add("::1")
    return ips


def is_local_network_ip(ip):
    """Check if an IP address is local (private, loopback, or link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return False


def ip_with_port(ip, port):
    """'ip:port', with IPv6 bracketed ([2001:db8::1]:443) so the port is unambiguous.
    Rich-escaped, since '[fe80::1]' would otherwise be swallowed as a markup tag."""
    host = f"[{ip}]" if ":" in ip and port is not None else ip
    return escape(f"{host}:{port_label(port)}" if port is not None else host)


def format_remote_highlighted(ip, port, sni=None):
    if not ip:
        return "-"
    port_part = f":{port_label(port)}" if port is not None else ""
    if is_blocklisted(ip):
        return f"[bold white on red] BLOCKLISTED [/] {ip_with_port(ip, port)}"
    if is_local_network_ip(ip):
        return f"[bold blue]{ip_with_port(ip, port)}[/]"
    # Prefer SNI over hostname resolution
    display_host = sni if sni else get_hostname(ip)
    if display_host:
        return f"[underline cyan]{display_host}[/]{port_part}"
    return ip_with_port(ip, port)


def format_hostname_status(ip, sni=None):
    if not ip:
        return "-"
    # Prefer SNI if available
    if sni:
        return sni
    host = get_hostname(ip)
    if host:
        return host
    if not _is_resolvable_ip(ip):
        return "[dim]n/a (private/local address)[/]"
    if not ONLINE_LOOKUPS:
        return "[dim]no name seen - not looked up (BASIC mode is private)[/]"
    now = time.time()
    with _dns_cache_lock:
        cached = _dns_cache.get(ip)
    if cached is not None and now < cached[1] and cached[0] is None:
        return "[dim]Unknown[/]"
    return "[dim]resolving...[/]"


def find_ip_relatives(rows, rip, exclude_key):
    if not rip:
        return 0, set()
    count = 0
    procs = set()
    for pname, data in rows.items():
        for ckey in data.get("connections", {}):
            if ckey == exclude_key:
                continue
            if ckey[3] == rip:
                count += 1
                procs.add(pname)
    return count, procs


def classify_bind_address(ip):
    if ip in ("0.0.0.0", "::"):
        return "ALL INTERFACES"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "UNKNOWN"
    if addr.is_loopback:
        return "LOOPBACK"
    if addr.is_link_local:
        return "LINK-LOCAL"
    if addr.is_private:
        return "LAN"
    return "PUBLIC"


def get_interface_name_for_ip(ip):
    if not ip:
        return "-"

    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.address.split("%")[0] == ip:
                    return iface
    except Exception:
        pass

    return "-"


# Translate port numbers into human-readable purposes


def classify_connection(proto, remote_port):
    """
    EDUCATIONAL: Enhanced connection classification with privacy awareness
    Now includes context about what the connection might mean for user privacy
    and system transparency, helping users understand Windows' hidden activities.
    """
    if proto == "UDP":
        if remote_port == 53:
            return "DNS"

        if remote_port == 123:
            return "NTP"

        if remote_port == 1900:
            return "SSDP"

        if remote_port == 5353:
            return "mDNS"

        if remote_port == 5355:
            return "LLMNR"

        if remote_port in (67, 68):
            return "DHCP"

        if remote_port == 443:
            return "QUIC"

    elif proto == "TCP":
        if remote_port == 443:
            return "HTTPS"

        if remote_port == 80:
            return "HTTP"

        if remote_port == 22:
            return "SSH"

        if remote_port == 3389:
            return "RDP"

        if remote_port == 445:
            return "SMB"

    return "-"


# Network scope classification for risk assessment
SCOPE_STYLE = {
    "PUBLIC": "bold red",
    "ALL INTERFACES": "bold yellow",
    "LAN": "bold blue",
    "LINK-LOCAL": "dim cyan",
    "LOOPBACK": "dim green",
    "UNKNOWN": "dim white",
}
SCOPE_SEVERITY = {
    "PUBLIC": 0,
    "ALL INTERFACES": 1,
    "LAN": 2,
    "LINK-LOCAL": 3,
    "LOOPBACK": 4,
    "UNKNOWN": 5,
}


def _proc_connections(p, kind="inet"):
    """Get network connections for a process with compatibility handling."""
    try:
        return p.net_connections(kind=kind)
    except AttributeError:
        return p.connections(kind=kind)


# System transparency and privacy monitoring functions
def detect_telemetry_connections(rows=None):
    """Microsoft traffic per (process, purpose) since NetSpy started - live
    connections plus the history of closed ones. Best-effort: purposes come
    from microsoft_purpose() (site name first, then network owner).
    Returns [{"process", "purpose", "bytes", "connections"}]."""
    found = []
    for pname, data in (rows.items() if rows is not None else compute_rows()):
        for purpose, (nbytes, conns) in microsoft_purposes(data).items():
            found.append({"process": pname, "purpose": purpose, "bytes": nbytes, "connections": conns})
    return found


# ============================================================================
# GLOBAL STATE & CONFIGURATION - Thread-safe data structures
# ============================================================================

# Views that don't need the main process table (fullscreen views)
FULLSCREEN_VIEWS = {
    "domains", "process_domains", "beacons", "timeline", "system_summary",
    "firewall", "firewall_detail", "app_detail", "raw_firewall",
    "help", "learning", "win_tools",
}

# Threading and synchronization objects
stop_event = threading.Event()
stats_lock = threading.Lock()
conn_lock = threading.Lock()
_listening_lock = threading.Lock()
_dns_cache_lock = threading.Lock()
_dns_pending_lock = threading.Lock()


_dns_worker_lock = threading.Lock()

# Global data structures
_listening_snapshot = {"ts": 0.0, "data": []}
stats = {}
conn_table = {}
flow_table = {}
_dns_cache = {}
_dns_pending = set()
_dns_worker_started = False

# Global state variables
packet_queue = queue_mod.Queue(maxsize=PACKET_QUEUE_MAX)
packet_count = 0
packets_dropped = 0  # queue overflow - those bytes are missing from the totals
sort_key = "total"
show_listening = False
show_tree = False
show_explainer = False  # Beginner "what am I looking at?" tips bar (toggle with 'e')
hide_idle = False  # Hide main-table rows idle longer than IDLE_ROW_AGE (toggle with 'o')
IDLE_ROW_AGE = 600.0  # seconds without traffic before a row is dimmed / hideable

# Performance counters
packet_parse_time = 0.0
packet_parse_count = 0

consume_time = 0.0
consume_count = 0

# Sort keys for different views
domain_sort_key = "total_bytes"
process_domain_sort_key = "total_bytes"
beacon_sort_key = "jitter"
firewall_sort_key = "total"
app_inventory_sort_key = "name"

# DNS work queue (cache, locks and flags are defined above with the other
# threading/data state - only the queue itself is unique to this spot)
_dns_queue = queue_mod.Queue(maxsize=DNS_QUEUE_MAX)

# Rate computation state
_rate_state_lock = threading.Lock()
_rate_state_process = {}
_rate_state_conn = {}

# Blocklist configuration
BLOCKLIST_NETWORKS = []
BLOCKLIST_SOURCE = []

# Network and capture state
capture_error = None
# BASIC (default): per-program bytes from Windows' own ETW events, no capture
#   driver, and NetSpy itself makes no network requests at all.
# ADVANCED (--advanced): Npcap packet capture (site names, TLS, ping) plus online
#   lookups (reverse DNS, IP owner/country). LIMITED: not elevated - list only.
CAPTURE_MODE = "basic"
ONLINE_LOOKUPS = False   # reverse DNS + ipwho.is/ip-api.com/rdap.org - ADVANCED only
ETW_COUNT_BYTES = False  # BASIC: ETW send/receive sizes are the byte counter
LOCAL_IPS = set()  # Will be populated in main() to avoid early psutil calls

# ============================================================================
# 3. NETWORK CORE - Packet capture, DNS resolution, connection tracking
# ============================================================================

# Fast path packet parser using dpkt for high-throughput basic field extraction
def parse_packet_fast_dpkt(raw_packet):
    """
    Fast packet parser using dpkt for lightweight field extraction.
    Returns basic fields needed for flow tracking without Scapy overhead.

    Returns tuple or None:
        (src_ip, dst_ip, src_port, dst_port, proto, length, payload) or None
    """
    if not DPKT_AVAILABLE:
        return None

    try:
        # Parse Ethernet frame
        eth = dpkt.ethernet.Ethernet(raw_packet)

        # Skip non-IP packets
        ip = eth.data
        if isinstance(ip, dpkt.ip.IP):
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
        elif isinstance(ip, dpkt.ip6.IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, ip.src)
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip.dst)
        else:
            return None
        length = len(raw_packet)

        # Extract protocol and ports
        if isinstance(ip.data, dpkt.tcp.TCP):
            proto = "TCP"
            tcp = ip.data
            src_port = tcp.sport
            dst_port = tcp.dport
            payload = bytes(tcp.data)
        elif isinstance(ip.data, dpkt.udp.UDP):
            proto = "UDP"
            udp = ip.data
            src_port = udp.sport
            dst_port = udp.dport
            payload = bytes(udp.data)
        elif isinstance(ip.data, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            # ICMPv6 types >= 130 are neighbour discovery / MLD (local plumbing), not pings
            if isinstance(ip.data, dpkt.icmp6.ICMP6) and ip.data.type >= 130:
                return None
            proto = "ICMP"
            src_port = None
            dst_port = None
            payload = b""
        else:
            return None

        return (src_ip, dst_ip, src_port, dst_port, proto, length, payload)

    except Exception:
        return None


# Enhanced connection metadata extraction
def extract_connection_metadata(proto, remote_ip, remote_port, payload):
    """
    EDUCATIONAL: Extract comprehensive metadata from connections for system transparency
    This helps users understand what their system is actually doing, including
    hidden Windows telemetry, background communications, and privacy concerns.

    NOTE: Telemetry detection is BEST-EFFORT ILLUSTRATIVE - Microsoft's actual
    infrastructure is much larger than this simplified detection. This feature is
    for educational transparency, not comprehensive blocking.
    """
    metadata = {
        "service": classify_connection(proto, remote_port),
        "data_classification": classify_data_sensitivity(remote_port, proto),
    }
    return metadata


# Known Microsoft endpoints -> what they are for. Matched as a domain suffix,
# most specific first, so "settings-win.data.microsoft.com" beats "data.microsoft.com"
# beats "microsoft.com". Sources: Microsoft's "Windows connection endpoints"
# documentation for Windows 10/11 plus Edge/Office/Defender endpoint lists.
MS_ENDPOINT_PURPOSES = {
    # Diagnostic data (telemetry) and crash reporting
    "events.data.microsoft.com": "Telemetry",
    "vortex.data.microsoft.com": "Telemetry",
    "vortex-win.data.microsoft.com": "Telemetry",
    "data.microsoft.com": "Telemetry",
    "telemetry.microsoft.com": "Telemetry",
    "aria.microsoft.com": "Telemetry",
    "events.data.msn.com": "Telemetry",
    "browser.events.data.microsoft.com": "Telemetry",
    "mobile.events.data.microsoft.com": "Telemetry",
    "applicationinsights.azure.com": "Telemetry",
    "dc.services.visualstudio.com": "Telemetry",
    "watson.microsoft.com": "Crash reports",
    "watson.telemetry.microsoft.com": "Crash reports",
    "oca.microsoft.com": "Crash reports",
    # Remote configuration / experiments pushed to the PC
    "settings-win.data.microsoft.com": "Remote config",
    "settings.data.microsoft.com": "Remote config",
    "config.edge.skype.com": "Remote config",
    "ecs.office.com": "Remote config",
    # Advertising, Spotlight, suggestions, news feed, web search
    "arc.msn.com": "Ads / Spotlight",
    "ris.api.iris.microsoft.com": "Ads / Spotlight",
    "msn.com": "News / Widgets",
    "api.msn.com": "News / Widgets",
    "tile-service.weather.microsoft.com": "News / Widgets",
    "bing.com": "Bing search",
    "bing.net": "Bing search",
    "activity.windows.com": "Activity history",
    "edge.activity.windows.com": "Activity history",
    # Security cloud lookups (file/URL reputation, sample upload)
    "wdcp.microsoft.com": "Defender cloud",
    "wdcpalt.microsoft.com": "Defender cloud",
    "wd.microsoft.com": "Defender cloud",
    "smartscreen.microsoft.com": "SmartScreen",
    "smartscreen-prod.microsoft.com": "SmartScreen",
    "urs.microsoft.com": "SmartScreen",
    "checkappexec.microsoft.com": "SmartScreen",
    "nav.smartscreen.microsoft.com": "SmartScreen",
    # Updates and Store
    "windowsupdate.com": "Windows Update",
    "update.microsoft.com": "Windows Update",
    "delivery.mp.microsoft.com": "Windows Update",
    "do.dsp.mp.microsoft.com": "Delivery Optimization",
    "mp.microsoft.com": "Store / Update",
    # Account, sync and cloud storage
    "login.live.com": "Microsoft account",
    "login.microsoftonline.com": "Microsoft account",
    "microsoftonline.com": "Microsoft account",
    "msauth.net": "Microsoft account",
    "msftauth.net": "Microsoft account",
    "msidentity.com": "Microsoft account",
    "microsoftonline-p.com": "Microsoft account",
    "account.live.com": "Microsoft account",
    "onedrive.com": "OneDrive",
    "onedrive.live.com": "OneDrive",
    "storage.live.com": "OneDrive",
    "sharepoint.com": "OneDrive / Office",
    "officeapps.live.com": "Office",
    "outlook.live.com": "Outlook",
    "live.com": "Microsoft service",
    # Background plumbing
    "wns.windows.com": "Push notifications",
    "notify.windows.com": "Push notifications",
    "msftconnecttest.com": "Connectivity check",
    "msftncsi.com": "Connectivity check",
    "time.windows.com": "Time sync",
    "edge.microsoft.com": "Edge services",
    "office.com": "Office",
    "cloud.microsoft": "Office",
    "svc.ms": "OneDrive / Office",
    "office.net": "Office",
    "office365.com": "Office",
    "outlook.com": "Outlook",
    "xboxlive.com": "Xbox",
    "xbox.com": "Xbox",
    "skype.com": "Skype / Teams",
    "teams.microsoft.com": "Skype / Teams",
    "windows.com": "Windows service",
    "windows.net": "Azure",
    "azure.com": "Azure",
    "trafficmanager.net": "Azure",
    "copilot.microsoft.com": "Copilot",
    "msedge.net": "Microsoft CDN",
    "azureedge.net": "Microsoft CDN",
    "azurefd.net": "Microsoft CDN",
    "msecnd.net": "Microsoft CDN",
    "s-microsoft.com": "Microsoft CDN",
    "gfx.ms": "Microsoft CDN",
    "microsoft.com": "Microsoft service",
}
_MS_SUFFIXES = sorted(MS_ENDPOINT_PURPOSES, key=len, reverse=True)

# Purposes that are about collecting data on, or advertising to, the user.
MS_TRACKING_PURPOSES = frozenset({
    "Telemetry", "Crash reports", "Ads / Spotlight", "News / Widgets",
    "Bing search", "Activity history",
})
# Order used to pick the single most telling purpose for a process row.
MS_PURPOSE_PRIORITY = [
    "Telemetry", "Crash reports", "Ads / Spotlight", "Activity history",
    "Bing search", "News / Widgets", "Remote config", "Defender cloud", "SmartScreen",
]

# Microsoft's own networks (BGP AS numbers) - catches endpoints with no known
# name. NOTE: AS8075 also hosts Azure customers, so this alone means
# "Microsoft-run network", not necessarily a Microsoft service.
MICROSOFT_ASNS = frozenset({8075, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 12076, 3598})


@functools.lru_cache(maxsize=4096)
def _ms_purpose_for_host(host):
    for suffix in _MS_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return MS_ENDPOINT_PURPOSES[suffix]
    return None


def microsoft_purpose(ip, sni=None):
    """What a connection to Microsoft is for ("Telemetry", "Windows Update", ...),
    "Microsoft network" if only the IP owner is known to be Microsoft, or None.
    Evaluated live: SNI and DNS names often arrive after the first packet."""
    host = sni or get_hostname(ip)
    if host:
        purpose = _ms_purpose_for_host(host.lower().rstrip("."))
        if purpose:
            return purpose
    info = get_ip_info(ip)
    if info and (
        info.get("asn") in MICROSOFT_ASNS
        or any(k in (info.get("org") or "").lower() for k in ("microsoft", "msft"))
    ):
        return "Microsoft network"
    return None


def ms_purpose_markup(purpose):
    if not purpose:
        return "[dim]-[/]"
    if purpose in MS_TRACKING_PURPOSES:
        return f"[bold red]{purpose}[/]"
    if purpose in ("Remote config", "Defender cloud", "SmartScreen"):
        return f"[yellow]{purpose}[/]"
    return f"[cyan]{purpose}[/]"


# Live connections are dropped after CONNECTION_RETENTION seconds; what they
# revealed is folded into data["history"] so the Microsoft column, System
# Summary and domain views keep covering everything since NetSpy started.
#   history = {"ms": {purpose: [bytes, connections]},
#              "domains": {domain: {"sent", "recv", "conns", "ips", "source"}}}
HISTORY_MAX_DOMAINS = 256  # per process
HISTORY_MAX_IPS = 16       # per domain


def _fold_into_history(data, ckey, cdata):
    """Called (under stats_lock) when a connection leaves the live list."""
    rip = ckey[3]
    hist = data.setdefault("history", {"ms": {}, "domains": {}})
    nbytes = cdata["sent"] + cdata["recv"]
    purpose = microsoft_purpose(rip, cdata.get("sni"))
    if purpose:
        h = hist["ms"].setdefault(purpose, [0, 0])
        h[0] += nbytes
        h[1] += 1
    domain, source = get_smart_domain_name(cdata, rip)
    if domain == "Unknown domain":
        return
    d = hist["domains"].get(domain)
    if d is None:
        if len(hist["domains"]) >= HISTORY_MAX_DOMAINS:
            return
        d = hist["domains"][domain] = {"sent": 0, "recv": 0, "conns": 0, "ips": set(), "source": source}
    d["sent"] += cdata["sent"]
    d["recv"] += cdata["recv"]
    d["conns"] += 1
    if len(d["ips"]) < HISTORY_MAX_IPS:
        d["ips"].add(rip)


def _merge_history(target, source):
    """Add source's history into target (both process entries; reader copies)."""
    src_hist = source.get("history")
    if not src_hist:
        return
    hist = target.setdefault("history", {"ms": {}, "domains": {}})
    for purpose, (nbytes, conns) in src_hist["ms"].items():
        h = hist["ms"].setdefault(purpose, [0, 0])
        h[0] += nbytes
        h[1] += conns
    for domain, d in src_hist["domains"].items():
        t = hist["domains"].setdefault(
            domain, {"sent": 0, "recv": 0, "conns": 0, "ips": set(), "source": d["source"]}
        )
        t["sent"] += d["sent"]
        t["recv"] += d["recv"]
        t["conns"] += d["conns"]
        t["ips"] |= d["ips"]


def microsoft_purposes(data):
    """{purpose: [bytes, connections]} for one process since NetSpy started."""
    totals = {p: list(v) for p, v in data.get("history", {}).get("ms", {}).items()}
    for (_proto, _lip, _lport, rip, _rport), cdata in data.get("connections", {}).items():
        purpose = microsoft_purpose(rip, cdata.get("sni"))
        if purpose:
            t = totals.setdefault(purpose, [0, 0])
            t[0] += cdata["sent"] + cdata["recv"]
            t[1] += 1
    return totals


def row_microsoft_summary(data):
    """Most telling Microsoft purpose of a process (since start), plus how
    many other distinct purposes it also has - for the main table column."""
    purposes = set(microsoft_purposes(data))
    if not purposes:
        return "[dim]-[/]"
    top = next((p for p in MS_PURPOSE_PRIORITY if p in purposes), sorted(purposes)[0])
    extra = f" [dim]+{len(purposes) - 1}[/]" if len(purposes) > 1 else ""
    return ms_purpose_markup(top) + extra


def classify_data_sensitivity(port, proto):
    """
    EDUCATIONAL: Classify the sensitivity of data being transmitted
    Helps users understand what type of data might be exposed.
    """
    if port == 443:
        return "Encrypted (HTTPS/TLS) - content hidden"
    if port == 80:
        return "Unencrypted (HTTP) - content visible"
    if port == 53:
        return "DNS queries (your browsing habits)"
    if port == 25:
        return "Email transmission (SMTP)"
    if port == 110 or port == 995:
        return "Email retrieval (POP3)"
    if port == 143 or port == 993:
        return "Email retrieval (IMAP)"
    return "General network data"


# DNS Resolution System
def _is_resolvable_ip(ip):
    """
    EDUCATIONAL: Only public IPs should be resolved to hostnames
    Private IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x) are local
    Loopback (127.0.0.1) is this machine only
    This prevents wasting DNS lookups on internal addresses
    """
    """Check if an IP address can be resolved (not private/local/multicast/reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _dns_worker_loop():
    while not stop_event.is_set():
        try:
            ip = _dns_queue.get(timeout=DNS_QUEUE_TIMEOUT)
        except queue_mod.Empty:
            continue

        try:
            host, _, _ = socket.gethostbyaddr(ip)
            ttl = DNS_SUCCESS_TTL
        except (socket.herror, socket.gaierror, socket.timeout):
            host = None
            ttl = DNS_FAILURE_TTL
        except OSError:
            host = None
            ttl = DNS_FAILURE_TTL

        now = time.time()
        with _dns_cache_lock:
            _dns_cache[ip] = (host, now + ttl)
            if len(_dns_cache) > DNS_CACHE_MAX:
                oldest_ip = min(_dns_cache, key=lambda k: _dns_cache[k][1])
                if oldest_ip != ip:
                    del _dns_cache[oldest_ip]

        with _dns_pending_lock:
            _dns_pending.discard(ip)


def _ensure_dns_worker():
    global _dns_worker_started
    with _dns_worker_lock:
        if not _dns_worker_started:
            threading.Thread(
                target=_dns_worker_loop, daemon=True, name="dns-resolver"
            ).start()
            _dns_worker_started = True


def get_hostname(ip):
    asked = _etw_dns_names.get(ip) if ip else None
    if asked:
        return asked[0]  # what the program looked up - beats reverse DNS
    if not ONLINE_LOOKUPS or not ip or not _is_resolvable_ip(ip):
        return None  # BASIC mode: no reverse-DNS query ever leaves the PC

    now = time.time()
    with _dns_cache_lock:
        cached = _dns_cache.get(ip)
        if cached is not None and now < cached[1]:
            return cached[0]

    with _dns_pending_lock:
        if ip in _dns_pending:
            return None
        _dns_pending.add(ip)

    _ensure_dns_worker()
    try:
        _dns_queue.put_nowait(ip)
    except queue_mod.Full:
        with _dns_pending_lock:
            _dns_pending.discard(ip)
    return None


def dns_cache_snapshot():
    """Get current DNS cache statistics for monitoring."""
    with _dns_cache_lock:
        cache_size = len(_dns_cache)
    with _dns_pending_lock:
        pending = len(_dns_pending)
    return cache_size, pending, _dns_queue.qsize()


# Country lookup for remote IPs (used by the connection inspector only).
# Tries several free, no-key providers in turn so one being down or rate-limited
# doesn't make the lookup fail, and retries after a short delay instead of
# caching a permanent blank.
_geo_cache = {}            # ip -> ({country, asn, org} or None, expiry_ts)
_geo_pending = set()       # ips with a lookup currently in flight
_geo_lock = threading.Lock()
_GEO_SUCCESS_TTL = 86400.0  # cache a found country for a day
_GEO_FAILURE_TTL = 120.0    # retry a failed/blocked lookup after 2 minutes


def _http_json(url, accept=None):
    import json
    import urllib.request

    headers = {"User-Agent": "NetSpy"}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=4) as resp:
        return json.loads(resp.read(65536).decode("utf-8", "replace"))


def _lookup_ip_info(ip):
    """Resolve an IP to {country, asn, org}, trying providers in order until one
    answers. asn/org identify the network owner (e.g. AS8075 = Microsoft)."""
    # 1) ipwho.is - HTTPS, no key, full country name + owning network
    try:
        d = _http_json(f"https://ipwho.is/{ip}?fields=success,country,connection")
        if d.get("country"):
            conn = d.get("connection") or {}
            return {"country": d["country"], "asn": conn.get("asn"), "org": conn.get("org") or conn.get("isp")}
    except Exception:
        pass
    # 2) ip-api.com - no key, full country name (HTTP on the free tier)
    try:
        d = _http_json(f"http://ip-api.com/json/{ip}?fields=status,country,as,org")
        if d.get("country"):
            asn = d.get("as", "").split(" ", 1)[0][2:]  # "AS8075 Microsoft Corporation"
            return {"country": d["country"], "asn": int(asn) if asn.isdigit() else None, "org": d.get("org") or d.get("as")}
    except Exception:
        pass
    # 3) RDAP registry - authoritative and NOT rate-limited (the same source the
    #    old 'w' expand used); returns an ISO country code, e.g. "DE", and the
    #    registered network name (e.g. "MSFT").
    try:
        d = _http_json(f"https://rdap.org/ip/{ip}", accept="application/rdap+json")
        if d.get("country"):
            return {"country": d["country"].upper(), "asn": None, "org": d.get("name")}
    except Exception:
        pass
    return None


_GEO_MAX_INFLIGHT = 8  # cap concurrent lookups - the main table can ask for many IPs at once
_GEO_CACHE_MAX = 2000


def get_ip_info(ip):
    """Non-blocking: return {country, asn, org} for a public IP if known, else
    None and start a one-off background lookup. Uses several providers in turn
    so it effectively never fails, and retries after a short delay rather than
    caching a permanent blank. Private/loopback IPs are skipped, and nothing
    is looked up at all unless ONLINE_LOOKUPS (ADVANCED mode)."""
    if not ONLINE_LOOKUPS or not ip or not _is_resolvable_ip(ip):
        return None
    now = time.time()
    with _geo_lock:
        entry = _geo_cache.get(ip)
        if entry is not None and now < entry[1]:
            return entry[0]
        prev = entry[0] if entry else None
        if ip in _geo_pending or len(_geo_pending) >= _GEO_MAX_INFLIGHT:
            return prev
        if len(_geo_cache) >= _GEO_CACHE_MAX:  # drop expired, then the oldest
            for k in [k for k, (_, exp) in _geo_cache.items() if exp <= now] or [
                min(_geo_cache, key=lambda k: _geo_cache[k][1])
            ]:
                _geo_cache.pop(k, None)
        _geo_pending.add(ip)

    def _worker():
        info = _lookup_ip_info(ip)
        ttl = _GEO_SUCCESS_TTL if info else _GEO_FAILURE_TTL
        with _geo_lock:
            _geo_cache[ip] = (info, time.time() + ttl)
            _geo_pending.discard(ip)

    threading.Thread(target=_worker, daemon=True, name="geo-country").start()
    return prev


def get_ip_country(ip):
    info = get_ip_info(ip)
    return info["country"] if info else None


# TLS/SSL Protocol Analysis
_TLS_VERSION_MAP = {
    b"\x03\x01": "TLS 1.0",
    b"\x03\x02": "TLS 1.1",
    b"\x03\x03": "TLS 1.2",
    b"\x03\x04": "TLS 1.3",
}


def parse_tls_client_hello(payload):
    """
    EDUCATIONAL: TLS ClientHello analysis for encrypted traffic inspection
    - Extracts SNI (Server Name Indication) - which domain the client wants
    - Identifies TLS version (1.0-1.3) for security assessment
    - Extracts ALPN (Application-Layer Protocol Negotiation) like HTTP/2
    This works without decrypting the traffic - only examining the handshake
    """
    try:
        if len(payload) < 9 or payload[0] != 0x16:
            return None
        if payload[5] != 0x01:
            return None
        pos = 9
        pos += 2
        pos += 32
        if pos >= len(payload):
            return None
        pos += 1 + payload[pos]
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cs_len
        if pos >= len(payload):
            return None
        pos += 1 + payload[pos]
        if pos + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        ext_end = min(pos + ext_total_len, len(payload))

        sni, alpn, versions = None, None, []
        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            ext_data = payload[pos + 4 : pos + 4 + ext_len]
            if ext_type == 0x00 and len(ext_data) > 2:
                sn_len = int.from_bytes(ext_data[0:2], "big")
                epos = 2
                while epos < 2 + sn_len and epos + 3 <= len(ext_data):
                    name_type = ext_data[epos]
                    name_len = int.from_bytes(ext_data[epos + 1 : epos + 3], "big")
                    name = ext_data[epos + 3 : epos + 3 + name_len]
                    if name_type == 0:
                        sni = name.decode("ascii", errors="replace")
                        break
                    epos += 3 + name_len
            elif ext_type == 0x10 and len(ext_data) > 2:
                alpn_len = int.from_bytes(ext_data[0:2], "big")
                epos, protos = 2, []
                while epos < 2 + alpn_len and epos < len(ext_data):
                    plen = ext_data[epos]
                    protos.append(
                        ext_data[epos + 1 : epos + 1 + plen].decode(
                            "ascii", errors="replace"
                        )
                    )
                    epos += 1 + plen
                if protos:
                    alpn = protos[0]
            elif ext_type == 0x2B and ext_data:
                lst_len = ext_data[0]
                versions = [ext_data[i : i + 2] for i in range(1, 1 + lst_len, 2)]
            pos += 4 + ext_len

        # We can only see client's advertised versions in ClientHello, not the negotiated version
        # The record layer version is often TLS 1.0 for compatibility, so we prioritize supported_versions extension
        if b"\x03\x04" in versions:
            tls_version = "TLS 1.3"  # Most accurate if supported_versions includes 1.3
        elif versions:
            tls_version = _TLS_VERSION_MAP.get(versions[0], "unknown")
        else:
            # Fallback to record layer version (often TLS 1.0 for backwards compatibility)
            # This is usually not the actual negotiated version
            tls_version = _TLS_VERSION_MAP.get(bytes(payload[1:3]), "unknown")

        if sni is None and alpn is None:
            return None
        return {"sni": sni, "version": tls_version, "alpn": alpn}
    except Exception:
        return None


def compute_rate(store, key, sent, recv, now):
    with _rate_state_lock:
        st = store.get(key)
        if st is None:
            store[key] = {
                "prev_sent": sent,
                "prev_recv": recv,
                "prev_ts": now,
                "last_rate": (0.0, 0.0),
            }
            return 0.0, 0.0
        dt = now - st["prev_ts"]
        if dt >= RATE_SAMPLE_INTERVAL:
            sent_rate = max(0.0, (sent - st["prev_sent"]) / dt)
            recv_rate = max(0.0, (recv - st["prev_recv"]) / dt)
            st["prev_sent"], st["prev_recv"], st["prev_ts"] = sent, recv, now
            st["last_rate"] = (sent_rate, recv_rate)
        return st["last_rate"]


def format_rate_pair(sent_rate, recv_rate):
    """Format transfer rate pair (sent/recv) for display."""
    if sent_rate <= 0 and recv_rate <= 0:
        return "[dim]- idle -[/]"
    return f"[red]^{bytes_fmt(sent_rate)}/s[/] [green]v{bytes_fmt(recv_rate)}/s[/]"


# ============================================================================
# 4. BEACON DETECTION - Behavioral analysis for suspicious patterns
# ============================================================================

# Beacon, jitter and timeline thresholds are defined in the centralized config
# block near the top of the file.

# Beacon detection state
_beacon_lock = threading.Lock()
_beacon_samples = {}
_beacon_last_seen = {}
_beacon_entity_type = {}  # Track whether each entity is 'domain' or 'ip'

# Timeline state
_timeline_lock = threading.Lock()
_timeline_events = collections.deque(maxlen=TIMELINE_MAX_EVENTS)


def record_beacon_sample(remote_ip, ts, sni=None):
    """
    EDUCATIONAL: Beacon detection for identifying Command & Control (C2) traffic
    Malware often communicates with C2 servers at regular intervals (beacons)
    This function records timestamps of connections to detect patterns:
    - Regular intervals (low jitter) = suspicious beaconing behavior
    - Irregular intervals (high jitter) = normal user activity
    """
    # Prefer SNI, then the name the program looked up, over the bare IP
    if not (sni and not sni.startswith("[")):
        asked = _etw_dns_names.get(remote_ip)
        sni = asked[0] if asked else None
    entity = sni if sni else remote_ip

    # Determine entity type: Domain (SNI), PTR (reverse DNS), or IP
    if sni and not sni.startswith("["):
        entity_type = "domain"
    elif remote_ip:
        # Check if the IP resolves to a PTR record
        hostname = get_hostname(remote_ip)
        if hostname and is_ptr_domain(hostname):
            entity = hostname  # Use the PTR name as the entity
            entity_type = "ptr"
        else:
            entity_type = "ip"
    else:
        entity_type = "ip"

    if not entity:
        return
    with _beacon_lock:
        dq = _beacon_samples.get(entity)
        if dq is None:
            if len(_beacon_samples) >= BEACON_MAX_ENTITIES:
                oldest_entity = min(
                    _beacon_last_seen, key=lambda k: _beacon_last_seen[k], default=None
                )
                if oldest_entity is not None:
                    _beacon_samples.pop(oldest_entity, None)
                    _beacon_last_seen.pop(oldest_entity, None)
                    _beacon_entity_type.pop(oldest_entity, None)
            dq = collections.deque(maxlen=BEACON_SAMPLES_PER_ENTITY)
            _beacon_samples[entity] = dq
            _beacon_entity_type[entity] = entity_type
        dq.append(ts)
        _beacon_last_seen[entity] = ts


def _prune_beacons(now):
    with _beacon_lock:
        stale = [
            entity
            for entity, ts in _beacon_last_seen.items()
            if now - ts > BEACON_ENTITY_RETENTION
        ]
        for entity in stale:
            _beacon_samples.pop(entity, None)
            _beacon_last_seen.pop(entity, None)
            _beacon_entity_type.pop(entity, None)


def record_timeline_event(timestamp, process_name, remote_entity, entity_type):
    """Record a network event for the timeline view."""
    with _timeline_lock:
        _timeline_events.append(
            {
                "timestamp": timestamp,
                "process": process_name,
                "remote": remote_entity,
                "type": entity_type,
            }
        )


def prune_timeline(now):
    """Remove old timeline events."""
    with _timeline_lock:
        while (
            _timeline_events
            and now - _timeline_events[0]["timestamp"] > TIMELINE_RETENTION
        ):
            _timeline_events.popleft()


# Calculate how regularly a process reconnects.
# Low jitter = very regular timing.
# High jitter = normal user activity.
def compute_beacon_stats():
    with _beacon_lock:
        snapshot = {entity: sorted(dq) for entity, dq in _beacon_samples.items()}

    results = []
    for entity, timestamps in snapshot.items():
        if len(timestamps) < BEACON_MIN_SAMPLES:
            continue
        from itertools import pairwise

        intervals = [b - a for a, b in pairwise(timestamps)]
        if not intervals:
            continue
        mean = sum(intervals) / len(intervals)
        if mean < BEACON_MIN_INTERVAL:
            continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        stddev = variance**0.5
        jitter_pct = (stddev / mean * 100.0) if mean else 0.0
        results.append(
            {
                "entity": entity,
                "entity_type": _beacon_entity_type.get(entity, "ip"),
                "mean_interval": mean,
                "jitter_pct": jitter_pct,
                "samples": len(timestamps),
                "last_seen": timestamps[-1],
            }
        )

    results.sort(key=lambda r: r["jitter_pct"])
    return results


def jitter_style(jitter_pct):
    if jitter_pct < JITTER_HIGHLY_REGULAR:
        return "bold red"

    if jitter_pct < JITTER_REGULAR:
        return "bold yellow"

    return "dim"


def beacon_assessment(jitter_pct):
    if jitter_pct < JITTER_HIGHLY_REGULAR:
        return "Highly Regular"

    elif jitter_pct < JITTER_REGULAR:
        return "Regular"

    elif jitter_pct < JITTER_MIXED:
        return "Mixed"

    else:
        return "Burst"


# ============================================================================
# 5. PROCESS ANALYSIS - File classification, risk assessment, LOLBins
# ============================================================================

# Executable location classification for security assessment
def classify_exe_location(exe_path):
    """
    EDUCATIONAL: File location analysis for malware detection
    System files (C:\\Windows\\System32) are usually legitimate
    User files (C:\\Program Files) are typically installed applications
    Suspicious locations (Temp, AppData, Downloads) may indicate malware
    This helps prioritize which processes need closer inspection
    """
    """Classify executable location for security assessment."""
    if not exe_path or exe_path.startswith(("unavailable", "(")):
        return "unknown"
    p = exe_path.lower()
    if p.startswith(WINDIR.lower() + "\\") or p.startswith(DEFENDER_DIR.lower() + "\\"):
        return "system"
    # Store/MSIX apps live in Program Files\WindowsApps; their launch aliases in AppData\Local\Microsoft\WindowsApps.
    if "\\windowsapps\\" in p:
        return "store_app"
    if "\\program files\\" in p or "\\program files (x86)\\" in p:
        return "program_files"
    if "\\appdata\\local\\temp\\" in p or "\\temp\\" in p:
        return "temp"
    if "\\appdata\\" in p:
        return "appdata"
    if "\\downloads\\" in p:
        return "downloads"
    return "other"


EXE_LOCATION_BADGE = {
    "system": "[green]Windows[/]",
    "program_files": "[green]Installed[/]",
    "store_app": "[green]Store app[/]",
    "temp": "[bold yellow]! Temp[/]",
    "appdata": "[bold yellow]! AppData[/]",
    "downloads": "[bold yellow]! Downloads[/]",
    "other": "[dim]Other[/]",
    "unknown": "[dim]Unknown[/]",
}
EXE_LOCATION_LABEL = {
    "system": "OK - Windows system directory",
    "program_files": "OK - Program Files",
    "store_app": "OK - Microsoft Store / MSIX app (WindowsApps)",
    "temp": "! Temp folder - unusual location for a long-running app",
    "appdata": "! AppData - common for user-installed/updater-dropped apps, also for malware",
    "downloads": "! Downloads folder - running an exe straight from Downloads",
    "other": "Unclassified location",
    "unknown": "Unknown (path unavailable - needs admin, or process has exited)",
}
SUSPICIOUS_LOCATIONS = {"temp", "appdata", "downloads"}

# Known LOLBins (Living Off The Land Binaries) - legitimate system tools often abused by malware
LOLBINS = {
    "powershell.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msbuild.exe",
    "installutil.exe",
    "reg.exe",
    "schtasks.exe",
}

# Core Windows infrastructure processes used throughout NetSpy.
# Single source of truth for:
#   - Firewall inventory separation
#   - Process classification
#   - System vs user app detection
CORE_WINDOWS_PROCESSES = frozenset({
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "smss.exe",
    "system",
})

SYSTEM_UI_PROCESSES = frozenset({
    "explorer.exe",
    "dwm.exe",
    "cmd.exe",
    "powershell.exe",
    "conhost.exe",
})


def is_system_process(proc_name, exe_location):
    return (
        exe_location == "system"
        or proc_name.lower().split(" (")[0] in CORE_WINDOWS_PROCESSES
    )





def is_lolbin(exe_name):
    """Check if the executable is a known LOLBin (Living Off The Land Binary)."""
    if not exe_name:
        return False
    return exe_name.lower() in LOLBINS


def classify_process_type(exe_name):
    """Classify process type for display in Process → Domain Mapping."""
    if not exe_name:
        return "Unknown"

    exe_lower = exe_name.lower().split(" (")[0]  # drop "svchost.exe (DoSvc)" service suffix

    # LOLBins - these are legitimate system tools that can be abused
    if exe_lower in LOLBINS:
        return "LOLBin"

    # Core Windows infrastructure processes
    if exe_lower in CORE_WINDOWS_PROCESSES:
        return "Service"


    # System processes - Windows system components
    if exe_lower in SYSTEM_UI_PROCESSES:
        return "System"

    # Default to App for everything else - let the discovery system categorize
    return "App"


def assess_file_trust(exe_path, sig_status, publisher, parent_name):
    """Assess file trust based on simple rules without AI or threat scores."""
    risk_factors = []

    # Check if unsigned
    if sig_status and sig_status.upper() not in ("VALID", "SIGNED"):
        risk_factors.append("unsigned")

    # Check suspicious location
    location = classify_exe_location(exe_path)
    if location in SUSPICIOUS_LOCATIONS:
        risk_factors.append(location)

    # Check suspicious parent
    if parent_name:
        parent_lower = parent_name.lower()
        suspicious_parents = [
            "powershell",
            "cmd",
            "mshta",
            "wscript",
            "rundll32",
            "regsvr32",
        ]
        if any(sp in parent_lower for sp in suspicious_parents):
            risk_factors.append("suspicious_parent")

    # One red flag -> worth a look; two or more together -> suspicious
    if not risk_factors:
        return "Looks normal", "green"
    if len(risk_factors) == 1:
        return "Worth investigating", "yellow"
    return "Suspicious", "red"


def assess_parent_risk(parent_name):
    """Assess parent process risk based on common threat patterns."""
    if not parent_name:
        return "Unknown", "dim"

    parent_lower = parent_name.lower()

    # Command-line launchers
    if any(cl in parent_lower for cl in ["powershell", "cmd"]):
        return "Command-line launcher", "yellow"

    # Office applications
    if any(
        office in parent_lower
        for office in ["winword", "excel", "powerpnt", "msaccess"]
    ):
        return "Office-launched process", "green"

    # Browsers
    if any(
        browser in parent_lower for browser in ["chrome", "firefox", "msedge", "opera"]
    ):
        return "Browser-launched process", "green"

    # System processes
    if any(sys in parent_lower for sys in ["svchost", "services", "explorer"]):
        return "System-launched process", "green"

    # LOLBins
    if parent_lower in LOLBINS:
        return "LOLBin launcher", "yellow"

    return "Standard parent", "dim"


# Security: IP Blocklist Management
def load_blocklist(path):
    """
    EDUCATIONAL: IP blocklists for known malicious infrastructure
    Blocklists contain IPs/CIDRs of known C2 servers, botnets, malware servers
    Loading these allows immediate identification of connections to bad actors
    Format: One IP/CIDR per line, # for comments
    """
    loaded, skipped = 0, 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    BLOCKLIST_NETWORKS.append(net)
                    BLOCKLIST_SOURCE.append(str(net))
                    loaded += 1
                except ValueError:
                    skipped += 1
    except OSError as e:
        return 0, 0, str(e)
    return loaded, skipped, None


def is_blocklisted(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in BLOCKLIST_NETWORKS)


def blocklist_match(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    for net, src in zip(BLOCKLIST_NETWORKS, BLOCKLIST_SOURCE):
        if addr in net:
            return src
    return None


# ==========================================================
# UI SCREENS
#
# Main = Process overview
# V    = Connection Investigation
# I    = File Investigation
# D    = Domain Intelligence
# P    = Process -> Domain Mapping
# B    = Beacon Watch
# F    = Firewall
# S    = System Summary
#
# Most UI navigation simply changes view_mode.
# ==========================================================
view_mode = "main"
selected_process = None
selected_connection_key = None
hide_main_in_detail = False
conn_sort_key = "order"
selected_connection_index_hint = 0
last_rendered_order = []
last_rendered_connections = []

# Scroll offsets for all views
main_scroll_offset = 0
detail_scroll_offset = 0
inspector_scroll_offset = 0
beacon_scroll_offset = 0
file_investigation_scroll_offset = 0
domain_scroll_offset = 0
process_domain_scroll_offset = 0
timeline_scroll_offset = 0
system_summary_scroll_offset = 0
help_scroll_offset = 0
learning_scroll_offset = 0
firewall_scroll_offset = 0
raw_firewall_scroll_offset = 0
app_inventory_scroll_offset = 0
app_detail_scroll_offset = 0

# Firewall rule state
_firewall_rules_cache = {"ts": 0.0, "data": []}
_firewall_rules_lock = threading.Lock()
_firewall_refreshing = False  # True while a background rule refresh is in flight
selected_firewall_rule = None
selected_raw_firewall_rule = None
firewall_detail_scroll_offset = 0
firewall_view_mode = "active"  # "active" for active processes, "inventory" for running processes, "all_apps" for all user apps
selected_app_inventory_item = None

# ============================================================================
# 6. FIREWALL INTEGRATION - Windows firewall rule management
# ============================================================================

# Firewall view configuration
# Which category of app the Running Processes / All User Apps lists
# show. Scanning System32/SysWOW64 pulls in hundreds of core Windows
# utilities alongside the handful of user-installed apps someone
# actually wants to review - "user" (the default) hides anything
# classify_exe_location tagged "system", so the list stays focused on
# what a person would plausibly want to Allow/Block by hand. Cycled
# with 'N' while either of those two views is open.
APP_FILTER_MODES = ["user", "system", "all"]
app_filter_mode = "user"

# (FLASH_WINDOW, CONNECTION_RETENTION, MAX_CONNECTIONS_PER_PROCESS,
# STATS_CLEANUP_INTERVAL, MAX_TREE_CHILDREN, MIN_CONN_ROWS, CONN_PANEL_CHROME,
# HEADER_PANEL_HEIGHT, CONN_REFRESH_INTERVAL, CONN_CACHE_TTL and
# MISS_RETRY_COOLDOWN all come from the centralized config block near the top.)
_last_stats_cleanup = 0.0

TYPE_MAP = {socket.SOCK_STREAM: "TCP", socket.SOCK_DGRAM: "UDP"}

_miss_attempt_lock = threading.Lock()
_recent_miss_attempts = {}


# Connection tracking and packet processing
def refresh_connections_loop():
    global _last_stats_cleanup
    while not stop_event.is_set():
        now = time.time()
        seen_conn = {}
        seen_flow = {}
        listening_snapshot = []
        names = {}  # pid -> row name for this pass (hundreds of sockets, few PIDs)
        _refresh_service_map()
        _refresh_local_ips(now)
        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.laddr:
                    continue
                proto = TYPE_MAP.get(c.type)
                if proto is None:
                    continue
                pid = c.pid
                if pid:
                    pname = names.get(pid)
                    if pname is None:
                        try:
                            pname = process_label(pid, psutil.Process(pid).name())
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pname = f"PID {pid}"
                        names[pid] = pname
                else:
                    pname = UNKNOWN_PROCESS_NAME

                seen_conn[(proto, c.laddr.port)] = (pid, pname)
                if c.raddr:
                    seen_flow[
                        (proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                    ] = (pid, pname)

                if c.status == psutil.CONN_LISTEN:
                    listening_snapshot.append(
                        {
                            "pid": pid,
                            "name": pname,
                            "proto": proto,
                            "ip": c.laddr.ip,
                            "port": c.laddr.port,
                        }
                    )
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception:
            pass

        with conn_lock:
            for key, (pid, pname) in seen_conn.items():
                conn_table[key] = (pid, pname, now)
            for key, (pid, pname) in seen_flow.items():
                flow_table[key] = (pid, pname, now)
            for table in (conn_table, flow_table):
                stale = [k for k, v in table.items() if now - v[2] > CONN_CACHE_TTL]
                for k in stale:
                    del table[k]

        for (proto, port), (pid, pname) in seen_conn.items():
            if pid and unresolved_process_label(proto, port) in stats:
                _rehome_unresolved(proto, port, pid, pname, now)

        with _listening_lock:
            _listening_snapshot["ts"] = now
            _listening_snapshot["data"] = listening_snapshot

        with _miss_attempt_lock:
            stale_misses = [k for k, t in _recent_miss_attempts.items() if now - t > 60]
            for k in stale_misses:
                del _recent_miss_attempts[k]

        if now - _last_stats_cleanup >= STATS_CLEANUP_INTERVAL:
            _last_stats_cleanup = now
            _prune_stats(now)

        stop_event.wait(ETW_CONN_REFRESH_INTERVAL if etw_status.startswith("on") else CONN_REFRESH_INTERVAL)


def _prune_stats(now):
    for cache in (_proc_info_cache, _conn_state_cache, _loopback_listener_cache):
        cache.prune()
    with stats_lock:
        for data in stats.values():
            conns = data.get("connections")
            if not conns:
                continue

            stale_keys = [
                k
                for k, v in conns.items()
                if now - v["last_seen"] > CONNECTION_RETENTION
                and k != selected_connection_key
            ]
            for k in stale_keys:
                _fold_into_history(data, k, conns.pop(k))

            overflow = len(conns) - MAX_CONNECTIONS_PER_PROCESS
            if overflow > 0:
                oldest_first = sorted(conns.items(), key=lambda kv: kv[1]["last_seen"])
                dropped = 0
                for k, _ in oldest_first:
                    if dropped >= overflow:
                        break
                    if k == selected_connection_key:
                        continue
                    _fold_into_history(data, k, conns.pop(k))
                    dropped += 1

    live_conn_keys = set()
    live_proc_names = set()
    with stats_lock:
        for pname, data in stats.items():
            live_proc_names.add(pname)
            conns2 = data.get("connections")
            if conns2:
                live_conn_keys.update(conns2.keys())

    with _rate_state_lock:
        for k in [k for k in _rate_state_conn if k not in live_conn_keys]:
            del _rate_state_conn[k]
        for k in [k for k in _rate_state_process if k not in live_proc_names]:
            del _rate_state_process[k]

    now2 = time.time()
    with _dns_cache_lock:
        expired = [ip for ip, (_, exp) in _dns_cache.items() if now2 >= exp]
        for ip in expired:
            del _dns_cache[ip]

    _prune_beacons(now2)
    prune_timeline(now2)
    if IS_WINDOWS:
        _etw_prune(now2)


# Windows services per PID. svchost.exe hosts most Windows services
# (Windows Update, Delivery Optimization, DNS Client, telemetry...) under
# one process name, so without this they all collapse into one row.
SERVICE_MAP_TTL = 10.0
SERVICE_MAP_MISS_COOLDOWN = 1.0
_service_map = {}  # pid -> [(service_name, display_name)]
_service_map_ts = 0.0
_service_map_lock = threading.Lock()


def _refresh_service_map(on_miss=False):
    """Re-read service->PID from the Service Control Manager (~20 ms).
    Runs every SERVICE_MAP_TTL, or sooner when an unknown svchost PID shows up."""
    global _service_map, _service_map_ts
    if not IS_WINDOWS:
        return
    if time.time() - _service_map_ts < (SERVICE_MAP_MISS_COOLDOWN if on_miss else SERVICE_MAP_TTL):
        return
    if not _service_map_lock.acquire(blocking=False):
        return
    try:
        _service_map_ts = time.time()
        fresh = {}
        for svc in psutil.win_service_iter():
            try:
                pid = svc.pid()
            except Exception:
                continue
            if pid:
                fresh.setdefault(pid, []).append((svc.name(), svc.display_name()))
        _service_map = fresh
    except Exception:
        pass
    finally:
        _service_map_lock.release()


def get_services_for_pid(pid):
    if not pid:
        return []
    svcs = _service_map.get(pid)
    if svcs is None:
        _refresh_service_map(on_miss=True)
        svcs = _service_map.get(pid)
    return svcs or []


def process_label(pid, name):
    """Row name for a process. svchost.exe gets its hosted service(s) appended -
    'svchost.exe (DoSvc)' - so each service host is its own row with its own bytes."""
    if not pid or name.lower() != "svchost.exe":
        return name
    svcs = get_services_for_pid(pid)
    if not svcs:
        return name
    shown = ", ".join(s[0] for s in svcs[:2])
    return f"{name} ({shown}{', ...' if len(svcs) > 2 else ''})"


def services_line(pid):
    """'Services:   Delivery Optimization (DoSvc), ...' for the detail views, or None."""
    svcs = get_services_for_pid(pid)
    if not svcs:
        return None
    return "Services:    " + escape(", ".join(f"{d} ({n})" for n, d in svcs))


# ============================================================================
# ETW (Event Tracing for Windows) - kernel-level, real-time attribution
# ============================================================================
# Polling the connection table (refresh_connections_loop) misses programs that
# connect and exit between two polls - exactly how Windows' telemetry runners
# (CompatTelRunner, DeviceCensus, ...) behave. ETW reports straight from the OS:
#   Kernel-Process : every process start  -> PID to exe name, even if it lives 50 ms
#   Kernel-Network : every TCP/UDP send/receive with its PID, every adapter, v4+v6
#   DNS-Client     : every name lookup and its answers - also when Windows uses
#                    encrypted DNS (DoH), where the wire shows nothing readable
# Needs admin. Pure ctypes, no extra package. Read-only: it only observes.
ETW_SESSION_NAME = "NetSpy-ETW"
ETW_NAME_TTL = 600.0       # keep exe names of exited processes this long
ETW_DNS_MAX = 8192         # ip -> looked-up name entries kept
ETW_FLOW_REFRESH = 2.0     # re-register an active flow at most this often
etw_status = "off"         # shown in the header
_etw_pid_names = {}        # pid -> (exe name, ts)
_etw_dns_names = {}        # ip -> (name the program asked DNS for, ts)
_etw_flow_seen = {}        # raw flow key -> ts (dedupe: send/recv fire per call)
_etw_dns_seen = {}         # (pid, name) -> ts (dedupe cache-hit lookups in the timeline)
_etw_lock = threading.Lock()

_ETW_KERNEL_PROCESS = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716"
_ETW_KERNEL_NETWORK = "7DD42A49-5329-4832-8DFD-43D979153A88"
_ETW_DNS_CLIENT = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D"

# Kernel-Network event IDs -> (proto, ip version, direction)
_ETW_NET_EVENTS = {
    10: ("TCP", 4, "sent"), 11: ("TCP", 4, "recv"), 12: ("TCP", 4, "sent"), 15: ("TCP", 4, "recv"),
    26: ("TCP", 6, "sent"), 27: ("TCP", 6, "recv"), 28: ("TCP", 6, "sent"), 31: ("TCP", 6, "recv"),
    42: ("UDP", 4, "sent"), 43: ("UDP", 4, "recv"),
    58: ("UDP", 6, "sent"), 59: ("UDP", 6, "recv"),
}

if IS_WINDOWS:
    import struct
    import uuid

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]

        @classmethod
        def of(cls, s):
            return cls.from_buffer_copy(uuid.UUID(s).bytes_le)

    class _WNODE_HEADER(ctypes.Structure):
        _fields_ = [("BufferSize", ctypes.c_ulong), ("ProviderId", ctypes.c_ulong),
                    ("HistoricalContext", ctypes.c_uint64), ("TimeStamp", ctypes.c_int64),
                    ("Guid", _GUID), ("ClientContext", ctypes.c_ulong), ("Flags", ctypes.c_ulong)]

    class _EVENT_TRACE_PROPERTIES(ctypes.Structure):
        _fields_ = [("Wnode", _WNODE_HEADER), ("BufferSize", ctypes.c_ulong),
                    ("MinimumBuffers", ctypes.c_ulong), ("MaximumBuffers", ctypes.c_ulong),
                    ("MaximumFileSize", ctypes.c_ulong), ("LogFileMode", ctypes.c_ulong),
                    ("FlushTimer", ctypes.c_ulong), ("EnableFlags", ctypes.c_ulong),
                    ("AgeLimit", ctypes.c_long), ("NumberOfBuffers", ctypes.c_ulong),
                    ("FreeBuffers", ctypes.c_ulong), ("EventsLost", ctypes.c_ulong),
                    ("BuffersWritten", ctypes.c_ulong), ("LogBuffersLost", ctypes.c_ulong),
                    ("RealTimeBuffersLost", ctypes.c_ulong), ("LoggerThreadId", ctypes.c_void_p),
                    ("LogFileNameOffset", ctypes.c_ulong), ("LoggerNameOffset", ctypes.c_ulong)]

    class _EVENT_TRACE_HEADER(ctypes.Structure):
        _fields_ = [("Size", ctypes.c_ushort), ("FieldTypeFlags", ctypes.c_ushort),
                    ("Version", ctypes.c_ulong), ("ThreadId", ctypes.c_ulong),
                    ("ProcessId", ctypes.c_ulong), ("TimeStamp", ctypes.c_int64),
                    ("Guid", _GUID), ("ProcessorTime", ctypes.c_uint64)]

    class _EVENT_TRACE(ctypes.Structure):
        _fields_ = [("Header", _EVENT_TRACE_HEADER), ("InstanceId", ctypes.c_ulong),
                    ("ParentInstanceId", ctypes.c_ulong), ("ParentGuid", _GUID),
                    ("MofData", ctypes.c_void_p), ("MofLength", ctypes.c_ulong),
                    ("ClientContext", ctypes.c_ulong)]

    class _SYSTEMTIME(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ushort) for n in
                    ("wYear", "wMonth", "wDayOfWeek", "wDay", "wHour", "wMinute", "wSecond", "wMs")]

    class _TIME_ZONE_INFORMATION(ctypes.Structure):
        _fields_ = [("Bias", ctypes.c_long), ("StandardName", ctypes.c_wchar * 32),
                    ("StandardDate", _SYSTEMTIME), ("StandardBias", ctypes.c_long),
                    ("DaylightName", ctypes.c_wchar * 32), ("DaylightDate", _SYSTEMTIME),
                    ("DaylightBias", ctypes.c_long)]

    class _TRACE_LOGFILE_HEADER(ctypes.Structure):
        _fields_ = [("BufferSize", ctypes.c_ulong), ("Version", ctypes.c_ulong),
                    ("ProviderVersion", ctypes.c_ulong), ("NumberOfProcessors", ctypes.c_ulong),
                    ("EndTime", ctypes.c_int64), ("TimerResolution", ctypes.c_ulong),
                    ("MaximumFileSize", ctypes.c_ulong), ("LogFileMode", ctypes.c_ulong),
                    ("BuffersWritten", ctypes.c_ulong), ("LogInstanceGuid", _GUID),
                    ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p),
                    ("TimeZone", _TIME_ZONE_INFORMATION), ("BootTime", ctypes.c_int64),
                    ("PerfFreq", ctypes.c_int64), ("StartTime", ctypes.c_int64),
                    ("ReservedFlags", ctypes.c_ulong), ("BuffersLost", ctypes.c_ulong)]

    class _EVENT_TRACE_LOGFILEW(ctypes.Structure):
        _fields_ = [("LogFileName", ctypes.c_wchar_p), ("LoggerName", ctypes.c_wchar_p),
                    ("CurrentTime", ctypes.c_int64), ("BuffersRead", ctypes.c_ulong),
                    ("ProcessTraceMode", ctypes.c_ulong), ("CurrentEvent", _EVENT_TRACE),
                    ("LogfileHeader", _TRACE_LOGFILE_HEADER), ("BufferCallback", ctypes.c_void_p),
                    ("BufferSize", ctypes.c_ulong), ("Filled", ctypes.c_ulong),
                    ("EventsLost", ctypes.c_ulong), ("EventRecordCallback", ctypes.c_void_p),
                    ("IsKernelTrace", ctypes.c_ulong), ("Context", ctypes.c_void_p)]

    class _EVENT_DESCRIPTOR(ctypes.Structure):
        _fields_ = [("Id", ctypes.c_ushort), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                    ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", ctypes.c_ushort),
                    ("Keyword", ctypes.c_uint64)]

    class _EVENT_HEADER(ctypes.Structure):
        _fields_ = [("Size", ctypes.c_ushort), ("HeaderType", ctypes.c_ushort),
                    ("Flags", ctypes.c_ushort), ("EventProperty", ctypes.c_ushort),
                    ("ThreadId", ctypes.c_ulong), ("ProcessId", ctypes.c_ulong),
                    ("TimeStamp", ctypes.c_int64), ("ProviderId", _GUID),
                    ("EventDescriptor", _EVENT_DESCRIPTOR), ("ProcessorTime", ctypes.c_uint64),
                    ("ActivityId", _GUID)]

    class _EVENT_RECORD(ctypes.Structure):
        _fields_ = [("EventHeader", _EVENT_HEADER), ("ProcessorIndex", ctypes.c_ushort),
                    ("LoggerId", ctypes.c_ushort), ("ExtendedDataCount", ctypes.c_ushort),
                    ("UserDataLength", ctypes.c_ushort), ("ExtendedData", ctypes.c_void_p),
                    ("UserData", ctypes.c_void_p), ("UserContext", ctypes.c_void_p)]

    _ETW_PROVIDER_BYTES = {
        uuid.UUID(_ETW_KERNEL_PROCESS).bytes_le: "process",
        uuid.UUID(_ETW_KERNEL_NETWORK).bytes_le: "network",
        uuid.UUID(_ETW_DNS_CLIENT).bytes_le: "dns",
    }


def _etw_api():
    adv = ctypes.WinDLL("advapi32")
    adv.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_wchar_p, ctypes.c_void_p]
    adv.StartTraceW.restype = ctypes.c_ulong
    adv.ControlTraceW.argtypes = [ctypes.c_uint64, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_ulong]
    adv.ControlTraceW.restype = ctypes.c_ulong
    adv.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(_GUID), ctypes.c_ulong, ctypes.c_ubyte,
                                   ctypes.c_uint64, ctypes.c_uint64, ctypes.c_ulong, ctypes.c_void_p]
    adv.EnableTraceEx2.restype = ctypes.c_ulong
    adv.OpenTraceW.argtypes = [ctypes.POINTER(_EVENT_TRACE_LOGFILEW)]
    adv.OpenTraceW.restype = ctypes.c_uint64
    adv.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
    adv.ProcessTrace.restype = ctypes.c_ulong
    adv.CloseTrace.argtypes = [ctypes.c_uint64]
    adv.CloseTrace.restype = ctypes.c_ulong
    return adv


def _etw_props():
    """EVENT_TRACE_PROPERTIES plus room for the logger/log-file names Windows writes back."""
    base = ctypes.sizeof(_EVENT_TRACE_PROPERTIES)
    buf = ctypes.create_string_buffer(base + 2048)
    props = _EVENT_TRACE_PROPERTIES.from_buffer(buf)
    props.Wnode.BufferSize = len(buf)
    props.Wnode.Flags = 0x00020000      # WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1       # QPC timestamps
    props.LogFileMode = 0x00000100      # EVENT_TRACE_REAL_TIME_MODE
    props.FlushTimer = 1                # deliver events within ~1 s
    props.BufferSize = 64               # KB per buffer
    props.MinimumBuffers = 16
    props.MaximumBuffers = 64
    props.LoggerNameOffset = base
    props.LogFileNameOffset = base + 1024
    return buf, props


def etw_stop():
    """Stop our ETW session (also unblocks the consumer thread). Safe to call twice."""
    if not IS_WINDOWS:
        return
    try:
        buf, props = _etw_props()
        _etw_api().ControlTraceW(0, ETW_SESSION_NAME, ctypes.byref(props), 1)  # EVENT_TRACE_CONTROL_STOP
    except Exception:
        pass


def _etw_wstr(data, off):
    """Read a NUL-terminated UTF-16 string from event data -> (text, next offset)."""
    end = off
    while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
        end += 2
    return data[off:end].decode("utf-16-le", "replace"), end + 2


def _etw_name_for_pid(pid):
    if pid == 4:
        return "System"
    entry = _etw_pid_names.get(pid)
    if entry:
        name = entry[0]
    else:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            # Keep the path too while the process is alive: firewall rules need it after it exits.
            exe = _safe(proc.exe, None)
            _etw_pid_names[pid] = (name, time.time(), exe) if exe else (name, time.time())
        except Exception:
            return f"PID {pid}"
    return process_label(pid, name)


def _etw_ip(raw):
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    ip = socket.inet_ntop(socket.AF_INET6, raw)
    return ip[7:] if ip.startswith("::ffff:") and "." in ip else ip  # dual-stack socket


def _rehome_unresolved(proto, lport, pid, pname, now):
    """Traffic seen before its owner was known sits under 'Unknown (proto :port)'.
    Once ETW or the connection table names the owner, move it - bytes,
    connections and all - to the real process row."""
    label = unresolved_process_label(proto, lport)
    with stats_lock:
        orphan = stats.get(label)
        if orphan is None or now - max(orphan["last_sent"], orphan["last_recv"]) > CONN_CACHE_TTL:
            return  # stale: the port may since have been reused by another program
        del stats[label]
        entry = stats.setdefault(pname, {"pid": pid, "sent": 0, "recv": 0, "last_sent": 0.0,
                                         "last_recv": 0.0, "connections": {}})
        entry["pid"] = pid or entry["pid"]
        entry["sent"] += orphan["sent"]
        entry["recv"] += orphan["recv"]
        entry["last_sent"] = max(entry["last_sent"], orphan["last_sent"])
        entry["last_recv"] = max(entry["last_recv"], orphan["last_recv"])
        _merge_history(entry, orphan)
        for ckey, cdata in orphan["connections"].items():
            cdata["pid"] = pid
            cdata["match_type"] = "exact"
            existing = entry["connections"].get(ckey)
            if existing is None:
                entry["connections"][ckey] = cdata
            else:
                existing["sent"] += cdata["sent"]
                existing["recv"] += cdata["recv"]
                existing["packets"] += cdata["packets"]
                existing["first_seen"] = min(existing["first_seen"], cdata["first_seen"])
                existing["last_seen"] = max(existing["last_seen"], cdata["last_seen"])


_ETW_DATA_EVENTS = frozenset({10, 11, 26, 27, 42, 43, 58, 59})  # send/recv; connect/accept carry 0 bytes


def _etw_on_network(eid, data, now):
    global packet_count
    kind = _ETW_NET_EVENTS.get(eid)
    if kind is None:
        return
    proto, ver, direction = kind
    alen = 4 if ver == 4 else 16
    if len(data) < 12 + 2 * alen:
        return
    pid, size = struct.unpack_from("<II", data, 0)
    if not pid:
        return
    counting = ETW_COUNT_BYTES and size and eid in _ETW_DATA_EVENTS
    raw_key = (eid & ~1, data[8:12 + 2 * alen])  # same flow for send+recv
    last = _etw_flow_seen.get(raw_key)
    refresh = last is None or now - last >= ETW_FLOW_REFRESH
    if not (counting or refresh):
        return

    daddr = _etw_ip(data[8:8 + alen])
    saddr = _etw_ip(data[8 + alen:8 + 2 * alen])
    dport, sport = struct.unpack_from(">HH", data, 8 + 2 * alen)
    # Kernel-Network reports from the connection's point of view: saddr is
    # local. Guard anyway in case a build flips it for receives.
    if daddr in LOCAL_IPS and saddr not in LOCAL_IPS:
        saddr, daddr, sport, dport = daddr, saddr, dport, sport
    pname = _etw_name_for_pid(pid)

    if counting and not (daddr.startswith("127.") or daddr == "::1"):  # loopback = local IPC
        packet_count += 1
        account_traffic(direction, proto, saddr, sport, daddr, dport, size, None, pid, pname, "exact")
    if refresh:
        _etw_flow_seen[raw_key] = now
        fkey = (proto, saddr, sport, daddr, dport)
        with conn_lock:
            flow_table[fkey] = (pid, pname, now)
            conn_table[(proto, sport)] = (pid, pname, now)
        with stats_lock:  # packets can beat this report by ~1 s: confirm their earlier guess
            entry = stats.get(pname)
            cd = entry["connections"].get(fkey) if entry else None
            if cd is not None and cd.get("pid") == pid:
                cd["match_type"] = "exact"
        if unresolved_process_label(proto, sport) in stats:
            _rehome_unresolved(proto, sport, pid, pname, now)


def _etw_on_process(eid, data, now):
    if eid != 1 or len(data) < 24:  # ProcessStart
        return
    pid = struct.unpack_from("<I", data, 0)[0]
    # The fields before ImageName differ between manifest versions (Win11 adds
    # sequence numbers), so locate the NT path itself: "\Device\...\x.exe".
    off = data.find(_NT_DEVICE_PREFIX)
    while off > 0 and off % 2:
        off = data.find(_NT_DEVICE_PREFIX, off + 1)
    if off > 0:
        image, _ = _etw_wstr(data, off)
        _etw_pid_names[pid] = (image.rsplit("\\", 1)[-1], now, _nt_to_dos(image))


_NT_DEVICE_PREFIX = "\\Device\\".encode("utf-16-le")
_nt_drive_map = None


def _nt_to_dos(path):
    """\\Device\\HarddiskVolume3\\x.exe -> C:\\x.exe (drive map built once)."""
    global _nt_drive_map
    if _nt_drive_map is None:
        _nt_drive_map = {}
        buf = ctypes.create_unicode_buffer(1024)
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if ctypes.windll.kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
                _nt_drive_map[buf.value.lower()] = f"{letter}:"
    low = path.lower()
    for dev, drive in _nt_drive_map.items():
        if low.startswith(dev + "\\"):
            return drive + path[len(dev):]
    return path


def _etw_on_dns(eid, header_pid, data, now):
    if eid != 3008 or not data:  # query completed
        return
    qname, off = _etw_wstr(data, 0)
    if len(data) < off + 16:
        return
    status = struct.unpack_from("<I", data, off + 12)[0]
    results, _ = _etw_wstr(data, off + 16)
    if status != 0 or not qname:
        return
    qname = qname.lower().rstrip(".")
    for token in results.split(";"):
        token = token.strip()
        if not token or token.startswith("type:"):
            continue
        if token.startswith("::ffff:"):
            token = token[7:]
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        _etw_dns_names[token] = (qname, now)
    if len(_etw_dns_names) > ETW_DNS_MAX:
        for ip, _ in sorted(_etw_dns_names.items(), key=lambda kv: kv[1][1])[: ETW_DNS_MAX // 4]:
            _etw_dns_names.pop(ip, None)

    key = (header_pid, qname)
    if header_pid != os.getpid() and now - _etw_dns_seen.get(key, 0) > 60:  # skip NetSpy's own lookups
        _etw_dns_seen[key] = now
        who = _etw_name_for_pid(header_pid) if header_pid else UNKNOWN_PROCESS_NAME
        record_timeline_event(now, who, qname, "dns")


def _etw_on_event(rec_ptr):
    try:
        rec = rec_ptr.contents
        hdr = rec.EventHeader
        source = _ETW_PROVIDER_BYTES.get(bytes(hdr.ProviderId))
        if source is None:
            return
        data = ctypes.string_at(rec.UserData, rec.UserDataLength) if rec.UserDataLength else b""
        now = time.time()
        eid = hdr.EventDescriptor.Id
        if source == "network":
            _etw_on_network(eid, data, now)
        elif source == "process":
            _etw_on_process(eid, data, now)
        else:
            _etw_on_dns(eid, hdr.ProcessId, data, now)
    except Exception:
        pass  # never let an exception escape into the native callback


if IS_WINDOWS:
    _ETW_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EVENT_RECORD))(_etw_on_event)


def _etw_prune(now):
    """Called from the stats cleanup: bound the ETW lookup tables."""
    with _etw_lock:
        for table, ttl in ((_etw_flow_seen, 30.0), (_etw_dns_seen, 120.0), (_etw_pid_names, ETW_NAME_TTL)):
            for k in [k for k, v in list(table.items()) if now - (v[1] if isinstance(v, tuple) else v) > ttl]:
                table.pop(k, None)


def _etw_thread(adv):
    global etw_status
    try:
        logfile = _EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = ETW_SESSION_NAME
        logfile.ProcessTraceMode = 0x00000100 | 0x10000000  # REAL_TIME | EVENT_RECORD
        logfile.EventRecordCallback = ctypes.cast(_ETW_CALLBACK, ctypes.c_void_p).value
        handle = adv.OpenTraceW(ctypes.byref(logfile))
        if handle == 0xFFFFFFFFFFFFFFFF:
            etw_status = f"off: OpenTrace error {ctypes.GetLastError()}"
            return
        handles = (ctypes.c_uint64 * 1)(handle)
        adv.ProcessTrace(handles, 1, None, None)  # blocks until etw_stop()
        adv.CloseTrace(handle)
    except Exception as e:
        etw_status = f"off: {e}"


def start_etw():
    """Start the ETW session and its consumer thread. Returns True if running."""
    global etw_status
    if not IS_WINDOWS:
        etw_status = "off: Windows only"
        return False
    if not is_admin():
        etw_status = "off: needs admin"
        return False
    try:
        adv = _etw_api()
        buf, props = _etw_props()
        handle = ctypes.c_uint64()
        rc = adv.StartTraceW(ctypes.byref(handle), ETW_SESSION_NAME, ctypes.byref(props))
        if rc == 183:  # ERROR_ALREADY_EXISTS - left behind by a run that was killed
            etw_stop()
            buf, props = _etw_props()
            rc = adv.StartTraceW(ctypes.byref(handle), ETW_SESSION_NAME, ctypes.byref(props))
        if rc != 0:
            etw_status = f"off: StartTrace error {rc}"
            return False
        enabled = []
        for guid, keywords, label in (
            (_ETW_KERNEL_PROCESS, 0x10, "process"),           # WINEVENT_KEYWORD_PROCESS
            (_ETW_KERNEL_NETWORK, 0x30, "network"),           # IPV4 | IPV6
            (_ETW_DNS_CLIENT, 0xFFFFFFFFFFFFFFFF, "DNS"),
        ):
            g = _GUID.of(guid)
            if adv.EnableTraceEx2(handle.value, ctypes.byref(g), 1, 5, keywords, 0, 0, None) == 0:
                enabled.append(label)
        if not enabled:
            etw_stop()
            etw_status = "off: no provider could be enabled"
            return False
        import atexit
        atexit.register(etw_stop)
        threading.Thread(target=_etw_thread, args=(adv,), daemon=True, name="etw").start()
        etw_status = "on (" + " + ".join(enabled) + ")"
        return True
    except Exception as e:
        etw_status = f"off: {e}"
        return False


# ============================================================================
# CAPTURE ADAPTERS - one sniffer per connected adapter
# ============================================================================
capture_auto = False       # True: follow every connected adapter (no --iface given)
_capture_ifaces = set()    # adapter names with a running sniffer
_capture_ifaces_lock = threading.Lock()
LOCAL_IP_REFRESH_INTERVAL = 5.0
_last_local_ip_refresh = 0.0


def capturable_ifaces():
    """Adapters with a routable address: Wi-Fi/Ethernet, VPN tunnels, VM networks.
    Skips loopback and adapters that only have link-local (169.254/fe80) addresses."""
    from scapy.all import conf

    names = []
    for iface in list(conf.ifaces.values()):
        for ip in list(iface.ips.get(4, [])) + list(iface.ips.get(6, [])):
            try:
                addr = ipaddress.ip_address(ip.split("%")[0])
            except ValueError:
                continue
            if not (addr.is_loopback or addr.is_link_local or addr.is_unspecified):
                names.append(iface.name)
                break
    return names


def ensure_capture_threads(reload=False):
    """Start a sniffer on every capturable adapter that doesn't have one yet."""
    try:
        if reload:
            from scapy.all import conf
            conf.ifaces.reload()
        for name in capturable_ifaces():
            with _capture_ifaces_lock:
                if name in _capture_ifaces:
                    continue
                _capture_ifaces.add(name)
            threading.Thread(target=sniff_thread_func, args=(name,), daemon=True,
                             name=f"sniff-{name}").start()
    except Exception as e:
        global capture_error
        capture_error = str(e)


def _refresh_local_ips(now):
    """Pick up IP changes (DHCP renew, VPN connect, IPv6 temporary addresses) -
    packets to an address not in LOCAL_IPS are dropped as 'not ours'."""
    global LOCAL_IPS, _last_local_ip_refresh
    if now - _last_local_ip_refresh < LOCAL_IP_REFRESH_INTERVAL:
        return
    _last_local_ip_refresh = now
    fresh = get_local_ips()
    if fresh != LOCAL_IPS:
        changed = bool(LOCAL_IPS)
        LOCAL_IPS = fresh
        if capture_auto and changed:
            ensure_capture_threads(reload=True)


def lookup_port_live(proto, port):
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr or c.laddr.port != port:
                continue
            if TYPE_MAP.get(c.type) != proto:
                continue
            pid = c.pid
            if pid:
                try:
                    return pid, process_label(pid, psutil.Process(pid).name())
                except Exception:
                    return pid, f"PID {pid}"
            return None, UNKNOWN_PROCESS_NAME
    except Exception:
        pass
    return None, None


# ==========================================================
# PACKET CAPTURE ENTRYPOINT
#
# Scapy calls this for every captured packet.
#
# Responsibilities:
#   - Identify protocol
#   - Identify direction
#   - Extract connection information
#   - Extract TLS metadata when available
#   - Push a lightweight event into packet_queue
#
# Heavy work is intentionally deferred to
# consume_packets_loop().
# ==========================================================
def _parse_with_scapy(pkt):
    """Fallback packet parse using Scapy, for when dpkt is unavailable or fails.
    Returns (src_ip, dst_ip, src_port, dst_port, proto, length, payload) - the
    same shape as parse_packet_fast_dpkt() - or None if the packet isn't one we
    track. Consolidates what used to be two identical inline copies."""
    if not SCAPY_AVAILABLE:
        return None
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        return None
    length = len(pkt)
    payload = b""

    if TCP in pkt:
        proto, src_port, dst_port = "TCP", pkt[TCP].sport, pkt[TCP].dport
        try:
            payload = bytes(pkt[TCP].payload)
        except Exception:
            payload = b""
    elif UDP in pkt:
        proto, src_port, dst_port = "UDP", pkt[UDP].sport, pkt[UDP].dport
    elif ICMP in pkt or (IPv6 in pkt and ip_layer.nh == 58 and pkt[IPv6].payload.type < 130):
        proto, src_port, dst_port = "ICMP", None, None
    else:
        return None

    return (ip_layer.src, ip_layer.dst, src_port, dst_port, proto, length, payload)


def handle_frame(raw, cls=None):
    """One captured frame as raw bytes. dpkt decodes it once; Scapy is only the
    fallback (no dpkt, or a link type dpkt's Ethernet parser doesn't handle,
    e.g. some VPN adapters) - Scapy dissecting every frame was the main
    per-packet CPU cost."""
    global packet_count, packets_dropped, packet_parse_time, packet_parse_count
    start_parse = time.perf_counter()

    parsed = parse_packet_fast_dpkt(raw) if DPKT_AVAILABLE else None
    if not parsed and cls is not None:
        try:
            parsed = _parse_with_scapy(cls(raw))
        except Exception:
            parsed = None
    if not parsed:
        return
    src_ip, dst_ip, src_port, dst_port, proto, length, payload = parsed

    # Determine direction and endpoints
    if src_ip in LOCAL_IPS:
        direction, local_ip, local_port, remote_ip, remote_port = (
            "sent",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        )
    elif dst_ip in LOCAL_IPS:
        direction, local_ip, local_port, remote_ip, remote_port = (
            "recv",
            dst_ip,
            dst_port,
            src_ip,
            src_port,
        )
    else:
        return

    # TLS INSPECTION: parse every outbound ClientHello (0x16 handshake record)
    # straight from the already-extracted payload. There is only one per
    # connection, so every one is read (no sampling).
    tls_info = None
    if (
        ENABLE_TLS_PARSING
        and proto == "TCP"
        and direction == "sent"
        and payload[:1] == b"\x16"
    ):
        tls_info = parse_tls_client_hello(payload)

    # NOTE: privacy/transparency metadata is NOT computed here. It only depends
    # on (proto, remote_ip, remote_port), which never changes for a connection,
    # so the consumer computes it once when the connection is first seen instead
    # of on every packet - keeping this per-packet capture callback cheap.
    packet_count += 1
    try:
        packet_queue.put_nowait(
            (
                direction,
                proto,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                length,
                tls_info,
            )
        )
    except queue_mod.Full:
        packets_dropped += 1
    packet_parse_time += time.perf_counter() - start_parse
    packet_parse_count += 1



CAPTURE_BPF = "(tcp or udp or icmp or icmp6) and not broadcast and not multicast"


def sniff_thread_func(iface):
    """Read raw frames from Npcap (kernel-side BPF filter) and hand the bytes
    straight to handle_frame() - no Scapy dissection on the hot path."""
    global capture_error
    sock = None
    try:
        from scapy.all import conf

        sock = conf.L2listen(iface=iface, filter=CAPTURE_BPF)
        while not stop_event.is_set():
            cls, raw, _ts = sock.recv_raw()  # returns (None, None, None) on its ~0.1 s timeout
            if raw:
                handle_frame(raw, cls)
    except Exception as e:
        capture_error = f"{iface}: {e}" if iface else str(e)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        with _capture_ifaces_lock:
            _capture_ifaces.discard(iface)  # lets ensure_capture_threads retry it


# ==========================================================
# ATTRIBUTION ENGINE
#
# Converts packet events into:
#
#   Process ownership
#   Connection statistics
#   Domain statistics
#   Beacon statistics
#
# Most NetSpy views ultimately depend on
# data produced here.
# ==========================================================


def account_traffic(direction, proto, local_ip, local_port, remote_ip, remote_port,
                    length, tls_info, pid, pname, match_type):
    """Add one packet (ADVANCED) or one ETW send/receive (BASIC) to the stats."""
    now = time.time()
    ckey = (proto, local_ip, local_port, remote_ip, remote_port)

    with stats_lock:
        entry = stats.setdefault(
            pname,
            {
                "pid": pid,
                "sent": 0,
                "recv": 0,
                "last_sent": 0.0,
                "last_recv": 0.0,
                "connections": {},
            },
        )
        if pid:
            entry["pid"] = pid

        entry[direction] += length
        entry[f"last_{direction}"] = now

        conns = entry["connections"]
        cdata = conns.get(ckey)
        if cdata is None:
            # Compute privacy/transparency metadata once per connection here
            # (constant for the life of the connection), not per packet.
            privacy_metadata = extract_connection_metadata(
                proto, remote_ip, remote_port, None
            )
            cdata = {
                "pid": pid,
                "sent": 0,
                "recv": 0,
                "packets": 0,
                "first_seen": now,
                "last_seen": now,
                "match_type": match_type,
                "privacy_metadata": privacy_metadata,  # Add privacy transparency data
            }
            conns[ckey] = cdata
            if len(conns) > MAX_CONNECTIONS_PER_PROCESS:
                candidates = [k for k in conns if k != selected_connection_key]
                if candidates:
                    oldest_key = min(
                        candidates, key=lambda k: conns[k]["last_seen"]
                    )
                    _fold_into_history(entry, oldest_key, conns.pop(oldest_key))
            if _is_resolvable_ip(remote_ip):
                record_beacon_sample(remote_ip, now, cdata.get("sni"))

            # Record timeline event for new connections
            # Determine the remote entity for timeline
            asked = _etw_dns_names.get(remote_ip)
            remote_entity = asked[0] if asked else remote_ip
            entity_type = "domain" if asked else "ip"
            record_timeline_event(now, pname, remote_entity, entity_type)
        else:
            prev_pid = cdata.get("pid")
            if pid:
                cdata["pid"] = pid
            rank = {"exact": 0, "live": 1, "port": 2, "unknown": 3, "n/a": 0}
            if match_type == "exact" and pid and pid == prev_pid:
                # An exact match now names the same process the earlier guess
                # did (the first packets usually beat ETW's report by ~1 s).
                cdata["match_type"] = "exact"
            elif rank.get(match_type or "unknown", 3) > rank.get(
                cdata.get("match_type", "exact") or "exact",
                0,
            ):
                cdata["match_type"] = match_type
        if tls_info:
            if tls_info.get("sni") and not cdata.get("sni"):
                cdata["sni"] = tls_info["sni"]
            if tls_info.get("version") and not cdata.get("tls_version"):
                cdata["tls_version"] = tls_info["version"]
            if tls_info.get("alpn") and not cdata.get("alpn"):
                cdata["alpn"] = tls_info["alpn"]

        cdata[direction] += length
        cdata["packets"] += 1
        cdata["last_seen"] = now


def consume_packets_loop():
    global consume_time, consume_count  
    while not stop_event.is_set():
        start_consume = time.perf_counter()
        try:
            (
                direction,
                proto,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                length,
                tls_info,
            ) = packet_queue.get(timeout=PACKET_QUEUE_TIMEOUT)
        except queue_mod.Empty:
            continue

        if proto == "ICMP":
            pid, pname, match_type = (
                None,
                "ICMP (ping/traceroute - app not identifiable)",
                "n/a",
            )
        else:
            with conn_lock:
                flow_hit = flow_table.get(
                    (proto, local_ip, local_port, remote_ip, remote_port)
                )
                port_hit = conn_table.get((proto, local_port))
            pid, pname, match_type = None, None, None
            if flow_hit:
                pid, pname, match_type = flow_hit[0], flow_hit[1], "exact"
            elif port_hit:
                pid, pname, match_type = port_hit[0], port_hit[1], "port"

            if pname is None:
                now = time.time()
                do_lookup = False
                with _miss_attempt_lock:
                    last_try = _recent_miss_attempts.get((proto, local_port), 0)
                    if now - last_try > MISS_RETRY_COOLDOWN:
                        _recent_miss_attempts[(proto, local_port)] = now
                        do_lookup = True
                if do_lookup:
                    pid, pname = lookup_port_live(proto, local_port)
                    if pname:
                        match_type = "live"
                        with conn_lock:
                            conn_table[(proto, local_port)] = (pid, pname, now)

            if pname is None:
                pname = unresolved_process_label(proto, local_port)
                match_type = "unknown"

        account_traffic(direction, proto, local_ip, local_port, remote_ip, remote_port,
                        length, tls_info, pid, pname, match_type)
        consume_time += time.perf_counter() - start_consume
        consume_count += 1


test_log_lock = threading.Lock()

# Uses centralized constant
test_log = collections.deque(maxlen=TEST_LOG_MAX_ENTRIES)

test_running = False

TEST_DNS_NAMES = [
    "google.com",
    "cloudflare.com",
    "microsoft.com",
    "github.com",
]

TEST_PING_TARGETS = [
    "8.8.8.8",
    TEST_NETCONNECTION_TARGET,
]

TEST_HTTP_URLS = [
    "https://www.msftconnecttest.com/connecttest.txt",
    TEST_WEB_URL,
]


def log_test(msg):
    with test_log_lock:
        test_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def _run(cmd, timeout=PROCESS_LOOKUP_TIMEOUT):
    try:
        subprocess.run(
            cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except Exception:
        return False


def _open(cmd):
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def run_test_traffic_burst():
    log_test("Test burst started - watch the table below as each line runs.")

    for name in TEST_DNS_NAMES:
        log_test(f"nslookup {name}  ->  expect: nslookup.exe (DNS query, UDP 53)")
        _run(["nslookup", name], timeout=NSLOOKUP_TIMEOUT)
        time.sleep(0.4)

    for target in TEST_PING_TARGETS:
        log_test(
            f"ping {target}  ->  expect: 'ICMP (ping/traceroute - app not identifiable)' row"
        )
        _run(
            ["ping", "-n", str(TEST_PING_COUNT), target],
            timeout=PING_TIMEOUT,
        )
        time.sleep(0.4)

    for url in TEST_HTTP_URLS:
        log_test(f"curl {url}  ->  expect: curl.exe")
        _run(["curl.exe", "-s", "-o", "NUL", url], timeout=CURL_TIMEOUT)
        time.sleep(0.4)

    log_test(
    f"PowerShell Invoke-WebRequest -> {TEST_WEB_URL}  expect: powershell.exe"
    )

    _run(
    [
        "powershell",
        "-NoProfile",
        "-Command",
        f"Invoke-WebRequest -UseBasicParsing -Uri '{TEST_WEB_URL}' -TimeoutSec {TEST_WEB_TIMEOUT} | Out-Null",
    ],
    timeout=POWERSHELL_WEB_TIMEOUT,
)
    time.sleep(0.4)

    log_test(
    f"Test-NetConnection to {TEST_NETCONNECTION_TARGET}:{TEST_NETCONNECTION_PORT}  ->  expect: powershell.exe"
    )
    _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Test-NetConnection -ComputerName {TEST_NETCONNECTION_TARGET} -Port {TEST_NETCONNECTION_PORT} | Out-Null",
        ],
        timeout=POWERSHELL_WEB_TIMEOUT,
    )
    time.sleep(0.4)

    log_test(
        "winget source update  ->  expect: winget.exe / WindowsPackageManagerServer.exe"
    )
    _run(["winget", "source", "update", "--accept-source-agreements"], timeout=WINGET_TIMEOUT)
    time.sleep(0.4)

    log_test("Opening Microsoft Store  ->  expect: WinStore.App.exe")
    _open(["cmd", "/c", "start", "", "ms-windows-store://home"])
    time.sleep(1.5)
    log_test(
        "Microsoft Store: downloads & updates page  ->  expect: WinStore.App.exe again"
    )
    _open(["cmd", "/c", "start", "", "ms-windows-store://downloadsandupdates"])
    time.sleep(0.4)

    log_test("Triggering Windows Update detection  ->  expect: svchost.exe (wuauserv)")
    _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "(New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()",
        ],
        timeout=WINDOWS_UPDATE_TIMEOUT,
    )
    time.sleep(0.4)

    log_test(
        "w32tm /resync  ->  expect: svchost.exe (Windows Time), UDP 123 (needs admin, else no-ops)"
    )
    _run(["w32tm", "/resync"], timeout=W32TM_TIMEOUT)
    time.sleep(0.4)

    for label, cmd in [
        (
            "Microsoft Edge",
            ["cmd", "/c", "start", "", "microsoft-edge:https://example.com"],
        ),
        ("Google Chrome", ["cmd", "/c", "start", "", "chrome", "https://example.com"]),
        ("Firefox", ["cmd", "/c", "start", "", "firefox", "https://example.com"]),
    ]:
        log_test(
            f"Opening {label}  ->  expect: matching browser .exe (skipped silently if not installed)"
        )
        _open(cmd)
        time.sleep(0.8)

    log_test(
        "Test burst complete. Some apps (Store, Update, browsers) keep checking in for a minute or two."
    )


def _test_wrapper():
    global test_running
    try:
        run_test_traffic_burst()
    finally:
        test_running = False


def start_test_burst():
    global test_running
    if test_running:
        log_test("Test burst already running - ignoring extra 'g' press.")
        return
    test_running = True
    threading.Thread(target=_test_wrapper, daemon=True).start()


_hash_cache = {}
_hash_lock = threading.Lock()
_signature_cache = {}
_signature_lock = threading.Lock()


def _file_identity(path):
    """A cache key that changes when a file is replaced: (path, size, mtime).
    Returns None if the path is missing or unreadable. Single source of truth
    for every file-keyed cache (hash, signature, ...)."""
    if not path or not os.path.isfile(path):
        return None
    try:
        stat = os.stat(path)
        return (path, stat.st_size, stat.st_mtime)
    except Exception:
        return None


def _cached_by_file(path, cache, lock, compute_fn):
    """Shared caching pattern for anything keyed off a file's current
    identity (size+mtime) - used by both the hash and signature
    lookups so a replaced binary re-computes but an unchanged one
    never re-hits disk or spawns a process on every render frame."""
    key = _file_identity(path)
    if key is None:
        return None
    with lock:
        if key in cache:
            return cache[key]
    value = compute_fn(path)
    with lock:
        cache[key] = value
    return value


def _compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def get_file_sha256(path):
    result = _cached_by_file(path, _hash_cache, _hash_lock, _compute_sha256)
    return result if result is not None else "-"


def _compute_signature(path):
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"$s = Get-AuthenticodeSignature -LiteralPath '{_ps_quote(path)}'; "
                "$s.Status.ToString(); if ($s.SignerCertificate) { $s.SignerCertificate.Subject }",
            ],
            capture_output=True,
            text=True,
            timeout=SIGNATURE_CHECK_TIMEOUT,
            check=False,
        )
        out = result.stdout.strip().splitlines()
        status = out[0].strip() if out else "UNKNOWN"
        cert = out[1] if len(out) > 1 else ""
        publisher = cert.split("CN=", 1)[1].split(",", 1)[0].strip() if "CN=" in cert else "-"
        return (status or "UNKNOWN", publisher)
    except Exception:
        return ("UNKNOWN", "-")


def get_signature_info(path):
    result = _cached_by_file(
        path, _signature_cache, _signature_lock, _compute_signature
    )
    return result if result is not None else ("UNKNOWN", "-")


_forensics_pending = set()
_forensics_lock = threading.Lock()


def request_file_forensics(path):
    """Non-blocking: return (sha256, sig_status, publisher) when BOTH the hash
    and the signature are already cached, otherwise (None, None, None) and kick
    off a one-off background computation. This keeps the render thread from ever
    blocking on a multi-megabyte file hash or a Get-AuthenticodeSignature
    PowerShell call (which previously froze the UI when opening File
    Investigation / App Detail on a given executable for the first time)."""
    key = _file_identity(path)
    if key is None:
        return (None, None, None)

    with _hash_lock:
        hash_cached = _hash_cache.get(key)
    with _signature_lock:
        sig_cached = _signature_cache.get(key)

    if hash_cached is not None and sig_cached is not None:
        return (hash_cached, sig_cached[0], sig_cached[1])

    with _forensics_lock:
        if path not in _forensics_pending:
            _forensics_pending.add(path)

            def _worker(p=path):
                try:
                    get_file_sha256(p)      # populates _hash_cache
                    get_signature_info(p)   # populates _signature_cache
                except Exception:
                    pass
                finally:
                    with _forensics_lock:
                        _forensics_pending.discard(p)

            threading.Thread(
                target=_worker, daemon=True, name="file-forensics"
            ).start()

    return (None, None, None)


# Process info cache (PROC_INFO_TTL from the centralized config block)
_proc_info_cache = TTLCache(PROC_INFO_TTL)
_cpu_procs = {}  # pid -> psutil.Process kept between refreshes so cpu_percent() has a baseline
_known_exe = {}  # pid -> last exe path seen while alive (memory only, bounded)


def _last_known_exe(pid):
    if pid == 4:
        return os.path.join(WINDIR, "System32", "ntoskrnl.exe")
    path = _known_exe.get(pid)
    if path:
        return path
    entry = _etw_pid_names.get(pid)
    return entry[2] if entry and len(entry) > 2 else None

def get_cached_signature_status(path):
    """Non-blocking: returns a signature status ONLY if it's already
    cached from a prior File Investigation visit ('i' key) - never
    spawns PowerShell itself. System Summary uses this instead of
    get_signature_info() so it can never block the render thread
    waiting on a fresh Get-AuthenticodeSignature call, no matter how
    many processes are running.
    Trade-off, stated plainly in the UI: the unsigned count only
    reflects processes you've actually opened File Investigation on
    at least once - it reads low/zero on a fresh session rather than
    silently becoming "complete" on its own. That's intentional;
    correctness here isn't worth reintroducing the per-frame stall."""
    key = _file_identity(path)
    if key is None:
        return None
    with _signature_lock:
        cached = _signature_cache.get(key)
    return cached[0] if cached else None


def file_forensics_or_placeholder(exe_path):
    """(sha256, sig_status, publisher, ready): placeholders while the background
    hash/signature check runs, "-" when there is no file to check."""
    if not (exe_path and os.path.isfile(exe_path)):
        return "-", "-", "-", True
    sha256, sig_status, publisher = request_file_forensics(exe_path)
    if sha256 is None:
        return "computing...", "checking...", "checking...", False
    return sha256, sig_status, publisher, True


def risk_indicator_lines(exe_location, forensics_ready, sig_status, lolbin):
    factors = []
    if exe_location in SUSPICIOUS_LOCATIONS:
        factors.append(f"Suspicious location: {exe_location}")
    if forensics_ready and sig_status and sig_status.upper() not in ("VALID", "SIGNED"):
        factors.append("Unsigned executable")
    if lolbin:
        factors.append("LOLBin (system tool)")
    if not factors:
        return []
    return ["", "[bold yellow]RISK INDICATORS[/]"] + [f"  ⚠ {f}" for f in factors]


def _safe(fn, default=None):
    """Call fn() and return its result, or `default` if it raises. Collapses
    the many identical per-attribute try/except blocks around psutil lookups."""
    try:
        return fn()
    except Exception:
        return default


_EMPTY_PROC_INFO = {
    "exe": "-",
    "parent_name": "-",
    "parent_pid": None,
    "username": "-",
    "create_time": None,
    "threads": 0,
    "memory": 0,
    "cpu": 0.0,
    "cmdline": "",
}


def _fetch_process_info(pid):
    """Fetch process information from psutil - used by TTLCache."""
    info = dict(_EMPTY_PROC_INFO, exe="unavailable")

    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        entry = _etw_pid_names.get(pid)
        info["exe"] = (_last_known_exe(pid) or resolve_exe_by_name(entry[0] if entry else None)
                       or "(process has exited)")
        return info
    except Exception:
        return info

    exe = _safe(p.exe, None) or _last_known_exe(pid) or resolve_exe_by_name(_safe(p.name, None))
    info["exe"] = exe or "unavailable (needs admin, or process is protected)"
    if exe:
        if len(_known_exe) >= 4096:
            _known_exe.pop(next(iter(_known_exe)))
        _known_exe[pid] = exe
    info["username"] = _safe(p.username, info["username"])
    info["cmdline"] = _safe(lambda: subprocess.list2cmdline(p.cmdline()), "")
    info["create_time"] = _safe(p.create_time, None)
    info["threads"] = _safe(p.num_threads, 0)
    info["memory"] = _safe(lambda: p.memory_info().rss, 0)
    cp = _cpu_procs.get(pid)
    if cp is None or _safe(cp.create_time) != info["create_time"]:  # new or PID reused
        if len(_cpu_procs) >= 1024:
            _cpu_procs.pop(next(iter(_cpu_procs)))
        cp = _cpu_procs[pid] = p
    info["cpu"] = _safe(lambda: cp.cpu_percent(interval=0.0), 0.0)

    ppid = _safe(p.ppid, None)
    info["parent_pid"] = ppid
    if ppid:
        info["parent_name"] = _safe(lambda: psutil.Process(ppid).name(), f"PID {ppid}")

    return info


def get_process_info(pid):
    if not pid:
        return dict(_EMPTY_PROC_INFO)
    return _proc_info_cache.get_or_compute(pid, lambda: _fetch_process_info(pid))


def process_exe_location(pid):
    """Location class of a PID's executable ("system", "appdata", ... "unknown")."""
    return classify_exe_location(get_process_info(pid)["exe"]) if pid else "unknown"


# ---------------------------------------------------------------------------
# Executable path resolution by name
# ---------------------------------------------------------------------------
# Firewall rules match on the program path, so a row needs a real path even when
# psutil can't give one: the process already exited, or it was running before
# NetSpy started (ETW never saw it launch, so only its name is known). Fallback:
# an index of installed programs by exe name, built in the background from
# Store/MSIX packages, App Paths, Uninstall entries, Start Menu shortcuts and
# the running process list.

APP_INDEX_TTL = 300  # seconds before the installed-programs index is rebuilt
_app_index = {}  # exe name (lower) -> [full paths]
_app_index_ts = 0.0
_app_index_building = False
_app_index_lock = threading.Lock()
_name_resolved_paths = set()  # paths found by name match (shown/logged as such)
_name_alternatives = {}  # resolved path (lower) -> other installed programs with the same exe name

_APP_INDEX_PS = r"""
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
if (-not $pkgs) { $pkgs = Get-AppxPackage -ErrorAction SilentlyContinue }
foreach ($p in $pkgs) { if ($p.InstallLocation) { "PKG|$($p.InstallLocation)" } }
$shell = New-Object -ComObject WScript.Shell
$menus = @("$env:ProgramData\Microsoft\Windows\Start Menu", "$env:APPDATA\Microsoft\Windows\Start Menu")
foreach ($m in $menus) {
    Get-ChildItem -LiteralPath $m -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        try { $t = $shell.CreateShortcut($_.FullName).TargetPath; if ($t -like '*.exe') { "LNK|$t" } } catch {}
    }
}
"""
_MANIFEST_EXE_RE = re.compile(r'\bExecutable="([^"]+\.exe)"', re.IGNORECASE)


def _index_add(index, path):
    if path and path.lower().endswith(".exe"):
        path = os.path.normpath(os.path.expandvars(path.strip().strip('"')))
        paths = index.setdefault(os.path.basename(path).lower(), [])
        if path.lower() not in (p.lower() for p in paths):
            paths.append(path)


def _index_registry(index):
    import winreg

    def subkeys(root, path, view=0):
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_READ | view)
        except OSError:
            return
        with key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                try:
                    yield winreg.OpenKey(key, winreg.EnumKey(key, i))
                except OSError:
                    continue

    def value(key, name):
        try:
            return str(winreg.QueryValueEx(key, name)[0])
        except OSError:
            return ""

    roots = [(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY), (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
             (winreg.HKEY_CURRENT_USER, 0)]
    for root, view in roots:
        for key in subkeys(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", view):
            with key:
                _index_add(index, value(key, ""))
        for key in subkeys(root, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", view):
            with key:
                icon = value(key, "DisplayIcon").split(",")[0]
                _index_add(index, icon)
                location = value(key, "InstallLocation").strip().strip('"')
                if location and os.path.isdir(location):
                    for exe in sorted(discover_executables_from_directory(location, max_depth=2))[:200]:
                        _index_add(index, exe)


def _index_packages_and_shortcuts(index):
    rc, out, _ = _run_powershell(_APP_INDEX_PS, timeout=120)
    for line in out.splitlines():
        kind, _, path = line.partition("|")
        if kind == "LNK":
            _index_add(index, path)
        elif kind == "PKG":
            try:
                with open(os.path.join(path, "AppxManifest.xml"), encoding="utf-8", errors="ignore") as f:
                    manifest = f.read()
            except OSError:
                continue
            for rel in _MANIFEST_EXE_RE.findall(manifest):
                _index_add(index, os.path.join(path, rel))


def _build_app_index():
    global _app_index, _app_index_ts, _app_index_building
    index = {}
    try:
        for p in psutil.process_iter(["exe"]):
            _index_add(index, p.info.get("exe"))
        _safe(lambda: _index_registry(index))
        _safe(lambda: _index_packages_and_shortcuts(index))
        with _app_index_lock:
            _app_index = index
            _app_index_ts = time.time()
    finally:
        with _app_index_lock:
            _app_index_building = False


def refresh_app_index_async(force=False):
    """Start a background (re)build of the installed-programs index; never blocks."""
    global _app_index_building
    with _app_index_lock:
        if _app_index_building or (not force and time.time() - _app_index_ts < APP_INDEX_TTL):
            return
        _app_index_building = True
    threading.Thread(target=_build_app_index, name="app-index", daemon=True).start()


def resolve_exe_by_name(name):
    """Best existing path for an exe name ("ImageGlass.exe", "svchost.exe (WpnService)"),
    or None. Prefers a copy that is running right now, then the newest file (a Store
    app update installs into a new version folder)."""
    if not name:
        return None
    key = name.split(" (")[0].strip().lower()
    if not key.endswith(".exe"):
        key += ".exe"
    refresh_app_index_async()
    with _app_index_lock:
        candidates = list(_app_index.get(key, ()))
    candidates = [p for p in candidates if os.path.isfile(p)]
    if not candidates:
        return None
    running = set()
    for p in psutil.process_iter(["name", "exe"]):
        if (p.info.get("name") or "").lower() == key and p.info.get("exe"):
            running.add(p.info["exe"].lower())
    best = max(candidates, key=lambda p: (p.lower() in running, _safe(lambda: os.path.getmtime(p), 0)))
    _name_resolved_paths.add(best.lower())
    others = [p for p in candidates if p != best]
    if others:
        _name_alternatives[best.lower()] = others
    return best


def is_windows_package_path(path):
    """True for Windows' own packaged apps (SystemApps, Microsoft.Windows.* in WindowsApps)."""
    p = (path or "").lower()
    if p.startswith(WINDIR.lower() + "\\"):
        return True
    m = re.search(r"\\windowsapps\\([^\\]+)", p)
    return bool(m) and m.group(1).startswith(("microsoft.windows", "microsoftwindows.", "windows."))


def get_process_ancestry(pid):
    chain = []
    visited = {pid}
    try:
        current_ppid = psutil.Process(pid).ppid()
    except Exception:
        return chain

    while current_ppid and current_ppid not in visited:
        try:
            p = psutil.Process(current_ppid)
            name = p.name()
        except Exception:
            break
        chain.append((current_ppid, name))
        visited.add(current_ppid)
        try:
            current_ppid = p.ppid()
        except Exception:
            break

    chain.reverse()
    return chain


def get_child_processes(pid):
    children = []
    try:
        for p in psutil.process_iter(["pid", "ppid", "name"]):
            info = p.info
            if info.get("ppid") == pid:
                children.append((info["pid"], info.get("name") or "?"))
    except Exception:
        pass
    return children


def build_process_tree(
    pid,
    name,
    connections=None,
    max_remote_leaves=3,
    max_children=None,
    pad_to_fixed_height=False,
):
    if max_children is None:
        max_children = MAX_TREE_CHILDREN
    ancestry = get_process_ancestry(pid)
    children = get_child_processes(pid)

    if ancestry:
        root_pid, root_name = ancestry[0]
        tree = Tree(f"{root_name} [dim](PID {root_pid})[/]")
        node = tree
        for anc_pid, anc_name in ancestry[1:]:
            node = node.add(f"{anc_name} [dim](PID {anc_pid})[/]")
        target_node = node.add(f"[bold yellow]{name}[/] [dim](PID {pid}, selected)[/]")
    else:
        tree = Tree(f"[bold yellow]{name}[/] [dim](PID {pid}, selected)[/]")
        target_node = tree

    shown_children = children[:max_children]
    for child_pid, child_name in shown_children:
        target_node.add(f"{child_name} [dim](PID {child_pid})[/]")
    hidden_count = len(children) - len(shown_children)
    if hidden_count > 0:
        target_node.add(
            f"[dim]... and {hidden_count} more child process(es) (not shown)[/]"
        )
    elif pad_to_fixed_height:
        target_node.add("[dim](no additional child processes)[/]")

    return tree


# Connection state cache (CONN_STATE_TTL from the centralized config block)
_conn_state_cache = TTLCache(CONN_STATE_TTL)


def _fetch_live_connection_states(pid):
    """Fetch live connection states from psutil - used by TTLCache."""
    states = {}
    try:
        p = psutil.Process(pid)
        for c in _proc_connections(p):
            if not c.laddr:
                continue
            proto = TYPE_MAP.get(c.type)
            rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else (None, None)
            states[(proto, c.laddr.ip, c.laddr.port, rip, rport)] = c.status
    except Exception:
        pass
    return states


def get_live_connection_states(pid):
    if not pid:
        return {}
    return _conn_state_cache.get_or_compute(pid, lambda: _fetch_live_connection_states(pid))


def get_listening_sockets():
    with _listening_lock:
        return list(_listening_snapshot["data"])


# Loopback listener cache (LOOPBACK_LISTENER_TTL from the centralized config block)
_loopback_listener_cache = TTLCache(LOOPBACK_LISTENER_TTL)


def _fetch_loopback_listener_map():
    """Fetch loopback listener map - used by TTLCache."""
    mapping = {}
    for s in get_listening_sockets():
        if classify_bind_address(s["ip"]) == "LOOPBACK":
            mapping[s["port"]] = (s["pid"], s["name"])
    return mapping


def get_loopback_listener_map():
    return _loopback_listener_cache.get_or_compute("map", _fetch_loopback_listener_map)


# Windows Firewall Rule Management
def get_firewall_rules():
    """
    EDUCATIONAL: Windows Firewall rule enumeration.

    Non-blocking: returns the cached rules immediately and, when the cache is
    stale, kicks off a single background refresh. The actual enumeration
    (Get-NetFirewallRule via PowerShell) can take several seconds on machines
    with many rules, so it must never run on the render thread - doing so froze
    the whole UI for the first second(s) after opening the Firewall view.
    """
    global _firewall_refreshing
    now = time.time()
    with _firewall_rules_lock:
        fresh = now - _firewall_rules_cache["ts"] < FIREWALL_RULES_TTL
        data = _firewall_rules_cache["data"]
        start_refresh = (not fresh) and (not _firewall_refreshing)
        if start_refresh:
            _firewall_refreshing = True

    if start_refresh:
        def _refresh_worker():
            global _firewall_refreshing
            try:
                rules = _fetch_firewall_rules_blocking()
                with _firewall_rules_lock:
                    _firewall_rules_cache["ts"] = time.time()
                    _firewall_rules_cache["data"] = rules
            finally:
                with _firewall_rules_lock:
                    _firewall_refreshing = False

        threading.Thread(
            target=_refresh_worker, daemon=True, name="fw-rules-refresh"
        ).start()

    return data


def _norm_program(program):
    """Rule program path -> lowercase absolute path ('%SystemRoot%' expanded)."""
    if not program:
        return ""
    return os.path.normcase(os.path.expandvars(program))


def rules_for_program(rules, exe_path):
    """Firewall rules whose program filter is exactly this executable."""
    if not exe_path or exe_path.startswith(("unavailable", "(", "unknown")):
        return []
    target = os.path.normcase(exe_path)
    return [r for r in rules if r.get("program") == target]


def _fetch_firewall_rules_blocking():
    """Blocking firewall-rule enumeration. Run ONLY from the background refresh
    worker in get_firewall_rules(), never the render thread."""
    rules = []
    try:
        # Use PowerShell to get firewall rules with proper string conversion
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "$prog = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { "
            "if ($_.Program -and $_.Program -ne 'Any') { $prog[$_.InstanceID] = $_.Program } }; "
            "Get-NetFirewallRule | Select-Object Name, DisplayName, "
            "@{Name='Direction';Expression={$_.Direction.ToString()}}, "
            "@{Name='Action';Expression={$_.Action.ToString()}}, "
            "@{Name='Enabled';Expression={$_.Enabled.ToString()}}, "
            "@{Name='Profile';Expression={$_.Profile.ToString()}}, Description, Grouping, "
            "@{Name='Program';Expression={$prog[$_.Name]}} | ConvertTo-Json -Compress",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=FIREWALL_RULE_TIMEOUT,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            import json

            try:
                rules_data = json.loads(result.stdout)
                if isinstance(rules_data, list):
                    for rule in rules_data:
                        # Convert enabled to boolean
                        enabled = rule.get("Enabled", False)
                        if isinstance(enabled, str):
                            enabled = enabled.lower() in ("true", "yes", "1")
                        elif isinstance(enabled, int):
                            enabled = enabled != 0

                        rules.append(
                            {
                                "name": rule.get("Name", ""),
                                "display_name": rule.get("DisplayName", ""),
                                "direction": rule.get("Direction", ""),
                                "action": rule.get("Action", ""),
                                "enabled": enabled,
                                "profile": rule.get("Profile", ""),
                                "description": rule.get("Description", ""),
                                "grouping": rule.get("Grouping", ""),
                                "program": _norm_program(rule.get("Program")),
                            }
                        )
            except json.JSONDecodeError:
                # Fallback to simpler parsing if JSON fails
                pass
    except Exception:
        # If PowerShell fails, try using netsh as fallback
        try:
            cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=NETSH_TIMEOUT,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
            # Parse netsh output (simplified parsing)
            if result.stdout:
                lines = result.stdout.split("\n")
                current_rule = {}
                for line in lines:
                    line = line.strip()
                    if line.startswith("Rule Name:"):
                        if current_rule:
                            rules.append(current_rule)
                        current_rule = {
                            "name": "",
                            "enabled": False,
                            "direction": "",
                            "action": "",
                            "profile": "",
                            "description": "",
                        }
                    elif line.startswith("Enabled:"):
                        current_rule["enabled"] = "Yes" in line
                    elif line.startswith("Direction:"):
                        current_rule["direction"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Action:"):
                        current_rule["action"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Profiles:"):
                        current_rule["profile"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Description:"):
                        current_rule["description"] = line.split(":", 1)[1].strip()
                if current_rule:
                    rules.append(current_rule)
        except Exception:
            pass

    return rules


# Running Processes State
_app_inventory_cache = {"ts": 0.0, "data": []}
_app_inventory_lock = threading.Lock()
# APP_INVENTORY_TTL comes from the centralized config block (30s, no disk writes)
_review_status = {}  # In-memory review status only (no disk writes)

# Background scanning state
_background_scan_thread = None
_background_scan_running = False
_background_scan_lock = threading.Lock()
_background_scan_progress = {"user": False, "system": False, "complete": False}


def load_review_status():
    """Load review status from memory (no disk writes)."""
    return _review_status


def save_review_status(status):
    """Save review status to memory (no disk writes)."""
    global _review_status
    _review_status = status


_default_action_cache = {"ts": 0.0, "data": None}
_default_action_lock = threading.Lock()
# DEFAULT_ACTION_TTL comes from the centralized config block


def _fetch_default_outbound_action():
    result = "Allow"  # Windows' own out-of-the-box default
    rc, out, _err = _run_powershell(
        "$p = (Get-NetConnectionProfile | Select-Object -First 1 -ExpandProperty NetworkCategory).ToString(); "
        "(Get-NetFirewallProfile -Name $p).DefaultOutboundAction.ToString()",
        timeout=DEFAULT_OUTBOUND_ACTION_TIMEOUT,
    )
    if out in ("Allow", "Block"):
        result = out
    with _default_action_lock:
        _default_action_cache["ts"] = time.time()
        _default_action_cache["data"] = result
        _default_action_cache["busy"] = False


def get_default_outbound_action():
    """The active network profile's default outbound action ('Allow' or
    'Block') - what governs any process with no explicit per-app rule.
    Non-blocking: answers from cache ("Allow", Windows' default, until the
    first lookup finishes) and refreshes in the background every
    DEFAULT_ACTION_TTL."""
    with _default_action_lock:
        stale = time.time() - _default_action_cache["ts"] >= DEFAULT_ACTION_TTL
        if stale and not _default_action_cache.get("busy"):
            _default_action_cache["busy"] = True
            threading.Thread(target=_fetch_default_outbound_action, daemon=True,
                             name="fw-default-action").start()
        return _default_action_cache["data"] or "Allow"


def check_firewall_rule_for_process(
    exe_path, process_name, has_active_connection=False
):
    """Effective firewall status for this process, most to least certain:
    1. Currently-observed traffic -> it IS getting through, full stop.
       Stronger evidence than any rule lookup, since it reflects
       what actually happened - this is what fixes Firefox showing
       "Block" while you're using it.
    2. An OUTBOUND rule that matches by name/path - direction is now
       checked, so an ordinary Inbound rule (normal, unrelated to
       whether the app can reach the internet) can no longer
       override the real answer. Block wins over Allow if both
       exist, matching Windows Firewall's own precedence.
    3. No matching outbound rule -> the active profile's default
       outbound action, instead of a bare "Unknown" - this is the
       actual governing rule for most apps on a stock install.
    0. A NetSpy-managed rule (B/A/X) outranks all of the above.
    """
    # --- NetSpy-managed rules win: this is YOUR explicit decision ---
    intent = get_netspy_intent(exe_path)
    if intent == "Block":
        return "Block (NetSpy)"
    if intent == "Allow":
        return "Allow (NetSpy)"
    # --- existing body continues unchanged from here ---
    if has_active_connection:
        return "Allow (active)"

    if not exe_path and not process_name:
        return get_default_outbound_action() + " (default)"

    try:
        matched_actions = [
            rule.get("action", "")
            for rule in rules_for_program(get_firewall_rules(), exe_path)
            if rule.get("direction", "").lower() == "outbound" and rule.get("enabled", False)
        ]

        if "Block" in matched_actions:
            return "Block (rule)"
        if "Allow" in matched_actions:
            return "Allow (rule)"

        return get_default_outbound_action() + " (default)"
    except Exception:
        return get_default_outbound_action() + " (default)"


# A handful of pseudo-processes with no real, stable file path to match
# a firewall rule against (kernel/memory-manager entries) - these are
# the only things worth excluding outright. Everything else that's
# actually running, including core Windows binaries under C:\Windows,
# belongs in the list - that's what SimpleWall shows, and blanket-
# hiding "system-located" exes was why svchost.exe/explorer.exe/
# rundll32.exe/taskhostw.exe/etc. never appeared here.
NON_ACTIONABLE_PROCESS_NAMES = {
    "system",
    "system idle process",
    "registry",
    "secure system",
    "memory compression",
}


def is_actionable_process(name, exe_path):
    """False for kernel/pseudo-processes that have no real file to
    match a firewall rule (or hash, or signature) against."""
    return name.lower() not in NON_ACTIONABLE_PROCESS_NAMES and bool(exe_path)


def get_all_system_processes():
    """Every process currently running on the machine, straight from
    the OS process table via psutil.process_iter() - NOT filtered by
    whether NetSpy has observed it making a network connection. This
    is the real gap vs SimpleWall: SimpleWall enumerates the actual
    process list; NetSpy's tabs were built from compute_rows(), which
    only contains processes NetSpy's packet capture has already seen
    traffic from. A quiet background service that hasn't talked
    recently (or whose connection aged out of CONNECTION_RETENTION)
    simply never showed up before, in either tab."""
    procs = []
    try:
        for p in psutil.process_iter(["pid", "name", "exe"]):
            info = p.info
            name = info.get("name") or "?"
            exe = info.get("exe") or ""
            if not exe:
                try:
                    exe = p.exe()
                except Exception:
                    exe = resolve_exe_by_name(name) or ""
            procs.append({"pid": info.get("pid"), "name": name, "exe": exe})
    except Exception:
        pass
    return procs


def get_application_inventory():
    """Every currently-running process, from the real OS process list
    (see get_all_system_processes) - not just ones NetSpy has observed
    making a network connection, and not filtered out just because
    they live under C:\\Windows."""
    now = time.time()
    with _app_inventory_lock:
        if now - _app_inventory_cache["ts"] < APP_INVENTORY_TTL:
            return _app_inventory_cache["data"]

    try:
        rows = dict(compute_rows())
    except Exception:
        rows = {}

    review_status = load_review_status()

    enriched_apps = []
    for proc in get_all_system_processes():
        name = proc["name"]
        if not is_actionable_process(name, proc["exe"]):
            continue

        exe_path = proc["exe"]
        exe_name = os.path.basename(exe_path) if exe_path else name

        reviewed = review_status.get(exe_name.lower(), {}).get("reviewed", False)

        # If NetSpy has network data for this exact process name, use
        # it for connection counts / "has active traffic right now";
        # otherwise it's a running process with no observed traffic
        # yet - still worth listing, just with 0 connections.
        net_data = rows.get(name) or rows.get(exe_name)
        connections = net_data.get("connections", {}) if net_data else {}
        has_active = len(connections) > 0

        exe_location = classify_exe_location(exe_path)
        firewall_state = check_firewall_rule_for_process(
            exe_path, exe_name, has_active_connection=has_active
        )
        location_badge = exe_location_badge(exe_path)

        enriched_apps.append(
            {
                "name": exe_name,
                "path": exe_path,
                "publisher": "-",
                "location": exe_location,
                "location_badge": location_badge,
                "sig_status": "-",
                "is_active": True,
                "reviewed": reviewed,
                "firewall_state": firewall_state,
                "size": 0,
                "connections": len(connections),
            }
        )

    # Dedupe by exe name, keeping whichever instance has more
    # connections (multiple svchost.exe instances collapse into one
    # row, same as your Active view already does).
    by_name = {}
    for app in enriched_apps:
        key = app["name"].lower()
        if key not in by_name or app["connections"] > by_name[key]["connections"]:
            by_name[key] = app
    enriched_apps = list(by_name.values())

    enriched_apps.sort(key=lambda x: x["name"].lower())

    with _app_inventory_lock:
        _app_inventory_cache["ts"] = now
        _app_inventory_cache["data"] = enriched_apps

    return enriched_apps


def get_installed_apps_from_registry():
    """Get installed applications from Windows Registry - completely dynamic."""
    installed_apps = set()

    try:
        import winreg

        # Check both 32-bit and 64-bit registry views
        registry_views = [winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]

        for registry_view in registry_views:
            try:
                # Uninstall registry keys
                uninstall_keys = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ]

                for uninstall_key in uninstall_keys:
                    try:
                        key = winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE,
                            uninstall_key,
                            0,
                            winreg.KEY_READ | registry_view,
                        )

                        # Enumerate all subkeys (installed applications)
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                i += 1

                                try:
                                    app_key = winreg.OpenKey(
                                        key, subkey_name, 0, winreg.KEY_READ
                                    )

                                    # Get display name and install location
                                    display_name = None
                                    install_location = None

                                    try:
                                        display_name = winreg.QueryValueEx(
                                            app_key, "DisplayName"
                                        )[0]
                                    except FileNotFoundError:
                                        pass

                                    try:
                                        install_location = winreg.QueryValueEx(
                                            app_key, "InstallLocation"
                                        )[0]
                                    except FileNotFoundError:
                                        pass

                                    if display_name:
                                        installed_apps.add(
                                            (display_name, install_location)
                                        )

                                    winreg.CloseKey(app_key)
                                except Exception:
                                    pass

                            except OSError:
                                break

                        winreg.CloseKey(key)
                    except Exception:
                        continue

            except Exception:
                continue

    except ImportError:
        # Fallback if winreg not available
        pass

    return installed_apps


def discover_executables_from_directory(directory, max_depth=3, min_size=1024):
    """Discover all executables in a directory tree without hardcoded lists."""
    executables = set()

    if not os.path.exists(directory):
        return executables

    try:
        for root, dirs, files in os.walk(directory):
            # Limit depth to avoid excessive scanning
            depth = root[len(directory) :].count(os.sep)
            if depth > max_depth:
                dirs[:] = []  # Don't recurse further
                continue

            for file in files:
                if file.lower().endswith(".exe"):
                    exe_path = os.path.join(root, file)
                    try:
                        if os.path.getsize(exe_path) >= min_size:
                            executables.add(exe_path)
                    except Exception:
                        continue
    except Exception:
        pass

    return executables


def _add_scanned_apps(exe_paths, review_status, running_names, all_apps_dict):
    """Add not-running, not-yet-listed executables to the app inventory."""
    for exe_path in exe_paths:
        exe_name = os.path.basename(exe_path)
        exe_lower = exe_name.lower()
        if exe_lower in running_names or exe_lower in all_apps_dict:
            continue
        try:
            all_apps_dict[exe_lower] = {
                "name": exe_name,
                "path": exe_path,
                "publisher": "-",
                "location": classify_exe_location(exe_path),
                "location_badge": exe_location_badge(exe_path),
                "sig_status": "-",
                "is_active": False,
                "reviewed": review_status.get(exe_lower, {}).get("reviewed", False),
                "firewall_state": check_firewall_rule_for_process(exe_path, exe_name),
                "size": 0,
            }
        except Exception:
            continue


def _scan_user_directories(review_status, running_names, all_apps_dict):
    """Scan user directories (fast scan - no system directories)."""
    # User-only directories (fast)
    user_dirs = [
        os.path.join(PROGRAM_FILES, ""),
        os.path.join(PROGRAM_FILES_X86, ""),
        os.path.join(LOCALAPPDATA, "Programs"),
        LOCALAPPDATA,
        DOWNLOADS_DIR,
    ]

    for program_dir in user_dirs:
        if os.path.exists(program_dir):
            discovered_exes = discover_executables_from_directory(
                program_dir, max_depth=2
            )
            _add_scanned_apps(discovered_exes, review_status, running_names, all_apps_dict)

    # Apps registered in the Uninstall registry keys
    for display_name, install_location in get_installed_apps_from_registry():
        if install_location and os.path.exists(install_location):
            # Search for executables in the install location
            discovered_exes = discover_executables_from_directory(
                install_location, max_depth=1
            )
            _add_scanned_apps(discovered_exes, review_status, running_names, all_apps_dict)


def _scan_system_directories(review_status, running_names, all_apps_dict):
    """Scan system directories (slow scan - runs in background)."""
    # System directories (slow)
    system_dirs = [
        SYSTEM32,
        SYSWOW64,
    ]

    # Windows Defender directories
    import glob as _glob
    for versioned_dir in _glob.glob(DEFENDER_PLATFORM_GLOB):
        if os.path.isdir(versioned_dir):
            system_dirs.append(versioned_dir)

    for program_dir in system_dirs:
        if os.path.exists(program_dir):
            discovered_exes = discover_executables_from_directory(
                program_dir, max_depth=1  # Reduce depth for system dirs
            )
            _add_scanned_apps(discovered_exes, review_status, running_names, all_apps_dict)


def _background_scan_worker():
    """Background thread that progressively scans directories."""
    global _background_scan_running

    with _background_scan_lock:
        if _background_scan_running:
            return
        _background_scan_running = True

    try:
        # Load review status
        review_status = load_review_status()

        # Get currently running processes to exclude them
        running_names = {
            os.path.basename(p["exe"]).lower()
            for p in get_all_system_processes()
            if p["exe"]
        }

        # Use dictionary for deduplication by exe name (lowercase)
        all_apps_dict = {}  # Key: exe_name.lower(), Value: app data

        # First pass: Fast user directories
        _scan_user_directories(review_status, running_names, all_apps_dict)

        # Update cache with user apps
        with _app_inventory_lock:
            cache_key = "_all_apps_cache"
            now = time.time()
            user_apps = list(all_apps_dict.values())
            user_apps.sort(key=lambda x: x["name"].lower())
            _app_inventory_cache[cache_key] = {"ts": now, "data": user_apps}

        with _background_scan_lock:
            _background_scan_progress["user"] = True

        # Second pass: Slow system directories (background)
        _scan_system_directories(review_status, running_names, all_apps_dict)

        # Update cache with all apps
        with _app_inventory_lock:
            cache_key = "_all_apps_cache"
            now = time.time()
            all_apps = list(all_apps_dict.values())
            all_apps.sort(key=lambda x: x["name"].lower())
            _app_inventory_cache[cache_key] = {"ts": now, "data": all_apps}

        with _background_scan_lock:
            _background_scan_progress["system"] = True
            _background_scan_progress["complete"] = True

    except Exception:
        pass
    finally:
        with _background_scan_lock:
            _background_scan_running = False


def start_background_scan():
    """Start background scanning if not already running."""
    with _background_scan_lock:
        if not _background_scan_running:
            global _background_scan_thread
            _background_scan_thread = threading.Thread(
                target=_background_scan_worker, 
                daemon=True, 
                name="app-scanner"
            )
            _background_scan_thread.start()


ALL_APPS_RESCAN_INTERVAL = 600.0  # installed apps change rarely; a scan walks whole folders


def get_all_user_apps():
    """Installed apps found on disk. Never scans on the render thread: returns
    what the background scan has found so far and starts a re-scan when the
    result is older than ALL_APPS_RESCAN_INTERVAL."""
    with _app_inventory_lock:
        cached = _app_inventory_cache.get("_all_apps_cache")
    if cached is None or time.time() - cached["ts"] >= ALL_APPS_RESCAN_INTERVAL:
        start_background_scan()
    return cached["data"] if cached else []


def clear_app_inventory_cache():
    """Re-read the running-process list on the next frame. The All Apps scan
    is left alone - NetSpy's own changes show through _with_live_state()."""
    with _app_inventory_lock:
        _app_inventory_cache["ts"] = 0.0


def update_application_review(exe_name, reviewed_status):
    """Update review status for an application."""
    review_status = load_review_status()
    exe_name_lower = exe_name.lower()

    if exe_name_lower not in review_status:
        review_status[exe_name_lower] = {}

    review_status[exe_name_lower]["reviewed"] = reviewed_status
    review_status[exe_name_lower]["last_updated"] = time.time()

    save_review_status(review_status)  # shown at once via _with_live_state()


def modify_firewall_rule(rule_name, new_action):
    """Change an EXISTING rule's action by its real rule Name (raw-rules view).
    Runs on its own thread; the outcome goes to the firewall action log."""
    if not is_admin():
        log_fw_action("[red]Needs admin[/] - firewall changes require an elevated terminal")
        return

    def _worker():
        rc, out, err = _run_powershell(
            f"Set-NetFirewallRule -Name '{_ps_quote(rule_name)}' -Action {new_action} -ErrorAction Stop",
            timeout=FIREWALL_RULE_TIMEOUT,
        )
        if rc == 0:
            log_fw_action(f"[green]OK[/] rule {escape(rule_name)}: {new_action}")
        else:
            detail = (err or out or "no detail").splitlines()[0][:120]
            log_fw_action(f"[red]FAILED[/] rule {escape(rule_name)}: {new_action} - {escape(detail)}")
        with _firewall_rules_lock:
            _firewall_rules_cache["ts"] = 0.0

    log_fw_action(f"[dim]Working...[/] rule {escape(rule_name)}: {new_action}")
    threading.Thread(target=_worker, daemon=True, name="fw-rule-edit").start()


NETSPY_RULE_PREFIX = "NetSpy"
# Block inbound as well as outbound when blocking. Outbound is what
# stops an app "calling home"; inbound additionally stops anything
# reaching it. Cheap to do both, so on by default.
NETSPY_BLOCK_INBOUND_TOO = True

# Rolling log of what each B/A/D keypress actually did, shown in a
# panel under the firewall views. Firewall changes are the one thing
# in this tool that MODIFIES the system rather than observing it, so
# every attempt - including failures and permission errors - is
# surfaced instead of failing silently.
_fw_action_lock = threading.Lock()
_fw_action_log = collections.deque(maxlen=8)
_fw_action_busy = set()  # exe paths with an in-flight change

# Our own record of intent, keyed by lowercased exe path. Written the
# instant a change succeeds so the table updates immediately, rather
# than waiting up to FIREWALL_RULES_TTL (30s) for the rule cache to
# catch up. The real rules remain the source of truth; this is only a
# fast-path overlay.
_netspy_intent = {}
_netspy_intent_lock = threading.Lock()


def log_fw_action(msg):
    with _fw_action_lock:
        _fw_action_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def _ps_quote(s):
    """Single-quote a string for PowerShell (doubling any embedded
    single quotes). Paths routinely contain spaces and occasionally
    quotes, and these strings go into a -Command script."""
    return (s or "").replace("'", "''")


def _run_powershell(script, timeout=POWERSHELL_DEFAULT_TIMEOUT):
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)


# Firewall Action Execution
def netspy_rule_name(exe_path, action, direction="Outbound"):
    """
    EDUCATIONAL: Deterministic firewall rule naming
    NetSpy creates its own firewall rules with predictable names
    This allows us to find and remove rules we created
    Format: 'NetSpy Block Outbound - firefox.exe'
    """
    """Deterministic rule name, so the same app always maps to the
    same rule and we can Remove-NetFirewallRule it by exact -Name
    instead of guessing with wildcards."""
    base = os.path.basename(exe_path) if exe_path else "unknown"
    return f"{NETSPY_RULE_PREFIX} {action} {direction} - {base}"


def _netspy_rule_names(exe_path):
    return {
        "block_out": netspy_rule_name(exe_path, "Block", "Outbound"),
        "block_in": netspy_rule_name(exe_path, "Block", "Inbound"),
        "allow_out": netspy_rule_name(exe_path, "Allow", "Outbound"),
    }


def get_netspy_intent(exe_path):
    """ "Block" / "Allow" / None - what WE last set for this exe."""
    if not exe_path:
        return None
    with _netspy_intent_lock:
        return _netspy_intent.get(exe_path.lower())


def _set_netspy_intent(exe_path, value):
    if not exe_path:
        return
    with _netspy_intent_lock:
        if value is None:
            _netspy_intent.pop(exe_path.lower(), None)
        else:
            _netspy_intent[exe_path.lower()] = value


def _apply_firewall_action_worker(label, exe_path, action):
    """Runs on its own thread: New-NetFirewallRule takes 1-3 seconds
    and the render loop must not block on it. Nothing here touches
    shared render state except the action log and the intent overlay,
    both lock-guarded."""
    try:
        names = _netspy_rule_names(exe_path)
        p = _ps_quote(exe_path)

        # Always clear our previous rules for this exe first, so B then
        # A then B never stacks duplicates or leaves a stale Block
        # sitting underneath a new Allow.
        script = (
            "$ErrorActionPreference = 'Stop'; "  # a failed New-NetFirewallRule -> exit code 1
            f"Remove-NetFirewallRule -Name '{_ps_quote(names['block_out'])}' -ErrorAction SilentlyContinue; "
            f"Remove-NetFirewallRule -Name '{_ps_quote(names['block_in'])}'  -ErrorAction SilentlyContinue; "
            f"Remove-NetFirewallRule -Name '{_ps_quote(names['allow_out'])}' -ErrorAction SilentlyContinue; "
        )

        if action == "Block":
            script += (
                f"New-NetFirewallRule -Name '{_ps_quote(names['block_out'])}' "
                f"-DisplayName '{_ps_quote(names['block_out'])}' "
                f"-Direction Outbound -Program '{p}' -Action Block -Profile Any -Enabled True | Out-Null; "
            )
            if NETSPY_BLOCK_INBOUND_TOO:
                script += (
                    f"New-NetFirewallRule -Name '{_ps_quote(names['block_in'])}' "
                    f"-DisplayName '{_ps_quote(names['block_in'])}' "
                    f"-Direction Inbound -Program '{p}' -Action Block -Profile Any -Enabled True | Out-Null; "
                )
        elif action == "Allow":
            script += (
                f"New-NetFirewallRule -Name '{_ps_quote(names['allow_out'])}' "
                f"-DisplayName '{_ps_quote(names['allow_out'])}' "
                f"-Direction Outbound -Program '{p}' -Action Allow -Profile Any -Enabled True | Out-Null; "
            )
        # action == "Default" -> removals only, nothing to create

        rc, out, err = _run_powershell(script)

        if rc == 0:
            _set_netspy_intent(exe_path, None if action == "Default" else action)
            if action == "Default":
                log_fw_action(
                    f"[green]OK[/] {label}: NetSpy rules removed - back to profile default"
                )
            else:
                extra = (
                    " (outbound+inbound)"
                    if (action == "Block" and NETSPY_BLOCK_INBOUND_TOO)
                    else " (outbound)"
                )
                log_fw_action(f"[green]OK[/] {label}: {action}{extra}")
        else:
            detail = (err or out or "no detail").splitlines()[0][:120]
            log_fw_action(f"[red]FAILED[/] {label}: {action} - {escape(detail)}")

        # Force both caches to re-read so the table reflects reality on
        # the next frame rather than serving a stale 30s-old snapshot.
        with _firewall_rules_lock:
            _firewall_rules_cache["ts"] = 0.0
        clear_app_inventory_cache()
    finally:
        with _fw_action_lock:
            _fw_action_busy.discard(exe_path.lower() if exe_path else "")


def apply_firewall_action(label, exe_path, action):
    """Entry point for the keyboard handler. Validates, then hands off
    to a thread. Never blocks the caller."""
    if action not in ("Block", "Allow", "Default"):
        return

    if not is_admin():
        log_fw_action(
            "[red]Needs admin[/] - firewall changes require an elevated terminal "
            "(right-click Terminal -> Run as administrator)"
        )
        return

    if not exe_path or exe_path.startswith(("unavailable", "(")):
        log_fw_action(
            f"[yellow]Skipped[/] {label}: no executable path found - not readable from the process "
            "and no installed program with this name (Windows Firewall rules match on path)"
        )
        refresh_app_index_async(force=True)  # an app installed since the last scan shows up next time
        return

    if os.path.basename(exe_path).lower() == "svchost.exe":
        log_fw_action(
            f"[yellow]Skipped[/] {label}: firewall rules match on program path, and every "
            "Windows service shares svchost.exe - blocking it would cut DNS, Windows Update "
            "and the rest. Disable the service itself (services.msc) instead."
        )
        return

    if not os.path.isfile(exe_path):
        log_fw_action(
            f"[yellow]Skipped[/] {label}: path no longer exists on disk ({exe_path})"
        )
        return

    key = exe_path.lower()
    with _fw_action_lock:
        if key in _fw_action_busy:
            log_fw_action(
                f"[dim]Ignored[/] {label}: a change for this app is still in flight"
            )
            return
        _fw_action_busy.add(key)

    if key in _name_resolved_paths:
        log_fw_action(f"[dim]Path found by name (process not readable):[/] {escape(exe_path)}")
        for other in _name_alternatives.get(key, [])[:3]:
            log_fw_action(f"[yellow]Note:[/] another program has the same name and is NOT affected: {escape(other)}")
    if "\\windowsapps\\" in key and action != "Default":
        log_fw_action(
            f"[dim]Note: {label} is a Store app - its folder name includes the version, so "
            "re-apply this rule after the app updates.[/]"
        )
    log_fw_action(f"[dim]Working...[/] {label}: {action}")
    threading.Thread(
        target=_apply_firewall_action_worker,
        args=(label, exe_path, action),
        daemon=True,
        name="fw-action",
    ).start()


def firewall_selected_target():
    """(label, exe_path) for whatever is selected in the CURRENT
    firewall view - the one piece of glue that lets one set of B/A/D
    keys work across all of them. Returns (None, None) when the
    current view has no controllable selection."""
    try:
        if view_mode == "firewall_detail" or (
            view_mode == "firewall" and firewall_view_mode == "active"
        ):
            if not selected_firewall_rule:
                return None, None
            rows = dict(compute_rows())
            data = rows.get(selected_firewall_rule)
            pid = data.get("pid") if data else None
            exe = get_process_info(pid).get("exe") if pid else None
            if not exe or exe.startswith(("unavailable", "(", "-")):
                exe = resolve_exe_by_name(selected_firewall_rule) or exe
            return selected_firewall_rule, exe

        if view_mode in ("firewall", "app_detail") and firewall_view_mode in (
            "inventory", "all_apps",
        ):
            if not selected_app_inventory_item:
                return None, None
            apps = get_filtered_apps_for_view(firewall_view_mode)
            for app in apps:
                if app["name"] == selected_app_inventory_item:
                    return app["name"], app.get("path") or resolve_exe_by_name(app["name"])
            return selected_app_inventory_item, resolve_exe_by_name(selected_app_inventory_item)
    except Exception:
        return None, None


def build_fw_action_panel():
    """Shown under every firewall view - the running record of what
    B/A/D actually did. Only rendered once something has been
    attempted, so it costs nothing until it's relevant."""
    with _fw_action_lock:
        if not _fw_action_log:
            return None
        body = "\n".join(_fw_action_log)
    hint = (
        "\n[dim]NetSpy-created rules are all named '"
        + NETSPY_RULE_PREFIX
        + " ...' - audit them with "
        "Get-NetFirewallRule -Name '"
        + NETSPY_RULE_PREFIX
        + " *'  |  remove them all with "
        "... | Remove-NetFirewallRule[/]"
    )
    return Panel(body + hint, title="Firewall actions", border_style="bright_red")


def format_connection_endpoint(rip, rport, sni=None):
    if not rip:
        return "-"
    try:
        is_loopback = ipaddress.ip_address(rip).is_loopback
    except (ValueError, TypeError):
        is_loopback = False

    base = format_remote_highlighted(rip, rport, sni)
    if not is_loopback:
        return base

    owner = get_loopback_listener_map().get(rport)
    if owner:
        opid, oname = owner
        return f"{base} [dim]<-> {oname} (PID {opid})[/]"
    return f"{base} [dim](local IPC)[/]"


def build_listening_panel():
    socks = get_listening_sockets()
    socks.sort(
        key=lambda s: (SCOPE_SEVERITY.get(classify_bind_address(s["ip"]), 9), s["port"])
    )

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Process")
    table.add_column("PID", justify="right", style="grey62")
    table.add_column("Proto", justify="center")
    table.add_column("Local address")
    table.add_column("Port", justify="right")
    table.add_column("Scope")

    for s in socks:
        scope = classify_bind_address(s["ip"])
        style = SCOPE_STYLE.get(scope, "white")
        table.add_row(
            s["name"],
            str(s["pid"] or "-"),
            s["proto"],
            s["ip"],
            str(s["port"]),
            f"[{style}]{scope}[/]",
        )

    if not socks:
        table.add_row(
            "(none found - try running elevated for the full list)",
            "-",
            "-",
            "-",
            "-",
            "-",
        )

    note = (
        "[bold red]PUBLIC[/]/[bold yellow]ALL INTERFACES[/] = potentially reachable from outside your LAN "
        "(subject to your router/firewall)   |   [bold blue]LAN[/] = only your local network can reach it   |   "
        "[dim green]LOOPBACK[/] = only this machine can reach it"
    )
    return Group(
        Panel(
            table,
            title="Listening sockets - what's accepting connections (l to hide)",
            border_style="yellow",
        ),
        Panel(note, border_style="yellow"),
    )


# ============================================================================
# 7. UI COMPONENTS - Display panels and view builders
# ============================================================================

# Connection data processing for display
def merge_connections(target, source):
    for key, cdata in source.items():
        if key in target:
            t = target[key]
            t["sent"] += cdata["sent"]
            t["recv"] += cdata["recv"]
            t["packets"] += cdata["packets"]
            t["first_seen"] = min(t["first_seen"], cdata["first_seen"])
            t["last_seen"] = max(t["last_seen"], cdata["last_seen"])
        else:
            target[key] = dict(cdata)


def aggregate_by_remote(connections):
    agg = collections.Counter()
    for (proto, lip, lport, rip, rport), cdata in connections.items():
        agg[(rip, rport)] += cdata["sent"] + cdata["recv"]
    return agg


def is_ptr_domain(domain):
    """Check if a domain name appears to be a PTR record (contains IP-like patterns)."""
    if not domain:
        return False
    # Common PTR patterns: contains IP-like sequences (e.g., 192.168.1.1.in-addr.arpa or 1.0.0.127.in-addr.arpa)
    # Also detect reverse DNS patterns like .bc.googleusercontent.com, .compute.amazonaws.com, etc.
    ptr_indicators = [
        "in-addr.arpa",
        "ip6.arpa",
        ".bc.googleusercontent.com",
        ".compute.amazonaws.com",
        ".compute-1.amazonaws.com",
        ".ec2.internal",
        ".internal.cloudapp.net",
    ]
    domain_lower = domain.lower()
    return any(indicator in domain_lower for indicator in ptr_indicators)


def truncate_domain_display(domain, max_length=30):
    """Truncate long domain names for display while keeping full value internally."""
    if not domain or len(domain) <= max_length:
        return domain

    # For PTR domains, try to extract the meaningful part
    if is_ptr_domain(domain):
        # Extract the main domain part (e.g., googleusercontent.com from 178.238.223.35.bc.googleusercontent.com)
        parts = domain.split(".")
        if len(parts) > 2:
            # Take the last 2-3 parts which are usually the actual domain
            main_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            if len(main_domain) <= max_length:
                return main_domain
            main_domain = ".".join(parts[-3:]) if len(parts) >= 3 else domain
            if len(main_domain) <= max_length:
                return main_domain

    # General truncation with ellipsis
    return domain[: max_length - 3] + "..."


# Prefer TLS SNI because it shows the hostname
# application actually requested.
# Fall back to PTR when SNI isn't available.
def get_smart_domain_name(cdata, rip):
    """Get the best available domain name with source tracking."""
    # Priority 1: TLS SNI (best - what the application actually requested)
    sni = cdata.get("sni")
    if sni and not sni.startswith("[") and sni != "-":
        return sni, "TLS SNI"

    # Priority 2: the name the program looked up (ETW DNS) - reliable
    asked = _etw_dns_names.get(rip) if rip else None
    if asked:
        return asked[0], "DNS"

    # Priority 3: PTR record (if available and not "no PTR record")
    host = get_hostname(rip)
    if host and "no ptr record" not in host.lower() and not host.startswith("["):
        return host, "PTR"

    return "Unknown domain", "None observed"


# Combine multiple connections into one domain entry.
# Example:
#   firefox -> github.com
#   chrome  -> github.com
#
# becomes:
#   github.com (2 processes)
def aggregate_by_domain(rows, target_domain):
    """Aggregate all connections to a specific domain across all processes."""
    domain_data = {
        "ips": set(),
        "processes": set(),
        "connections": 0,
        "sent": 0,
        "recv": 0,
        "ports": set(),
        "first_seen": None,
        "last_seen": None,
    }
    if (
        not target_domain
        or target_domain.startswith("[")
        or target_domain in ("-", "Unknown domain")
    ):
        return domain_data

    for proc_name, data in rows.items():
        for ckey, cdata in data.get("connections", {}).items():
            _proto, _lip, _lport, rip, rport = ckey
            sni = cdata.get("sni")
            hostname = sni if sni else get_hostname(rip)

            if hostname and hostname == target_domain:
                domain_data["ips"].add(rip)
                domain_data["processes"].add(proc_name)
                domain_data["connections"] += 1
                domain_data["sent"] += cdata["sent"]
                domain_data["recv"] += cdata["recv"]
                if rport:
                    domain_data["ports"].add(rport)

                # Track first_seen and last_seen across all connections to this domain
                if cdata.get("first_seen") and (
                    domain_data["first_seen"] is None
                    or cdata["first_seen"] < domain_data["first_seen"]
                ):
                    domain_data["first_seen"] = cdata["first_seen"]
                if cdata.get("last_seen") and (
                    domain_data["last_seen"] is None
                    or cdata["last_seen"] > domain_data["last_seen"]
                ):
                    domain_data["last_seen"] = cdata["last_seen"]

    return domain_data


def aggregate_by_ip(rows, target_ip):
    """Same shape as aggregate_by_domain(), for a remote with no known name."""
    agg = {"ips": {target_ip}, "processes": set(), "connections": 0, "sent": 0, "recv": 0,
           "ports": set(), "first_seen": None, "last_seen": None}
    for proc_name, data in rows.items():
        for (_proto, _lip, _lport, rip, rport), cdata in data.get("connections", {}).items():
            if rip != target_ip:
                continue
            agg["processes"].add(proc_name)
            agg["connections"] += 1
            agg["sent"] += cdata["sent"]
            agg["recv"] += cdata["recv"]
            if rport:
                agg["ports"].add(rport)
            agg["first_seen"] = min(filter(None, (agg["first_seen"], cdata["first_seen"])))
            agg["last_seen"] = max(filter(None, (agg["last_seen"], cdata["last_seen"])))
    return agg


# ==========================================================
# DOMAIN INTELLIGENCE ENGINE
#
# Converts:
#
#   Process -> Connection -> IP
#
# into:
#
#   Domain -> Processes -> Traffic
#
# Example:
#
#   firefox.exe -> chatgpt.com
#   msedge.exe  -> chatgpt.com
#
# becomes:
#
#   chatgpt.com
#       processes: 2
#       traffic: ...
#
# Powers:
#   D = Domain View
#   P = Process→Domain Mapping
# ==========================================================


def known_domains(connections):
    """Distinct named domains across a process's connections."""
    domains = set()
    for (_proto, _lip, _lport, rip, _rport), cdata in connections.items():
        domain, _ = get_smart_domain_name(cdata, rip)
        if domain != "Unknown domain":
            domains.add(domain)
    return domains


def compute_domain_summary(rows=None):
    """Compute summary statistics for all domains across all processes."""
    rows = dict(compute_rows()) if rows is None else rows
    domain_stats = {}

    for proc_name, data in rows.items():
        for ckey, cdata in data.get("connections", {}).items():
            _proto, _lip, _lport, rip, _rport = ckey

            # Use smart domain naming
            domain, domain_source = get_smart_domain_name(cdata, rip)

            # Skip unknown domains for summary
            if domain == "Unknown domain":
                continue

            if domain not in domain_stats:
                domain_stats[domain] = {
                    "processes": set(),
                    "connections": 0,
                    "sent": 0,
                    "recv": 0,
                    "ips": set(),
                    "source": domain_source,
                }

            domain_stats[domain]["processes"].add(proc_name)
            domain_stats[domain]["connections"] += 1
            domain_stats[domain]["sent"] += cdata["sent"]
            domain_stats[domain]["recv"] += cdata["recv"]
            domain_stats[domain]["ips"].add(rip)

        for domain, h in data.get("history", {}).get("domains", {}).items():
            s = domain_stats.setdefault(domain, {
                "processes": set(), "connections": 0, "sent": 0, "recv": 0,
                "ips": set(), "source": h["source"],
            })
            s["processes"].add(proc_name)
            s["connections"] += h["conns"]
            s["sent"] += h["sent"]
            s["recv"] += h["recv"]
            s["ips"] |= h["ips"]

    # Convert sets to counts for display
    for domain, stats in domain_stats.items():
        stats["process_count"] = len(stats["processes"])
        stats["ip_count"] = len(stats["ips"])
        stats["total_bytes"] = stats["sent"] + stats["recv"]
        stats["is_ptr"] = is_ptr_domain(domain)

    return domain_stats


def compute_process_domain_mapping():
    """Compute process-to-domain mapping showing what each process talks to."""
    rows = dict(compute_rows())
    process_domains = {}

    for proc_name, data in rows.items():
        # Normalize process name to lowercase for aggregation
        normalized_name = proc_name.lower()

        domain_traffic = {}  # Track traffic per domain
        connections = 0
        total_bytes = 0

        for ckey, cdata in data.get("connections", {}).items():
            _proto, _lip, _lport, rip, _rport = ckey

            # Use smart domain naming
            domain, _ = get_smart_domain_name(cdata, rip)

            # Skip unknown domains
            if domain != "Unknown domain":
                if domain not in domain_traffic:
                    domain_traffic[domain] = 0
                domain_traffic[domain] += cdata["sent"] + cdata["recv"]

            connections += 1
            total_bytes += cdata["sent"] + cdata["recv"]

        for domain, h in data.get("history", {}).get("domains", {}).items():
            nbytes = h["sent"] + h["recv"]
            domain_traffic[domain] = domain_traffic.get(domain, 0) + nbytes
            connections += h["conns"]
            total_bytes += nbytes

        if domain_traffic:  # Only include processes that have domain connections
            # Find top domain by traffic
            top_domain = max(domain_traffic.items(), key=lambda kv: kv[1])
            top_domain_name, top_domain_bytes = top_domain
            traffic_share = (
                (top_domain_bytes / total_bytes * 100) if total_bytes > 0 else 0
            )

            # Classify process type
            process_type = classify_process_type(normalized_name)

            # Merge if this normalized process already exists
            if normalized_name in process_domains:
                existing = process_domains[normalized_name]
                existing["domains"].update(domain_traffic.keys())
                for domain, traffic in domain_traffic.items():
                    existing["domain_traffic"][domain] = (
                        existing["domain_traffic"].get(domain, 0) + traffic
                    )
                existing["connection_count"] += connections
                existing["total_bytes"] += total_bytes

                # Recalculate top domain after merge
                new_top = max(existing["domain_traffic"].items(), key=lambda kv: kv[1])
                existing["top_domain"] = new_top[0]
                existing["top_domain_bytes"] = new_top[1]
                existing["domain_count"] = len(existing["domains"])
                existing["traffic_share"] = (
                    (new_top[1] / existing["total_bytes"] * 100)
                    if existing["total_bytes"] > 0
                    else 0
                )
            else:
                process_domains[normalized_name] = {
                    "domains": set(domain_traffic.keys()),
                    "domain_traffic": domain_traffic,
                    "connection_count": connections,
                    "total_bytes": total_bytes,
                    "domain_count": len(domain_traffic),
                    "top_domain": top_domain_name,
                    "top_domain_bytes": top_domain_bytes,
                    "traffic_share": traffic_share,
                    "process_type": process_type,
                }

    return process_domains


def compute_rows():
    with stats_lock:
        rows = []
        for name, data in stats.items():
            copy = dict(data)
            copy["connections"] = dict(data.get("connections", {}))
            copy.pop("history", None)
            _merge_history(copy, data)  # private copy: prune may change it meanwhile
            rows.append((name, copy))

    unresolved = [r for r in rows if r[0].startswith("Unknown (")]
    if unresolved:
        rows = [r for r in rows if not r[0].startswith("Unknown (")]
        agg = {
            "pid": None,
            "sent": 0,
            "recv": 0,
            "last_sent": 0.0,
            "last_recv": 0.0,
            "connections": {},
        }
        for _, data in unresolved:
            agg["sent"] += data["sent"]
            agg["recv"] += data["recv"]
            agg["last_sent"] = max(agg["last_sent"], data.get("last_sent", 0.0))
            agg["last_recv"] = max(agg["last_recv"], data.get("last_recv", 0.0))
            merge_connections(agg["connections"], data.get("connections", {}))
            _merge_history(agg, data)
        rows.append((f"Unresolved / short-lived ({len(unresolved)} ports)", agg))
    return rows


def sort_rows(rows):
    def last_activity(kv):
        d = kv[1]
        return max(d.get("last_sent", 0.0), d.get("last_recv", 0.0))

    key_funcs = {
        "sent": lambda kv: kv[1]["sent"],
        "recv": lambda kv: kv[1]["recv"],
        "total": lambda kv: kv[1]["sent"] + kv[1]["recv"],
        "name": lambda kv: kv[0].lower(),
        "recent": last_activity,
    }
    rows = list(rows)
    rows.sort(
        key=key_funcs.get(sort_key, key_funcs["total"]), reverse=(sort_key != "name")
    )
    return rows


NUMBER_SORT_MAP = {
    "1": "name",
    "2": "sent",
    "3": "recv",
    "4": "total",
    "5": "recent",
}

CONN_NUMBER_SORT_MAP = {
    "1": "order",
    "2": "sent",
    "3": "recv",
    "4": "total",
    "5": "packets",
}
CONN_SORT_FUNCS = {
    "order": lambda kv: (kv[1]["first_seen"], kv[0]),
    "sent": lambda kv: (-kv[1]["sent"], kv[0]),
    "recv": lambda kv: (-kv[1]["recv"], kv[0]),
    "total": lambda kv: (-(kv[1]["sent"] + kv[1]["recv"]), kv[0]),
    "packets": lambda kv: (-kv[1]["packets"], kv[0]),
}

# Domain View sort options
DOMAIN_NUMBER_SORT_MAP = {
    "1": "domain",
    "2": "processes",
    "3": "connections",
    "4": "total_bytes",
    "5": "ips",
}
DOMAIN_SORT_FUNCS = {
    "domain": lambda kv: (kv[0].lower(),),
    "processes": lambda kv: (-kv[1]["process_count"], kv[0].lower()),
    "connections": lambda kv: (-kv[1]["connections"], kv[0].lower()),
    "total_bytes": lambda kv: (-kv[1]["total_bytes"], kv[0].lower()),
    "ips": lambda kv: (-kv[1]["ip_count"], kv[0].lower()),
}

# Sort configuration for different views
# Process → Domain Mapping sort options
PROCESS_DOMAIN_NUMBER_SORT_MAP = {
    "1": "process",
    "2": "domains",
    "3": "connections",
    "4": "traffic",
    "5": "type",
}
PROCESS_DOMAIN_SORT_FUNCS = {
    "process": lambda kv: (kv[0].lower(),),
    "domains": lambda kv: (-kv[1]["domain_count"], kv[0].lower()),
    "connections": lambda kv: (-kv[1]["connection_count"], kv[0].lower()),
    "traffic": lambda kv: (-kv[1]["total_bytes"], kv[0].lower()),
    "type": lambda kv: (kv[1]["process_type"], kv[0].lower()),
}

# Beacon Watch sort options
BEACON_NUMBER_SORT_MAP = {
    "1": "entity",
    "2": "interval",
    "3": "jitter",
    "4": "samples",
    "5": "last_contact",
}
BEACON_SORT_FUNCS = {
    "entity": lambda r: (r["entity"].lower(),),
    "interval": lambda r: (r["mean_interval"], r["entity"].lower()),
    "jitter": lambda r: (
        r["jitter_pct"],
        r["entity"].lower(),
    ),  # Lower jitter first (more regular)
    "samples": lambda r: (-r["samples"], r["entity"].lower()),  # More samples first
    "last_contact": lambda r: (
        -r["last_seen"],
        r["entity"].lower(),
    ),  # Most recent first
}

# Firewall Active Processes sort options
FIREWALL_NUMBER_SORT_MAP = {
    "1": "process",
    "2": "connections",
    "3": "domains",
    "4": "traffic",
    "5": "location",
}


def _get_firewall_sort_key_func(sort_key):
    """Dynamic sort function for firewall view to handle computed fields.

    Since some sort keys require computed values (like domain count or location),
    this function returns the appropriate sorting function for the requested key.

    Args:
        sort_key: The sort key to generate a function for

    Returns:
        function: Sort function that takes a (process_name, data) tuple and returns sort key
    """

    def process_func(kv):
        return (kv[0].lower(),)

    def connections_func(kv):
        return (-len(kv[1].get("connections", {})), kv[0].lower())

    def domains_func(kv):
        return (-len(known_domains(kv[1].get("connections", {}))), kv[0].lower())

    def traffic_func(kv):
        return (-(kv[1]["sent"] + kv[1]["recv"]), kv[0].lower())

    def location_func(kv):
        return (process_exe_location(kv[1].get("pid")), kv[0].lower())

    funcs = {
        "process": process_func,
        "connections": connections_func,
        "domains": domains_func,
        "traffic": traffic_func,
        "location": location_func,
    }
    return funcs.get(sort_key, traffic_func)


# App Inventory sort options
APP_INVENTORY_NUMBER_SORT_MAP = {
    "1": "name",
    "2": "location",
    "3": "reviewed",
    "4": "firewall",
    "5": "connections",
}


def _get_app_inventory_sort_key_func(sort_key):
    """Dynamic sort function for app inventory to handle firewall state.

    Since firewall state sorting requires custom priority (Block > Unknown > Allow),
    this function returns the appropriate sorting function for the requested key.

    Args:
        sort_key: The sort key to generate a function for

    Returns:
        function: Sort function that takes an app dict and returns sort key
    """

    def name_func(app):
        return (app["name"].lower(),)

    def location_func(app):
        return (app["location"], app["name"].lower())

    def reviewed_func(app):
        return (not app["reviewed"], app["name"].lower())  # Unreviewed first

    def firewall_func(app):
        # Sort by firewall state: Block first, then Unknown, then Allow
        state = app["firewall_state"]
        # Extract the main state (Block, Allow, Unknown) from the full state string
        state_main = state.split()[0] if state else "Unknown"
        state_priority = {"Block": 0, "Unknown": 1, "Allow": 2}.get(state_main, 1)
        return (state_priority, app["name"].lower())

    def connections_func(app):
        return (-app.get("connections", 0), app["name"].lower())

    funcs = {
        "name": name_func,
        "location": location_func,
        "reviewed": reviewed_func,
        "firewall": firewall_func,
        "connections": connections_func,
    }
    return funcs.get(sort_key, name_func)


def move_selection(delta):
    global selected_process, selected_connection_key
    order = list(last_rendered_order)
    if not order:
        return
    if selected_process in order:
        idx = order.index(selected_process)
    else:
        idx = 0 if delta >= 0 else len(order) - 1
    idx = max(0, min(len(order) - 1, idx + delta))
    new_sel = order[idx]
    if new_sel != selected_process:
        selected_connection_key = None
    selected_process = new_sel


def move_connection_selection(delta):
    global selected_connection_key, selected_connection_index_hint
    order = list(last_rendered_connections)
    if not order:
        return
    if selected_connection_key in order:
        idx = order.index(selected_connection_key)
    else:
        idx = max(0, min(len(order) - 1, selected_connection_index_hint))
    idx = max(0, min(len(order) - 1, idx + delta))
    selected_connection_key = order[idx]
    selected_connection_index_hint = idx


def _move_scroll_global(name, delta):
    """Generic scroll handler that clamps a module-level integer at zero.

    This is used by all the specific move_X_scroll functions to avoid
    code duplication while maintaining named wrappers for existing call sites.
    """
    globals()[name] = max(0, globals()[name] + delta)


# Which module-level scroll-offset global each view scrolls. Views not listed
# here (main/detail) move a row *selection* instead and are handled separately;
# anything unlisted falls back to the inspector's offset.
VIEW_SCROLL_OFFSETS = {
    "beacons": "beacon_scroll_offset",
    "file_investigation": "file_investigation_scroll_offset",
    "domains": "domain_scroll_offset",
    "process_domains": "process_domain_scroll_offset",
    "timeline": "timeline_scroll_offset",
    "system_summary": "system_summary_scroll_offset",
    "help": "help_scroll_offset",
    "learning": "learning_scroll_offset",
    "firewall_detail": "firewall_detail_scroll_offset",
    "app_detail": "app_detail_scroll_offset",
    "raw_firewall": "raw_firewall_scroll_offset",
    "inspector": "inspector_scroll_offset",
}


def handle_selection_scroll(
    items, selected_item, scroll_offset, delta, max_rows_hint=None
):
    """Generic helper for handling selection and scrolling in lists.

    Args:
        items: List of items to select from
        selected_item: Currently selected item
        scroll_offset: Current scroll offset
        delta: Movement delta (+1 or -1)
        max_rows_hint: Optional hint for visible rows

    Returns:
        tuple: (new_selected_item, new_scroll_offset)
    """
    if not items:
        return selected_item, scroll_offset

    if max_rows_hint is None:
        max_rows = max(3, get_body_height() - 8)
    else:
        max_rows = max_rows_hint

    # Find current index
    try:
        current_idx = items.index(selected_item)
    except ValueError:
        current_idx = 0 if delta >= 0 else len(items) - 1

    # Calculate new index
    new_idx = max(0, min(len(items) - 1, current_idx + delta))
    new_selected_item = items[new_idx]

    # Auto-scroll to keep selection visible
    new_scroll_offset = scroll_offset
    if new_idx < new_scroll_offset:
        new_scroll_offset = new_idx
    elif new_idx >= new_scroll_offset + max_rows:
        new_scroll_offset = new_idx - max_rows + 1

    return new_selected_item, new_scroll_offset


def _ensure_selection_visible(names, selected_name, scroll_offset, max_rows):
    """Keep selected item visible in scrollable list, with fallback to first item.

    This function ensures that the selected item remains visible in the viewport
    by adjusting the scroll offset. If the selected item is no longer in the list
    (e.g., process exited), it falls back to selecting the first item.

    Args:
        names: List of item names currently displayed
        selected_name: Currently selected item name
        scroll_offset: Current scroll offset
        max_rows: Maximum number of visible rows

    Returns:
        tuple: (selected_name, scroll_offset) adjusted for visibility
    """
    if selected_name in names:
        idx = names.index(selected_name)
        if idx < scroll_offset:
            scroll_offset = idx
        elif idx >= scroll_offset + max_rows:
            scroll_offset = idx - max_rows + 1
    elif names:
        selected_name = names[0]
        scroll_offset = 0
    return selected_name, scroll_offset


def compute_max_rows(available_lines, chrome=4):
    """Calculate maximum number of rows that can fit in available space.

    Args:
        available_lines: Available vertical space (None to use terminal height)
        chrome: Number of lines reserved for panel chrome (borders, headers)

    Returns:
        int: Maximum number of displayable rows (minimum 3)
    """
    base = available_lines if available_lines is not None else get_body_height()
    return max(3, base - chrome)


def build_scrollable_text_panel(
    lines,
    scroll_offset,
    *,
    title_base,
    border_style,
    back_hint="Esc back",
    chrome=2,
    available_lines=None,
):
    """Build a scrollable text panel with proper scrolling hints and range display.

    This is used for all scrollable text panels (help, learning, inspector, etc.)
    to provide consistent scrolling behavior and visual feedback.

    Args:
        lines: List of text lines to display
        scroll_offset: Current scroll offset (will be clamped to valid range)
        title_base: Base title string for the panel
        border_style: Rich border style
        back_hint: Navigation hint text
        chrome: Number of lines for panel chrome
        available_lines: Available vertical space (None to use terminal height)

    Returns:
        tuple: (Panel object, adjusted scroll_offset)
    """
    total_lines = len(lines)
    max_visible = compute_max_rows(available_lines, chrome)
    scroll_offset = max(0, min(scroll_offset, max(0, total_lines - max_visible)))
    window = lines[scroll_offset : scroll_offset + max_visible]

    scrolled_up = scroll_offset > 0
    scrolled_down = scroll_offset + len(window) < total_lines
    scroll_hint = ""
    if scrolled_up and scrolled_down:
        scroll_hint = "  [more above/below - arrows/PgUp/PgDn/Home/End]"
    elif scrolled_up:
        scroll_hint = "  [more above - Home to jump to top]"
    elif scrolled_down:
        scroll_hint = "  [more below - End to jump to bottom]"

    range_lo = scroll_offset + 1 if total_lines else 0
    range_hi = scroll_offset + len(window)
    title = f"{title_base}  (lines {range_lo}-{range_hi}/{total_lines})  {back_hint}{scroll_hint}"

    panel = Panel("\n".join(window), title=title, border_style=border_style)
    panel.height = max_visible + chrome
    return panel, scroll_offset


def style_firewall_state(firewall_state):
    """Apply color styling to firewall state based on action type."""
    if firewall_state.startswith("Allow"):
        return f"[bold green]{firewall_state}[/]"
    elif firewall_state.startswith("Block"):
        return f"[bold red]{firewall_state}[/]"
    else:
        return f"[bold yellow]{firewall_state}[/]"


def format_parent_display(exe_info):
    """Format parent process information for display.

    Returns formatted string like 'explorer.exe (PID 4212)' or handles cases
    where name lookup failed (parent_name already set to 'PID N').

    Args:
        exe_info: Process info dictionary containing parent_name and parent_pid

    Returns:
        str: Formatted parent process display string
    """
    name = exe_info.get("parent_name", "-")
    if name.startswith("PID "):
        return name
    ppid = exe_info.get("parent_pid")
    return f"{name} (PID {ppid})" if ppid else name


def exe_location_badge(exe_path):
    """Generate a color-coded badge for executable location classification."""
    return EXE_LOCATION_BADGE.get(classify_exe_location(exe_path), "[dim]-[/]")


def style_reviewed_status(reviewed):
    """Apply color styling to application review status."""
    if reviewed:
        return "[bold green]Approved[/]"
    else:
        return "[bold yellow]Unreviewed[/]"


def firewall_active_processes(rows):
    """Active-process list as the firewall panel shows it: user apps first,
    then system processes, then the current firewall sort.
    Returns (sorted [(name, data)], user_count, system_count)."""
    user_processes, system_processes = [], []
    for proc_name, data in rows.items():
        if is_system_process(proc_name, process_exe_location(data.get("pid"))):
            system_processes.append((proc_name, data))
        else:
            user_processes.append((proc_name, data))
    ordered = sorted(
        user_processes + system_processes,
        key=_get_firewall_sort_key_func(firewall_sort_key),
    )
    return ordered, len(user_processes), len(system_processes)


def move_firewall_selection(delta):
    """Move selection in firewall views across different modes.

    Handles selection movement for Active Network Processes, Running Processes,
    and All User Apps views, ensuring selection stays visible and synchronized
    with the currently displayed filtered list.

    Args:
        delta: Movement direction (+1 for down, -1 for up)
    """
    global selected_firewall_rule, selected_app_inventory_item
    global firewall_scroll_offset, app_inventory_scroll_offset

    if firewall_view_mode == "active":
        # Get current processes
        try:
            sorted_processes, _, _ = firewall_active_processes(dict(compute_rows()))
            process_names = [name for name, _ in sorted_processes]

            if not process_names:
                return

            selected_firewall_rule, firewall_scroll_offset = handle_selection_scroll(
                process_names, selected_firewall_rule, firewall_scroll_offset, delta
            )

        except Exception:
            pass

    elif firewall_view_mode == "inventory" or firewall_view_mode == "all_apps":
        # Get the SAME filtered list the panel is currently showing -
        # navigating an unfiltered list while the screen shows a
        # filtered one would let '[' / ']' land on rows you can't see.
        apps = get_filtered_apps_for_view(firewall_view_mode)

        # Sort the apps the same way the panel displays them
        # This prevents skipping items when navigating with arrow keys
        sorted_apps = sorted(
            apps,
            key=_get_app_inventory_sort_key_func(app_inventory_sort_key),
        )

        # Use exact name matching for selection (case-sensitive)
        app_names = [app["name"] for app in sorted_apps]

        if not app_names:
            return

        selected_app_inventory_item, app_inventory_scroll_offset = (
            handle_selection_scroll(
                app_names,
                selected_app_inventory_item,
                app_inventory_scroll_offset,
                delta,
            )
        )


# ============================================================================
# WINDOWS NETWORK TOOLS (w) - Windows' own commands, kept apart from NetSpy
# ============================================================================
# NetSpy itself only observes. This view just starts Windows' own network
# tools - nothing is reimplemented. Console commands run together in ONE new
# PowerShell window (their output never mixes into NetSpy's live screen);
# windowed tools simply open.

_SYS32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

WIN_TOOL_GROUPS = {
    "check": "CHECK  [dim](read-only)[/]",
    "fix": "FIX  [dim](changes settings - yellow ones ask you to confirm)[/]",
    "open": "OPEN  [dim](Windows' own windows)[/]",
}

# kind "ps" = PowerShell run in the shared new window, "open" = opened by the shell.
# warn = shown in yellow and needs a second Enter on "Run selected".
WIN_TOOLS = [
    {"group": "check", "name": "Adapter info", "cmd": "Get-NetIPConfiguration", "kind": "ps",
     "run": "Get-NetIPConfiguration -Detailed"},
    {"group": "check", "name": "DNS servers", "cmd": "Get-DnsClientServerAddress", "kind": "ps",
     "run": "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | "
            "Format-Table InterfaceAlias, ServerAddresses -AutoSize"},
    {"group": "check", "name": "DNS cache", "cmd": "Get-DnsClientCache", "kind": "ps",
     "run": "Get-DnsClientCache | Sort-Object Entry | Format-Table Entry, Data, TimeToLive -AutoSize"},
    {"group": "check", "name": "Hosts file", "cmd": "active lines of drivers\\etc\\hosts", "kind": "ps",
     "run": r"$h = Get-Content (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') | "
            r"Where-Object { $_ -notmatch '^\s*(#|$)' }; "
            r"if ($h) { $h } else { 'No active entries - only comments.' }"},
    {"group": "check", "name": "Proxy", "cmd": "netsh winhttp show proxy + user proxy", "kind": "ps",
     "run": r"netsh winhttp show proxy; "
            r"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | "
            r"Format-List ProxyEnable, ProxyServer, AutoConfigURL"},
    {"group": "check", "name": "ARP / neighbors", "cmd": "Get-NetNeighbor (+ shared-MAC warning)", "kind": "ps",
     # Multicast (224-239.x, MAC 01-00-5E-...) repeats once per adapter - not a real device.
     "run": "$n = Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -notin 'Unreachable','Incomplete' "
            "-and $_.LinkLayerAddress -notin '','00-00-00-00-00-00','FF-FF-FF-FF-FF-FF' "
            "-and $_.LinkLayerAddress -notlike '01-00-5E-*' }; "
            "$n | Sort-Object InterfaceAlias, IPAddress | Format-Table InterfaceAlias, IPAddress, LinkLayerAddress, State -AutoSize | Out-Host; "
            "$d = @($n | Group-Object LinkLayerAddress | ForEach-Object { $ips = @($_.Group.IPAddress | Sort-Object -Unique); "
            "if ($ips.Count -gt 1) { [pscustomobject]@{ Name = $_.Name; IPs = $ips } } }); "
            "if ($d) { foreach ($g in $d) { Write-Host ('WARNING: ' + $g.Name + ' is used by ' + ($g.IPs -join ', ') + "
            "' - possible ARP spoofing (or one device with several IPs)') -ForegroundColor Yellow } } "
            "else { Write-Host 'No MAC address is shared by two IPs.' -ForegroundColor Green }"},
    {"group": "check", "name": "Route table", "cmd": "Get-NetRoute", "kind": "ps",
     "run": "Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric | "
            "Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -AutoSize"},
    {"group": "check", "name": "Connectivity check", "cmd": "ping router, ping 1.1.1.1, resolve a name", "kind": "ps",
     "run": "$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Sort-Object RouteMetric | Select-Object -First 1).NextHop; "
            "foreach ($t in @(@('Router', $gw), @('Internet', '1.1.1.1'))) { "
            "if (-not $t[1]) { Write-Host 'Router    no default gateway' -ForegroundColor Red; continue }; "
            "$ok = Test-Connection $t[1] -Count 2 -Quiet; "
            "Write-Host ('{0,-9} {1,-16} {2}' -f $t[0], $t[1], $(if ($ok) { 'reachable' } else { 'NO REPLY' })) "
            "-ForegroundColor $(if ($ok) { 'Green' } else { 'Red' }) }; "
            "try { $r = Resolve-DnsName microsoft.com -Type A -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1; "
            "Write-Host ('DNS       microsoft.com -> ' + $r.IPAddress) -ForegroundColor Green } "
            "catch { Write-Host 'DNS       lookup FAILED' -ForegroundColor Red }"},
    {"group": "check", "name": "Wi-Fi status", "cmd": "netsh wlan show interfaces", "kind": "ps",
     "run": "netsh wlan show interfaces"},
    {"group": "check", "name": "Firewall status", "cmd": "Get-NetFirewallProfile", "kind": "ps",
     "run": "Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize"},
    {"group": "fix", "name": "Flush DNS", "cmd": "ipconfig /flushdns", "kind": "ps",
     "run": "ipconfig /flushdns"},
    {"group": "fix", "name": "Clear ARP cache", "cmd": "netsh interface ip delete arpcache", "kind": "ps",
     "admin": True, "run": "netsh interface ip delete arpcache"},
    {"group": "fix", "name": "Renew IP", "cmd": "ipconfig /release + /renew", "kind": "ps",
     "admin": True, "warn": "drops the connection for a few seconds",
     "run": "ipconfig /release | Out-Null; ipconfig /renew"},
    {"group": "fix", "name": "Reset Winsock", "cmd": "netsh winsock reset", "kind": "ps",
     "admin": True, "warn": "restart needed", "run": "netsh winsock reset"},
    {"group": "fix", "name": "Reset TCP/IP", "cmd": "netsh int ip reset", "kind": "ps",
     "admin": True, "warn": "restart needed", "run": "netsh int ip reset"},
    {"group": "open", "name": "Network Connections", "cmd": "ncpa.cpl", "kind": "open", "run": "ncpa.cpl"},
    {"group": "open", "name": "Firewall (advanced)", "cmd": "wf.msc", "kind": "open", "run": "wf.msc"},
    {"group": "open", "name": "Resource Monitor", "cmd": "resmon (Network tab)", "kind": "open",
     "run": os.path.join(_SYS32, "resmon.exe")},
    {"group": "open", "name": "Network settings", "cmd": "Settings > Network (Network reset is here)", "kind": "open",
     "run": "ms-settings:network-advancedsettings"},
]

# Menu state: the keyboard thread writes it, the render thread reads it.
_wt_lock = threading.Lock()
_wt = {"pos": 0, "picked": set(), "msg": "", "confirm": False, "typed": "", "typed_at": 0.0}


def _launch_win_tools(numbers):
    """Opens the windowed tools, then runs every console tool in one new
    PowerShell window. Returns a one-line status message."""
    started, failed, ps_parts = [], [], []
    for num in numbers:
        t = WIN_TOOLS[num - 1]
        if t["kind"] == "open":
            try:
                os.startfile(t["run"])
                started.append(t["name"])
            except OSError:
                failed.append(t["name"])
        else:
            ps_parts.append(
                "Write-Host ''; "
                f"Write-Host '=== {num}  {_ps_quote(t['name'])}  ({_ps_quote(t['cmd'])}) ===' -ForegroundColor Cyan; "
                f"try {{ & {{ {t['run']} }} | Out-Host }} catch {{ Write-Host $_ -ForegroundColor Red }}"
            )
    if ps_parts:
        script = (
            "$Host.UI.RawUI.WindowTitle = 'NetSpy - Windows network tools'\n"
            + "\n".join(ps_parts)
            + "\nWrite-Host ''; Write-Host 'Done - you can close this window.' -ForegroundColor Green"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        try:
            subprocess.Popen(
                ["powershell", "-NoProfile", "-NoExit", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", encoded],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            started.append(f"{len(ps_parts)} command(s) in a new PowerShell window")
        except OSError:
            failed.append("PowerShell window")
    msg = f"[green]{datetime.now().strftime('%H:%M:%S')} started:[/] " + ", ".join(started) if started else ""
    if failed:
        msg += ("   " if msg else "") + "[red]could not start:[/] " + ", ".join(failed)
    return msg


def win_tools_move(delta):
    rows = len(WIN_TOOLS) + 2  # tools + Run + Back
    with _wt_lock:
        _wt["pos"] = (_wt["pos"] + delta) % rows
        _wt["confirm"] = False
        _wt["typed"] = ""


def win_tools_key(ch):
    """Keys for the Windows tools view. Returns "back" to leave the view,
    True when the key was used here, False to let the normal handler see it."""
    n = len(WIN_TOOLS)
    with _wt_lock:
        if ch.isdigit():
            # Digits jump to a tool; a second digit within a second makes 10-99.
            now = time.time()
            if now - _wt["typed_at"] > 1:
                _wt["typed"] = ""
            _wt["typed_at"] = now
            if int(_wt["typed"] + ch) > n:
                _wt["typed"] = ""
            _wt["typed"] += ch
            if int(_wt["typed"]) >= 1:
                _wt["pos"] = int(_wt["typed"]) - 1
            _wt["confirm"] = False
            return True
        if ch not in ("\r", " "):
            return False
        _wt["typed"] = ""
        pos = _wt["pos"]
        if pos == n + 1:
            return "back"
        if pos < n:
            t = WIN_TOOLS[pos]
            if t.get("admin") and not is_admin():
                _wt["msg"] = "[yellow]That one needs NetSpy running as Administrator.[/]"
            elif pos + 1 in _wt["picked"]:
                _wt["picked"].discard(pos + 1)
            else:
                _wt["picked"].add(pos + 1)
            _wt["confirm"] = False
            return True
        # "Run selected"
        numbers = sorted(_wt["picked"])
        if not numbers:
            _wt["msg"] = "[yellow]Select at least one tool first.[/]"
            return True
        risky = [WIN_TOOLS[i - 1] for i in numbers if WIN_TOOLS[i - 1].get("warn")]
        if risky and not _wt["confirm"]:
            _wt["confirm"] = True
            _wt["msg"] = "[bold yellow]Press Enter again to run:[/] " + ", ".join(
                f"{t['name']} ({t['warn']})" for t in risky
            )
            return True
        _wt["confirm"] = False
        _wt["picked"].clear()
    msg = _launch_win_tools(numbers)  # outside the lock - Popen/startfile can take a moment
    with _wt_lock:
        _wt["msg"] = msg
    return True


def build_win_tools_panel(available_lines=None):
    from rich.markup import escape

    admin = is_admin()
    n = len(WIN_TOOLS)
    with _wt_lock:
        pos, picked, msg = _wt["pos"], set(_wt["picked"]), _wt["msg"]

    lines, sel_line, group = [], 0, None
    for i, t in enumerate(WIN_TOOLS):
        if t["group"] != group:
            group = t["group"]
            if lines:
                lines.append("")
            lines.append(f"[bold]{WIN_TOOL_GROUPS[group]}[/]")
        on = (i + 1) in picked
        locked = t.get("admin") and not admin
        arrow = "[bold white]>[/]" if i == pos else " "
        box_ = "\\[x]" if on else "\\[ ]"
        note = "needs Administrator" if locked else escape(t["cmd"])
        if t.get("warn") and not locked:
            note += f"  [yellow]({t['warn']})[/]"
        style = "dim" if locked else "bold green" if on else "bold white" if i == pos else "white"
        if i == pos:
            sel_line = len(lines)
        lines.append(f"{arrow} [{style}]{box_} {i + 1:>2}  {t['name']:<22}[/] [dim]{note}[/]")

    lines.append("")
    for j, label in ((n, "Run selected"), (n + 1, "Back to NetSpy")):
        if pos == j:
            sel_line = len(lines)
            lines.append(f"[bold white]> {label}[/]")
        else:
            lines.append(f"  [cyan]{label}[/]")

    # Keep the selected row on screen when the terminal is short.
    max_rows = compute_max_rows(available_lines, chrome=7)
    start = 0
    if len(lines) > max_rows:
        start = max(0, min(sel_line - max_rows // 2, len(lines) - max_rows))
    body = lines[start : start + max_rows]

    selected = ", ".join(str(x) for x in sorted(picked)) or "none"
    footer = f"[bold green]Selected: {selected}[/]"
    if msg:
        footer += "\n" + msg
    note = (
        "[dim]These are Windows' own tools, not part of NetSpy. Console commands run together "
        "in one new PowerShell window; windowed tools open on their own.[/]"
    )
    return Group(
        Panel(
            "\n".join(body),
            title=f"Windows network tools   Up/Down move   1-{n} jump   Enter select   Esc/w back",
            border_style="bright_blue",
        ),
        Panel(footer + "\n" + note, border_style="bright_blue"),
    )


# ============================================================================
# 8. KEYBOARD HANDLING - User input processing
# ============================================================================

ESC_PARENT_VIEW = {
    "app_detail": "firewall",
    "firewall_detail": "firewall",
    "raw_firewall": "firewall",
    "inspector": "detail",
    "file_investigation": "inspector",
}


def keyboard_listener_loop():
    global sort_key, show_listening, show_tree, show_explainer, hide_idle, view_mode, selected_process
    global DEVELOPER_MODE
    global hide_main_in_detail, conn_sort_key
    global selected_firewall_rule, selected_raw_firewall_rule, firewall_view_mode
    global selected_app_inventory_item, app_filter_mode, app_detail_scroll_offset
    global \
        domain_sort_key, \
        process_domain_sort_key, \
        beacon_sort_key, \
        firewall_sort_key, \
        app_inventory_sort_key
    if not HAVE_MSVCRT:
        return
    while not stop_event.is_set():
        if msvcrt.kbhit():
            try:
                raw = msvcrt.getch()
            except Exception:
                raw = b""

            if raw == b"\x1b":
                # Esc key - go back to the parent view (everything else -> main)
                view_mode = ESC_PARENT_VIEW.get(view_mode, "main")
                continue
            elif raw in (b"\xe0", b"\x00"):
                try:
                    code = msvcrt.getch()
                except Exception:
                    code = b""
                if view_mode == "win_tools":
                    if code in (b"H", b"P"):
                        win_tools_move(-1 if code == b"H" else 1)
                    continue
                if code == b"H":
                    _arrow_scroll(-1)
                elif code == b"P":
                    _arrow_scroll(1)
                elif code == b"I":
                    _arrow_scroll(-_page_size())
                elif code == b"Q":
                    _arrow_scroll(_page_size())
                elif code == b"G":
                    _scroll_to("top")
                elif code == b"O":
                    _scroll_to("bottom")
                continue

            try:
                ch = raw.decode(errors="ignore").lower()
            except Exception:
                ch = ""

            if view_mode == "win_tools":
                used = win_tools_key(ch)
                if used == "back":
                    view_mode = "main"
                if used:
                    continue

            if ch == "q":
                stop_event.set()
            elif ch in NUMBER_SORT_MAP:
                if view_mode == "main":
                    sort_key = NUMBER_SORT_MAP[ch]
                elif view_mode == "detail":
                    conn_sort_key = CONN_NUMBER_SORT_MAP.get(ch, conn_sort_key)
                elif view_mode == "domains":
                    domain_sort_key = DOMAIN_NUMBER_SORT_MAP.get(ch, domain_sort_key)
                elif view_mode == "process_domains":
                    process_domain_sort_key = PROCESS_DOMAIN_NUMBER_SORT_MAP.get(
                        ch, process_domain_sort_key
                    )
                elif view_mode == "beacons":
                    beacon_sort_key = BEACON_NUMBER_SORT_MAP.get(ch, beacon_sort_key)
                elif view_mode == "firewall":
                    if firewall_view_mode == "active":
                        firewall_sort_key = FIREWALL_NUMBER_SORT_MAP.get(
                            ch, firewall_sort_key
                        )
                    elif firewall_view_mode in ("inventory", "all_apps"):
                        app_inventory_sort_key = APP_INVENTORY_NUMBER_SORT_MAP.get(
                            ch, app_inventory_sort_key
                        )
            elif ch == "r":
                if view_mode == "firewall" or view_mode == "firewall_detail":
                    view_mode = "raw_firewall"
                    selected_raw_firewall_rule = None
                elif view_mode == "raw_firewall":
                    view_mode = "firewall"
                else:
                    sort_key = "recv"
            elif ch == "c":
                with stats_lock:
                    stats.clear()
            elif ch == "h":
                if view_mode == "help":
                    view_mode = "main"
                else:
                    view_mode = "help"
            elif ch == "?":
                if view_mode == "learning":
                    view_mode = "main"
                else:
                    view_mode = "learning"
            elif ch == "j":
                DEVELOPER_MODE = not DEVELOPER_MODE
            elif ch == "l":
                show_listening = not show_listening
            elif ch == "b":
                if view_mode in ("firewall", "firewall_detail", "app_detail"):
                    label, exe = firewall_selected_target()
                    if label:
                        apply_firewall_action(label, exe, "Block")
                elif view_mode == "raw_firewall":
                    if selected_raw_firewall_rule:
                        modify_firewall_rule(selected_raw_firewall_rule, "Block")
                elif view_mode == "beacons":
                    view_mode = "main"
                else:
                    view_mode = "beacons"
            elif ch == "a":
                if view_mode in ("firewall", "firewall_detail", "app_detail"):
                    label, exe = firewall_selected_target()
                    if label:
                        apply_firewall_action(label, exe, "Allow")
                elif view_mode == "raw_firewall":
                    if selected_raw_firewall_rule:
                        modify_firewall_rule(selected_raw_firewall_rule, "Allow")
            elif ch == "x":
                if view_mode in ("firewall", "firewall_detail", "app_detail"):
                    label, exe = firewall_selected_target()
                    if label:
                        apply_firewall_action(label, exe, "Default")
            elif ch == "n":
                # Cycle which category of app Running Processes / All
                # User Apps shows - "user" (default) hides everything
                # classify_exe_location tagged "system", so scanning
                # System32/SysWOW64 doesn't turn these into a
                # thousand-row list. 'x' was already taken by Default,
                # so this got 'n' instead.
                if view_mode == "firewall" and firewall_view_mode in (
                    "inventory",
                    "all_apps",
                ):
                    idx = APP_FILTER_MODES.index(app_filter_mode)
                    app_filter_mode = APP_FILTER_MODES[
                        (idx + 1) % len(APP_FILTER_MODES)
                    ]
                    selected_app_inventory_item = None
            elif ch == "k":
                # (was 'a') bulk mark-all-reviewed, inventory/all_apps only -
                # limited to whatever the current category filter is
                # showing, so "mark all reviewed" can't silently touch
                # hundreds of hidden system apps.
                if view_mode == "firewall" and (
                    firewall_view_mode == "inventory"
                    or firewall_view_mode == "all_apps"
                ):
                    processes = get_filtered_apps_for_view(firewall_view_mode)
                    for proc in processes:
                        update_application_review(proc["name"], True)
            elif ch == "d":
                if view_mode == "domains":
                    view_mode = "main"
                else:
                    view_mode = "domains"
            elif ch == "p":
                if view_mode == "process_domains":
                    view_mode = "main"
                else:
                    view_mode = "process_domains"
            elif ch == "t":
                if view_mode == "timeline":
                    view_mode = "main"
                else:
                    view_mode = "timeline"
            elif ch == "s":
                if view_mode == "system_summary":
                    view_mode = "main"
                else:
                    view_mode = "system_summary"
            elif ch == "f":
                if view_mode == "firewall":
                    view_mode = "main"
                else:
                    view_mode = "firewall"
                    selected_firewall_rule = None
                    firewall_view_mode = "active"  # Reset to active mode
            elif ch == "w":
                view_mode = "main" if view_mode == "win_tools" else "win_tools"
            elif ch == "i":
                if view_mode == "inspector" and selected_process:
                    view_mode = "file_investigation"
                elif view_mode == "file_investigation":
                    view_mode = "inspector"
                elif view_mode == "firewall":
                    # Toggle between active processes and running processes
                    if firewall_view_mode == "active":
                        firewall_view_mode = "inventory"
                    elif firewall_view_mode == "inventory":
                        firewall_view_mode = "active"
                    selected_firewall_rule = None
            elif ch == "u":
                if view_mode == "firewall":
                    # Toggle between active processes and all user apps
                    if firewall_view_mode == "active":
                        firewall_view_mode = "all_apps"
                    elif firewall_view_mode == "all_apps":
                        firewall_view_mode = "active"
                    elif firewall_view_mode == "inventory":
                        firewall_view_mode = "all_apps"
                    selected_firewall_rule = None
            elif ch == "y":
                show_tree = not show_tree
            elif ch == "m":
                hide_main_in_detail = not hide_main_in_detail
            elif ch == "e":
                # Toggle the beginner "what am I looking at?" tips bar.
                show_explainer = not show_explainer
            elif ch == "o":
                hide_idle = not hide_idle
            elif ch == "g":
                start_test_burst()
            elif ch == "\r":  # Enter
                if view_mode == "main":
                    if not selected_process and last_rendered_order:
                        selected_process = last_rendered_order[0]
                    if selected_process:
                        view_mode = "detail"
                elif view_mode == "detail" and selected_connection_key:
                    view_mode = "inspector"
                elif (
                    view_mode == "firewall"
                    and firewall_view_mode == "active"
                    and selected_firewall_rule
                ):
                    view_mode = "firewall_detail"
                elif (
                    view_mode == "firewall"
                    and (
                        firewall_view_mode == "inventory"
                        or firewall_view_mode == "all_apps"
                    )
                    and selected_app_inventory_item
                ):
                    # Enter opens a detail panel with enough context to
                    # actually decide Allow vs Block (review status moved to Space)
                    view_mode = "app_detail"
                    app_detail_scroll_offset = 0
                elif view_mode == "firewall_detail":
                    # Go to main connection view for this process
                    selected_process = selected_firewall_rule
                    view_mode = "detail"
            elif ch == " ":
                # Toggle reviewed status without leaving the list -
                # works from the list itself or its detail view.
                if (
                    view_mode == "firewall"
                    and firewall_view_mode in ("inventory", "all_apps")
                    and selected_app_inventory_item
                ) or (view_mode == "app_detail" and selected_app_inventory_item):
                    processes = get_filtered_apps_for_view(firewall_view_mode)
                    for proc in processes:
                        if proc["name"] == selected_app_inventory_item:
                            update_application_review(proc["name"], not proc["reviewed"])
                            break
                elif (
                    view_mode == "detail"
                    or view_mode == "beacons"
                    or view_mode == "domains"
                    or view_mode == "process_domains"
                    or view_mode == "timeline"
                    or view_mode == "system_summary"
                    or view_mode == "help"
                    or view_mode == "learning"
                ):
                    view_mode = "main"
                elif view_mode == "app_detail":
                    view_mode = "firewall"
                elif view_mode == "firewall_detail":
                    view_mode = "firewall"
                elif view_mode == "raw_firewall":
                    view_mode = "firewall"
                elif view_mode == "firewall":
                    view_mode = "main"
        time.sleep(0.05)


def _page_size():
    return max(5, get_body_height() - 4)


def _arrow_scroll(delta):
    """Single scroll/selection dispatcher for Up/Down/PageUp/PageDown
    in every view. Up and Down used to each carry their own copy of
    this same if/elif chain.
    Now there's one: the firewall views move a row *selection* (since
    Enter acts on whichever row is picked); everything else just
    scrolls a plain list."""
    if view_mode == "firewall":
        move_firewall_selection(delta)
    elif view_mode == "firewall_detail":
        _move_scroll_global("firewall_detail_scroll_offset", delta)
    elif view_mode == "app_detail":
        _move_scroll_global("app_detail_scroll_offset", delta)
    else:
        _scroll(delta)


def _scroll(delta):
    if view_mode == "main":
        move_selection(delta)
    elif view_mode == "detail":
        move_connection_selection(delta)
    elif view_mode == "firewall":
        if firewall_view_mode in ("inventory", "all_apps"):
            _move_scroll_global("app_inventory_scroll_offset", delta)
        else:
            _move_scroll_global("firewall_scroll_offset", delta)
    else:
        _move_scroll_global(
            VIEW_SCROLL_OFFSETS.get(view_mode, "inspector_scroll_offset"), delta
        )


def _scroll_to(where):
    global main_scroll_offset, selected_process, selected_connection_key
    global \
        inspector_scroll_offset, \
        beacon_scroll_offset, \
        file_investigation_scroll_offset, \
        domain_scroll_offset
    global process_domain_scroll_offset, timeline_scroll_offset
    global system_summary_scroll_offset, firewall_scroll_offset
    global firewall_detail_scroll_offset, app_inventory_scroll_offset
    global app_detail_scroll_offset
    if view_mode == "main":
        if last_rendered_order:
            selected_process = (
                last_rendered_order[0] if where == "top" else last_rendered_order[-1]
            )
        main_scroll_offset = (
            0 if where == "top" else max(0, len(last_rendered_order) - 1)
        )
    elif view_mode == "detail":
        if last_rendered_connections:
            selected_connection_key = (
                last_rendered_connections[0]
                if where == "top"
                else last_rendered_connections[-1]
            )
    elif view_mode == "beacons":
        beacon_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "file_investigation":
        file_investigation_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "domains":
        domain_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "process_domains":
        process_domain_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "timeline":
        timeline_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "system_summary":
        system_summary_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "firewall":
        if firewall_view_mode == "inventory" or firewall_view_mode == "all_apps":
            app_inventory_scroll_offset = 0 if where == "top" else 10**9
        else:
            firewall_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "app_detail":
        app_detail_scroll_offset = 0 if where == "top" else 10**9
    elif view_mode == "firewall_detail":
        firewall_detail_scroll_offset = 0 if where == "top" else 10**9
    else:
        inspector_scroll_offset = 0 if where == "top" else 10**9


console = Console()
START_TIME = time.time()


def get_body_height():
    try:
        total = console.size.height
    except (AttributeError, OSError):
        total = 40
    used = 6
    if show_listening:
        used += 12
    with test_log_lock:
        if test_log:
            used += min(len(test_log), 14) + 2
    return max(6, total - used)


def render_height(renderable):
    try:
        lines = console.render_lines(renderable, console.options.update(height=None))
        return len(lines)
    except (AttributeError, OSError):
        return 0


def build_header(full_mode):
    uptime = int(time.time() - START_TIME)

    mode_txt = {
        "basic": "[bold green]BASIC[/] (private: NetSpy sends nothing - Windows ETW, no capture driver)",
        "advanced": "[bold cyan]ADVANCED[/] (packet capture + online lookups: reverse DNS, ipwho.is / ip-api.com / rdap.org)",
        "limited": "[bold yellow]LIMITED[/] (not elevated - connection list only, no byte counts)",
    }.get(CAPTURE_MODE, CAPTURE_MODE)

    admin_txt = "[green]yes[/]" if is_admin() else "[red]no[/]"

    lines = [
        f"Mode: {mode_txt}   |   Elevated: {admin_txt}   |   Uptime: {duration_fmt(uptime)}"
    ]

    if DEVELOPER_MODE:
        lines.append(
        f"DEV: tree-cap={MAX_TREE_CHILDREN} | "
        f"conn-cap/proc={MAX_CONNECTIONS_PER_PROCESS} | "
        f"retention={CONNECTION_RETENTION:.0f}s | "
        f"scroll=windowed | "
        f"attribution=confidence-aware | "
        f"beacon-watch=on"
        )


    if full_mode:
        lines.append(
            (f"Packets: {packet_count}" if CAPTURE_MODE == "advanced" else f"Net events: {packet_count}")
            + (f" [bold red](dropped {packets_dropped} - totals undercount)[/]" if packets_dropped else "")
            + (f"   |   Adapters: {len(_capture_ifaces)}" if CAPTURE_MODE == "advanced" else "")
            + f"   |   ETW: {'[green]' if etw_status.startswith('on') else '[yellow]'}{escape(etw_status)}[/]"
            + "   |   "
            f"Sort [1 name/2 sent/3 recv/4 total/5 recent]: "
            f"[bold]{sort_key}[/]   |   "
            f"Arrow keys navigate   PgUp/PgDn/Home/End jump   "
            f"Enter View Connections   Esc back   "
            f"l listening   b beacons   d domains   "
            f"p process→domain   t timeline   s system   "
            f"f firewall   y tree   m hide-main   "
            f"i file investigation   w windows tools   e tips   h help   ? concepts"
        )
    else:
        lines.append(
            f"Sort: [bold]{sort_key}[/]   "
            f"(byte counts and the inspector need an elevated terminal)   |   "
            f"l listening   f firewall   w windows tools   e tips   h help   ? concepts"
        )

    if capture_error:
        lines.append(
            f"[red]Capture unavailable:[/] {escape(capture_error)}"
            if not full_mode
            else f"[yellow]Capture warning:[/] {escape(capture_error)}"
        )

    avg_parse_ms = (
        (packet_parse_time / packet_parse_count) * 1000
        if packet_parse_count
        else 0.0
    )

    avg_consume_ms = (
        (consume_time / consume_count) * 1000
        if consume_count
        else 0.0
    )

    pps = (
        packet_count / max(1, (time.time() - START_TIME))
    )

    if DEVELOPER_MODE:
        lines.append(
        f"Performance: Parse={avg_parse_ms:.6f}ms   "
        f"Process={avg_consume_ms:.6f}ms   "
        f"PPS={pps:.0f}"
    )

    if DEVELOPER_MODE:
        lines.append(
        f"Debug: ParseCount={packet_parse_count} "
        f"ConsumeCount={consume_count}"
    )

    dns_size, dns_pending, dns_qdepth = dns_cache_snapshot()

    if DEVELOPER_MODE:
        lines.append(
        f"DNS cache: {dns_size}/{DNS_CACHE_MAX} entries | "
        f"pending: {dns_pending} | "
        f"queue: {dns_qdepth}/{DNS_QUEUE_MAX}"
    )


    title = (
    f"[bold green]NetSpy v{VERSION}[/] [yellow](DEV)[/]"
    if DEVELOPER_MODE
    else f"[bold green]NetSpy v{VERSION}[/]"
    )

    return Panel(
    "\n".join(lines),
    title=title,
    border_style="green",
    )




# Shared explanation dictionaries for consistency across the UI
TCP_STATE_EXPLANATIONS = {
    "ESTABLISHED": "ESTABLISHED means the TCP connection is fully open and data can flow in both directions. This is the normal state for active connections.",
    "LISTEN": "LISTEN means the process is waiting for incoming connections on this port. It's not actively connected to anything yet.",
    "TIME_WAIT": "TIME_WAIT means the connection is closing and waiting for packets to ensure the remote end received the closure. Normal after connections end.",
    "CLOSE_WAIT": "CLOSE_WAIT means the remote end closed the connection, but this end hasn't yet. The process should close it soon.",
    "SYN_SENT": "SYN_SENT means this end is trying to establish a connection but hasn't received a response yet.",
    "SYN_RECV": "SYN_RECV means this end received a connection request but hasn't completed the handshake yet.",
    "FIN_WAIT1": "FIN_WAIT1 means this end closed the connection and is waiting for the remote end to acknowledge.",
    "FIN_WAIT2": "FIN_WAIT2 means this end closed the connection and received acknowledgment, waiting for the remote end to close.",
    "CLOSING": "CLOSING means both ends tried to close simultaneously, rare but can happen in race conditions.",
    "LAST_ACK": "LAST_ACK means this end is waiting for the final acknowledgment before the connection fully closes.",
}

ALPN_PROTOCOL_EXPLANATIONS = {
    "HTTP/2": "HTTP/2 is the modern web protocol used by many websites. It multiplexes multiple requests over a single TCP connection for better performance.",
    "HTTP/1.1": "HTTP/1.1 is the traditional web protocol. It requires separate connections for each request unless keep-alive is used.",
    "SPDY/3.1": "SPDY was an early protocol that led to HTTP/2. It's now largely deprecated in favor of HTTP/2.",
}

TLS_VERSION_EXPLANATIONS = {
    "TLS 1.3": "TLS 1.3 is the latest and most secure version of TLS. It has faster handshakes and improved security over previous versions.",
    "TLS 1.2": "TLS 1.2 is widely used and secure. It's the minimum recommended version for modern connections.",
    "TLS 1.1": "TLS 1.1 is deprecated and should be avoided. It has known security weaknesses.",
    "TLS 1.0": "TLS 1.0 is obsolete and insecure. Modern browsers and servers should not use it.",
}

DOMAIN_SOURCE_EXPLANATIONS = {
    "DNS": "The name the program itself looked up just before connecting (seen via Windows' DNS events, also with encrypted DNS). As reliable as SNI.",
    "TLS SNI": "TLS SNI (Server Name Indication) is the hostname the application requested during the TLS handshake. It's usually more useful than PTR records for understanding where traffic is actually going.",
    "PTR": "PTR records are reverse DNS entries that map IPs to hostnames. They can be useful but may not reflect the actual service being accessed, as multiple domains can share the same IP.",
}

TRUST_ASSESSMENT_EXPLANATIONS = {
    "Looks normal": "No red flag found: the signature is valid, it does not run from Temp / Downloads / AppData, and it was not started by a script host. This is a quick check, not a malware scan.",
    "Worth investigating": "One red flag: unsigned, or running from Temp / Downloads / AppData, or started by a script host. Often harmless (per-user installs live in AppData) - check the publisher and path.",
    "Suspicious": "The file has multiple risk factors that together suggest it may be suspicious. This could include being unsigned, running from an unusual location, or being launched by a suspicious parent process.",
}

PARENT_RISK_EXPLANATIONS = {
    "Command-line launcher": "This process was launched by a command-line interpreter (PowerShell, CMD). This is common for legitimate automation but can also be used by malware for execution.",
    "Office-launched process": "This process was launched by a Microsoft Office application. This is normal for macros and document-embedded automation, but can be abused by malicious documents.",
    "Browser-launched process": "This process was launched by a web browser. This is normal for downloads and browser extensions, but can be used for drive-by downloads.",
    "System-launched process": "This process was launched by a Windows system component. This is typically normal behavior.",
    "LOLBin launcher": "This process was launched by a Living Off The Land Binary (LOLBin) - a legitimate system tool often abused by malware to evade detection.",
    "Standard parent": "This process was launched by a standard parent process with no obvious suspicious characteristics.",
}

LOCATION_EXPLANATIONS = {
    "system": "System files are located in Windows system directories. This is normal for OS components and system services.",
    "program_files": "Program Files is the standard location for installed applications. This is generally considered safe and normal.",
    "store_app": "WindowsApps holds apps installed from the Microsoft Store or as MSIX packages. The folder is protected by Windows and each app is signed, so this is normal.",
    "temp": "The Temp folder is for temporary files. Executables running from here are unusual for long-running applications and could indicate installer behavior, downloaded executables, or some malware.",
    "appdata": "AppData is for application data. Executables here are common for user-installed software, updaters, and some legitimate applications, but is also a common location for malware.",
    "downloads": "The Downloads folder is for user downloads. Executables running directly from here could indicate software being installed, users running downloaded executables, or potential security risk if from untrusted sources.",
}

BEACON_ASSESSMENT_EXPLANATIONS = {
    "Highly Regular": "Highly Regular means reconnect intervals vary very little. This pattern is common with:\n• Monitoring agents\n• Scheduled tasks\n• Some command-and-control beacons",
    "Regular": "Regular means reconnect intervals are fairly consistent. This could be normal behavior for legitimate services or automated processes.",
    "Mixed": "Mixed means reconnect intervals vary moderately. This is typical of interactive applications or services with variable load patterns.",
    "Burst/Interactive": "Burst/Interactive means reconnect intervals vary significantly. This is normal for user-driven applications like web browsers, chat clients, or on-demand services.",
}

# ============================================================================
# BEGINNER "WHAT AM I LOOKING AT?" EXPLAINERS
# ============================================================================
# A short, plain-language orientation for each screen, aimed at someone new to
# networking / homelab security. Shown as a compact tips bar under the header
# (toggle with the 'e' key). Each entry is (one-line "what this screen is",
# [bullet lines of "what you're seeing / what to look for"]). Keep bullets
# short so the bar stays small even on a laptop-sized terminal.

VIEW_EXPLAINERS = {
    "main": (
        "LIVE NETWORK MONITOR - every program on this PC that uses the network, and how much it sends and receives.",
        [
            "One row per program. [bold red]Sent[/] / [bold green]Received[/] light up while data flows. "
            "svchost.exe rows name the Windows service inside, e.g. [bold]svchost.exe (DiagTrack)[/] = Windows telemetry.",
            "[bold]Microsoft[/] = what that program's Microsoft traffic is for: [bold red]red[/] = telemetry / ads, "
            "[yellow]yellow[/] = remote settings / security lookups, [cyan]cyan[/] = updates and normal services.",
            "[bold]Top remote[/]: [underline cyan]name[/] = the site it contacted, [bold blue]blue[/] = a device on your own network, "
            "bare number = no name known. Press [bold]Enter[/] to see every connection of the selected program.",
        ],
    ),
    "detail": (
        "CONNECTIONS FOR ONE PROGRAM - each row is one conversation between this program and one server.",
        [
            "Read a row as: this PC -> server : port. The port tells you the kind of traffic, e.g. "
            "[bold]443[/] = HTTPS (encrypted web), [bold]53[/] = DNS lookup, [bold]123[/] = clock sync.",
            "[bold]State[/] ESTABLISHED = open; TIME_WAIT / CLOSE_WAIT = closing (normal). "
            "[bold]Attr[/] = how sure NetSpy is that this program owns it: [green]exact[/] (certain) > [yellow]live?[/] > [yellow]port~[/] (best guess).",
            "Press [bold]Enter[/] on a connection to inspect it alone.",
        ],
    ),
    "inspector": (
        "CONNECTION INSPECTOR - everything known about the ONE connection you selected.",
        [
            "Where it goes (IP, name, country, Microsoft purpose), how (protocol, port, TLS version) and how much data moved.",
            "Who owns it: the program, the program that started it (parent), how long it has been running.",
            "Press [bold]i[/] to check whether the program file itself is trustworthy.",
        ],
    ),
    "file_investigation": (
        "FILE INVESTIGATION - is the program behind this connection trustworthy? (simple, visible rules - no hidden score)",
        [
            "[bold]SHA-256[/] = the file's fingerprint; search it on virustotal.com to see what antivirus engines say. "
            "[bold]Signature[/] = which company vouches for the file.",
            "Red flags: no signature, runs from Temp / Downloads, or was started by PowerShell / cmd.",
            "A valid signature means the file is unchanged and its publisher is known - not that it is harmless.",
        ],
    ),
    "beacons": (
        "BEACON WATCH - servers this PC reconnects to on a steady, clock-like rhythm.",
        [
            "[bold]Interval[/] = average time between reconnects. [bold]Jitter[/] = how much that timing varies "
            "(e.g. every 60 s +/- 1 s = about 2% jitter).",
            "Low jitter ([red]under 5%[/]) means automated software, not a person clicking.",
            "Updaters, sync tools and telemetry beacon too - treat a beacon as a lead to check, not proof of malware.",
        ],
    ),
    "domains": (
        "DOMAINS - every site / service this PC talks to, grouped by name.",
        [
            "Answers 'where is my traffic actually going?'. Each row shows how many programs, connections and bytes use that name.",
            "[bold]Source[/]: SNI / DNS = the name the program itself asked for (reliable); PTR = the server's reverse-DNS name (only a hint).",
            "Look for a name you do not recognise that moves a lot of data.",
        ],
    ),
    "process_domains": (
        "PROGRAM -> DOMAIN MAP - which programs talk to which services.",
        [
            "Answers 'what does this program connect to?', e.g. explorer.exe -> bing.com means Start menu search goes online.",
            "Good for spotting a program reaching somewhere it has no reason to go.",
        ],
    ),
    "timeline": (
        "NETWORK TIMELINE - new connections and name lookups, newest first (last few minutes).",
        [
            "Type [bold]dns[/] = a program looked up a name; [bold]domain[/] / [bold]ip[/] = it opened a new connection.",
            "Try it: open the Start menu or Widgets, then watch which programs reach out and to where.",
        ],
    ),
    "system_summary": (
        "SYSTEM SUMMARY - the whole PC on one screen.",
        [
            "Counts of active programs, domains, beacons, unsigned programs and internet connections.",
            "[bold]Microsoft connections[/]: how many go to Microsoft, how many are telemetry / ads, and which programs send them.",
        ],
    ),
    "firewall": (
        "FIREWALL - see and control which programs may use the network (real Windows Firewall rules).",
        [
            "Select a program, then [bold green]a[/] = Allow, [bold red]b[/] = Block, [bold]x[/] = remove NetSpy's rule (back to Windows' default).",
            "[bold]i[/] / [bold]u[/] switch between active, running and all installed apps; [bold]Enter[/] = details, [bold]r[/] = raw Windows rules.",
            "A blocked program stays blocked after NetSpy closes. svchost.exe cannot be blocked here (all services share that file) - use services.msc.",
        ],
    ),
    "firewall_detail": (
        "FIREWALL DETAIL - one program's network activity and firewall state, to help you decide Allow or Block.",
        [
            "[bold green]a[/] = Allow, [bold red]b[/] = Block, [bold]x[/] = Default. [bold]Enter[/] jumps to this program's live connections.",
        ],
    ),
    "app_detail": (
        "APP DETAIL - facts about one installed app so you can decide whether it should reach the internet.",
        [
            "[bold green]a[/] = Allow, [bold red]b[/] = Block, [bold]x[/] = Default. [bold]Space[/] marks it as reviewed (kept until NetSpy closes).",
        ],
    ),
    "raw_firewall": (
        "RAW FIREWALL RULES - the rules exactly as Windows Firewall stores them.",
        [
            "This is what Windows actually enforces. Arrows move the marked top row; [bold green]a[/] / [bold red]b[/] change it to Allow / Block.",
        ],
    ),
    "win_tools": (
        "WINDOWS NETWORK TOOLS - Windows' own network commands, each run in its own window.",
        [
            "Type a number or use the arrows, [bold]Space[/] to pick, then [bold]Enter[/] on 'Run selected'.",
            "[bold]check[/] tools only read (e.g. DNS cache, proxy); [bold]fix[/] tools change settings and ask you to confirm first.",
        ],
    ),
    "help": (
        "HELP - every key and every screen.",
        ["Scroll with the arrow keys / PageUp / PageDown. Press [bold]h[/] or [bold]Esc[/] to go back."],
    ),
    "learning": (
        "CONCEPTS - plain-language explanations of the networking and security terms NetSpy uses.",
        ["New to this? Start here. Press [bold]?[/] or [bold]Esc[/] to go back."],
    ),
}


def _current_explainer_key():
    """Map the live view state to a VIEW_EXPLAINERS key, accounting for the
    firewall sub-modes so the tip matches what is actually on screen."""
    if view_mode == "firewall":
        # The 'firewall' entry already covers active/inventory/all_apps well
        # enough for a beginner, so no sub-mode split is needed here.
        return "firewall"
    return view_mode


def build_explainer_panel():
    """Compact, beginner-friendly 'what am I looking at?' bar for the current
    screen. Returns a Panel, or None when there is nothing useful to say."""
    entry = VIEW_EXPLAINERS.get(_current_explainer_key())
    if not entry:
        return None

    headline, bullets = entry
    lines = [f"[bold cyan]{headline}[/]"]
    for b in bullets:
        lines.append(f"  [cyan]-[/] {b}")
    lines.append(
        "[dim]Tip: press [bold]e[/] to hide these beginner tips  |  "
        "[bold]h[/] controls  |  [bold]?[/] full concept glossary[/]"
    )

    return Panel(
        "\n".join(lines),
        title="[bold]Beginner tips[/] (e to hide)",
        border_style="cyan",
        box=box.ROUNDED,
    )


def build_help_lines():
    """The Controls/Tool-Help text - previously unreachable dead code
    trapped after a return statement inside build_learning_panel, which
    is why pressing 'h' silently did nothing. Now its own real
    function, windowed the same way as every other scrollable panel."""
    text = (
        "[bold]Moving around[/]\n"
        "  Arrows / PageUp / PageDown / Home / End   scroll whatever list is on screen\n"
        "  Enter   open: program -> its connections -> one connection    Esc   go back one step\n"
        "  1-5     sort the current list (see below)                     q     quit\n\n"
        "[bold]Screens[/] (press the key again or Esc to return)\n"
        "  d  Domains - which sites/services this PC talks to\n"
        "  p  Program -> domain map - which program talks to which site\n"
        "  t  Timeline - new connections and DNS lookups, newest first\n"
        "  s  System summary - the whole PC on one screen, incl. Microsoft / telemetry totals\n"
        "  b  Beacon watch - servers contacted on a fixed rhythm\n"
        "  f  Firewall - allow / block programs (real Windows Firewall rules)\n"
        "  w  Windows tools - Windows' own network commands (DNS cache, proxy, resets...)\n"
        "  i  File investigation of the program behind the inspected connection\n"
        "  ?  Concepts - what the networking / security terms mean\n\n"
        "[bold]Toggles[/]\n"
        "  e  beginner tips bar     l  listening ports panel     y  process tree panel\n"
        "  m  hide the program list while viewing connections   o  hide programs idle > 10 min\n"
        "  c  reset all counters    g  generate test traffic (to check NetSpy sees it)   j  developer stats\n\n"
        "[bold]Sorting (keys 1-5)[/]\n"
        "  Main:            1 name   2 sent   3 received   4 total   5 last seen\n"
        "  Connections:     1 first seen   2 sent   3 received   4 total   5 packets\n"
        "  Domains:         1 name   2 programs   3 connections   4 bytes   5 IPs\n"
        "  Program->domain: 1 name   2 domains   3 connections   4 traffic   5 type\n"
        "  Beacons:         1 server   2 interval   3 jitter   4 samples   5 last contact\n"
        "  Firewall:        1 name   2 connections   3 domains   4 traffic   5 location\n"
        "  Firewall apps:   1 name   2 location   3 reviewed   4 firewall state   5 connections\n\n"
        "[bold]Main table columns[/]\n"
        "  Process     the program. svchost.exe shows its Windows service, e.g. svchost.exe (DoSvc) = Delivery Optimization\n"
        "              System = Windows itself (file sharing, NetBIOS)\n"
        "              System / Unknown = connections no program owns any more (already closing)\n"
        "              Unresolved / short-lived = traffic whose program could not be identified in time\n"
        "  PID         process ID - Windows' number for a running program (\"2 pids\" = two copies running)\n"
        "  Sent / Received / Total   bytes since NetSpy started; [bold red]bright red[/] / [bold green]green[/] = moving right now\n"
        "              (BASIC: data bytes from Windows; ADVANCED: whole frames incl. headers, a few % more)\n"
        "  Last seen   time since the last packet\n"
        "  Top remote  the server it exchanged the most data with:\n"
        "              [underline cyan]v10.events.data.microsoft.com[/]:443 = name known   [bold blue]192.168.1.1[/] = your own network\n"
        "              [bold white on red] BLOCKLISTED [/] = on the list you loaded with --blocklist\n"
        "  Microsoft   purpose of its Microsoft traffic:\n"
        "              [bold red]Telemetry, Crash reports, Ads / Spotlight, Bing search, News / Widgets, Activity history[/]\n"
        "                = data about you / ads\n"
        "              [yellow]Remote config, Defender cloud, SmartScreen[/] = settings and security lookups\n"
        "              [cyan]Windows Update, Microsoft account, OneDrive, Store...[/] = normal services\n"
        "              Microsoft network = a Microsoft-owned server with no known purpose; +2 = two more purposes\n"
        "              Counts everything since NetSpy started - closed connections are kept as totals in RAM\n"
        "  Conns       open connections right now     Rate   current speed (^ up, v down)\n"
        "  Location    where the .exe lives: Windows / Installed = normal; [bold yellow]! AppData, ! Temp, ! Downloads[/] = worth a look\n"
        "  Rows idle for over 10 minutes are dimmed.\n\n"
        "[bold]Header[/]\n"
        "  Mode     [bold green]BASIC[/] (default) = private: NetSpy itself sends nothing, no capture driver, bytes from ETW\n"
        "           [bold cyan]ADVANCED[/] (start with --advanced) = adds packet capture (site names, TLS, ping) and online\n"
        "           lookups (reverse DNS, IP owner / country) - those lookups tell third parties which IPs you check\n"
        "  Packets  captured so far ([bold red]dropped[/] = NetSpy fell behind, totals are too low); BASIC shows Net events\n"
        "  Adapters network cards being captured (Wi-Fi, Ethernet, VPN...)\n"
        "  ETW      Windows' own event feed: names short-lived programs and shows every DNS lookup (needs admin)\n\n"
        "[bold]Connection inspector (Enter on a connection)[/]\n"
        "  Remote server (name, country, Microsoft purpose), protocol, port, TLS version, bytes, state,\n"
        "  how NetSpy matched it to the program (Attr), and the owning program, its parent and runtime.\n\n"
        "[bold]File investigation (i)[/]\n"
        "  SHA-256 fingerprint, digital signature and publisher, file location, parent program and\n"
        "  risk indicators, combined by simple visible rules into: Looks normal / Worth investigating / Suspicious.\n\n"
        "[bold]Firewall (f)[/]\n"
        "  Three lists: active programs (default), running programs (i), all installed apps (u).\n"
        "  a Allow   b Block   x remove NetSpy's rule   r raw Windows rules   Enter details\n"
        "  In the app lists: n cycle user / system / all   Space mark reviewed   k mark all reviewed\n"
        "  Rules are real Windows Firewall rules and stay after NetSpy closes. Review marks are memory-only.\n\n"
        "[bold]Listening ports (l)[/]\n"
        "  Programs waiting for incoming connections, by who can reach them: [dim green]LOOPBACK[/] = this PC only,\n"
        "  [bold blue]LAN[/] = your network, [bold yellow]ALL INTERFACES[/] / [bold red]PUBLIC[/] = possibly outside too (router/firewall permitting).\n\n"
        f"[bold]Beacon watch (b)[/]\n"
        f"  Servers reconnected to on a regular schedule. Jitter = how much the timing varies:\n"
        f"  Highly regular < {JITTER_HIGHLY_REGULAR}%   Regular < {JITTER_REGULAR}%   Mixed < {JITTER_MIXED}%   Burst / interactive above.\n"
        f"  Keeps up to {BEACON_SAMPLES_PER_ENTITY} timestamps for each of up to {BEACON_MAX_ENTITIES} servers; local addresses are ignored.\n\n"
        f"[bold]Timeline (t)[/]  last {TIMELINE_MAX_EVENTS} events, kept {TIMELINE_RETENTION / 60:.0f} minutes.\n\n"
        f"[bold]Names for IP addresses[/]  taken, in order, from: the TLS handshake (SNI), Windows' DNS lookups (ETW),\n"
        f"  then reverse DNS (cached {DNS_SUCCESS_TTL / 3600:.0f} h, failures {DNS_FAILURE_TTL / 60:.0f} min). Private addresses are never looked up.\n"
        "  To tell whether an unnamed IP belongs to Microsoft, its owner is looked up once at ipwho.is / ip-api.com / rdap.org."
    )
    return text.split("\n")


def build_help_panel(available_lines=None):
    global help_scroll_offset
    panel, help_scroll_offset = build_scrollable_text_panel(
        build_help_lines(),
        help_scroll_offset,
        title_base="Tool Help",
        border_style="magenta",
        back_hint="h/Esc back",
        available_lines=available_lines,
    )
    return panel


def build_learning_lines():
    text = (
        "[bold cyan]NETWORKING & SECURITY CONCEPTS[/]  (plain meaning first, details after)\n\n"
        "[bold yellow]IP address and port[/]\n"
        "An IP address is a computer's address on a network; a port is the 'door' for one service on it.\n"
        "Example: 142.250.185.238:443 = Google's server, door 443 (HTTPS). IPv6 looks like [2a00:1450::1]:443.\n"
        "Private (192.168.x.x, 10.x.x.x, fe80::...) = your own network; everything else = the internet.\n\n"
        "[bold yellow]Process, PID and svchost.exe[/]\n"
        "A process is a running program; the PID is Windows' number for it (it changes every run).\n"
        "svchost.exe is a shared host for Windows services - NetSpy names the service inside, e.g.\n"
        "svchost.exe (DiagTrack) = telemetry, (wuauserv) = Windows Update, (Dnscache) = DNS client.\n"
        "Parent process = the program that started it, e.g. explorer.exe starts what you double-click.\n\n"
        "[bold yellow]TCP and UDP[/]\n"
        "TCP = a phone call: set up first, everything arrives in order (web, email, most apps).\n"
        "UDP = a postcard: just sent, no guarantee (DNS, video calls, games, QUIC).\n\n"
        "[bold yellow]TCP connection states[/]\n"
        "SYN_SENT = calling (stuck here = server unreachable or blocked)   ESTABLISHED = connected\n"
        "TIME_WAIT / CLOSE_WAIT = hanging up (normal)   LISTEN = waiting for others to connect in\n\n"
        "[bold yellow]DNS[/]\n"
        "The internet's phone book: turns a name (github.com) into an IP address (140.82.121.4).\n"
        "Normally port 53 and readable by anyone on the network. Encrypted DNS (DoH, port 443) hides it on\n"
        "the wire - NetSpy still sees every lookup and which program made it, via Windows' own events (ETW).\n\n"
        "[bold yellow]TLS, HTTPS and SNI[/]\n"
        "TLS encrypts a connection; HTTPS = web over TLS (port 443). Nobody in between can read the content.\n"
        "SNI = the site name the program announces at the start, unencrypted - so NetSpy can show\n"
        "'v10.events.data.microsoft.com' instead of a bare IP. TLS 1.3 / 1.2 are current; 1.0 / 1.1 are outdated.\n"
        "Encrypted Client Hello (ECH) can hide the SNI - then you only see a generic name like cloudflare-ech.com.\n\n"
        "[bold yellow]QUIC / HTTP/3[/]\n"
        "Newer web transport over UDP port 443 (TLS built in), used by browsers and many Microsoft services.\n"
        "Its site name is not read from packets; the DNS lookup before it usually names it.\n\n"
        "[bold yellow]Reverse DNS (PTR)[/]\n"
        "Asking 'what is the name of this IP?'. Example: 140.82.121.4 -> lb-140-82-121-4-fra.github.com.\n"
        "Only a hint: often missing, and cloud servers return the provider's name, not the site's.\n\n"
        "[bold yellow]Telemetry[/]\n"
        "Usage and diagnostic data a program sends home: hardware, settings, crashes, app usage.\n"
        "Windows sends it mainly from svchost.exe (DiagTrack) to *.events.data.microsoft.com.\n"
        "NetSpy shows when, how often and how much - the content itself is encrypted.\n\n"
        "[bold yellow]Microsoft network (ASN)[/]\n"
        "Every IP belongs to a network owner with a number (ASN); Microsoft's is AS8075. 'Microsoft network'\n"
        "means a Microsoft-owned server - also used by other companies' apps hosted on Azure.\n"
        "Needs an online owner lookup, so it only appears in ADVANCED mode.\n\n"
        "[bold yellow]ETW (Event Tracing for Windows)[/]\n"
        "Windows' built-in live event feed. NetSpy uses it to name programs that connect and exit within\n"
        "milliseconds and to see every DNS lookup. Needs admin; shown as 'ETW: on' in the header.\n\n"
        "[bold yellow]Packet capture (ADVANCED mode only)[/]\n"
        "Copying every packet that passes the network card (via the Npcap driver). Adds site names from\n"
        "the TLS handshake, TLS versions and ping traffic. BASIC mode needs none of it: Windows' own\n"
        "events (ETW) already report every send and receive with its program and size.\n\n"
        "[bold yellow]Connection attribution (Attr)[/]\n"
        "How NetSpy knows which program owns a connection:\n"
        "exact = Windows' connection table or ETW confirms it   live? = one quick re-check, usually right\n"
        "port~ = matched on the local port only, can be wrong if the port was reused   none = unknown\n\n"
        "[bold yellow]Listening and exposure[/]\n"
        "A listening program waits for others to connect in. Who can reach it depends on its address:\n"
        "LOOPBACK (127.0.0.1, ::1) = this PC only   LAN = your network   ALL INTERFACES (0.0.0.0) / PUBLIC =\n"
        "every network the PC is on - reachable from outside unless the router or firewall stops it.\n\n"
        "[bold yellow]Beaconing[/]\n"
        "Reconnecting on a fixed schedule, e.g. 12:00:00, 12:01:00, 12:02:00. Normal for updaters,\n"
        "sync and telemetry; also how malware checks in with its controller (C2). A lead, not proof.\n\n"
        "[bold yellow]Executable location[/]\n"
        "Windows (C:\\Windows\\...) and Installed (C:\\Program Files\\...) need admin rights to change - normal.\n"
        "AppData, Temp, Downloads are writable by any program - normal for some apps (Discord, VS Code)\n"
        "but also where malware hides, so they are flagged for a second look.\n\n"
        "[bold yellow]Digital signature[/]\n"
        "The publisher's cryptographic stamp. Valid = file unchanged since signed, publisher known.\n"
        "NotSigned = no stamp. Invalid / HashMismatch = file changed after signing (red flag).\n"
        "Valid does not mean safe - malware is sometimes signed too.\n\n"
        "[bold yellow]SHA-256[/]\n"
        "A file's fingerprint: identical files always match, one changed byte gives a different value.\n"
        "Paste it into virustotal.com to see if it is a known file.\n\n"
        "[bold yellow]LOLBins (Living Off the Land binaries)[/]\n"
        "Built-in Windows tools that can also run attacker commands, e.g. powershell, cmd, rundll32,\n"
        "certutil, regsvr32, mshta. Signed by Microsoft, so they look trustworthy - check what started them.\n\n"
        "[bold yellow]Common ports[/]\n"
        "53 DNS   80 HTTP (unencrypted web)   443 HTTPS / QUIC   123 time sync   22 SSH   3389 Remote Desktop\n"
        "445 SMB file sharing   137-138 NetBIOS (old Windows name lookup)   5353 mDNS   1900 SSDP / UPnP\n"
        "25 / 587 email sending   853 DNS over TLS"
    )
    return text.split("\n")


def build_learning_panel(available_lines=None):
    global learning_scroll_offset
    panel, learning_scroll_offset = build_scrollable_text_panel(
        build_learning_lines(),
        learning_scroll_offset,
        title_base="Networking & Cybersecurity Concepts",
        border_style="cyan",
        back_hint="?/Esc back",
        available_lines=available_lines,
    )
    return panel


def build_full_table(max_rows_hint=None):
    global last_rendered_order, main_scroll_offset

    table = Table(box=box.HEAVY, expand=True, border_style="green")
    try:
        term_width = console.size.width
    except (AttributeError, OSError):
        term_width = 200
    # Narrow terminal: drop the least useful columns first instead of letting
    # rich cut off the right-hand side of the table.
    drop = set()
    for col, min_term in (("Rate", 185), ("Conns", 175), ("PID", 165), ("[4] Total", 155), ("Location", 140)):
        if term_width < min_term:
            drop.add(col)
    columns = [
        ("[1] Process", dict(no_wrap=True, ratio=2, min_width=16)),
        ("PID", dict(justify="right", style="grey62", width=9, no_wrap=True)),
        ("[2] Sent", dict(justify="right", width=10, no_wrap=True)),
        ("[3] Received", dict(justify="right", width=12, no_wrap=True)),
        ("[4] Total", dict(justify="right", style="bold", width=10, no_wrap=True)),
        ("[5] Last seen", dict(justify="right", style="grey62", width=13, no_wrap=True)),
        ("Top remote", dict(no_wrap=True, ratio=2, min_width=16)),
        ("Microsoft", dict(width=20, no_wrap=True)),
        ("Conns", dict(justify="right", style="grey62", width=6, no_wrap=True)),
        ("Rate", dict(justify="right", width=22, no_wrap=True)),
        ("Location", dict(width=11, no_wrap=True)),
    ]
    keep = [i for i, (header, _) in enumerate(columns) if header not in drop]
    for i in keep:
        table.add_column(columns[i][0], **columns[i][1])

    now = time.time()
    all_rows = sort_rows(compute_rows())

    def _idle_for(d):
        last = max(d.get("last_sent", 0.0), d.get("last_recv", 0.0))
        return now - last if last else float("inf")

    hidden_idle = 0
    if hide_idle:
        kept = [r for r in all_rows if _idle_for(r[1]) <= IDLE_ROW_AGE]
        hidden_idle = len(all_rows) - len(kept)
        all_rows = kept
    last_rendered_order = [name for name, _ in all_rows]
    total_rows = len(all_rows)

    if max_rows_hint is not None:
        max_rows = max(3, max_rows_hint)
    else:
        max_rows = max(3, get_body_height() - 4)
    if view_mode != "main":
        max_rows = min(max_rows, 8)

    if selected_process in last_rendered_order:
        sel_idx = last_rendered_order.index(selected_process)
        if sel_idx < main_scroll_offset:
            main_scroll_offset = sel_idx
        elif sel_idx >= main_scroll_offset + max_rows:
            main_scroll_offset = sel_idx - max_rows + 1
    main_scroll_offset = max(0, min(main_scroll_offset, max(0, total_rows - max_rows)))

    window = all_rows[main_scroll_offset : main_scroll_offset + max_rows]

    for name, data in window:
        connections = data.get("connections", {})
        remote_bytes = aggregate_by_remote(connections)
        if remote_bytes:
            (top_ip, top_port), _ = max(remote_bytes.items(), key=lambda kv: kv[1])
            # Try to find SNI for this remote IP from connections
            top_sni = None
            for ckey, cdata in connections.items():
                _proto, _lip, _lport, rip, _rport = ckey
                if rip == top_ip and _rport == top_port:
                    top_sni = cdata.get("sni")
                    break
            top_remote_display = format_remote_highlighted(top_ip, top_port, top_sni)
        else:
            top_remote_display = "-"

        last_sent = data.get("last_sent", 0.0)
        last_recv = data.get("last_recv", 0.0)
        sent_active = last_sent and (now - last_sent) <= FLASH_WINDOW
        recv_active = last_recv and (now - last_recv) <= FLASH_WINDOW

        stale = _idle_for(data) > IDLE_ROW_AGE
        sent_style = "bold bright_red" if sent_active else "dim red"
        recv_style = "bold bright_green" if recv_active else "dim green"
        name_style = (
            "bold bright_white" if (sent_active or recv_active)
            else "grey50" if stale else "white"
        )

        last_act_ts = max(last_sent, last_recv)
        last_act_text = age_fmt(now - last_act_ts) if last_act_ts else "-"

        is_selected = name == selected_process
        marker = "> " if is_selected else "  "

        proc_pid_for_check = data.get("pid")
        exe_for_check = (
            get_process_info(proc_pid_for_check)["exe"] if proc_pid_for_check else "-"
        )
        path_badge = exe_location_badge(exe_for_check)

        sent_rate, recv_rate = compute_rate(
            _rate_state_process, name, data["sent"], data["recv"], now
        )
        rate_display = format_rate_pair(sent_rate, recv_rate)

        distinct_pids = {c.get("pid") for c in connections.values() if c.get("pid")}
        if len(distinct_pids) > 1:
            pid_display = f"{len(distinct_pids)} pids"
        elif distinct_pids:
            pid_display = str(next(iter(distinct_pids)))
        else:
            pid_display = str(data.get("pid") or "-")

        cells = (
            f"{marker}[{name_style}]{name}[/]",
            pid_display,
            f"[{sent_style}]{bytes_fmt(data['sent'])}[/]",
            f"[{recv_style}]{bytes_fmt(data['recv'])}[/]",
            bytes_fmt(data["sent"] + data["recv"]),
            last_act_text,
            top_remote_display,
            row_microsoft_summary(data),
            str(len(connections)),
            rate_display,
            path_badge,
        )
        table.add_row(
            *(cells[i] for i in keep),
            style="on grey23" if is_selected else ("dim" if stale else None),
        )

    if not window:
        table.add_row(
            "(waiting for traffic...)" if not all_rows else "(scrolled past the end)",
            *["-"] * (len(keep) - 1),
        )

    title = (
        f"Processes ({main_scroll_offset + 1}-{main_scroll_offset + len(window)} of {total_rows})"
        if total_rows
        else "Processes"
    )
    if hidden_idle:
        title += f" [dim]- {hidden_idle} idle >{IDLE_ROW_AGE / 60:.0f}m hidden (o to show)[/]"
    elif not hide_idle:
        title += " [dim]- o hides idle[/]"
    panel = Panel(table, title=title, border_style="green")
    if view_mode != "main":
        panel.height = max_rows + 4
    return panel


def build_detail_panel(available_lines=None):
    global \
        last_rendered_connections, \
        detail_scroll_offset, \
        selected_connection_index_hint

    if not selected_process:
        return None

    rows = dict(compute_rows())
    data = rows.get(selected_process)
    if not data:
        return Panel(
            f"No current data for {selected_process} (it may have gone idle or its counters were cleared).",
            title="Detail view (Esc to go back)",
            border_style="yellow",
        )

    anchor_pid = data.get("pid")
    info = get_process_info(anchor_pid)
    parent = info["parent_name"]
    if info.get("parent_pid"):
        parent += f" (PID {info['parent_pid']})"
    exe_badge = exe_location_badge(info["exe"])
    header_lines = [
        f"PID {anchor_pid or '-'}  |  Parent: {parent}",
        f"EXE [{exe_badge}]: {info['exe']}",
        *([f"CMD: {escape(info['cmdline'])}"] if info.get("cmdline") else []),
        *filter(None, [services_line(anchor_pid)]),
    ]
    header_text = Text.from_markup("\n".join(header_lines), overflow="ellipsis")
    header_text.no_wrap = True  # one row per line, so the panel height below is exact
    header_panel = Panel(
        header_text,
        title=f"[bold]{selected_process}[/]",
        border_style="cyan",
    )

    connections = data.get("connections", {})

    header_height = max(HEADER_PANEL_HEIGHT, len(header_lines) + 2)
    header_panel.height = header_height

    tree_panel = None
    tree_panel_height = 0
    if show_tree and anchor_pid:
        if available_lines is not None:
            room_for_tree = (
                available_lines
                - header_height
                - MIN_CONN_ROWS
                - CONN_PANEL_CHROME
            )
        else:
            room_for_tree = MAX_TREE_CHILDREN + 6

        if room_for_tree <= 0:
            tree_panel = Panel(
                "[dim]Hidden - not enough vertical space for both panels. "
                "Resize your terminal taller, or press 'y' to keep it off.[/]",
                title="Process tree  [y to toggle]",
                border_style="cyan",
            )
            tree_panel.height = 3
            tree_panel_height = 3
        else:
            ancestry_len = len(get_process_ancestry(anchor_pid))
            fixed_tree_lines = ancestry_len + 1 + 1
            room_for_children = room_for_tree - 2 - fixed_tree_lines
            children_to_show = max(0, min(MAX_TREE_CHILDREN, room_for_children))

            tree = build_process_tree(
                anchor_pid,
                selected_process,
                connections,
                max_children=children_to_show,
                pad_to_fixed_height=True,
            )
            tree_panel = Panel(
                tree,
                title="Process tree (ancestry -> this process -> children / top remotes)  [y to hide]",
                border_style="cyan",
            )
            tree_panel_height = min(
                room_for_tree, fixed_tree_lines + children_to_show + 2
            )
            tree_panel.height = tree_panel_height

    by_pid = collections.defaultdict(dict)
    for ckey, cdata in connections.items():
        owner_pid = cdata.get("pid") or anchor_pid or 0
        by_pid[owner_pid][ckey] = cdata

    total_tracked = len(connections)
    ordered_pids = sorted(
        by_pid.keys(),
        key=lambda p: sum(c["sent"] + c["recv"] for c in by_pid[p].values()),
        reverse=True,
    )

    flat_entries = []
    for owner_pid in ordered_pids:
        owner_name = selected_process
        if owner_pid and owner_pid != anchor_pid:
            try:
                owner_name = psutil.Process(owner_pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            except OSError:
                pass
        flat_entries.append(("header", owner_pid, owner_name))
        owner_conns = sorted(
            by_pid[owner_pid].items(),
            key=CONN_SORT_FUNCS.get(conn_sort_key, CONN_SORT_FUNCS["order"]),
        )
        for ckey, cdata in owner_conns:
            flat_entries.append(("conn", ckey, cdata, owner_pid))

    all_conn_keys = [e[1] for e in flat_entries if e[0] == "conn"]
    last_rendered_connections = all_conn_keys
    if selected_connection_key in all_conn_keys:
        selected_connection_index_hint = all_conn_keys.index(selected_connection_key)

    used_by_other_panels = header_height + (
        tree_panel_height if tree_panel else 0
    )
    if available_lines is not None:
        max_rows = max(1, available_lines - used_by_other_panels - CONN_PANEL_CHROME)
    else:
        max_rows = max(1, get_body_height() - used_by_other_panels - CONN_PANEL_CHROME)

    total_entries = len(flat_entries)
    if selected_connection_key in all_conn_keys:
        sel_flat_idx = next(
            i
            for i, e in enumerate(flat_entries)
            if e[0] == "conn" and e[1] == selected_connection_key
        )
        if sel_flat_idx < detail_scroll_offset:
            detail_scroll_offset = sel_flat_idx
        elif sel_flat_idx >= detail_scroll_offset + max_rows:
            detail_scroll_offset = sel_flat_idx - max_rows + 1
    detail_scroll_offset = max(
        0, min(detail_scroll_offset, max(0, total_entries - max_rows))
    )

    window = flat_entries[detail_scroll_offset : detail_scroll_offset + max_rows]

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("PID / Local -> Remote", no_wrap=True, overflow="ellipsis")
    table.add_column("Proto", justify="center", width=6, no_wrap=True)
    table.add_column("Sent", justify="right", width=10, no_wrap=True)
    table.add_column("Received", justify="right", width=10, no_wrap=True)
    table.add_column("Packets", justify="right", width=8, no_wrap=True)
    table.add_column("State", width=13, no_wrap=True)
    table.add_column("Attr", width=8, no_wrap=True)
    table.add_column("Microsoft", width=20, no_wrap=True)

    shown_conn_keys = []
    live_state_cache = {}

    for entry in window:
        if entry[0] == "header":
            _, owner_pid, owner_name = entry
            pid_label = f"[bold]PID {owner_pid or '-'}[/]"
            if owner_name != selected_process:
                pid_label += f" [dim]({owner_name})[/]"
            table.add_row("", pid_label, "", "", "", "", "", "")
        else:
            _, ckey, cdata, owner_pid = entry
            proto, _lip, lport, rip, rport = ckey
            is_sel = ckey == selected_connection_key
            marker = "> " if is_sel else "  "
            if owner_pid not in live_state_cache:
                live_state_cache[owner_pid] = (
                    get_live_connection_states(owner_pid) if owner_pid else {}
                )
            state = live_state_cache[owner_pid].get(ckey, "-")

            endpoint_display = format_connection_endpoint(rip, rport, cdata.get("sni"))
            sni = cdata.get("sni")
            if sni:
                endpoint_display = f"[bold cyan]{sni}[/] -> {endpoint_display}"
            local_display = (
                f"{lport} -> {endpoint_display}"
                if lport is not None
                else endpoint_display
            )

            privacy_concern = ms_purpose_markup(microsoft_purpose(rip, sni))

            table.add_row(
                marker,
                local_display,
                proto,
                bytes_fmt(cdata["sent"]),
                bytes_fmt(cdata["recv"]),
                str(cdata["packets"]),
                state,
                format_attribution(cdata.get("match_type")),
                privacy_concern,
                style="on grey23" if is_sel else None,
            )
            shown_conn_keys.append(ckey)

    idle_children_note = None
    if anchor_pid:
        live_children = get_child_processes(anchor_pid)
        idle_children = [p for p, _ in live_children if p not in by_pid]
        if idle_children:
            idle_children_note = f"[dim]+ {len(idle_children)} more child process(es) with no observed connections[/]"

    if not connections:
        table.add_row("", "(no connections recorded yet)", "-", "-", "-", "-", "-", "-")
    elif not window:
        table.add_row(
            "",
            "(scrolled past the end - press Home to go back up)",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
        )
    elif idle_children_note and detail_scroll_offset + max_rows >= total_entries:
        table.add_row("", idle_children_note, "", "", "", "", "", "")

    range_lo = detail_scroll_offset + 1 if total_entries else 0
    range_hi = detail_scroll_offset + len(window)
    conn_title = (
        f"Connections  rows {range_lo}-{range_hi}/{total_entries}  "
        f"({len(shown_conn_keys)}/{total_tracked} conns, {len(by_pid)} pids)  "
        f"sort:{conn_sort_key}  [1-5 sort]  Arrow keys  Enter  Esc  "
        f"m:{'main hidden' if hide_main_in_detail else 'main shown'}"
    )
    conn_panel = Panel(table, title=conn_title, border_style="cyan")
    parts = [header_panel]
    if tree_panel:
        parts.append(tree_panel)
    parts.append(conn_panel)

    return Group(*parts)


# ==========================================================
# CONNECTION INVESTIGATION VIEW (V)
#
# Builds the detailed inspector shown after:
#
#   Main View
#      ↓
#      V
#      ↓
#   Enter
#
# Combines:
#   Connection data
#   TLS intelligence
#   Domain intelligence
#   Process information
#
# into a single forensic view.
# ==========================================================
def build_inspector_lines():
    try:
        if not selected_process or not selected_connection_key:
            return (
                [
                    (
                        "No connection selected - open a process with Enter, then pick one "
                        "with the arrow keys."
                    )
                ],
                False,
            )

        rows = dict(compute_rows())
        data = rows.get(selected_process)
        if not data:
            return ([f"No current data for {selected_process}."], False)

        connections = data.get("connections", {})
        cdata = connections.get(selected_connection_key)
        if not cdata:
            return (
                [
                    (
                        "This connection is no longer tracked (it closed and aged out, or was evicted to stay "
                        f"within the {MAX_CONNECTIONS_PER_PROCESS}-connection cap for this process)."
                    )
                ],
                False,
            )

        proto, lip, lport, rip, rport = selected_connection_key

        if rip and classify_bind_address(rip) == "LOOPBACK":
            direction = "LOCAL IPC"
        elif any(s["proto"] == proto and s["port"] == lport for s in get_listening_sockets()):
            direction = "INBOUND (remote connected to a port this program listens on)"
        else:
            direction = "OUTBOUND (this PC started it)"

        pid = cdata.get("pid") or data.get("pid")
        exact_name = (
            _safe(lambda: psutil.Process(pid).name(), selected_process)
            if pid and pid != data.get("pid")
            else selected_process
        )
        live_states = get_live_connection_states(pid)
        state = live_states.get(selected_connection_key)
        if state is None:
            state = "-" if proto != "TCP" else "closed (no longer in Windows' connection table)"
        service = WELL_KNOWN_PORTS.get(rport, "-")
        classification = classify_connection(proto, rport)

        local_display = ip_with_port(lip, lport) if (lip and lport is not None) else (lip or "-")
        interface_name = get_interface_name_for_ip(lip)

        match_type = cdata.get("match_type")
        attribution_note = {
            "exact": "exact 5-tuple match - strong evidence this PID owns this connection",
            "live": "one-off live re-check, local-port only - usually right, not certain",
            "port": "cached local-port-only match - can misattribute if another process briefly shared this port",
            "unknown": "never resolved to a process",
            "n/a": "ICMP has no port/PID concept",
        }.get(match_type, "unknown")

        exe_info = get_process_info(pid)

        started = clock_fmt(exe_info["create_time"]) if exe_info["create_time"] else "-"
        running_for = (
            duration_fmt(time.time() - exe_info["create_time"])
            if exe_info["create_time"]
            else "-"
        )

        now = time.time()
        sent_rate, recv_rate = compute_rate(
            _rate_state_conn, selected_connection_key, cdata["sent"], cdata["recv"], now
        )
        rate_display = format_rate_pair(sent_rate, recv_rate)
        age_seconds = now - cdata["first_seen"]

        blocklist_line = None
        if BLOCKLIST_NETWORKS and rip:
            rule = blocklist_match(rip)
            if rule:
                blocklist_line = (
                    f"Blocklist:   [bold white on red] MATCH [/]  rule: {rule}"
                )
            else:
                blocklist_line = "Blocklist:   [dim]no match[/]"

        # Add privacy transparency information
        privacy_metadata = cdata.get("privacy_metadata", {})
        purpose = microsoft_purpose(rip, cdata.get("sni"))
        if purpose:
            ms_text = ms_purpose_markup(purpose)
        elif rip and _is_resolvable_ip(rip) and not ONLINE_LOOKUPS:
            ms_text = "[dim]no known Microsoft name - IP owner not looked up (BASIC mode is private)[/]"
        elif rip and _is_resolvable_ip(rip) and get_ip_info(rip) is None:
            ms_text = "[dim]checking who owns this IP...[/]"
        else:
            ms_text = "[dim]no - not a known Microsoft endpoint or network[/]"
        privacy_line = "Microsoft:   " + ms_text
        data_classification = privacy_metadata.get("data_classification", "")
        if data_classification:
            privacy_line += f"  |  {data_classification} [dim](by port)[/]"

        remote_scope = classify_bind_address(rip) if rip else None

        lines = [
            f"Process:     {exact_name}"
            + (f"  under {selected_process}" if exact_name != selected_process else ""),
            f"PID:         {pid or '-'}",
            *filter(None, [services_line(pid)]),
            "",
            f"Protocol:    {proto}",
            f"Direction:   {direction}",
            f"Interface:   {interface_name}",
            f"Local:       {local_display}",
            f"Remote:      {format_connection_endpoint(rip, rport, cdata.get('sni'))}",
        ]
        if remote_scope:
            scope_style = SCOPE_STYLE.get(remote_scope, "white")
            lines.append(f"Remote scope: [{scope_style}]{remote_scope}[/]")
        lines.append(f"Hostname:    {format_hostname_status(rip, cdata.get('sni'))}")
        if rip and _is_resolvable_ip(rip) and not ONLINE_LOOKUPS:
            lines.append("Country:     [dim]not looked up (BASIC mode is private)[/]")
        elif rip and _is_resolvable_ip(rip):
            _country = get_ip_country(rip)
            lines.append(
                f"Country:     {_country + '  [dim](where the IP is registered - big clouds may serve from elsewhere)[/]' if _country else '[dim]looking up...[/]'}"
            )
        lines.append(
            f"Service:     {classification if classification != '-' else service}  [dim](guessed from the port)[/]"
        )
        lines.append(f"State:       {state}")

        # Add explanation for State directly under it
        if state and state != "-" and state in TCP_STATE_EXPLANATIONS:
            lines.append(f"[dim cyan]→ {TCP_STATE_EXPLANATIONS[state]}[/]")

        lines.append(
            f"Data:        sent {bytes_fmt(cdata['sent'])}, received {bytes_fmt(cdata['recv'])}, "
            f"{cdata['packets']} {'packets' if CAPTURE_MODE == 'advanced' else 'sends/receives'}  "
            f"[dim]({'frames on the wire, incl. headers' if CAPTURE_MODE == 'advanced' else 'data bytes reported by Windows'})[/]"
        )
        lines.append(f"Rate:        {rate_display}")
        lines.append(f"Seen for:    {duration_fmt(age_seconds)}  [dim](since NetSpy first saw it)[/]")
        lines.append(
            f"Attribution: {format_attribution(match_type)}  [dim]({attribution_note})[/]"
        )

        # Add privacy transparency information
        if privacy_line:
            lines.append(privacy_line)

        # Default values so Pyright knows they always exist
        alpn_display = "-"
        tls_version = "-"

        if cdata.get("sni") or cdata.get("tls_version"):
            alpn_translations = {
                "h2": "HTTP/2",
                "http/1.1": "HTTP/1.1",
                "http/1.0": "HTTP/1.0",
                "spdy/3.1": "SPDY/3.1",
            }

            alpn_display = cdata.get("alpn") or "-"

            if alpn_display != "-" and alpn_display.lower() in alpn_translations:
                alpn_display = alpn_translations[alpn_display.lower()]

            tls_version = cdata.get("tls_version") or "-"

            lines += [
                "",
                "TLS INTELLIGENCE",
                f"Server Name: {cdata.get('sni') or '-'}",
                f"Protocol:    {alpn_display}",
                f"Version:     {tls_version}  [dim](highest the client offered)[/]",
            ]

        if alpn_display in ALPN_PROTOCOL_EXPLANATIONS:
            lines.append(f"[dim cyan]→ {ALPN_PROTOCOL_EXPLANATIONS[alpn_display]}[/]")
        if (
            tls_version
            and tls_version != "-"
            and tls_version in TLS_VERSION_EXPLANATIONS
        ):
            lines.append(f"[dim cyan]→ {TLS_VERSION_EXPLANATIONS[tls_version]}[/]")

        # Domain Profile - group by SNI/hostname with smart naming
        try:
            domain, domain_source = get_smart_domain_name(cdata, rip)
            domain_data = (
                aggregate_by_domain(rows, domain) if domain != "Unknown domain"
                else aggregate_by_ip(rows, rip)
            )
        except Exception:
            # Fallback if domain aggregation fails
            domain, domain_source = get_smart_domain_name(cdata, rip)
            domain_data = {
                "ips": {rip} if rip else set(),
                "processes": {exact_name},
                "connections": 1,
                "ports": {rport} if rport else set(),
            }

        # Show "Current IP" if only one IP, "IPs Seen" if multiple
        ip_list = (
            sorted(domain_data["ips"]) if domain_data["ips"] else ([rip] if rip else [])
        )
        if len(ip_list) == 1:
            ip_display = f"Current IP:  {ip_list[0]}"
        elif len(ip_list) > 1:
            ip_display = f"IPs Seen:    {', '.join(ip_list)}"
        else:
            ip_display = f"Current IP:  {rip}" if rip else "Current IP:  -"

        # Format First Seen and Last Seen timestamps
        first_seen_display = (
            clock_fmt(domain_data.get("first_seen"))
            if domain_data.get("first_seen")
            else "-"
        )
        last_seen_display = (
            clock_fmt(domain_data.get("last_seen"))
            if domain_data.get("last_seen")
            else "-"
        )

        lines += [
            "",
            "DOMAIN PROFILE" if domain != "Unknown domain" else "REMOTE PROFILE  [dim](no name known - grouped by IP)[/]",
            f"Domain:      {domain if domain != 'Unknown domain' else '-'}",
            f"Source:      {domain_source}",
        ]

        # Add explanation for Source directly under it
        if (
            domain_source
            and domain_source != "None observed"
            and domain_source in DOMAIN_SOURCE_EXPLANATIONS
        ):
            lines.append(f"[dim cyan]→ {DOMAIN_SOURCE_EXPLANATIONS[domain_source]}[/]")

        lines.extend(
            [
                ip_display,
                f"First Seen:  {first_seen_display}",
                f"Last Seen:   {last_seen_display}",
                f"Connections: {domain_data['connections']}",
                f"Processes:   {', '.join(sorted(domain_data['processes'])) if domain_data['processes'] else exact_name}",
                f"Ports:       {', '.join(map(str, sorted(domain_data['ports']))) if domain_data['ports'] else str(rport) if rport else '-'}",
            ]
        )

        if blocklist_line:
            lines.append(blocklist_line)

        parent_display = format_parent_display(exe_info)
        lines += [
            "",
            "PROCESS",
            f"User:        {exe_info['username']}",
            f"Started:     {started}",
            f"Running For: {running_for}",
            f"Parent:      {parent_display}",
            f"Threads:     {exe_info['threads']}  CPU: {exe_info['cpu']:.1f}% [dim](last few seconds, % of one core)[/]  "
            f"Memory: {bytes_fmt(exe_info['memory'])}",
        ]
        if exe_info.get("cmdline"):
            lines.append(f"Command:     {escape(exe_info['cmdline'])}")

        lines += [
            "",
            "[dim]Press 'i' for file investigation (SHA-256, signature, publisher)[/]",
        ]

        return (lines, True)
    except Exception as e:
        return ([f"Error building inspector: {e!s}"], False)


def build_inspector_panel(available_lines=None):
    global inspector_scroll_offset
    lines, scrollable = build_inspector_lines()
    if not scrollable:
        return Panel(
            "\n".join(lines), title="Connection inspector", border_style="yellow"
        )
    panel, inspector_scroll_offset = build_scrollable_text_panel(
        lines,
        inspector_scroll_offset,
        title_base="Connection inspector",
        border_style="bright_cyan",
        back_hint="Esc back  i file investigation",
        available_lines=available_lines,
    )
    return panel


def build_file_investigation_lines():
    try:
        if not selected_process or not selected_connection_key:
            return (
                [
                    (
                        "No connection selected - open a process with Enter, then pick one "
                        "with the arrow keys."
                    )
                ],
                False,
            )

        rows = dict(compute_rows())
        data = rows.get(selected_process)
        if not data:
            return ([f"No current data for {selected_process}."], False)

        connections = data.get("connections", {})
        cdata = connections.get(selected_connection_key)
        if not cdata:
            return (
                [
                    (
                        "This connection is no longer tracked (it closed and aged out, or was evicted to stay "
                        f"within the {MAX_CONNECTIONS_PER_PROCESS}-connection cap for this process)."
                    )
                ],
                False,
            )

        pid = cdata.get("pid") or data.get("pid")
        exact_name = (
            _safe(lambda: psutil.Process(pid).name(), selected_process)
            if pid and pid != data.get("pid")
            else selected_process
        )

        exe_info = get_process_info(pid)
        exe_path = exe_info.get("exe", "")

        # Placeholders this frame while the hash/signature run in the background.
        sha256, sig_status, publisher, forensics_ready = file_forensics_or_placeholder(exe_path)

        exe_location = classify_exe_location(exe_info["exe"])
        exe_label = EXE_LOCATION_LABEL.get(exe_location, "Unclassified")

        # Assess file trust (only once the signature check has actually run -
        # otherwise we'd flash a misleading verdict based on placeholder values).
        if forensics_ready:
            trust_assessment, trust_style = assess_file_trust(
                exe_info["exe"], sig_status, publisher, exe_info["parent_name"]
            )
        else:
            trust_assessment, trust_style = "Pending signature check...", "dim"

        # Assess parent risk
        parent_risk, parent_risk_style = assess_parent_risk(exe_info["parent_name"])

        # Check if this is a LOLBin
        is_lolbin_exe = is_lolbin(exact_name.lower())

        # Process timeline
        started = clock_fmt(exe_info["create_time"]) if exe_info["create_time"] else "-"
        running_for = (
            duration_fmt(time.time() - exe_info["create_time"])
            if exe_info["create_time"]
            else "-"
        )

        # Parent process display
        parent_display = format_parent_display(exe_info)

        lines = [
            f"Process:     {exact_name}"
            + (f"  under {selected_process}" if exact_name != selected_process else ""),
            f"PID:         {pid or '-'}",
            *filter(None, [services_line(pid)]),
            "",
            "TRUST SUMMARY",
            f"Publisher:   {publisher}",
            f"Signed:      {sig_status}",
        ]

        # Add explanation for Signature directly under it
        if forensics_ready and sig_status and sig_status != "-":
            if sig_status.upper() in ("VALID", "SIGNED"):
                lines.append(
                    "[dim cyan]→ A valid signature means the executable was digitally signed and the signature verification succeeded.[/]"
                )
                lines.append(
                    "[dim cyan]→ Important: A valid signature does NOT guarantee the software is safe. Malware can also be signed.[/]"
                )
            else:
                lines.append(
                    f"[dim cyan]→ An invalid or missing signature ({sig_status}) means the executable's digital signature could not be verified.[/]"
                )
                lines.append(
                    "[dim cyan]→ This is common for: unsigned software, self-signed certificates, modified executables, or some malware.[/]"
                )

        lines.extend(
            [
                f"Location:    {exe_label}",
                "",
                f"Assessment: [{trust_style}]{trust_assessment}[/]",
            ]
        )

        # Add explanation for Assessment directly under it
        if trust_assessment and trust_assessment in TRUST_ASSESSMENT_EXPLANATIONS:
            lines.append(
                f"[dim cyan]→ {TRUST_ASSESSMENT_EXPLANATIONS[trust_assessment]}[/]"
            )

        lines.extend(
            [
                "",
                "PROCESS LINEAGE",
                *([f"Command:     {escape(exe_info['cmdline'])}"] if exe_info.get("cmdline") else []),
                f"Parent:      {parent_display}",
                f"Flag:        [{parent_risk_style}]{parent_risk}[/]",
            ]
        )

        # Add explanation for Parent Risk directly under it
        if (
            parent_risk
            and parent_risk != "Unknown"
            and parent_risk in PARENT_RISK_EXPLANATIONS
        ):
            lines.append(f"[dim cyan]→ {PARENT_RISK_EXPLANATIONS[parent_risk]}[/]")

        lines.extend(
            [
                "",
                "LOCATION ANALYSIS",
                f"Folder:      {exe_location.title() if exe_location != 'unknown' else 'Unknown'}",
                f"Assessment:  {exe_label}",
            ]
        )

        # Add explanation for Location directly under it
        if (
            exe_location
            and exe_location != "unknown"
            and exe_location in LOCATION_EXPLANATIONS
        ):
            lines.append(f"[dim cyan]→ {LOCATION_EXPLANATIONS[exe_location]}[/]")

        lines.extend(
            [
                "",
                "PROCESS TIMELINE",
                f"Started:     {started}",
                f"Running:     {running_for}",
                "",
                "FILE",
                f"SHA-256:     {sha256}",
                f"Signature:   {sig_status}",
                f"Publisher:   {publisher}",
            ]
        )

        # Add RISK INDICATORS section if there are any risk factors
        risk_indicators = []
        if is_lolbin_exe:
            risk_indicators.append(("LOLBin", "Yes"))
            risk_indicators.append(("Executable", exact_name))
        if exe_location in SUSPICIOUS_LOCATIONS:
            risk_indicators.append(("Location", exe_location.title()))
        if forensics_ready and sig_status and sig_status.upper() not in ("VALID", "SIGNED"):
            risk_indicators.append(("Signature", sig_status))

        if risk_indicators:
            lines.append("")
            lines.append("RISK INDICATORS")
            for indicator, value in risk_indicators:
                lines.append(f"{indicator:12} {value}")

            # Add LOLBin explanation if present
            if is_lolbin_exe:
                lines.append(
                    "[dim cyan]→ LOLBin (Living Off The Land Binary) refers to legitimate system tools that can be abused by malware to evade detection.[/]"
                )
                lines.append(
                    "[dim cyan]→ Examples include PowerShell, CMD, rundll32, and certutil. These tools are signed by Microsoft but can be used maliciously.[/]"
                )

        return (lines, True)
    except Exception as e:
        return ([f"Error building file investigation: {e!s}"], False)


# ==========================================================
# FILE INVESTIGATION (I)
#
# Focused on executable trust rather than networking.
#
# Shows:
#   SHA256
#   Signature
#   Publisher
#   Trust assessment
#
# Used for malware analysis and executable review.
# ==========================================================
def build_file_investigation_panel(available_lines=None):
    global file_investigation_scroll_offset
    lines, scrollable = build_file_investigation_lines()
    if not scrollable:
        return Panel(
            "\n".join(lines), title="File investigation", border_style="yellow"
        )
    panel, file_investigation_scroll_offset = build_scrollable_text_panel(
        lines,
        file_investigation_scroll_offset,
        title_base="File investigation",
        border_style="bright_magenta",
        back_hint="Esc back",
        available_lines=available_lines,
    )
    return panel


# Creates the D screen.
# Groups traffic by domain instead of IP.
def build_domain_panel(available_lines=None):
    global domain_scroll_offset

    domain_stats = compute_domain_summary()

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("[1] Domain", no_wrap=True, ratio=3)
    table.add_column("Source", justify="center", width=8, no_wrap=True)
    table.add_column("[2] Processes", justify="right", width=10, no_wrap=True)
    table.add_column("[3] Connections", justify="right", width=12, no_wrap=True)
    table.add_column("[4] Total Bytes", justify="right", width=14, no_wrap=True)
    table.add_column("[5] IPs", justify="right", width=8, no_wrap=True)

    # Sort using the domain sort functions
    sorted_domains = sorted(
        domain_stats.items(),
        key=DOMAIN_SORT_FUNCS.get(domain_sort_key, DOMAIN_SORT_FUNCS["total_bytes"]),
    )

    max_rows = compute_max_rows(available_lines)

    total = len(sorted_domains)
    domain_scroll_offset = max(0, min(domain_scroll_offset, max(0, total - max_rows)))
    window = sorted_domains[domain_scroll_offset : domain_scroll_offset + max_rows]

    # Get the first source for explanation
    first_source = None
    if window:
        first_source = window[0][1].get("source", "Unknown")

    for domain, stats in window:
        source = stats.get("source", "Unknown")
        is_ptr = stats.get("is_ptr", False)

        source_style = {
            "TLS SNI": "bold green",
            "DNS": "bold green",
            "PTR": "yellow",
            "None observed": "dim",
        }.get(source, "dim")

        # Dim PTR domains to make them less prominent
        if is_ptr:
            domain_display = f"[dim]{domain}[/]"
        else:
            domain_display = f"[bold cyan]{domain}[/]"

        table.add_row(
            domain_display,
            f"[{source_style}]{source}[/]",
            str(stats["process_count"]),
            str(stats["connections"]),
            bytes_fmt(stats["total_bytes"]),
            str(stats["ip_count"]),
        )

    if not window:
        if total == 0:
            msg = "(no domain data yet - wait for TLS connections with SNI)"
        else:
            msg = "(scrolled past the end)"
        table.add_row(msg, "-", "-", "-", "-", "-")

    range_lo = domain_scroll_offset + 1 if total else 0
    range_hi = domain_scroll_offset + len(window)
    title = (
        f"Domains  ({range_lo}-{range_hi}/{total})  Sort: [bold]{domain_sort_key}[/]  "
        f"Arrow keys scroll  [1-5 sort]  Esc/d back to main"
    )

    # Build note with inline explanation if available
    note_lines = [
        "[dim]Domain summary shows all remote services this machine is talking to, grouped by SNI/hostname.\n",
        "Source indicates how the domain was identified: TLS SNI or DNS (reliable), PTR record (a hint).\n",
        "TLS SNI domains are shown first and prominently, PTR domains are dimmed and shown second.\n",
        "Helps answer 'What services is this machine actually talking to?' at a glance for threat hunting.\n",
        "Only includes domains from TLS connections with SNI or PTR records - plain HTTP won't appear here.[/]",
    ]

    # Add inline explanation for the first source
    if first_source and first_source != "None observed":
        explanation_text = DOMAIN_SOURCE_EXPLANATIONS.get(first_source, "")
        if explanation_text:
            note_lines.append("")
            note_lines.append(f"[dim cyan]Source: {first_source}[/]")
            note_lines.append(f"[dim cyan]→ {explanation_text}[/]")

    note = "\n".join(note_lines)

    return Group(
        Panel(table, title=title, border_style="cyan"),
        Panel(note, border_style="cyan"),
    )


# ==========================================================
# PROCESS -> DOMAIN MAPPING (P)
#
# Answers:
#
#   What internet services does this process use?
#
# Example:
#
#   firefox.exe
#     -> chatgpt.com
#     -> github.com
#
# Useful during threat hunting because behavior is
# often easier to understand by domain than by IP.
# ==========================================================
def build_process_domain_panel(available_lines=None):
    """Process → Domain Mapping - shows what each process talks to."""
    global process_domain_scroll_offset

    process_domains = compute_process_domain_mapping()

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("[1] Process", no_wrap=True, ratio=2)
    table.add_column("[5] Type", justify="center", width=8, no_wrap=True)
    table.add_column("Top Domain", no_wrap=True, ratio=2)
    table.add_column("[2] Domains", justify="right", width=8, no_wrap=True)
    table.add_column("[3] Conns", justify="right", width=6, no_wrap=True)
    table.add_column("[4] Traffic", justify="right", width=12, no_wrap=True)

    # Sort using the process domain sort functions
    sorted_processes = sorted(
        process_domains.items(),
        key=PROCESS_DOMAIN_SORT_FUNCS.get(
            process_domain_sort_key, PROCESS_DOMAIN_SORT_FUNCS["traffic"]
        ),
    )

    max_rows = compute_max_rows(available_lines)

    total = len(sorted_processes)
    process_domain_scroll_offset = max(
        0, min(process_domain_scroll_offset, max(0, total - max_rows))
    )
    window = sorted_processes[
        process_domain_scroll_offset : process_domain_scroll_offset + max_rows
    ]

    for proc_name, data in window:
        top_domain = data["top_domain"]
        truncated_domain = truncate_domain_display(top_domain)
        top_domain_display = (
            f"{truncated_domain} ({bytes_fmt(data['top_domain_bytes'])})"
        )

        # Style based on process type
        process_type = data["process_type"]
        type_style = {
            "LOLBin": "bold red",
            "Browser": "bold green",
            "Service": "bold blue",
            "System": "bold yellow",
            "IDE": "bold cyan",
            "Dev": "bold cyan",
            "Office": "bold magenta",
        }.get(process_type, "white")

        # Flag suspicious domains (pastebin, raw.githubusercontent, etc.)
        suspicious_domains = [
            "pastebin",
            "raw.githubusercontent",
            "bit.ly",
            "tinyurl",
            "t.co",
        ]
        is_suspicious = any(sus in top_domain.lower() for sus in suspicious_domains)
        if is_suspicious:
            top_domain_display = f"[bold yellow]{top_domain_display}[/]"

        # Display normalized process name (lowercase) for consistency
        display_name = proc_name

        table.add_row(
            f"[bold cyan]{display_name}[/]",
            f"[{type_style}]{process_type}[/]",
            top_domain_display,
            str(data["domain_count"]),
            str(data["connection_count"]),
            bytes_fmt(data["total_bytes"]),
        )

    if not window:
        if total == 0:
            msg = "(no process-domain data yet - wait for TLS connections with SNI)"
        else:
            msg = "(scrolled past the end)"
        table.add_row(msg, "-", "-", "-", "-", "-")

    range_lo = process_domain_scroll_offset + 1 if total else 0
    range_hi = process_domain_scroll_offset + len(window)
    title = (
        f"Process → Domain Mapping  ({range_lo}-{range_hi}/{total})  Sort: [bold]{process_domain_sort_key}[/]  "
        f"Arrow keys scroll  [1-5 sort]  Esc/p back to main"
    )
    note = (
        "[dim]Shows what services each process is actually talking to, with top domain by traffic.\n"
        "Type classification: Browser, Service, LOLBin, System, IDE, Dev, Office, App.\n"
        "Suspicious domains (pastebin, raw.githubusercontent, etc.) are highlighted in yellow.\n"
        "Answers 'What services does firefox.exe talk to?' immediately.\n"
        "Perfect for threat hunting and professional demos.[/]"
    )
    return Group(
        Panel(table, title=title, border_style="magenta"),
        Panel(note, border_style="magenta"),
    )


def build_timeline_panel(available_lines=None):
    """Network Timeline - shows recent network events chronologically."""
    global timeline_scroll_offset

    with _timeline_lock:
        events = list(_timeline_events)

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time", justify="right", width=10, no_wrap=True)
    table.add_column("Process", no_wrap=True, ratio=2)
    table.add_column("Remote Entity", no_wrap=True, ratio=3)
    table.add_column("Type", justify="center", width=6, no_wrap=True)

    # Sort by timestamp (newest first)
    events.sort(key=lambda e: e["timestamp"], reverse=True)

    max_rows = compute_max_rows(available_lines)

    total = len(events)
    timeline_scroll_offset = max(
        0, min(timeline_scroll_offset, max(0, total - max_rows))
    )
    window = events[timeline_scroll_offset : timeline_scroll_offset + max_rows]

    for event in window:
        timestamp = clock_fmt(event["timestamp"])
        process = event["process"]
        remote = event["remote"]
        entity_type = event["type"].upper()

        # Style based on entity type
        if entity_type == "DOMAIN":
            remote_display = f"[bold cyan]{remote}[/]"
        else:
            remote_display = remote

        table.add_row(
            timestamp,
            f"[bold white]{process}[/]",
            remote_display,
            entity_type,
        )

    if not window:
        if total == 0:
            msg = "(no timeline events yet - wait for new connections)"
        else:
            msg = "(scrolled past the end)"
        table.add_row(msg, "-", "-", "-")

    range_lo = timeline_scroll_offset + 1 if total else 0
    range_hi = timeline_scroll_offset + len(window)
    title = (
        f"Network Timeline  ({range_lo}-{range_hi}/{total})  newest first  "
        f"Arrow keys scroll  Esc/t back to main"
    )
    note = (
        f"[dim]Shows recent network events chronologically (last {TIMELINE_MAX_EVENTS} events, "
        f"kept for {TIMELINE_RETENTION / 60:.0f} minutes).\n"
        "Answers 'What happened in the last few minutes?' immediately.\n"
        "Perfect for spotting suspicious activity patterns and correlation.\n"
        "Memory-only, no disk persistence.[/]"
    )
    return Group(
        Panel(table, title=title, border_style="blue"),
        Panel(note, border_style="blue"),
    )


def build_system_summary_panel(available_lines=None):
    """Lightweight dashboard - pure aggregation of data OTHER views
    already compute every render. No new detection logic, no
    subprocess calls. Unsigned-executable count is cache-only (see
    get_cached_signature_status) and explicitly labeled as partial."""
    rows = dict(compute_rows())
    domain_stats = compute_domain_summary(rows)
    beacon_stats = compute_beacon_stats()
    telemetry = detect_telemetry_connections(rows)

    total_processes = len(rows)
    total_domains = len(domain_stats)
    beacon_candidates = len(beacon_stats)

    # Public connections, broken down by which processes actually
    # drive the number - a bare count told you nothing (a browser
    # alone can rack up 30+ public connections on its own).
    public_by_process = collections.Counter()
    for pname, data in rows.items():
        for ckey in data.get("connections", {}):
            rip = ckey[3]
            if rip and not is_local_network_ip(rip):
                public_by_process[pname] += 1
    public_connections = sum(public_by_process.values())
    top_public_procs = public_by_process.most_common(3)

    # Top 3 domains instead of a single "winner" - costs nothing
    # extra, domain_stats already has everything.
    top_domains = sorted(
        domain_stats.items(), key=lambda kv: kv[1]["total_bytes"], reverse=True
    )[:3]

    # Unsigned count: cache-only, never triggers a fresh check.
    unsigned_count = 0
    unsigned_checked = 0
    for data in rows.values():
        pid = data.get("pid")
        if not pid:
            continue
        exe_info = get_process_info(pid)  # cached (PROC_INFO_TTL) - psutil only, no subprocess
        status = get_cached_signature_status(exe_info.get("exe", ""))
        if status is None:
            continue  # never checked via File Investigation yet
        unsigned_checked += 1
        if status.upper() not in ("VALID", "SIGNED"):
            unsigned_count += 1

    lines = [
        "[bold]SYSTEM SUMMARY[/]",
        "",
        f"Processes:             {total_processes}",
        f"Domains contacted:     {total_domains}",
    ]

    if top_domains:
        lines.append("")
        lines.append("[bold]TOP DOMAINS[/]")
        for domain, stats in top_domains:
            lines.append(
                f"  {domain}  ({bytes_fmt(stats['total_bytes'])}, "
                f"{stats['process_count']} process(es))"
            )

    lines.append("")
    lines.append(f"Public connections:    {public_connections}")
    if top_public_procs:
        procs_display = ", ".join(f"{p} ({n})" for p, n in top_public_procs)
        lines.append(f"  driven mostly by:    {procs_display}")

    lines.append("")
    lines.append(f"Beacon candidates:     {beacon_candidates}")
    ms_conns = sum(t["connections"] for t in telemetry)
    ms_bytes = sum(t["bytes"] for t in telemetry)
    tracking = [t for t in telemetry if t["purpose"] in MS_TRACKING_PURPOSES]
    lines.append(
        f"Microsoft connections: {ms_conns} since start, {bytes_fmt(ms_bytes)}   "
        f"([bold red]{sum(t['connections'] for t in tracking)} tracking / ads, "
        f"{bytes_fmt(sum(t['bytes'] for t in tracking))}[/])"
    )
    by_purpose = {}
    for t in telemetry:
        agg = by_purpose.setdefault(t["purpose"], [0, 0, collections.Counter()])
        agg[0] += t["connections"]
        agg[1] += t["bytes"]
        agg[2][t["process"]] += t["bytes"]
    for purpose, (conns, nbytes, procs) in sorted(by_purpose.items(), key=lambda kv: -kv[1][1]):
        names = [name for name, _ in procs.most_common(3)]
        more = " ..." if len(procs) > 3 else ""
        lines.append(
            f"  {ms_purpose_markup(purpose)}: {conns}x, {bytes_fmt(nbytes)}  "
            f"<- {escape(', '.join(names))}{more}"
        )

    lines.append("")
    if unsigned_checked:
        lines.append(f"Unsigned executables:  {unsigned_count} of {unsigned_checked} checked so far")
    else:
        lines.append(
            "Unsigned executables:  not checked yet - open a connection and "
            "press 'i' (File Investigation)"
        )

    if beacon_candidates or telemetry or unsigned_count:
        lines.append("")
        lines.append("[bold]LOOK CLOSER[/]")
        if beacon_candidates:
            lines.append(
                f"  [yellow]→ {beacon_candidates} entity(s) reconnecting on a "
                f"regular schedule - press 'b' for Beacon Watch[/]"
            )
        if telemetry:
            lines.append(
                f"  [dim]→ {ms_conns} connection(s) to known Microsoft "
                f"endpoints (best-effort pattern match, not comprehensive)[/]"
            )
        if unsigned_count:
            lines.append(
                f"  [yellow]→ {unsigned_count} unsigned executable(s) among those "
                f"checked - press 'i' on other processes to check more[/]"
            )
    else:
        lines.append("")
        lines.append(
            "[green]No beacon patterns, flagged telemetry, or known-unsigned "
            "executables right now.[/]"
        )

    lines.append("")
    lines.append(
        "[dim]Unsigned-executable count only reflects processes you've opened File "
        "Investigation ('i') on at least once - a free cache read, never a fresh scan.[/]"
    )

    return Panel(
        "\n".join(lines),
        title="System Summary  Esc/s back to main",
        border_style="bright_yellow",
    )
def filter_apps_by_category(apps, mode):
    if mode == "all":
        return apps

    if mode == "system":
        return [
            a
            for a in apps
            if (
                a.get("location") == "system"
                or a.get("location") == "unknown"  # Include unknown (AccessDenied cases)
                or (a.get("location") == "store_app" and is_windows_package_path(a.get("path")))
            )
        ]

    # USER - includes third-party Store apps (e.g. ImageGlass), not Windows' own packages
    return [
        a
        for a in apps
        if (
            a.get("location") in ("program_files", "appdata", "downloads", "temp", "other")
            or (a.get("location") == "store_app" and not is_windows_package_path(a.get("path")))
        )
    ]


def get_filtered_apps_for_view(mode):
    """The one place that decides which apps a firewall_view_mode of
    'inventory' or 'all_apps' actually shows - fetch, then narrow by
    the current app_filter_mode. Every call site that used to call
    get_application_inventory()/get_all_user_apps() directly (the
    panel builders, selection movement, bulk-review, the B/A/X
    target resolver) now goes through this instead, so navigation,
    bulk actions, and what's on screen can never drift out of sync
    with each other."""
    apps = get_application_inventory() if mode == "inventory" else get_all_user_apps()
    return [_with_live_state(a) for a in filter_apps_by_category(apps, app_filter_mode)]


def _with_live_state(app):
    """Apply review marks and NetSpy firewall changes made since the list was
    built, so they show at once without re-scanning."""
    reviewed = _review_status.get(app["name"].lower(), {}).get("reviewed", False)
    intent = get_netspy_intent(app.get("path"))
    if reviewed == app["reviewed"] and not intent:
        return app
    return dict(app, reviewed=reviewed, **({"firewall_state": f"{intent} (NetSpy)"} if intent else {}))


# ==========================================================
# FIREWALL CONTROL CENTER (F)
#
# Provides:
#
#   Active Network Processes
#   Application Inventory
#   Raw Firewall Rules
#
# Designed to present firewall information at a
# process level instead of raw Windows rule GUIDs.
# ==========================================================
def build_firewall_panel(available_lines=None):
    """Firewall Panel - switches between Active Network Processes, Running Processes, and All User Apps."""

    if firewall_view_mode == "inventory":
        return build_app_inventory_panel(available_lines)
    elif firewall_view_mode == "all_apps":
        return build_all_apps_panel(available_lines)
    else:
        return build_active_processes_panel(available_lines)


def build_active_processes_panel(available_lines=None):
    """Active Network Processes Panel - shows current network activity."""
    global firewall_scroll_offset, selected_firewall_rule

    # Get current processes from NetSpy's monitoring
    rows = dict(compute_rows())

    # Get Windows Firewall rules for context
    firewall_rules = get_firewall_rules()

    # Calculate firewall statistics
    enabled_count = sum(1 for rule in firewall_rules if rule.get("enabled", False))
    allow_count = sum(
        1
        for rule in firewall_rules
        if rule.get("action") == "Allow" and rule.get("enabled", False)
    )
    block_count = sum(
        1
        for rule in firewall_rules
        if rule.get("action") == "Block" and rule.get("enabled", False)
    )

    sorted_processes, user_count, system_count = firewall_active_processes(rows)

    # Build the note/legend panel BEFORE sizing the table, and measure
    # its real rendered height, so it counts against the available
    # budget instead of silently exceeding it - this is what let the
    # table grow past its allotted space once the firewall action log
    # below it grew large enough to eat the slack that had been
    # hiding the overflow.
    note = f"[bold green]Active[/] [yellow]Idle[/] [dim]No connections[/]  [bold green]Allow[/] [bold red]Block[/] [bold yellow]Unknown[/]  Rules: {enabled_count} ({allow_count} allow, {block_count} block)  Apps: {user_count}  System: {system_count}  [dim]I Running  U All Apps  R Raw Rules  Arrows scroll  Enter details[/]"
    note_panel = Panel(note, border_style="yellow")
    note_height = render_height(note_panel)

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("[1] Process", no_wrap=True, ratio=2)
    table.add_column("Network Status", justify="center", width=15, no_wrap=True)
    table.add_column("Firewall", justify="center", width=18, no_wrap=True)
    table.add_column("[2] Connections", justify="right", width=12, no_wrap=True)
    table.add_column("[3] Domains", justify="right", width=8, no_wrap=True)
    table.add_column("[4] Traffic", justify="right", width=12, no_wrap=True)
    table.add_column("[5] Location", width=12, no_wrap=True)

    chrome = 4 + note_height
    max_rows = compute_max_rows(available_lines, chrome)

    total = len(sorted_processes)

    process_names = [name for name, _ in sorted_processes]
    selected_firewall_rule, firewall_scroll_offset = _ensure_selection_visible(
        process_names, selected_firewall_rule, firewall_scroll_offset, max_rows
    )

    firewall_scroll_offset = max(
        0, min(firewall_scroll_offset, max(0, total - max_rows))
    )
    window = sorted_processes[
        firewall_scroll_offset : firewall_scroll_offset + max_rows
    ]

    for proc_name, data in window:
        connections = data.get("connections", {})
        total_bytes = data["sent"] + data["recv"]
        connection_count = len(connections)

        domain_count = len(known_domains(connections))

        pid = data.get("pid")
        exe_path = get_process_info(pid)["exe"] if pid else "unknown"
        location_badge = exe_location_badge(exe_path)

        # Check firewall state, with observed traffic as ground truth
        has_active_now = connection_count > 0
        firewall_state = check_firewall_rule_for_process(
            exe_path, proc_name, has_active_connection=has_active_now
        )
        firewall_display = style_firewall_state(firewall_state)

        # Determine network status based on activity
        now = time.time()
        last_sent = data.get("last_sent", 0.0)
        last_recv = data.get("last_recv", 0.0)
        is_active = (now - last_sent <= FLASH_WINDOW) or (
            now - last_recv <= FLASH_WINDOW
        )

        if is_active:
            status = "[bold green]Active[/]"
        elif connection_count > 0:
            status = "[yellow]Idle[/]"
        else:
            status = "[dim]No connections[/]"

        is_selected = proc_name == selected_firewall_rule
        marker = "> " if is_selected else "  "

        table.add_row(
            marker,
            proc_name,
            status,
            firewall_display,
            str(connection_count),
            str(domain_count),
            bytes_fmt(total_bytes),
            location_badge,
            style="on grey23" if is_selected else None,
        )

    if not window:
        if total == 0:
            msg = "(no processes with network activity yet)"
        else:
            msg = "(scrolled past the end)"
        table.add_row("", msg, "-", "-", "-", "-", "-")

    range_lo = firewall_scroll_offset + 1 if total else 0
    range_hi = firewall_scroll_offset + len(window)

    title = (
        f"ACTIVE NETWORK PROCESSES  ({range_lo}-{range_hi}/{total})  "
        f"Sort: [bold]{firewall_sort_key}[/]  "
        f"Active: {sum(1 for _, d in window if (time.time() - d.get('last_sent', 0) <= FLASH_WINDOW or time.time() - d.get('last_recv', 0) <= FLASH_WINDOW))}  "
        f"Arrow keys navigate  [1-5 sort]  Enter inspect  I running processes  U all apps  R raw rules  Esc/F back to main"
    )

    return Group(
        Panel(table, title=title, border_style="yellow"),
        note_panel,
    )


def _build_app_list_panel(
    apps, available_lines, *, item_column_header, title_prefix, border_style, title_hint
):
    """Shared body for the two 'flat app list with Location/Reviewed/
    Firewall columns' screens - RUNNING PROCESSES and ALL USER APPS
    were previously copy-pasted from each other with only labels
    changed. Both already shared app_inventory_scroll_offset and
    selected_app_inventory_item, so merging them changes nothing."""
    global app_inventory_scroll_offset, selected_app_inventory_item

    total_apps = len(apps)
    reviewed_count = sum(1 for app in apps if app["reviewed"])
    unreviewed_count = total_apps - reviewed_count

    reviewed_pct = (
        f"{reviewed_count / total_apps * 100:.1f}%" if total_apps > 0 else "0%"
    )

    unreviewed_pct = (
        f"{unreviewed_count / total_apps * 100:.1f}%" if total_apps > 0 else "0%"
    )

    filter_label = {
        "user": "[green]USER APPS[/]",
        "system": "[yellow]WINDOWS/SYSTEM[/]",
        "all": "[cyan]ALL APPS[/]",
    }.get(app_filter_mode, app_filter_mode.upper())

    note = (
        f"[bold green]Approved[/]  "
        f"[bold yellow]Unreviewed[/]  "
        f"[bold green]Allow[/]  "
        f"[bold red]Block[/]  "
        f"[bold yellow]Unknown[/]   |   "
        f"Total: {total_apps}   "
        f"Rev: {reviewed_count} ({reviewed_pct})   "
        f"Unrev: {unreviewed_count} ({unreviewed_pct})   |   "
        f"Filter: {filter_label}   "
        f"N = cycle filter"
    )

    note_panel = Panel(note, border_style=border_style)
    note_height = render_height(note_panel)

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column(f"[1] {item_column_header}", no_wrap=True, ratio=2)
    table.add_column("[2] Location", width=12, no_wrap=True)
    table.add_column("[3] Reviewed", justify="center", width=10, no_wrap=True)
    table.add_column("[4] Firewall", justify="center", width=18, no_wrap=True)

    # Sort using the app inventory sort functions
    sorted_apps = sorted(
        apps,
        key=_get_app_inventory_sort_key_func(app_inventory_sort_key),
    )

    chrome = 4 + note_height
    max_rows = compute_max_rows(available_lines, chrome)

    total = len(sorted_apps)
    app_names = [app["name"] for app in sorted_apps]
    selected_app_inventory_item, app_inventory_scroll_offset = (
        _ensure_selection_visible(
            app_names,
            selected_app_inventory_item,
            app_inventory_scroll_offset,
            max_rows,
        )
    )

    app_inventory_scroll_offset = max(
        0, min(app_inventory_scroll_offset, max(0, total - max_rows))
    )
    window = sorted_apps[
        app_inventory_scroll_offset : app_inventory_scroll_offset + max_rows
    ]

    for app in window:
        is_selected = app["name"] == selected_app_inventory_item
        table.add_row(
            "> " if is_selected else "  ",
            app["name"],
            app["location_badge"],
            style_reviewed_status(app["reviewed"]),
            style_firewall_state(app["firewall_state"]),
            style="on grey23" if is_selected else None,
        )

    if not window:
        msg = (
            ("(scanning installed apps...)" if not _background_scan_progress["complete"] else "(no applications found)")
            if total == 0 else "(scrolled past the end)"
        )
        table.add_row("", msg, "-", "-", "-")

    range_lo = app_inventory_scroll_offset + 1 if total else 0
    range_hi = app_inventory_scroll_offset + len(window)

    title = (
        f"{title_prefix}  ({range_lo}-{range_hi}/{total})  "
        f"Sort: [bold]{app_inventory_sort_key}[/]  "
        f"Reviewed: {reviewed_count}  Unreviewed: {unreviewed_count}  {title_hint}"
    )
    return Group(Panel(table, title=title, border_style=border_style), note_panel)


def _scan_loading_hint():
    with _background_scan_lock:
        scan_complete = _background_scan_progress["complete"]
    return "" if scan_complete else " [dim](more apps loading in background...)[/]"


def build_app_inventory_panel(available_lines=None):
    """Running Processes Panel - shows current running processes with network activity."""

    return _build_app_list_panel(
        get_filtered_apps_for_view("inventory"),
        available_lines,
        item_column_header="Process",
        title_prefix=f"RUNNING PROCESSES [{app_filter_mode.upper()}]",
        border_style="cyan",
        title_hint="[N cycle filter]  Arrow keys navigate  Enter details  Space approve  K approve all  I active processes  U all apps  Esc/F back to main",
    )


def build_all_apps_panel(available_lines=None):
    """All apps inventory."""

    loading_hint = _scan_loading_hint()
    return _build_app_list_panel(
        get_filtered_apps_for_view("all_apps"),
        available_lines,
        item_column_header="Application",
        title_prefix=f"ALL APPS [{app_filter_mode.upper()}]",
        border_style="magenta",
        title_hint=f"[N cycle filter]  Arrow keys navigate  Enter details  Space approve  K approve all  I active processes  U all apps  Esc/F back to main{loading_hint}",
    )


def build_firewall_detail_panel(available_lines=None):
    """Process Firewall Detail Panel - shows process details and firewall control options."""
    global firewall_detail_scroll_offset

    if not selected_firewall_rule:
        return Panel(
            "No process selected - use arrows to select a process, then press Enter.",
            title="Process Firewall Details",
            border_style="yellow",
        )

    rows = dict(compute_rows())
    selected_process_data = rows.get(selected_firewall_rule)

    if not selected_process_data:
        return Panel(
            f"Process '{selected_firewall_rule}' not found (may have exited).",
            title="Process Firewall Details",
            border_style="yellow",
        )

    pid = selected_process_data.get("pid")
    connections = selected_process_data.get("connections", {})
    total_bytes = selected_process_data["sent"] + selected_process_data["recv"]

    # Get process info
    exe_info = (
        get_process_info(pid)
        if pid
        else {"exe": "unknown", "parent_name": "unknown", "username": "unknown"}
    )
    exe_path = exe_info.get("exe", "unknown")
    exe_location = classify_exe_location(exe_path)
    location_badge = exe_location_badge(exe_path)

    # Get unique domains
    domains = set()
    domain_connections = {}
    for ckey, cdata in connections.items():
        _proto, _lip, _lport, rip, _rport = ckey
        domain, _ = get_smart_domain_name(cdata, rip)
        if domain != "Unknown domain":
            domains.add(domain)
            domain_connections[domain] = (
                domain_connections.get(domain, 0) + cdata["sent"] + cdata["recv"]
            )

    # Sort domains by traffic
    sorted_domains = sorted(
        domain_connections.items(), key=lambda kv: kv[1], reverse=True
    )

    # Get signature info (non-blocking: computed in the background on first view)
    _sha, sig_status, publisher, forensics_ready = file_forensics_or_placeholder(exe_path)

    # Firewall rules whose program filter is exactly this executable
    related_rules = rules_for_program(get_firewall_rules(), exe_path)

    # Build detailed information
    lines = [
        "[bold]PROCESS FIREWALL PROFILE[/]",
        "",
        f"Process:     {selected_firewall_rule}",
        f"PID:         {pid or '-'}",
        *filter(None, [services_line(pid)]),
        f"Publisher:   {publisher}",
        f"Signed:      {sig_status}",
        f"Location:    {location_badge}",
        f"User:        {exe_info.get('username', '-')}",
        "",
        "[bold]NETWORK ACTIVITY[/]",
        f"Connections: {len(connections)}",
        f"Domains:     {len(domains)}",
        f"Total Data:  {bytes_fmt(total_bytes)}",
        f"Sent:        {bytes_fmt(selected_process_data['sent'])}",
        f"Received:    {bytes_fmt(selected_process_data['recv'])}",
    ]

    if sorted_domains:
        lines.append("")
        lines.append("[bold]TOP DOMAINS (by traffic)[/]")
        for domain, traffic in sorted_domains[:5]:
            lines.append(f"  {domain}  ({bytes_fmt(traffic)})")
        if len(sorted_domains) > 5:
            lines.append(f"  ... and {len(sorted_domains) - 5} more")

    if related_rules:
        lines.append("")
        lines.append(f"[bold]RELATED FIREWALL RULES: {len(related_rules)}[/]")
        for rule in related_rules[:3]:
            rule_name = rule.get("display_name") or rule.get("name", "Unknown")
            action = rule.get("action", "Unknown")
            enabled = "Enabled" if rule.get("enabled", False) else "Disabled"
            lines.append(f"  {escape(rule_name)}")
            lines.append(f"    {rule.get('direction', '-')} {action} | {enabled}")
        if len(related_rules) > 3:
            lines.append(f"  ... and {len(related_rules) - 3} more rules")
        lines.append("")
        lines.append("[dim]Press R to view all raw firewall rules[/]")

    lines += risk_indicator_lines(
        exe_location, forensics_ready, sig_status, is_lolbin(selected_firewall_rule.lower())
    )

    lines.append("")
    lines.append("[bold]ACTIONS[/]")
    lines.append("[dim]Press 'Enter' to view full connection details in main view[/]")
    lines.append("[dim]Press 'R' to view raw Windows Firewall rules[/]")
    lines.append("[dim]Press Esc to return to process list[/]")

    panel, firewall_detail_scroll_offset = build_scrollable_text_panel(
        lines,
        firewall_detail_scroll_offset,
        title_base="Process Firewall Profile",
        border_style="bright_yellow",
        back_hint="Esc back  Enter connections  R raw rules",
        available_lines=available_lines,
    )
    return panel

def build_app_detail_panel(available_lines=None):
    """Detail view for an item selected from Running Processes / All
    User Apps - the same Main -> v -> Enter -> Connection Inspector
    pattern, applied to Firewall's own list views. Enter used to just
    silently flip a review flag with zero context; this shows enough
    (publisher, signature, location, current firewall verdict) to
    actually decide Allow vs Block."""
    global app_detail_scroll_offset

    if not selected_app_inventory_item:
        return Panel(
            "No app selected - use arrows to select one, then press Enter.",
            title="Application Detail",
            border_style="yellow",
        )

    apps = get_filtered_apps_for_view(firewall_view_mode)
    app = next((a for a in apps if a["name"] == selected_app_inventory_item), None)
    if not app:
        return Panel(
            f"'{selected_app_inventory_item}' is no longer in the current list "
            "(filter changed, or it exited/was uninstalled).",
            title="Application Detail",
            border_style="yellow",
        )

    exe_path = app.get("path") or ""
    exe_location = app.get("location", "unknown")
    exe_label = EXE_LOCATION_LABEL.get(exe_location, "Unclassified")

    sha256, sig_status, publisher, forensics_ready = file_forensics_or_placeholder(exe_path)

    if forensics_ready:
        trust_assessment, trust_style = assess_file_trust(exe_path, sig_status, publisher, None)
    else:
        trust_assessment, trust_style = "Pending signature check...", "dim"
    is_lolbin_exe = is_lolbin(app["name"].lower())

    lines = [
        "[bold]APPLICATION FIREWALL PROFILE[/]",
        "",
        f"Application: {app['name']}",
        f"Path:        {exe_path or '-'}",
        f"Publisher:   {publisher}",
        f"Signed:      {sig_status}",
        f"Location:    {exe_label}",
        "",
        "[bold]FIREWALL[/]",
        f"State:       {style_firewall_state(app['firewall_state'])}",
        f"Reviewed:    {style_reviewed_status(app['reviewed'])}",
        "",
        f"Assessment: [{trust_style}]{trust_assessment}[/]",
    ]
    if trust_assessment in TRUST_ASSESSMENT_EXPLANATIONS:
        lines.append(f"[dim cyan]→ {TRUST_ASSESSMENT_EXPLANATIONS[trust_assessment]}[/]")

    if app.get("is_active"):
        conn_count = app.get("connections", 0)
        lines += ["", "[bold]NETWORK ACTIVITY[/]", f"Active connections: {conn_count}"]
        if conn_count == 0:
            lines.append("[dim]Currently running, no active connections observed yet.[/]")
    else:
        lines += ["", "[dim]Not currently running - no live connection data.[/]"]

    lines += risk_indicator_lines(exe_location, forensics_ready, sig_status, is_lolbin_exe)

    lines += [
        "",
        "[bold]ACTIONS[/]",
        "[dim]Press 'b' to Block this app, 'a' to Allow it, 'x' to clear NetSpy's rule[/]",
        "[dim]Press Space to toggle reviewed status[/]",
        "[dim]Press Esc to return to the list[/]",
    ]

    panel, app_detail_scroll_offset = build_scrollable_text_panel(
        lines, app_detail_scroll_offset,
        title_base="Application Detail", border_style="bright_yellow",
        back_hint="Esc back  b Block  a Allow  x Default  Space review",
        available_lines=available_lines,
    )
    return panel

def build_raw_firewall_panel(available_lines=None):
    """Raw Windows Firewall Rules Panel - shows actual firewall rules for expert users."""
    global raw_firewall_scroll_offset, selected_raw_firewall_rule

    rules = get_firewall_rules()

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("Rule Name", no_wrap=True, ratio=3)
    table.add_column("Direction", justify="center", width=10, no_wrap=True)
    table.add_column("Action", justify="center", width=8, no_wrap=True)
    table.add_column("Enabled", justify="center", width=8, no_wrap=True)
    table.add_column("Profile", justify="center", width=12, no_wrap=True)

    # Sort rules: enabled first, then by action, then by name
    def rule_sort_key(rule):
        enabled_priority = 0 if rule.get("enabled", False) else 1
        action_priority = {"Allow": 0, "Block": 1}.get(rule.get("action", ""), 2)
        name = rule.get("name", "").lower()
        return (enabled_priority, action_priority, name)

    sorted_rules = sorted(rules, key=rule_sort_key)

    max_rows = compute_max_rows(available_lines)

    total = len(sorted_rules)
    raw_firewall_scroll_offset = max(
        0, min(raw_firewall_scroll_offset, max(0, total - max_rows))
    )
    window = sorted_rules[
        raw_firewall_scroll_offset : raw_firewall_scroll_offset + max_rows
    ]

    # The selected rule is the top visible row - arrows scroll the list, so
    # the selection moves with it and A/B always act on the marked row.
    selected_raw_firewall_rule = window[0].get("name") if window else None

    # Calculate statistics
    enabled_count = sum(1 for rule in rules if rule.get("enabled", False))
    allow_count = sum(
        1
        for rule in rules
        if rule.get("action") == "Allow" and rule.get("enabled", False)
    )
    block_count = sum(
        1
        for rule in rules
        if rule.get("action") == "Block" and rule.get("enabled", False)
    )

    for rule in window:
        rule_id = rule.get("name", "")
        rule_name = escape(rule.get("display_name") or rule_id or "Unknown")
        direction = rule.get("direction", "-")
        action = rule.get("action", "-")
        enabled = rule.get("enabled", False)
        profile = rule.get("profile", "-")

        is_selected = rule_id == selected_raw_firewall_rule
        marker = "> " if is_selected else "  "

        # Style based on action and enabled state
        action_style = "bold green" if action == "Allow" else "bold red"
        enabled_style = "bold green" if enabled else "dim red"
        enabled_text = "Yes" if enabled else "No"

        table.add_row(
            marker,
            rule_name,
            direction,
            f"[{action_style}]{action}[/]",
            f"[{enabled_style}]{enabled_text}[/]",
            profile,
            style="on grey23" if is_selected else None,
        )

    if not window:
        if total == 0:
            msg = "(no firewall rules found - may need admin privileges)"
        else:
            msg = "(scrolled past the end)"
        table.add_row("", msg, "-", "-", "-", "-")

    range_lo = raw_firewall_scroll_offset + 1 if total else 0
    range_hi = raw_firewall_scroll_offset + len(window)
    title = (
        f"Raw Firewall Rules  ({range_lo}-{range_hi}/{total})  "
        f"Enabled: {enabled_count}  Allow: {allow_count}  Block: {block_count}  "
        f"Arrows move  A Allow  B Block (top row, marked >)  Esc back to process view"
    )

    note_lines = [
        "[bold]RAW WINDOWS FIREWALL RULES[/]",
        "",
        "Expert view showing actual Windows Firewall rules - not process-centric.",
        "Useful for firewall administrators, debugging, and power users.",
        "",
        "[bold green]Enabled Allow[/] rules = Windows lets this traffic through by default",
        "[bold red]Enabled Block[/] rules = Windows blocks this traffic by default",
        "[dim red]Disabled[/] rules = Rule exists but is not active",
        "",
        f"Total Rules: {total}  |  Active: {enabled_count}  |  Allowing: {allow_count}  |  Blocking: {block_count}",
        "",
        "[dim]Use arrows to move the marked (top) row, A to Allow it, B to Block it.[/]",
        "[dim]Press Esc to return to Process Firewall view.[/]",
        "[dim]This gives you expert-level access to Windows Firewall rules.[/]",
    ]

    note = "\n".join(note_lines)

    return Group(
        Panel(table, title=title, border_style="red"),
        Panel(note, border_style="red"),
    )


def build_basic_table():
    table = Table(box=box.HEAVY, expand=True, border_style="green")
    table.add_column("[1] Process", no_wrap=True, ratio=2)
    table.add_column("PID", justify="right", style="grey62", width=9, no_wrap=True)
    table.add_column("Protocol", justify="center", width=8, no_wrap=True)
    table.add_column("Remote address", no_wrap=True, ratio=3)
    table.add_column("Status", width=13, no_wrap=True)

    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        conns = []

    names = {}
    for c in conns:
        if not c.raddr:
            continue
        proto = TYPE_MAP.get(c.type, "?")
        pid = c.pid
        if pid not in names:
            names[pid] = (
                _safe(lambda: process_label(pid, psutil.Process(pid).name()), f"PID {pid}")
                if pid else UNKNOWN_PROCESS_NAME
            )
        pname = names[pid]
        remote = format_remote_highlighted(c.raddr.ip, c.raddr.port)
        rows.append((pname, pid, proto, remote, c.status))

    rows.sort(key=lambda r: r[0].lower())

    max_rows = max(3, get_body_height() - 4)
    global main_scroll_offset
    main_scroll_offset = max(0, min(main_scroll_offset, max(0, len(rows) - max_rows)))
    window = rows[main_scroll_offset : main_scroll_offset + max_rows]

    for pname, pid, proto, remote, status in window:
        table.add_row(pname, str(pid or "-"), proto, remote, status)

    if not window:
        table.add_row("(no active connections found)", "-", "-", "-", "-")

    title = (
        f"Connections ({main_scroll_offset + 1}-{main_scroll_offset + len(window)} of {len(rows)})"
        if rows
        else "Connections"
    )
    return Panel(table, title=title, border_style="green")


# ==========================================================
# BEACON WATCH (B)
#
# Detects highly regular reconnect patterns.
#
# Uses:
#   Interval
#   Jitter
#   Sample count
#
# Does NOT detect malware.
#
# It only highlights communication patterns that
# Shows entities that reconnect on a schedule.
# may deserve investigation.
# ==========================================================


def build_beacon_panel(available_lines=None):
    global beacon_scroll_offset

    rows = dict(compute_rows())
    results = compute_beacon_stats()
    now = time.time()

    table = Table(box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("[1] Entity", no_wrap=True, ratio=2)
    table.add_column("Type", justify="center", width=6, no_wrap=True)
    table.add_column("[2] Interval", justify="right", width=10, no_wrap=True)
    table.add_column("[3] Jitter", justify="right", width=9, no_wrap=True)
    table.add_column("Assessment", justify="center", width=14, no_wrap=True)
    table.add_column("[4] Samples", justify="right", width=9, no_wrap=True)
    table.add_column("[5] Last contact", justify="right", width=13, no_wrap=True)
    table.add_column("Process(es)", no_wrap=True, ratio=2)

    # Sort using the beacon sort functions
    sorted_results = sorted(
        results,
        key=BEACON_SORT_FUNCS.get(beacon_sort_key, BEACON_SORT_FUNCS["jitter"]),
    )

    max_rows = compute_max_rows(available_lines)

    total = len(sorted_results)
    beacon_scroll_offset = max(0, min(beacon_scroll_offset, max(0, total - max_rows)))
    window = sorted_results[beacon_scroll_offset : beacon_scroll_offset + max_rows]

    # Get the first assessment for explanation
    first_assessment = None
    if window:
        first_assessment = beacon_assessment(window[0]["jitter_pct"])

    for r in window:
        entity = r["entity"]
        entity_type = r["entity_type"]

        # Find processes for this entity
        procs = set()
        if entity_type == "domain":
            # Find processes connecting to this domain (SNI or looked-up name)
            for proc_name, data in rows.items():
                for ckey, cdata in data.get("connections", {}).items():
                    if get_smart_domain_name(cdata, ckey[3])[0] == entity:
                        procs.add(proc_name)
        elif entity_type == "ptr":
            # Find processes connecting to this PTR hostname
            for proc_name, data in rows.items():
                for ckey, cdata in data.get("connections", {}).items():
                    _, _, _, rip, _ = ckey
                    hostname = get_hostname(rip)
                    if hostname == entity:
                        procs.add(proc_name)
        else:
            # Find processes connecting to this IP
            _, procs = find_ip_relatives(rows, entity, None)

        proc_display = ", ".join(sorted(procs)) if procs else "-"
        jstyle = jitter_style(r["jitter_pct"])
        assessment = beacon_assessment(r["jitter_pct"])
        assessment_style = jstyle  # Use same color scheme as jitter

        # Format entity display based on type
        if entity_type == "domain":
            entity_display = f"[bold cyan]{entity}[/]"
        elif entity_type == "ptr":
            entity_display = f"[dim]{entity}[/]"
        else:
            entity_display = format_remote_highlighted(entity, None)

        table.add_row(
            entity_display,
            entity_type.upper(),
            duration_fmt(r["mean_interval"]),
            f"[{jstyle}]{r['jitter_pct']:.1f}%[/]",
            f"[{assessment_style}]{assessment}[/]",
            str(r["samples"]),
            age_fmt(now - r["last_seen"]),
            proc_display,
        )

    if not window:
        if total == 0:
            msg = (
                "(no recurring-connection pattern observed yet - needs at least "
                f"{BEACON_MIN_SAMPLES} reconnects to the same entity, "
                f"{BEACON_MIN_INTERVAL:.0f}s+ apart)"
            )
        else:
            msg = "(scrolled past the end)"
        table.add_row(msg, "-", "-", "-", "-", "-", "-")

    range_lo = beacon_scroll_offset + 1 if total else 0
    range_hi = beacon_scroll_offset + len(window)
    title = (
        f"Beacon Watch  ({range_lo}-{range_hi}/{total})  Sort: [bold]{beacon_sort_key}[/]  "
        f"Arrow keys scroll  [1-5 sort]  Esc/b back to main"
    )

    # Build note with inline explanation if available
    note_lines = [
        "[dim]Beacon Watch tracks domains (SNI), PTR hostnames, and IPs.  ",
        "Interval = average time between new connections.  ",
        "Jitter = how much that interval varies (stddev/mean) - lower means more regular.  ",
        "Assessment = interpretation of jitter pattern: Highly Regular (<5%), Regular (<15%), ",
        "Mixed (<50%), Burst/Interactive (>50%).  ",
        "A steady interval with low jitter is the classic signature of scheduled beacon traffic ",
        "(C2 check-ins, implants, monitoring agents) - this is an observation, not a verdict; ",
        "open the process in the main table (Enter) to look closer.[/]",
    ]

    # Add inline explanation for the first assessment
    if first_assessment:
        explanation_text = BEACON_ASSESSMENT_EXPLANATIONS.get(first_assessment, "")
        if explanation_text:
            note_lines.append("")
            note_lines.append(f"[dim cyan]Assessment: {first_assessment}[/]")
            note_lines.append(f"[dim cyan]→ {explanation_text}[/]")

    note = "\n".join(note_lines)

    return Group(
        Panel(table, title=title, border_style="red"),
        Panel(note, border_style="red"),
    )


def build_view(full_mode):
    parts = []
    header = build_header(full_mode)
    parts.append(header)
    used = render_height(header)

    if show_explainer:
        explainer = build_explainer_panel()
        if explainer is not None:
            parts.append(explainer)
            used += render_height(explainer)

    if show_listening:
        p = build_listening_panel()
        parts.append(p)
        used += render_height(p)
    with test_log_lock:
        if test_log:
            p = Panel(
                "\n".join(test_log),
                title="Test Mode Log (g to re-run)",
                border_style="green",
            )
            parts.append(p)
            used += render_height(p)

    try:
        total_height = console.size.height
    except Exception:
        total_height = 40

    hide_main_now = hide_main_in_detail and view_mode != "main"
    # Only build main table if we're not in a fullscreen view and not hiding it
    should_build_main = not hide_main_now and view_mode not in FULLSCREEN_VIEWS

    if should_build_main:
        main_budget = max(3, total_height - used - 6)
        if view_mode != "main":
            main_budget = min(main_budget, 8)
        main_panel = build_full_table(main_budget) if full_mode else build_basic_table()
        parts.append(main_panel)
        used += render_height(main_panel)

    remaining = max(4, total_height - used - 2)

    if full_mode and view_mode == "detail":
        dp = build_detail_panel(remaining)
        if dp:
            parts.append(dp)
    elif full_mode and view_mode == "inspector":
        parts.append(build_inspector_panel(remaining))
    elif full_mode and view_mode == "file_investigation":
        parts.append(build_file_investigation_panel(remaining))
    elif full_mode and view_mode == "beacons":
        parts.append(build_beacon_panel(remaining))
    elif full_mode and view_mode == "domains":
        parts.append(build_domain_panel(remaining))
    elif full_mode and view_mode == "process_domains":
        parts.append(build_process_domain_panel(remaining))
    elif full_mode and view_mode == "timeline":
        parts.append(build_timeline_panel(remaining))
    elif full_mode and view_mode == "system_summary":
        parts.append(build_system_summary_panel(remaining))
    elif view_mode == "firewall":
        fw_log = build_fw_action_panel()
        log_h = render_height(fw_log) if fw_log else 0
        # Reserve space for the firewall actions panel (at least 10 lines to ensure complete visibility)
        reserved_for_log = max(10, log_h) if fw_log else 0
        parts.append(build_firewall_panel(max(4, remaining - reserved_for_log)))
        if fw_log:
            parts.append(fw_log)
    elif view_mode == "firewall_detail":
        fw_log = build_fw_action_panel()
        log_h = render_height(fw_log) if fw_log else 0
        # Reserve space for the firewall actions panel (at least 10 lines to ensure complete visibility)
        reserved_for_log = max(10, log_h) if fw_log else 0
        parts.append(build_firewall_detail_panel(max(4, remaining - reserved_for_log)))
        if fw_log:
            parts.append(fw_log)
    elif view_mode == "app_detail":
        fw_log = build_fw_action_panel()
        log_h = render_height(fw_log) if fw_log else 0
        reserved_for_log = max(10, log_h) if fw_log else 0
        parts.append(build_app_detail_panel(max(4, remaining - reserved_for_log)))
        if fw_log:
            parts.append(fw_log)
    elif view_mode == "raw_firewall":
        fw_log = build_fw_action_panel()
        log_h = render_height(fw_log) if fw_log else 0
        parts.append(build_raw_firewall_panel(max(4, remaining - log_h)))
        if fw_log:
            parts.append(fw_log)

    elif view_mode == "help":
        parts.append(build_help_panel(remaining))
    elif view_mode == "learning":
        parts.append(build_learning_panel(remaining))
    elif view_mode == "win_tools":
        parts.append(build_win_tools_panel(remaining))

    return Group(*parts)


def list_interfaces():
    print('Available network interfaces (use with --iface "name"):\n')
    for name in psutil.net_if_addrs():
        print(f"  - {name}")


# ==========================================================
# APPLICATION ENTRYPOINT
#
# Initializes:
#
#   DNS subsystem
#   Capture subsystem
#   UI subsystem
#   Background worker threads
#
# Then starts the live Rich interface.
# ==========================================================


# ============================================================================
# 9. MAIN ENTRY POINT - Application initialization
# ============================================================================

def main():
    global FLASH_WINDOW, CONNECTION_RETENTION
    global MAX_CONNECTIONS_PER_PROCESS, LOCAL_IPS, capture_auto
    global CAPTURE_MODE, ONLINE_LOOKUPS, ETW_COUNT_BYTES

    parser = argparse.ArgumentParser(
        description="NetSpy - live per-process network monitor"
    )

    parser.add_argument("--version", action="version", version=f"NetSpy v{VERSION}")

    parser.add_argument(
        "--advanced",
        action="store_true",
        help=(
            "ADVANCED mode: Npcap packet capture (site names, TLS, ping) plus online "
            "lookups (reverse DNS, IP owner/country via ipwho.is, ip-api.com, rdap.org). "
            "Default is BASIC: private (NetSpy sends nothing), no capture driver needed."
        ),
    )

    parser.add_argument(
        "--iface",
        help="ADVANCED: capture on one interface only (see --list-interfaces)",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List interfaces and exit",
    )

    parser.add_argument("--basic", action="store_true", help=argparse.SUPPRESS)  # old flag; BASIC is the default

    parser.add_argument(
        "--test",
        action="store_true",
        help="Auto-run the test traffic burst shortly after startup",
    )

    parser.add_argument(
        "--flash-window",
        type=float,
        default=1.5,
        help=(
            "Seconds a Sent/Received cell stays bright after activity "
            "before fading (default 1.5)"
        ),
    )

    parser.add_argument(
        "--connection-retention",
        type=float,
        default=120.0,
        help=(
            "Seconds an idle connection stays tracked before it's "
            "dropped (default 120)"
        ),
    )

    parser.add_argument(
        "--max-connections-per-process",
        type=int,
        default=100,
        help=(
            "Hard cap on tracked connections per process; "
            "oldest dropped first (default 100)"
        ),
    )

    parser.add_argument(
        "--blocklist",
        help=(
            "Path to a file of blocklisted IPs/CIDRs "
            "(one per line, # comments allowed)"
        ),
    )

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    FLASH_WINDOW = args.flash_window
    CONNECTION_RETENTION = args.connection_retention
    MAX_CONNECTIONS_PER_PROCESS = args.max_connections_per_process

    want_advanced = args.advanced and not args.basic

    console.print(f"[bold green]NetSpy v{VERSION} starting...[/]")

    # ---------------------------------------------------------
    # BLOCKLIST
    # ---------------------------------------------------------

    if args.blocklist:
        loaded, skipped, err = load_blocklist(args.blocklist)

        if err:
            console.print(
                f"[red]Could not read blocklist:[/] {err}"
            )
        else:
            console.print(
                f"[yellow]Blocklist loaded:[/] {loaded} entries"
                + (
                    f" ({skipped} malformed lines skipped)"
                    if skipped
                    else ""
                )
            )

    # ---------------------------------------------------------
    # ADMIN CHECK
    # ---------------------------------------------------------

    if not is_admin():
        console.print(
            "[yellow]Note:[/] not running elevated - per-program byte counts need "
            "Windows' event tracing (ETW), which needs admin. Right-click your terminal "
            "and choose 'Run as administrator' for the full picture."
        )

    if want_advanced and not SCAPY_AVAILABLE:
        console.print(
            "[yellow]--advanced needs scapy and Npcap - starting in BASIC mode.[/] "
            "Install: pip install scapy dpkt  and Npcap: https://npcap.com/#download"
        )
        want_advanced = False

    if want_advanced and not DPKT_AVAILABLE:
        console.print(
            "[yellow]dpkt not available - every packet goes through Scapy (slower).[/] "
            "Run: pip install dpkt"
        )

    # ---------------------------------------------------------
    # LOCAL IP INITIALIZATION
    # ---------------------------------------------------------

    LOCAL_IPS = get_local_ips()

    etw_network = start_etw() and "network" in etw_status
    refresh_app_index_async()  # installed-programs index for processes whose path can't be read

    threads = []

    # ---------------------------------------------------------
    # CONNECTION REFRESH THREAD
    # ---------------------------------------------------------

    t_conn = threading.Thread(
        target=refresh_connections_loop,
        daemon=True,
    )

    t_conn.start()
    threads.append(t_conn)

    # ---------------------------------------------------------
    # KEYBOARD THREAD
    # ---------------------------------------------------------

    if HAVE_MSVCRT:
        t_key = threading.Thread(
            target=keyboard_listener_loop,
            daemon=True,
        )

        t_key.start()
        threads.append(t_key)

    else:
        console.print(
            "[yellow]Interactive key controls need Windows "
            "(msvcrt) - use Ctrl+C to quit.[/]"
        )

    # ---------------------------------------------------------
    # FULL MODE PACKET CAPTURE
    # ---------------------------------------------------------

    if want_advanced:
        if args.iface:
            _capture_ifaces.add(args.iface)
            threading.Thread(target=sniff_thread_func, args=(args.iface,), daemon=True).start()
        else:
            capture_auto = True
            ensure_capture_threads()
        threading.Thread(target=consume_packets_loop, daemon=True).start()

        time.sleep(1.0)  # give the sniffers a moment to open their adapters
        if capture_error and not _capture_ifaces:  # no adapter is being captured
            console.print(f"[red]Packet capture failed:[/] {capture_error}")
            console.print("[yellow]Falling back to BASIC mode.[/]")
            want_advanced = False

    if want_advanced:
        CAPTURE_MODE, ONLINE_LOOKUPS = "advanced", True
    elif etw_network:
        CAPTURE_MODE, ETW_COUNT_BYTES = "basic", True
    else:
        CAPTURE_MODE = "limited"
        console.print(f"[yellow]Per-program byte counts unavailable ({etw_status}) - showing the connection list only.[/]")
    full_mode = CAPTURE_MODE != "limited"

    # ---------------------------------------------------------
    # OPTIONAL TEST TRAFFIC
    # ---------------------------------------------------------

    if args.test:
        start_test_burst()

    # Give background threads a moment to populate initial state.
    time.sleep(0.5)

    # ---------------------------------------------------------
    # LIVE UI
    # ---------------------------------------------------------

    last_good_frame = None

    try:
        with Live(
            build_view(full_mode),
            console=console,
            screen=True,
            vertical_overflow="crop",
            auto_refresh=False,
        ) as live:

            while not stop_event.is_set():

                try:
                    frame = build_view(full_mode)
                    last_good_frame = frame

                except Exception:
                    # Keep displaying the last valid frame if one
                    # render cycle encounters an error.
                    frame = last_good_frame

                if frame is not None:
                    live.update(
                        frame,
                        refresh=True,
                    )

                # Keep the original stable update interval.
                time.sleep(0.25)

    except KeyboardInterrupt:
        pass

    finally:
        stop_event.set()

        console.print(
            "\n[cyan]Shutting down...[/]"
        )


def _script_path_from_prompt():
    """Path of netspy.py when started from the >>> prompt: run_path() sets
    __file__; exec(open(path).read()) doesn't, so the path is read from the
    command just typed (prompt history) or netspy.py in the current folder."""
    path = globals().get("__file__")
    if path and os.path.isfile(path):
        return os.path.abspath(path)
    try:
        import _pyrepl.readline as prompt_history  # the >>> prompt of Python 3.13+

        count = prompt_history.get_current_history_length()
        for n in range(count, max(count - 5, 0), -1):
            m = re.search(r"""open\(\s*r?["']([^"']+\.py)["']""", prompt_history.get_history_item(n) or "")
            if m and os.path.isfile(m.group(1)):
                return os.path.abspath(m.group(1))
    except Exception:
        pass
    path = os.path.join(os.getcwd(), "netspy.py")
    return path if os.path.isfile(path) else None


if __name__ == "__main__":
    if hasattr(sys, "ps1"):  # started from the interactive >>> prompt
        # The prompt shares the keyboard with NetSpy, so NetSpy is started again
        # in its own Administrator window. Options come from sys.argv, e.g.
        #   sys.argv = ["netspy.py", "--advanced"]   before exec()/run_path().
        script = _script_path_from_prompt()
        options = sys.argv[1:]
        if not options and script:
            # open() takes only a file name, so the mode is asked here instead.
            choice = input("Mode - 1 = BASIC (private), 2 = ADVANCED (packet capture) [1]: ").strip()
            if choice == "2" or choice.lower().startswith("a"):
                options = ["--advanced"]
        started = False
        if script and IS_WINDOWS:
            params = subprocess.list2cmdline([script] + options)
            started = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, os.path.dirname(script), 1
            ) > 32
        if started:
            print(f"NetSpy v{VERSION} opened in a new Administrator window"
                  + (f" with {' '.join(options)}." if options else " (BASIC mode)."))
        else:
            print(
                "NetSpy could not open its own window"
                + (" (the Administrator prompt was declined)." if script else " (netspy.py not found).")
                + "\nFrom this >>> prompt (change the path; the first line is only for ADVANCED):\n"
                '    import sys, runpy; sys.argv = ["netspy.py", "--advanced"]\n'
                '    runpy.run_path(r"C:\\path\\to\\netspy.py", run_name="__main__")\n'
                "Or from PowerShell (as Administrator):  python netspy.py  /  python netspy.py --advanced"
            )
    else:
        main()
