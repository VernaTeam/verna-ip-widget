"""Verna IP Widget (v3.5.3).

A tiny always-on-top, draggable desktop widget for Windows that shows the
current public IP, country name, country flag and city. VPN connect and
disconnect are reflected within ~2-3 seconds.

v3.5.3 fixes:
- "No connection" no longer lingers for over a minute after a Windows boot.
  The widget autostarts from the Run key before the network is usable, and
  because the local route already exists no signature change fires to force a
  re-fetch. Two changes: a failed fetch now retries on a 2s/4s/8s backoff
  instead of waiting out the 15s poll, and a fetch with no local route at all
  returns immediately (0.6 ms measured) rather than walking three APIs over
  two transports at an 8-second timeout each, which cost up to 48 seconds to
  learn what the routing table already knew.
- Fetch failures are logged. The log previously recorded startup and network
  changes but was silent about the thing that actually goes wrong.

v3.5.2 fixes:
- The traffic-path badge no longer trusts the registry alone. A VPN client
  that exits without clearing ProxyEnable leaves Windows advertising a proxy
  that nothing serves; the badge said PROXY while urllib quietly fell back to
  a direct connection and returned the user's real domestic IP. The badge now
  reads DIRECT when the configured proxy refuses connections, decided by a
  loopback liveness probe and confirmed by which transport actually carried
  the fetch.
- A failed fetch no longer contradicts itself. It used to print "No
  connection" while leaving the previous IP, city and ISP on screen. The last
  reading now survives but is dimmed and marked "(last known)", and the
  no-history case clears the detail lines instead.

v3.5 features:
- The right-click menu acts on the FIRST click. Every handler had been
  bound on the child widgets AND on the toplevel, but a child's bindtags
  already include the toplevel, so each one ran twice: two stacked menus,
  and wheel notches that stepped opacity and size by two.
- "Lock position": pins the widget where it is, so a stray drag cannot move
  it. Size and opacity stay adjustable while locked.
- The opacity menu shows which preset is active (radio marks), and both the
  opacity and size cascades show the current value in their label -- the
  opacity entries were plain commands with no indicator at all.

v3.4 features:
- Traffic-path badge: the widget now says HOW traffic leaves the machine
  (VPN / PROXY / DIRECT / OFFLINE), not just where it lands. Derived from
  the adapter that owns the outbound route plus the Windows proxy settings.
- ISP / organisation line, so a datacenter (VPN egress) is distinguishable
  from a local ISP even when both geolocate to the same country.
- Self-heal watchdog: every few seconds the widget verifies it is still
  viewable and on-screen, re-asserts always-on-top, and refuses to stay
  hidden when no tray icon exists to restore it from. An override-redirect
  window has no taskbar button and no Alt+Tab entry, so without this it can
  become permanently unreachable.
- Global hotkey Ctrl+Alt+I summons the widget from anywhere.
- Tray icon is re-created automatically when explorer.exe restarts
  (detected via a change of the Shell_TrayWnd window handle).
- Rotating log file next to the config, plus a tkinter callback-exception
  hook: a console-less build previously discarded every traceback.
- Periodic timers reschedule themselves in a finally block. Previously any
  exception permanently killed polling or VPN detection with no symptom
  other than a silently stale IP.
- "Reset appearance" menu entry, and the opacity wheel now requires Shift.
  A stray scroll used to drop the widget to 20% opacity and persist it.
- Position is clamped against the whole virtual desktop, not just the
  primary monitor, and re-clamped continuously rather than only at startup.

v3.3 features:
- Near-instant VPN detection WITHOUT hammering geolocation APIs. Every
  NET_CHECK_INTERVAL_MS the widget computes a purely LOCAL "network
  signature" (zero internet traffic): the local outbound IP (a UDP connect
  performs only a route lookup, no packets are sent) plus the Windows
  system proxy registry settings. TUN-mode VPNs change the former,
  system-proxy VPNs (v2rayN etc.) change the latter. When the signature
  changes, a forced geo fetch runs after a short debounce (network flaps
  several times during a VPN switch). The 15s background poll remains as a
  safety net for public-IP changes with no local footprint (e.g. switching
  servers inside the VPN app).
- "Refresh now" is a forced fetch: it starts a new fetch generation even if
  one is in flight; the older result is discarded by the sequence check.

v3.2 features:
- System tray icon (pystray + Pillow): the tray icon shows the CURRENT
  country flag and its tooltip shows "Country - IP". Left-click toggles
  widget visibility; right-click opens a menu (Show/Hide, Refresh, Exit).
- Graceful degradation: if pystray/Pillow are not installed, the widget
  runs exactly as before, just without a tray icon.
- All pystray callbacks are marshalled onto the tkinter main thread via
  root.after(); tkinter objects are never touched from the tray thread.

v3.1 fixes:
- Fresh urllib opener per request (re-reads Windows system proxy each time)
  with a direct-connection fallback, so VPN connect/disconnect is always
  reflected without restarting the app.
- Fetch watchdog + generation counter: a fetch thread stuck in DNS (not
  covered by urllib's timeout) can no longer freeze polling, and its late
  result can never overwrite fresher data.

v3 features:
- Single-instance guard (Windows named mutex): a second launch exits silently.
- Copy IP to clipboard (double-click or menu) with transient feedback.
- Status dot: green = data fresh, yellow = fetching, red = fetch failed.
- Country label flashes briefly when the public IP changes (VPN on/off).
- "Always on top" toggle, persisted.
- Atomic config writes; settings are flushed on exit.

v2 features:
- Resizable via discrete size tiers (Ctrl+MouseWheel or right-click menu).
- Window opacity control (MouseWheel over the widget, or menu presets).
- "Transparent background" mode: only text/flag float over the desktop.

Dependencies (optional, tray only): pystray, pillow.

Run without a console window (PowerShell, project dir):
    venv\\Scripts\\pythonw.exe ip_widget.py
Build (console-less exe):
    venv\\Scripts\\python.exe -m PyInstaller --onefile --noconsole --clean ^
        --hidden-import pystray._win32 --name VernaIPWidget ip_widget.py
"""

from __future__ import annotations

import base64
import ctypes
import io
import json
import logging
import logging.handlers
import os
import socket
import sys
import tempfile
import threading
import time
import tkinter as tk
import urllib.request
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

try:  # tray support is optional; the widget works without it
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

APP_NAME = "VernaIPWidget"
POLL_INTERVAL_MS = 15_000        # safety-net public IP re-check
NET_CHECK_INTERVAL_MS = 2_000    # local (zero-traffic) network signature check
NET_CHANGE_DEBOUNCE_MS = 1_200   # wait for the network to settle after a change
HTTP_TIMEOUT = 8  # seconds (covers connect/read, NOT DNS resolution)
FETCH_WATCHDOG_S = 45  # abandon a fetch thread stuck longer than this

# After a failed fetch, retry on a short backoff instead of waiting out the
# full poll interval. At boot the widget is launched from the Run key before
# Windows has finished bringing the network up: the route already exists, so
# no signature change fires, and a failed cycle can cost 3 APIs x 2 transports
# x HTTP_TIMEOUT before the 15s poll even comes round again. That left "No
# connection" on screen for over a minute on a machine that was online.
RETRY_BASE_MS = 2_000
RETRY_MAX_MS = POLL_INTERVAL_MS
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VernaIPWidget/3.5.3"

CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
CONFIG_SAVE_DEBOUNCE_MS = 600
LOG_FILE = CONFIG_DIR / "widget.log"
LOG_MAX_BYTES = 256 * 1024
LOG_BACKUPS = 1

# --- self-heal watchdog ---
SELF_HEAL_INTERVAL_MS = 3_000
# Re-assert always-on-top every Nth tick rather than every tick: another
# topmost window can quietly demote us, but SetWindowPos is not free.
TOPMOST_REASSERT_EVERY = 10
MIN_VISIBLE_PX = 24  # keep at least this much of the widget on-screen

# --- global hotkey (Ctrl+Alt+I) ---
HOTKEY_ID = 1
MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_NOREPEAT = 0x4000
WM_HOTKEY = 0x0312
VK_I = 0x49
HOTKEY_LABEL = "Ctrl+Alt+I"

# --- virtual desktop metrics (all monitors, not just the primary) ---
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79

# --- window visibility (Win32 truth, not Tk's bookkeeping) ---
GA_ROOT = 2
SW_SHOWNOACTIVATE = 4  # un-hide / un-minimise without stealing focus

FLAG_URL_TEMPLATE = "https://flagcdn.com/{size}/{cc}.png"
TRAY_FLAG_SIZE = "64x48"  # flagcdn asset used for the tray icon
TRAY_ICON_PX = 64         # square canvas size for the tray icon
RUN_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
PROXY_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
MUTEX_NAME = f"{APP_NAME}_singleton_mutex"
ERROR_ALREADY_EXISTS = 183

IP_CHANGE_FLASH_MS = 1500
COPY_FEEDBACK_MS = 1200

# --- colors ---
BG = "#1b1e2b"
FG = "#e8e8ea"
FG_DIM = "#9aa0b0"
FG_ERROR = "#e5534b"
BORDER = "#3a3f55"
ACCENT = "#4cc38a"       # also used for the "fresh" status dot and IP-change flash
STATUS_FETCHING = "#d29922"
STATUS_ERROR = "#e5534b"

# A configured system proxy that refuses connections is not a proxy in use.
# Only loopback proxies are probed on the timer: a refusal there is instant,
# while an unreachable remote address would block the UI thread for the whole
# timeout. Remote proxies fall back to the transport signal from the fetch.
PROXY_PROBE_TIMEOUT = 0.25
LOOPBACK_PREFIXES = ("127.", "localhost", "::1")

# --- traffic-path badge ---
PATH_VPN = "VPN"
PATH_PROXY = "PROXY"
PATH_DIRECT = "DIRECT"
PATH_OFFLINE = "OFFLINE"
PATH_COLORS = {
    PATH_VPN: "#4cc38a",
    PATH_PROXY: "#4cc38a",
    PATH_DIRECT: "#d29922",
    PATH_OFFLINE: "#e5534b",
}

# --- size tiers (font sizes, flag asset size, paddings) ---
SCALE_TIERS: list[dict[str, Any]] = [
    {"name": "Small",   "title_size": 8,  "detail_size": 7,  "flag": "16x12", "padx": 6,  "pady": 3},
    {"name": "Medium",  "title_size": 10, "detail_size": 9,  "flag": "32x24", "padx": 10, "pady": 6},
    {"name": "Large",   "title_size": 13, "detail_size": 11, "flag": "48x36", "padx": 12, "pady": 8},
    {"name": "X-Large", "title_size": 16, "detail_size": 13, "flag": "64x48", "padx": 14, "pady": 10},
]
DEFAULT_SCALE_INDEX = 1  # Medium

ALPHA_MIN = 0.20
ALPHA_MAX = 1.00
ALPHA_STEP = 0.05
ALPHA_PRESETS = [1.00, 0.80, 0.60, 0.40, 0.20]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# The shipped build is console-less (pythonw / --noconsole), so stderr goes
# nowhere: without this file every traceback was silently discarded, which is
# exactly the information needed to explain an intermittent disappearance.

def _setup_logging() -> logging.Logger:
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if logger.handlers:
        return logger
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS,
            encoding="utf-8", delay=True,
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
    except Exception:
        handler = logging.NullHandler()
    logger.addHandler(handler)
    return logger


LOG = _setup_logging()


@dataclass
class GeoInfo:
    ip: str
    country: str
    country_code: str  # ISO 3166-1 alpha-2, lowercase
    city: str
    isp: str = ""  # ISP / organisation, when the API supplies one


# ---------------------------------------------------------------------------
# Single instance guard (Windows named mutex)
# ---------------------------------------------------------------------------

_mutex_handle: Optional[int] = None  # kept alive for the whole process


def acquire_single_instance_lock() -> bool:
    """Return True if this is the only running instance.

    The mutex handle is intentionally never closed; Windows releases it
    automatically when the process exits.
    """
    global _mutex_handle
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _mutex_handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    return ctypes.get_last_error() != ERROR_ALREADY_EXISTS


# ---------------------------------------------------------------------------
# Local network state (zero internet traffic)
# ---------------------------------------------------------------------------

# IANA ifType values that indicate a virtual / tunnel interface.
IF_TYPE_PPP = 23
IF_TYPE_PROP_VIRTUAL = 53
IF_TYPE_TUNNEL = 131
VIRTUAL_IF_TYPES = frozenset({IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL, IF_TYPE_TUNNEL})

# Substrings found in the adapter Description/FriendlyName of the tunnel
# drivers Windows VPN and anti-censorship clients install. Matched
# case-insensitively; many of these present as ifType 6 (ethernet) so the
# ifType check alone is not enough.
VPN_ADAPTER_HINTS = (
    "wireguard", "wintun", "tap-windows", "tap adapter", "tap-win", "openvpn",
    "tunnel", "nordlynx", "proton", "mullvad", "expressvpn", "surfshark",
    "windscribe", "cloudflare warp", "warp", "zerotier", "tailscale",
    "singbox", "sing-box", "v2ray", "xray", "hysteria", "outline", "psiphon",
    "softether", "zscaler", "forticlient", "anyconnect", "pangp",
    "globalprotect", "checkpoint", "sonicwall", "pptp", "l2tp",
)

# GAA_FLAG_SKIP_ANYCAST | _MULTICAST | _DNS_SERVER | _FRIENDLY_NAME is NOT
# used: FriendlyName is wanted. Only the address families we never read are
# skipped.
GAA_FLAGS = 0x0002 | 0x0004 | 0x0008  # SKIP_ANYCAST | SKIP_MULTICAST | SKIP_DNS
AF_INET = 2
ERROR_BUFFER_OVERFLOW = 111


class _SOCKADDR(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_ubyte * 26)]


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.POINTER(_SOCKADDR)),
                ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


# Only the prefix up to Address is declared; the API fills a buffer sized from
# its own request, so the trailing fields simply go unread.
_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),
    ("IfIndex", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", wintypes.ULONG),
    ("Flags", wintypes.ULONG),
    ("Mtu", wintypes.ULONG),
    ("IfType", wintypes.DWORD),
    ("OperStatus", ctypes.c_uint),
]


def _sockaddr_to_ipv4(sockaddr: Any) -> str:
    """Extract the dotted-quad from a SOCKADDR_IN, or "" for other families."""
    if not sockaddr:
        return ""
    addr = sockaddr.contents
    if addr.sa_family != AF_INET:
        return ""
    # sockaddr_in: 2 bytes family, 2 bytes port, then the 4 address bytes.
    return ".".join(str(byte) for byte in bytes(addr.sa_data[2:6]))


def find_adapter_for_ip(local_ip: str) -> Optional[tuple[str, int]]:
    """Return (name, ifType) of the adapter holding local_ip, or None.

    Uses GetAdaptersAddresses so the answer reflects the interface the OS
    would actually route through. Guessing from the address range does not
    work: a VPN handing out 10.x is indistinguishable from a LAN.
    """
    if not local_ip:
        return None
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi")
        size = wintypes.ULONG(15 * 1024)
        for _ in range(3):
            buffer = ctypes.create_string_buffer(size.value)
            result = iphlpapi.GetAdaptersAddresses(
                AF_INET, GAA_FLAGS, None, buffer, ctypes.byref(size)
            )
            if result == ERROR_BUFFER_OVERFLOW:
                continue  # size now holds the required length; retry
            if result != 0:
                return None
            break
        else:
            return None

        node = ctypes.cast(buffer, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
        while node:
            adapter = node.contents
            unicast = adapter.FirstUnicastAddress
            while unicast:
                if _sockaddr_to_ipv4(unicast.contents.Address.lpSockaddr) == local_ip:
                    name = adapter.Description or adapter.FriendlyName or ""
                    return name, int(adapter.IfType)
                unicast = unicast.contents.Next
            node = adapter.Next
    except Exception:
        LOG.exception("adapter lookup failed")
    return None


def parse_proxy_endpoint(proxy: str) -> Optional[tuple[str, int]]:
    """Pull (host, port) out of a Windows ProxyServer value.

    The value takes several shapes: a bare "host:port", a scheme-qualified
    "http://host:port", or a per-protocol list
    "http=host:port;https=host:port". Any single endpoint is enough to probe.
    """
    if not proxy:
        return None
    candidate = proxy.strip()
    if ";" in candidate:  # per-protocol list; the first entry will do
        candidate = candidate.split(";", 1)[0]
    if "=" in candidate:  # "http=host:port"
        candidate = candidate.split("=", 1)[1]
    if "://" in candidate:  # "http://host:port"
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.strip().rstrip("/")
    if ":" not in candidate:
        return None
    host, _, port_text = candidate.rpartition(":")
    try:
        return host, int(port_text)
    except ValueError:
        return None


def is_loopback_proxy(proxy: str) -> bool:
    endpoint = parse_proxy_endpoint(proxy)
    if endpoint is None:
        return False
    host = endpoint[0].lower().strip("[]")
    return host.startswith(LOOPBACK_PREFIXES)


def is_proxy_reachable(proxy: str) -> bool:
    """True if something is listening on the configured proxy endpoint.

    A VPN client that exits without clearing ProxyEnable leaves the registry
    claiming a proxy that nothing serves. Reporting PROXY in that state is
    wrong: traffic is going out direct.
    """
    endpoint = parse_proxy_endpoint(proxy)
    if endpoint is None:
        return False
    try:
        with socket.create_connection(endpoint, timeout=PROXY_PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def looks_like_vpn(adapter_name: str, if_type: int) -> bool:
    if if_type in VIRTUAL_IF_TYPES:
        return True
    lowered = adapter_name.lower()
    return any(hint in lowered for hint in VPN_ADAPTER_HINTS)


@dataclass
class NetworkState:
    """A cheap, purely local fingerprint of the current network path.

    - local_ip: connect() on a UDP socket sends NO packets; it only asks the
      OS routing table which local address would be used. TUN-mode VPNs
      change this.
    - proxy: the Windows system proxy settings. System-proxy VPN clients
      (v2rayN, Nekoray, ...) toggle these.
    - adapter / if_type: which interface owns local_ip, used to tell a
      tunnel apart from a physical NIC.

    Any change in `signature` means the traffic path changed and the public
    IP should be re-checked immediately.
    """
    local_ip: str = ""
    proxy: str = ""
    adapter: str = ""
    if_type: int = 0
    # None = not probed yet. False = configured but nothing is listening.
    proxy_alive: Optional[bool] = None

    @property
    def signature(self) -> str:
        return f"{self.local_ip}|{self.proxy}"

    @property
    def path(self) -> str:
        """Classify the egress path for the badge.

        A configured-but-dead proxy reads as DIRECT, because that is where the
        traffic actually goes: urllib falls back to a direct connection and
        the widget itself gets its data that way.
        """
        if not self.local_ip:
            return PATH_OFFLINE
        if looks_like_vpn(self.adapter, self.if_type):
            return PATH_VPN
        if self.proxy and self.proxy_alive is not False:
            return PATH_PROXY
        return PATH_DIRECT


def read_network_state(with_adapter: bool = True) -> NetworkState:
    """Read the local network state. No internet traffic is generated.

    with_adapter=False skips the GetAdaptersAddresses walk, which is the only
    non-trivial part. The 2-second change poll uses that fast path; the
    adapter is resolved once per actual change.
    """
    local_ip = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(1.0)
            probe.connect(("8.8.8.8", 53))  # route lookup only, no I/O
            local_ip = probe.getsockname()[0]
    except OSError:
        pass  # no network at all; empty string is itself a valid signature

    proxy = ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_REG_KEY) as key:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enabled:
                proxy, _ = winreg.QueryValueEx(key, "ProxyServer")
    except OSError:
        pass

    state = NetworkState(local_ip=local_ip, proxy=str(proxy))
    if with_adapter:
        # Both of these are behind the flag deliberately. The 2-second change
        # poll uses the fast path, because a closed loopback port does NOT
        # refuse instantly on Windows -- it burns the whole timeout, and that
        # would stall the UI thread every tick. Here it costs one probe per
        # actual network change, and the transport signal from the next fetch
        # corrects the badge anyway.
        if state.proxy and is_loopback_proxy(state.proxy):
            state.proxy_alive = is_proxy_reachable(state.proxy)
        found = find_adapter_for_ip(local_ip)
        if found is not None:
            state.adapter, state.if_type = found
    return state


# ---------------------------------------------------------------------------
# Window placement helpers
# ---------------------------------------------------------------------------

def virtual_screen_rect() -> Optional[tuple[int, int, int, int]]:
    """Return (x, y, width, height) spanning every monitor, or None.

    winfo_screenwidth/height only describe the PRIMARY monitor, so clamping
    against them drags a widget parked on a secondary display back onto the
    primary one.
    """
    try:
        user32 = ctypes.windll.user32
        rect = (user32.GetSystemMetrics(SM_XVIRTUALSCREEN),
                user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
                user32.GetSystemMetrics(SM_CXVIRTUALSCREEN),
                user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        return rect if rect[2] > 0 and rect[3] > 0 else None
    except Exception:
        return None


def taskbar_handle() -> int:
    """HWND of the shell taskbar. It changes when explorer.exe restarts,
    which is also when every tray icon is silently dropped."""
    try:
        return int(ctypes.windll.user32.FindWindowW("Shell_TrayWnd", None) or 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# HTTP / geolocation
# ---------------------------------------------------------------------------

def _http_get(url: str, use_system_proxy: bool) -> bytes:
    """GET a URL with a FRESH opener per call.

    urllib.request.urlopen caches a global opener whose proxy settings are
    read once at first use. VPN clients toggle the Windows system proxy at
    runtime, so we must re-read it on every request. With
    use_system_proxy=False a direct connection is forced (covers the case
    where a closed VPN app left a dead system proxy behind).
    """
    handler = (
        urllib.request.ProxyHandler()      # re-reads current system proxy now
        if use_system_proxy
        else urllib.request.ProxyHandler({})  # force direct connection
    )
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with opener.open(request, timeout=HTTP_TIMEOUT) as response:
        return response.read()


def _http_get_resilient(url: str) -> tuple[bytes, bool]:
    """Try via the current system proxy first, then fall back to direct.

    Returns (body, proxy_path_worked). The second value is ground truth about
    where the traffic went: if the system proxy is configured but dead, the
    first attempt fails and the direct fallback is what actually succeeded.
    Discarding that was why a stale ProxyEnable made the badge lie.
    """
    try:
        return _http_get(url, use_system_proxy=True), True
    except Exception:
        return _http_get(url, use_system_proxy=False), False


def _http_get_body(url: str) -> bytes:
    """_http_get_resilient for callers that do not care about the transport."""
    return _http_get_resilient(url)[0]


def _parse_ip_api(raw: bytes) -> Optional[GeoInfo]:
    data = json.loads(raw)
    if data.get("status") != "success":
        return None
    return GeoInfo(
        ip=str(data.get("query", "")),
        country=str(data.get("country", "")),
        country_code=str(data.get("countryCode", "")).lower(),
        city=str(data.get("city", "")),
        isp=str(data.get("isp") or data.get("org") or ""),
    )


def _parse_ipwhois(raw: bytes) -> Optional[GeoInfo]:
    data = json.loads(raw)
    if not data.get("success", False):
        return None
    connection = data.get("connection")
    connection = connection if isinstance(connection, dict) else {}
    return GeoInfo(
        ip=str(data.get("ip", "")),
        country=str(data.get("country", "")),
        country_code=str(data.get("country_code", "")).lower(),
        city=str(data.get("city", "")),
        isp=str(connection.get("isp") or connection.get("org") or ""),
    )


def _parse_ipinfo(raw: bytes) -> Optional[GeoInfo]:
    data = json.loads(raw)
    ip = data.get("ip")
    if not ip:
        return None
    code = str(data.get("country", "")).lower()
    org = str(data.get("org", ""))
    if org.startswith("AS") and " " in org:
        org = org.split(" ", 1)[1]  # "AS15169 Google LLC" -> "Google LLC"
    return GeoInfo(
        ip=str(ip),
        country=code.upper(),  # ipinfo free tier returns only the code
        country_code=code,
        city=str(data.get("city", "")),
        isp=org,
    )


GEO_APIS: list[tuple[str, Callable[[bytes], Optional[GeoInfo]]]] = [
    ("http://ip-api.com/json/?fields=status,country,countryCode,city,query,isp,org", _parse_ip_api),
    ("https://ipwho.is/", _parse_ipwhois),
    ("https://ipinfo.io/json", _parse_ipinfo),
]


def fetch_geo() -> tuple[Optional[GeoInfo], Optional[bool]]:
    """Try each geolocation API in order; return the first valid result.

    Also returns whether the system-proxy path is what carried the request,
    or None if nothing succeeded. That is the most reliable statement the
    widget can make about where its traffic actually went.
    """
    if not read_network_state(with_adapter=False).local_ip:
        # No route at all. Walking every API and both transports here would
        # burn the better part of a minute to learn what the routing table
        # already said for free.
        LOG.info("no local route; skipping the geolocation fetch")
        return None, None

    for url, parser in GEO_APIS:
        try:
            body, via_proxy = _http_get_resilient(url)
            info = parser(body)
            if info and info.ip and info.country_code:
                return info, via_proxy
        except Exception:
            continue
    return None, None


def fetch_flag_png(country_code: str, size: str) -> Optional[bytes]:
    try:
        return _http_get_body(FLAG_URL_TEMPLATE.format(size=size, cc=country_code))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Windows startup (HKCU Run key, no admin needed)
# ---------------------------------------------------------------------------

def _startup_command() -> str:
    if getattr(sys, "frozen", False):  # running as a PyInstaller exe
        return f'"{sys.executable}"'
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    interpreter = pythonw if pythonw.exists() else Path(sys.executable)
    return f'"{interpreter}" "{Path(__file__).resolve()}"'


def is_startup_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_NAME)
        return True
    except OSError:
        return False


def set_startup(enabled: bool) -> None:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _startup_command())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Config persistence (position, scale, alpha, transparent mode, topmost)
# ---------------------------------------------------------------------------

def load_config() -> dict[str, Any]:
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(config: dict[str, Any]) -> None:
    """Atomic write: a crash/power-loss mid-write can never corrupt the file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=CONFIG_DIR, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                json.dump(config, tmp_file, indent=2)
            os.replace(tmp_path, CONFIG_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception:
        pass  # persistence is best-effort


# ---------------------------------------------------------------------------
# Tray icon images (Pillow)
# ---------------------------------------------------------------------------

def build_tray_image_from_flag(png: bytes) -> "Image.Image":
    """Center a 4:3 flag onto a transparent square canvas for the tray."""
    flag = Image.open(io.BytesIO(png)).convert("RGBA")
    canvas = Image.new("RGBA", (TRAY_ICON_PX, TRAY_ICON_PX), (0, 0, 0, 0))
    scaled_height = int(TRAY_ICON_PX * flag.height / flag.width)
    flag = flag.resize((TRAY_ICON_PX, scaled_height), Image.LANCZOS)
    canvas.paste(flag, (0, (TRAY_ICON_PX - scaled_height) // 2))
    return canvas


def build_fallback_tray_image() -> "Image.Image":
    """Simple dark badge with a green dot, used until a flag is available."""
    image = Image.new("RGBA", (TRAY_ICON_PX, TRAY_ICON_PX), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle([4, 14, 60, 50], radius=10, fill=(27, 30, 43, 255))
    draw.ellipse([26, 26, 38, 38], fill=(76, 195, 138, 255))
    return image


# ---------------------------------------------------------------------------
# Widget
# ---------------------------------------------------------------------------

class IPWidget:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title(APP_NAME)
        self.root.overrideredirect(True)          # frameless
        self.root.configure(bg=BORDER)
        # Without this, a traceback in any callback goes to a stderr that does
        # not exist in a console-less build.
        self.root.report_callback_exception = self._on_tk_exception

        self._drag_offset: tuple[int, int] = (0, 0)
        self._fetching = False
        self._fetch_started_at = 0.0   # time.monotonic() of the running fetch
        self._fetch_seq = 0            # generation counter for fetch results
        # Flag cache keyed by (country_code, size) so each tier gets a sharp asset.
        self._flag_cache: dict[tuple[str, str], tk.PhotoImage] = {}
        self._current_info: Optional[GeoInfo] = None
        self._save_job: Optional[str] = None
        self._flash_job: Optional[str] = None
        self._copy_feedback_job: Optional[str] = None
        self._dragging = False

        # --- network-change detection state ---
        self._net_state = read_network_state()
        self._net_signature = self._net_state.signature
        self._net_change_job: Optional[str] = None  # pending debounced fetch
        self._retry_job: Optional[str] = None       # pending backoff retry
        self._retry_delay_ms = RETRY_BASE_MS

        # --- self-heal state ---
        self._heal_tick = 0
        self._shutting_down = False
        self._hwnd = 0  # resolved lazily, once the window exists
        self._taskbar_hwnd = taskbar_handle()
        self._isp_shown = False

        # --- tray state ---
        self._tray_icon: Optional["pystray.Icon"] = None
        self._tray_country_code: Optional[str] = None  # flag currently on the tray
        self._widget_hidden = False

        # --- load persisted settings with safe defaults / validation ---
        config = load_config()
        raw_scale = config.get("scale", DEFAULT_SCALE_INDEX)
        self._scale_index: int = (
            raw_scale if isinstance(raw_scale, int) and 0 <= raw_scale < len(SCALE_TIERS)
            else DEFAULT_SCALE_INDEX
        )
        raw_alpha = config.get("alpha", 1.0)
        self._alpha: float = (
            min(max(float(raw_alpha), ALPHA_MIN), ALPHA_MAX)
            if isinstance(raw_alpha, (int, float)) else 1.0
        )
        self._transparent_bg: bool = bool(config.get("transparent", False))
        self._topmost: bool = bool(config.get("topmost", True))
        self._locked: bool = bool(config.get("locked", False))
        self._saved_pos = config.get("x"), config.get("y")

        # --- UI ---
        self.frame = tk.Frame(self.root, bg=BG)
        self.frame.pack(padx=1, pady=1)  # 1px border via root bg

        self.top_row = tk.Frame(self.frame, bg=BG)
        self.top_row.pack(anchor="w", fill="x")

        self.flag_label = tk.Label(self.top_row, bg=BG, fg=FG)
        self.flag_label.pack(side="left")

        self.country_label = tk.Label(self.top_row, text="Detecting...", bg=BG, fg=FG)
        self.country_label.pack(side="left", padx=(6, 0))

        self.status_dot = tk.Label(self.top_row, text="\u25cf", bg=BG, fg=STATUS_FETCHING)
        self.status_dot.pack(side="right", padx=(8, 0))

        # Answers the actual question the widget exists for: not only WHERE
        # traffic lands, but HOW it leaves this machine.
        self.path_badge = tk.Label(self.top_row, text="", bg=BG, fg=FG_DIM)
        self.path_badge.pack(side="right", padx=(8, 0))

        self.detail_label = tk.Label(self.frame, text="", bg=BG, fg=FG_DIM, justify="left")
        self.detail_label.pack(anchor="w")

        # Packed only when an ISP is known; a datacenter name here is what
        # distinguishes VPN egress from a local ISP in the same country.
        self.isp_label = tk.Label(self.frame, text="", bg=BG, fg=FG_DIM, justify="left")

        # --- bindings (on all widgets so any visible pixel is a grab handle) ---
        # Bind ONCE, on the toplevel only. Every child's bindtags already
        # contain the toplevel ("." — see Tk's default (widget, class,
        # toplevel, all) chain), so a binding here fires for events over any
        # child. Binding the same handler on the children as well ran every
        # handler TWICE per event: tk_popup posted two stacked menus, so the
        # first click only dismissed the top one and a second was needed to
        # reach an entry; the wheel also stepped opacity and size twice per
        # notch. Do not re-add per-child bindings.
        self.root.bind("<ButtonPress-1>", self._on_drag_start)
        self.root.bind("<B1-Motion>", self._on_drag_move)
        self.root.bind("<ButtonRelease-1>", self._on_drag_end)
        self.root.bind("<Double-Button-1>", self._copy_ip)
        self.root.bind("<Button-3>", self._show_menu)
        # Opacity needs Shift: a bare wheel event used to fade the widget to
        # 20% and persist it, which reads as "it vanished".
        self.root.bind("<Shift-MouseWheel>", self._on_wheel_opacity)
        self.root.bind("<Control-MouseWheel>", self._on_wheel_scale)

        self._build_menu()
        self._init_tray()
        self._apply_scale()
        self._apply_alpha()
        self._apply_transparency()
        self._apply_topmost()
        self._restore_position()
        self._render_path_badge()
        self._start_hotkey_listener()
        self._start_fetch()
        self.root.after(POLL_INTERVAL_MS, self._poll)
        self.root.after(NET_CHECK_INTERVAL_MS, self._watch_network)
        self.root.after(SELF_HEAL_INTERVAL_MS, self._self_heal)
        LOG.info(
            "started (path=%s adapter=%s topmost=%s transparent=%s alpha=%.2f)",
            self._net_state.path, self._net_state.adapter or "?",
            self._topmost, self._transparent_bg, self._alpha,
        )

    def _post(self, callback: Callable[..., Any], *args: Any) -> None:
        """Marshal a callback from a worker thread onto the tkinter main loop.

        Worker threads are daemons that outlive root.destroy(), so a fetch
        still in flight at exit would otherwise raise "main thread is not in
        main loop" out of a thread with nobody to catch it.
        """
        if self._shutting_down:
            return
        try:
            self.root.after(0, callback, *args)
        except (RuntimeError, tk.TclError):
            pass  # the interpreter is gone; the result is moot

    def _on_tk_exception(self, exc_type: Any, exc_value: Any, exc_tb: Any) -> None:
        LOG.error("unhandled callback exception",
                  exc_info=(exc_type, exc_value, exc_tb))

    # --- widget right-click menu ---

    def _build_menu(self) -> None:
        self.startup_var = tk.BooleanVar(value=is_startup_enabled())
        self.scale_var = tk.IntVar(value=self._scale_index)
        self.alpha_var = tk.DoubleVar(value=self._alpha)
        self.transparent_var = tk.BooleanVar(value=self._transparent_bg)
        self.topmost_var = tk.BooleanVar(value=self._topmost)
        self.lock_var = tk.BooleanVar(value=self._locked)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Refresh now", command=self._force_fetch)
        self.menu.add_command(label="Copy IP  (double-click)", command=self._copy_ip)
        if TRAY_AVAILABLE:
            # Only offer hiding when a tray icon exists to restore from.
            self.menu.add_command(
                label=f"Hide to tray  (back with {HOTKEY_LABEL})",
                command=self._hide_widget,
            )
        self.menu.add_separator()

        size_menu = tk.Menu(self.menu, tearoff=0)
        for index, tier in enumerate(SCALE_TIERS):
            size_menu.add_radiobutton(
                label=tier["name"],
                variable=self.scale_var,
                value=index,
                command=lambda i=index: self._set_scale(i),
            )
        self.menu.add_cascade(label="Size", menu=size_menu)
        self._size_entry = self.menu.index("end")

        opacity_menu = tk.Menu(self.menu, tearoff=0)
        for preset in ALPHA_PRESETS:
            # Radiobuttons, not commands: the old plain entries gave no
            # indication of which opacity was actually in effect.
            opacity_menu.add_radiobutton(
                label=f"{int(preset * 100)}%",
                variable=self.alpha_var,
                value=preset,
                command=lambda a=preset: self._set_alpha(a),
            )
        self.menu.add_cascade(label="Opacity", menu=opacity_menu)
        self._opacity_entry = self.menu.index("end")

        self.menu.add_checkbutton(
            label="Transparent background",
            variable=self.transparent_var,
            command=self._toggle_transparency,
        )
        self.menu.add_checkbutton(
            label="Always on top",
            variable=self.topmost_var,
            command=self._toggle_topmost,
        )
        self.menu.add_checkbutton(
            label="Lock position",
            variable=self.lock_var,
            command=self._toggle_lock,
        )
        self.menu.add_command(label="Reset appearance", command=self._reset_appearance)
        self.menu.add_separator()
        self.menu.add_command(label="Open log folder", command=self._open_log_folder)
        self.menu.add_checkbutton(
            label="Run at Windows startup",
            variable=self.startup_var,
            command=self._toggle_startup,
        )
        self.menu.add_separator()
        self.menu.add_command(label="Exit", command=self._exit)

    def _show_menu(self, event: tk.Event) -> None:
        """Post the right-click menu.

        This must be reached exactly once per right-click; see the binding
        block in __init__ for why binding it on the children too made it fire
        twice. grab_release is the pairing tk_popup documents -- without it
        the menu can keep an input grab after it unposts.
        """
        self._sync_menu_labels()
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _sync_menu_labels(self) -> None:
        """Show the live size and opacity in the cascade labels, so the
        current state is readable without opening the submenus."""
        try:
            self.menu.entryconfigure(
                self._size_entry,
                label=f"Size:  {self._tier['name']}  (Ctrl+Wheel)",
            )
            self.menu.entryconfigure(
                self._opacity_entry,
                label=f"Opacity:  {int(round(self._alpha * 100))}%  (Shift+Wheel)",
            )
        except tk.TclError:
            pass  # cosmetic only; never block the menu from opening

    # --- system tray ---
    # All pystray callbacks run on the tray's own thread; they must never
    # touch tkinter directly. Each one marshals onto the main thread via
    # root.after(0, ...).

    def _init_tray(self) -> None:
        if not TRAY_AVAILABLE:
            return
        try:
            tray_menu = pystray.Menu(
                pystray.MenuItem(
                    "Show / Hide widget",
                    self._on_tray_toggle,
                    default=True,  # left-click action
                ),
                pystray.MenuItem("Refresh now", self._on_tray_refresh),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", self._on_tray_exit),
            )
            self._tray_icon = pystray.Icon(
                APP_NAME, build_fallback_tray_image(), APP_NAME, tray_menu
            )
            self._tray_icon.run_detached()
        except Exception:
            self._tray_icon = None  # tray is optional; never break the widget

    def _on_tray_toggle(self, _icon: Any, _item: Any) -> None:
        self._post(self._toggle_widget_visibility)

    def _on_tray_refresh(self, _icon: Any, _item: Any) -> None:
        self._post(self._force_fetch)

    def _on_tray_exit(self, _icon: Any, _item: Any) -> None:
        self._post(self._exit)

    def _toggle_widget_visibility(self) -> None:
        if self._widget_hidden:
            self._show_widget()
        else:
            self._hide_widget()

    def _hide_widget(self) -> None:
        if self._tray_icon is None:
            return  # never hide without a tray icon to restore from
        self.root.withdraw()
        self._widget_hidden = True

    def _show_widget(self) -> None:
        self.root.deiconify()
        self._force_show_window()
        # Re-assert frameless/topmost: some Windows shells reset these
        # after a withdraw/deiconify cycle on override-redirect windows.
        self.root.overrideredirect(True)
        # An override-redirect window has no taskbar button and no Alt+Tab
        # entry, so deiconify alone can leave it buried behind other windows
        # whenever always-on-top is off.
        self.root.lift()
        self._apply_topmost()
        self._widget_hidden = False

    def _summon(self, _event: Optional[tk.Event] = None) -> None:
        """Bring the widget back from anywhere (global hotkey or menu)."""
        LOG.info("summoned")
        self._show_widget()
        self._ensure_on_screen()
        self._flash_country()  # a cue for where on screen it actually is

    # --- global hotkey ---

    def _start_hotkey_listener(self) -> None:
        threading.Thread(target=self._hotkey_worker, daemon=True).start()

    def _hotkey_worker(self) -> None:
        """Own thread with its own message queue.

        RegisterHotKey with a NULL window posts WM_HOTKEY to the CALLING
        thread's queue, so this thread must both register and pump. The
        callback is marshalled onto the tkinter main thread.
        """
        try:
            user32 = ctypes.windll.user32
            registered = user32.RegisterHotKey(
                None, HOTKEY_ID, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, VK_I
            )
            if not registered:
                LOG.warning("global hotkey %s unavailable (another app owns it)",
                            HOTKEY_LABEL)
                return
            LOG.info("global hotkey %s registered", HOTKEY_LABEL)
            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message == WM_HOTKEY:
                    self._post(self._summon)
        except Exception:
            LOG.exception("hotkey listener stopped")

    # --- self-heal watchdog ---

    def _self_heal(self) -> None:
        """Keep the widget reachable.

        A frameless override-redirect window cannot be restored by the user:
        no taskbar button, no Alt+Tab entry. Anything that hides it -- a
        shell "show desktop", a resolution change parking it off-screen, a
        lost topmost flag, a tray icon dropped by an explorer restart --
        would otherwise be permanent.
        """
        try:
            self._heal_tick += 1
            if self._widget_hidden:
                if self._tray_icon is None:
                    LOG.warning("hidden with no tray icon to restore from; forcing it back")
                    self._show_widget()
            else:
                if not self.root.winfo_viewable() or self._shell_hid_the_window():
                    LOG.warning("window was hidden or minimised; restoring it")
                    self.root.deiconify()
                    self.root.overrideredirect(True)
                    self._force_show_window()
                    self.root.lift()
                self._ensure_on_screen()
                if self._topmost and self._heal_tick % TOPMOST_REASSERT_EVERY == 0:
                    self.root.attributes("-topmost", True)
            self._check_shell_restart()
        except Exception:
            LOG.exception("self-heal tick failed")
        finally:
            self.root.after(SELF_HEAL_INTERVAL_MS, self._self_heal)

    def _toplevel_hwnd(self) -> int:
        """HWND of the actual top-level window.

        winfo_id() returns Tk's inner child window; the shell acts on its
        root ancestor, so that is the handle whose visibility must be read.
        """
        if self._hwnd:
            return self._hwnd
        try:
            self._hwnd = int(ctypes.windll.user32.GetAncestor(
                self.root.winfo_id(), GA_ROOT))
        except Exception:
            LOG.exception("could not resolve the top-level window handle")
            self._hwnd = 0
        return self._hwnd

    def _shell_hid_the_window(self) -> bool:
        """True when Windows itself hid or minimised us.

        "Show desktop" (Win+D) and friends act directly on the HWND, so Tk
        still believes the window is mapped and winfo_viewable() keeps
        returning True. A frameless window has no taskbar button, so without
        this check the user has no way to bring it back.
        """
        hwnd = self._toplevel_hwnd()
        if not hwnd:
            return False
        try:
            user32 = ctypes.windll.user32
            return not user32.IsWindowVisible(hwnd) or bool(user32.IsIconic(hwnd))
        except Exception:
            return False

    def _force_show_window(self) -> None:
        hwnd = self._toplevel_hwnd()
        if not hwnd:
            return
        try:
            ctypes.windll.user32.ShowWindow(hwnd, SW_SHOWNOACTIVATE)
        except Exception:
            LOG.exception("ShowWindow failed")

    def _ensure_on_screen(self) -> None:
        """Drag the window back onto the virtual desktop if it is outside it."""
        if self._dragging:
            return  # do not fight an in-progress drag
        width, height = self.root.winfo_width(), self.root.winfo_height()
        if width <= 1 or height <= 1:
            return  # not laid out yet
        rect = virtual_screen_rect()
        if rect is None:
            origin_x, origin_y = 0, 0
            span_w = self.root.winfo_screenwidth()
            span_h = self.root.winfo_screenheight()
        else:
            origin_x, origin_y, span_w, span_h = rect
        x, y = self.root.winfo_x(), self.root.winfo_y()
        clamped_x = min(max(x, origin_x), max(origin_x, origin_x + span_w - width))
        clamped_y = min(max(y, origin_y), max(origin_y, origin_y + span_h - height))
        if (clamped_x, clamped_y) != (x, y):
            LOG.warning("window was off-screen at (%d, %d); moved to (%d, %d)",
                        x, y, clamped_x, clamped_y)
            self.root.geometry(f"+{clamped_x}+{clamped_y}")
            self._schedule_save()

    def _check_shell_restart(self) -> None:
        """Re-create the tray icon after explorer.exe restarts.

        pystray does not listen for the TaskbarCreated broadcast, so its icon
        is gone for good otherwise. The taskbar window handle changing is a
        cheap, reliable proxy for that event.
        """
        hwnd = taskbar_handle()
        if not hwnd:
            return
        if self._taskbar_hwnd and hwnd != self._taskbar_hwnd:
            LOG.warning("explorer restart detected (taskbar %d -> %d); "
                        "re-creating the tray icon", self._taskbar_hwnd, hwnd)
            self._restart_tray()
        self._taskbar_hwnd = hwnd

    def _restart_tray(self) -> None:
        if not TRAY_AVAILABLE:
            return
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                LOG.exception("stopping the stale tray icon failed")
            self._tray_icon = None
        self._tray_country_code = None
        self._init_tray()
        if self._current_info is not None:
            self._update_tray_info(self._current_info)

    # --- appearance reset ---

    def _reset_appearance(self) -> None:
        """Escape hatch for a widget that has become invisible: full opacity,
        opaque background, always-on-top, default size, back on-screen."""
        LOG.info("appearance reset")
        self._scale_index = DEFAULT_SCALE_INDEX
        self._alpha = 1.0
        self._transparent_bg = False
        self._topmost = True
        self.scale_var.set(self._scale_index)
        self.transparent_var.set(False)
        self.topmost_var.set(True)
        self._apply_scale()
        self._apply_alpha()
        self._apply_transparency()
        self._show_widget()
        self._saved_pos = (None, None)  # forces the default top-right corner
        self._restore_position()
        self._render_flag()
        if self._current_info is not None:
            self._ensure_flag_async(self._current_info.country_code)
        self._save_now()

    def _open_log_folder(self) -> None:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            os.startfile(str(CONFIG_DIR))  # noqa: S606 - fixed, app-owned path
        except Exception:
            LOG.exception("could not open the log folder")

    def _update_tray_info(self, info: GeoInfo) -> None:
        """Update tray tooltip immediately; swap the flag icon if the
        country changed (flag bytes are fetched asynchronously)."""
        if self._tray_icon is None:
            return
        try:
            parts = [self._net_state.path, info.country, info.ip]
            if info.isp:
                parts.append(info.isp)
            if self._net_state.adapter:
                parts.append(f"via {self._net_state.adapter}")
            self._tray_icon.title = " \u00b7 ".join(parts)[:127]
        except Exception:
            LOG.exception("tray tooltip update failed")
        if info.country_code == self._tray_country_code:
            return

        code = info.country_code

        def worker() -> None:
            png = fetch_flag_png(code, TRAY_FLAG_SIZE)
            if png is not None:
                self._post(self._apply_tray_flag, code, png)

        threading.Thread(target=worker, daemon=True).start()

    def _apply_tray_flag(self, country_code: str, png: bytes) -> None:
        if self._tray_icon is None:
            return
        # A newer country may have arrived while the flag was downloading.
        if self._current_info is None or self._current_info.country_code != country_code:
            return
        try:
            self._tray_icon.icon = build_tray_image_from_flag(png)
            self._tray_country_code = country_code
        except Exception:
            pass  # keep the previous/fallback icon

    # --- scale (resize) ---

    @property
    def _tier(self) -> dict[str, Any]:
        return SCALE_TIERS[self._scale_index]

    def _set_scale(self, index: int) -> None:
        index = min(max(index, 0), len(SCALE_TIERS) - 1)
        if index == self._scale_index:
            return
        self._scale_index = index
        self.scale_var.set(index)
        self._apply_scale()
        self._render_flag()  # may fall back to text until the new size is fetched
        if self._current_info is not None:
            self._ensure_flag_async(self._current_info.country_code)
        self._schedule_save()

    def _apply_scale(self) -> None:
        tier = self._tier
        self.frame.config(padx=tier["padx"], pady=tier["pady"])
        title_font = ("Segoe UI", tier["title_size"], "bold")
        detail_font = ("Consolas", tier["detail_size"])
        self.flag_label.config(font=title_font)
        self.country_label.config(font=title_font)
        self.status_dot.config(font=("Segoe UI", tier["detail_size"]))
        self.path_badge.config(font=("Segoe UI", tier["detail_size"], "bold"))
        self.detail_label.config(font=detail_font)
        self.isp_label.config(font=detail_font)

    def _on_wheel_scale(self, event: tk.Event) -> None:
        direction = 1 if event.delta > 0 else -1
        self._set_scale(self._scale_index + direction)

    # --- opacity ---

    def _set_alpha(self, alpha: float) -> None:
        # Rounded so wheel steps land on clean values: 0.85000000000000001
        # would never match the 0.85 a radiobutton compares against.
        self._alpha = round(min(max(alpha, ALPHA_MIN), ALPHA_MAX), 2)
        self._apply_alpha()
        self._schedule_save()

    def _apply_alpha(self) -> None:
        self.root.attributes("-alpha", self._alpha)
        self.alpha_var.set(self._alpha)  # keeps the menu radio mark in sync

    def _on_wheel_opacity(self, event: tk.Event) -> None:
        direction = 1 if event.delta > 0 else -1
        self._set_alpha(self._alpha + direction * ALPHA_STEP)

    # --- transparent background ---

    def _toggle_transparency(self) -> None:
        self._transparent_bg = self.transparent_var.get()
        self._apply_transparency()
        self._schedule_save()

    def _apply_transparency(self) -> None:
        # Windows-specific: pixels matching the key color become fully
        # transparent AND click-through. Dragging then requires grabbing
        # the text/flag pixels themselves.
        key_color = BG if self._transparent_bg else ""
        try:
            self.root.wm_attributes("-transparentcolor", key_color)
        except tk.TclError:
            pass  # non-Windows platforms: silently ignore
        # Hide the 1px border in transparent mode, restore it otherwise.
        self.root.configure(bg=BG if self._transparent_bg else BORDER)

    # --- always on top ---

    def _toggle_topmost(self) -> None:
        self._topmost = self.topmost_var.get()
        self._apply_topmost()
        self._schedule_save()

    def _apply_topmost(self) -> None:
        self.root.attributes("-topmost", self._topmost)

    # --- position lock ---

    def _toggle_lock(self) -> None:
        """Pin the widget in place. Size and opacity stay adjustable; only
        dragging is blocked. The self-heal clamp still overrides this -- a
        locked position that is off-screen is not worth honouring."""
        self._locked = self.lock_var.get()
        LOG.info("position %s", "locked" if self._locked else "unlocked")
        self._schedule_save()

    # --- copy IP ---

    def _copy_ip(self, _event: Optional[tk.Event] = None) -> None:
        if self._current_info is None or not self._current_info.ip:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._current_info.ip)
        self._show_copy_feedback()

    def _show_copy_feedback(self) -> None:
        if self._copy_feedback_job is not None:
            self.root.after_cancel(self._copy_feedback_job)
        self.detail_label.config(text="Copied \u2713", fg=ACCENT)
        self._copy_feedback_job = self.root.after(COPY_FEEDBACK_MS, self._restore_detail)

    def _restore_detail(self) -> None:
        self._copy_feedback_job = None
        if self._current_info is not None:
            city_part = f"  \u00b7  {self._current_info.city}" if self._current_info.city else ""
            self.detail_label.config(text=f"{self._current_info.ip}{city_part}", fg=FG_DIM)

    def _render_isp(self) -> None:
        """Show the ISP line only when there is one, so the widget does not
        grow an empty row on APIs that omit it."""
        isp = self._current_info.isp if self._current_info else ""
        if isp:
            self.isp_label.config(text=isp[:38])
            if not self._isp_shown:
                self.isp_label.pack(anchor="w")
                self._isp_shown = True
        elif self._isp_shown:
            self.isp_label.pack_forget()
            self._isp_shown = False

    # --- network-change detection (local, zero internet traffic) ---

    def _watch_network(self) -> None:
        """Every NET_CHECK_INTERVAL_MS compare the local network signature.
        On change, schedule a forced fetch after a debounce window: the
        network typically flaps several times while a VPN connects, and we
        want one fetch after it settles, not five during the transition."""
        try:
            # Fast path: the adapter walk is skipped until something changes.
            state = read_network_state(with_adapter=False)
            if state.signature != self._net_signature:
                self._net_signature = state.signature
                self._net_state = read_network_state()  # resolve the new path
                LOG.info("network path changed to %s (adapter=%s ifType=%d proxy=%s)",
                         self._net_state.path, self._net_state.adapter or "?",
                         self._net_state.if_type, self._net_state.proxy or "-")
                self._render_path_badge()
                if self._net_change_job is not None:
                    self.root.after_cancel(self._net_change_job)
                self._net_change_job = self.root.after(
                    NET_CHANGE_DEBOUNCE_MS, self._on_network_settled
                )
        except Exception:
            LOG.exception("network watch tick failed")
        finally:
            # Rescheduling must survive any failure above: an exception here
            # used to kill VPN detection permanently, with no symptom beyond
            # a silently stale IP.
            self.root.after(NET_CHECK_INTERVAL_MS, self._watch_network)

    def _render_path_badge(self) -> None:
        path = self._net_state.path
        self.path_badge.config(text=path, fg=PATH_COLORS.get(path, FG_DIM))

    def _on_network_settled(self) -> None:
        self._net_change_job = None
        self._force_fetch()

    # --- polling / fetching ---

    def _poll(self) -> None:
        try:
            self._start_fetch()
        except Exception:
            LOG.exception("poll tick failed")
        finally:
            self.root.after(POLL_INTERVAL_MS, self._poll)

    def _force_fetch(self) -> None:
        """Start a new fetch generation immediately, even if one is in
        flight; the in-flight result is discarded by the sequence check."""
        self._start_fetch(force=True)

    def _start_fetch(self, force: bool = False) -> None:
        """Start a background fetch unless one is running and still healthy.

        Watchdog: urllib's timeout does not cover DNS resolution, so a thread
        can hang indefinitely right after a VPN state change. If the running
        fetch is older than FETCH_WATCHDOG_S, abandon it (daemon thread) and
        start a new one. The generation counter makes late results from
        abandoned threads harmless. force=True skips the in-flight check
        entirely (used for manual refresh and network-change events).
        """
        now = time.monotonic()
        if (not force and self._fetching
                and (now - self._fetch_started_at) < FETCH_WATCHDOG_S):
            return
        self._cancel_retry()
        self._fetching = True
        self._fetch_started_at = now
        self._fetch_seq += 1
        self.status_dot.config(fg=STATUS_FETCHING)
        threading.Thread(
            target=self._fetch_worker, args=(self._fetch_seq,), daemon=True
        ).start()

    def _cancel_retry(self) -> None:
        if self._retry_job is not None:
            self.root.after_cancel(self._retry_job)
            self._retry_job = None

    def _schedule_retry(self) -> None:
        """Re-fetch soon after a failure, backing off toward the poll rate."""
        self._cancel_retry()
        delay = self._retry_delay_ms
        LOG.info("fetch failed; retrying in %.0fs", delay / 1000)
        self._retry_job = self.root.after(delay, self._on_retry)
        self._retry_delay_ms = min(delay * 2, RETRY_MAX_MS)

    def _on_retry(self) -> None:
        self._retry_job = None
        self._force_fetch()

    def _fetch_worker(self, seq: int) -> None:
        """Runs in a background thread. Only raw bytes cross the thread
        boundary; all tkinter objects are created on the main thread."""
        info, via_proxy = fetch_geo()
        flag_size = self._tier["flag"]
        flag_png: Optional[bytes] = None
        if info and (info.country_code, flag_size) not in self._flag_cache:
            flag_png = fetch_flag_png(info.country_code, flag_size)
        self._post(self._apply_result, seq, info, flag_png, flag_size,
                   via_proxy)

    def _ensure_flag_async(self, country_code: str) -> None:
        """Fetch the flag asset for the current tier size if not cached."""
        flag_size = self._tier["flag"]
        if (country_code, flag_size) in self._flag_cache:
            return

        def worker() -> None:
            png = fetch_flag_png(country_code, flag_size)
            if png is not None:
                self._post(self._cache_flag_and_render, country_code, flag_size, png)

        threading.Thread(target=worker, daemon=True).start()

    def _cache_flag_and_render(self, country_code: str, size: str, png: bytes) -> None:
        self._store_flag(country_code, size, png)
        self._render_flag()

    def _store_flag(self, country_code: str, size: str, png: bytes) -> None:
        try:
            image = tk.PhotoImage(data=base64.b64encode(png).decode("ascii"))
            self._flag_cache[(country_code, size)] = image
        except tk.TclError:
            pass

    def _apply_result(self, seq: int, info: Optional[GeoInfo],
                      flag_png: Optional[bytes], flag_size: str,
                      via_proxy: Optional[bool] = None) -> None:
        if seq != self._fetch_seq:
            return  # stale result from an abandoned fetch; a newer one owns the UI
        self._fetching = False

        # Ground truth beats the registry: if a proxy is configured but the
        # direct fallback is what carried the request, nothing is listening on
        # it and the real path is DIRECT.
        if via_proxy is not None and self._net_state.proxy:
            self._net_state.proxy_alive = via_proxy

        if info is None:
            self._schedule_retry()
            self.status_dot.config(fg=STATUS_ERROR)
            if self._current_info is None:
                self.country_label.config(text="No connection", fg=FG_ERROR)
                self.flag_label.config(image="", text="!")
                self.detail_label.config(text="", fg=FG_DIM)
                self._render_isp()
            else:
                # Keep the last reading but mark it stale. Printing "No
                # connection" above a live-looking IP, city and ISP made the
                # widget contradict itself.
                self.country_label.config(text=self._current_info.country, fg=FG_DIM)
                if self._copy_feedback_job is None:
                    city = self._current_info.city
                    city_part = f"  \u00b7  {city}" if city else ""
                    self.detail_label.config(
                        text=f"{self._current_info.ip}{city_part}   (last known)",
                        fg=FG_DIM,
                    )
            self._render_path_badge()
            return

        # Back to a clean slate: the next failure starts the backoff over.
        self._cancel_retry()
        self._retry_delay_ms = RETRY_BASE_MS

        previous_ip = self._current_info.ip if self._current_info else None
        self._current_info = info
        self.status_dot.config(fg=ACCENT)

        if flag_png and (info.country_code, flag_size) not in self._flag_cache:
            self._store_flag(info.country_code, flag_size, flag_png)

        self._render_flag()
        self._render_isp()
        self._render_path_badge()
        self._update_tray_info(info)
        self.country_label.config(text=info.country, fg=FG)
        # Don't overwrite the transient "Copied" feedback if it's showing.
        if self._copy_feedback_job is None:
            city_part = f"  \u00b7  {info.city}" if info.city else ""
            self.detail_label.config(text=f"{info.ip}{city_part}", fg=FG_DIM)

        if previous_ip is not None and previous_ip != info.ip:
            self._flash_country()

    def _flash_country(self) -> None:
        """Briefly highlight the country name: on a public-IP change, and to
        show where the widget is after it has been summoned."""
        if self._flash_job is not None:
            self.root.after_cancel(self._flash_job)
        self.country_label.config(fg=ACCENT)
        self._flash_job = self.root.after(IP_CHANGE_FLASH_MS, self._end_flash)

    def _end_flash(self) -> None:
        self._flash_job = None
        self.country_label.config(fg=FG)

    def _render_flag(self) -> None:
        """Show the flag image for the current tier, or a text fallback."""
        if self._current_info is None:
            return
        code = self._current_info.country_code
        flag_image = self._flag_cache.get((code, self._tier["flag"]))
        if flag_image is not None:
            self.flag_label.config(image=flag_image, text="")
        else:
            self.flag_label.config(image="", text=f"[{code.upper()}]")

    # --- dragging ---

    def _on_drag_start(self, event: tk.Event) -> None:
        if self._locked:
            return
        self._dragging = True
        self._drag_offset = (event.x_root - self.root.winfo_x(),
                             event.y_root - self.root.winfo_y())

    def _on_drag_move(self, event: tk.Event) -> None:
        if self._locked or not self._dragging:
            return
        x = event.x_root - self._drag_offset[0]
        y = event.y_root - self._drag_offset[1]
        self.root.geometry(f"+{x}+{y}")

    def _on_drag_end(self, _event: tk.Event) -> None:
        if not self._dragging:
            return  # locked, or a click that never became a drag
        self._dragging = False
        self._schedule_save()

    def _restore_position(self) -> None:
        """Place the widget, clamped to the virtual desktop (all monitors).

        Clamping against the primary monitor alone would yank a widget parked
        on a secondary display back onto the primary one at every start.
        """
        self.root.update_idletasks()
        rect = virtual_screen_rect()
        if rect is None:
            origin_x, origin_y = 0, 0
            span_w = self.root.winfo_screenwidth()
            span_h = self.root.winfo_screenheight()
        else:
            origin_x, origin_y, span_w, span_h = rect
        width = self.root.winfo_reqwidth()
        height = self.root.winfo_reqheight()

        x, y = self._saved_pos
        if not (isinstance(x, int) and isinstance(y, int)):
            # default: top-right corner of the primary area, small margin
            x = origin_x + span_w - width - 40
            y = origin_y + 40
        x = min(max(x, origin_x), max(origin_x, origin_x + span_w - width))
        y = min(max(y, origin_y), max(origin_y, origin_y + span_h - height))
        self.root.geometry(f"+{x}+{y}")

    # --- persistence (debounced: wheel events fire rapidly) ---

    def _schedule_save(self) -> None:
        if self._save_job is not None:
            self.root.after_cancel(self._save_job)
        self._save_job = self.root.after(CONFIG_SAVE_DEBOUNCE_MS, self._save_now)

    def _save_now(self) -> None:
        self._save_job = None
        save_config({
            "x": self.root.winfo_x(),
            "y": self.root.winfo_y(),
            "scale": self._scale_index,
            "alpha": round(self._alpha, 2),
            "transparent": self._transparent_bg,
            "topmost": self._topmost,
            "locked": self._locked,
        })

    # --- startup / exit ---

    def _toggle_startup(self) -> None:
        try:
            set_startup(self.startup_var.get())
        except OSError:
            self.startup_var.set(is_startup_enabled())

    def _exit(self) -> None:
        """Flush pending settings, stop the tray icon, destroy the window."""
        LOG.info("exiting")
        self._shutting_down = True  # stop worker threads posting into a dead loop
        self._cancel_retry()
        if self._save_job is not None:
            self.root.after_cancel(self._save_job)
        self._save_now()
        if self._tray_icon is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    if not acquire_single_instance_lock():
        sys.exit(0)  # another instance is already running
    IPWidget().run()
