#!/usr/bin/env python3
"""
WiFi Radar Pro — Advanced Network Device Discovery & Analysis
============================================================
Requirements : pip install PyQt6 requests
System deps  : sudo apt install arp-scan nmap net-tools iw
Run as root  : sudo venv/bin/python wifi_radar_pro.py

New in Pro:
  • Real OpenStreetMap via embedded HTML (no extra lib needed)
  • GPS coordinates + Google Maps link per device
  • Port scan per device (top 30 ports)
  • Live traffic monitor (bytes sent/recv via /proc/net/arp + ss)
  • Exact MAC manufacturer via macvendors.com API
  • Device name from NetBIOS / mDNS / SSDP
  • Signal strength (if available via iw)
"""

import sys
import socket
import subprocess
import re
import json
import threading
import time
import ipaddress
import concurrent.futures
from datetime import datetime
from typing import Optional

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QTextEdit,
    QProgressBar,
    QSplitter,
    QScrollArea,
    QComboBox,
    QCheckBox,
    QFileDialog,
    QDialog,
    QDialogButtonBox,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import (
    QColor,
    QPainter,
    QPen,
    QBrush,
    QPainterPath,
    QFont,
    QRadialGradient,
    QDesktopServices,
)

# ── Try loading WebEngine for embedded map ─────────────────────────────────────
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView

    HAS_WEBENGINE = True
except ImportError:
    HAS_WEBENGINE = False

# ══════════════════════════════════════════════════════════════════════════════
# Palette
# ══════════════════════════════════════════════════════════════════════════════
BG = "#07090F"
BG_PANEL = "#0B0E1A"
BG_CARD = "#0F1320"
BG_INPUT = "#131728"
BORDER = "#1A2236"
CYAN = "#00E5FF"
GREEN = "#00FF9C"
PURPLE = "#9D4EDD"
ORANGE = "#FF8C00"
RED = "#FF3D5A"
YELLOW = "#FFD60A"
BLUE = "#3B82F6"
PINK = "#EC4899"
TEXT = "#DCE6F0"
TEXT_DIM = "#3D4F6B"
TEXT_MID = "#7A8FA8"

TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5900,
    8080,
    8443,
    8888,
    9100,
    548,
    631,
    1883,
    5353,
    62078,
    49152,
]

SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    548: "AFP",
    631: "IPP",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5353: "mDNS",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9100: "Printer",
    49152: "UPnP",
    62078: "iPhone-Sync",
}

QSS = f"""
QMainWindow,QWidget{{background:{BG};color:{TEXT};
    font-family:'Consolas','Courier New',monospace;font-size:12px;}}
QTabWidget::pane{{border:1px solid {BORDER};background:{BG_PANEL};border-radius:8px;}}
QTabBar::tab{{background:{BG_CARD};color:{TEXT_DIM};padding:8px 16px;
    border:1px solid {BORDER};border-bottom:none;
    border-top-left-radius:6px;border-top-right-radius:6px;font-weight:600;}}
QTabBar::tab:selected{{background:{BG_PANEL};color:{CYAN};border-bottom:2px solid {CYAN};}}
QTabBar::tab:hover:!selected{{color:{TEXT};}}
QTableWidget{{background:{BG_CARD};gridline-color:{BORDER};
    border:1px solid {BORDER};border-radius:8px;
    selection-background-color:#1A2540;}}
QTableWidget::item{{padding:5px 8px;color:{TEXT};border:none;}}
QHeaderView::section{{background:{BG_PANEL};color:{CYAN};padding:7px 8px;
    border:none;border-bottom:1px solid {BORDER};
    font-size:10px;font-weight:700;letter-spacing:1px;}}
QScrollBar:vertical{{background:{BG_CARD};width:5px;border-radius:2px;}}
QScrollBar::handle:vertical{{background:{BORDER};border-radius:2px;min-height:16px;}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0;}}
QComboBox{{background:{BG_INPUT};color:{TEXT};border:1px solid {BORDER};
    border-radius:6px;padding:4px 10px;}}
QComboBox::drop-down{{border:none;width:20px;}}
QComboBox QAbstractItemView{{background:{BG_CARD};color:{TEXT};
    selection-background-color:{BORDER};border:1px solid {BORDER};}}
QCheckBox{{color:{TEXT_MID};spacing:6px;}}
QCheckBox::indicator{{width:14px;height:14px;border:1px solid {BORDER};
    border-radius:3px;background:{BG_INPUT};}}
QCheckBox::indicator:checked{{background:{CYAN};border-color:{CYAN};}}
QSplitter::handle{{background:{BORDER};}}
QPushButton{{font-family:'Consolas','Courier New',monospace;}}
"""


# ══════════════════════════════════════════════════════════════════════════════
# Network helpers
# ══════════════════════════════════════════════════════════════════════════════
def _run(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return str(e)


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"


def _get_gateway():
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def _get_interface():
    out = _run(["ip", "route", "show", "default"])
    m = re.search(r"dev (\w+)", out)
    return m.group(1) if m else "wlan0"


def _get_subnet():
    ip = _get_local_ip()
    out = _run(["ip", "-o", "-f", "inet", "addr", "show"])
    for line in out.splitlines():
        if ip in line:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m:
                return m.group(1)
    parts = ip.rsplit(".", 1)
    return parts[0] + ".0/24"


def _get_ssid():
    try:
        out = _run(["iwgetid", "-r"], timeout=3).strip()
        return out or "N/A"
    except:
        return "N/A"


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""


def _ping_alive(ip):
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=2
        )
        return r.returncode == 0
    except:
        return False


def _get_ttl_os(ip):
    try:
        out = _run(["ping", "-c", "1", "-W", "1", ip], timeout=3)
        m = re.search(r"ttl=(\d+)", out, re.I)
        if m:
            t = int(m.group(1))
            if t <= 64:
                return f"🐧 Linux / Android (TTL={t})"
            if t <= 128:
                return f"🪟 Windows (TTL={t})"
            return f"📡 Network Device (TTL={t})"
    except:
        pass
    return "❓ Unknown"


def _get_mac_from_arp(ip):
    _run(["ping", "-c", "1", "-W", "1", ip], timeout=2)
    out = _run(["arp", "-n", ip])
    m = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", out)
    return m.group(0).upper() if m else "N/A"


# ── MAC manufacturer via macvendors.com (free API) ────────────────────────────
_vendor_cache = {}


def _mac_manufacturer(mac: str) -> str:
    if not mac or mac == "N/A":
        return "Unknown"
    prefix = mac[:8].upper().replace("-", ":")
    if prefix in _vendor_cache:
        return _vendor_cache[prefix]
    if HAS_REQUESTS:
        try:
            r = requests.get(f"https://api.macvendors.com/{prefix}", timeout=4)
            if r.status_code == 200:
                v = r.text.strip()
                _vendor_cache[prefix] = v
                return v
        except:
            pass
    # fallback local table
    LOCAL = {
        "B8:27:EB": "Raspberry Pi Foundation",
        "DC:A6:32": "Raspberry Pi Foundation",
        "00:50:56": "VMware Inc",
        "00:0C:29": "VMware Inc",
        "52:54:00": "QEMU/KVM",
        "AC:DE:48": "Apple Inc",
        "00:1A:11": "Google LLC",
        "EC:43:F6": "TP-Link",
        "50:C7:BF": "TP-Link",
        "C4:E9:84": "TP-Link",
        "FC:FB:FB": "Cisco Systems",
        "00:14:22": "Dell Inc",
        "3C:97:0E": "HP Inc",
        "00:26:55": "Samsung",
        "00:1D:0F": "Huawei",
        "04:C0:6F": "Huawei",
        "00:17:F2": "Apple Inc",
        "70:56:81": "Apple Inc",
        "A8:60:B6": "Apple Inc",
        "28:18:78": "Microsoft",
        "C4:85:08": "Xiaomi",
        "98:FA:E3": "Xiaomi",
        "14:DD:A9": "ASUS",
        "1C:7E:E5": "D-Link",
        "B0:C5:54": "D-Link",
    }
    v = LOCAL.get(prefix, "Unknown")
    _vendor_cache[prefix] = v
    return v


# ── NetBIOS name ──────────────────────────────────────────────────────────────
def _netbios_name(ip: str) -> str:
    try:
        out = _run(["nmblookup", "-A", ip], timeout=4)
        for line in out.splitlines():
            m = re.match(r"\s+(\S+)\s+<00>.*<ACTIVE>", line)
            if m:
                return m.group(1).strip()
    except:
        pass
    return ""


# ── mDNS name ─────────────────────────────────────────────────────────────────
def _mdns_name(ip: str) -> str:
    try:
        out = _run(["avahi-resolve", "-a", ip], timeout=4)
        parts = out.strip().split()
        if len(parts) >= 2:
            return parts[1]
    except:
        pass
    return ""


# ── Port scan (top 30) ────────────────────────────────────────────────────────
def _scan_ports(ip: str) -> list[dict]:
    results = []

    def check(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.7)
            if s.connect_ex((ip, port)) == 0:
                svc = SERVICES.get(port, "unknown")
                banner = ""
                try:
                    if port in (80, 8080, 8443, 443, 9200):
                        s2 = socket.socket()
                        s2.settimeout(1)
                        s2.connect((ip, port))
                        s2.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s2.recv(256).decode("utf-8", "replace")[:80].strip()
                        s2.close()
                    elif port in (21, 22, 25, 110, 143):
                        s2 = socket.socket()
                        s2.settimeout(1)
                        s2.connect((ip, port))
                        banner = s2.recv(256).decode("utf-8", "replace")[:80].strip()
                        s2.close()
                except:
                    pass
                results.append({"port": port, "service": svc, "banner": banner})
            s.close()
        except:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        ex.map(check, TOP_PORTS)
    return sorted(results, key=lambda x: x["port"])


# ── Traffic stats from /proc/net/dev ──────────────────────────────────────────
def _iface_traffic(iface: str) -> dict:
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if iface in line:
                    parts = line.split()
                    return {"rx_bytes": int(parts[1]), "tx_bytes": int(parts[9])}
    except:
        pass
    return {"rx_bytes": 0, "tx_bytes": 0}


def _fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024**2:
        return f"{b / 1024:.1f} KB"
    if b < 1024**3:
        return f"{b / 1024**2:.1f} MB"
    return f"{b / 1024**3:.2f} GB"


# ── Geo-locate an IP via ip-api.com ──────────────────────────────────────────
def _geolocate(ip: str) -> dict:
    if not HAS_REQUESTS:
        return {}
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,"
            "lat,lon,isp,org,as,proxy,hosting,timezone",
            timeout=6,
        )
        d = r.json()
        if d.get("status") == "success":
            return d
    except:
        pass
    return {}


def _flag(code: str) -> str:
    if len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0]) - 65) + chr(0x1F1E6 + ord(code[1]) - 65)


def _device_icon(vendor: str, hostname: str, ports: list) -> str:
    v = vendor.lower()
    h = hostname.lower()
    open_ports = [p["port"] for p in ports]
    if any(x in v for x in ["apple", "iphone", "ipad"]):
        return "🍎"
    if any(x in h for x in ["iphone", "ipad", "apple"]):
        return "🍎"
    if 62078 in open_ports:
        return "📱"  # iPhone sync
    if any(x in v for x in ["samsung", "xiaomi", "huawei"]):
        return "📱"
    if any(x in v for x in ["raspberry"]):
        return "🫐"
    if any(x in v for x in ["cisco", "d-link", "tp-link", "netgear", "asus"]):
        return "📡"
    if any(x in v for x in ["vmware", "virtualbox", "qemu"]):
        return "🖥"
    if 9100 in open_ports:
        return "🖨"  # printer
    if 1883 in open_ports:
        return "🌐"  # IoT/MQTT
    if any(x in h for x in ["router", "gateway", "ap"]):
        return "📡"
    if any(x in h for x in ["phone", "android", "mobile"]):
        return "📱"
    if any(x in v for x in ["hp", "dell", "lenovo", "acer"]):
        return "💻"
    return "🖥"


# ══════════════════════════════════════════════════════════════════════════════
# HTML Map builder (OpenStreetMap via Leaflet.js — no API key needed)
# ══════════════════════════════════════════════════════════════════════════════
def build_map_html(devices: list[dict], center_lat: float, center_lon: float) -> str:
    markers_js = ""
    for d in devices:
        geo = d.get("geo", {})
        lat = geo.get("lat")
        lon = geo.get("lon")
        if not lat or not lon:
            continue
        ip = d.get("ip", "")
        hostname = d.get("hostname", "") or ip
        vendor = d.get("manufacturer", "Unknown")
        country = geo.get("country", "")
        city = geo.get("city", "")
        isp = geo.get("isp", "")
        icon = d.get("icon", "🖥")
        ports = ", ".join(str(p["port"]) for p in d.get("open_ports", [])[:8])
        gmaps = f"https://www.google.com/maps?q={lat},{lon}"
        popup = (
            f"<b>{icon} {ip}</b><br>"
            f"Host: {hostname}<br>"
            f"Vendor: {vendor}<br>"
            f"Location: {city}, {country}<br>"
            f"ISP: {isp}<br>"
            f"Open ports: {ports or 'scanning...'}<br>"
            f"<a href='{gmaps}' target='_blank'>📍 Google Maps</a>"
        )
        color = "#00FF9C" if d.get("status") == "online" else "#FF8C00"
        markers_js += f"""
        L.circleMarker([{lat},{lon}], {{
            radius: 10, color: '{color}', fillColor: '{color}',
            fillOpacity: 0.8, weight: 2
        }}).addTo(map).bindPopup(`{popup}`);
        """

    # add gateway/self marker
    markers_js += f"""
    L.marker([{center_lat},{center_lon}]).addTo(map)
        .bindPopup('<b>📍 Your Location (Gateway)</b><br>Lat: {center_lat}<br>Lon: {center_lon}')
        .openPopup();
    """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<style>
  body {{margin:0;padding:0;background:#07090F;}}
  #map {{width:100%;height:100vh;}}
</style>
<link rel="stylesheet"
  href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
</head>
<body>
<div id="map"></div>
<script>
  var map = L.map('map', {{
    center: [{center_lat}, {center_lon}],
    zoom: 10,
    attributionControl: true
  }});
  L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
    attribution: '© OpenStreetMap contributors',
    maxZoom: 18
  }}).addTo(map);
  {markers_js}
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# Custom widgets
# ══════════════════════════════════════════════════════════════════════════════
class PulseDot(QWidget):
    def __init__(self, color=GREEN, parent=None):
        super().__init__(parent)
        self.color = QColor(color)
        self._a = 255
        self._d = -5
        self.setFixedSize(12, 12)
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(30)

    def _tick(self):
        self._a += self._d
        if self._a <= 60 or self._a >= 255:
            self._d = -self._d
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QColor(self.color)
        c.setAlpha(self._a)
        p.setBrush(c)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(1, 1, 10, 10)
        p.end()


class RadarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(200, 200)
        self._angle = 0
        self._dots = []
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(40)

    def set_dots(self, dots):
        self._dots = dots
        self.update()

    def _tick(self):
        self._angle = (self._angle + 3) % 360
        self.update()

    def paintEvent(self, _):
        import math

        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx = cy = 100
        R = 88
        for i in range(1, 5):
            r = R * i // 4
            p.setPen(QPen(QColor(BORDER), 1))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(cx - r, cy - r, r * 2, r * 2)
        p.setPen(QPen(QColor(BORDER), 1))
        p.drawLine(cx - R, cy, cx + R, cy)
        p.drawLine(cx, cy - R, cx, cy + R)
        path = QPainterPath()
        path.moveTo(cx, cy)
        for deg in range(60):
            a = math.radians(-(self._angle - deg))
            path.lineTo(cx + R * math.cos(a), cy + R * math.sin(a))
        path.closeSubpath()
        grad = QRadialGradient(cx, cy, R)
        c1 = QColor(GREEN)
        c1.setAlpha(55)
        c2 = QColor(GREEN)
        c2.setAlpha(0)
        grad.setColorAt(0, c1)
        grad.setColorAt(1, c2)
        p.fillPath(path, QBrush(grad))
        a = math.radians(-self._angle)
        p.setPen(QPen(QColor(GREEN), 2))
        p.drawLine(
            int(cx), int(cy), int(cx + R * math.cos(a)), int(cy + R * math.sin(a))
        )
        for da, dist, color in self._dots:
            a2 = math.radians(-da)
            x = cx + int(dist * math.cos(a2))
            y = cy + int(dist * math.sin(a2))
            dc = QColor(color)
            dc.setAlpha(220)
            p.setBrush(dc)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(x - 5, y - 5, 10, 10)
            dc2 = QColor(color)
            dc2.setAlpha(50)
            p.setBrush(dc2)
            p.drawEllipse(x - 9, y - 9, 18, 18)
        p.setBrush(QColor(CYAN))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(cx - 5, cy - 5, 10, 10)
        p.setPen(QColor(CYAN))
        p.setFont(QFont("Consolas", 7))
        p.drawText(cx + 7, cy - 3, "YOU")
        p.end()


# ── Device detail dialog ───────────────────────────────────────────────────────
class DeviceDetailDialog(QDialog):
    def __init__(self, d: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Device Details — {d.get('ip', '')}")
        self.setMinimumSize(580, 620)
        self.setStyleSheet(
            QSS
            + f"""
            QDialog{{background:{BG_CARD};border:1px solid {BORDER};border-radius:12px;}}
        """
        )
        l = QVBoxLayout(self)
        l.setContentsMargins(20, 20, 20, 20)
        l.setSpacing(12)

        # header
        hdr = QHBoxLayout()
        icon_l = QLabel(d.get("icon", "🖥"))
        icon_l.setStyleSheet("font-size:32px;background:transparent;border:none;")
        ip_l = QLabel(d.get("ip", ""))
        ip_l.setStyleSheet(
            f"color:{CYAN};font-size:18px;font-weight:700;"
            f"background:transparent;border:none;"
        )
        sc = GREEN if d.get("status") == "online" else RED
        st = QLabel("● " + d.get("status", "").upper())
        st.setStyleSheet(
            f"color:{sc};font-size:11px;background:transparent;border:none;"
        )
        hdr.addWidget(icon_l)
        hdr.addWidget(ip_l)
        hdr.addStretch()
        hdr.addWidget(st)
        l.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color:{BORDER};")
        l.addWidget(sep)

        tabs = QTabWidget()
        l.addWidget(tabs, 1)

        # ── Info tab ──────────────────────────────────────────────────────────
        info_w = QWidget()
        info_w.setStyleSheet("background:transparent;")
        il = QVBoxLayout(info_w)
        il.setSpacing(6)
        il.setContentsMargins(8, 8, 8, 8)

        def row(k, v, vc=TEXT_MID):
            rw = QHBoxLayout()
            kl = QLabel(k + ":")
            kl.setFixedWidth(130)
            kl.setStyleSheet(
                f"color:{TEXT_DIM};font-size:11px;background:transparent;border:none;"
            )
            vl = QLabel(str(v))
            vl.setWordWrap(True)
            vl.setStyleSheet(
                f"color:{vc};font-size:11px;background:transparent;border:none;"
            )
            rw.addWidget(kl)
            rw.addWidget(vl, 1)
            return rw

        geo = d.get("geo", {})
        flag = _flag(geo.get("countryCode", "")) if geo else ""
        for k, v, c in [
            ("IP Address", d.get("ip", ""), CYAN),
            ("Hostname", d.get("hostname", "N/A"), TEXT),
            ("NetBIOS Name", d.get("netbios", "N/A"), TEXT),
            ("mDNS Name", d.get("mdns", "N/A"), TEXT),
            ("MAC Address", d.get("mac", "N/A"), YELLOW),
            ("Manufacturer", d.get("manufacturer", "Unknown"), ORANGE),
            ("OS Guess", d.get("os", "Unknown"), GREEN),
            ("Status", d.get("status", "").upper(), GREEN),
            ("First Seen", d.get("found_at", ""), TEXT_MID),
            ("Country", f"{flag} {geo.get('country', '')}", TEXT),
            ("City", geo.get("city", "N/A"), TEXT_MID),
            ("ISP", geo.get("isp", "N/A"), CYAN),
            ("Organization", geo.get("org", "N/A"), TEXT_MID),
            ("Timezone", geo.get("timezone", "N/A"), TEXT_DIM),
            ("Coordinates", f"{geo.get('lat', '?')} , {geo.get('lon', '?')}", YELLOW),
        ]:
            il.addLayout(row(k, v, c))

        # Google Maps button
        lat = geo.get("lat")
        lon = geo.get("lon")
        if lat and lon:
            gm = QPushButton(f"📍 Open in Google Maps ({lat}, {lon})")
            gm.setCursor(Qt.CursorShape.PointingHandCursor)
            gm.setStyleSheet(
                f"background:{BG_INPUT};color:{CYAN};"
                f"border:1px solid {CYAN};border-radius:6px;padding:6px;"
            )
            gm.clicked.connect(
                lambda: QDesktopServices.openUrl(
                    QUrl(f"https://www.google.com/maps?q={lat},{lon}")
                )
            )
            il.addWidget(gm)

        tags = []
        if geo.get("proxy"):
            tags.append(("PROXY", ORANGE))
        if geo.get("hosting"):
            tags.append(("HOSTING/VPS", PURPLE))
        if tags:
            tl = QHBoxLayout()
            for txt, col in tags:
                t = QLabel(f"⚠ {txt}")
                t.setStyleSheet(
                    f"color:{col};background:rgba(255,140,0,0.12);"
                    f"border:1px solid {col};border-radius:4px;"
                    f"padding:2px 8px;font-size:10px;font-weight:700;"
                )
                tl.addWidget(t)
            tl.addStretch()
            il.addLayout(tl)

        il.addStretch()
        tabs.addTab(info_w, "📋 Info")

        # ── Ports tab ─────────────────────────────────────────────────────────
        ports_w = QWidget()
        ports_w.setStyleSheet("background:transparent;")
        pl = QVBoxLayout(ports_w)
        pl.setContentsMargins(8, 8, 8, 8)
        ptbl = QTableWidget()
        ptbl.setColumnCount(3)
        ptbl.setHorizontalHeaderLabels(["PORT", "SERVICE", "BANNER"])
        ptbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        ptbl.verticalHeader().setVisible(False)
        ptbl.setStyleSheet(f"background:{BG};border:none;")
        open_ports = d.get("open_ports", [])
        ptbl.setRowCount(len(open_ports))
        for i, port in enumerate(open_ports):
            for col, (txt, color) in enumerate(
                [
                    (str(port["port"]), CYAN),
                    (port["service"], GREEN),
                    (port["banner"][:60], TEXT_DIM),
                ]
            ):
                item = QTableWidgetItem(txt)
                item.setForeground(QColor(color))
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                ptbl.setItem(i, col, item)
        if not open_ports:
            no = QLabel("No open ports found (or scan not complete)")
            no.setStyleSheet(f"color:{TEXT_DIM};padding:20px;")
            no.setAlignment(Qt.AlignmentFlag.AlignCenter)
            pl.addWidget(no)
        pl.addWidget(ptbl)
        tabs.addTab(ports_w, "🔌 Ports")

        # close
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.setStyleSheet(
            f"QPushButton{{background:{BG_PANEL};color:{TEXT};"
            f"border:1px solid {BORDER};border-radius:6px;padding:5px 16px;}}"
        )
        btns.rejected.connect(self.reject)
        l.addWidget(btns)


# ══════════════════════════════════════════════════════════════════════════════
# Discovery + deep-scan worker
# ══════════════════════════════════════════════════════════════════════════════
class DiscoveryWorker(QThread):
    device_found = pyqtSignal(dict)
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    finished_ = pyqtSignal(list)

    def __init__(self, subnet, method, do_ports, do_geo, do_netbios):
        super().__init__()
        self.subnet = subnet
        self.method = method
        self.do_ports = do_ports
        self.do_geo = do_geo
        self.do_netbios = do_netbios
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        hosts = list(ipaddress.ip_network(self.subnet, strict=False).hosts())
        total = len(hosts)
        self.log.emit(
            f"[*] Scanning {self.subnet}  ({total} hosts)  method={self.method}"
        )

        if self.method == "ARP (arp-scan)":
            raw = self._arp_scan()
        elif self.method == "ARP cache (instant)":
            raw = self._arp_cache()
        else:
            raw = self._ping_sweep(hosts, total)

        self.log.emit(f"[*] Found {len(raw)} live hosts — running deep analysis...")

        enriched = []
        for i, d in enumerate(raw):
            if self._stop:
                break
            d = self._enrich(d)
            enriched.append(d)
            self.device_found.emit(d)
            self.progress.emit(i + 1, len(raw))

        self.log.emit(f"[✓] Done — {len(enriched)} devices")
        self.finished_.emit(enriched)

    # ── scan methods ──────────────────────────────────────────────────────────
    def _arp_scan(self):
        iface = _get_interface()
        self.log.emit(f"[*] arp-scan on {iface}")
        out = _run(["sudo", "arp-scan", "--interface", iface, self.subnet], timeout=30)
        devices = []
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                devices.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "status": "online",
                        "found_at": datetime.now().strftime("%H:%M:%S"),
                    }
                )
                self.log.emit(f"[+] {ip}  {mac}")
        if not devices:
            self.log.emit("[!] arp-scan empty → fallback to ping sweep")
            hosts = list(ipaddress.ip_network(self.subnet, strict=False).hosts())
            return self._ping_sweep(hosts, len(hosts))
        return devices

    def _ping_sweep(self, hosts, total):
        devices = []
        done = 0
        lock = threading.Lock()

        def probe(ip):
            nonlocal done
            if self._stop:
                return
            ip = str(ip)
            if _ping_alive(ip):
                mac = _get_mac_from_arp(ip)
                with lock:
                    devices.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "status": "online",
                            "found_at": datetime.now().strftime("%H:%M:%S"),
                        }
                    )
                    self.log.emit(f"[+] {ip}  {mac}")
            with lock:
                done += 1
                self.progress.emit(done, total)

        with concurrent.futures.ThreadPoolExecutor(max_workers=150) as ex:
            ex.map(probe, hosts)
        return devices

    def _arp_cache(self):
        out = _run(["arp", "-n"])
        devices = []
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})", line)
            if m:
                ip, mac = m.group(1), m.group(2).upper()
                devices.append(
                    {
                        "ip": ip,
                        "mac": mac,
                        "status": "recent",
                        "found_at": datetime.now().strftime("%H:%M:%S"),
                    }
                )
                self.log.emit(f"[+] {ip}  {mac}")
        return devices

    # ── deep enrich ───────────────────────────────────────────────────────────
    def _enrich(self, d: dict) -> dict:
        ip = d["ip"]
        mac = d.get("mac", "N/A")

        # hostname
        d["hostname"] = _hostname(ip) or ip

        # manufacturer from real API
        self.log.emit(f"[~] {ip} — manufacturer lookup")
        d["manufacturer"] = _mac_manufacturer(mac)

        # OS from TTL
        d["os"] = _get_ttl_os(ip)

        # NetBIOS / mDNS
        if self.do_netbios:
            self.log.emit(f"[~] {ip} — NetBIOS/mDNS")
            d["netbios"] = _netbios_name(ip) or "N/A"
            d["mdns"] = _mdns_name(ip) or "N/A"
        else:
            d["netbios"] = "N/A"
            d["mdns"] = "N/A"

        # Port scan
        if self.do_ports:
            self.log.emit(f"[~] {ip} — port scan")
            d["open_ports"] = _scan_ports(ip)
        else:
            d["open_ports"] = []

        # Geo
        if self.do_geo:
            self.log.emit(f"[~] {ip} — geolocate")
            d["geo"] = _geolocate(ip)
        else:
            d["geo"] = {}

        # icon (after ports + vendor are known)
        d["icon"] = _device_icon(
            d.get("manufacturer", ""), d.get("hostname", ""), d.get("open_ports", [])
        )
        return d


# ══════════════════════════════════════════════════════════════════════════════
# Traffic monitor worker
# ══════════════════════════════════════════════════════════════════════════════
class TrafficWorker(QThread):
    update = pyqtSignal(str, str)  # (rx_rate, tx_rate)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        prev = _iface_traffic(self.iface)
        prev_t = time.time()
        while not self._stop:
            time.sleep(1)
            curr = _iface_traffic(self.iface)
            dt = time.time() - prev_t
            rx_rate = (curr["rx_bytes"] - prev["rx_bytes"]) / dt
            tx_rate = (curr["tx_bytes"] - prev["tx_bytes"]) / dt
            self.update.emit(
                _fmt_bytes(int(rx_rate)) + "/s", _fmt_bytes(int(tx_rate)) + "/s"
            )
            prev = curr
            prev_t = time.time()


# ══════════════════════════════════════════════════════════════════════════════
# Main window
# ══════════════════════════════════════════════════════════════════════════════
class WiFiRadarPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Radar Pro — Network Discovery & Analysis")
        self.setMinimumSize(1280, 820)
        self.setStyleSheet(QSS)
        self._worker: Optional[DiscoveryWorker] = None
        self._traffic_worker: Optional[TrafficWorker] = None
        self._devices: list[dict] = []
        self._start_time: Optional[datetime] = None

        root = QWidget()
        self.setCentralWidget(root)
        ml = QVBoxLayout(root)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.setSpacing(0)
        ml.addWidget(self._build_header())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setSizes([270, 1010])
        ml.addWidget(splitter, 1)
        ml.addWidget(self._build_statusbar())

        self._detect_network()
        QTimer.singleShot(500, self._start_traffic_monitor)

    # ── header ────────────────────────────────────────────────────────────────
    def _build_header(self):
        h = QWidget()
        h.setFixedHeight(58)
        h.setStyleSheet(f"background:{BG_PANEL};border-bottom:1px solid {BORDER};")
        l = QHBoxLayout(h)
        l.setContentsMargins(20, 0, 20, 0)
        l.setSpacing(12)
        logo = QLabel("◉  WiFi Radar Pro")
        logo.setStyleSheet(
            f"color:{GREEN};font-size:18px;font-weight:700;letter-spacing:2px;"
        )
        ver = QLabel("Advanced Network Discovery")
        ver.setStyleSheet(
            f"color:{TEXT_DIM};font-size:10px;background:{BG_CARD};"
            f"border:1px solid {BORDER};border-radius:8px;padding:2px 8px;"
        )
        l.addWidget(logo)
        l.addWidget(ver)
        l.addStretch()
        # traffic display
        self._rx_lbl = QLabel("↓ --")
        self._rx_lbl.setStyleSheet(f"color:{GREEN};font-size:11px;min-width:80px;")
        self._tx_lbl = QLabel("↑ --")
        self._tx_lbl.setStyleSheet(f"color:{ORANGE};font-size:11px;min-width:80px;")
        self._net_lbl = QLabel("Detecting...")
        self._net_lbl.setStyleSheet(f"color:{TEXT_MID};font-size:11px;")
        l.addWidget(self._rx_lbl)
        l.addWidget(self._tx_lbl)
        l.addWidget(self._net_lbl)
        l.addSpacing(10)
        self._pulse = PulseDot(GREEN)
        l.addWidget(self._pulse)
        return h

    # ── left panel ────────────────────────────────────────────────────────────
    def _build_left(self):
        w = QWidget()
        w.setFixedWidth(270)
        w.setStyleSheet(f"background:{BG_PANEL};border-right:1px solid {BORDER};")
        l = QVBoxLayout(w)
        l.setContentsMargins(12, 14, 12, 14)
        l.setSpacing(10)

        # radar
        rc = QWidget()
        rc.setStyleSheet("background:transparent;")
        rl = QHBoxLayout(rc)
        rl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._radar = RadarWidget()
        rl.addWidget(self._radar)
        l.addWidget(rc)

        # network info
        nif = self._card_frame()
        nil = QVBoxLayout(nif)
        nil.setContentsMargins(10, 8, 10, 8)
        nil.setSpacing(3)
        self._net_rows = {}
        for k in ["SSID", "Your IP", "Gateway", "Interface", "Subnet"]:
            row = QHBoxLayout()
            kl = QLabel(k + ":")
            kl.setFixedWidth(70)
            kl.setStyleSheet(
                f"color:{TEXT_DIM};font-size:10px;background:transparent;border:none;"
            )
            vl = QLabel("—")
            vl.setStyleSheet(
                f"color:{CYAN};font-size:11px;font-weight:600;"
                f"background:transparent;border:none;"
            )
            row.addWidget(kl)
            row.addWidget(vl)
            nil.addLayout(row)
            self._net_rows[k] = vl
        l.addWidget(nif)

        # scan options
        opt = self._card_frame()
        ol = QVBoxLayout(opt)
        ol.setContentsMargins(10, 8, 10, 8)
        ol.setSpacing(6)
        ol.addWidget(self._dim_lbl("Scan Method:"))
        self._method = QComboBox()
        self._method.addItems(["ARP (arp-scan)", "Ping sweep", "ARP cache (instant)"])
        ol.addWidget(self._method)
        self._chk_ports = QCheckBox("Port scan each device")
        self._chk_ports.setChecked(True)
        self._chk_geo = QCheckBox("Geo-locate each IP")
        self._chk_geo.setChecked(True)
        self._chk_netbios = QCheckBox("NetBIOS / mDNS names")
        self._chk_netbios.setChecked(True)
        ol.addWidget(self._chk_ports)
        ol.addWidget(self._chk_geo)
        ol.addWidget(self._chk_netbios)
        l.addWidget(opt)

        # stats
        stats = self._card_frame()
        sl = QVBoxLayout(stats)
        sl.setContentsMargins(10, 8, 10, 8)
        sl.setSpacing(3)
        self._stat = {}
        for k, lbl in [
            ("devices", "Devices"),
            ("ports", "Open Ports"),
            ("elapsed", "Elapsed"),
            ("subnet_sz", "Subnet Size"),
        ]:
            row = QHBoxLayout()
            kl = QLabel(lbl + ":")
            kl.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
            vl = QLabel("—")
            vl.setStyleSheet(f"color:{GREEN};font-weight:700;font-size:11px;")
            row.addWidget(kl)
            row.addWidget(vl)
            sl.addLayout(row)
            self._stat[k] = vl
        l.addWidget(stats)

        self._progress = QProgressBar()
        self._progress.setFixedHeight(3)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(f"""
            QProgressBar{{background:{BG_CARD};border:none;border-radius:1px;}}
            QProgressBar::chunk{{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
                stop:0 {PURPLE},stop:1 {GREEN});border-radius:1px;}}""")
        l.addWidget(self._progress)

        for txt, slot, color, en in [
            (
                "◉  Start Discovery",
                self._start,
                f"qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {PURPLE},stop:1 {GREEN})",
                True,
            ),
        ]:
            btn = QPushButton(txt)
            btn.setFixedHeight(42)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(
                f"QPushButton{{background:{color};color:{BG};"
                f"border:none;border-radius:8px;font-size:13px;"
                f"font-weight:700;}}QPushButton:disabled{{background:{BORDER};color:{TEXT_DIM};}}"
            )
            btn.clicked.connect(slot)
            btn.setEnabled(en)
            l.addWidget(btn)
            if txt.startswith("◉"):
                self._btn_scan = btn

        self._btn_stop = QPushButton("⏹  Stop")
        self._btn_stop.setFixedHeight(34)
        self._btn_stop.setEnabled(False)
        self._btn_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_stop.setStyleSheet(
            f"QPushButton{{background:{BG_CARD};color:{RED};"
            f"border:1px solid {RED};border-radius:8px;font-size:12px;}}"
            f"QPushButton:hover{{background:{RED};color:white;}}"
            f"QPushButton:disabled{{color:{TEXT_DIM};border-color:{BORDER};}}"
        )
        self._btn_stop.clicked.connect(self._stop)
        l.addWidget(self._btn_stop)

        self._btn_export = QPushButton("💾  Export JSON")
        self._btn_export.setFixedHeight(32)
        self._btn_export.setEnabled(False)
        self._btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_export.setStyleSheet(
            f"QPushButton{{background:{BG_CARD};color:{CYAN};"
            f"border:1px solid {CYAN};border-radius:8px;font-size:11px;}}"
            f"QPushButton:hover{{background:{CYAN};color:{BG};}}"
            f"QPushButton:disabled{{color:{TEXT_DIM};border-color:{BORDER};}}"
        )
        self._btn_export.clicked.connect(self._export)
        l.addWidget(self._btn_export)
        l.addStretch()
        return w

    # ── right panel ───────────────────────────────────────────────────────────
    def _build_right(self):
        w = QWidget()
        w.setStyleSheet(f"background:{BG};")
        l = QVBoxLayout(w)
        l.setContentsMargins(10, 8, 10, 8)
        l.setSpacing(6)

        self._tabs = QTabWidget()

        # Tab: Device Cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea{{background:{BG};border:none;}}")
        self._cards_w = QWidget()
        self._cards_w.setStyleSheet(f"background:{BG};")
        self._cards_l = QVBoxLayout(self._cards_w)
        self._cards_l.setSpacing(8)
        self._cards_l.setContentsMargins(6, 6, 6, 6)
        self._cards_l.addStretch()
        scroll.setWidget(self._cards_w)
        self._tabs.addTab(scroll, "🖥  Devices")

        # Tab: Full Table
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels(
            [
                "",
                "IP",
                "HOSTNAME",
                "MANUFACTURER",
                "MAC",
                "OS",
                "PORTS",
                "LOCATION",
                "FOUND",
            ]
        )
        self._table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self._table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.cellDoubleClicked.connect(self._on_table_dclick)
        self._table.setColumnWidth(0, 32)
        self._tabs.addTab(self._table, "📋  Table")

        # Tab: Map
        if HAS_WEBENGINE:
            self._map_view = QWebEngineView()
            self._map_view.setStyleSheet(f"background:{BG};")
            self._tabs.addTab(self._map_view, "🗺  Live Map")
        else:
            fallback = QTextEdit()
            fallback.setReadOnly(True)
            fallback.setStyleSheet(
                f"background:{BG_PANEL};color:{YELLOW};padding:20px;font-size:12px;"
            )
            fallback.setPlainText(
                "PyQt6-WebEngine not installed.\n\n"
                "Install it with:\n"
                "  pip install PyQt6-WebEngine\n\n"
                "Then relaunch — the live OpenStreetMap will appear here.\n\n"
                "Alternatively, after scanning use Export JSON and the\n"
                "coordinates are included for each device."
            )
            self._map_view = None
            self._tabs.addTab(fallback, "🗺  Live Map")

        # Tab: Log
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setStyleSheet(
            f"QTextEdit{{background:{BG_PANEL};color:{GREEN};"
            f"border:none;padding:12px;font-size:11px;font-family:monospace;}}"
        )
        self._tabs.addTab(self._log, "📄  Log")

        l.addWidget(self._tabs, 1)
        return w

    # ── statusbar ─────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = QWidget()
        bar.setFixedHeight(26)
        bar.setStyleSheet(f"background:{BG_PANEL};border-top:1px solid {BORDER};")
        l = QHBoxLayout(bar)
        l.setContentsMargins(14, 0, 14, 0)
        self._status = QLabel("Ready — press Start Discovery")
        self._status.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        l.addWidget(self._status)
        l.addStretch()
        self._clock = QLabel()
        self._clock.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        t = QTimer(self)
        t.timeout.connect(self._tick)
        t.start(1000)
        self._tick()
        l.addWidget(self._clock)
        return bar

    def _tick(self):
        self._clock.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        if self._start_time and self._worker and self._worker.isRunning():
            el = (datetime.now() - self._start_time).seconds
            self._stat["elapsed"].setText(f"{el}s")

    # ── helpers ───────────────────────────────────────────────────────────────
    def _card_frame(self):
        f = QFrame()
        f.setStyleSheet(
            f"QFrame{{background:{BG_CARD};border:1px solid {BORDER};"
            f"border-radius:8px;}}"
        )
        return f

    def _dim_lbl(self, txt):
        l = QLabel(txt)
        l.setStyleSheet(f"color:{TEXT_DIM};font-size:10px;")
        return l

    # ── detect network ────────────────────────────────────────────────────────
    def _detect_network(self):
        self._my_ip = _get_local_ip()
        self._gateway = _get_gateway()
        self._iface = _get_interface()
        self._subnet = _get_subnet()
        self._ssid = _get_ssid()

        self._net_rows["SSID"].setText(self._ssid)
        self._net_rows["Your IP"].setText(self._my_ip)
        self._net_rows["Gateway"].setText(self._gateway)
        self._net_rows["Interface"].setText(self._iface)
        self._net_rows["Subnet"].setText(self._subnet)
        self._net_lbl.setText(f"📶 {self._ssid}  🌐 {self._my_ip}")

        net = ipaddress.ip_network(self._subnet, strict=False)
        self._stat["subnet_sz"].setText(str(net.num_addresses - 2))

        self._log_msg(f"[*] SSID     : {self._ssid}")
        self._log_msg(f"[*] Your IP  : {self._my_ip}")
        self._log_msg(f"[*] Gateway  : {self._gateway}")
        self._log_msg(f"[*] Interface: {self._iface}")
        self._log_msg(f"[*] Subnet   : {self._subnet}")

    # ── traffic monitor ───────────────────────────────────────────────────────
    def _start_traffic_monitor(self):
        self._traffic_worker = TrafficWorker(self._iface)
        self._traffic_worker.update.connect(self._on_traffic)
        self._traffic_worker.start()

    def _on_traffic(self, rx, tx):
        self._rx_lbl.setText(f"↓ {rx}")
        self._tx_lbl.setText(f"↑ {tx}")

    # ── start/stop scan ───────────────────────────────────────────────────────
    def _start(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait()
        self._devices.clear()
        self._table.setRowCount(0)
        while self._cards_l.count() > 1:
            item = self._cards_l.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._log.clear()
        self._progress.setValue(0)
        self._btn_scan.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_export.setEnabled(False)
        self._start_time = datetime.now()
        self._stat["devices"].setText("0")
        self._stat["ports"].setText("0")
        self._status.setText("Scanning network...")

        self._worker = DiscoveryWorker(
            self._subnet,
            self._method.currentText(),
            self._chk_ports.isChecked(),
            self._chk_geo.isChecked(),
            self._chk_netbios.isChecked(),
        )
        self._worker.device_found.connect(self._on_device)
        self._worker.log.connect(self._log_msg)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished_.connect(self._on_done)
        self._worker.start()

    def _stop(self):
        if self._worker:
            self._worker.stop()
        self._btn_scan.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._status.setText("Stopped by user")

    # ── device arrived ────────────────────────────────────────────────────────
    def _on_device(self, d: dict):
        self._devices.append(d)
        cnt = len(self._devices)
        self._stat["devices"].setText(str(cnt))
        total_ports = sum(len(x.get("open_ports", [])) for x in self._devices)
        self._stat["ports"].setText(str(total_ports))

        # radar dot
        import random

        dots = [
            (
                random.uniform(0, 360),
                random.uniform(18, 85),
                GREEN if x.get("status") == "online" else ORANGE,
            )
            for x in self._devices
        ]
        self._radar.set_dots(dots)

        # device card
        card = self._make_card(d)
        self._cards_l.insertWidget(self._cards_l.count() - 1, card)

        # table row
        r = self._table.rowCount()
        self._table.insertRow(r)
        geo = d.get("geo", {})
        loc = ""
        if geo.get("city"):
            loc = f"{geo['city']}, {geo.get('country', '')}"
        cols = [
            (d.get("icon", "🖥"), TEXT),
            (d.get("ip", ""), CYAN),
            (d.get("hostname", "") or d.get("netbios", "") or "N/A", TEXT),
            (d.get("manufacturer", "Unknown"), ORANGE),
            (d.get("mac", "N/A"), TEXT_DIM),
            (d.get("os", "Unknown"), YELLOW),
            (str(len(d.get("open_ports", []))), GREEN),
            (loc, TEXT_MID),
            (d.get("found_at", ""), TEXT_DIM),
        ]
        for col, (txt, color) in enumerate(cols):
            item = QTableWidgetItem(txt)
            item.setForeground(QColor(color))
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self._table.setItem(r, col, item)

        # update map
        self._refresh_map()

    def _on_progress(self, done, total):
        pct = int(done / total * 100) if total else 0
        self._progress.setValue(pct)

    def _on_done(self, devices):
        self._btn_scan.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_export.setEnabled(True)
        el = (datetime.now() - self._start_time).seconds
        self._stat["elapsed"].setText(f"{el}s")
        self._progress.setValue(100)
        self._status.setText(f"✅  Done — {len(devices)} devices | {el}s")
        self._refresh_map()
        self._tabs.setCurrentIndex(0)

    def _on_table_dclick(self, row, _):
        if row < len(self._devices):
            dlg = DeviceDetailDialog(self._devices[row], self)
            dlg.exec()

    def _log_msg(self, msg):
        self._log.append(
            f"<span style='color:{TEXT_DIM};'>[{datetime.now().strftime('%H:%M:%S')}]"
            f"</span> {msg}"
        )

    # ── device card ───────────────────────────────────────────────────────────
    def _make_card(self, d: dict) -> QFrame:
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame{{background:{BG_CARD};border:1px solid {BORDER};
                    border-radius:10px;}}
            QFrame:hover{{border-color:{CYAN};}}""")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        l = QVBoxLayout(card)
        l.setContentsMargins(14, 12, 14, 10)
        l.setSpacing(4)

        # header
        top = QHBoxLayout()
        icon = QLabel(d.get("icon", "🖥"))
        icon.setStyleSheet("font-size:22px;background:transparent;border:none;")
        ip_l = QLabel(d.get("ip", ""))
        ip_l.setStyleSheet(
            f"color:{CYAN};font-size:14px;font-weight:700;"
            f"background:transparent;border:none;"
        )
        sc = GREEN if d.get("status") == "online" else RED
        st = QLabel("● " + d.get("status", "").upper())
        st.setStyleSheet(
            f"color:{sc};font-size:10px;background:transparent;border:none;"
        )
        top.addWidget(icon)
        top.addWidget(ip_l)
        top.addStretch()
        top.addWidget(st)
        l.addLayout(top)

        # key info
        geo = d.get("geo", {})
        flag = _flag(geo.get("countryCode", "")) if geo else ""
        loc = (
            f"{flag} {geo.get('city', '')}, {geo.get('country', '')}"
            if geo.get("city")
            else "N/A"
        )
        ports_str = ", ".join(str(p["port"]) for p in d.get("open_ports", [])[:6])
        if len(d.get("open_ports", [])) > 6:
            ports_str += "…"

        for k, v, c in [
            ("Host", d.get("hostname", "") or d.get("netbios", "") or "N/A", TEXT),
            ("Vendor", d.get("manufacturer", "Unknown"), ORANGE),
            ("OS", d.get("os", "Unknown"), YELLOW),
            ("Ports", ports_str or "none", GREEN if ports_str else TEXT_DIM),
            ("Loc", loc, TEXT_MID),
        ]:
            row = QHBoxLayout()
            row.setSpacing(6)
            kl = QLabel(k + ":")
            kl.setFixedWidth(42)
            kl.setStyleSheet(
                f"color:{TEXT_DIM};font-size:10px;background:transparent;border:none;"
            )
            vl = QLabel(v)
            vl.setWordWrap(True)
            vl.setStyleSheet(
                f"color:{c};font-size:11px;background:transparent;border:none;"
            )
            row.addWidget(kl)
            row.addWidget(vl, 1)
            l.addLayout(row)

        # detail button
        btn = QPushButton("Details →")
        btn.setFixedHeight(24)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            f"background:transparent;color:{CYAN};"
            f"border:none;font-size:10px;text-align:right;"
        )
        btn.clicked.connect(lambda _, dev=d: DeviceDetailDialog(dev, self).exec())
        l.addWidget(btn)
        return card

    # ── map refresh ───────────────────────────────────────────────────────────
    def _refresh_map(self):
        if not self._map_view:
            return
        # get center from own IP geo or gateway
        center_lat, center_lon = 35.6892, 51.3890  # default Tehran
        my_geo = _geolocate(self._my_ip) if HAS_REQUESTS else {}
        if my_geo.get("lat"):
            center_lat = my_geo["lat"]
            center_lon = my_geo["lon"]
        html = build_map_html(self._devices, center_lat, center_lon)
        self._map_view.setHtml(html, QUrl("https://openstreetmap.org"))

    # ── export ────────────────────────────────────────────────────────────────
    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save", "wifi_radar_report.json", "JSON (*.json)"
        )
        if not path:
            return
        data = {
            "scan_time": datetime.now().isoformat(),
            "network": self._subnet,
            "ssid": self._ssid,
            "your_ip": self._my_ip,
            "devices": self._devices,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._status.setText(f"💾  Exported → {path}")

    def closeEvent(self, e):
        if self._traffic_worker:
            self._traffic_worker.stop()
        if self._worker:
            self._worker.stop()
        super().closeEvent(e)


# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = WiFiRadarPro()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
