from unittest.mock import MagicMock, patch


from radarnet.cli import (
    _device_icon,
    _flag,
    _fmt_bytes,
    _get_ttl_os,
    _mac_manufacturer,
    _ping_alive,
    _run,
    build_map_html,
)


def test_fmt_bytes():
    assert _fmt_bytes(500) == "500 B"
    assert _fmt_bytes(1024) == "1.0 KB"
    assert _fmt_bytes(1024 * 1024) == "1.0 MB"
    assert _fmt_bytes(1024 * 1024 * 1024 * 2) == "2.00 GB"


def test_flag():
    # Test valid 2-letter country code
    assert _flag("US") == "🇺🇸"
    # Test invalid code fallback
    assert _flag("XYZ") == "🌐"
    assert _flag("A") == "🌐"


def test_device_icon():
    # Apple/iPhone checks
    assert _device_icon("Apple Inc", "", []) == "🍎"
    assert _device_icon("", "my-iphone", []) == "🍎"
    assert _device_icon("", "", [{"port": 62078}]) == "📱"

    # Samsung/Xiaomi/Huawei checks
    assert _device_icon("Xiaomi Communications", "", []) == "📱"

    # Raspberry Pi check
    assert _device_icon("Raspberry Pi Foundation", "", []) == "🫐"

    # Cisco/Router check
    assert _device_icon("Cisco Systems", "", []) == "📡"
    assert _device_icon("", "gateway", []) == "📡"

    # VM check
    assert _device_icon("VMware Inc", "", []) == "🖥"

    # Printer check
    assert _device_icon("", "", [{"port": 9100}]) == "🖨"

    # IoT/MQTT check
    assert _device_icon("", "", [{"port": 1883}]) == "🌐"

    # Fallback default
    assert _device_icon("Some Unknown Vendor", "generic-host", []) == "🖥"


def test_get_ttl_os():
    with patch("radarnet.cli._run") as mock_run:
        # Linux TTL (<= 64)
        mock_run.return_value = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=64 time=1.23 ms"
        assert "Linux" in _get_ttl_os("1.1.1.1")

        # Windows TTL (<= 128)
        mock_run.return_value = "Reply from 1.1.1.1: bytes=32 time=10ms TTL=128"
        assert "Windows" in _get_ttl_os("1.1.1.1")

        # Network Device TTL
        mock_run.return_value = "Reply from 1.1.1.1: bytes=32 time=10ms TTL=255"
        assert "Network Device" in _get_ttl_os("1.1.1.1")

        # Unknown
        mock_run.return_value = "Request timed out."
        assert "Unknown" in _get_ttl_os("1.1.1.1")


def test_mac_manufacturer():
    # Test fallback table
    with patch("radarnet.cli.HAS_REQUESTS", False):
        assert _mac_manufacturer("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"
        assert _mac_manufacturer("00:50:56:44:55:66") == "VMware Inc"
        assert _mac_manufacturer("unknown-mac") == "Unknown"

    # Test API lookup with HAS_REQUESTS as True
    with patch("radarnet.cli.HAS_REQUESTS", True):
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Test Manufacturer"
            mock_get.return_value = mock_response

            # Clear cache for the test prefix
            from radarnet.cli import _vendor_cache

            _vendor_cache.pop("00:11:22", None)

            assert _mac_manufacturer("00:11:22:33:44:55") == "Test Manufacturer"


def test_run():
    with patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.stdout = "test stdout\n"
        mock_proc.stderr = "test stderr\n"
        mock_sub.return_value = mock_proc

        out = _run(["ls"])
        assert "test stdout" in out
        assert "test stderr" in out

    with patch("subprocess.run", side_effect=Exception("Subprocess Error")):
        # If run raises exception
        out = _run(["invalid-cmd"])
        assert out is not None


def test_ping_alive():
    with patch("subprocess.run") as mock_sub:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_sub.return_value = mock_proc
        assert _ping_alive("127.0.0.1") is True

        mock_proc.returncode = 1
        assert _ping_alive("127.0.0.1") is False


def test_build_map_html():
    devices = [
        {
            "ip": "192.168.1.5",
            "hostname": "test-device",
            "manufacturer": "Apple Inc",
            "status": "online",
            "icon": "🍎",
            "geo": {
                "lat": 35.6892,
                "lon": 51.3890,
                "country": "Iran",
                "city": "Tehran",
                "isp": "MCI",
            },
            "open_ports": [{"port": 80, "service": "HTTP", "banner": ""}],
        }
    ]

    html = build_map_html(devices, 35.6892, 51.3890)
    assert "test-device" in html
    assert "Apple Inc" in html
    assert "Tehran" in html
    assert "Google Maps" in html
    assert "leaflet.js" in html
