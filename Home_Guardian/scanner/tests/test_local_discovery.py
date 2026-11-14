import ipaddress

import pytest

from home_guardian_scanner.local_discovery import (
    detect_primary_ipv4_network,
    guess_device_type,
    scan_hosts,
)


def test_scan_hosts_returns_discovered_devices_from_injected_connector():
    open_pairs = {("192.168.0.1", 53), ("192.168.0.1", 80), ("192.168.0.22", 554)}

    def connector(ip_address, port, timeout_seconds):
        assert timeout_seconds == 0.1
        return (ip_address, port) in open_pairs

    result = scan_hosts(
        ["192.168.0.1", "192.168.0.22", "192.168.0.99"],
        ports=[53, 80, 554],
        timeout_seconds=0.1,
        connector=connector,
    )

    assert result["devices_found"] == 2
    assert result["devices"][0]["device_type"] == "router"
    assert result["devices"][1]["device_type"] == "camera"


def test_scan_hosts_returns_empty_when_no_ports_are_open():
    result = scan_hosts(["192.168.0.99"], ports=[80], connector=lambda *_: False)

    assert result["devices_found"] == 0
    assert result["devices"] == []


def test_guess_device_type_prefers_camera_and_router_signals():
    assert guess_device_type([80, 554]) == "camera"
    assert guess_device_type([53, 80]) == "router"
    assert guess_device_type([23]) == "iot"


def test_detect_primary_ipv4_network_fails_loudly_without_ipv4(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "no-ipv4")
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [])

    with pytest.raises(RuntimeError, match="IPv4"):
        detect_primary_ipv4_network()


def test_detect_primary_ipv4_network_uses_first_non_loopback(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "home-pc")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [
            (None, None, None, None, ("127.0.0.1", 0)),
            (None, None, None, None, ("192.168.1.20", 0)),
        ],
    )

    assert detect_primary_ipv4_network() == ipaddress.ip_network("192.168.1.0/24")
