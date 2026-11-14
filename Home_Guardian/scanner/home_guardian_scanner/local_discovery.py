from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Callable, Iterable
from typing import Any

from .normalize import normalize_scan

DEFAULT_PORTS = (21, 22, 23, 53, 80, 443, 554, 1900, 8080)
PortConnector = Callable[[str, int, float], bool]


def can_connect(ip_address: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((ip_address, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def scan_hosts(
    hosts: Iterable[str],
    ports: Iterable[int] = DEFAULT_PORTS,
    timeout_seconds: float = 0.25,
    connector: PortConnector = can_connect,
) -> dict[str, Any]:
    devices: list[dict[str, Any]] = []
    for host in hosts:
        open_ports = [
            port
            for port in ports
            if connector(str(host), int(port), timeout_seconds)
        ]
        if not open_ports:
            continue
        devices.append(make_device_from_ports(str(host), open_ports))

    return normalize_scan(
        {
            "scan_id": "local-discovery",
            "scan_source": "windows-port-probe",
            "devices": devices,
        }
    )


def run_local_discovery(
    network_cidr: str | None = None,
    ports: Iterable[int] = DEFAULT_PORTS,
    max_hosts: int = 16,
    timeout_seconds: float = 0.1,
) -> dict[str, Any]:
    network = ipaddress.ip_network(network_cidr, strict=False) if network_cidr else detect_primary_ipv4_network()
    hosts = [str(host) for index, host in enumerate(network.hosts()) if index < max_hosts]
    return scan_hosts(hosts, ports=ports, timeout_seconds=timeout_seconds)


def detect_primary_ipv4_network(prefix: int = 24) -> ipaddress.IPv4Network:
    hostname = socket.gethostname()
    candidates = [
        info[4][0]
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        if not info[4][0].startswith("127.")
    ]
    if not candidates:
        raise RuntimeError("로컬 IPv4 주소를 찾지 못했습니다.")
    return ipaddress.ip_network(f"{candidates[0]}/{prefix}", strict=False)


def make_device_from_ports(ip_address: str, open_ports: list[int]) -> dict[str, Any]:
    device_type = guess_device_type(open_ports)
    return {
        "device_id": f"local-{ip_address.replace('.', '-')}",
        # A port probe is evidence, not a product identity.  The backend
        # resolver receives an empty name and performs the catalog lookup.
        "name": "",
        "device_type": device_type,
        "manufacturer": "",
        "model": "",
        "ip_address": ip_address,
        "mac_address": f"UNKNOWN-{ip_address}",
        "online": True,
        "last_seen": "",
        "open_ports": sorted(open_ports),
        "services": [service_name(port) for port in sorted(open_ports)],
        "default_credentials": False,
        "encryption": "unknown",
        "firmware": "unknown",
        "vulnerabilities": [],
    }


def guess_device_type(open_ports: Iterable[int]) -> str:
    port_set = set(open_ports)
    if 554 in port_set:
        return "camera"
    if {53, 80}.issubset(port_set) or 1900 in port_set:
        return "router"
    if 23 in port_set:
        return "iot"
    if 80 in port_set or 443 in port_set:
        return "web-device"
    return "unknown"


def guess_device_name(ip_address: str, device_type: str) -> str:
    # Kept as a compatibility helper for callers that imported it in older
    # scanner versions.  It must never manufacture a resident-facing label.
    del ip_address, device_type
    return ""


def service_name(port: int) -> str:
    names = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        53: "dns",
        80: "http",
        443: "https",
        554: "rtsp",
        1900: "upnp",
        8080: "http-alt",
    }
    return names.get(port, f"tcp-{port}")


def main() -> None:
    print(json.dumps(run_local_discovery(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
