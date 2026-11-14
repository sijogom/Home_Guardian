from __future__ import annotations

from copy import deepcopy
from typing import Any


def normalize_scan(data: dict[str, Any]) -> dict[str, Any]:
    if "devices" not in data or not isinstance(data["devices"], list):
        raise ValueError("devices 배열이 필요합니다.")

    seen_macs: set[str] = set()
    normalized_devices = []
    for raw_device in data["devices"]:
        device = normalize_device(raw_device)
        mac = device["mac_address"].upper()
        if mac in seen_macs:
            continue
        seen_macs.add(mac)
        device["mac_address"] = mac
        normalized_devices.append(device)

    result = deepcopy(data)
    result["devices"] = normalized_devices
    result["devices_found"] = len(normalized_devices)
    return result


def normalize_device(device: dict[str, Any]) -> dict[str, Any]:
    required = ["ip_address", "mac_address"]
    missing = [field for field in required if not device.get(field)]
    if missing:
        raise ValueError(f"필수 기기 필드가 없습니다: {', '.join(missing)}")

    normalized = deepcopy(device)
    # Names are resolved by the backend after the scanner submits evidence.
    normalized.setdefault("name", "")
    normalized.setdefault("device_type", "unknown")
    normalized.setdefault("manufacturer", "")
    normalized.setdefault("model", "")
    normalized.setdefault("identity_status", "enriching")
    normalized.setdefault("open_ports", [])
    normalized.setdefault("services", [])
    normalized.setdefault("default_credentials", False)
    normalized.setdefault("vulnerabilities", [])
    return normalized
