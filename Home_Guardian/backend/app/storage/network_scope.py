"""Privacy-safe network scope identifiers for scan history isolation.

Raw Wi-Fi identifiers are intentionally accepted only at the write boundary.
They are converted to a keyed digest and must never be stored or returned.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Mapping, Sequence
from typing import Any


_MAC_HEX = re.compile(r"^[0-9A-F]{12}$")
_SCOPE_SECRET_ENV = "HG_AUTH_TOKEN_SECRET"
_SCOPE_VERSION = "network-scope-v1"
_STRONG_SCOPE_PREFIXES = ("hgns1g-", "hgns1b-")


def _normalized_mac(value: Any) -> str | None:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if not _MAC_HEX.fullmatch(compact):
        return None
    if compact in {"000000000000", "020000000000", "FFFFFFFFFFFF"}:
        return None
    # A gateway/AP identifier must be an individual (unicast) address.
    if int(compact[:2], 16) & 1:
        return None
    return compact


def normalized_physical_mac(value: Any) -> str | None:
    """Return one canonical real MAC suitable for private identity binding.

    Synthetic ``UNKNOWN-*`` values, broadcast/multicast addresses and Android's
    privacy placeholder are deliberately rejected.  The value stays inside the
    repository; public payloads continue to omit hardware addresses.
    """

    compact = _normalized_mac(value)
    if compact is None:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def is_strong_network_scope_id(value: Any) -> bool:
    """Whether a scope is backed by a gateway MAC or connected AP BSSID.

    A subnet-only digest cannot distinguish two homes that both use a common
    private CIDR.  It is safe for opaque storage compatibility, but must never
    authorize cross-scan identity, firmware or alias restoration.
    """

    scope_id = str(value or "").strip()
    return scope_id.startswith(_STRONG_SCOPE_PREFIXES)


def _normalized_ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def _normalized_subnet(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_network(str(value or "").strip(), strict=False))
    except ValueError:
        return None


def _gateway_mac(
    network_context: Mapping[str, Any],
    discovered_devices: Sequence[Mapping[str, Any]] | None,
) -> str | None:
    gateway_ip = _normalized_ip(network_context.get("gateway_ip"))
    if gateway_ip is None or not discovered_devices:
        return None
    for device in discovered_devices:
        if not isinstance(device, Mapping):
            continue
        if _normalized_ip(device.get("ip_address")) != gateway_ip:
            continue
        mac = _normalized_mac(device.get("mac_address"))
        if mac is not None:
            return mac
    return None


def _scope_id(
    *,
    home_id: str,
    subnet: str,
    basis: str,
    strength: str,
) -> str | None:
    """Return one keyed scope id without retaining its raw basis."""

    secret = os.environ.get(_SCOPE_SECRET_ENV, "").strip()
    if len(secret) < 32:
        return None
    material = "\x1f".join((_SCOPE_VERSION, str(home_id), subnet, basis)).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return f"hgns1{strength}-{digest[:32]}"


def derive_strong_network_scope_ids(
    *,
    home_id: str,
    network_context: Mapping[str, Any] | None,
    discovered_devices: Sequence[Mapping[str, Any]] | None,
) -> tuple[str, ...]:
    """Return every strong opaque scope candidate available at write time.

    A dual-band access point can expose a different BSSID on 2.4 GHz and
    5 GHz while the physical gateway stays the same.  Computing both the
    gateway-MAC and connected-BSSID digests lets a request-bound verifier
    compare candidates without ever storing SSID/BSSID text.  The gateway
    candidate remains first so existing canonical scope selection is stable.
    """

    if not isinstance(network_context, Mapping):
        return ()
    subnet = _normalized_subnet(network_context.get("subnet_cidr"))
    if subnet is None:
        return ()

    candidates: list[str] = []
    gateway_mac = _gateway_mac(network_context, discovered_devices)
    if gateway_mac is not None:
        candidate = _scope_id(
            home_id=home_id,
            subnet=subnet,
            basis=f"gateway-mac:{gateway_mac}",
            strength="g",
        )
        if candidate is not None:
            candidates.append(candidate)

    bssid = _normalized_mac(network_context.get("bssid"))
    if bssid is not None:
        candidate = _scope_id(
            home_id=home_id,
            subnet=subnet,
            basis=f"bssid:{bssid}",
            strength="b",
        )
        if candidate is not None and candidate not in candidates:
            candidates.append(candidate)
    return tuple(candidates)


def strong_network_scope_candidates_overlap(
    left: Sequence[Any] | None,
    right: Sequence[Any] | None,
) -> bool:
    """Return whether two request-bound strong-scope candidate sets overlap.

    Subnet-only compatibility scopes are excluded even if supplied by a
    caller.  This helper establishes only opaque network-scope equivalence;
    it does not authorize device identity, MAC restoration, or IP-based
    history reuse.
    """

    left_ids = {
        str(value or "").strip()
        for value in (left or ())
        if is_strong_network_scope_id(value)
    }
    right_ids = {
        str(value or "").strip()
        for value in (right or ())
        if is_strong_network_scope_id(value)
    }
    return bool(left_ids.intersection(right_ids))


def derive_network_scope_id(
    *,
    home_id: str,
    network_context: Mapping[str, Any] | None,
    discovered_devices: Sequence[Mapping[str, Any]] | None,
) -> str | None:
    """Return an opaque, stable scope id without retaining Wi-Fi identifiers.

    Evidence priority is the observed gateway MAC, then the connected AP BSSID,
    then a subnet-only compatibility fallback.  The fallback deliberately keeps
    old clients working, but identical private CIDRs cannot be distinguished
    without gateway/BSSID evidence.  Callers therefore still keep current-scan
    membership separate from historical enrichment.
    """

    if not isinstance(network_context, Mapping):
        return None
    subnet = _normalized_subnet(network_context.get("subnet_cidr"))
    if subnet is None:
        return None

    strong_candidates = derive_strong_network_scope_ids(
        home_id=home_id,
        network_context=network_context,
        discovered_devices=discovered_devices,
    )
    if strong_candidates:
        return strong_candidates[0]

    # Production authentication already rejects a missing/short secret.  A
    # repository used independently must fail closed instead of inventing an
    # unkeyed network fingerprint.
    return _scope_id(
        home_id=home_id,
        subnet=subnet,
        basis=f"subnet:{subnet}",
        strength="s",
    )
