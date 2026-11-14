"""Repository-neutral predicates for reusing device identity history.

These helpers deliberately do not query a database.  A repository supplies a
previous authoritative snapshot and this module checks the parts that must be
identical across SQLite and SQLAlchemy backends before any history proof can be
minted.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..services.device_identity import (
    DEVICE_TYPE_LABELS,
    is_concrete_product_model,
    is_product_manufacturer,
    normalize_vendor_name,
)
from ..services.identity_enrichment import _authenticated_self_android_triplet
from .network_scope import is_strong_network_scope_id, normalized_physical_mac


_EXACT_MDNS_MAC_TOKEN = re.compile(r"^[0-9A-Fa-f]{12}$")
_BSSID_SCOPE_ID = re.compile(r"^hgns1b-[0-9a-f]{32}$")
_AUTHENTICATED_SELF_ANDROID_HISTORY_KIND = "authenticated_self_android"


def _snapshot_mapping(payload: str | Mapping[str, Any] | None) -> dict[str, Any] | None:
    if isinstance(payload, Mapping):
        return dict(payload)
    try:
        decoded = json.loads(payload or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _fingerprints(snapshot: Mapping[str, Any]) -> list[str]:
    values = snapshot.get("fingerprints")
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values]


def _private_ipv4(value: Any) -> str | None:
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if (
        parsed.version != 4
        or not parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
    ):
        return None
    return str(parsed)


def _normalized_marker_values(snapshot: Mapping[str, Any], key: str) -> set[str]:
    values = snapshot.get(key)
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return set()
    return {
        str(value).strip().casefold().replace("_", "-")
        for value in values
        if str(value).strip()
    }


def _history_snapshot_payload(record: Mapping[str, Any]) -> Any:
    if "snapshot_payload" in record:
        return record.get("snapshot_payload")
    return record.get("device_snapshot_json")


def _historical_authenticated_self_triplet(
    snapshot: Mapping[str, Any],
    *,
    expected_ip: str,
    current_physical_mac: str,
) -> tuple[str, str, str] | None:
    """Validate serialized self markers while permitting its old UNKNOWN MAC.

    The normal authenticated-self parser correctly requires a real MAC because
    it is used at the live request boundary.  Persisted Android snapshots made
    before a server neighbour refresh may instead contain the explicit
    ``UNKNOWN-<ip>`` placeholder.  The current observation's independently
    verified physical MAC is injected only for that parser check after the
    historical placeholder has been bound to the exact same private IP.
    """

    historical_ip = _private_ipv4(snapshot.get("ip_address"))
    if historical_ip != expected_ip:
        return None

    raw_historical_mac = str(snapshot.get("mac_address") or "").strip()
    historical_mac = normalized_physical_mac(raw_historical_mac)
    if historical_mac is not None:
        if historical_mac != current_physical_mac:
            return None
    elif raw_historical_mac.casefold() != f"unknown-{expected_ip}".casefold():
        return None

    candidate = dict(snapshot)
    candidate["ip_address"] = historical_ip
    candidate["mac_address"] = current_physical_mac
    return _authenticated_self_android_triplet(candidate)


def _current_concrete_identity_conflicts(
    snapshot: Mapping[str, Any],
    historical_triplet: tuple[str, str, str],
) -> bool:
    historical_manufacturer, historical_model, historical_type = historical_triplet
    current_model = " ".join(str(snapshot.get("model") or "").strip().split())
    current_manufacturer_raw = " ".join(
        str(snapshot.get("manufacturer") or "").strip().split()
    )
    current_manufacturer = normalize_vendor_name(current_manufacturer_raw)
    if not is_concrete_product_model(current_model, current_manufacturer):
        return False
    if current_model.casefold() != historical_model.casefold():
        return True
    if (
        is_product_manufacturer(current_manufacturer)
        and current_manufacturer.casefold() != historical_manufacturer.casefold()
    ):
        return True
    current_type = str(snapshot.get("device_type") or "").strip().casefold()
    return current_type in DEVICE_TYPE_LABELS and current_type != historical_type


def verified_authenticated_self_android_history_identity(
    historical_records: Sequence[Mapping[str, Any]] | None,
    current_snapshot_payload: str | Mapping[str, Any] | None,
    *,
    home_id: str,
    current_scope_candidates: Sequence[str] | None,
    current_physical_mac: str | None,
) -> dict[str, Any] | None:
    """Carry a repeated Android self identity to one fresh same-L2 neighbour.

    This verifier is deliberately repository-neutral and fail-closed.  At
    least two distinct ``android-native`` scans must agree on the same home,
    exact BSSID-derived scope, private IP and authenticated self Build triplet.
    The current observation must independently contain the same private IP, a
    real physical MAC and the server-only fresh-neighbour marker.  Historical
    real MACs must match the current one; the exact ``UNKNOWN-<ip>`` placeholder
    is accepted because old Android snapshots could precede the server's
    neighbour-table refresh.

    Each history record supplies ``scan_id``, ``home_id``,
    ``network_scope_id``, ``scan_source`` and ``snapshot_payload`` (or the
    storage-native alias ``device_snapshot_json``).  Only the agreed exact
    identity and its bounded history kind are returned.
    """

    expected_home = str(home_id or "").strip()
    current_mac = normalized_physical_mac(current_physical_mac)
    current_snapshot = _snapshot_mapping(current_snapshot_payload)
    bssid_scope_candidates = {
        scope
        for raw_scope in (current_scope_candidates or ())
        if (scope := str(raw_scope or "").strip().casefold())
        and _BSSID_SCOPE_ID.fullmatch(scope)
    }
    if (
        not expected_home
        or current_mac is None
        or current_snapshot is None
        or not bssid_scope_candidates
    ):
        return None

    current_ip = _private_ipv4(current_snapshot.get("ip_address"))
    if current_ip is None:
        return None
    if normalized_physical_mac(current_snapshot.get("mac_address")) != current_mac:
        return None
    if "server-neighbor" not in _normalized_marker_values(
        current_snapshot, "discovery_sources"
    ):
        return None

    records = historical_records or ()
    if isinstance(records, (str, bytes, Mapping)):
        return None

    scan_ids: set[str] = set()
    historical_scope: str | None = None
    agreed_triplet: tuple[str, str, str] | None = None
    for record in records:
        if not isinstance(record, Mapping):
            return None
        scan_id = str(record.get("scan_id") or "").strip()
        record_home = str(record.get("home_id") or "").strip()
        record_scope = str(record.get("network_scope_id") or "").strip().casefold()
        record_source = str(record.get("scan_source") or "").strip().casefold()
        if (
            not scan_id
            or scan_id in scan_ids
            or record_home != expected_home
            or record_scope not in bssid_scope_candidates
            or record_source != "android-native"
        ):
            return None
        if historical_scope is None:
            historical_scope = record_scope
        elif record_scope != historical_scope:
            return None

        snapshot = _snapshot_mapping(_history_snapshot_payload(record))
        if snapshot is None:
            return None
        snapshot_source = str(snapshot.get("scan_source") or "").strip().casefold()
        if snapshot_source and snapshot_source != "android-native":
            return None
        triplet = _historical_authenticated_self_triplet(
            snapshot,
            expected_ip=current_ip,
            current_physical_mac=current_mac,
        )
        if triplet is None:
            return None
        if agreed_triplet is None:
            agreed_triplet = triplet
        elif triplet != agreed_triplet:
            return None
        scan_ids.add(scan_id)

    if len(scan_ids) < 2 or agreed_triplet is None:
        return None
    if _current_concrete_identity_conflicts(current_snapshot, agreed_triplet):
        return None

    manufacturer, model, device_type = agreed_triplet
    return {
        "manufacturer": manufacturer,
        "model": model,
        "device_type": device_type,
        "_history_kind": _AUTHENTICATED_SELF_ANDROID_HISTORY_KIND,
    }


def _exact_mdns_mac_token(snapshot: Mapping[str, Any]) -> str | None:
    """Return one unambiguous MAC-shaped mDNS instance token.

    Separators, suffixes and embedded friendly names are rejected.  Accepting
    those looser forms would turn a parser guess into device-owned evidence.
    Repeated copies of the same exact token are harmless; two different valid
    tokens are ambiguous and therefore fail closed.
    """

    tokens: set[str] = set()
    for fingerprint in _fingerprints(snapshot):
        prefix, separator, raw_value = fingerprint.partition(":")
        if not separator or prefix.casefold() != "mdns-name":
            continue
        value = raw_value.strip()
        if _EXACT_MDNS_MAC_TOKEN.fullmatch(value):
            tokens.add(value.upper())
    if len(tokens) != 1:
        return None
    return next(iter(tokens))


def exact_spotify_mdns_mac_token(
    snapshot_payload: str | Mapping[str, Any] | None,
) -> str | None:
    """Return the exact MAC-shaped token from a current Spotify mDNS advert.

    Repositories use this only to narrow historical snapshot candidates before
    calling the fail-closed continuity verifier below.  The token remains
    application-layer evidence: this helper never promotes it to a physical
    MAC or returns it unless the same snapshot also carries the exact Spotify
    service type and an mDNS discovery source.
    """

    snapshot = _snapshot_mapping(snapshot_payload)
    if (
        snapshot is None
        or not _has_mdns_discovery_source(snapshot)
        or not _has_exact_spotify_mdns_type(snapshot)
    ):
        return None
    return _exact_mdns_mac_token(snapshot)


def _has_exact_spotify_mdns_type(snapshot: Mapping[str, Any]) -> bool:
    for fingerprint in _fingerprints(snapshot):
        prefix, separator, raw_value = fingerprint.partition(":")
        if not separator or prefix.casefold() != "mdns-type":
            continue
        service_type = raw_value.strip().casefold().lstrip(".")
        if service_type.endswith(".local"):
            service_type = service_type[: -len(".local")]
        if service_type == "_spotify-connect._tcp":
            return True
    return False


def _has_mdns_discovery_source(snapshot: Mapping[str, Any]) -> bool:
    sources = snapshot.get("discovery_sources")
    return isinstance(sources, list) and any(
        str(source).strip().casefold() == "mdns" for source in sources
    )


def _has_structured_family_hub_getinfo(snapshot: Mapping[str, Any]) -> bool:
    fingerprints = [value.casefold() for value in _fingerprints(snapshot)]
    if "spotify-getinfo-done" not in fingerprints:
        return False
    advertised_brands = {
        advertised_value.strip()
        for value in fingerprints
        for prefix, separator, advertised_value in (value.partition(":"),)
        if separator and prefix == "spotify-brand" and advertised_value.strip()
    }
    if advertised_brands != {"samsung"}:
        return False
    for value in fingerprints:
        prefix, separator, advertised_value = value.partition(":")
        if not separator or prefix not in {"spotify-model", "spotify-name"}:
            continue
        normalized_value = re.sub(r"[^a-z0-9]", "", advertised_value)
        if "familyhub" in normalized_value:
            return True
    return False


def _family_hub_family_identity() -> dict[str, Any]:
    return {
        "manufacturer": "Samsung",
        "model": "Family Hub",
        "device_type": "fridge",
        "_history_kind": "appliance_family",
    }


def verified_family_hub_snapshot_identity(
    snapshot_payload: str | Mapping[str, Any] | None,
    *,
    historical_scope_id: str | None,
    current_scope_id: str | None,
    current_physical_mac: str | None,
    current_snapshot_payload: str | Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a bounded Family Hub family identity from a prior snapshot.

    The current observation must have a real MAC and a strong network scope.
    The historical snapshot must normally belong to the same scope, except for
    the narrow legacy migrations where that older scan had either the keyed
    subnet-scope form (``hgns1s-``) or no persisted scope at all.  An unscoped
    row is accepted only when the current observation independently supplies a
    matching real MAC, exact MAC-shaped Spotify mDNS token, mDNS source and
    strong scope.  The appliance itself must previously have returned Samsung
    + Family Hub fields through Spotify ZeroConf ``getInfo``.

    Only the product family is returned.  No retail part number is inferred.
    """

    current_mac = normalized_physical_mac(current_physical_mac)
    current_scope = str(current_scope_id or "")
    historical_scope = str(historical_scope_id or "")
    if current_mac is None or not is_strong_network_scope_id(current_scope):
        return None
    scope_matches = historical_scope == current_scope or historical_scope.startswith(
        "hgns1s-"
    )
    legacy_unscoped = not historical_scope
    if not scope_matches and not legacy_unscoped:
        return None

    snapshot = _snapshot_mapping(snapshot_payload)
    if snapshot is None or not _has_structured_family_hub_getinfo(snapshot):
        return None

    historical_mac = normalized_physical_mac(snapshot.get("mac_address"))
    historical_token = _exact_mdns_mac_token(snapshot)
    compact_current_mac = current_mac.replace(":", "")
    if historical_mac is not None:
        # A conflicting physical address is stronger contrary evidence; do not
        # let a copied/friendly mDNS token override it.
        if historical_mac != current_mac:
            return None
    elif (
        historical_token != compact_current_mac
        or not _has_mdns_discovery_source(snapshot)
        or not _has_exact_spotify_mdns_type(snapshot)
    ):
        return None

    if legacy_unscoped:
        current_snapshot = _snapshot_mapping(current_snapshot_payload)
        if current_snapshot is None:
            return None
        snapshot_current_mac = normalized_physical_mac(
            current_snapshot.get("mac_address")
        )
        if snapshot_current_mac != current_mac:
            return None
        if _exact_mdns_mac_token(current_snapshot) != compact_current_mac:
            return None
        if not _has_mdns_discovery_source(current_snapshot):
            return None
        if not _has_exact_spotify_mdns_type(current_snapshot):
            return None

    return _family_hub_family_identity()


def verified_family_hub_advertised_token_identity(
    historical_snapshot_payload: str | Mapping[str, Any] | None,
    current_snapshot_payload: str | Mapping[str, Any] | None,
    *,
    historical_scope_id: str | None,
    current_scope_id: str | None,
    current_physical_mac: str | None = None,
) -> dict[str, Any] | None:
    """Recover Family Hub family identity through an attested mDNS token.

    This path exists for a sleeping appliance whose current Android snapshot
    cannot read the neighbour table and therefore has no physical MAC.  It is
    deliberately narrower than hostname or OUI matching:

    * the previous authoritative snapshot must bind a real physical MAC to an
      exact 12-hex mDNS instance token emitted by that same device;
    * that previous snapshot must contain a completed, structured Samsung
      Family Hub Spotify ZeroConf ``getInfo`` response;
    * the current snapshot must directly advertise the same exact token and
      the exact Spotify Connect mDNS service on a strong compatible scope.

    The token is only continuity evidence.  It is never returned or promoted
    to a current physical MAC, and the result is limited to the verified
    product family rather than a retail part number.
    """

    current_scope = str(current_scope_id or "")
    historical_scope = str(historical_scope_id or "")
    if not is_strong_network_scope_id(current_scope):
        return None
    if historical_scope != current_scope and not historical_scope.startswith("hgns1s-"):
        return None

    historical_snapshot = _snapshot_mapping(historical_snapshot_payload)
    current_snapshot = _snapshot_mapping(current_snapshot_payload)
    if historical_snapshot is None or current_snapshot is None:
        return None

    historical_mac = normalized_physical_mac(historical_snapshot.get("mac_address"))
    if historical_mac is None:
        return None
    historical_token = _exact_mdns_mac_token(historical_snapshot)
    if historical_token is None or historical_token != historical_mac.replace(":", ""):
        return None
    if not _has_structured_family_hub_getinfo(historical_snapshot):
        return None

    current_token = _exact_mdns_mac_token(current_snapshot)
    if current_token != historical_token:
        return None
    if not _has_mdns_discovery_source(current_snapshot):
        return None
    if not _has_exact_spotify_mdns_type(current_snapshot):
        return None

    raw_current_mac: Any = current_physical_mac
    if raw_current_mac is None:
        raw_current_mac = current_snapshot.get("mac_address")
    if raw_current_mac is not None and str(raw_current_mac).strip():
        current_mac_text = str(raw_current_mac).strip()
        # The normalization boundary stores `UNKNOWN-<ip>` when Android cannot
        # expose a neighbour-table MAC.  That explicit placeholder means
        # "physical MAC absent"; arbitrary malformed values remain conflicts.
        if not current_mac_text.casefold().startswith("unknown-"):
            normalized_current_mac = normalized_physical_mac(current_mac_text)
            if (
                normalized_current_mac is None
                or normalized_current_mac.replace(":", "") != current_token
            ):
                return None

    return _family_hub_family_identity()
