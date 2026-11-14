from __future__ import annotations

import copy
import json

import pytest

from app.storage.identity_history import (
    verified_authenticated_self_android_history_identity,
    verified_family_hub_advertised_token_identity,
    verified_family_hub_snapshot_identity,
)


STRONG_SCOPE = "hgns1b-0123456789abcdef0123456789abcdef"
OTHER_STRONG_SCOPE = "hgns1g-fedcba9876543210fedcba9876543210"
LEGACY_SCOPE = "hgns1s-11111111111111111111111111111111"
EXPECTED_IDENTITY = {
    "manufacturer": "Samsung",
    "model": "Family Hub",
    "device_type": "fridge",
    "_history_kind": "appliance_family",
}
SELF_HISTORY_HOME = "home-self-history"
SELF_HISTORY_IP = "192.168.50.27"
SELF_HISTORY_MAC = "DA:AA:BB:CC:DD:20"
SELF_HISTORY_MODEL = "SM-S928N"
SELF_HISTORY_IDENTITY = {
    "manufacturer": "Samsung",
    "model": SELF_HISTORY_MODEL,
    "device_type": "phone",
    "_history_kind": "authenticated_self_android",
}


def authenticated_self_history_snapshot(
    *,
    ip_address: str = SELF_HISTORY_IP,
    mac_address: str | None = None,
    model: str = SELF_HISTORY_MODEL,
) -> dict[str, object]:
    return {
        "device_id": "self-device",
        "name": f"내 휴대폰 ({model})",
        "device_type": "phone",
        "manufacturer": "samsung",
        "model": model,
        "ip_address": ip_address,
        "mac_address": mac_address or f"UNKNOWN-{ip_address}",
        "online": True,
        "open_ports": [],
        "services": ["self-device"],
        "discovery_sources": ["self"],
        "fingerprints": [
            "self-android",
            "self-manufacturer:samsung",
            f"self-model:{model}",
        ],
        "risk_signals": ["self_device"],
        "confidence": 1.0,
        "scan_source": "android-native",
    }


def authenticated_self_history_record(
    number: int,
    *,
    snapshot: dict[str, object] | None = None,
    home_id: str = SELF_HISTORY_HOME,
    network_scope_id: str = STRONG_SCOPE,
    scan_source: str = "android-native",
) -> dict[str, object]:
    return {
        "scan_id": f"scan-self-history-{number}",
        "home_id": home_id,
        "network_scope_id": network_scope_id,
        "scan_source": scan_source,
        "snapshot_payload": snapshot or authenticated_self_history_snapshot(),
    }


def current_self_history_neighbor(
    *,
    ip_address: str = SELF_HISTORY_IP,
    mac_address: str = SELF_HISTORY_MAC,
) -> dict[str, object]:
    return {
        "device_id": "endpoint-current",
        "ip_address": ip_address,
        "mac_address": mac_address,
        "manufacturer": "",
        "model": "",
        "device_type": "unknown",
        "discovery_sources": ["server-neighbor"],
    }


def resolve_authenticated_self_history(
    records: list[dict[str, object]] | None = None,
    current: dict[str, object] | None = None,
    *,
    home_id: str = SELF_HISTORY_HOME,
    scope_candidates: list[str] | None = None,
    current_mac: str | None = SELF_HISTORY_MAC,
):
    return verified_authenticated_self_android_history_identity(
        records
        if records is not None
        else [
            authenticated_self_history_record(1),
            authenticated_self_history_record(2),
        ],
        current if current is not None else current_self_history_neighbor(),
        home_id=home_id,
        current_scope_candidates=(
            scope_candidates
            if scope_candidates is not None
            else [OTHER_STRONG_SCOPE, STRONG_SCOPE]
        ),
        current_physical_mac=current_mac,
    )


def test_authenticated_self_history_recovers_exact_triplet_from_two_scans():
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(2),
    ]
    records[1]["device_snapshot_json"] = json.dumps(
        records[1].pop("snapshot_payload"), ensure_ascii=False
    )

    assert resolve_authenticated_self_history(records) == SELF_HISTORY_IDENTITY


@pytest.mark.parametrize(
    "records",
    [
        [authenticated_self_history_record(1)],
        [
            authenticated_self_history_record(1),
            {
                **authenticated_self_history_record(2),
                "scan_id": "scan-self-history-1",
            },
        ],
    ],
    ids=["single-observation", "duplicate-scan-id"],
)
def test_authenticated_self_history_requires_two_distinct_scans(records):
    assert resolve_authenticated_self_history(records) is None


def test_authenticated_self_history_rejects_conflicting_historical_model():
    conflicting = authenticated_self_history_snapshot(model="SM-S926N")
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(2, snapshot=conflicting),
    ]

    assert resolve_authenticated_self_history(records) is None


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("services", []),
        ("discovery_sources", ["android-native"]),
        ("risk_signals", []),
        (
            "fingerprints",
            [
                "self-android",
                "self-manufacturer:samsung",
                f"self-model:{SELF_HISTORY_MODEL}",
                "self-type:phone",
            ],
        ),
        ("confidence", 0.99),
    ],
    ids=[
        "service-marker",
        "source-marker",
        "risk-marker",
        "extra-self-fingerprint",
        "confidence",
    ],
)
def test_authenticated_self_history_rejects_inexact_self_markers(field, replacement):
    snapshot = authenticated_self_history_snapshot()
    snapshot[field] = replacement
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(2, snapshot=snapshot),
    ]

    assert resolve_authenticated_self_history(records) is None


@pytest.mark.parametrize(
    "record_mutation",
    [
        lambda record: record.__setitem__("home_id", "home-other"),
        lambda record: record.__setitem__("network_scope_id", LEGACY_SCOPE),
        lambda record: record.__setitem__(
            "network_scope_id", "hgns1b-fedcba9876543210fedcba9876543210"
        ),
        lambda record: record.__setitem__("scan_source", "server-network-probe"),
    ],
    ids=["different-home", "weak-scope", "different-bssid-scope", "wrong-source"],
)
def test_authenticated_self_history_rejects_wrong_history_boundary(record_mutation):
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(2),
    ]
    record_mutation(records[1])

    assert resolve_authenticated_self_history(records) is None


def test_authenticated_self_history_rejects_different_historical_ip():
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(
            2,
            snapshot=authenticated_self_history_snapshot(ip_address="192.168.50.28"),
        ),
    ]

    assert resolve_authenticated_self_history(records) is None


@pytest.mark.parametrize(
    ("current_mutation", "current_mac"),
    [
        (lambda current: current.__setitem__("discovery_sources", ["mdns"]), SELF_HISTORY_MAC),
        (
            lambda current: current.__setitem__(
                "mac_address", "DA:AA:BB:CC:DD:21"
            ),
            SELF_HISTORY_MAC,
        ),
        (lambda current: current.__setitem__("mac_address", "UNKNOWN-192.168.50.27"), None),
        (lambda current: current.__setitem__("ip_address", "192.168.50.29"), SELF_HISTORY_MAC),
    ],
    ids=[
        "not-server-neighbor",
        "physical-mac-conflict",
        "physical-mac-missing",
        "current-ip-changed",
    ],
)
def test_authenticated_self_history_requires_current_fresh_exact_neighbor(
    current_mutation,
    current_mac,
):
    current = current_self_history_neighbor()
    current_mutation(current)

    assert resolve_authenticated_self_history(current=current, current_mac=current_mac) is None


@pytest.mark.parametrize(
    ("manufacturer", "model", "device_type"),
    [
        ("Samsung", "SM-S926N", "phone"),
        ("LG", SELF_HISTORY_MODEL, "phone"),
        ("Samsung", SELF_HISTORY_MODEL, "tablet"),
    ],
    ids=["model-conflict", "manufacturer-conflict", "type-conflict"],
)
def test_authenticated_self_history_rejects_current_concrete_identity_conflict(
    manufacturer,
    model,
    device_type,
):
    current = current_self_history_neighbor()
    current.update(
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
    )

    assert resolve_authenticated_self_history(current=current) is None


def test_authenticated_self_history_accepts_matching_historical_real_mac():
    records = [
        authenticated_self_history_record(
            number,
            snapshot=authenticated_self_history_snapshot(mac_address=SELF_HISTORY_MAC),
        )
        for number in (1, 2)
    ]

    assert resolve_authenticated_self_history(records) == SELF_HISTORY_IDENTITY


def test_authenticated_self_history_rejects_conflicting_historical_real_mac():
    records = [
        authenticated_self_history_record(1),
        authenticated_self_history_record(
            2,
            snapshot=authenticated_self_history_snapshot(
                mac_address="DA:AA:BB:CC:DD:21"
            ),
        ),
    ]

    assert resolve_authenticated_self_history(records) is None


def test_authenticated_self_history_requires_current_bssid_scope_candidate():
    assert resolve_authenticated_self_history(
        scope_candidates=[OTHER_STRONG_SCOPE]
    ) is None


def historical_snapshot() -> dict[str, object]:
    return {
        "mac_address": "40:CA:63:FE:00:03",
        "fingerprints": [
            "mdns-name:40CA63FE0003",
            "mdns-type:._spotify-connect._tcp",
            "spotify-getinfo-done",
            "spotify-brand:Samsung",
            "spotify-model:Family_HUB",
        ],
        "discovery_sources": ["mdns", "spotify-getinfo"],
    }


def current_snapshot() -> dict[str, object]:
    return {
        "fingerprints": [
            "mdns-name:40CA63FE0003",
            "mdns-type:._spotify-connect._tcp",
        ],
        "discovery_sources": ["mdns"],
    }


def current_snapshot_with_physical_mac(
    mac_address: str = "40:CA:63:FE:00:03",
    token: str = "40CA63FE0003",
) -> dict[str, object]:
    snapshot = current_snapshot()
    snapshot["ip_address"] = "192.168.0.3"
    snapshot["mac_address"] = mac_address
    snapshot["fingerprints"][0] = f"mdns-name:{token}"
    return snapshot


def resolve(
    historical: dict[str, object] | str | None = None,
    current: dict[str, object] | str | None = None,
    *,
    historical_scope: str = STRONG_SCOPE,
    current_scope: str = STRONG_SCOPE,
    current_mac: str | None = None,
):
    return verified_family_hub_advertised_token_identity(
        historical_snapshot() if historical is None else historical,
        current_snapshot() if current is None else current,
        historical_scope_id=historical_scope,
        current_scope_id=current_scope,
        current_physical_mac=current_mac,
    )


def test_advertised_token_recovers_bounded_family_identity_without_current_mac():
    assert resolve() == EXPECTED_IDENTITY


def test_advertised_token_accepts_exact_current_mac_and_legacy_scope_migration():
    assert resolve(
        historical_scope=LEGACY_SCOPE,
        current_mac="40-ca-63-fe-00-03",
    ) == EXPECTED_IDENTITY


def test_advertised_token_treats_explicit_unknown_ip_placeholder_as_missing_mac():
    current = current_snapshot()
    current["mac_address"] = "UNKNOWN-192.168.0.3"
    assert resolve(current=current) == EXPECTED_IDENTITY


@pytest.mark.parametrize(
    ("historical_mutation", "current_mutation"),
    [
        (
            None,
            lambda value: value["fingerprints"].__setitem__(
                0, "mdns-name:40CA63FE0004"
            ),
        ),
        (lambda value: value.__setitem__("mac_address", None), None),
        (
            lambda value: value.__setitem__(
                "fingerprints",
                [item for item in value["fingerprints"] if item != "spotify-getinfo-done"],
            ),
            None,
        ),
        (
            lambda value: value.__setitem__(
                "fingerprints",
                [item for item in value["fingerprints"] if not item.startswith("spotify-brand:")],
            ),
            None,
        ),
        (
            lambda value: value["fingerprints"].append("spotify-brand:OtherBrand"),
            None,
        ),
        (
            lambda value: value.__setitem__(
                "fingerprints",
                [item for item in value["fingerprints"] if not item.startswith("spotify-model:")],
            ),
            None,
        ),
        (None, lambda value: value.__setitem__("discovery_sources", ["tcp-port-probe"])),
        (
            None,
            lambda value: value.__setitem__(
                "fingerprints",
                [item for item in value["fingerprints"] if not item.startswith("mdns-type:")],
            ),
        ),
        (
            None,
            lambda value: value["fingerprints"].__setitem__(0, "mdns-name:40CA632CF54"),
        ),
        (
            None,
            lambda value: value["fingerprints"].__setitem__(
                0, "mdns-name:40:CA:63:FE:00:03"
            ),
        ),
    ],
    ids=[
        "token-mismatch",
        "history-mac-missing",
        "getinfo-not-done",
        "getinfo-brand-missing",
        "getinfo-brand-conflict",
        "getinfo-family-missing",
        "current-mdns-source-missing",
        "current-spotify-type-missing",
        "short-token",
        "separated-token",
    ],
)
def test_advertised_token_rejects_incomplete_or_unbound_evidence(
    historical_mutation,
    current_mutation,
):
    historical = copy.deepcopy(historical_snapshot())
    current = copy.deepcopy(current_snapshot())
    if historical_mutation is not None:
        historical_mutation(historical)
    if current_mutation is not None:
        current_mutation(current)
    assert resolve(historical, current) is None


@pytest.mark.parametrize(
    "current_mac",
    ["40:CA:63:FE:00:04", "02:00:00:00:00:00", "not-a-mac"],
)
def test_advertised_token_rejects_conflicting_or_invalid_present_current_mac(current_mac):
    assert resolve(current_mac=current_mac) is None


@pytest.mark.parametrize(
    ("historical_scope", "current_scope"),
    [
        (STRONG_SCOPE, "hgns1s-22222222222222222222222222222222"),
        (OTHER_STRONG_SCOPE, STRONG_SCOPE),
        ("", STRONG_SCOPE),
    ],
)
def test_advertised_token_rejects_weak_or_incompatible_scope(
    historical_scope,
    current_scope,
):
    assert resolve(
        historical_scope=historical_scope,
        current_scope=current_scope,
    ) is None


def test_advertised_token_rejects_multiple_distinct_exact_tokens():
    current = current_snapshot()
    current["fingerprints"].append("mdns-name:40CA63FE0004")
    assert resolve(current=current) is None


def test_existing_same_mac_family_hub_helper_is_preserved():
    assert verified_family_hub_snapshot_identity(
        historical_snapshot(),
        historical_scope_id=STRONG_SCOPE,
        current_scope_id=STRONG_SCOPE,
        current_physical_mac="40:CA:63:FE:00:03",
    ) == EXPECTED_IDENTITY


@pytest.mark.parametrize("historical_mac", ["40:CA:63:FE:00:03", None])
def test_legacy_unscoped_family_hub_requires_current_real_mac_and_exact_token(
    historical_mac,
):
    historical = historical_snapshot()
    historical["mac_address"] = historical_mac
    assert verified_family_hub_snapshot_identity(
        historical,
        historical_scope_id=None,
        current_scope_id=STRONG_SCOPE,
        current_physical_mac="40:CA:63:FE:00:03",
        current_snapshot_payload=current_snapshot_with_physical_mac(),
    ) == EXPECTED_IDENTITY


@pytest.mark.parametrize(
    ("current_mac", "current_token"),
    [
        ("40:CA:63:FE:00:04", "40CA63FE0004"),
        ("40:CA:63:FE:00:03", "40CA63FE0004"),
    ],
    ids=["same-ip-reused-by-different-mac", "current-token-mismatch"],
)
def test_legacy_unscoped_family_hub_rejects_reused_ip_or_token_mismatch(
    current_mac,
    current_token,
):
    historical = historical_snapshot()
    historical["ip_address"] = "192.168.0.3"
    current = current_snapshot_with_physical_mac(current_mac, current_token)
    assert current["ip_address"] == historical["ip_address"]
    assert verified_family_hub_snapshot_identity(
        historical,
        historical_scope_id=None,
        current_scope_id=STRONG_SCOPE,
        current_physical_mac=current_mac,
        current_snapshot_payload=current,
    ) is None


@pytest.mark.parametrize(
    "removed_fingerprint_prefix",
    ["spotify-getinfo-done", "spotify-brand:", "spotify-model:"],
    ids=["getinfo-not-done", "structured-brand-missing", "structured-model-missing"],
)
def test_legacy_unscoped_family_hub_rejects_incomplete_structured_getinfo(
    removed_fingerprint_prefix,
):
    historical = historical_snapshot()
    historical["fingerprints"] = [
        value
        for value in historical["fingerprints"]
        if not value.startswith(removed_fingerprint_prefix)
    ]
    assert verified_family_hub_snapshot_identity(
        historical,
        historical_scope_id=None,
        current_scope_id=STRONG_SCOPE,
        current_physical_mac="40:CA:63:FE:00:03",
        current_snapshot_payload=current_snapshot_with_physical_mac(),
    ) is None


def test_legacy_unscoped_family_hub_rejects_missing_current_snapshot_proof():
    assert verified_family_hub_snapshot_identity(
        historical_snapshot(),
        historical_scope_id=None,
        current_scope_id=STRONG_SCOPE,
        current_physical_mac="40:CA:63:FE:00:03",
    ) is None
