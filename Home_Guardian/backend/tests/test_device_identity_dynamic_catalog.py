from __future__ import annotations

import copy
import hashlib
import json

import pytest

from app.services.device_identity import (
    resolve_device_identity,
    search_product_catalog,
    verified_catalog_identity,
    verified_catalog_marker_identity,
)
from app.services.identity_enrichment import (
    IdentityEnrichmentError,
    build_verified_product_catalog_entry,
)


def _overlay(
    manufacturer: str,
    model: str,
    device_type: str,
    source_url: str,
    *,
    provenance: str = "automated-official-web-search",
) -> dict[str, str]:
    return build_verified_product_catalog_entry(
        manufacturer=manufacturer,
        exact_model=model,
        device_type=device_type,
        source_url=source_url,
        provenance=provenance,
        verified_at="2026-08-28T00:00:00Z",
    )


def _structured_observation(
    manufacturer: str,
    model: str,
    device_type: str,
    *,
    device_id: str = "device-a",
    ip_address: str = "192.168.10.20",
) -> dict[str, object]:
    return {
        "device_id": device_id,
        "ip_address": ip_address,
        "mac_address": "00:11:22:33:44:55",
        "manufacturer": "",
        "model": "",
        "device_type": device_type,
        "fingerprints": [
            f"http-manufacturer:{manufacturer}",
            f"http-model:{model}",
            f"http-device-type:{device_type}",
        ],
        "services": ["http"],
        "open_ports": [80],
    }


def test_verified_overlay_exactly_resolves_structured_product_across_networks() -> None:
    entry = _overlay(
        "LG",
        "WHISEN-X1000",
        "air_conditioner",
        "https://www.lg.com/kr/air-conditioners/whisen-x1000",
    )
    first = _structured_observation(
        "LG", "WHISEN-X1000", "air_conditioner", ip_address="192.168.10.20"
    )
    second = _structured_observation(
        "LG", "WHISEN-X1000", "air_conditioner", ip_address="10.20.30.40"
    )

    for observation in (first, second):
        matches = search_product_catalog(observation, catalog_entries=[entry])
        assert matches[0]["match_kind"] == "exact_model"
        assert matches[0]["source"] == "verified_product_catalog_overlay"
        assert matches[0]["resolution_provenance"] == "automated-official-web-search"
        assert matches[0]["product_label"] == "LG 에어컨"

        resolved = resolve_device_identity(observation, catalog_entries=[entry])
        assert resolved["identity_status"] == "resolved"
        assert resolved["manufacturer"] == "LG"
        assert resolved["model"] == "WHISEN-X1000"
        assert resolved["device_type"] == "air_conditioner"
        assert resolved["canonical_name"] == "LG 에어컨 (WHISEN-X1000)"


def test_same_model_different_makers_requires_current_manufacturer_evidence() -> None:
    model = "SHARED-X9000"
    entries = [
        _overlay("LG", model, "camera", "https://www.lg.com/global/cameras/shared-x9000"),
        _overlay(
            "Samsung",
            model,
            "camera",
            "https://www.samsung.com/sec/cameras/shared-x9000/",
        ),
    ]
    ambiguous = {
        "device_type": "camera",
        "fingerprints": [f"http-model:{model}", "http-device-type:camera"],
        "services": ["http"],
        "open_ports": [80],
    }

    matches = search_product_catalog(ambiguous, catalog_entries=entries)
    assert {match["manufacturer"] for match in matches} == {"LG", "Samsung"}
    assert all(match["match_kind"] == "candidate" for match in matches)
    unresolved = resolve_device_identity(ambiguous, catalog_entries=entries)
    assert unresolved["identity_status"] != "resolved"
    assert unresolved["canonical_name"] == ""

    strong_lg = _structured_observation("LG", model, "camera")
    resolved = resolve_device_identity(strong_lg, catalog_entries=entries)
    assert resolved["identity_status"] == "resolved"
    assert resolved["manufacturer"] == "LG"
    assert resolved["canonical_name"] == f"LG 카메라 ({model})"


def test_static_catalog_precedes_equal_or_conflicting_overlay() -> None:
    equal = _overlay(
        "Sonos",
        "Arc",
        "speaker",
        "https://www.sonos.com/en-us/guides/arc",
    )
    conflicting_type = _overlay(
        "Sonos",
        "Arc",
        "tv",
        "https://www.sonos.com/en-us/guides/arc",
    )
    observation = _structured_observation("Sonos", "Arc", "speaker")

    matches = search_product_catalog(
        observation, catalog_entries=[equal, conflicting_type]
    )
    exact = [match for match in matches if match["match_kind"] == "exact_model"]
    assert len(exact) == 1
    assert exact[0]["catalog_id"] == "sonos-speaker"
    assert exact[0]["source"] == "server_product_catalog"
    resolved = resolve_device_identity(
        observation, catalog_entries=[equal, conflicting_type]
    )
    assert resolved["canonical_name"] == "Sonos 스피커 (Arc)"


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("manufacturer_key", "tampered-maker"),
        ("model_key", "tampered-model"),
        ("source_url", "https://lg.example.com/products/safebox-x900"),
        ("provenance", "unverified-import"),
        ("catalog_signature", "not-a-signature"),
        ("catalog_signature", "b" * 64),
        ("device_type", "iot"),
    ],
)
def test_malformed_or_tampered_overlay_is_ignored(field: str, bad_value: str) -> None:
    entry = _overlay(
        "LG",
        "SAFEBOX-X900",
        "camera",
        "https://www.lg.com/global/cameras/safebox-x900",
    )
    entry[field] = bad_value
    observation = _structured_observation("LG", "SAFEBOX-X900", "camera")

    assert search_product_catalog(observation, catalog_entries=[entry]) == []


@pytest.mark.parametrize(
    ("manufacturer", "model", "device_type", "source_url", "expected_label"),
    [
        (
            "LG",
            "WHISEN-A2000",
            "air_conditioner",
            "https://www.lg.com/kr/air-conditioners/whisen-a2000",
            "LG 에어컨",
        ),
        (
            "KT",
            "GIGA-X2000",
            "router",
            "https://product.kt.com/wDic/productDetail.do",
            "KT 공유기",
        ),
        (
            "Netgear",
            "NIGHTHAWK-X2000",
            "router",
            "https://www.netgear.com/home/wifi/routers/nighthawk-x2000/",
            "넷기어 공유기",
        ),
        (
            "Dahua",
            "DH-IPC-X2000",
            "camera",
            "https://www.dahuasecurity.com/products/dh-ipc-x2000",
            "다후아 카메라",
        ),
    ],
)
def test_registered_official_vendor_domains_are_allowed_for_overlay(
    manufacturer: str,
    model: str,
    device_type: str,
    source_url: str,
    expected_label: str,
) -> None:
    entry = _overlay(manufacturer, model, device_type, source_url)
    observation = _structured_observation(manufacturer, model, device_type)

    match = search_product_catalog(observation, catalog_entries=[entry])[0]
    assert match["match_kind"] == "exact_model"
    assert match["product_label"] == expected_label


def test_overlay_resolution_does_not_mutate_or_merge_distinct_observation_ids() -> None:
    entry = _overlay(
        "Netgear",
        "ACADEMY-X5000",
        "router",
        "https://www.netgear.com/home/wifi/routers/academy-x5000/",
    )
    first = _structured_observation(
        "Netgear",
        "ACADEMY-X5000",
        "router",
        device_id="classroom-device-01",
        ip_address="10.10.0.21",
    )
    second = _structured_observation(
        "Netgear",
        "ACADEMY-X5000",
        "router",
        device_id="classroom-device-02",
        ip_address="10.10.0.22",
    )
    before_first = copy.deepcopy(first)
    before_second = copy.deepcopy(second)

    first_identity = resolve_device_identity(first, catalog_entries=[entry])
    second_identity = resolve_device_identity(second, catalog_entries=[entry])

    assert first == before_first
    assert second == before_second
    assert first["device_id"] != second["device_id"]
    assert first_identity["canonical_name"] == second_identity["canonical_name"]
    assert "device_id" not in first_identity
    assert "device_id" not in second_identity


def test_overlay_catalog_marker_and_bound_history_are_revalidated_with_same_entries() -> None:
    entry = _overlay(
        "LG",
        "HISTORY-X8000",
        "air_conditioner",
        "https://www.lg.com/kr/air-conditioners/history-x8000",
    )
    observation = _structured_observation(
        "LG", "HISTORY-X8000", "air_conditioner"
    )
    resolved = resolve_device_identity(observation, catalog_entries=[entry])

    expected = {
        "manufacturer": "LG",
        "model": "HISTORY-X8000",
        "device_type": "air_conditioner",
        "evidence": "서버에 이전에 확인된 품번과 현재 장치 대조",
    }
    # The immediate presentation boundary can revalidate the exact overlay
    # through its bound HMAC-signed row. A public/scanner-shaped copy loses
    # that private row and still needs the repository's signed entries
    # explicitly.
    assert verified_catalog_marker_identity(resolved) == expected
    # Resolver output is persisted as a JSON snapshot by both repository
    # implementations; the signed presentation proof must stay serializable.
    json.dumps(resolved, ensure_ascii=False)
    forged_bound_proof = copy.deepcopy(resolved)
    forged_bound_proof["_verified_catalog_overlay_entries"][0][
        "catalog_signature"
    ] = "b" * 64
    assert verified_catalog_marker_identity(forged_bound_proof) is None
    serialized_shape = {
        key: value for key, value in resolved.items() if not key.startswith("_")
    }
    assert verified_catalog_marker_identity(serialized_shape) is None
    marker = verified_catalog_marker_identity(resolved, catalog_entries=[entry])
    assert marker == expected

    historical_record = {
        **observation,
        **serialized_shape,
        "scan_source": "android-native",
        "mac_address": "00:11:22:33:44:55",
        "is_phantom": False,
    }
    assert verified_catalog_identity(historical_record) is None
    assert verified_catalog_identity(
        historical_record, catalog_entries=[entry]
    ) == marker


def test_conflicting_duplicate_overlay_types_are_all_ignored() -> None:
    model = "CONFLICT-X7000"
    entries = [
        _overlay(
            "Netgear",
            model,
            "router",
            "https://www.netgear.com/home/wifi/routers/conflict-x7000/",
        ),
        _overlay(
            "Netgear",
            model,
            "camera",
            "https://www.netgear.com/home/security/cameras/conflict-x7000/",
        ),
    ]
    observation = _structured_observation("Netgear", model, "router")

    assert search_product_catalog(observation, catalog_entries=entries) == []


def test_efm_alias_overlay_cannot_shadow_same_static_iptime_model() -> None:
    entry = _overlay(
        "EFM",
        "A3004NS-M",
        "router",
        "https://www.iptime.com/iptime/etc/down_prd_list.php",
    )
    observation = _structured_observation("EFM", "A3004NS-M", "router")

    matches = search_product_catalog(observation, catalog_entries=[entry])
    exact = [item for item in matches if item["match_kind"] == "exact_model"]
    assert len(exact) == 1
    assert exact[0]["catalog_id"] == "iptime-router"
    assert exact[0]["source"] == "server_product_catalog"
    assert resolve_device_identity(
        observation, catalog_entries=[entry]
    )["canonical_name"] == "ipTIME 공유기 (A3004NS-M)"


def test_overlay_exact_model_uses_nfkc_spacing_key_and_canonical_display() -> None:
    entry = _overlay(
        "LG",
        "WHISEN X1000",
        "air_conditioner",
        "https://www.lg.com/kr/air-conditioners/whisen-x1000",
    )
    observation = _structured_observation(
        "LG", "ＷＨＩＳＥＮ   Ｘ１０００", "air_conditioner"
    )

    match = search_product_catalog(observation, catalog_entries=[entry])[0]
    assert match["match_kind"] == "exact_model"
    assert match["model"] == "WHISEN X1000"
    resolved = resolve_device_identity(observation, catalog_entries=[entry])
    assert resolved["model"] == "WHISEN X1000"
    assert resolved["canonical_name"] == "LG 에어컨 (WHISEN X1000)"


def test_dynamic_marker_rebinds_only_to_identical_promoted_static_product() -> None:
    entry = _overlay(
        "EFM",
        "A3004",
        "router",
        "https://www.iptime.com/iptime/etc/down_prd_list.php",
    )
    old_id_payload = "\x1f".join(
        (entry["manufacturer_key"], entry["model_key"], entry["device_type"])
    )
    old_catalog_id = "verified-product-" + hashlib.sha256(
        old_id_payload.encode("utf-8")
    ).hexdigest()[:24]
    historical = {
        "identity_status": "resolved",
        "identity_resolver_version": "server-identity-1.0.0",
        "identity_confidence": 0.96,
        "manufacturer": "EFM",
        "model": "A3004",
        "device_type": "router",
        "identity_candidates": [
            {
                "kind": "서버 카탈로그 확정",
                "catalog_id": old_catalog_id,
                "label": "ipTIME 공유기 (A3004)",
            }
        ],
    }

    assert verified_catalog_marker_identity(
        historical, catalog_entries=[entry]
    ) == {
        "manufacturer": "EFM",
        "model": "A3004",
        "device_type": "router",
        "evidence": "서버에 이전에 확인된 품번과 현재 장치 대조",
    }
    assert verified_catalog_marker_identity(
        {**historical, "device_type": "camera"}, catalog_entries=[entry]
    ) is None
    forged_marker = copy.deepcopy(historical)
    forged_marker["identity_candidates"][0]["catalog_id"] = (
        "verified-product-000000000000000000000000"
    )
    assert verified_catalog_marker_identity(
        forged_marker, catalog_entries=[entry]
    ) is None


@pytest.mark.parametrize(
    ("manufacturer", "source_url"),
    [
        ("Google", "https://sites.google.com/view/CAST-X1000/"),
        ("LG", "https://www.lg.com:444/kr/air-conditioners/WHISEN-X1000"),
        ("Samsung", "https://www.samsung.com/sec/community/RF85C90N1AP/"),
        ("Samsung", "https://www.samsung.com/sec/forums/RF85C90N1AP/"),
        ("KT", "https://product.kt.com/wDic/productDetail.do?ItemCode=SAFE-X1000"),
        ("Acme", "https://acme.com/products/ACME-X1000/"),
    ],
)
def test_signed_overlay_requires_registered_fqdn_port_and_product_path(
    manufacturer: str,
    source_url: str,
) -> None:
    with pytest.raises(IdentityEnrichmentError, match="IDENTITY_MODEL_NOT_SPECIFIC"):
        _overlay(
            manufacturer,
            "CAST-X1000" if manufacturer == "Google" else "SAFE-X1000",
            "tv" if manufacturer in {"Google", "Samsung"} else "router",
            source_url,
            provenance="operator-reviewed",
        )
