from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import unicodedata
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.parse import urlsplit

from .device_identity import (
    DEVICE_TYPE_LABELS,
    MODEL_PREFIX_DEVICE_TYPE,
    MODEL_PREFIX_VENDOR,
    VENDOR_KO,
    is_registered_official_product_source,
    is_concrete_product_model,
    is_product_manufacturer,
    normalize_vendor_name,
    vendor_from_model_prefix,
    vendor_from_oui,
    vendor_from_text,
)
from .device_presentation import (
    contains_forbidden_device_name,
    contains_non_product_identifier,
    contains_private_network_identifier,
    is_self_observation,
)


IDENTITY_ENRICHMENT_STATUSES = frozenset(
    {"review_required", "resolved", "rejected", "blocked", "superseded"}
)
IDENTITY_ENRICHMENT_REJECT_REASONS = frozenset(
    {"NOT_A_PRODUCT", "INSUFFICIENT_EVIDENCE", "INCORRECT_BINDING"}
)
IDENTITY_ENRICHMENT_RESOLVER_VERSION = "identity-enrichment-review-1.0.0"
IDENTITY_RESOLUTION_PROVENANCE_OPERATOR = "operator-reviewed"
IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED = "automated-official-web-search"
IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP = "automated-official-http"
IDENTITY_RESOLUTION_AUTOMATED_PROVENANCES = frozenset(
    {
        IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED,
        IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
    }
)
IDENTITY_RESOLUTION_PROVENANCES = frozenset(
    {
        IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
        *IDENTITY_RESOLUTION_AUTOMATED_PROVENANCES,
    }
)

_STRUCTURED_FINGERPRINT_PREFIXES = {
    "spotify-brand": "manufacturer_hints",
    "airplay-manufacturer": "manufacturer_hints",
    "upnp-manufacturer": "manufacturer_hints",
    "ipp-manufacturer": "manufacturer_hints",
    "printer-manufacturer": "manufacturer_hints",
    "http-manufacturer": "manufacturer_hints",
    "spotify-model": "model_hints",
    "upnp-model": "model_hints",
    "googlecast-model": "model_hints",
    "airplay-model": "model_hints",
    "ipp-model": "model_hints",
    "http-model": "model_hints",
    "http-product": "model_hints",
    "spotify-type": "device_type_hints",
    "upnp-device-type": "device_type_hints",
    "googlecast-type": "device_type_hints",
    "http-device-type": "device_type_hints",
    "mdns-type": "service_hints",
}
_STRUCTURED_PROOF_PREFIXES = {
    "spotify-brand": ("manufacturer", "spotify"),
    "airplay-manufacturer": ("manufacturer", "airplay"),
    "upnp-manufacturer": ("manufacturer", "upnp"),
    "ipp-manufacturer": ("manufacturer", "ipp"),
    "printer-manufacturer": ("manufacturer", "ipp"),
    "http-manufacturer": ("manufacturer", "http"),
    "spotify-model": ("model", "spotify"),
    "upnp-model": ("model", "upnp"),
    "googlecast-model": ("model", "googlecast"),
    "airplay-model": ("model", "airplay"),
    "ipp-model": ("model", "ipp"),
    "http-model": ("model", "http"),
    "http-product": ("model", "http"),
    "spotify-type": ("device_type", "spotify"),
    "upnp-device-type": ("device_type", "upnp"),
    "googlecast-type": ("device_type", "googlecast"),
    "http-device-type": ("device_type", "http"),
}
_STRUCTURED_MDNS_TXT_FIELDS = {
    "manufacturer": ("manufacturer_hints", "manufacturer"),
    "model": ("model_hints", "model"),
}
_SPOTIFY_TYPE_PROOFS = {
    "tv": "tv",
    "computer": "computer",
    "cast_video": "tv",
    "stb": "tv",
    "avr": "audio",
    "speaker": "speaker",
    "audio_dongle": "speaker",
    "cast_audio": "speaker",
}
_STRONG_SERVICE_TYPE_PROOFS = {
    "ipp": "printer",
    "onvif": "camera",
    "ws-discovery": "camera",
}
_ALLOWED_SERVICES = frozenset(
    {
        "airplay",
        "googlecast",
        "http",
        "https",
        "ipp",
        "mdns",
        "mqtt",
        "netbios",
        "onvif",
        "rtsp",
        "smb",
        "spotify-connect",
        "ssdp",
        "ssh",
        "telnet",
        "upnp",
        "ws-discovery",
    }
)
_ALLOWED_DISCOVERY_SOURCES = frozenset(
    {
        "airplay",
        "googlecast",
        "ipp",
        "mdns",
        "netbios",
        "onvif",
        "server-protocol-probe",
        "spotify",
        "ssdp",
        "http",
        "tcp-port-probe",
        "upnp",
        "ws-discovery",
    }
)
_GENERIC_MODEL_WORDS = frozenset(
    {
        "air conditioner",
        "appliance",
        "camera",
        "computer",
        "device",
        "family",
        "family hub",
        "family_hub",
        "fridge",
        "hub",
        "iot",
        "kitchen",
        "living room",
        "printer",
        "refrigerator",
        "router",
        "series",
        "smart tv",
        "speaker",
        "television",
        "tv",
        "unknown",
        "web-device",
        "공유기",
        "기기",
        "냉장고",
        "모델",
        "스마트 tv",
        "에어컨",
        "카메라",
    }
)
_MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|\b[0-9a-f]{12}\b")
_SAFE_HINT_RE = re.compile(r"^[0-9A-Za-z가-힣][0-9A-Za-z가-힣 .,_()+/&-]{0,95}$")
_SAFE_SERVICE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
_SAFE_HOST_BINDING_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,62}$")
_HOST_BINDING_SERVICE_SUFFIX_RE = re.compile(
    r"\._[0-9A-Za-z-]+\._(?:tcp|udp)\.local$", re.IGNORECASE
)
_HOST_BINDING_FINGERPRINT_SOURCES = {
    "netbios-name": "netbios",
    "mdns-name": "mdns",
}
_STABLE_BINDING_PROOF_SOURCES = frozenset(
    {
        "airplay",
        "googlecast",
        "ipp",
        "mdns",
        "onvif",
        "spotify",
        "upnp",
        "ws-discovery",
    }
)
_OPAQUE_SOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#?=&%-]{7,511}$")
_AUTHENTICATED_SELF_ANDROID_SOURCE = "authenticated-self-android"
_AUTHENTICATED_SELF_ANDROID_PROOF_FIELD = "_authenticated_self_android_proof"
_AUTHENTICATED_SELF_ANDROID_PROOF = object()
_AUTHENTICATED_SELF_ANDROID_TOKEN_PREFIXES = (
    "authenticated-self-android",
    "authenticated-self-manufacturer:",
    "authenticated-self-model:",
    "authenticated-self-type:",
)
_PHYSICAL_MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


class IdentityEnrichmentError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def identity_enrichment_hmac_secret() -> bytes:
    configured = os.environ.get("HG_AUTH_TOKEN_SECRET", "").strip()
    if len(configured) < 32:
        raise RuntimeError("HG_AUTH_TOKEN_SECRET must be at least 32 characters")
    return hmac.new(
        configured.encode("utf-8"),
        b"home-guardian/identity-enrichment/v1",
        hashlib.sha256,
    ).digest()


def _normalized_marker_values(device: Mapping[str, Any], field: str) -> set[str]:
    raw_values = device.get(field) or []
    if isinstance(raw_values, str):
        raw_values = [raw_values]
    return {
        str(value or "").strip().casefold().replace("_", "-")
        for value in raw_values
        if str(value or "").strip()
    }


def _validated_physical_mac(value: object) -> str | None:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(compact) != 12:
        return None
    canonical = ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if not _PHYSICAL_MAC_RE.fullmatch(canonical):
        return None
    if compact in {"000000000000", "020000000000", "FFFFFFFFFFFF"}:
        return None
    if int(compact[:2], 16) & 1:
        return None
    return canonical


def _authenticated_self_model_type(model: str) -> str | None:
    upper = model.upper().replace("_", "")
    for prefix, device_type in sorted(
        MODEL_PREFIX_DEVICE_TYPE,
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if upper.startswith(prefix.upper().replace("_", "")):
            return device_type
    return None


def _authenticated_self_android_triplet(
    device: Mapping[str, Any],
) -> tuple[str, str, str] | None:
    """Validate the Build identity carried by a server-attested self row.

    This validates product semantics only.  It does not mint trust from the
    client payload: callers must additionally require the in-process object
    sentinel, which can be added only after the request/L2 verifier succeeds.
    """

    if not is_self_observation(device):
        return None
    try:
        confidence = float(device.get("confidence"))
    except (TypeError, ValueError):
        return None
    if isinstance(device.get("confidence"), bool) or confidence != 1.0:
        return None

    try:
        local_ip = ipaddress.ip_address(str(device.get("ip_address") or "").strip())
    except ValueError:
        return None
    if (
        local_ip.version != 4
        or not local_ip.is_private
        or local_ip.is_loopback
        or local_ip.is_link_local
        or local_ip.is_multicast
    ):
        return None
    if _validated_physical_mac(device.get("mac_address")) is None:
        return None

    manufacturer_raw = " ".join(str(device.get("manufacturer") or "").strip().split())
    manufacturer = normalize_vendor_name(manufacturer_raw)
    model = " ".join(str(device.get("model") or "").strip().split())
    device_type = str(device.get("device_type") or "").strip().casefold()
    if (
        not is_product_manufacturer(manufacturer)
        or not is_concrete_product_model(model, manufacturer)
        or device_type not in DEVICE_TYPE_LABELS
    ):
        return None

    prefix_vendor = vendor_from_model_prefix(model)
    prefix_type = _authenticated_self_model_type(model)
    if (
        prefix_vendor is None
        or normalize_vendor_name(prefix_vendor).casefold() != manufacturer.casefold()
        or prefix_type != device_type
    ):
        return None

    services = _normalized_marker_values(device, "services")
    sources = _normalized_marker_values(device, "discovery_sources")
    risks = _normalized_marker_values(device, "risk_signals")
    fingerprints = {
        str(value or "").strip()
        for value in (device.get("fingerprints") or [])
        if str(value or "").strip()
    }
    self_fingerprints = {
        value
        for value in fingerprints
        if value.casefold().startswith("self-")
    }
    expected_self_fingerprints = {
        "self-android",
        f"self-manufacturer:{manufacturer_raw}",
        f"self-model:{model}",
    }
    if (
        "self-device" not in services
        or "self" not in sources
        or "self-device" not in risks
        or self_fingerprints != expected_self_fingerprints
    ):
        return None
    return manufacturer, model, device_type


def strip_untrusted_authenticated_self_android(
    observation: Mapping[str, Any],
) -> dict[str, Any]:
    """Remove every client-serializable imitation of the server-only proof."""

    cleaned = {
        str(key): value
        for key, value in observation.items()
        if not str(key).startswith("_authenticated_self_android")
    }
    for field in ("services", "discovery_sources", "fingerprints", "risk_signals"):
        raw_values = cleaned.get(field)
        if not isinstance(raw_values, (list, tuple, set)):
            continue
        cleaned[field] = [
            value
            for value in raw_values
            if not str(value or "").strip().casefold().startswith(
                _AUTHENTICATED_SELF_ANDROID_TOKEN_PREFIXES
            )
        ]
    return cleaned


def bind_authenticated_self_android_claim(
    observation: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Attach an in-process proof after the request/L2 verifier succeeds.

    The caller is responsible for checking the current HTTP peer, declared
    local address, fresh same-interface neighbour entry, unique physical MAC,
    subnet and strong scope.  This helper deliberately accepts no flag or raw
    marker that a JSON client could forge.  It only revalidates the exact Build
    triplet and adds an object identity that cannot survive serialization.
    """

    cleaned = strip_untrusted_authenticated_self_android(observation)
    if _authenticated_self_android_triplet(cleaned) is None:
        return None
    cleaned[_AUTHENTICATED_SELF_ANDROID_PROOF_FIELD] = (
        _AUTHENTICATED_SELF_ANDROID_PROOF
    )
    return cleaned


def authenticated_self_android_evidence(
    observation: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project a genuine server-only sentinel to private structured evidence."""

    if (
        observation.get(_AUTHENTICATED_SELF_ANDROID_PROOF_FIELD)
        is not _AUTHENTICATED_SELF_ANDROID_PROOF
    ):
        return None
    triplet = _authenticated_self_android_triplet(observation)
    if triplet is None:
        return None
    manufacturer, model, device_type = triplet
    return {
        "manufacturer_hints": [manufacturer],
        "model_hints": [model],
        "device_type_hints": [device_type],
        "structured_provenance": [
            {
                "kind": kind,
                "source": _AUTHENTICATED_SELF_ANDROID_SOURCE,
                "value": value,
            }
            for kind, value in (
                ("manufacturer", manufacturer),
                ("model", model),
                ("device_type", device_type),
            )
        ],
    }


def authenticated_self_android_binding(
    observation: Mapping[str, Any],
) -> tuple[str, str, str, str, str] | None:
    """Return the primitive one-shot storage binding for a genuine sentinel.

    The tuple contains only the exact current endpoint and validated Build
    triplet.  It intentionally omits a timestamp, SSID/BSSID and any reusable
    IP-only fallback.  Repositories must still require one strong current
    scope, an unambiguous physical MAC and one exact normalized stored match.
    """

    if authenticated_self_android_evidence(observation) is None:
        return None
    triplet = _authenticated_self_android_triplet(observation)
    physical_mac = _validated_physical_mac(observation.get("mac_address"))
    if triplet is None or physical_mac is None:
        return None
    manufacturer, model, device_type = triplet
    return (
        str(observation.get("ip_address") or "").strip(),
        physical_mac,
        manufacturer,
        model,
        device_type,
    )


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(label: str, value: object) -> str:
    payload = f"{label}\0{_canonical_json(value)}".encode("utf-8")
    return hmac.new(identity_enrichment_hmac_secret(), payload, hashlib.sha256).hexdigest()


def build_identity_job_key(
    *,
    home_id: str,
    device_id: str,
    network_scope_id: str | None,
    physical_mac: str | None,
    evidence_binding_signature: str | None = None,
) -> str:
    stable_binding = str(evidence_binding_signature or "").strip()
    payload = {
        "home_id": home_id,
        # A model, hostname or service signature describes a product family or
        # endpoint advertisement, not one physical unit. Without a physical
        # MAC the opaque observation id must remain in the key so two devices
        # advertising identical evidence cannot share an approval.
        "device_id": device_id if not physical_mac else "",
        "network_scope_id": network_scope_id or "",
        "physical_mac": physical_mac or "",
    }
    # Preserve every existing physical-MAC and blocked-job key.  Adding even an
    # empty JSON member would otherwise invalidate signed jobs during upgrade.
    if stable_binding and not physical_mac:
        payload["evidence_binding_signature"] = stable_binding
    return _digest("job-key", payload)


def identity_job_key_matches(job: Mapping[str, Any]) -> bool:
    evidence = job.get("evidence")
    stable_binding = (
        stable_identity_evidence_signature(
            evidence,
            device_id=job.get("device_id"),
        )
        if isinstance(evidence, Mapping)
        else None
    )
    claimed_binding = str(job.get("evidence_binding_signature") or "").strip() or None
    if claimed_binding is not None and (
        stable_binding is None
        or not hmac.compare_digest(stable_binding, claimed_binding)
    ):
        return False
    try:
        expected = build_identity_job_key(
            home_id=str(job.get("home_id") or ""),
            device_id=str(job.get("device_id") or ""),
            network_scope_id=str(job.get("network_scope_id") or "") or None,
            physical_mac=str(job.get("physical_mac") or "") or None,
            evidence_binding_signature=claimed_binding,
        )
    except (RuntimeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, str(job.get("job_key") or ""))


def build_evidence_signature(evidence: Mapping[str, Any]) -> str:
    return _digest("evidence", dict(evidence))


def evidence_signature_matches(evidence: Mapping[str, Any], signature: object) -> bool:
    expected = build_evidence_signature(evidence)
    return hmac.compare_digest(expected, str(signature or ""))


def build_resolution_signature(
    *,
    job_key: str,
    evidence_signature: str,
    resolution: Mapping[str, Any],
    source_reference: str,
    resolution_provenance: str,
) -> str:
    if resolution_provenance not in IDENTITY_RESOLUTION_PROVENANCES:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return _digest(
        "resolution-envelope",
        {
            "job_key": job_key,
            "evidence_signature": evidence_signature,
            "resolution": dict(resolution),
            "source_reference": source_reference,
            "resolution_provenance": resolution_provenance,
        },
    )


def is_automated_identity_resolution_provenance(value: object) -> bool:
    return str(value or "").strip() in IDENTITY_RESOLUTION_AUTOMATED_PROVENANCES


def _verified_product_catalog_key(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or ""))
    return " ".join(normalized.strip().casefold().split())


def verified_product_catalog_keys(
    manufacturer: object,
    exact_model: object,
) -> tuple[str, str]:
    """Return stable, non-household keys for one exact product fact."""

    manufacturer_key = _verified_product_catalog_key(
        normalize_vendor_name(str(manufacturer or "").strip())
    )
    model_key = _verified_product_catalog_key(exact_model)
    if not manufacturer_key or not model_key:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return manufacturer_key, model_key


def build_verified_product_catalog_entry(
    *,
    manufacturer: object,
    device_type: object,
    exact_model: object,
    source_url: object,
    provenance: object,
    verified_at: object | None = None,
) -> dict[str, str]:
    """Validate and sign a global exact-product fact.

    The signed payload deliberately contains no home, network or device
    binding. Those fields remain in the per-home enrichment job/history while
    this record can be reused across homes only when a later observation
    independently advertises the same exact product evidence.
    """

    normalized_provenance = str(provenance or "").strip()
    if normalized_provenance not in IDENTITY_RESOLUTION_PROVENANCES:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    validated = validate_identity_resolution(
        manufacturer=manufacturer,
        device_type=device_type,
        model=exact_model,
        source_reference=source_url,
    )
    parsed_source = urlsplit(validated["source_reference"])
    if parsed_source.query or parsed_source.fragment:
        # A global product fact must not retain per-request tracking or
        # resident-derived query values. Keep only stable official pages.
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    # A signed global product row is reusable across households regardless of
    # how it was approved.  Operator review therefore does not bypass the same
    # explicit manufacturer/FQDN/path trust registry used by automation.
    if not source_matches_registered_official_domain(
        validated["source_reference"],
        validated["manufacturer"],
    ):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    verified_text = str(verified_at or "").strip()
    if not verified_text:
        verified_text = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed_verified_at = datetime.fromisoformat(verified_text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC") from exc
    if parsed_verified_at.tzinfo is None:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")

    manufacturer_key, model_key = verified_product_catalog_keys(
        validated["manufacturer"],
        validated["model"],
    )
    payload = {
        "manufacturer": validated["manufacturer"],
        "manufacturer_key": manufacturer_key,
        "exact_model": validated["model"],
        "model_key": model_key,
        "device_type": validated["device_type"],
        "source_url": validated["source_reference"],
        "provenance": normalized_provenance,
        "verified_at": verified_text,
    }
    return {
        **payload,
        "catalog_signature": _digest("verified-product-catalog/v1", payload),
    }


def verified_product_catalog_entry_matches(entry: Mapping[str, Any]) -> bool:
    """Verify a persisted global catalog row before exposing it to resolvers."""

    try:
        rebuilt = build_verified_product_catalog_entry(
            manufacturer=entry.get("manufacturer"),
            device_type=entry.get("device_type"),
            exact_model=entry.get("exact_model"),
            source_url=entry.get("source_url"),
            provenance=entry.get("provenance"),
            verified_at=entry.get("verified_at"),
        )
    except (IdentityEnrichmentError, RuntimeError, TypeError, ValueError):
        return False
    for field in (
        "manufacturer",
        "manufacturer_key",
        "exact_model",
        "model_key",
        "device_type",
        "source_url",
        "provenance",
        "verified_at",
    ):
        if not hmac.compare_digest(str(rebuilt[field]), str(entry.get(field) or "")):
            return False
    return hmac.compare_digest(
        rebuilt["catalog_signature"],
        str(entry.get("catalog_signature") or ""),
    )


def resolution_signature_matches(job: Mapping[str, Any]) -> bool:
    resolution = job.get("resolution")
    if not isinstance(resolution, Mapping):
        return False
    provenance = str(
        job.get("resolution_provenance")
        or resolution.get("resolution_provenance")
        or ""
    )
    try:
        expected = build_resolution_signature(
            job_key=str(job.get("job_key") or ""),
            evidence_signature=str(job.get("evidence_signature") or ""),
            resolution=resolution,
            source_reference=str(job.get("source_reference") or ""),
            resolution_provenance=provenance,
        )
    except (IdentityEnrichmentError, RuntimeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, str(job.get("resolution_signature") or ""))


def _safe_hint(value: object) -> str | None:
    text = " ".join(str(value or "").strip().split())
    if not text or len(text) > 96 or not _SAFE_HINT_RE.fullmatch(text):
        return None
    if (
        _MAC_RE.search(text)
        or contains_private_network_identifier(text)
        or text.casefold().endswith(".local")
    ):
        return None
    return text


def _globally_administered_oui_vendor(value: object) -> str | None:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(compact) != 12:
        return None
    first_octet = int(compact[:2], 16)
    if first_octet & 0b11:
        # Multicast and locally administered addresses do not prove the
        # hardware vendor even when their first three octets happen to occur
        # in the IEEE registry.
        return None
    return vendor_from_oui(compact)


def _structured_type_proof(prefix: str, value: str) -> str | None:
    normalized = value.strip().casefold().replace("-", "_")
    if prefix == "spotify-type":
        return _SPOTIFY_TYPE_PROOFS.get(normalized)
    if prefix in {"upnp-device-type", "upnp-type"}:
        if "internetgatewaydevice" in normalized or "wanconnectiondevice" in normalized:
            return "router"
        if "printer" in normalized:
            return "printer"
        return None
    if prefix == "googlecast-type":
        return _SPOTIFY_TYPE_PROOFS.get(normalized)
    return normalized if normalized in DEVICE_TYPE_LABELS else None


def _stable_host_binding_token(prefix: str, value: object) -> str | None:
    """Return a keyed, non-reversible token for one protocol hostname.

    Host names are useful for correlating a MAC-less observation inside one
    strong Wi-Fi scope, but they may contain a resident's name or room.  Store
    neither the raw value nor an address-shaped service instance.  This token
    is binding evidence only; it never proves manufacturer, model or category.
    """

    source = _HOST_BINDING_FINGERPRINT_SOURCES.get(prefix)
    if source is None:
        return None
    candidate = " ".join(str(value or "").strip().split())
    candidate = _HOST_BINDING_SERVICE_SUFFIX_RE.sub("", candidate).strip().strip(".")
    if ".local" in candidate.casefold():
        candidate = candidate.split(".", 1)[0]
    if (
        not candidate
        or not _SAFE_HOST_BINDING_RE.fullmatch(candidate)
        or candidate.casefold() in {"localhost", "local", "unknown", "workstation", "services"}
        or _MAC_RE.fullmatch(candidate)
        or re.fullmatch(r"[0-9A-Fa-f]{12}", candidate)
    ):
        return None
    return f"hghost1-{_digest('identity-host-binding', {'source': source, 'host': candidate.casefold()})}"


def structured_identity_evidence(device: Mapping[str, Any]) -> dict[str, Any]:
    """Extract review clues without retaining household network identifiers."""

    evidence: dict[str, set[str]] = {
        "manufacturer_hints": set(),
        "model_hints": set(),
        "device_type_hints": set(),
        "service_hints": set(),
        "discovery_sources": set(),
    }
    structured_provenance: set[tuple[str, str, str]] = set()
    authenticated_self = authenticated_self_android_evidence(device)
    if authenticated_self is not None:
        for key in (
            "manufacturer_hints",
            "model_hints",
            "device_type_hints",
        ):
            evidence[key].update(authenticated_self.get(key) or [])
        for proof in authenticated_self.get("structured_provenance") or []:
            if isinstance(proof, Mapping):
                structured_provenance.add(
                    (
                        str(proof.get("kind") or ""),
                        str(proof.get("source") or ""),
                        str(proof.get("value") or ""),
                    )
                )
    host_binding_hints: set[str] = set()
    host_binding_sources: set[str] = set()
    observed_protocols = {
        str(value or "").strip().casefold()
        for field in ("services", "discovery_sources")
        for value in (device.get(field) or [])
    }

    for raw in device.get("fingerprints") or []:
        fingerprint = str(raw or "")
        prefix, separator, value = fingerprint.partition(":")
        normalized_prefix = prefix.strip().casefold()
        host_binding_token = (
            _stable_host_binding_token(normalized_prefix, value)
            if separator
            else None
        )
        host_binding_source = _HOST_BINDING_FINGERPRINT_SOURCES.get(normalized_prefix)
        if host_binding_token and host_binding_source in observed_protocols:
            host_binding_hints.add(host_binding_token)
            host_binding_sources.add(host_binding_source)
        target = _STRUCTURED_FINGERPRINT_PREFIXES.get(normalized_prefix)
        hint = _safe_hint(value) if separator and target else None
        if hint:
            if target == "device_type_hints":
                hint = _structured_type_proof(normalized_prefix, hint)
            if not hint:
                continue
            evidence[target].add(hint)
            proof_kind_source = _STRUCTURED_PROOF_PREFIXES.get(normalized_prefix)
            if proof_kind_source:
                proof_kind, proof_source = proof_kind_source
                structured_provenance.add((proof_kind, proof_source, hint))

        # Native mDNS TXT fields use ``mdns-txt:key=value``.  Parse only the
        # two product identity keys the resolver already trusts; arbitrary TXT
        # names, locations and endpoint-controlled metadata must not enter the
        # review evidence or become product models.
        if separator and normalized_prefix == "mdns-txt":
            txt_key, txt_separator, txt_value = value.partition("=")
            normalized_txt_key = txt_key.strip().casefold()
            field = _STRUCTURED_MDNS_TXT_FIELDS.get(normalized_txt_key)
            if field is None and normalized_txt_key in {"am", "md"}:
                # AirPlay/RAOP uses ``am`` for a hardware model. ``md`` is also
                # used by Cast devices, but AirPlay capability bitmaps such as
                # ``0,1,2`` are not models.
                if not re.fullmatch(r"\d+(?:,\d+)+", txt_value.strip()):
                    field = ("model_hints", "model")
            txt_hint = _safe_hint(txt_value) if txt_separator and field else None
            if field and txt_hint:
                target, proof_kind = field
                evidence[target].add(txt_hint)
                structured_provenance.add((proof_kind, "mdns", txt_hint))

        if separator and normalized_prefix == "upnp-type":
            type_hint = _structured_type_proof(normalized_prefix, value)
            if type_hint:
                evidence["device_type_hints"].add(type_hint)
                structured_provenance.add(("device_type", "upnp", type_hint))

    oui_vendor = _globally_administered_oui_vendor(device.get("mac_address"))
    if oui_vendor:
        safe_vendor = _safe_hint(normalize_vendor_name(oui_vendor))
        if safe_vendor:
            evidence["manufacturer_hints"].add(safe_vendor)
            structured_provenance.add(
                ("manufacturer", "physical-mac-oui", safe_vendor)
            )

    for raw in device.get("services") or []:
        service = str(raw or "").strip().casefold()
        if service in _ALLOWED_SERVICES and _SAFE_SERVICE_RE.fullmatch(service):
            evidence["service_hints"].add(service)
            type_hint = _STRONG_SERVICE_TYPE_PROOFS.get(service)
            if type_hint:
                evidence["device_type_hints"].add(type_hint)
                structured_provenance.add(("device_type", service, type_hint))
    for raw in device.get("discovery_sources") or []:
        source = str(raw or "").strip().casefold()
        if source in _ALLOWED_DISCOVERY_SOURCES and _SAFE_SERVICE_RE.fullmatch(source):
            evidence["discovery_sources"].add(source)

    result: dict[str, Any] = {
        key: sorted(values)[:32]
        for key, values in evidence.items()
        if values
    }
    if host_binding_hints:
        result["host_binding_hints"] = sorted(host_binding_hints)[:8]
        result["host_binding_sources"] = sorted(host_binding_sources)[:8]
    if structured_provenance:
        result["structured_provenance"] = [
            {"kind": kind, "source": source, "value": value}
            for kind, source, value in sorted(structured_provenance)
        ][:64]
    return result


def stable_identity_evidence_signature(
    evidence: Mapping[str, Any],
    *,
    device_id: object = None,
) -> str | None:
    """Return a stable signed binding for strong MAC-less observations.

    The signature is deliberately narrower than ``build_evidence_signature``:
    changing a port or adding a generic service must not create a new identity.
    Conversely, a bare refused connection, open port, OUI string, mDNS/SSDP
    category or arbitrary friendly name is never enough.  The accepted inputs
    are either a concrete structured model accompanied by structured maker/type
    proof, or a privacy-preserving NetBIOS/mDNS host token produced above.
    Hostnames are not globally unique, so the latter must also be scoped to the
    current opaque observation id. Two computers advertising the same default
    hostname therefore remain separate jobs and approvals.
    Product resolution remains subject to the stricter official-source and
    structured-model validators; this helper authorizes only queue binding.
    """

    if not isinstance(evidence, Mapping):
        return None

    raw_proofs = evidence.get("structured_provenance")
    proofs: list[dict[str, str]] = []
    if isinstance(raw_proofs, list):
        for raw in raw_proofs:
            if not isinstance(raw, Mapping):
                continue
            kind = str(raw.get("kind") or "").strip().casefold()
            source = str(raw.get("source") or "").strip().casefold()
            value = _safe_hint(raw.get("value"))
            if (
                kind in {"manufacturer", "model", "device_type"}
                and source in _STABLE_BINDING_PROOF_SOURCES
                and value
            ):
                proofs.append({"kind": kind, "source": source, "value": value})

    makers = sorted(
        {
            normalize_vendor_name(proof["value"])
            for proof in proofs
            if proof["kind"] == "manufacturer"
            and is_product_manufacturer(proof["value"])
        },
        key=str.casefold,
    )
    kinds = sorted(
        {
            normalized
            for proof in proofs
            if proof["kind"] == "device_type"
            and (normalized := _structured_type_proof("", proof["value"]))
            in DEVICE_TYPE_LABELS
            and normalized not in {"unknown", "web-device", "iot", "audio"}
        }
    )
    models = sorted(
        {
            proof["value"]
            for proof in proofs
            if proof["kind"] == "model"
            and (
                any(is_concrete_product_model(proof["value"], maker) for maker in makers)
                or is_concrete_product_model(proof["value"])
            )
        },
        key=str.casefold,
    )
    # A structured model code may itself carry a maintained vendor/category
    # family (for example RF* or Mac<generation>,<variant>).  Use the same
    # generic prefix registries as the core resolver; never add a one-household
    # or one-exact-model exception here.
    derived_makers = {
        normalize_vendor_name(vendor)
        for model in models
        if (vendor := vendor_from_model_prefix(model))
    }
    derived_kinds = {
        device_type
        for model in models
        for prefix, device_type in MODEL_PREFIX_DEVICE_TYPE
        if model.upper().startswith(prefix.upper())
        and device_type in DEVICE_TYPE_LABELS
        and device_type not in {"unknown", "web-device", "iot", "audio"}
    }
    makers = sorted({*makers, *derived_makers}, key=str.casefold)
    kinds = sorted({*kinds, *derived_kinds})
    if models and (makers or kinds):
        payload = {
            "models": models,
            "manufacturers": makers,
            "device_types": kinds,
            "model_sources": sorted(
                {proof["source"] for proof in proofs if proof["kind"] == "model"}
            ),
        }
        return f"hges1-{_digest('stable-identity-evidence', payload)}"

    host_tokens = sorted(
        {
            str(value).strip()
            for value in (evidence.get("host_binding_hints") or [])
            if re.fullmatch(r"hghost1-[0-9a-f]{64}", str(value).strip())
        }
    )
    host_sources = sorted(
        {
            str(value).strip().casefold()
            for value in (evidence.get("host_binding_sources") or [])
            if str(value).strip().casefold() in {"mdns", "netbios"}
        }
    )
    if host_tokens and host_sources:
        observation_id = str(device_id or "").strip()
        if not observation_id:
            return None
        return f"hges1-{_digest('stable-identity-evidence', {'hosts': host_tokens, 'sources': host_sources, 'observation_id': observation_id})}"
    return None


def blocked_binding_reason(
    network_scope_id: str | None,
    physical_mac: str | None,
    evidence: Mapping[str, Any] | None = None,
    *,
    device_id: object = None,
) -> str | None:
    # Import lazily so this service remains usable while ``app.storage`` is
    # selecting its concrete repository.  Approval must use the exact same
    # strong-scope and physical-MAC contract as the storage boundary; merely
    # having two non-empty strings is not a trustworthy binding.
    from ..storage.network_scope import is_strong_network_scope_id, normalized_physical_mac

    has_strong_scope = is_strong_network_scope_id(network_scope_id)
    has_physical_mac = normalized_physical_mac(physical_mac) is not None
    has_stable_evidence = (
        stable_identity_evidence_signature(evidence or {}, device_id=device_id)
        is not None
    )
    if not has_strong_scope and not (has_physical_mac or has_stable_evidence):
        return "STRONG_SCOPE_AND_PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED"
    if not has_strong_scope:
        return "STRONG_SCOPE_REQUIRED"
    if not (has_physical_mac or has_stable_evidence):
        return "PHYSICAL_MAC_OR_STABLE_EVIDENCE_REQUIRED"
    return None


def _specific_model(value: object, manufacturer: str) -> str:
    model = _safe_hint(value)
    if (
        model is None
        or model.casefold() in _GENERIC_MODEL_WORDS
        or not is_concrete_product_model(model, manufacturer)
        or contains_forbidden_device_name(model)
        or contains_non_product_identifier(model)
    ):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return model


def _source_reference(value: object) -> str:
    source = str(value or "").strip()
    if not source or len(source) > 512 or not _OPAQUE_SOURCE_RE.fullmatch(source):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    parsed = urlsplit(source)
    if parsed.scheme:
        if parsed.scheme.casefold() != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        host = parsed.hostname.casefold()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        try:
            if ipaddress.ip_address(host).is_private:
                raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        except ValueError:
            pass
    if _MAC_RE.search(source) or contains_private_network_identifier(source):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return source


def _source_matches_manufacturer(source: str, manufacturer: str) -> bool:
    return is_registered_official_product_source(source, manufacturer)


def source_matches_registered_official_domain(source: object, manufacturer: object) -> bool:
    """Return true only for an explicitly registered manufacturer domain.

    Manual approval and automated research share this boundary. Supporting a
    new manufacturer requires an explicit trust-registry entry; a brand-looking
    rented subdomain such as ``acme.github.io`` is never inferred as official.
    """

    try:
        safe_source = _source_reference(source)
    except IdentityEnrichmentError:
        return False
    return is_registered_official_product_source(safe_source, manufacturer)


def validate_identity_resolution(
    *,
    manufacturer: object,
    device_type: object,
    model: object,
    source_reference: object,
) -> dict[str, str]:
    maker = _safe_hint(manufacturer)
    kind = str(device_type or "").strip().casefold()
    if (
        maker is None
        or not is_product_manufacturer(maker)
        or kind not in DEVICE_TYPE_LABELS
        or kind in {"unknown", "web-device", "iot"}
        or contains_forbidden_device_name(maker)
        or contains_non_product_identifier(maker)
    ):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    normalized_maker = normalize_vendor_name(maker)
    specific_model = _specific_model(model, normalized_maker)
    source = _source_reference(source_reference)
    if not _source_matches_manufacturer(source, normalized_maker):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    model_vendor = vendor_from_text(specific_model)
    upper_model = specific_model.upper()
    if model_vendor is None:
        model_vendor = next(
            (
                vendor
                for prefix, vendor in sorted(
                    MODEL_PREFIX_VENDOR.items(), key=lambda item: len(item[0]), reverse=True
                )
                if upper_model.startswith(prefix.upper())
            ),
            None,
        )
    if model_vendor and normalize_vendor_name(model_vendor).casefold() != normalized_maker.casefold():
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    model_type = next(
        (
            expected_type
            for prefix, expected_type in sorted(
                MODEL_PREFIX_DEVICE_TYPE, key=lambda item: len(item[0]), reverse=True
            )
            if upper_model.startswith(prefix.upper())
        ),
        None,
    )
    if model_type and model_type != kind:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    parsed_source = urlsplit(source)
    if parsed_source.hostname:
        source_vendor = vendor_from_text(parsed_source.hostname.replace(".", " "))
        if source_vendor and normalize_vendor_name(source_vendor).casefold() != normalized_maker.casefold():
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    display_maker = VENDOR_KO.get(normalize_vendor_name(maker), maker)
    canonical_name = f"{display_maker} {DEVICE_TYPE_LABELS[kind]} ({specific_model})"
    if (
        contains_forbidden_device_name(canonical_name)
        or contains_non_product_identifier(canonical_name)
        or contains_private_network_identifier(canonical_name)
    ):
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return {
        "manufacturer": maker,
        "device_type": kind,
        "model": specific_model,
        "canonical_name": canonical_name[:96],
        "source_reference": source,
    }


def project_identity_enrichment_job(job: Mapping[str, Any]) -> dict[str, Any]:
    evidence = job.get("evidence")
    resolution = job.get("resolution")
    return {
        "job_id": str(job.get("job_id") or ""),
        "status": str(job.get("status") or ""),
        "blocked_reason": str(job.get("blocked_reason") or "") or None,
        "binding_ready": blocked_binding_reason(
            str(job.get("network_scope_id") or "") or None,
            str(job.get("physical_mac") or "") or None,
            evidence if isinstance(evidence, Mapping) else None,
            device_id=job.get("device_id"),
        )
        is None,
        "evidence": dict(evidence) if isinstance(evidence, Mapping) else {},
        "seen_count": int(job.get("seen_count") or 0),
        "first_seen_at": str(job.get("first_seen_at") or ""),
        "last_seen_at": str(job.get("last_seen_at") or ""),
        "updated_at": str(job.get("updated_at") or ""),
        "resolution": (
            {
                key: resolution.get(key)
                for key in ("manufacturer", "device_type", "model", "canonical_name")
                if resolution.get(key)
            }
            if isinstance(resolution, Mapping)
            else None
        ),
        "source_reference": str(job.get("source_reference") or "") or None,
        "resolution_provenance": (
            str(job.get("resolution_provenance") or "") or None
        ),
        "resolved_at": str(job.get("resolved_at") or "") or None,
    }


def manual_history_evidence(job_id: str) -> list[str]:
    return resolution_history_evidence(
        job_id,
        IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
    )


def resolution_history_evidence(job_id: str, provenance: str) -> list[str]:
    if provenance not in IDENTITY_RESOLUTION_PROVENANCES:
        raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
    return [f"identity-enrichment-job:{job_id}", f"official-source:{provenance}"]


def trusted_identity_resolution(
    history: Mapping[str, Any],
    job: Mapping[str, Any],
) -> dict[str, str] | None:
    """Verify persisted operator or official-web resolution provenance.

    Legacy reviewed rows have no explicit provenance column; they retain the
    original operator-reviewed meaning. Automated rows must carry the separate
    marker in both the signed job resolution and its matching history evidence.
    """

    if (
        history.get("identity_status") != "manual_resolved"
        or job.get("status") != "resolved"
        or not identity_job_key_matches(job)
        or not evidence_signature_matches(job.get("evidence") or {}, job.get("evidence_signature"))
        or not resolution_signature_matches(job)
    ):
        return None
    resolution = job.get("resolution")
    if not isinstance(resolution, Mapping):
        return None
    provenance = str(
        job.get("resolution_provenance")
        or resolution.get("resolution_provenance")
        or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
    )
    if provenance not in IDENTITY_RESOLUTION_PROVENANCES:
        return None
    if resolution.get("history_resolution_id") != history.get("resolution_id"):
        return None
    for field in ("manufacturer", "device_type", "model", "canonical_name"):
        if str(history.get(field) or "") != str(resolution.get(field) or ""):
            return None
    evidence = history.get("identity_evidence")
    if not isinstance(evidence, list) or any(
        required not in evidence
        for required in resolution_history_evidence(str(job.get("job_id") or ""), provenance)
    ):
        return None
    try:
        validated = validate_identity_resolution(
            manufacturer=resolution.get("manufacturer"),
            device_type=resolution.get("device_type"),
            model=resolution.get("model"),
            source_reference=job.get("source_reference"),
        )
    except IdentityEnrichmentError:
        return None
    if is_automated_identity_resolution_provenance(provenance):
        evidence_map = job.get("evidence")
        if not isinstance(evidence_map, Mapping):
            return None
        normalized_model = " ".join(str(validated["model"]).casefold().split())
        model_hints = {
            " ".join(str(value or "").casefold().split())
            for value in evidence_map.get("model_hints") or []
        }
        if normalized_model not in model_hints or not source_matches_registered_official_domain(
            validated["source_reference"],
            validated["manufacturer"],
        ):
            return None
    return {key: validated[key] for key in ("manufacturer", "device_type", "model", "canonical_name")}


def trusted_manual_resolution(
    history: Mapping[str, Any],
    job: Mapping[str, Any],
) -> dict[str, str] | None:
    resolution = job.get("resolution")
    provenance = str(
        job.get("resolution_provenance")
        or (
            resolution.get("resolution_provenance")
            if isinstance(resolution, Mapping)
            else None
        )
        or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
    )
    if provenance != IDENTITY_RESOLUTION_PROVENANCE_OPERATOR:
        return None
    return trusted_identity_resolution(history, job)
