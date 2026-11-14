"""사용자에게 보이는 기기 이름을 한 곳에서 결정한다.

탐색 과정의 단서(OUI, 포트, 임시 이름)는 실제 물품 이름이 아니다. 이 모듈은
확인된 제조사와 물품 종류가 함께 있을 때만 기기를 공개하고, 일반 제품은
``제조사 물품 종류 (모델명·품번)`` 형식으로 만든다. 컴퓨터는 LAN에서 모델을
제공하지 않는 경우가 많으므로 OUI와 SMB 응답으로 제조사·컴퓨터군만 검증된
경우에 한해 ``제조사 컴퓨터``로 공개한다.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
from ipaddress import ip_address, ip_network
import re
from typing import Any

from .device_identity import (
    DEVICE_TYPE_LABELS,
    VENDOR_KO,
    _is_family_hub_alias,
    _GENERIC_MANUFACTURERS,
    _GENERIC_MODELS,
    _SOFTWARE_RECEIVER_BRANDS,
    advertised_brands_conflict,
    advertised_models_conflict,
    brand_from_advertised,
    device_type_from_signals,
    is_concrete_product_model,
    model_from_advertised,
    normalize_vendor_name,
    strong_device_type_from_signals,
    verified_catalog_marker_identity,
    vendor_from_model_prefix,
    vendor_from_oui,
)


# 이 표현은 내부 탐색 데이터에도 남을 수 있지만, 공개 API와 UI에는 절대 보이면 안 된다.
FORBIDDEN_DEVICE_NAME_TERMS = (
    "웹 관리 기기",
    "제조사 미확인",
    "정체불명 기기",
    "알 수 없는 기기",
    "기기 후보",
    "확인 필요 기기",
    "임시 인터넷 신호",
    "확인되지 않은 신호",
    "현재 Wi-Fi 이웃 확인",
    "TCP 서비스 응답",
    "기기 정보 방송 응답",
    "연결된 장비",
    "서비스 응답",
    "미확인",
    "정체불명",
    "알 수 없는",
    "확인되지 않은",
    "임시 기기",
    "후보 기기",
    "unknown device",
    "unidentified device",
    "unverified device",
    "candidate device",
    "unresolved device",
    "temporary device",
    "generic device",
    "web-device",
    "web device",
    "iot device",
)

# The scanner needs a small amount of network state to explain whether the
# inspection ran on the resident's Wi-Fi.  It also sends aggregate counters so
# a missed-device report can be separated from an identity-enrichment delay.
# Discovery banners, chipset/OUI lookups, arbitrary notes, and addresses never
# cross this boundary.  Keep every diagnostic field on an allowlist.
_PUBLIC_NETWORK_INTERFACE_TYPES = frozenset({"wifi", "unknown"})
_SCAN_DIAGNOSTIC_FIELDS = (
    "subnet_host_count",
    "candidate_host_count",
    "requested_host_limit",
    "requested_port_count",
    "arp_entries_before_probe",
    "mdns_hosts",
    "mdns_raw_hosts",
    "ssdp_hosts",
    "onvif_hosts",
    "tcp_hosts",
    "tcp_responsive_hosts",
    "tcp_probe_completed_hosts",
    "arp_entries_after_probe",
    "arp_observation_hosts",
    "arp_stale_entries_suppressed",
    "neighbor_fresh_state_hosts",
    "neighbor_unverified_hosts",
    "wifi_network_socket_bind_attempts",
    "wifi_network_socket_bind_failures",
    "wifi_network_socket_bind_suppressed",
    "wifi_network_unbound_paths_skipped",
    "wifi_network_evidence_path_failures",
    # Privacy-safe identity-pipeline stage counts from Android.  These values
    # expose no MAC, hostname, manufacturer text, model text or device id.
    "physical_mac_hosts",
    "manufacturer_hint_hosts",
    "model_hint_hosts",
    "raw_observation_count",
    "observation_host_limit",
    "observation_overflow_events",
    "observation_hosts_dropped",
    "observation_hosts_evicted",
    "observation_receive_buffer_dropped",
    # Server-computed only.  It reveals no address, hostname or product data;
    # it tells the client that one or more observations were outside the
    # declared home subnet and therefore quarantined before storage.
    "out_of_subnet_observations_dropped",
    # Server-computed aggregate for local-hostname URL evidence removed before
    # any DNS resolution or HTTP request.  The observation itself is retained.
    "endpoint_evidence_quarantined",
)
_SCAN_DIAGNOSTIC_BOOLEAN_FIELDS = (
    "candidate_coverage_complete",
    "neighbor_proc_source_available_before",
    "neighbor_ip_source_available_before",
    "neighbor_source_available_before",
    "neighbor_proc_source_available_after",
    "neighbor_ip_source_available_after",
    "neighbor_source_available_after",
    "neighbor_probe_complete",
    "neighbor_presence_confirmed",
    "neighbor_coverage_complete",
    "candidate_stimulation_complete",
    "tcp_transport_complete",
    "wifi_network_socket_binding_required",
    "wifi_network_socket_binding_complete",
    # Server-side L2 augmentation was intentionally skipped because the
    # Android scan and this server could not prove that they share the same
    # gateway.  This is a privacy-safe aggregate flag; it contains no network
    # address, hostname or device identifier.
    "server_probe_l2_unverified",
    "tcp_scan_timed_out",
    # The native scanner stops accepting additional observations once its
    # bounded inventory buffer is full.  Preserve this aggregate completion
    # signal so the server can withhold a final score instead of presenting a
    # truncated scan as complete.
    "observation_limit_reached",
    "scan_partial",
)
_MAX_SCAN_DIAGNOSTIC_VALUE = 1_000_000


def is_self_observation(device: Mapping[str, Any] | None) -> bool:
    """Return whether an observation describes the phone running the scan.

    The native scanner adds explicit self markers so the server can keep the
    observation for diagnostics without counting the scanner itself as a
    household device.  This is deliberately signal-based; an IP address,
    port, or manufacturer alone must never hide a real device.
    """
    if not isinstance(device, Mapping):
        return False

    def normalized_values(key: str) -> set[str]:
        values = device.get(key) or []
        if isinstance(values, str):
            values = [values]
        return {str(value).strip().lower().replace("_", "-") for value in values if str(value).strip()}

    risk_signals = normalized_values("risk_signals")
    discovery_sources = normalized_values("discovery_sources")
    services = normalized_values("services")
    device_id = str(device.get("device_id") or "").strip().lower().replace("_", "-")
    return (
        "self-device" in risk_signals
        or "self" in discovery_sources
        or "self-device" in services
        or device_id in {"self", "self-device"}
    )

# OUI 등록자, 칩셋·모듈 회사, 소프트웨어 수신기 이름은 소비자가 이해할 물품 제조사가 아니다.
_NON_PRODUCT_BRANDS = {
    "espressif",
    "realtek",
    "seongji",
    "intel",
    "mediatek",
    "qualcomm",
    "broadcom",
    "microsoft",
    "librespot",
    "spotify",
}
_NON_PRODUCT_BRAND_TOKENS = tuple(_NON_PRODUCT_BRANDS) + (
    "espressif systems",
    "realtek semiconductor",
    "seongji electronics",
    "broadcom limited",
    "qualcomm incorporated",
    "mediatek incorporated",
    "칩셋",
    "모듈 제조사",
)
_NON_PRODUCT_MODEL_TOKENS = (
    "esp32",
    "esp8266",
    "rtl",
    "realtek",
    "mediatek",
    "qualcomm",
    "broadcom",
    "chipset",
    "칩셋",
    "module",
)

# A web server banner is useful private evidence for CVE matching, but it is
# never a household-product model.  In particular, do not turn a server name
# (or its version) into a canonical device label merely because it is not in a
# chipset deny-list.
_SERVER_BANNER_MODEL_TOKENS = (
    "apache",
    "boa",
    "busybox",
    "caddy",
    "httpd",
    "lighttpd",
    "nginx",
    "openresty",
    "server",
    "webs",
    "x-powered-by",
)
_SERVER_BANNER_FINGERPRINT_PREFIXES = (
    "http-server:",
    "http-powered-by:",
    "ssdp-server:",
)

# 일부 mDNS 서비스 형식은 특정 제품 생태계가 소유·광고하는 식별자다. 이 값은
# 포트·서버 배너·OUI가 아니라 기기가 스스로 내보낸 서비스 타입이므로, 정확히
# 일치할 때만 제조사 근거로 쓴다. 부분 문자열이나 일반 오디오 서비스는 허용하지
# 않는다.
_BRANDED_SERVICE_MANUFACTURERS = {
    "mdns-type:._sonos._tcp": "Sonos",
}

# A narrow code-to-category table is retained for structured observations and
# legacy notification sanitization.  It never grants manufacturer/model
# provenance by itself.
_LEGACY_CATALOG_MODEL_TYPES: dict[str, tuple[tuple[str, str], ...]] = {
    "Samsung": (("SM-T", "tablet"), ("SM-", "phone"), ("RF", "fridge"), ("QN", "tv"), ("UN", "tv"), ("WF", "iot"), ("WW", "iot"), ("RB", "fridge"), ("FAMILY", "fridge")),
    "LG": (("OLED", "tv"), ("LM", "tv"), ("NANO", "tv"), ("GC", "fridge")),
    "Apple": (("APPLETV", "tv"), ("IPHONE", "phone"), ("IPAD", "phone"), ("HOMEPOD", "speaker")),
    "Google": (("CHROMECAST", "tv"), ("NEST", "speaker")),
    "TP-Link": (("ARCHER", "router"), ("DECO", "router"), ("TL-", "router")),
    "ASUS": (("RT-", "router"), ("DSL-", "router"), ("ROG", "router")),
    "Netgear": (("R", "router"), ("NIGHTHAWK", "router"), ("ORBI", "router")),
    "iptime(EFM)": (("A", "router"), ("B", "router"), ("BE", "router"), ("C", "router"), ("N", "router"), ("NAS", "nas"), ("T", "router"), ("X", "router")),
    "Hikvision": (("DS-", "camera"),),
    "Dahua": (("DH-", "camera"), ("IPC-", "camera"), ("NVR", "nas")),
    "Sony": (("BRAVIA", "tv"), ("KD-", "tv"), ("XR-", "tv")),
    "Xiaomi": (("MI", "iot"), ("MJSX", "iot"), ("ROBOROCK", "robot")),
}
_IPV4_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Za-z_.-])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9A-Za-z_.-])"
)
_MAC_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
)
_LEGACY_DASHED_DEVICE_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:dev|device)-"
    r"((?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})-"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2}))(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# Do not try to encode every valid IPv6 spelling in a regular expression.
# In particular, the previous expression missed compressed literals such as
# ``fe80::1`` and ``::1``.  Extract conservative hexadecimal/colon tokens and
# let ``ip_address`` make the final decision below.
_IPV6_CANDIDATE_RE = re.compile(r"[0-9A-Fa-f:.]+")
_PRIVATE_PUBLIC_FIELD_KEYS = frozenset(
    {"ip_address", "mac_address", "source_ip", "source_mac", "client_ip", "client_mac"}
)
# IEEE OUI 데이터에는 가정용 완제품 제조사가 아닌 등록기관 표기가 일부 있다.
# 구 DB·스캐너 필드·자유 형식 조치 문구로도 들어올 수 있으므로 OUI 조회 단계에만
# 두지 않고 다른 공개 표시 규칙과 같은 경계에서 판별한다.
_NON_PRODUCT_REGISTRATION_PHRASES = (
    "ieee registration authority",
    "registration authority",
    "registered authority",
    "organizationally unique identifier",
    "organizationally unique id",
    "mac address block",
    "individual address block",
    "extended unique identifier",
    "oui registration",
    "oui 등록기관",
    "oui 등록 기관",
    "등록기관",
    "등록 기관",
)
_NON_PRODUCT_REGISTRATION_EXACT = frozenset(
    {
        "private",
        "ieee",
        "oui",
        "iana",
        "ma-l",
        "ma-m",
        "ma-s",
        "oui 확인 필요",
        "private oui",
        "private address",
    }
)
# 단순 부분문자열 대신 토큰 경계를 쓴다. 실제 모델명에 ``ma`` 같은 글자가 있다고
# IEEE MA-* 등록 등급과 우연히 닮았다는 이유로 제거하면 안 된다.
_NON_PRODUCT_REGISTRATION_TOKEN = re.compile(
    r"(?<![0-9a-z_])(?:ieee|oui|iana|ma[-\s]?[lms])(?![0-9a-z_])",
    re.IGNORECASE,
)
_PRIVATE_REGISTRATION_LABEL = re.compile(
    r"(?<![0-9a-z_])private(?:[\s:/-]+(?:oui|registration(?:\s+authority)?|address(?:\s+block)?|mac|ieee|iana|ma[-\s]?[lms]|등록(?:기관)?|기기|device))(?![0-9a-z_])",
    re.IGNORECASE,
)
# web-device와 일반 IoT 신호는 물품 종류를 확정하는 근거가 될 수 없다.
_PUBLIC_DEVICE_TYPES = frozenset(
    key for key in DEVICE_TYPE_LABELS if key not in {"web-device", "iot", "audio"}
)

# A verified computer may expose a useful local host name through NetBIOS or
# mDNS even when it does not expose a board/model number.  This is a display
# suffix only: it never proves a product identity and is never used for OUI,
# history, or device-id binding.  Keep the parser deliberately narrow so raw
# service records and MAC-address-bearing mDNS instance names cannot leak into
# the resident-facing label.
_PUBLIC_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_PUBLIC_HOSTNAME_HEX_IDENTIFIER_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_OBSERVATION_SUFFIX_RE = re.compile(r"^[0-9A-F]{6}$")
_HOSTNAME_MAC_SUFFIX_RE = re.compile(
    r"\s*\[[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\]\s*"
)
_HOSTNAME_SERVICE_SUFFIX_RE = re.compile(
    r"\._(?:workstation|services?)\._(?:tcp|udp)\.local$", re.IGNORECASE
)


def _sanitized_observed_host_name(device: Mapping[str, Any]) -> str | None:
    """Return only the bounded host token from current NetBIOS/mDNS evidence."""

    candidates: list[tuple[int, str]] = []
    for raw in _fingerprints(device):
        value = _clean(raw)
        lowered = value.casefold()
        if lowered.startswith("netbios-name:"):
            candidate = value.split(":", 1)[1].strip()
            priority = 0
        elif lowered.startswith("mdns-name:"):
            candidate = value.split(":", 1)[1].strip()
            priority = 1
        else:
            continue

        candidate = _HOSTNAME_MAC_SUFFIX_RE.sub("", candidate)
        candidate = _HOSTNAME_SERVICE_SUFFIX_RE.sub("", candidate).strip().strip(".")
        # mDNS instance names may carry a service path after a readable host;
        # never expose that protocol suffix as if it were a computer name.
        if ".local" in candidate.casefold():
            candidate = candidate.split(".", 1)[0]
        candidate = candidate.strip()
        if not candidate or not _PUBLIC_HOSTNAME_RE.fullmatch(candidate):
            continue
        if (
            candidate.casefold() in {"workstation", "services", "local", "unknown"}
            or _PUBLIC_HOSTNAME_HEX_IDENTIFIER_RE.fullmatch(candidate)
            or contains_forbidden_device_name(candidate)
            or contains_non_product_identifier(candidate)
            or contains_private_network_identifier(candidate)
        ):
            continue
        candidates.append((priority, candidate.casefold()))

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], len(item[1]), item[1]))
    return candidates[0][1]


def _public_computer_host_name(device: Mapping[str, Any]) -> str | None:
    """Return a current, sanitized host name for a verified computer family.

    NetBIOS/mDNS names are useful to a resident (for example ``desktop-home``),
    but they are not manufacturer or model evidence.  Only a computer that
    already passed the family-identity contract may receive this suffix.
    """

    if (
        _clean(device.get("device_type")) != "computer"
        or device.get("identity_family_verified") is not True
        or _clean(device.get("identity_status")) not in {"resolved", "manual_resolved"}
    ):
        return None
    return _sanitized_observed_host_name(device)
_PUBLIC_DEVICE_COPY_FIELDS = (
    # Keep this list aligned with the resident/guardian Device contract.  A
    # legacy scan snapshot can contain arbitrary extra values, so a copy-and-
    # remove approach is unsafe even when those values look harmless.
    "device_id",
    "home_id",
    "online",
    "last_seen",
    "default_credentials",
    "encryption",
    "discovery_sources",
    "scan_source",
    "confidence",
    "security_score",
    "risk_level",
    "risk_summary",
    "recommended_actions",
    "alias",
    "identity_status",
    "identity_evidence",
    "identity_family_verified",
)
_PUBLIC_NOTIFICATION_TEXT_FIELDS = ("title", "message", "description", "action_guide")
_NOTIFICATION_DEVICE_LABEL_FIELDS = frozenset(
    {"device_name", "device_label", "display_name", "canonical_name", "guessed_product", "name"}
)
_PUBLIC_NOTIFICATION_DEVICE_TYPE_KEYS = {
    **{label.casefold(): key for key, label in DEVICE_TYPE_LABELS.items()},
    **{key.casefold(): key for key in DEVICE_TYPE_LABELS},
}
_PUBLIC_NOTIFICATION_DEVICE_LABEL_RE = re.compile(
    rf"(?<![0-9A-Za-z가-힣])"
    rf"(?P<brand>[0-9A-Za-z가-힣][0-9A-Za-z가-힣._&-]{{0,63}})\s+"
    rf"(?P<device_type>{'|'.join(re.escape(label) for label in sorted(_PUBLIC_NOTIFICATION_DEVICE_TYPE_KEYS, key=len, reverse=True))})\s*"
    rf"\((?P<model>[^()\r\n]{{1,128}})\)",
    re.IGNORECASE,
)
_REDACTED = object()
_TRUSTED_MANUAL_PRESENTATION_PROOF = object()
_PUBLIC_IDENTITY_HISTORY_STATUSES = frozenset(
    {"resolved", "manual_resolved", "enriching", "unresolved"}
)
_PUBLIC_HISTORY_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?"
)


@dataclass(frozen=True)
class DevicePresentation:
    visible: bool
    canonical_name: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    device_type: str | None = None


def bind_trusted_manual_identity(device: Mapping[str, Any]) -> dict[str, Any]:
    """Bind a job-validated manual resolution to this in-process projection.

    Repositories call this only after ``trusted_manual_resolution`` has checked
    the signed enrichment job, matching history row, physical MAC and network
    scope.  The object sentinel cannot arrive through JSON or a legacy database
    row, so a copied ``manual_resolved`` string is never sufficient proof.
    """
    result = dict(device)
    result["_trusted_manual_presentation_proof"] = _TRUSTED_MANUAL_PRESENTATION_PROOF
    return result


def contains_forbidden_device_name(value: object) -> bool:
    text = str(value or "").strip().lower()
    return bool(text) and any(term.lower() in text for term in FORBIDDEN_DEVICE_NAME_TERMS)


def _clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def contains_non_product_identifier(value: object) -> bool:
    """Return whether text identifies a chipset, module, or software vendor rather than a household product."""
    normalized = _clean(value).lower()
    if not normalized:
        return False
    compact = "".join(character for character in normalized if character.isalnum())
    has_chipset_or_module_identifier = any(
        token in normalized or "".join(character for character in token if character.isalnum()) in compact
        for token in _NON_PRODUCT_BRAND_TOKENS + _NON_PRODUCT_MODEL_TOKENS
    )
    if has_chipset_or_module_identifier:
        return True
    if normalized in _NON_PRODUCT_REGISTRATION_EXACT:
        return True
    if any(phrase in normalized for phrase in _NON_PRODUCT_REGISTRATION_PHRASES):
        return True
    return bool(
        _NON_PRODUCT_REGISTRATION_TOKEN.search(normalized)
        or _PRIVATE_REGISTRATION_LABEL.search(normalized)
    )


def legacy_device_id_ip_address(value: object) -> str | None:
    """Return the IPv4 address embedded in an old ``dev-192-168-...`` ID.

    Earlier app versions made an otherwise private LAN address part of a
    public device identifier. This parser is intentionally strict: product
    model numbers are not identifiers, and only the legacy device-ID shape is
    accepted.
    """
    match = _LEGACY_DASHED_DEVICE_ID_RE.search(_clean(value))
    if match is None:
        return None
    candidate = match.group(1).replace("-", ".")
    try:
        parsed = ip_address(candidate)
    except ValueError:
        return None
    return str(parsed) if parsed.version == 4 else None


def _contains_ipv6_address(value: object) -> bool:
    """Return whether text contains a syntactically valid IPv6 literal.

    ``ip_address`` handles all compressed and mixed IPv6 forms consistently.
    Keeping token extraction separate prevents a partial match from treating a
    product code as an address while still catching literals embedded in a
    legacy ID, URL, or notification sentence.
    """
    for match in _IPV6_CANDIDATE_RE.finditer(_clean(value)):
        candidate = match.group(0)
        if ":" not in candidate:
            continue
        try:
            parsed = ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == 6:
            return True
    return False


def _device_id_contains_private_network_identifier(value: object) -> bool:
    text = _clean(value)
    return bool(
        text
        and (
            legacy_device_id_ip_address(text) is not None
            or _IPV4_ADDRESS_RE.search(text)
            or _contains_ipv6_address(text)
            or _MAC_ADDRESS_RE.search(text)
        )
    )


def public_device_id(device_id: object, home_id: object | None = None) -> str:
    """Return a stable public-safe device identifier.

    New observations already use an opaque ID in storage. For a legacy row
    whose ID contains an IP or MAC address, expose a deterministic digest
    instead. The storage repositories resolve that digest back to the legacy
    row for detail and alias operations, so this does not break the mobile API
    contract.
    """
    raw_id = _clean(device_id)
    if not raw_id or not _device_id_contains_private_network_identifier(raw_id):
        return raw_id
    scope = _clean(home_id) or "default-home"
    digest_input = f"home-guardian-public-device-id:v1:{scope}:{raw_id}"
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:24]
    return f"device-{digest}"


def contains_private_network_identifier(value: object) -> bool:
    """Return whether text contains a literal network address that is never public device text."""
    text = _clean(value)
    return bool(
        text
        and (
            _IPV4_ADDRESS_RE.search(text)
            or _MAC_ADDRESS_RE.search(text)
            or _contains_ipv6_address(text)
            or legacy_device_id_ip_address(text) is not None
        )
    )


def is_safe_device_alias(value: object) -> bool:
    return (
        not contains_forbidden_device_name(value)
        and not contains_non_product_identifier(value)
        and not contains_private_network_identifier(value)
    )


def _is_product_brand(value: str | None) -> bool:
    normalized = _clean(value)
    if not normalized:
        return False
    lowered = normalized.lower()
    return (
        lowered not in _GENERIC_MANUFACTURERS
        and lowered not in _SOFTWARE_RECEIVER_BRANDS
        and not contains_non_product_identifier(normalized)
    )


def _is_product_model(value: str | None, manufacturer: str | None = None) -> bool:
    normalized = _clean(value)
    lowered = normalized.lower()
    if (
        not normalized
        or lowered in _GENERIC_MODELS
        or lowered in _SOFTWARE_RECEIVER_BRANDS
        or not is_concrete_product_model(normalized, manufacturer)
    ):
        return False
    if contains_forbidden_device_name(normalized) or contains_non_product_identifier(normalized):
        return False
    if contains_private_network_identifier(normalized):
        return False
    if any(token in lowered for token in _SERVER_BANNER_MODEL_TOKENS):
        return False
    # A slash-version form is a server/firmware identifier unless it was
    # independently advertised as a product model by a structured protocol.
    if re.fullmatch(r"[a-z][a-z0-9._-]*/v?\d+(?:\.\d+){0,4}[a-z0-9._-]*", lowered):
        return False
    return True


def _fingerprints(device: dict[str, Any]) -> list[str]:
    return [_clean(value) for value in (device.get("fingerprints") or []) if _clean(value)]


def _is_server_banner_value(value: str | None, fingerprints: list[str]) -> bool:
    normalized = _clean(value)
    lowered = normalized.lower()
    if not normalized:
        return False
    if any(token in lowered for token in _SERVER_BANNER_MODEL_TOKENS):
        return True
    return any(
        fingerprint.lower().startswith(prefix) and _clean(fingerprint[len(prefix) :]).lower() == lowered
        for fingerprint in fingerprints
        for prefix in _SERVER_BANNER_FINGERPRINT_PREFIXES
    )


def _advertised_model(
    device: dict[str, Any],
    fingerprints: list[str],
    manufacturer: str | None = None,
) -> str | None:
    del device
    if advertised_models_conflict(fingerprints):
        return None
    value = model_from_advertised(fingerprints)
    return (
        value
        if _is_product_model(value, manufacturer)
        and not _is_server_banner_value(value, fingerprints)
        else None
    )


def _advertised_brand_key(device: dict[str, Any], fingerprints: list[str]) -> str | None:
    del device
    if advertised_brands_conflict(fingerprints):
        return None
    branded_service_manufacturer = next(
        (
            manufacturer
            for fingerprint in fingerprints
            if (manufacturer := _BRANDED_SERVICE_MANUFACTURERS.get(fingerprint.lower())) is not None
        ),
        None,
    )
    advertised_brand = brand_from_advertised(fingerprints)
    if advertised_brand and branded_service_manufacturer:
        if normalize_vendor_name(advertised_brand) != normalize_vendor_name(branded_service_manufacturer):
            return None
    value = advertised_brand or branded_service_manufacturer
    if not _is_product_brand(value):
        return None
    normalized = normalize_vendor_name(str(value))
    return normalized if _is_product_brand(normalized) else None


def _catalog_model_matches(model: str | None, prefix: str) -> bool:
    if not is_concrete_product_model(model):
        return False
    normalized = _clean(model).upper().replace("_", "")
    normalized_prefix = prefix.upper().replace("_", "")
    if not normalized.startswith(normalized_prefix):
        return False
    compact = "".join(character for character in normalized if character.isalnum())
    return len(compact) >= 4 and any(character.isdigit() for character in compact)


def _catalog_device_type(brand_key: str | None, model: str | None) -> str | None:
    if not brand_key or not model:
        return None
    for prefix, device_type in _LEGACY_CATALOG_MODEL_TYPES.get(brand_key, ()):
        if _catalog_model_matches(model, prefix):
            return device_type
    return None


def _verified_product_identity(device: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return a public brand/model only when structured evidence corroborates it.

    Raw request fields are retained internally for merge/CVE work, but they do
    not become public identity merely because they are syntactically harmless.
    Legacy raw fields and discovery-source strings are deliberately excluded.
    They can remain private enrichment facts, but only structured manufacturer
    and model advertisements may reach this path.
    """
    fingerprints = _fingerprints(device)
    if advertised_brands_conflict(fingerprints) or advertised_models_conflict(fingerprints):
        return None, None
    advertised_brand = _advertised_brand_key(device, fingerprints)
    advertised_model = _advertised_model(device, fingerprints, advertised_brand)
    raw_brand = _clean(device.get("manufacturer"))
    model = advertised_model

    brand_key: str | None = advertised_brand
    if brand_key is None and model:
        inferred = vendor_from_model_prefix(model)
        if inferred and _is_product_brand(inferred):
            brand_key = normalize_vendor_name(inferred)
    # A structured manufacturer can be public without an advertised model;
    # however, a raw model cannot hitch a ride on it unless it was corroborated.
    if brand_key and raw_brand and advertised_brand:
        normalized_raw = normalize_vendor_name(raw_brand)
        if normalized_raw != advertised_brand:
            # The device advertised a different manufacturer.  Keep the
            # advertised value and never reuse the conflicting raw model.
            model = advertised_model

    if not brand_key:
        return None, None
    return brand_key, model


def _trusted_manual_product_identity(
    device: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Return a product only for an in-process, job-validated manual proof."""
    if (
        _clean(device.get("identity_status")) != "manual_resolved"
        or device.get("_trusted_manual_presentation_proof")
        is not _TRUSTED_MANUAL_PRESENTATION_PROOF
    ):
        return None
    raw_brand = _clean(device.get("manufacturer"))
    brand_key = normalize_vendor_name(raw_brand) if _is_product_brand(raw_brand) else ""
    model = _clean(device.get("model"))
    device_type = _clean(device.get("device_type"))
    if (
        not brand_key
        or not _is_product_model(model, brand_key)
        or device_type not in _PUBLIC_DEVICE_TYPES
    ):
        return None
    return brand_key, model, device_type


def _catalog_marked_product_identity(
    device: dict[str, Any],
) -> tuple[str, str, str] | None:
    """Return a product only after the persisted exact marker is revalidated."""
    exact = verified_catalog_marker_identity(device)
    if exact is None:
        return None
    brand_key = normalize_vendor_name(_clean(exact.get("manufacturer")))
    model = _clean(exact.get("model"))
    device_type = _clean(exact.get("device_type"))
    if (
        not _is_product_brand(brand_key)
        or not _is_product_model(model, brand_key)
        or device_type not in _PUBLIC_DEVICE_TYPES
    ):
        return None
    return brand_key, model, device_type


def _has_verified_explicit_type(device: dict[str, Any]) -> bool:
    """Accept an explicit type only when it has more evidence than a port number or a scanner placeholder."""
    fingerprints = _fingerprints(device)
    services = [str(value) for value in (device.get("services") or [])]
    if strong_device_type_from_signals(fingerprints, services):
        return True

    sources = {_clean(value).lower() for value in (device.get("discovery_sources") or [])}
    current_type = _clean(device.get("device_type"))
    ports = {int(port) for port in (device.get("open_ports") or []) if str(port).isdigit()}
    signal_text = " ".join([*fingerprints, *services]).lower()

    # A protocol name by itself does not identify a household product.  Only
    # protocols whose protocol contract identifies the category are sufficient:
    # ONVIF / WS-Discovery for cameras, and SMB's paired ports for computers.
    # Generic mDNS, SSDP and an arbitrary web port remain internal evidence only.
    if current_type == "camera" and sources.intersection({"onvif", "ws-discovery"}):
        return True
    if current_type == "computer" and {139, 445}.intersection(ports):
        return True
    if current_type == "router" and (
        "internetgatewaydevice" in signal_text or "wanconnectiondevice" in signal_text
    ):
        return True
    if current_type in {"audio", "speaker"} and "_sonos._tcp" in signal_text:
        return True

    brand_key, model = _verified_product_identity(device)
    if not brand_key or not model:
        return False
    inferred_type = device_type_from_signals(fingerprints, services, sorted(ports))
    if inferred_type == current_type and inferred_type in _PUBLIC_DEVICE_TYPES:
        return True
    return _catalog_device_type(brand_key, model) == current_type


def _resolve_public_device_type(device: dict[str, Any]) -> str | None:
    current = _clean(device.get("device_type"))
    fingerprints = _fingerprints(device)
    services = [str(value) for value in (device.get("services") or [])]
    inferred = strong_device_type_from_signals(fingerprints, services)
    if inferred in _PUBLIC_DEVICE_TYPES:
        return inferred
    if current in _PUBLIC_DEVICE_TYPES and _has_verified_explicit_type(device):
        return current
    return None


def _verified_family_computer_identity(device: dict[str, Any]) -> tuple[str, str] | None:
    """Return a model-less computer family only after independent OUI proof.

    A computer may not expose a board model over the LAN.  The public contract
    can still show the real manufacturer and ``컴퓨터`` family when the resolver
    marked it family-verified, the host answered SMB, and the observed MAC OUI
    independently agrees with the stored manufacturer.  This prevents a raw
    client string or a bare port guess from becoming a product label.
    """
    if (
        _clean(device.get("device_type")) != "computer"
        or _clean(device.get("model"))
        or device.get("identity_family_verified") is not True
        or _clean(device.get("identity_status")) not in {"resolved", "manual_resolved"}
        or not _has_verified_explicit_type(device)
    ):
        return None
    raw_brand = _clean(device.get("manufacturer"))
    if not _is_product_brand(raw_brand):
        return None
    oui_brand = vendor_from_oui(_clean(device.get("mac_address")))
    evidence = {
        _clean(value)
        for value in (device.get("identity_evidence") or [])
        if _clean(value)
    }
    fingerprints = _fingerprints(device)
    # A fresh Android scan can prove SMB/NetBIOS presence while Android 11
    # withholds the gateway/host MAC.  In that case the repository may attach
    # an opaque, server-verified historical-family marker.  It is narrower than
    # trusting a raw manufacturer field and survives storage as explicit
    # provenance labels, so the public card still cannot be forged by a client.
    trusted_history_family = (
        "서버에 이전에 확인된 제품 정보" in evidence
        and any(value.startswith("server-history:verified-family") for value in fingerprints)
    )
    if not oui_brand and not trusted_history_family:
        return None
    raw_display = VENDOR_KO.get(normalize_vendor_name(raw_brand), normalize_vendor_name(raw_brand))
    oui_display = (
        VENDOR_KO.get(normalize_vendor_name(oui_brand), normalize_vendor_name(oui_brand))
        if oui_brand
        else raw_display
    )
    if not raw_display or raw_display.casefold() != oui_display.casefold():
        return None
    return normalize_vendor_name(oui_brand or raw_brand), "computer"


def _verified_family_appliance_identity(device: dict[str, Any]) -> tuple[str, str, str] | None:
    """Return a server-verified Family Hub appliance family identity.

    This is the presentation counterpart to the server resolver.  A direct
    ``Family Hub`` string is not enough: the row must be resolved by the
    server and either carry the repository history marker (sleeping appliance)
    or the device's structured ``getInfo`` proof (first scan in any network).
    The returned model is the product family label, so a missing retail part
    number cannot be mistaken for one.
    """
    if (
        _clean(device.get("device_type")) != "fridge"
        or _clean(device.get("identity_status")) not in {"resolved", "manual_resolved"}
        or device.get("identity_family_verified") is not True
    ):
        return None
    raw_brand = _clean(device.get("manufacturer"))
    normalized_brand = normalize_vendor_name(raw_brand)
    # Persisted rows from older resolver versions used the resident-facing
    # Korean label in ``manufacturer``.  It is still the same Samsung brand,
    # but ``normalize_vendor_name`` intentionally maps only registry/English
    # strings.  Accept the exact display-label round trip here; never accept a
    # fuzzy substring or arbitrary localized value.
    if normalized_brand.casefold() != "samsung" and raw_brand.casefold() == VENDOR_KO["Samsung"].casefold():
        normalized_brand = "Samsung"
    if normalized_brand.casefold() != "samsung":
        return None
    fingerprints = _fingerprints(device)
    has_history_proof = any(
        value.startswith("server-history:verified-familyhub") for value in fingerprints
    )
    has_current_getinfo_proof = any(
        value.casefold() == "spotify-getinfo-done" for value in fingerprints
    )
    if not (has_history_proof or has_current_getinfo_proof):
        return None
    model = _clean(device.get("model"))
    if model and not _is_family_hub_alias(model):
        return None
    return normalized_brand, "Family Hub", "fridge"


def build_device_presentation(device: dict[str, Any]) -> DevicePresentation:
    """탐색 결과를 사용자에게 공개할 수 있는지와 표준 표시명을 계산한다."""
    if bool(device.get("is_phantom")) or bool(device.get("is_unresolved")):
        return DevicePresentation(visible=False)

    family_appliance_identity = _verified_family_appliance_identity(device)
    family_identity = _verified_family_computer_identity(device)
    trusted_identity = (
        _trusted_manual_product_identity(device)
        or _catalog_marked_product_identity(device)
    )
    if family_appliance_identity is not None:
        brand_key, model, device_type = family_appliance_identity
    elif family_identity is not None:
        brand_key, device_type = family_identity
        model = ""
    elif trusted_identity is not None:
        brand_key, model, device_type = trusted_identity
    else:
        device_type = _resolve_public_device_type(device)
        brand_key, model = _verified_product_identity(device)
    manufacturer = VENDOR_KO.get(brand_key, brand_key) if brand_key else None

    # 제조사·품번을 확인하지 못하면 종류만으로는 공개하지 않는다.  ONVIF,
    # AirPlay, SSDP 같은 프로토콜은 탐지 근거이지 제품명/품목 확정 근거가
    # 아니므로 '카메라', '오디오 기기' 같은 오인 표기를 만들지 않는다.
    if not device_type:
        return DevicePresentation(visible=False)
    # Exact consumer products still require a concrete model/part number.  The
    # only model-less exception is the independently verified computer family
    # above; it is never used for appliances, cameras, audio, or generic IoT.
    if not manufacturer or (
        not family_identity
        and not family_appliance_identity
        and (not model or not _is_product_model(model, brand_key))
    ):
        return DevicePresentation(visible=False)
    type_label = DEVICE_TYPE_LABELS[device_type]
    base = f"{manufacturer} {type_label}"
    canonical_name = f"{base} ({model})" if model else base
    # The family contract intentionally permits a model-less computer.  When
    # that same verified row also carries a current NetBIOS/mDNS host name,
    # retain the name the resident recognizes without treating it as a model.
    if family_identity is not None:
        host_name = _public_computer_host_name(device)
        if host_name:
            canonical_name = f"{canonical_name} - {host_name}"
    return DevicePresentation(
        visible=True,
        canonical_name=canonical_name,
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
    )


def apply_device_presentation(device: dict[str, Any]) -> dict[str, Any] | None:
    """공개 가능한 표준 필드만 가진 기기 객체를 반환한다. 근거 부족 신호는 ``None``이다."""
    presentation = build_device_presentation(device)
    if not presentation.visible or not presentation.canonical_name:
        return None

    result = {
        field: device[field]
        for field in _PUBLIC_DEVICE_COPY_FIELDS
        if field in device
    }
    alias = _clean(device.get("alias"))
    # 별칭은 사용자가 직접 정한 이름만 사용한다. 기본 이름은 위치를 추정하지 않는다.
    result["name"] = alias if alias and is_safe_device_alias(alias) else presentation.canonical_name
    if alias and is_safe_device_alias(alias):
        result["alias"] = alias
    elif alias:
        result.pop("alias", None)
    result["canonical_name"] = presentation.canonical_name
    result["manufacturer"] = presentation.manufacturer or ""
    result["model"] = presentation.model or ""
    result["device_type"] = presentation.device_type or ""
    result["is_resolved"] = True
    if "device_id" in result:
        result["device_id"] = public_device_id(result.get("device_id"), result.get("home_id"))
    # These values are useful for server-side scoring but do not help a resident decide what
    # to do. Keep the public schema stable without forwarding protocol/banner internals.
    result["open_ports"] = []
    result["services"] = []
    result["firmware"] = ""
    result["vulnerabilities"] = _public_vulnerabilities(device.get("vulnerabilities"))
    result["risk_explanations"] = _public_risk_explanations(device.get("risk_explanations"))
    return sanitize_public_payload(result)


def _verified_finding_product_clue(device: dict[str, Any]) -> DevicePresentation:
    """Return a clue only when manufacturer, model and type have provenance.

    An unresolved row can contain friendly names, an OUI registrant, raw
    scanner fields, or a resolver candidate.  None of those values proves a
    household product.  A finding may carry a product clue only when the
    device advertised both manufacturer and model through structured protocol
    fields and its category is independently supported by a strong protocol
    signal or the bounded manufacturer/model catalog.

    This helper never promotes the observation to ``devices[]``.  That state
    transition remains the identity resolver's responsibility.
    """
    fingerprints = _fingerprints(device)
    brand_key = _advertised_brand_key(device, fingerprints)
    model = _advertised_model(device, fingerprints, brand_key)
    if not brand_key or not model:
        return DevicePresentation(visible=False)

    services = [str(value) for value in (device.get("services") or [])]
    device_type = strong_device_type_from_signals(fingerprints, services)
    if device_type not in _PUBLIC_DEVICE_TYPES:
        device_type = _catalog_device_type(brand_key, model)
    if device_type not in _PUBLIC_DEVICE_TYPES:
        # The exact maker and model above came from structured fields emitted
        # by the endpoint itself.  For an unresolved *clue* (never a resolved
        # inventory product), retain the scanner's bounded category only when
        # that same observation came through a structured discovery protocol.
        # This keeps a self-advertised ``Samsung / XYZ-9000 / fridge`` clue in
        # the automatic research queue without turning a TCP port, OUI or
        # friendly name into a product type.
        reported_type = _clean(device.get("device_type"))
        structured_sources = {
            _clean(value).casefold()
            for value in (device.get("discovery_sources") or [])
            if _clean(value)
        }
        if reported_type in _PUBLIC_DEVICE_TYPES and structured_sources.intersection(
            {
                "airplay",
                "googlecast",
                "http",
                "mdns",
                "onvif",
                "server-protocol-probe",
                "spotify-connect",
                "spotify-getinfo",
                "ssdp",
                "upnp",
                "ws-discovery",
            }
        ):
            device_type = reported_type
    if device_type not in _PUBLIC_DEVICE_TYPES:
        return DevicePresentation(visible=False)

    manufacturer = VENDOR_KO.get(brand_key, brand_key)
    type_label = DEVICE_TYPE_LABELS.get(device_type)
    if not manufacturer or not type_label:
        return DevicePresentation(visible=False)
    return DevicePresentation(
        visible=True,
        canonical_name=f"{manufacturer} {type_label} ({model})",
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
    )


_PUBLIC_FINDING_EVIDENCE_LABELS = {
    "기기 이름·서비스 광고": "기기가 보낸 네트워크 정보",
    "네트워크 기기 설명": "기기가 보낸 네트워크 정보",
    "카메라 응답 정보": "기기가 보낸 네트워크 응답",
    "공유기가 알려준 기기 이름": "공유기가 알려준 연결 정보",
    "제품이 보낸 모델 정보": "기기가 보낸 식별 정보",
    "서버에 이전에 확인된 제품 정보": "서버에 저장된 식별 정보",
    "제품 품번 단서": "기기가 보낸 식별 정보",
    "제품 제조사 광고": "기기가 보낸 식별 정보",
    "네트워크 제조사 조회 단서": "네트워크 등록 정보 단서",
    "열려 있는 네트워크 서비스": "기기가 응답한 네트워크 서비스",
    "서버 호스트 하드웨어 등록": "서버에 등록된 하드웨어 정보",
}


def _public_finding_evidence(value: object) -> list[str]:
    """Project private resolver evidence to a fixed, product-neutral vocabulary."""
    if not isinstance(value, list):
        return []
    public_labels = frozenset(_PUBLIC_FINDING_EVIDENCE_LABELS.values())
    labels = []
    for item in value:
        cleaned = _clean(item)
        public_label = _PUBLIC_FINDING_EVIDENCE_LABELS.get(cleaned)
        if public_label is not None:
            labels.append(public_label)
        elif cleaned in public_labels:
            # ``build_public_detected_connections`` receives the already-safe
            # identity-finding projection.  Preserve its fixed vocabulary
            # instead of erasing every evidence label on the second boundary.
            labels.append(cleaned)
    return list(dict.fromkeys(labels))


def _public_finding_candidates(
    value: object,
    verified_clue: DevicePresentation,
) -> list[dict[str, Any]]:
    """Return candidates only when their label exactly matches a verified clue."""
    if (
        not isinstance(value, list)
        or not verified_clue.visible
        or not verified_clue.canonical_name
    ):
        return []

    result: list[dict[str, Any]] = []
    for candidate in value:
        if not isinstance(candidate, Mapping):
            continue
        label = _clean(candidate.get("label"))
        for suffix in (" 품번 확인 중", " 제품 정보 확인 중", " 제품 정보 확인 필요", " 확인 중"):
            if label.endswith(suffix):
                label = label[: -len(suffix)].rstrip()
                break
        if label != verified_clue.canonical_name:
            continue

        item: dict[str, Any] = {
            "label": verified_clue.canonical_name[:120],
            # Candidate metadata is resolver-internal text.  Keep the public
            # state fixed so a forged/legacy kind cannot smuggle a brand,
            # placeholder, or queue message back into the app.
            "kind": "확인된 제품 단서",
        }
        catalog_id = _clean(candidate.get("catalog_id"))
        if catalog_id and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", catalog_id):
            item["catalog_id"] = catalog_id
        try:
            confidence = float(candidate.get("confidence"))
        except (TypeError, ValueError):
            confidence = 0.0
        if 0 < confidence <= 1:
            item["confidence"] = round(confidence, 2)
        result.append(item)
    return result


def build_identity_finding(device: dict[str, Any]) -> dict[str, Any]:
    """Expose a detected-but-not-yet-resolved observation without inventing a name.

    Findings are deliberately separate from ``devices[]``.  They still count
    as detections, carry the server's next action and safe evidence labels, and
    remain eligible for a later resolver retry.  No IP/MAC, chipset name or
    placeholder product label is returned.
    """
    status = _clean(device.get("identity_status")) or "unresolved"
    if status not in {"enriching", "unresolved"}:
        status = "unresolved"
    verified_clue = _verified_finding_product_clue(device)
    safe_candidates = _public_finding_candidates(
        device.get("identity_candidates"),
        verified_clue,
    )
    if verified_clue.visible and verified_clue.canonical_name and not safe_candidates:
        # Persist an explicit server-generated attestation marker with the
        # sanitized clue. The raw fingerprints are intentionally not public,
        # so the second projection boundary needs this exact marker to
        # distinguish a clue built here from a legacy friendly label.
        safe_candidates = [
            {
                "label": verified_clue.canonical_name,
                "kind": "확인된 제품 단서",
            }
        ]
    safe_evidence = _public_finding_evidence(device.get("identity_evidence"))
    raw_risk_level = _clean(device.get("risk_level"))
    finding_risk_level = raw_risk_level if raw_risk_level in {"red", "yellow"} else "yellow"
    # A finding is resolver/audit state, not a product card.  A resident label
    # is attached only when current structured evidence can say something more
    # specific than "connected device". Bare transport responses remain in
    # private evidence/research state and never receive a fabricated name or
    # increase the public device count.
    observed = _observed_connection_presentation(device)
    display_name = verified_clue.canonical_name or (
        str(observed.get("display_name") or "") if observed else ""
    )
    finding = {
        "device_id": public_device_id(device.get("device_id"), device.get("home_id")),
        "identity_status": status,
        "display_name": display_name,
        # Notes from old rows and scanner requests are private resolver data.
        # A fixed copy preserves the next action without echoing a guessed
        # product name, raw fingerprint, or internal queue state.
        "identity_note": (
            "기기가 직접 보낸 제품 단서를 서버가 검증하고 있어요."
            if verified_clue.visible
            else "현재 관측 근거를 보안 점수에 반영했어요."
        ),
        "identity_candidates": safe_candidates,
        "identity_evidence": list(dict.fromkeys(safe_evidence)),
        "online": bool(device.get("online", True)),
        "last_seen": _clean(device.get("last_seen")),
        "risk_level": finding_risk_level,
        "risk_summary": (
            "보안 위험 신호가 있어 먼저 확인이 필요해요."
            if finding_risk_level == "red"
            else "확인된 보안 신호를 기준으로 현재 상태를 계산했어요."
        ),
        "detected": True,
        "retry_after_scan": True,
    }
    if verified_clue.visible:
        finding["manufacturer"] = verified_clue.manufacturer or ""
        finding["model"] = verified_clue.model or ""
        finding["device_type"] = verified_clue.device_type or ""

    if observed:
        # A verified product clue owns the resident-facing name. Protocol
        # observations from the same IP remain useful supporting evidence, but
        # must never replace that product name with a service label.
        observed_payload = dict(observed)
        if verified_clue.visible:
            observed_payload.pop("display_name", None)
        finding.update(observed_payload)
    return sanitize_public_payload(finding)


_OBSERVED_RESPONSE_LABELS = {
    "computer": "컴퓨터 응답",
    "router": "공유기 응답",
    "camera": "카메라 응답",
    "fridge": "냉장고 응답",
    "tv": "TV 응답",
    "speaker": "스피커 응답",
    "lock": "도어록 응답",
    "plug": "스마트 플러그 응답",
    "hub": "스마트 허브 응답",
    "phone": "휴대폰 응답",
    "tablet": "태블릿 응답",
    "nas": "저장장치 응답",
    "printer": "프린터 응답",
    "light": "스마트 조명 응답",
    "robot": "로봇청소기 응답",
    "thermostat": "온도조절기 응답",
    "air_conditioner": "에어컨 응답",
}
_OBSERVED_SERVICE_LABELS = {
    "googlecast": "Google Cast 서비스 응답",
    "airplay": "AirPlay 서비스 응답",
    "onvif": "카메라 표준 서비스 응답",
    "ws-discovery": "기기 검색 서비스 응답",
    "ipp": "인쇄 서비스 응답",
    "smb": "파일 공유 서비스 응답",
    "netbios": "컴퓨터 이름 서비스 응답",
    "spotify-connect": "Spotify Connect 서비스 응답",
    "mdns": "기기 정보 방송 응답",
    "upnp": "기기 설명 서비스 응답",
    "ssdp": "기기 검색 서비스 응답",
    "mqtt": "IoT 메시지 서비스 응답",
    "https": "보안 웹 서비스 응답",
    "http": "웹 관리 서비스 응답",
    "ssh": "원격 관리 서비스 응답",
    "telnet": "Telnet 원격 관리 응답",
    "rtsp": "영상 스트림 서비스 응답",
    "tcp-service": "TCP 서비스 응답",
}
_OBSERVED_SERVICE_KEYS = frozenset((*_OBSERVED_SERVICE_LABELS, "neighbor-presence"))


def _spotify_connect_response_verified(device: Mapping[str, Any]) -> bool:
    """Distinguish an actual Spotify advertisement/response from a probe attempt.

    The native collector records port 17654 as ``spotify-connect`` before its
    ZeroConf getInfo request finishes. ``spotify-probe:*`` therefore proves
    only that a request was attempted. A completed getInfo response, a real
    mDNS service advertisement, or the server probe's response-specific source
    is required before the resident label may say Spotify Connect responded.
    """

    fingerprints = {
        _clean(value).casefold()
        for value in (device.get("fingerprints") or [])
        if _clean(value)
    }
    sources = {
        _clean(value).casefold()
        for value in (device.get("discovery_sources") or [])
        if _clean(value)
    }
    return bool(
        "spotify-getinfo-done" in fingerprints
        or "spotify-connect" in sources
        or any(
            value.startswith("mdns-type:") and "spotify-connect" in value
            for value in fingerprints
        )
    )


def _observation_suffix_from_device_id(
    device_id: object,
    home_id: object | None = None,
) -> str:
    public_id = public_device_id(device_id, home_id)
    if not public_id:
        return ""
    digest = hashlib.sha256(
        f"home-guardian-observation-label:v1:{public_id}".encode("utf-8")
    ).hexdigest()
    return digest[:6].upper()


def _observed_service_display_name(
    service: str,
    *,
    observed_port: int | None = None,
    observation_suffix: str = "",
) -> str:
    base = _OBSERVED_SERVICE_LABELS[service]
    if service == "tcp-service":
        if observed_port is None or not observation_suffix:
            return ""
        return f"{base} (포트 {observed_port}) · {observation_suffix}"
    if observation_suffix:
        if not observation_suffix:
            return ""
        return f"{base} · {observation_suffix}"
    return base


def _safe_observed_connection_type(device: Mapping[str, Any]) -> str:
    """Return only a protocol-backed category for a visible detection row.

    This is intentionally weaker than product identity.  It lets the app say
    *what kind of connection answered* while keeping manufacturer/model blank
    until the server can prove them.  A bare refusal marker, OUI, or arbitrary
    name therefore does not become a visible category row.
    """
    current_type = _clean(device.get("device_type"))
    if current_type not in _OBSERVED_RESPONSE_LABELS:
        current_type = ""
    fingerprints = _fingerprints(device)
    services = [str(value) for value in (device.get("services") or [])]
    sources = {_clean(value).lower() for value in (device.get("discovery_sources") or [])}
    ports = {int(value) for value in (device.get("open_ports") or []) if str(value).isdigit()}
    signal_text = " ".join([*fingerprints, *services]).lower()

    # SMB's paired ports are the only model-less computer proof accepted by
    # the resolver.  The same rule is used here so a random label cannot turn
    # into a "computer" row.
    if current_type == "computer" and (
        ports.intersection({139, 445})
        or sources.intersection({"netbios"})
        or any(
            fingerprint.startswith("netbios-name:")
            or (
                fingerprint.startswith("mdns-type:")
                and "_workstation._tcp" in fingerprint
            )
            for fingerprint in fingerprints
        )
    ):
        return "computer"
    if current_type == "camera" and sources.intersection({"onvif", "ws-discovery"}):
        return "camera"
    if current_type == "router" and any(
        token in signal_text for token in ("internetgatewaydevice", "wanconnectiondevice")
    ):
        return "router"

    strong_type = strong_device_type_from_signals(fingerprints, services)
    if strong_type in _OBSERVED_RESPONSE_LABELS:
        return strong_type
    return ""


def _verified_observed_manufacturer(device: Mapping[str, Any]) -> str | None:
    """Return a maker only when current OUI or structured advertisement proves it."""

    fingerprints = _fingerprints(device)
    advertised = None if advertised_brands_conflict(fingerprints) else brand_from_advertised(fingerprints)
    oui_vendor = vendor_from_oui(_clean(device.get("mac_address")))
    raw = _clean(device.get("manufacturer"))
    raw_normalized = normalize_vendor_name(raw) if raw else ""
    proven = advertised or oui_vendor
    if not proven:
        return None
    normalized = normalize_vendor_name(proven)
    display = VENDOR_KO.get(normalized, normalized)
    raw_display = VENDOR_KO.get(raw_normalized, raw_normalized) if raw_normalized else ""
    # The resolver may already have converted an IEEE organization name to its
    # resident-facing brand (for example ASRock Incorporation -> ASRock). Treat
    # those two spellings as the same maker, but still reject a genuinely
    # conflicting scanner-provided manufacturer.
    if raw_display and raw_display.casefold() != display.casefold():
        return None
    if not _is_product_brand(normalized) or contains_non_product_identifier(display):
        return None
    return display


_FRESH_NEIGHBOR_SOURCES = frozenset({"android-neighbor", "server-neighbor"})
_STALE_ARP_ONLY_SOURCES = frozenset({"android-arp", "arp"})
_REFUSAL_ONLY_SOURCES = frozenset(
    {"tcp-refused-presence", "server-tcp-refused-presence"}
)
_L2_FALLBACK_LABEL = "Wi-Fi 단말"


def _has_physical_mac(value: object) -> bool:
    """Return whether a scanner value is a concrete unicast MAC address."""

    normalized = _clean(value).replace("-", ":").upper()
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", normalized):
        return False
    octets = [int(part, 16) for part in normalized.split(":")]
    return bool(
        not (octets[0] & 1)
        and any(octets)
        and any(octet != 0xFF for octet in octets)
    )


def _has_verified_l2_presence(device: Mapping[str, Any]) -> bool:
    """Return whether this row proves one current LAN endpoint.

    An interface-bound neighbour source is sufficient even when Android could
    not read its MAC.  A concrete MAC is also sufficient unless the row is an
    explicitly stale ARP/refusal-only artifact.  Application-layer service or
    port responses without either fact stay private.
    """

    if bool(device.get("is_phantom")):
        return False
    sources = {
        _clean(value).casefold()
        for value in (device.get("discovery_sources") or [])
        if _clean(value)
    }
    if sources.intersection(_FRESH_NEIGHBOR_SOURCES):
        return True
    if not _has_physical_mac(device.get("mac_address")):
        return False
    artifact_sources = _STALE_ARP_ONLY_SOURCES | _REFUSAL_ONLY_SOURCES
    return not bool(sources and sources.issubset(artifact_sources))


def _observed_identity_display_name(
    device: Mapping[str, Any],
    *,
    observed_type: str,
    manufacturer: str | None,
    host_name: str | None,
    observation_suffix: str,
    l2_presence: bool,
) -> tuple[str, str | None]:
    """Build a useful evidence-backed label without inventing a product name."""

    alias = _clean(device.get("alias"))
    if alias and is_safe_device_alias(alias):
        return alias, alias
    type_label = DEVICE_TYPE_LABELS.get(observed_type) if observed_type else None
    if host_name and manufacturer and type_label:
        return f"{manufacturer} {type_label} - {host_name}", None
    if host_name:
        return host_name, None
    if manufacturer and type_label:
        return f"{manufacturer} {type_label}", None
    if type_label and observation_suffix:
        return f"{type_label} · {observation_suffix}", None
    if l2_presence and observation_suffix:
        return f"{_L2_FALLBACK_LABEL} · {observation_suffix}", None
    return "", None


def _observed_connection_presentation(device: Mapping[str, Any]) -> dict[str, Any] | None:
    """Build a public type label plus private supporting service evidence.

    A transport or discovery response proves only that an endpoint answered; it
    does not prove that the response is a distinct physical product. Service
    metadata is therefore retained for a product/type row at the same IP, while
    a service-only observation receives no resident-facing name.
    """

    if bool(device.get("is_phantom")):
        return None
    observed_type = _safe_observed_connection_type(device)
    l2_presence = _has_verified_l2_presence(device)
    normalized_services = {
        _clean(value).casefold() for value in (device.get("services") or []) if _clean(value)
    }
    normalized_sources = {
        _clean(value).casefold()
        for value in (device.get("discovery_sources") or [])
        if _clean(value)
    }
    open_ports = {
        int(value) for value in (device.get("open_ports") or []) if str(value).isdigit()
    }
    advertised_service_sources = normalized_sources.intersection(_OBSERVED_SERVICE_LABELS)
    # A fresh L2 neighbour or concrete physical MAC proves one local endpoint,
    # but not a retail product. It receives a safe hostname/alias/type label or
    # an opaque stable suffix; protocol and neighbour-table terms stay private.
    observed_service = (
        "neighbor-presence"
        if l2_presence
        else next(
            (
                service
                for service in _OBSERVED_SERVICE_LABELS
                if (service in normalized_services or service in advertised_service_sources)
                and (
                    service != "spotify-connect"
                    or _spotify_connect_response_verified(device)
                )
                and (
                    service in normalized_sources
                    or bool(open_ports)
                    or normalized_sources.intersection(
                        {"mdns", "ssdp", "upnp", "onvif", "ws-discovery", "server-protocol-probe"}
                    )
                )
            ),
            None,
        )
    )
    observed_port: int | None = None
    source_only_protocol = bool(
        observed_service
        and observed_service in advertised_service_sources
        and observed_service not in normalized_services
    )
    if observed_service is None and open_ports and normalized_sources.intersection(
        {"tcp-port-probe", "server-protocol-probe", "server-tcp-probe"}
    ):
        observed_service = "tcp-service"
        observed_port = min(open_ports)
    suffix_required = bool(observed_type or l2_presence or observed_service or source_only_protocol)
    observation_suffix = (
        _observation_suffix_from_device_id(device.get("device_id"), device.get("home_id"))
        if suffix_required
        else ""
    )
    if suffix_required and not observation_suffix:
        # A missing opaque suffix invalidates the service projection, not an
        # independently verified product category on the same observation.
        observed_service = None
        observed_port = None
        source_only_protocol = False
        suffix_required = False
    if not observed_type and not observed_service:
        return None
    manufacturer = _verified_observed_manufacturer(device)
    host_name = _sanitized_observed_host_name(device)
    display_name, observed_alias = _observed_identity_display_name(
        device,
        observed_type=observed_type,
        manufacturer=manufacturer,
        host_name=host_name,
        observation_suffix=observation_suffix,
        l2_presence=l2_presence,
    )
    if display_name and (
        contains_forbidden_device_name(display_name)
        or contains_private_network_identifier(display_name)
        or contains_non_product_identifier(display_name)
    ):
        return None
    result: dict[str, Any] = {}
    if display_name:
        result["display_name"] = display_name
    if observed_alias:
        result["alias"] = observed_alias
    if observed_type:
        result["observed_type"] = observed_type
        result["observed_type_verified"] = True
    if observed_service:
        result["observed_service"] = observed_service
        result["observed_service_verified"] = True
    if source_only_protocol:
        result["observed_source_only"] = True
        result["observed_source_only_verified"] = True
    if observed_port is not None:
        result["observed_port"] = observed_port
        result["observed_port_verified"] = True
    if observation_suffix:
        result["observation_suffix"] = observation_suffix
        result["observation_suffix_verified"] = True
    if manufacturer:
        result["observed_manufacturer"] = manufacturer
        result["observed_manufacturer_verified"] = True
    if host_name:
        result["observed_host_name"] = host_name
        result["host_name_verified"] = True
    return result


def build_public_detected_connections(
    findings: object,
) -> list[dict[str, Any]]:
    """Project evidence-backed unresolved observations into non-product rows.

    ``identity_findings`` remains the private resolver contract for backward
    compatibility.  This separate list is the resident-facing contract: it
    carries only an opaque id, a non-generic evidence-backed label, safe
    evidence labels and risk state. Bare transport responses stay private.
    A verified current L2 endpoint remains visible under a safe hostname,
    alias, verified maker/type, or opaque stable suffix without inventing a
    retail product identity.
    """
    if not isinstance(findings, list):
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping) or finding.get("detected") is not True:
            continue
        device_id = _clean(finding.get("device_id"))
        if not device_id or device_id in seen:
            continue
        verified_clue = _verified_public_finding_clue(finding)
        observed_type = _clean(finding.get("observed_type"))
        observed_type_verified = (
            finding.get("observed_type_verified") is True
            and observed_type in _OBSERVED_RESPONSE_LABELS
        )
        observed_service = _clean(finding.get("observed_service")).casefold()
        observed_service_verified = (
            finding.get("observed_service_verified") is True
            and observed_service in _OBSERVED_SERVICE_KEYS
        )
        observed_source_only = (
            finding.get("observed_source_only") is True
            and finding.get("observed_source_only_verified") is True
        )
        observed_port: int | None = None
        if finding.get("observed_port_verified") is True:
            try:
                candidate_port = int(finding.get("observed_port"))
            except (TypeError, ValueError):
                candidate_port = 0
            if 1 <= candidate_port <= 65535:
                observed_port = candidate_port
        observation_suffix = _clean(finding.get("observation_suffix")).upper()
        expected_suffix = _observation_suffix_from_device_id(device_id)
        suffix_verified = bool(
            finding.get("observation_suffix_verified") is True
            and _OBSERVATION_SUFFIX_RE.fullmatch(observation_suffix)
            and expected_suffix
            and observation_suffix == expected_suffix
        )
        suffix_required = bool(
            observed_service in {"tcp-service", "neighbor-presence"}
            or observed_source_only
        )
        if observed_service == "tcp-service" and observed_port is None:
            observed_service_verified = False
        if suffix_required and not suffix_verified:
            observed_service_verified = False
        observed_manufacturer = _clean(finding.get("observed_manufacturer"))
        manufacturer_verified = (
            finding.get("observed_manufacturer_verified") is True
            and bool(observed_manufacturer)
            and _is_product_brand(observed_manufacturer)
            and not contains_non_product_identifier(observed_manufacturer)
        )
        observed_alias = _clean(finding.get("alias"))
        alias_verified = bool(
            observed_alias
            and is_safe_device_alias(observed_alias)
        )
        observed_host = _clean(finding.get("observed_host_name"))
        host_verified = (
            finding.get("host_name_verified") is True
            and bool(_PUBLIC_HOSTNAME_RE.fullmatch(observed_host))
            and not _PUBLIC_HOSTNAME_HEX_IDENTIFIER_RE.fullmatch(observed_host)
            and not contains_forbidden_device_name(observed_host)
            and not contains_non_product_identifier(observed_host)
            and not contains_private_network_identifier(observed_host)
        )
        l2_presence_verified = bool(
            observed_service == "neighbor-presence"
            and observed_service_verified
            and suffix_verified
            and observed_port is None
            and not observed_source_only
        )
        if verified_clue.visible and verified_clue.canonical_name:
            display_name = verified_clue.canonical_name
            public_type = verified_clue.device_type or ""
        elif observed_type_verified or l2_presence_verified:
            type_label = DEVICE_TYPE_LABELS.get(observed_type)
            if alias_verified:
                display_name = observed_alias
            elif host_verified and manufacturer_verified and type_label:
                display_name = f"{observed_manufacturer} {type_label} - {observed_host}"
            elif host_verified:
                display_name = observed_host
            elif manufacturer_verified and type_label:
                display_name = f"{observed_manufacturer} {type_label}"
            elif type_label and suffix_verified:
                display_name = f"{type_label} · {observation_suffix}"
            elif l2_presence_verified:
                display_name = f"{_L2_FALLBACK_LABEL} · {observation_suffix}"
            else:
                continue
            # Do not trust a legacy/forged friendly label. The internal finding
            # must carry exactly the presentation recomputed from its verified
            # structured fields.
            if _clean(finding.get("display_name")) != display_name:
                continue
            public_type = observed_type or "network"
        else:
            # This is the important anti-generic boundary: a real pending
            # service/transport observation without a product clue or verified
            # device type is not exposed as a resident inventory row.
            continue
        risk_level = _clean(finding.get("risk_level"))
        if risk_level not in {"red", "yellow", "green", "unknown"}:
            risk_level = "yellow"
        evidence = _public_finding_evidence(finding.get("identity_evidence"))
        projected: dict[str, Any] = {
            "device_id": device_id,
            "display_name": display_name,
            "name": display_name,
            "device_type": public_type,
            "identity_status": (
                _clean(finding.get("identity_status"))
                if _clean(finding.get("identity_status")) in {"enriching", "unresolved"}
                else "unresolved"
            ),
            "presentation_kind": "observed_connection",
            "product_clue_verified": bool(verified_clue.visible),
            "identity_note": (
                "기기가 직접 보낸 제조사·제품명·품번 단서를 확인했어요. 서버가 최종 제품 정보와 대조하고 있어요."
                if verified_clue.visible
                else "기기가 직접 보낸 현재 관측 근거를 보안 점수에 반영했어요."
            ),
            "identity_evidence": evidence,
            "identity_candidates": [],
            "online": bool(finding.get("online", True)),
            "last_seen": _clean(finding.get("last_seen")),
            "risk_level": risk_level,
            "risk_summary": (
                "보안 위험 신호가 있어 먼저 확인이 필요해요."
                if risk_level == "red"
                else "확인된 보안 신호를 기준으로 현재 상태를 계산했어요."
            ),
            "detected": True,
            "is_identity_finding": True,
        }
        if verified_clue.visible:
            projected["manufacturer"] = verified_clue.manufacturer or ""
            projected["model"] = verified_clue.model or ""
            projected["observed_type_verified"] = True
        else:
            if observed_type_verified:
                projected["observed_type_verified"] = True
            if manufacturer_verified:
                projected["manufacturer"] = observed_manufacturer
                projected["observed_manufacturer_verified"] = True
            if host_verified:
                projected["observed_host_name"] = observed_host
                projected["host_name_verified"] = True
            if alias_verified:
                projected["alias"] = observed_alias
        if observed_service_verified:
            projected["observed_service"] = observed_service
            projected["observed_service_verified"] = True
        if observed_source_only and observed_service_verified:
            projected["observed_source_only"] = True
            projected["observed_source_only_verified"] = True
        if observed_port is not None and observed_service_verified:
            projected["observed_port"] = observed_port
            projected["observed_port_verified"] = True
        if suffix_verified and observed_service_verified:
            projected["observation_suffix"] = observation_suffix
            projected["observation_suffix_verified"] = True
        result.append(sanitize_public_payload(projected))
        seen.add(device_id)
    return result


def _verified_public_finding_clue(finding: Mapping[str, Any]) -> DevicePresentation:
    """Revalidate a structured product clue before it reaches a detected row.

    ``build_identity_finding`` adds these fields only after checking structured
    manufacturer, concrete model and independently supported product type.  A
    result can nevertheless be loaded from legacy storage, so this public
    boundary repeats the non-product and exact-label checks instead of trusting
    a friendly name or an arbitrary candidate.
    """

    manufacturer = _clean(finding.get("manufacturer"))
    model = _clean(finding.get("model"))
    device_type = _clean(finding.get("device_type"))
    display_name = _clean(finding.get("display_name"))
    type_label = DEVICE_TYPE_LABELS.get(device_type)
    if (
        not manufacturer
        or not model
        or not type_label
        or device_type not in _PUBLIC_DEVICE_TYPES
        or not is_concrete_product_model(model, manufacturer)
        or contains_forbidden_device_name(display_name)
        or contains_non_product_identifier(manufacturer)
        or contains_non_product_identifier(model)
        or contains_private_network_identifier(display_name)
    ):
        return DevicePresentation(visible=False)

    canonical_name = f"{manufacturer} {type_label} ({model})"
    if display_name != canonical_name:
        return DevicePresentation(visible=False)
    candidates = finding.get("identity_candidates")
    if not isinstance(candidates, list) or not any(
        isinstance(candidate, Mapping)
        and _clean(candidate.get("label")) == canonical_name
        and _clean(candidate.get("kind")) == "확인된 제품 단서"
        for candidate in candidates
    ):
        return DevicePresentation(visible=False)
    return DevicePresentation(
        visible=True,
        canonical_name=canonical_name,
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
    )


def normalized_storage_fields(device: dict[str, Any]) -> dict[str, Any]:
    """쓰기 경로에서 오래된 임시 이름을 정규화한다.

    미확정 신호는 내부 분석용으로만 남기되, 공개될 수 있는 이름·제조사·모델은 저장하지 않는다.
    """
    presentation = build_device_presentation(device)
    identity_status = _clean(device.get("identity_status")) or (
        "resolved" if device.get("is_resolved") else "unresolved"
    )
    if not presentation.visible or not presentation.canonical_name:
        raw_manufacturer = _clean(device.get("manufacturer"))
        raw_model = _clean(device.get("model"))
        verified_clue = _verified_finding_product_clue(device)
        return {
            # Keep diagnostic facts for merge, scoring and later re-identification,
            # but never retain a temporary public-facing name.  Reads always pass
            # through apply_device_presentation(), so weak evidence remains hidden.
            "name": "",
            # A stale canonical name from an older resolved snapshot must not
            # survive once the row fails the current provenance boundary.
            # Private raw facts remain available for resolver retries below.
            "canonical_name": "",
            "manufacturer": raw_manufacturer if _is_product_brand(raw_manufacturer) else "",
            "model": (
                raw_model
                if _is_product_model(raw_model, raw_manufacturer)
                and not _is_server_banner_value(raw_model, _fingerprints(device))
                else ""
            ),
            "device_type": _clean(device.get("device_type")) or "unknown",
            "identity_status": "enriching" if identity_status == "enriching" else "unresolved",
            "identity_note": _clean(device.get("identity_note")),
            "identity_candidates": _public_finding_candidates(
                device.get("identity_candidates"),
                verified_clue,
            ),
            "identity_evidence": device.get("identity_evidence") if isinstance(device.get("identity_evidence"), list) else [],
            "identity_family_verified": verified_clue.visible,
            "identity_resolver_version": _clean(device.get("identity_resolver_version")),
            "identity_confidence": float(device.get("identity_confidence", device.get("confidence", 0.2)) or 0.2),
            "is_resolved": False,
            "is_unresolved": True,
        }
    brand_key, model = _verified_product_identity(device)
    stored_brand = brand_key
    if not stored_brand and presentation.manufacturer and _is_product_brand(presentation.manufacturer):
        stored_brand = normalize_vendor_name(presentation.manufacturer)
    return {
        "name": presentation.canonical_name,
        # Storage keeps an internal normalized product key so CVE matching remains stable;
        # every user-facing read still passes through apply_device_presentation(), which
        # converts it to the friendly Korean brand label.
        "manufacturer": stored_brand or "",
        "model": model or presentation.model or "",
        "device_type": presentation.device_type or "",
        "canonical_name": presentation.canonical_name,
        "identity_status": "manual_resolved" if identity_status == "manual_resolved" else "resolved",
        "identity_note": _clean(device.get("identity_note")),
        "identity_candidates": device.get("identity_candidates") if isinstance(device.get("identity_candidates"), list) else [],
        "identity_evidence": device.get("identity_evidence") if isinstance(device.get("identity_evidence"), list) else [],
        "identity_family_verified": bool(device.get("identity_family_verified")),
        "identity_resolver_version": _clean(device.get("identity_resolver_version")),
        "identity_confidence": float(device.get("identity_confidence", device.get("confidence", 0.9)) or 0.9),
        "is_resolved": True,
        "is_unresolved": False,
    }


def _public_notification_brand_key(value: object) -> str | None:
    """Resolve a rendered brand name only when it maps to a known public brand."""
    text = _clean(value)
    if not text:
        return None
    folded = text.casefold()
    for brand_key, display_name in VENDOR_KO.items():
        if folded in {brand_key.casefold(), display_name.casefold()}:
            return brand_key
    normalized = normalize_vendor_name(text)
    return normalized if normalized in VENDOR_KO else None


def _is_verified_legacy_notification_device_label(match: re.Match[str]) -> bool:
    """Accept only a bounded, previously supported public product label.

    Old notification rows have no discovery provenance.  A readable
    ``brand type (model)`` string is therefore not sufficient evidence by
    itself.  The legacy catalog is the narrow compatibility path: it preserves
    real historic notifications for known families without allowing arbitrary
    self-consistent labels to become resident-facing facts.
    """
    brand_key = _public_notification_brand_key(match.group("brand"))
    device_type = _PUBLIC_NOTIFICATION_DEVICE_TYPE_KEYS.get(match.group("device_type").casefold())
    model = _clean(match.group("model"))
    return bool(
        brand_key
        and device_type
        and model
        and _catalog_device_type(brand_key, model) == device_type
    )


def _contains_unverified_legacy_notification_device_label(value: object) -> bool:
    text = _clean(value)
    return bool(
        text
        and any(
            not _is_verified_legacy_notification_device_label(match)
            for match in _PUBLIC_NOTIFICATION_DEVICE_LABEL_RE.finditer(text)
        )
    )


def sanitize_public_notification(notification: dict[str, Any]) -> dict[str, Any]:
    """Project legacy-only or identifying notification text into a safe notice."""
    result = dict(notification)
    public_text_fields = _PUBLIC_NOTIFICATION_TEXT_FIELDS
    if any(
        contains_forbidden_device_name(result.get(field))
        or contains_non_product_identifier(result.get(field))
        or contains_private_network_identifier(result.get(field))
        or _contains_unverified_legacy_notification_device_label(result.get(field))
        for field in public_text_fields
    ) or any(
        _contains_unverified_legacy_notification_device_label(result.get(field))
        for field in _NOTIFICATION_DEVICE_LABEL_FIELDS
    ):
        result["title"] = "기기 확인 안내"
        result["message"] = "확인된 기기 정보를 다시 확인하고 있어요. 다음 검사 후 알려드릴게요."
        if "description" in result:
            result["description"] = result["message"]
        if "action_guide" in result:
            result["action_guide"] = "다음 검사 후 확인된 기기만 알려드릴게요."
        for field in _NOTIFICATION_DEVICE_LABEL_FIELDS:
            result.pop(field, None)
    return sanitize_public_payload(result)


def _public_vulnerabilities(value: object) -> list[dict[str, Any]]:
    """Expose only resident-facing descriptions, never vendor/product matching internals."""
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        public = {
            key: item.get(key)
            for key in ("cve_id", "severity", "summary_ko", "remediation_ko")
            if item.get(key) not in (None, "")
        }
        safe = sanitize_public_payload(public)
        if safe:
            result.append(safe)
    return result


def _public_risk_explanations(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        public = {
            key: item.get(key)
            for key in ("summary_ko", "remediation_ko")
            if item.get(key) not in (None, "")
        }
        safe = sanitize_public_payload(public)
        if safe:
            result.append(safe)
    return result


def _verified_observation_service_value(
    payload: Mapping[str, Any],
    key: object,
    value: object,
) -> bool:
    """Allow a fixed service label only inside its verified observation DTO."""

    if (
        _clean(payload.get("observed_service")).casefold() != "spotify-connect"
        or payload.get("observed_service_verified") is not True
    ):
        return False
    expected_label = _OBSERVED_SERVICE_LABELS["spotify-connect"]
    return bool(
        (_clean(key) in {"display_name", "name"} and _clean(value) == expected_label)
        or (_clean(key) == "observed_service" and _clean(value).casefold() == "spotify-connect")
    )


def _sanitize_public_value(
    value: Any,
    home_id: object | None = None,
    *,
    allow_verified_service_value: bool = False,
) -> Any:
    if isinstance(value, str):
        return (
            _REDACTED
            if (
                contains_forbidden_device_name(value)
                or (
                    contains_non_product_identifier(value)
                    and not allow_verified_service_value
                )
                or contains_private_network_identifier(value)
            )
            else value
        )
    if isinstance(value, list):
        return [
            safe
            for item in value
            if (safe := _sanitize_public_value(item, home_id)) is not _REDACTED
        ]
    if isinstance(value, dict):
        return sanitize_public_payload(value, home_id=home_id)
    return value


def sanitize_public_payload(payload: dict[str, Any], home_id: object | None = None) -> dict[str, Any]:
    """Recursively remove discovery-only labels from a resident-facing payload.

    This is deliberately applied after each endpoint-specific projection.  The
    storage layer may retain raw observations for scoring and re-identification,
    but no string nested below a public response may reintroduce a chipset,
    scanner placeholder, or other forbidden device label.
    """
    scope = payload.get("home_id") or home_id
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(key, str) and (
            key.strip().lower() in _PRIVATE_PUBLIC_FIELD_KEYS
            or contains_forbidden_device_name(key)
            or contains_non_product_identifier(key)
            or contains_private_network_identifier(key)
        ):
            continue

        public_value = (
            public_device_id(value, scope)
            if isinstance(key, str) and key.strip().lower() == "device_id"
            else value
        )
        safe = _sanitize_public_value(
            public_value,
            scope,
            allow_verified_service_value=_verified_observation_service_value(
                payload,
                key,
                public_value,
            ),
        )
        if safe is not _REDACTED:
            result[key] = safe
    return result


def project_public_identity_history(
    item: Mapping[str, Any],
    *,
    home_id: object | None = None,
) -> dict[str, Any]:
    """Project a private resolver-history row into an explicit public DTO.

    Repository history deliberately retains raw evidence for later resolver
    retries and audit.  A public endpoint must not echo that storage shape:
    legacy rows can contain IP/MAC literals, OUI/chipset labels, temporary
    names, arbitrary candidates, or protocol fingerprints.  This allowlist
    exposes only stable state, a fixed resident-facing message, and a product
    identity that passes the same central ``DevicePresentation`` rules as the
    device list.
    """

    status = _clean(item.get("identity_status"))
    if status not in _PUBLIC_IDENTITY_HISTORY_STATUSES:
        status = "unresolved"

    # A legacy row may claim ``resolved`` while carrying an unsafe or
    # unverifiable product label.  Preserve that raw row privately, but do not
    # tell a resident that identification succeeded unless the central product
    # presentation contract accepts it.
    presentation = build_device_presentation(dict(item))
    if status in {"resolved", "manual_resolved"} and not (
        presentation.visible and presentation.canonical_name
    ):
        status = "unresolved"

    message_by_status = {
        "resolved": "제품 정보 확인을 마쳤어요.",
        "manual_resolved": "확인된 제품 정보를 저장했어요.",
        "enriching": "서버가 제품 정보를 확인하고 있어요.",
        "unresolved": "다음 점검 때 제품 정보를 다시 확인해요.",
    }
    result: dict[str, Any] = {
        "identity_status": status,
        "resolved": status in {"resolved", "manual_resolved"},
        "message": message_by_status[status],
    }

    public_id = public_device_id(item.get("device_id"), home_id)
    if public_id:
        result["device_id"] = public_id

    observed_at = _clean(item.get("observed_at"))
    if observed_at and len(observed_at) <= 40 and _PUBLIC_HISTORY_TIMESTAMP_RE.fullmatch(observed_at):
        result["observed_at"] = observed_at

    try:
        confidence = float(item.get("confidence"))
    except (TypeError, ValueError):
        confidence = -1.0
    if 0 <= confidence <= 1:
        result["confidence"] = round(confidence, 2)

    # An unresolved/malicious legacy row stays in private history but cannot
    # manufacture a public product.  Resolved rows must pass the exact same
    # name/brand/model/type validation used everywhere else.
    if presentation.visible and presentation.canonical_name:
        result.update(
            {
                "canonical_name": presentation.canonical_name,
                "manufacturer": presentation.manufacturer or "",
                "model": presentation.model or "",
                "device_type": presentation.device_type or "",
            }
        )

    return sanitize_public_payload(result, home_id=home_id)


def normalize_stored_network_context(network_context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize the private scan context retained for later scan validation.

    A native scan needs its local address and subnet internally to prove that
    it actually ran on the resident's Wi-Fi and to merge later observations.
    Those values are never a user-facing result.  Keep a narrowly validated
    private representation instead of treating the public projection as the
    database format.
    """
    if not isinstance(network_context, Mapping):
        return {}

    result: dict[str, Any] = {}
    for field in ("local_ip", "gateway_ip"):
        value = _validated_ip_address(network_context.get(field))
        if value is not None:
            result[field] = value

    subnet = _validated_subnet(network_context.get("subnet_cidr"))
    if subnet is not None:
        result["subnet_cidr"] = subnet

    interface_type = network_context.get("interface_type")
    if isinstance(interface_type, str):
        normalized_interface = interface_type.strip().lower()
        if normalized_interface in _PUBLIC_NETWORK_INTERFACE_TYPES:
            result["interface_type"] = normalized_interface

    for field in ("is_private_network", "is_emulator", "is_virtual_network"):
        value = network_context.get(field)
        if isinstance(value, bool):
            result[field] = value

    raw_diagnostics = network_context.get("scan_diagnostics")
    if isinstance(raw_diagnostics, Mapping):
        diagnostics: dict[str, int] = {}
        for field in _SCAN_DIAGNOSTIC_FIELDS:
            value = raw_diagnostics.get(field)
            # bool is an int subclass, but is not a valid counter.
            if isinstance(value, bool):
                continue
            if isinstance(value, int) and 0 <= value <= _MAX_SCAN_DIAGNOSTIC_VALUE:
                diagnostics[field] = value
            elif isinstance(value, float) and value.is_integer() and 0 <= value <= _MAX_SCAN_DIAGNOSTIC_VALUE:
                diagnostics[field] = int(value)
        if diagnostics:
            result["scan_diagnostics"] = diagnostics
        for field in _SCAN_DIAGNOSTIC_BOOLEAN_FIELDS:
            if isinstance(raw_diagnostics.get(field), bool):
                result.setdefault("scan_diagnostics", {})[field] = raw_diagnostics[field]

    return result


def sanitize_public_network_context(network_context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return only non-identifying scan-state flags to a public API response.

    IP addresses, gateways and subnets are scanner evidence, not resident UI
    text.  This explicit projection also protects legacy scan rows that still
    contain those fields from being echoed through a result endpoint.
    """
    private_context = normalize_stored_network_context(network_context)
    public_context = {
        field: private_context[field]
        for field in ("interface_type", "is_private_network", "is_emulator", "is_virtual_network")
        if field in private_context
    }
    if "scan_diagnostics" in private_context:
        public_context["scan_diagnostics"] = private_context["scan_diagnostics"]
    return public_context


def _validated_ip_address(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


def _validated_subnet(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ip_network(value.strip(), strict=False))
    except ValueError:
        return None
