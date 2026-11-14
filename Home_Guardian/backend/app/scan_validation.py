from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

ANDROID_VIRTUAL_NETWORKS = (ip_network("10.0.2.0/24"), ip_network("10.0.3.0/24"))
DOCUMENTATION_NETWORKS = (ip_network("192.0.2.0/24"), ip_network("198.51.100.0/24"), ip_network("203.0.113.0/24"))

_URL_EVIDENCE_PREFIXES = ("ssdp-location:", "upnp-location:", "http-location:")
_HOST_EVIDENCE_PREFIXES = ("spotify-endpoint:", "onvif-endpoint:", "mdns-host:")
_RESERVED_SELF_LIST_MARKERS = {
    "services": {"self", "self-device"},
    "discovery_sources": {"self", "self-device"},
    "risk_signals": {"self", "self-device"},
}
_RESERVED_SELF_FINGERPRINTS = (
    "self-android",
    "self-manufacturer:",
    "self-model:",
    "self-type:",
)
_RESERVED_AUTHENTICATED_SELF_PREFIX = "authenticated-self-"
_RESERVED_SELF_NAME_RE = re.compile(
    r"^(?:(?:내|본인|점검)\s*)?(?:휴대폰|태블릿|기기)(?:\s*\([^)]{1,256}\))?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScanObservationBoundary:
    """Result of applying the declared LAN boundary to private observations.

    ``devices`` may still contain private addresses because this object is used
    only between the authenticated request boundary and repository storage.
    Public endpoints must continue to use ``DevicePresentation`` and the
    network-context sanitizer.
    """

    devices: list[dict[str, Any]]
    network_context: dict[str, Any]
    dropped_count: int
    quarantined_endpoint_count: int


def strip_untrusted_self_claims(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Remove client-serializable markers that can hide a household endpoint.

    Native Android self metadata is useful only as a *claim* supplied to the
    current-request L2 verifier.  It is not authority by itself.  This helper
    keeps the observation, its address, MAC and product/protocol evidence while
    removing every marker consumed by ``is_self_observation`` plus the reserved
    Build fingerprints.  A server-attested row may be reconstructed later from
    the original claim and an in-process proof; every other row remains an
    ordinary endpoint and therefore stays in the public/identity pipeline.
    """

    cleaned = {
        str(key): value
        for key, value in observation.items()
        if not str(key).startswith("_authenticated_self_android")
    }

    for field, reserved in _RESERVED_SELF_LIST_MARKERS.items():
        raw_values = cleaned.get(field)
        if isinstance(raw_values, str):
            values = [raw_values]
        elif isinstance(raw_values, (list, tuple, set)):
            values = raw_values
        else:
            continue
        cleaned[field] = [
            value
            for value in values
            if (
                (normalized := _normalized_claim_token(value)) not in reserved
                and not normalized.startswith(_RESERVED_AUTHENTICATED_SELF_PREFIX)
            )
        ]

    raw_fingerprints = cleaned.get("fingerprints")
    if isinstance(raw_fingerprints, str):
        fingerprint_values = [raw_fingerprints]
    elif isinstance(raw_fingerprints, (list, tuple, set)):
        fingerprint_values = raw_fingerprints
    else:
        fingerprint_values = None
    if fingerprint_values is not None:
        cleaned["fingerprints"] = [
            value
            for value in fingerprint_values
            if not _reserved_self_fingerprint(value)
        ]

    # Some internal/server adapters use a singular source field even though
    # the public request model uses discovery_sources.  It must not become an
    # alternate self-hiding switch if such a mapping reaches this boundary.
    for field in ("source", "discovery_source"):
        if field not in cleaned:
            continue
        source = _normalized_claim_token(cleaned.get(field))
        if source in {"self", "self-device"} or source.startswith(
            _RESERVED_AUTHENTICATED_SELF_PREFIX
        ):
            cleaned.pop(field, None)

    device_id = _normalized_claim_token(cleaned.get("device_id"))
    if device_id in {"self", "self-device"} or device_id.startswith(
        ("self-", _RESERVED_AUTHENTICATED_SELF_PREFIX)
    ):
        cleaned["device_id"] = None

    name = " ".join(str(cleaned.get("name") or "").strip().split())
    if (
        _RESERVED_SELF_NAME_RE.fullmatch(name)
        or _normalized_claim_token(name) in {"self", "self-device"}
        or _normalized_claim_token(name).startswith(
            ("self-", _RESERVED_AUTHENTICATED_SELF_PREFIX)
        )
    ):
        cleaned["name"] = None
    return cleaned


def _normalized_claim_token(value: Any) -> str:
    return str(value or "").strip().casefold().replace("_", "-")


def _reserved_self_fingerprint(value: Any) -> bool:
    normalized = _normalized_claim_token(value)
    return normalized == _RESERVED_SELF_FINGERPRINTS[0] or normalized.startswith(
        (
            *_RESERVED_SELF_FINGERPRINTS[1:],
            _RESERVED_AUTHENTICATED_SELF_PREFIX,
        )
    )


def actual_android_scan_rejection_reasons(
    network_context: Mapping[str, Any] | None,
    devices: Iterable[Any] | None,
) -> list[str]:
    context = network_context or {}
    reasons: list[str] = []
    local_ip = string_or_none(context.get("local_ip"))
    gateway_ip = string_or_none(context.get("gateway_ip"))
    declared_subnet = declared_ipv4_subnet(context)

    if is_truthy(context.get("is_emulator")):
        reasons.append("Android Emulator")
    if is_truthy(context.get("is_virtual_network")):
        reasons.append("가상 네트워크")
    if ip_in_networks(local_ip, ANDROID_VIRTUAL_NETWORKS):
        reasons.append("Android Emulator 로컬 주소")
    if ip_in_networks(gateway_ip, ANDROID_VIRTUAL_NETWORKS):
        reasons.append("Android Emulator 게이트웨이 주소")
    if subnet_in_networks(string_or_none(context.get("subnet_cidr")), ANDROID_VIRTUAL_NETWORKS):
        reasons.append("Android Emulator 서브넷")
    if not local_ip or ip_in_networks(local_ip, DOCUMENTATION_NETWORKS):
        reasons.append("실제 휴대폰 Wi-Fi IP 확인 안 됨")
    if declared_subnet is None:
        reasons.append("Wi-Fi 서브넷 확인 안 됨")
    elif not declared_subnet.is_private:
        reasons.append("사설 Wi-Fi 서브넷 확인 안 됨")
    elif not address_is_usable_host(local_ip, declared_subnet):
        reasons.append("휴대폰 주소와 Wi-Fi 서브넷이 일치하지 않음")
    if declared_subnet is not None and not address_is_usable_host(gateway_ip, declared_subnet):
        reasons.append("공유기 주소와 Wi-Fi 서브넷이 일치하지 않음")
    if context.get("interface_type") != "wifi":
        reasons.append("Wi-Fi 연결 확인 안 됨")
    if context.get("is_private_network") is not True:
        reasons.append("사설 공유기 대역 확인 안 됨")
    if devices is None:
        reasons.append("점검 결과 목록 확인 안 됨")

    for device in devices or []:
        device_ip = device_ip_address(device)
        if ip_in_networks(device_ip, ANDROID_VIRTUAL_NETWORKS):
            reasons.append("가상망 기기 주소")
        if ip_in_networks(device_ip, DOCUMENTATION_NETWORKS):
            reasons.append("문서/샘플용 기기 주소")

    return list(dict.fromkeys(reasons))


def enforce_declared_subnet_boundary(
    network_context: Mapping[str, Any] | None,
    devices: Iterable[Mapping[str, Any]] | None,
    *,
    prior_dropped: int = 0,
    prior_quarantined_endpoints: int = 0,
) -> ScanObservationBoundary:
    """Keep only observations proven to belong to the declared IPv4 subnet.

    A primary address outside the subnet is not a device on the currently
    selected home LAN and is rejected.  Explicit SSDP, Spotify, ONVIF or mDNS
    endpoint evidence that cannot be proven to belong to the same subnet is
    removed from an otherwise valid in-subnet observation.  This keeps the
    real device in the identity pipeline while preventing a foreign endpoint
    from lending product metadata to it or triggering a server-side fetch.

    The function never returns rejected addresses or evidence in diagnostics.
    It records only an aggregate count, and that count makes the scan partial
    rather than silently treating the remaining subset as complete.
    """

    context = dict(network_context) if isinstance(network_context, Mapping) else {}
    subnet = declared_ipv4_subnet(context)
    retained: list[dict[str, Any]] = []
    raw_diagnostics = context.get("scan_diagnostics")
    diagnostics = dict(raw_diagnostics) if isinstance(raw_diagnostics, Mapping) else {}
    native_dropped = diagnostics.get("out_of_subnet_observations_dropped")
    bounded_native_dropped = (
        native_dropped
        if isinstance(native_dropped, int)
        and not isinstance(native_dropped, bool)
        and 0 <= native_dropped <= 1_000_000
        else 0
    )
    # The native scanner can already have quarantined observations that are no
    # longer present in ``devices``.  Preserve that bounded aggregate and let
    # the server only increase it.  ``max`` prevents the second post-probe pass
    # from counting the same native drops twice.
    dropped = max(max(0, int(prior_dropped)), bounded_native_dropped)
    native_quarantined_endpoints = diagnostics.get("endpoint_evidence_quarantined")
    bounded_native_quarantined_endpoints = (
        native_quarantined_endpoints
        if isinstance(native_quarantined_endpoints, int)
        and not isinstance(native_quarantined_endpoints, bool)
        and 0 <= native_quarantined_endpoints <= 1_000_000
        else 0
    )
    existing_quarantined_endpoint_count = max(
        max(0, int(prior_quarantined_endpoints)),
        bounded_native_quarantined_endpoints,
    )
    newly_quarantined_endpoints = 0

    for raw_device in devices or []:
        if not isinstance(raw_device, Mapping):
            dropped += 1
            continue
        device = dict(raw_device)
        if subnet is None or not address_is_usable_host(device.get("ip_address"), subnet):
            dropped += 1
            continue
        device, quarantined = quarantine_untrusted_endpoint_evidence(device, subnet)
        newly_quarantined_endpoints += quarantined
        retained.append(device)

    # Rejected endpoint fingerprints are removed immediately.  A second pass
    # therefore sees only newly added server-probe evidence, so it is safe to
    # add that count to the aggregate carried in the network context.
    quarantined_endpoint_count = min(
        1_000_000,
        existing_quarantined_endpoint_count + newly_quarantined_endpoints,
    )

    # Retain only the bounded aggregate.  The main request boundary and the
    # network-context normalizer prevent addresses or evidence text from being
    # exposed with it.
    diagnostics.pop("out_of_subnet_observations_dropped", None)
    if dropped:
        diagnostics["out_of_subnet_observations_dropped"] = dropped
    diagnostics.pop("endpoint_evidence_quarantined", None)
    if quarantined_endpoint_count:
        diagnostics["endpoint_evidence_quarantined"] = quarantined_endpoint_count
    if diagnostics:
        context["scan_diagnostics"] = diagnostics
    else:
        context.pop("scan_diagnostics", None)
    return ScanObservationBoundary(
        devices=retained,
        network_context=context,
        dropped_count=dropped,
        quarantined_endpoint_count=quarantined_endpoint_count,
    )


def scan_is_partial(network_context: Mapping[str, Any] | None) -> bool:
    """Return whether explicit scanner diagnostics prove incomplete coverage.

    Legacy rows and non-native scans often have no diagnostic object.  Absence
    alone is therefore not reinterpreted as failure; only explicit negative
    evidence holds the score.
    """

    if not isinstance(network_context, Mapping):
        return False
    diagnostics = network_context.get("scan_diagnostics")
    if not isinstance(diagnostics, Mapping):
        return False
    dropped = diagnostics.get("out_of_subnet_observations_dropped")
    quarantined_endpoints = diagnostics.get("endpoint_evidence_quarantined")
    # Modern Android builds commonly deny both /proc/net/arp and `ip neigh` to
    # an ordinary app.  That means neighbor coverage is an optional evidence
    # source, not a reliable execution-success signal.  Missing/suppressed
    # neighbor rows remain visible in private diagnostics, while completion is
    # based on whether the bounded candidate pass and its network transports
    # actually finished.  Otherwise every healthy scan on those devices is
    # mislabeled partial and can never publish a score.
    return (
        diagnostics.get("scan_partial") is True
        or diagnostics.get("candidate_coverage_complete") is False
        or diagnostics.get("candidate_stimulation_complete") is False
        or diagnostics.get("tcp_transport_complete") is False
        or diagnostics.get("wifi_network_socket_binding_complete") is False
        or diagnostics.get("tcp_scan_timed_out") is True
        or diagnostics.get("observation_limit_reached") is True
        or (isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0)
        or (
            isinstance(quarantined_endpoints, int)
            and not isinstance(quarantined_endpoints, bool)
            and quarantined_endpoints > 0
        )
    )


def scan_coverage_complete(network_context: Mapping[str, Any] | None) -> bool | None:
    """Project scanner coverage to a tri-state public value.

    ``None`` means an older/non-native scan did not provide coverage evidence.
    Explicit timeout or boundary rejection always overrides a positive
    candidate-coverage flag.
    """

    if not isinstance(network_context, Mapping):
        return None
    diagnostics = network_context.get("scan_diagnostics")
    if not isinstance(diagnostics, Mapping):
        return None
    candidate_complete = diagnostics.get("candidate_coverage_complete")
    has_completion_signal = (
        isinstance(candidate_complete, bool)
        or isinstance(diagnostics.get("neighbor_coverage_complete"), bool)
        or diagnostics.get("tcp_scan_timed_out") is True
        or diagnostics.get("scan_partial") is True
    )
    dropped = diagnostics.get("out_of_subnet_observations_dropped")
    has_completion_signal = has_completion_signal or (
        isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0
    )
    quarantined_endpoints = diagnostics.get("endpoint_evidence_quarantined")
    has_completion_signal = has_completion_signal or (
        isinstance(quarantined_endpoints, int)
        and not isinstance(quarantined_endpoints, bool)
        and quarantined_endpoints > 0
    )
    # Component success is not sufficient to finalize coverage, but every
    # explicit component failure is sufficient to hold it.
    has_completion_signal = has_completion_signal or scan_is_partial(network_context)
    if not has_completion_signal:
        return None
    return not scan_is_partial(network_context) and candidate_complete is not False


def declared_ipv4_subnet(network_context: Mapping[str, Any] | None) -> IPv4Network | None:
    if not isinstance(network_context, Mapping):
        return None
    value = string_or_none(network_context.get("subnet_cidr"))
    if value is None:
        return None
    try:
        parsed = ip_network(value, strict=False)
    except ValueError:
        return None
    return parsed if isinstance(parsed, IPv4Network) else None


def address_is_usable_host(value: Any, subnet: IPv4Network) -> bool:
    text = string_or_none(value)
    if text is None:
        return False
    try:
        parsed = ip_address(text)
    except ValueError:
        return False
    return (
        isinstance(parsed, IPv4Address)
        and parsed in subnet
        and parsed != subnet.network_address
        and parsed != subnet.broadcast_address
    )


def quarantine_untrusted_endpoint_evidence(
    device: dict[str, Any],
    subnet: IPv4Network,
) -> tuple[dict[str, Any], int]:
    """Remove endpoint evidence that is not an in-subnet IP literal.

    The observation's own address has already passed the declared-subnet
    boundary.  A malformed, hostname-based, credential-bearing, public, or
    foreign endpoint therefore invalidates only that fingerprint, not the
    existence of the observed LAN device.
    """

    fingerprints = device.get("fingerprints")
    if not isinstance(fingerprints, list):
        return device, 0

    retained: list[Any] = []
    quarantined = 0
    for value in fingerprints:
        if not isinstance(value, str):
            retained.append(value)
            continue
        evidence = value.strip()
        lowered = evidence.lower()
        if not lowered.startswith((*_URL_EVIDENCE_PREFIXES, *_HOST_EVIDENCE_PREFIXES)):
            retained.append(value)
            continue

        host: str | None
        if lowered.startswith(_URL_EVIDENCE_PREFIXES):
            raw_url = evidence.split(":", 1)[1].strip()
            try:
                parsed = urlsplit(raw_url)
                host = parsed.hostname
                valid_transport = (
                    parsed.scheme.lower() in {"http", "https"}
                    and parsed.username is None
                    and parsed.password is None
                )
            except ValueError:
                host = None
                valid_transport = False
            if not valid_transport:
                quarantined += 1
                continue
        else:
            host = evidence.split(":", 1)[1].split("|", 1)[0].strip()

        normalized_host = (host or "").strip().strip("[]")
        if not address_is_usable_host(normalized_host, subnet):
            quarantined += 1
            continue
        retained.append(value)

    if quarantined:
        sanitized = dict(device)
        sanitized["fingerprints"] = retained
        return sanitized, quarantined
    return device, 0


def device_ip_address(device: Any) -> str | None:
    if isinstance(device, Mapping):
        return string_or_none(device.get("ip_address"))
    return string_or_none(getattr(device, "ip_address", None))


def string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def is_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def ip_in_networks(value: str | None, networks: tuple[IPv4Network, ...]) -> bool:
    if value is None:
        return False
    try:
        parsed = ip_address(value)
    except ValueError:
        return False
    return isinstance(parsed, IPv4Address) and any(parsed in network for network in networks)


def subnet_in_networks(value: str | None, networks: tuple[IPv4Network, ...]) -> bool:
    if value is None:
        return False
    try:
        parsed = ip_network(value, strict=False)
    except ValueError:
        return False
    return isinstance(parsed, IPv4Network) and any(parsed.subnet_of(network) or network.subnet_of(parsed) for network in networks)
