from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Sequence
from uuid import uuid4

ML_SOURCE_PATH = Path(__file__).resolve().parents[3] / "ml"
if str(ML_SOURCE_PATH) not in sys.path:
    sys.path.append(str(ML_SOURCE_PATH))

from home_guardian_ml.hybrid_scoring import score_device_hybrid as score_device
from home_guardian_ml.scoring import _is_phantom_signal

from .constants import HOME, default_home_id_for_user
from .guardian_invites import (
    build_deep_link,
    clean_optional_name,
    default_display_name,
    effective_invite_status,
    generate_short_code,
    guardian_invite_summary,
    hash_guardian_session_token,
    invite_expires_at,
    is_generic_ward_display_name,
    normalize_guardian_invite,
    normalize_invite_lookup,
    parse_utc_text,
)
from .network_scope import (
    derive_network_scope_id,
    derive_strong_network_scope_ids,
    is_strong_network_scope_id,
    normalized_physical_mac,
)
from .scan_state import (
    IDENTITY_PENDING_STEP,
    PARTIAL_SCAN_NOTIFICATION,
    PARTIAL_SCAN_STEP,
    annotate_identity_incomplete_security,
    project_partial_security,
)
from ..scan_validation import (
    actual_android_scan_rejection_reasons,
    enforce_declared_subnet_boundary,
    scan_is_partial,
    strip_untrusted_self_claims,
)
from .scoring_helpers import (
    build_public_identity_findings,
    confirmed_public_red_count,
    public_score_status,
    scan_completed_message,
    score_device_with_current_cve,
    scoring_with_cve,
    summarize_public_security,
    visible_identity_findings,
)
from .identity_history import (
    exact_spotify_mdns_mac_token,
    verified_authenticated_self_android_history_identity,
    verified_family_hub_advertised_token_identity,
    verified_family_hub_snapshot_identity,
)
from ..services.device_presentation import (
    apply_device_presentation,
    bind_trusted_manual_identity,
    build_identity_finding,
    contains_non_product_identifier,
    is_self_observation,
    is_safe_device_alias,
    legacy_device_id_ip_address,
    normalize_stored_network_context,
    normalized_storage_fields,
    public_device_id,
    sanitize_public_notification,
    sanitize_public_network_context,
)
from ..services.device_identity import (
    _GENERIC_MANUFACTURERS,
    _GENERIC_MODELS,
    bind_verified_catalog_history,
    bind_verified_appliance_family_history,
    device_type_from_signals,
    resolve_device_identity,
    strong_device_type_from_signals,
    verified_catalog_marker_identity,
)
from ..services.identity_enrichment import (
    IDENTITY_ENRICHMENT_REJECT_REASONS,
    IDENTITY_ENRICHMENT_RESOLVER_VERSION,
    IDENTITY_RESOLUTION_PROVENANCES,
    IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
    IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
    IdentityEnrichmentError,
    authenticated_self_android_binding,
    bind_authenticated_self_android_claim,
    blocked_binding_reason,
    build_evidence_signature,
    build_identity_job_key,
    build_resolution_signature,
    build_verified_product_catalog_entry,
    evidence_signature_matches,
    identity_job_key_matches,
    is_automated_identity_resolution_provenance,
    resolution_history_evidence,
    source_matches_registered_official_domain,
    stable_identity_evidence_signature,
    strip_untrusted_authenticated_self_android,
    structured_identity_evidence,
    trusted_identity_resolution,
    validate_identity_resolution,
    verified_product_catalog_entry_matches,
    verified_product_catalog_keys,
)


# Keep ordinary request connections away from database-wide journal changes.
# ``journal_mode`` is configured once when a repository process starts, while
# every connection gets the same lock wait budget before it executes SQL.
_SQLITE_BUSY_TIMEOUT_MS = 30_000

# Bump this identifier whenever ``_migrate_schema`` gains a release migration
# that existing databases must run.  The marker is written only after the
# schema and data migration succeeds, so a failed migration remains retryable.
_SQLITE_SCHEMA_MIGRATION_ID = "sqlite-repository-2026-08-29-v1"


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _ambiguous_physical_macs(
    devices: Sequence[Mapping[str, Any]],
) -> set[str]:
    """Return MACs claimed by more than one endpoint in one scan.

    A physical address is useful private binding evidence only while it names
    one observation.  Scanner/bridge defects can repeat one address across
    multiple IPs; using that value for approvals or identity history would
    silently join distinct devices.  Keep the observed address in the frozen
    scan payload, but remove it from identity binding whenever the current
    authoritative snapshot is ambiguous.
    """

    endpoints_by_mac: dict[str, set[tuple[str, str]]] = {}
    for device in devices:
        mac = normalized_physical_mac(device.get("mac_address"))
        if mac is None:
            continue
        endpoint = (
            str(device.get("device_id") or "").strip(),
            str(device.get("ip_address") or "").strip(),
        )
        endpoints_by_mac.setdefault(mac, set()).add(endpoint)
    return {
        mac
        for mac, endpoints in endpoints_by_mac.items()
        if len(endpoints) > 1
    }


def _prepare_identity_enrichment_jobs(
    devices: Sequence[Mapping[str, Any]],
    *,
    home_id: str,
    network_scope_id: str | None,
    ambiguity_devices: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build canonical queue bindings for one authoritative snapshot."""

    strong_scope = network_scope_id if is_strong_network_scope_id(network_scope_id) else None
    ambiguous_macs = _ambiguous_physical_macs(
        devices if ambiguity_devices is None else ambiguity_devices
    )
    prepared: list[dict[str, Any]] = []
    for device in devices:
        observed_mac = normalized_physical_mac(device.get("mac_address"))
        physical_mac = None if observed_mac in ambiguous_macs else observed_mac
        evidence = structured_identity_evidence(device)
        evidence_binding_signature = stable_identity_evidence_signature(
            evidence,
            device_id=device.get("device_id"),
        )
        blocked_reason = blocked_binding_reason(
            strong_scope,
            physical_mac,
            evidence,
            device_id=device.get("device_id"),
        )
        prepared.append(
            {
                "device": device,
                "physical_mac": physical_mac,
                "evidence": evidence,
                "evidence_binding_signature": evidence_binding_signature,
                "job_key": build_identity_job_key(
                    home_id=home_id,
                    device_id=str(device.get("device_id") or ""),
                    network_scope_id=strong_scope,
                    physical_mac=physical_mac,
                    evidence_binding_signature=evidence_binding_signature,
                ),
                "blocked_reason": blocked_reason,
                "status": "blocked" if blocked_reason else "review_required",
            }
        )
    return prepared


def _hold_identity_incomplete_security(
    summary: dict[str, Any],
    identity_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compatibility wrapper for the identity-pending score annotation."""

    return annotate_identity_incomplete_security(summary, identity_findings)


_AUTHORITATIVE_SCAN_SOURCE = "android-native"


def _project_security_events(
    home_id: str,
    observations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project resident alerts only from validated Android observations."""

    events: list[dict[str, Any]] = []
    for observation in observations:
        severity = str(observation.get("risk_level") or "").lower()
        if severity not in {"red", "yellow"}:
            continue
        device_id = str(observation.get("device_id") or "")
        unresolved = bool(observation.get("is_unresolved")) or str(
            observation.get("identity_status") or ""
        ).casefold() in {"enriching", "unresolved"}
        if unresolved:
            title = (
                "점검 중 확인된 보안 위험"
                if severity == "red"
                else "점검 중 확인된 보안 주의"
            )
            description = (
                "점검 중 즉시 확인이 필요한 보안 위험을 발견했어요."
                if severity == "red"
                else "점검 중 보안 설정 확인이 필요한 신호를 발견했어요."
            )
            action_guide = "위험 안내를 확인하고 필요하면 해당 연결을 제한해 주세요."
        else:
            display_name = str(
                observation.get("canonical_name")
                or observation.get("name")
                or observation.get("display_name")
                or "기기"
            )
            title = f"{display_name} 보안 안내"
            description = (
                "확인된 연결에 즉시 점검이 필요한 보안 위험이 있어요."
                if severity == "red"
                else "확인된 기기의 보안 설정과 업데이트를 확인해 주세요."
            )
            action_guide = "기기 제조사 앱과 펌웨어를 확인하고, 필요하면 네트워크에서 분리해 주세요."
        event = sanitize_public_notification(
            {
                "event_id": "event-"
                + hashlib.sha256(f"{home_id}:{device_id}:{severity}".encode("utf-8")).hexdigest()[:24],
                "severity": severity,
                "title": title,
                "description": description,
                "message": description,
                "device_id": device_id,
                "created_at": str(observation.get("last_seen") or observation.get("first_seen") or ""),
                "action_guide": action_guide,
            }
        )
        event["description"] = event.pop("message")
        events.append(event)
    return events


def _validated_authoritative_snapshot(
    network_context: dict[str, Any] | None,
    devices: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    """Revalidate one stored Android snapshot at the repository read boundary.

    Older databases can contain observations written before the declared-LAN
    boundary existed.  Keep those private rows for resolver diagnostics, but
    never let an out-of-subnet observation enter the current device view.  The
    aggregate drop diagnostic is carried into score/result consumers so they
    hold the score instead of treating the reduced set as a complete scan.
    """

    context = normalize_stored_network_context(network_context)
    if actual_android_scan_rejection_reasons(context, devices):
        return None
    bounded = enforce_declared_subnet_boundary(context, devices)
    # Deployments can reopen databases written by a build that treated a
    # router-wide TCP refusal fanout as presence and persisted
    # ``is_phantom=false``.  Re-apply the current presence contract at the read
    # boundary so those rows cannot re-enter devices, score, findings, or the
    # active identity-job reconciliation before another phone scan occurs.
    # The immutable JSON remains available for diagnostics.  A refusal marker
    # accompanied by a real MAC, open port, mDNS/SSDP/ONVIF/neighbor response,
    # or other independent fingerprint is deliberately preserved.
    current_devices: list[dict[str, Any]] = []
    for raw_device in bounded.devices:
        device = dict(raw_device)
        if _is_unverified_presence_only_observation(device):
            device["is_phantom"] = True
        current_devices.append(device)
    return bounded.network_context, current_devices


def sqlite_row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def default_db_path() -> Path:
    configured = os.environ.get("HOME_GUARDIAN_DB_PATH")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / ".tmp" / "home_guardian.sqlite3"


def scoped_device_id(home_id: str, device_id: str) -> str:
    if home_id == HOME["home_id"]:
        return device_id
    return f"{home_id}:{device_id}"


_SERVER_BANNER_PREFIXES = ("http-server:", "ssdp-server:")

_REFUSAL_PRESENCE_SOURCES = frozenset(
    {
        "tcp-refused-presence",
        "server-tcp-refused-presence",
    }
)
_STALE_ARP_PRESENCE_SOURCES = frozenset({"android-arp", "arp"})
_INDEPENDENT_PRESENCE_SOURCES = frozenset(
    {
        "android-neighbor",
        "server-neighbor",
        "mdns",
        "ssdp",
        "upnp",
        "onvif",
        "ws-discovery",
        "netbios",
        "server-protocol-probe",
        "spotify-connect",
        "self",
    }
)
_NON_CORROBORATING_FINGERPRINT_PREFIXES = (
    "spotify-probe:",
    # These are repository audit/enrichment markers, not responses observed
    # from the address during this scan. They must never prove liveness.
    "server-history:",
    "official-source:",
)
_STABLE_EVIDENCE_BINDING_SIGNATURE = re.compile(r"^hges1-[0-9a-f]{64}$")


def _observed_open_ports(raw_device: Mapping[str, Any]) -> list[int]:
    """Return the same bounded integer-port evidence used by normalization."""

    return sorted(
        {
            int(port)
            for port in (raw_device.get("open_ports") or [])
            if str(port).isdigit() and 0 < int(port) <= 65535
        }
    )


def _has_independent_current_presence(raw_device: Mapping[str, Any]) -> bool:
    """Whether this observation has evidence independent of an OPEN result.

    Port-derived service names and device-type guesses are intentionally not
    presence evidence.  A fresh physical MAC, an interface-bound neighbor, a
    multicast/protocol response, or a non-empty response payload/fingerprint
    is.  A TCP refusal only proves that an intermediary returned RST/ICMP; it
    does not prove that the probed address is a household device.  An explicit
    firmware value is also a protocol banner even when an old collector did
    not copy it into ``fingerprints``.
    """

    if normalized_physical_mac(raw_device.get("mac_address")) is not None:
        return True
    fingerprints = {
        str(value).strip().casefold()
        for value in (raw_device.get("fingerprints") or [])
        if value is not None and str(value).strip()
    }
    # The native collector records ``spotify-probe:*`` before it attempts the
    # HTTP getInfo request.  It is an audit marker for a port-derived attempt,
    # not a response.  A success adds ``spotify-getinfo-done`` and structured
    # fields, which remain independent corroboration through this branch.
    if any(
        not fingerprint.startswith(_NON_CORROBORATING_FINGERPRINT_PREFIXES)
        for fingerprint in fingerprints
    ):
        return True
    sources = {
        str(value).strip().casefold()
        for value in (raw_device.get("discovery_sources") or [])
        if str(value).strip()
    }
    if sources.intersection(_INDEPENDENT_PRESENCE_SOURCES):
        return True
    firmware = str(raw_device.get("firmware") or "").strip().casefold()
    if firmware and firmware != "unknown":
        return True
    # Some collectors provide the structured protocol result directly while a
    # fingerprint list is unavailable.  Requiring both fields avoids treating
    # a port-derived generic manufacturer or model guess as corroboration.
    manufacturer = str(raw_device.get("manufacturer") or "").strip().casefold()
    model = str(raw_device.get("model") or "").strip().casefold()
    return bool(
        manufacturer
        and manufacturer not in _GENERIC_MANUFACTURERS
        and model
        and model not in _GENERIC_MODELS
    )


def _is_refusal_only_observation(raw_device: Mapping[str, Any]) -> bool:
    """Return whether refusal is the observation's only liveness signal.

    Some routers, carrier gateways and transparent security devices answer a
    broad address range with TCP refusal.  The response is useful transport
    telemetry but must not create a household device.  An actually open port
    or independent current evidence still preserves the observation and keeps
    any refusal marker as supplemental diagnostic information.
    """

    sources = {
        str(value).strip().casefold()
        for value in (raw_device.get("discovery_sources") or [])
        if value is not None and str(value).strip()
    }
    return bool(
        sources.intersection(_REFUSAL_PRESENCE_SOURCES)
        and not _observed_open_ports(raw_device)
        and not _has_independent_current_presence(raw_device)
    )


def _is_stale_arp_only_observation(raw_device: Mapping[str, Any]) -> bool:
    """Return whether a cached ARP entry is the only current-presence signal.

    ``android-arp``/``arp`` came from legacy cache readers and can outlive the
    device that previously owned an address.  The MAC carried by that same
    cache entry, and old identity labels attached to it, do not make it fresh.
    Preserve the row only when this scan also observed address-specific
    liveness: a current neighbor source, an actually OPEN port, a protocol
    response/fingerprint, or a real response banner.
    """

    sources = {
        str(value).strip().casefold()
        for value in (raw_device.get("discovery_sources") or [])
        if value is not None and str(value).strip()
    }
    if not sources.intersection(_STALE_ARP_PRESENCE_SOURCES):
        return False
    if _observed_open_ports(raw_device):
        return False
    if sources.intersection(_INDEPENDENT_PRESENCE_SOURCES):
        return False
    fingerprints = {
        str(value).strip().casefold()
        for value in (raw_device.get("fingerprints") or [])
        if value is not None and str(value).strip()
    }
    if any(
        not fingerprint.startswith(_NON_CORROBORATING_FINGERPRINT_PREFIXES)
        for fingerprint in fingerprints
    ):
        return False
    firmware = str(raw_device.get("firmware") or "").strip().casefold()
    return not firmware or firmware == "unknown"


def _is_unverified_presence_only_observation(raw_device: Mapping[str, Any]) -> bool:
    """Reject transport/cache artifacts that do not prove a current device."""

    return _is_refusal_only_observation(raw_device) or _is_stale_arp_only_observation(
        raw_device
    )


def phantom_port_echo_mask(discovered_devices: list[dict[str, Any]]) -> list[bool]:
    """Classify refusal-only and stale-ARP-only observations as phantom.

    An OPEN result is address-specific liveness evidence.  The number of hosts
    exposing the same port cannot distinguish a proxy echo from a classroom,
    office, or lab containing many identical real products.  Therefore neither
    port equality nor cohort size is a deletion signal.  Refusal-only telemetry
    remains excluded because it can be generated by an intermediary for an
    otherwise absent address; any actual open port or independent discovery
    evidence preserves the row.  A legacy ARP cache entry is treated the same
    way unless a fresh neighbor/protocol/open-port response also exists.
    """

    return [
        isinstance(raw_device, Mapping)
        and _is_unverified_presence_only_observation(raw_device)
        for raw_device in discovered_devices
    ]


def _server_banner_from_fingerprints(fingerprints: list[str]) -> str | None:
    """HTTP/SSDP Server 배너를 fingerprint 에서 추출한다(http-server 우선).

    네이티브는 배너를 firmware 필드가 아니라 ``http-server:``/``ssdp-server:`` fingerprint 로 보내는데,
    취약/EOL 서버 배너 CVE 매칭(Boa 등)은 firmware 를 읽는다. 배너를 firmware 로 승격하지 않으면
    제조사 미상 공유기의 Boa 배너가 firmware='unknown' 이라 매칭되지 않아 미탐된다(실측 확인).
    """
    for prefix in _SERVER_BANNER_PREFIXES:
        for fp in fingerprints:
            if fp.lower().startswith(prefix):
                value = fp[len(prefix):].strip()
                if value:
                    # 방어적 길이 제한: 배너는 공격자(악의적 LAN 기기)가 임의로 광고할 수 있으므로,
                    # 거대 문자열이 firmware 로 저장돼 UI 레이아웃/메모리를 망가뜨리지 않게 자른다.
                    # 실제 서버 배너는 짧다(예 'Boa/0.94.14rc21'). CVE 배너 매칭에도 충분.
                    return value[:200]
    return None


def normalize_observed_device(
    raw_device: dict[str, Any],
    scan_source: str,
    home_id: str = HOME["home_id"],
    verified_identity: dict[str, str] | None = None,
    *,
    phantom_port_echo: bool = False,
    catalog_entries: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    ip_address = str(raw_device.get("ip_address") or "").strip()
    if not ip_address:
        raise ValueError("ip_address가 없는 탐색 기기는 저장할 수 없습니다.")

    # 리스트 필드는 `or [...]` 로 받는다(.get(key, default) 는 키가 None 값으로 존재하면 None 을 반환해
    # 순회 시 크래시한다). 한 기기의 불완전/이상 데이터가 normalize 를 터뜨려 전체 스캔을 망치지 않게 한다.
    open_ports = _observed_open_ports(raw_device)
    services = [str(s) for s in (raw_device.get("services") or service_names(open_ports))]
    risk_signals = list(dict.fromkeys(str(item) for item in (raw_device.get("risk_signals") or [])))
    fingerprints = [str(item) for item in (raw_device.get("fingerprints") or [])]
    discovery_sources = [str(item) for item in (raw_device.get("discovery_sources") or [scan_source])]

    # firmware: native 가 명시 firmware 를 줬으면 쓰고, 없으면(unknown) HTTP/SSDP 서버 배너를 승격한다.
    # 취약 서버 배너 CVE 매칭(Boa 등)이 firmware 를 읽으므로, 배너를 firmware 로 올려야 미탐을 막는다.
    raw_firmware = str(raw_device.get("firmware") or "").strip()
    if raw_firmware and raw_firmware.lower() != "unknown":
        firmware = raw_firmware
    else:
        firmware = _server_banner_from_fingerprints(fingerprints) or "unknown"

    # Physical identity must come from the scanner/probe boundary that verified
    # one fresh L2 observation on the current interface.  Storage must not
    # re-read the server neighbour table (which can be stale or from another
    # NIC), and an advertised mDNS/fingerprint MAC is untrusted product
    # evidence rather than proof of the host's physical identity.
    # ``mac_address`` is the one explicit physical-address channel accepted by
    # storage.  Do not infer it from a fingerprint, advertised service name or
    # a repository-side neighbour-table lookup.  The Android/server collectors
    # put only a fresh, current-interface neighbour observation in this field;
    # storage still validates/canonicalises it before it can bind history.
    verified_mac = normalized_physical_mac(raw_device.get("mac_address"))
    mac_address = verified_mac or f"UNKNOWN-{ip_address}"

    # A device that previously exposed a catalog-backed model can go quiet
    # when it enters standby (notably a Family Hub).  The repository may pass
    # an exact-MAC historical identity here; only missing/non-product scanner
    # fields are enriched, and the resolver still rechecks the model against
    # the current catalog.  This avoids both the old vague label and a guessed
    # product based on a port or chip vendor alone.
    history = verified_identity if isinstance(verified_identity, dict) else None
    history_reused = False
    history_appliance_family_reused = False
    if history:
        current_manufacturer = str(raw_device.get("manufacturer") or "").strip()
        current_model = str(raw_device.get("model") or "").strip()
        history_manufacturer = str(history.get("manufacturer") or "").strip()
        history_model = str(history.get("model") or "").strip()
        # A previously catalog-verified MAC is stronger than a weak current
        # OUI/protocol hint.  In particular, Family Hub can advertise a
        # Spotify receiver type while asleep and expose no model at all.  The
        # old condition only allowed a matching manufacturer, so a harmless
        # OUI label (for example an internal chip vendor) could prevent the
        # verified product from being restored even though the model was
        # empty.  Permit that second path when the current observation has no
        # product model and does not itself match an exact catalog product.
        current_model_is_generic = current_model.lower() in _GENERIC_MODELS
        current_exact_catalog_models: list[str] = []
        if current_model_is_generic:
            try:
                from ..services.device_identity import search_product_catalog

                current_catalog_matches = search_product_catalog(
                    {
                        **raw_device,
                        "model": current_model,
                        "manufacturer": current_manufacturer,
                    },
                    limit=3,
                    catalog_entries=catalog_entries,
                )
                current_exact_catalog_models = [
                    str(item.get("model") or "").strip()
                    for item in current_catalog_matches
                    if item.get("match_kind") == "exact_model" and item.get("model")
                ]
            except (ImportError, TypeError, ValueError):
                current_exact_catalog_models = []
        # A verified identity is supplied only after the repository has
        # matched the same physical MAC to a high-confidence, catalog-backed
        # product.  Reuse it when the current model is the same product or is
        # genuinely missing/generic.  A different non-generic model remains
        # authoritative; old history must not overwrite a real new product.
        history_model_matches_current = (
            bool(current_model)
            and current_model.casefold() == history_model.casefold()
        ) or any(
            model.casefold() == history_model.casefold() for model in current_exact_catalog_models
        )
        can_reuse_history = bool(
            history.get("_history_kind") != "appliance_family"
            and
            history_manufacturer
            and history_model
            and (
                current_model_is_generic
                or history_model_matches_current
            )
        )
        can_reuse_appliance_family_history = bool(
            history.get("_verified_appliance_family_history_proof") is not None
            and history.get("_history_kind") == "appliance_family"
            and history_manufacturer
            and history_model
            and current_model_is_generic
            and str(history.get("device_type") or "").strip().lower() == "fridge"
            and str(raw_device.get("device_type") or "").strip().lower()
            in {"", "unknown", "audio", "speaker", "fridge"}
        )
        if can_reuse_history:
            raw_device = {**raw_device, "manufacturer": history_manufacturer}
            raw_device = {**raw_device, "model": history_model}
            raw_device = {**raw_device, "device_type": str(history.get("device_type") or "")}
        elif can_reuse_appliance_family_history:
            raw_device = {**raw_device, "manufacturer": history_manufacturer}
            raw_device = {**raw_device, "model": history_model}
            raw_device = {**raw_device, "device_type": "fridge"}
        if can_reuse_history:
            fingerprints = list(dict.fromkeys([*fingerprints, "server-history:verified-product"]))
            discovery_sources = list(dict.fromkeys([*discovery_sources, "server-history"]))
            history_reused = True
        elif can_reuse_appliance_family_history:
            fingerprints = list(
                dict.fromkeys([*fingerprints, "server-history:verified-familyhub"])
            )
            discovery_sources = list(dict.fromkeys([*discovery_sources, "server-history"]))
            history_reused = True
            history_appliance_family_reused = True

    # device_type: native 의 단정(예: spotify-connect→speaker)을 신뢰하지 않고 mDNS/SSDP 신호로
    # 재판정한다. 명확한 신호가 없을 때만 native hint → 포트 추정 순으로 fallback.
    native_type = str(raw_device.get("device_type") or "").strip()
    signal_type = device_type_from_signals(fingerprints, services, open_ports)
    # native 가 bare _spotify-connect 만 보고 audio/speaker 로 단정했는데 구체 getInfo deviceType
    # (spotify-type:*)이 없으면 그 종류를 신뢰하지 않는다. Spotify Connect 는 스피커뿐 아니라 TV·냉장고
    # (삼성 패밀리허브)에도 실리므로, 근거가 bare _spotify-connect 뿐인 'audio' 단정은 절전 냉장고를
    # '오디오 기기'로 오탐시킨다(실측: 사용자 LAN 의 .3 냉장고가 getInfo 미응답 시 device_type=audio 로 저장).
    fp_blob = " ".join(fingerprints).lower()
    spotify_only_audio_guess = (
        native_type in ("audio", "speaker")
        and "_spotify-connect" in fp_blob
        and "spotify-type:" not in fp_blob
    )
    # native 의 'tv'(googlecast/airplay→tv)·'hub'(homekit/hue→hub)는 프로토콜만 보고 단정한 모호 추정이다.
    # 이것은 *고신뢰 신호(ci 카테고리·cast 스피커 모델명)*로만 재판정한다 — 약한 토큰 추정(_rtsp→camera 등)
    # 으로 뒤집으면 화면공유로 _rtsp 를 광고하는 webOS TV 가 'camera' 로 잘못 분류된다(적대적 검증으로 확인).
    # 실측: 네이티브가 Nest Mini/HomePod 를 'tv', HomeKit Hue 전구를 'hub' 로 보내 ci/cast-speaker 보정이 우회됐음.
    strong_type = strong_device_type_from_signals(fingerprints, services)
    # mDNS TXT/이름의 명확한 종류 신호(가전 등)는 native 의 약한 추정보다 우선한다.
    if native_type in ("tv", "hub") and strong_type:
        device_type = strong_type
    elif signal_type and native_type in ("", "unknown", "web-device", "speaker", "iot", "audio"):
        device_type = signal_type
    elif spotify_only_audio_guess:
        device_type = "unknown"  # 근거 약함 → 미상(identify_device 가 '정체불명 기기'로 안내, 사용자 이름 지정 유도)
    elif native_type:
        device_type = native_type
    else:
        device_type = guess_device_type(open_ports, risk_signals)

    # device_id 는 native 가 준 값(MAC 유무로 갈림) 대신 IP 기준으로 통일한다(같은 기기 병합).
    device_id = scoped_device_id(home_id, make_device_id(ip_address, mac_address))

    device = {
        "device_id": device_id,
        "home_id": home_id,
        # The scanner must not manufacture a resident-facing label.  The
        # server resolver below fills this only after catalog/evidence checks.
        "name": str(raw_device.get("name") or "").strip(),
        "device_type": device_type,
        "manufacturer": str(raw_device.get("manufacturer") or "").strip(),
        "model": str(raw_device.get("model") or "").strip(),
        "ip_address": ip_address,
        "mac_address": mac_address,
        "online": bool(raw_device.get("online", True)),
        "last_seen": str(raw_device.get("last_seen") or utc_now()),
        "open_ports": open_ports,
        "services": [str(service) for service in services],
        "default_credentials": bool(raw_device.get("default_credentials", False)),
        "encryption": str(raw_device.get("encryption") or "unknown"),
        "firmware": firmware,
        "vulnerabilities": raw_device.get("vulnerabilities") if isinstance(raw_device.get("vulnerabilities"), list) else [],
        "discovery_sources": discovery_sources,
        "fingerprints": fingerprints,
        "risk_signals": risk_signals,
        "scan_source": scan_source,
        "confidence": float(raw_device.get("confidence", 0.65)),
    }
    # A refusal without an actual response, or a legacy ARP cache entry without
    # fresh corroboration, is not a current household-device observation.
    # Recheck here as defense in depth even when a caller omitted the scan-level
    # mask.  An actually OPEN port is always preserved per address; cohort size
    # and repeated service names are never deletion evidence.
    refusal_only = _is_refusal_only_observation(raw_device)
    stale_arp_only = _is_stale_arp_only_observation(raw_device)
    presence_only_phantom = bool(
        (phantom_port_echo or refusal_only or stale_arp_only)
        and (refusal_only or stale_arp_only)
    )
    if presence_only_phantom:
        device["is_phantom"] = True
        device["risk_signals"] = list(dict.fromkeys([*risk_signals, "phantom_signal"]))
        device["identity_note"] = (
            "TCP 연결 거부 외에 기기 존재 근거가 없어 네트워크 응답 신호로 분리했어요."
            if refusal_only
            else "과거 ARP 캐시 외에 이번 점검의 현재 기기 존재 근거가 없어 분리했어요."
        )
        device.update(
            resolve_device_identity(device, catalog_entries=catalog_entries)
        )
        device.update(normalized_storage_fields(device))
        return device
    # The backend owns identity enrichment.  Unresolved observations remain in
    # storage with their evidence and are surfaced as identity findings rather
    # than being silently removed from scan counts.
    resolved_identity = resolve_device_identity(
        device,
        catalog_entries=catalog_entries,
    )
    # The repository only supplies ``verified_identity`` after an exact
    # catalog match on the same physical MAC.  Re-run the resolver with those
    # fields as the authoritative product evidence so a conflicting weak
    # current banner cannot downgrade a known product to ``enriching``.
    # This keeps discovery honest: no IP/MAC or port is used to invent a name;
    # the durable, catalog-backed identity is the proof.
    if history_reused and history_manufacturer and (
        history_model or history_appliance_family_reused
    ):
        historical_device = {
            **device,
            "manufacturer": history_manufacturer,
            "model": history_model,
            "device_type": str(history.get("device_type") or device.get("device_type") or ""),
            "fingerprints": list(
                dict.fromkeys(
                    [
                        *fingerprints,
                        (
                            "server-history:verified-familyhub"
                            if history_appliance_family_reused
                            else "server-history:verified-product"
                        ),
                    ]
                )
            ),
        }
        if (
            history_appliance_family_reused
            and history.get("_verified_appliance_family_history_proof") is not None
        ):
            historical_device["_verified_appliance_family_history_proof"] = history.get(
                "_verified_appliance_family_history_proof"
            )
            historical_device["fingerprints"] = list(
                dict.fromkeys([*fingerprints, "server-history:verified-familyhub"])
            )
        else:
            historical_device = bind_verified_catalog_history(historical_device)
        historical_identity = resolve_device_identity(
            historical_device,
            catalog_entries=catalog_entries,
        )
        if historical_identity.get("is_resolved"):
            resolved_identity = historical_identity
    device.update(resolved_identity)
    device.update(normalized_storage_fields(device))
    return device



_scoring_with_cve = scoring_with_cve


def apply_verified_product_catalog_projection(
    devices: list[dict[str, Any]],
    catalog_entries: list[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Re-project observed rows with verified global product facts.

    The catalog may enrich only rows that are already present in the validated
    scan snapshot.  It never creates membership, revives a phantom, or merges
    two classroom devices that advertise the same model.
    """

    if not devices or not catalog_entries:
        return devices
    projected: list[dict[str, Any]] = []
    for original in devices:
        if bool(original.get("is_phantom")):
            projected.append(original)
            continue
        identity = resolve_device_identity(
            original,
            catalog_entries=catalog_entries,
        )
        if not bool(identity.get("is_resolved")):
            projected.append(original)
            continue
        enriched = {**original, **identity}
        enriched.update(normalized_storage_fields(enriched))
        enriched = _scoring_with_cve(enriched)
        scored = score_device(enriched)
        enriched.update(
            security_score=scored["score"],
            risk_level=scored["risk_level"],
            risk_summary=scored["summary"],
            recommended_actions=scored["recommended_actions"],
        )
        projected.append(enriched)
    return projected


def verified_catalog_resolution_for_job(
    job: Mapping[str, Any],
    catalog_entries: Sequence[Mapping[str, Any]],
) -> dict[str, str] | None:
    """Bind one signed observation to one exact global catalog fact.

    This is intentionally stricter than presentation projection.  A queue row
    is closed only when its HMAC/job binding is current and its structured
    manufacturer, exact model and device type proofs all identify one signed
    catalog row.  No home/network identifier is copied into the global fact.
    """

    verified_entries = [
        entry
        for entry in catalog_entries
        if isinstance(entry, Mapping)
        and verified_product_catalog_entry_matches(entry)
    ]
    if not verified_entries or job.get("status") != "review_required":
        return None
    evidence = job.get("evidence")
    if not isinstance(evidence, Mapping):
        return None
    if (
        blocked_binding_reason(
            str(job.get("network_scope_id") or "") or None,
            str(job.get("physical_mac") or "") or None,
            evidence,
            device_id=job.get("device_id"),
        )
        is not None
        or not identity_job_key_matches(job)
        or not evidence_signature_matches(evidence, job.get("evidence_signature"))
    ):
        return None

    from ..services.identity_research import _safe_string_list
    from ..services.official_product_lookup import _normalized_type

    raw_proofs = evidence.get("structured_provenance")
    if not isinstance(raw_proofs, list) or not raw_proofs or len(raw_proofs) > 64:
        return None
    proofs: list[dict[str, str]] = []
    for raw in raw_proofs:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "source", "value"}:
            return None
        kind = str(raw.get("kind") or "").strip().casefold()
        source = str(raw.get("source") or "").strip().casefold()
        value = " ".join(str(raw.get("value") or "").strip().split())
        if (
            kind not in {"manufacturer", "model", "device_type"}
            or not source
            or len(source) > 48
            or not value
            or len(value) > 96
        ):
            return None
        proofs.append({"kind": kind, "source": source, "value": value})

    model_values = {
        " ".join(str(value or "").strip().split())
        for value in _safe_string_list(evidence.get("model_hints"))
        if str(value or "").strip()
    }
    if len(model_values) != 1:
        return None
    model = next(iter(model_values))

    maker_values: set[str] = set()
    type_values: set[str] = set()
    model_proof_values: set[str] = set()
    for proof in proofs:
        if not isinstance(proof, Mapping):
            return None
        kind = str(proof.get("kind") or "").strip().casefold()
        value = " ".join(str(proof.get("value") or "").strip().split())
        if kind == "manufacturer" and value:
            maker_values.add(value)
        elif kind == "model" and value:
            model_proof_values.add(value)
        elif kind == "device_type":
            normalized_type = _normalized_type(value)
            if normalized_type is not None:
                type_values.add(normalized_type)
    if not maker_values or not model_proof_values or len(type_values) > 1:
        return None
    try:
        maker_pairs = {
            verified_product_catalog_keys(value, model) for value in maker_values
        }
    except IdentityEnrichmentError:
        return None
    maker_keys = {pair[0] for pair in maker_pairs}
    model_key = next(iter(maker_pairs))[1]
    try:
        proof_model_keys = {
            verified_product_catalog_keys(next(iter(maker_values)), value)[1]
            for value in model_proof_values
        }
    except IdentityEnrichmentError:
        return None
    if proof_model_keys != {model_key} or len(maker_keys) != 1:
        return None
    maker_key = next(iter(maker_keys))

    hinted_makers: set[str] = set()
    for value in _safe_string_list(evidence.get("manufacturer_hints")):
        try:
            hinted_makers.add(verified_product_catalog_keys(value, model)[0])
        except IdentityEnrichmentError:
            return None
    if hinted_makers and hinted_makers != {maker_key}:
        return None
    hinted_types = {
        normalized
        for value in _safe_string_list(evidence.get("device_type_hints"))
        if (normalized := _normalized_type(value)) is not None
    }
    if len(hinted_types) > 1:
        return None

    matches = [
        entry
        for entry in verified_entries
        if str(entry.get("manufacturer_key") or "") == maker_key
        and str(entry.get("model_key") or "") == model_key
        and (not type_values or str(entry.get("device_type") or "").casefold() in type_values)
        and (not hinted_types or str(entry.get("device_type") or "").casefold() in hinted_types)
    ]
    if len(matches) != 1:
        return None
    entry = matches[0]
    return {
        "manufacturer": str(entry.get("manufacturer") or ""),
        "device_type": str(entry.get("device_type") or ""),
        "model": str(entry.get("exact_model") or ""),
        "source_reference": str(entry.get("source_url") or ""),
        "resolution_provenance": str(entry.get("provenance") or ""),
    }


def verified_catalog_reconcile_version(
    catalog_entries: Sequence[Mapping[str, Any]],
) -> str | None:
    """Return a household-free version for the currently trusted catalog."""

    signatures = sorted(
        str(entry.get("catalog_signature") or "").strip()
        for entry in catalog_entries
        if isinstance(entry, Mapping)
        and verified_product_catalog_entry_matches(entry)
        and str(entry.get("catalog_signature") or "").strip()
    )
    if not signatures:
        return None
    digest = hashlib.sha256("\n".join(signatures).encode("utf-8")).hexdigest()
    return f"verified-catalog-v1-{digest}"


def device_row_values(device: dict[str, Any]) -> tuple[Any, ...]:
    return (
        device["device_id"],
        device.get("home_id", HOME["home_id"]),
        device["name"],
        device["device_type"],
        device["manufacturer"],
        device["model"],
        device["ip_address"],
        device["mac_address"],
        int(device["online"]),
        device["last_seen"],
        json.dumps(device["open_ports"], ensure_ascii=False),
        json.dumps(device.get("services", service_names(device["open_ports"])), ensure_ascii=False),
        int(device["default_credentials"]),
        device["encryption"],
        device.get("firmware", "unknown"),
        json.dumps(device["vulnerabilities"], ensure_ascii=False),
        json.dumps(device.get("discovery_sources", []), ensure_ascii=False),
        json.dumps(device.get("fingerprints", []), ensure_ascii=False),
        json.dumps(device.get("risk_signals", []), ensure_ascii=False),
        device["scan_source"],
        float(device.get("confidence", 0.85)),
        int(bool(device.get("is_unresolved", False))),
        int(bool(device.get("is_phantom", False))),
        device["security_score"],
        device["risk_level"],
        device["risk_summary"],
        json.dumps(device["recommended_actions"], ensure_ascii=False),
        {"red": 0, "yellow": 1, "green": 2}.get(device["risk_level"], 3),
    )


def make_device_id(ip_address: str, mac_address: str) -> str:
    # 같은 기기가 mDNS 유무(MAC 획득 여부)에 따라 다른 ID 로 갈리지 않도록 IP 기준으로 통일한다.
    # 다만 LAN 주소 자체는 API/UI 식별자가 되면 안 된다. 결정적 해시를 사용하면 이전 스캔과의
    # 병합 특성은 보존하면서도 새 DB 행과 모든 공개 응답에서 주소를 노출하지 않는다.
    del mac_address
    digest = hashlib.sha256(
        f"home-guardian-device-id:v1:{ip_address.strip()}".encode("utf-8")
    ).hexdigest()[:24]
    return f"dev-{digest}"


def _parse_iso(value: Any) -> datetime | None:
    """ISO8601 문자열(끝에 Z 포함)을 datetime 으로. 실패하면 None.

    타임존이 없는(naive) 값은 UTC 로 간주해 aware 로 통일한다. 그러지 않으면 병합에서
    aware 와 섞여 빼는 순간 TypeError 가 나 기기목록 조회 전체가 크래시한다(단일 실패점 방지)."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed

# 기기가 '능동적으로 알린' 권위 있는 정체 신호(getInfo 브랜드·UPnP 제조사·NetBIOS 이름 등).
# 이게 있으면 그 스냅샷의 식별을 신뢰한다 — 단순 OUI 추정보다 강하다.
_ADVERTISED_IDENTITY_PREFIXES = (
    "spotify-brand:", "spotify-model:", "spotify-name:",
    "mdns-txt:manufacturer=", "mdns-txt:fn=", "mdns-txt:md=", "mdns-txt:usb_mfg=",
    "airplay-manufacturer:", "upnp-manufacturer:", "netbios-name:",
)


def _identity_strength(device: dict[str, Any]) -> int:
    """스냅샷의 식별 신뢰도. 간헐적 신호(냉장고 Spotify getInfo 등)로 한 번 확실히 식별된 정체가
    이후 그 신호를 못 받은 약한 스냅샷에 강등되지 않도록 병합에서 우선순위로 쓴다.

    2 = 기기가 능동적으로 브랜드/이름을 광고(getInfo·UPnP·NetBIOS 등) / 1 = 제조사 추정(OUI 등) / 0 = 미상.
    """
    if str(device.get("identity_status") or "") in {"resolved", "manual_resolved"} and device.get("canonical_name"):
        return 3
    fingerprints = [str(f).lower() for f in (device.get("fingerprints") or [])]
    if any(fp.startswith(prefix) for fp in fingerprints for prefix in _ADVERTISED_IDENTITY_PREFIXES):
        return 2
    manufacturer = str(device.get("manufacturer") or "").strip().lower()
    if manufacturer and manufacturer not in _GENERIC_MANUFACTURERS:
        return 1
    return 0


def _real_mac(device: dict[str, Any]) -> str | None:
    """실제 하드웨어 MAC 만 반환한다. Android 가 MAC 을 못 얻어 만든 합성값('UNKNOWN-<ip>')은 None.
    병합에서 '서로 다른 물리 기기'를 판별하는 근거로만 쓴다(합성 MAC 은 판별 불가)."""
    return normalized_physical_mac(device.get("mac_address"))


def _merge_observation_key(device: dict[str, Any]) -> str | None:
    """Stable physical-observation key for cross-scan retention.

    DHCP can move one IoT device between IP addresses.  A real MAC is the
    stronger key; an IP is only the fallback when the platform cannot expose
    a MAC.  Synthetic ``UNKNOWN-*`` values are deliberately ignored so they
    cannot make two unrelated hosts look like one device.
    """
    mac = _real_mac(device)
    if mac:
        return f"mac:{mac}"
    ip = str(device.get("ip_address") or "").strip()
    if ip:
        return f"ip:{ip}"
    raw_id = str(device.get("device_id") or "").strip()
    return f"id:{raw_id}" if raw_id else None


def _different_physical_device(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """두 스냅샷이 *확실히* 다른 물리 기기인가. 둘 다 실제 MAC 이 있고 서로 다를 때만 True.
    한쪽이라도 MAC 미상이면 판별 불가이므로 False(같은 기기로 간주해 기존 stickiness 유지).
    근거: 같은 IP 라도 real MAC 이 다르면 DHCP 가 IP 를 다른 기기에 재할당한 것이다(IP 재사용)."""
    ma, mb = _real_mac(a), _real_mac(b)
    return ma is not None and mb is not None and ma != mb


def merge_latest_observed_scans(
    valid_scans: list[tuple[str, str | None, dict[str, Any], list[dict[str, Any]]]],
) -> list[dict[str, Any]] | None:
    """Build the current device view from valid scans without crossing networks.

    Membership always comes only from the newest valid scan.  Historical
    identity/firmware enrichment is permitted only when the newest scan and
    the older evidence share one gateway/BSSID-backed scope *and* one real MAC.
    Subnet-only and legacy rows deliberately fail closed to latest-only because
    common private CIDRs cannot distinguish different physical networks.
    """

    if not valid_scans:
        return None

    retain_window = timedelta(hours=24)
    max_scans = 20
    latest_created = _parse_iso(valid_scans[0][0])
    latest_scope_id = valid_scans[0][1]
    windowed: list[list[dict[str, Any]]] = [valid_scans[0][3]]

    if is_strong_network_scope_id(latest_scope_id):
        for created_at, network_scope_id, _network_context, devices in valid_scans[1:max_scans]:
            if network_scope_id != latest_scope_id:
                continue
            scan_time = _parse_iso(created_at)
            if latest_created and scan_time and latest_created - scan_time > retain_window:
                continue
            windowed.append(devices)

    latest_devices = windowed[0]
    latest_keys = {
        key
        for device in latest_devices
        if (key := _merge_observation_key(device)) is not None
    }
    snaps_by_key: dict[str, list[dict[str, Any]]] = {}
    key_order: list[str] = []
    for devices in windowed:
        for device in devices:
            merge_key = _merge_observation_key(device)
            if not merge_key:
                continue
            if merge_key not in snaps_by_key:
                snaps_by_key[merge_key] = []
                key_order.append(merge_key)
            snaps_by_key[merge_key].append(device)

    merged: dict[str, dict[str, Any]] = {}
    for merge_key in key_order:
        if merge_key not in latest_keys:
            continue
        snaps = snaps_by_key[merge_key]
        current = snaps[0]
        device = dict(current)

        # An address/device-id fallback can establish current membership, but
        # it cannot prove physical continuity.  Only a real MAC may authorize
        # old product identity or firmware evidence.
        same_device_snaps = (
            [snap for snap in snaps if not _different_physical_device(snap, current)]
            if merge_key.startswith("mac:")
            else [current]
        )
        # Historical identity may enrich current membership only after the
        # central exact-product validator accepts it.  Legacy rows that merely
        # claimed ``resolved`` (room names, family words or generic models)
        # must not outrank a current unresolved observation.  Operator-approved
        # identities are projected separately from their audited resolved job;
        # a snapshot flag alone is never sufficient provenance.
        trusted_identity_snaps = [
            current,
            *[
                snap
                for snap in same_device_snaps[1:]
                if verified_catalog_marker_identity(snap) is not None
            ],
        ]
        best = max(trusted_identity_snaps, key=_identity_strength)
        if _identity_strength(best) > _identity_strength(current):
            for field in (
                "name",
                "manufacturer",
                "model",
                "device_type",
                "canonical_name",
                "identity_status",
                "identity_resolver_version",
                "identity_note",
                "identity_confidence",
            ):
                if best.get(field):
                    device[field] = best[field]
            for field in ("identity_candidates", "identity_evidence"):
                if isinstance(best.get(field), list) and best[field]:
                    device[field] = best[field]
            if best.get("fingerprints"):
                device["fingerprints"] = best["fingerprints"]
            # Historical rows may enrich identity, never current membership.
            # In particular, a fresh read-boundary classification of the
            # newest row as refusal-only/stale-ARP phantom must survive even
            # when an older same-MAC snapshot has an exact catalog product.
            # Copying or popping ``is_phantom`` here revives an absent device.
            for field in ("is_unresolved",):
                if best.get(field):
                    device[field] = best[field]
                else:
                    device.pop(field, None)
            if best.get("is_resolved") is True:
                device["is_resolved"] = True

        if str(device.get("firmware") or "").strip().lower() in ("", "unknown"):
            for snap in same_device_snaps:
                snap_firmware = str(snap.get("firmware") or "").strip()
                if snap_firmware and snap_firmware.lower() != "unknown":
                    device["firmware"] = snap_firmware
                    break
        device["online"] = True
        merged[merge_key] = device

    return list(merged.values()) if merged else None


def guess_device_type(open_ports: list[int], risk_signals: list[str] | None = None) -> str:
    risk_signals = risk_signals or []
    port_set = set(open_ports)
    if 554 in port_set or 3702 in port_set or "camera_candidate" in risk_signals:
        return "camera"
    if {53, 80}.issubset(port_set) or {53, 443}.issubset(port_set):
        return "router"
    if 23 in port_set:
        return "iot"
    if port_set.intersection({80, 443, 8080, 8443}):
        return "web-device"
    return "unknown"


def guess_device_name(ip_address: str, device_type: str) -> str:
    # Compatibility shim for old imports.  Product names are assigned by the
    # server identity resolver after evidence/catalog matching; this helper
    # must never manufacture a resident-facing label from an address or port.
    del ip_address, device_type
    return ""


def service_names(open_ports: list[int]) -> list[str]:
    names = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        53: "dns",
        80: "http",
        443: "https",
        554: "rtsp",
        1900: "upnp",
        3702: "onvif",
        8080: "http-alt",
        8443: "https-alt",
        8899: "iot-camera",
    }
    return [names.get(port, f"tcp-{port}") for port in open_ports]


class SQLiteRepository:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self._lock = RLock()
        self._initialize()

    def user_by_id(self, user_id: str) -> dict[str, Any] | None:
        row = self._fetch_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
        if row is None:
            return None
        return self._user_from_row(row)

    def upsert_user(self, user: dict[str, Any]) -> dict[str, Any]:
        user_id = str(user.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required")
        home_id = str(user.get("home_id") or default_home_id_for_user(user_id)).strip()
        email = str(user.get("email") or "").strip()
        nickname = str(user.get("nickname") or user.get("name") or "").strip()
        if not home_id or not email or not nickname:
            raise ValueError("user_id, email, nickname and home_id are required")
        values = {
            "user_id": user_id,
            "email": email,
            "nickname": nickname,
            "role": str(user.get("role") or "user").strip(),
            "email_verified": int(bool(user.get("email_verified", True))),
            "home_id": home_id,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (user_id, email, nickname, role, email_verified, home_id)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    email = excluded.email,
                    nickname = excluded.nickname,
                    role = excluded.role,
                    email_verified = excluded.email_verified,
                    home_id = excluded.home_id
                """,
                (
                    values["user_id"],
                    values["email"],
                    values["nickname"],
                    values["role"],
                    values["email_verified"],
                    values["home_id"],
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO homes (home_id, name, mode) VALUES (?, ?, ?)",
                (home_id, "우리집", HOME["mode"]),
            )
        stored = self.user_by_id(user_id)
        if stored is None:
            raise RuntimeError("user upsert did not persist")
        return stored

    def _stored_devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        latest_scan_devices = self._latest_observed_scan_devices(home_id=home_id)
        if latest_scan_devices is not None:
            return self._apply_aliases(
                [device for device in latest_scan_devices if not is_self_observation(device)],
                home_id,
            )

        return []

    def devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        return self._public_devices(self._stored_devices(home_id))

    def latest_scan_context(self, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        """Return the newest valid Android scan context for server-side policy."""

        scans = self._fetch_all(
            """
            SELECT scan_id, network_context_json, network_scope_id
            FROM scans
            WHERE home_id = ? AND scan_source = 'android-native'
            ORDER BY created_at DESC
            """,
            (home_id,),
        )
        for scan in scans:
            rows = self._fetch_all(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan["scan_id"],),
            )
            devices = [json.loads(row["device_snapshot_json"]) for row in rows]
            bounded = _validated_authoritative_snapshot(
                json.loads(scan["network_context_json"] or "{}"),
                devices,
            )
            if bounded is None:
                continue
            context, _bounded_devices = bounded
            return context
        return None

    def _latest_scan_devices_only(self, home_id: str) -> list[dict[str, Any]] | None:
        """Return snapshots from the newest valid Android scan, without history merge."""
        scans = self._fetch_all(
            """
            SELECT scan_id, network_context_json, network_scope_id
            FROM scans
            WHERE home_id = ? AND scan_source = 'android-native'
            ORDER BY created_at DESC
            """,
            (home_id,),
        )
        for scan in scans:
            rows = self._fetch_all(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan["scan_id"],),
            )
            devices = [json.loads(row["device_snapshot_json"]) for row in rows]
            bounded = _validated_authoritative_snapshot(
                json.loads(scan["network_context_json"] or "{}"),
                devices,
            )
            if bounded is None:
                continue
            _network_context, devices = bounded
            devices = apply_verified_product_catalog_projection(
                devices,
                self.verified_product_catalog_entries(),
            )
            devices = self._apply_approved_manual_identities(
                devices,
                home_id=home_id,
                network_scope_id=scan["network_scope_id"],
            )
            return self._apply_aliases(
                [device for device in devices if not is_self_observation(device)],
                home_id,
                network_scope_id=scan["network_scope_id"],
                observed_scope_supplied=True,
            )
        return None

    def identity_findings(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        """Return detected observations that still need server identity enrichment."""
        # Identity findings describe the latest valid observation window only.
        # Historical unresolved rows remain in the private resolver history but
        # must not accumulate into the resident's current device count.
        latest = self._latest_scan_devices_only(home_id)
        devices = self._stored_devices(home_id) if latest is None else latest
        return build_public_identity_findings(devices, self.devices(home_id=home_id))

    def identity_history(
        self,
        device_id: str | None = None,
        home_id: str = HOME["home_id"],
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return server resolver attempts for diagnostics/guardian audit."""
        bounded_limit = max(1, min(int(limit), 200))
        requested_public_id: str | None = None
        if device_id:
            stored_id = self._resolve_stored_device_id(device_id, home_id) or device_id
            requested_public_id = public_device_id(stored_id, home_id)
            has_observed_scan, active_scope = self._latest_valid_network_scope(home_id)
            current_devices = self._latest_observed_scan_devices(home_id) or []
            current = next(
                (
                    item
                    for item in current_devices
                    if str(item.get("device_id") or "") == stored_id
                    or public_device_id(item.get("device_id"), home_id) == device_id
                ),
                None,
            )
            current_mac = normalized_physical_mac((current or {}).get("mac_address"))
            if current_mac in _ambiguous_physical_macs(current_devices):
                current_mac = None
            if not (
                current is not None
                and has_observed_scan
                and is_strong_network_scope_id(active_scope)
            ):
                return []
            if current_mac:
                rows = self._fetch_all(
                    """
                    SELECT * FROM device_identity_history
                    WHERE home_id = ? AND network_scope_id = ? AND upper(physical_mac) = ?
                    ORDER BY observed_at DESC LIMIT ?
                    """,
                    (home_id, active_scope, current_mac, bounded_limit),
                )
            else:
                # Randomized/unavailable MACs cannot prove continuity across
                # scans. The current validated snapshot plus strong home scope
                # permits only its newest same-scope resolver attempt.
                rows = self._fetch_all(
                    """
                    SELECT * FROM device_identity_history
                    WHERE home_id = ? AND network_scope_id = ? AND device_id IN (?, ?)
                    ORDER BY observed_at DESC LIMIT 1
                    """,
                    (home_id, active_scope, device_id, stored_id),
                )
        else:
            rows = self._fetch_all(
                """
                SELECT * FROM device_identity_history
                WHERE home_id = ?
                ORDER BY observed_at DESC LIMIT ?
                """,
                (home_id, bounded_limit),
            )
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "resolution_id": row["resolution_id"],
                    "home_id": row["home_id"],
                    "device_id": requested_public_id or public_device_id(row["device_id"], home_id),
                    "observed_at": row["observed_at"],
                    "identity_status": row["identity_status"],
                    "manufacturer": row["manufacturer"],
                    "device_type": row["device_type"],
                    "model": row["model"],
                    "canonical_name": row["canonical_name"],
                    "confidence": row["confidence"],
                    "identity_evidence": json.loads(row["evidence_json"]),
                    "identity_candidates": json.loads(row["candidates_json"]),
                    "identity_note": row["note"],
                    "resolver_version": row["resolver_version"],
                }
            )
        return result

    @staticmethod
    def _identity_enrichment_job_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        data = sqlite_row_to_dict(row)
        if data is None:
            return None
        try:
            evidence = json.loads(data.get("evidence_json") or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            evidence = {}
        try:
            resolution = json.loads(data.get("resolution_json") or "null")
        except (TypeError, ValueError, json.JSONDecodeError):
            resolution = None
        return {
            **data,
            "evidence": evidence if isinstance(evidence, dict) else {},
            "resolution": resolution if isinstance(resolution, dict) else None,
        }

    def _upsert_identity_enrichment_jobs(
        self,
        devices: list[dict[str, Any]],
        *,
        home_id: str,
        network_scope_id: str | None,
        ambiguity_devices: list[dict[str, Any]] | None = None,
    ) -> None:
        strong_scope = network_scope_id if is_strong_network_scope_id(network_scope_id) else None
        now = utc_now()
        prepared_jobs = _prepare_identity_enrichment_jobs(
            devices,
            home_id=home_id,
            network_scope_id=strong_scope,
            ambiguity_devices=ambiguity_devices,
        )
        active_job_keys = {
            str(prepared["job_key"]) for prepared in prepared_jobs
        }
        with self._lock, self._connect() as conn:
            if conn.execute(
                "SELECT 1 FROM homes JOIN users ON users.home_id = homes.home_id "
                "WHERE homes.home_id = ? LIMIT 1",
                (home_id,),
            ).fetchone() is None:
                raise ValueError("authenticated home does not exist")
            # Materialize every current canonical key before closing legacy
            # keys.  This ordering keeps an active replacement in the same
            # transaction even when the key format changed between releases.
            for prepared in prepared_jobs:
                device = prepared["device"]
                physical_mac = prepared["physical_mac"]
                evidence = prepared["evidence"]
                evidence_binding_signature = prepared["evidence_binding_signature"]
                job_key = str(prepared["job_key"])
                blocked_reason = prepared["blocked_reason"]
                status_value = str(prepared["status"])
                evidence_json = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
                conn.execute(
                    """
                    INSERT INTO identity_enrichment_jobs (
                        job_id, job_key, home_id, device_id, network_scope_id,
                        physical_mac, evidence_binding_signature, status,
                        blocked_reason, evidence_json,
                        evidence_signature, seen_count, first_seen_at,
                        last_seen_at, updated_at, resolution_json,
                        source_reference, resolution_provenance,
                        resolution_signature, research_attempt_count,
                        research_last_attempt_at, research_next_attempt_at,
                        resolved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL)
                    ON CONFLICT(job_key) DO UPDATE SET
                        device_id = excluded.device_id,
                        network_scope_id = excluded.network_scope_id,
                        physical_mac = excluded.physical_mac,
                        evidence_binding_signature = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_binding_signature
                            ELSE excluded.evidence_binding_signature
                        END,
                        status = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.status
                            ELSE excluded.status
                        END,
                        blocked_reason = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.blocked_reason
                            ELSE excluded.blocked_reason
                        END,
                        evidence_json = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_json
                            ELSE excluded.evidence_json
                        END,
                        evidence_signature = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_signature
                            ELSE excluded.evidence_signature
                        END,
                        research_attempt_count = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_attempt_count
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN 0
                            ELSE identity_enrichment_jobs.research_attempt_count
                        END,
                        research_last_attempt_at = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_last_attempt_at
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN NULL
                            ELSE identity_enrichment_jobs.research_last_attempt_at
                        END,
                        research_next_attempt_at = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_next_attempt_at
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN NULL
                            ELSE identity_enrichment_jobs.research_next_attempt_at
                        END,
                        seen_count = identity_enrichment_jobs.seen_count + 1,
                        last_seen_at = excluded.last_seen_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        f"identity-job-{uuid4()}",
                        job_key,
                        home_id,
                        str(device.get("device_id") or ""),
                        strong_scope,
                        physical_mac,
                        evidence_binding_signature,
                        status_value,
                        blocked_reason,
                        evidence_json,
                        build_evidence_signature(evidence),
                        now,
                        now,
                        now,
                    ),
                )
            if active_job_keys:
                placeholders = ",".join("?" for _ in active_job_keys)
                conn.execute(
                    f"""
                    UPDATE identity_enrichment_jobs
                    SET status = 'superseded', blocked_reason = 'NOT_IN_LATEST_SCAN',
                        research_next_attempt_at = NULL, updated_at = ?
                    WHERE home_id = ? AND status IN ('review_required', 'blocked')
                      AND job_key NOT IN ({placeholders})
                    """,
                    (now, home_id, *sorted(active_job_keys)),
                )
            else:
                conn.execute(
                    """
                    UPDATE identity_enrichment_jobs
                    SET status = 'superseded', blocked_reason = 'NOT_IN_LATEST_SCAN',
                        research_next_attempt_at = NULL, updated_at = ?
                    WHERE home_id = ? AND status IN ('review_required', 'blocked')
                    """,
                    (now, home_id),
                )

    def identity_enrichment_jobs(
        self,
        *,
        status_filter: str | None = None,
        limit: int = 100,
        home_id: str | None = None,
    ) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 200))
        if status_filter and home_id:
            rows = self._fetch_all(
                "SELECT * FROM identity_enrichment_jobs WHERE status = ? AND home_id = ? "
                "ORDER BY updated_at DESC LIMIT ?",
                (status_filter, home_id, bounded_limit),
            )
        elif status_filter:
            rows = self._fetch_all(
                "SELECT * FROM identity_enrichment_jobs WHERE status = ? "
                "ORDER BY updated_at DESC LIMIT ?",
                (status_filter, bounded_limit),
            )
        elif home_id:
            rows = self._fetch_all(
                "SELECT * FROM identity_enrichment_jobs WHERE home_id = ? "
                "ORDER BY updated_at DESC LIMIT ?",
                (home_id, bounded_limit),
            )
        else:
            rows = self._fetch_all(
                "SELECT * FROM identity_enrichment_jobs ORDER BY updated_at DESC LIMIT ?",
                (bounded_limit,),
            )
        return [
            job
            for row in rows
            if (job := self._identity_enrichment_job_from_row(row)) is not None
        ]

    def identity_research_due_home_ids(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
    ) -> list[str]:
        """Return every due home fairly, independent of the per-job API window."""

        bounded_limit = max(1, min(int(limit), 2000))
        bounded_offset = max(0, int(offset))
        now = utc_now()
        rows = self._fetch_all(
            """
            WITH home_activity AS (
                SELECT home_id,
                       CASE WHEN MAX(research_last_attempt_at) IS NULL THEN 0 ELSE 1 END
                           AS attempted_rank,
                       MAX(research_last_attempt_at) AS last_processed_at,
                       MIN(first_seen_at) AS oldest_at
                FROM identity_enrichment_jobs
                WHERE status = 'review_required'
                GROUP BY home_id
            ), due_homes AS (
                SELECT DISTINCT home_id
                FROM identity_enrichment_jobs
                WHERE status = 'review_required'
                  AND (research_next_attempt_at IS NULL OR research_next_attempt_at <= ?)
            )
            SELECT home_activity.home_id, attempted_rank, last_processed_at, oldest_at
            FROM home_activity
            JOIN due_homes ON due_homes.home_id = home_activity.home_id
            ORDER BY attempted_rank ASC,
                     COALESCE(last_processed_at, oldest_at) ASC,
                     oldest_at ASC, home_activity.home_id ASC
            LIMIT ? OFFSET ?
            """,
            (now, bounded_limit, bounded_offset),
        )
        return [str(row["home_id"]) for row in rows if str(row["home_id"] or "").strip()]

    def identity_research_due_jobs(
        self,
        *,
        home_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Page due jobs in the exact oldest-first claim order."""

        bounded_limit = max(1, min(int(limit), 200))
        bounded_offset = max(0, int(offset))
        rows = self._fetch_all(
            """
            SELECT * FROM identity_enrichment_jobs
            WHERE home_id = ? AND status = 'review_required'
              AND (research_next_attempt_at IS NULL OR research_next_attempt_at <= ?)
            ORDER BY COALESCE(research_last_attempt_at, first_seen_at) ASC,
                     first_seen_at ASC, job_id ASC
            LIMIT ? OFFSET ?
            """,
            (home_id, utc_now(), bounded_limit, bounded_offset),
        )
        return [
            job
            for row in rows
            if (job := self._identity_enrichment_job_from_row(row)) is not None
        ]

    @staticmethod
    def _verified_product_catalog_row(row: sqlite3.Row | None) -> dict[str, str] | None:
        if row is None:
            return None
        entry = {key: str(row[key] or "") for key in row.keys()}
        return entry if verified_product_catalog_entry_matches(entry) else None

    @staticmethod
    def _register_verified_product_catalog(
        conn: sqlite3.Connection,
        *,
        validated: Mapping[str, Any],
        provenance: str,
        verified_at: str,
    ) -> dict[str, str]:
        entry = build_verified_product_catalog_entry(
            manufacturer=validated.get("manufacturer"),
            device_type=validated.get("device_type"),
            exact_model=validated.get("model"),
            source_url=validated.get("source_reference"),
            provenance=provenance,
            verified_at=verified_at,
        )
        existing_row = conn.execute(
            "SELECT * FROM verified_product_catalog "
            "WHERE manufacturer_key = ? AND model_key = ?",
            (entry["manufacturer_key"], entry["model_key"]),
        ).fetchone()
        existing = SQLiteRepository._verified_product_catalog_row(existing_row)
        if existing is not None:
            if existing["device_type"] != entry["device_type"]:
                raise IdentityEnrichmentError("IDENTITY_CATALOG_CONFLICT")
            # A second official URL or a repeated resolution is useful in the
            # per-device audit history, but it must not churn the global fact.
            return existing
        if existing_row is not None:
            # A row with an invalid HMAC is not product evidence. Replace it
            # only while writing a newly validated, signed product fact.
            conn.execute(
                "DELETE FROM verified_product_catalog "
                "WHERE manufacturer_key = ? AND model_key = ?",
                (entry["manufacturer_key"], entry["model_key"]),
            )
        conn.execute(
            """
            INSERT INTO verified_product_catalog (
                manufacturer, manufacturer_key, exact_model, model_key,
                device_type, source_url, provenance, verified_at,
                catalog_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(
                entry[field]
                for field in (
                    "manufacturer",
                    "manufacturer_key",
                    "exact_model",
                    "model_key",
                    "device_type",
                    "source_url",
                    "provenance",
                    "verified_at",
                    "catalog_signature",
                )
            ),
        )
        return entry

    def verified_product_catalog_entries(self) -> list[dict[str, str]]:
        """Return only HMAC-verified global product facts.

        The method is intentionally unscoped: catalog rows contain no home,
        device or network identifiers and are reusable across observations.
        """

        rows = self._fetch_all(
            "SELECT * FROM verified_product_catalog "
            "ORDER BY manufacturer_key, model_key"
        )
        return [
            entry
            for row in rows
            if (entry := self._verified_product_catalog_row(row)) is not None
        ]

    def resolve_identity_enrichment_job(
        self,
        job_id: str,
        *,
        manufacturer: str,
        device_type: str,
        model: str,
        source_reference: str,
        resolution_provenance: str = IDENTITY_RESOLUTION_PROVENANCE_OPERATOR,
        expected_evidence_signature: str | None = None,
        expected_job_key: str | None = None,
        _propagate_catalog: bool = True,
        _catalog_reuse: bool = False,
        _device_scoped: bool = False,
    ) -> dict[str, Any]:
        if resolution_provenance not in IDENTITY_RESOLUTION_PROVENANCES:
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        if _device_scoped and (
            resolution_provenance != IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP
            or _propagate_catalog
            or _catalog_reuse
        ):
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        validated = validate_identity_resolution(
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=source_reference,
        )
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM identity_enrichment_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_FOUND")
            if job.get("status") == "resolved":
                raise IdentityEnrichmentError("IDENTITY_JOB_ALREADY_RESOLVED")
            if job.get("status") == "blocked":
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if job.get("status") != "review_required":
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_REVIEWABLE")
            if not identity_job_key_matches(job):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            network_scope_id = (
                str(job.get("network_scope_id") or "")
                if is_strong_network_scope_id(job.get("network_scope_id"))
                else None
            )
            physical_mac = normalized_physical_mac(job.get("physical_mac"))
            evidence = job.get("evidence") or {}
            if blocked_binding_reason(
                network_scope_id,
                physical_mac,
                evidence,
                device_id=job.get("device_id"),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if not evidence_signature_matches(evidence, job.get("evidence_signature")):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            current_signature = str(job.get("evidence_signature") or "")
            if expected_evidence_signature is not None and not hmac.compare_digest(
                current_signature,
                str(expected_evidence_signature),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            current_job_key = str(job.get("job_key") or "")
            if expected_job_key is not None and not hmac.compare_digest(
                current_job_key,
                str(expected_job_key),
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")

            # Android Build fields are useful only for this server-attested
            # physical observation.  They are not a globally reusable product
            # fact.  Reuse the research eligibility verifier so the ordinary
            # resolver cannot accidentally promote an authenticated-self job
            # into ``verified_product_catalog``.
            from ..services.identity_research import (
                _eligible_job,
                _requires_device_scoped_resolution,
            )

            eligible_job = _eligible_job(job)
            has_authenticated_self_evidence = any(
                isinstance(proof, Mapping)
                and str(proof.get("source") or "").strip().casefold()
                == "authenticated-self-android"
                for proof in evidence.get("structured_provenance") or []
            )
            eligible_requires_device_scope = (
                eligible_job is not None
                and _requires_device_scoped_resolution(eligible_job)
            )
            if has_authenticated_self_evidence != _device_scoped or (
                _device_scoped and not eligible_requires_device_scope
            ):
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            if _device_scoped:
                safe_evidence = eligible_job.get("evidence") or {}

                def normalized(value: object) -> str:
                    return " ".join(str(value or "").strip().casefold().split())

                exact_hints = {
                    "manufacturer": {
                        normalized(value)
                        for value in safe_evidence.get("manufacturer_hints") or []
                    },
                    "model": {
                        normalized(value)
                        for value in safe_evidence.get("model_hints") or []
                    },
                    "device_type": {
                        normalized(value)
                        for value in safe_evidence.get("device_type_hints") or []
                    },
                }
                if any(
                    normalized(validated[field]) not in exact_hints[field]
                    for field in ("manufacturer", "model", "device_type")
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
                authenticated_proofs = {
                    (
                        str(proof.get("kind") or "").strip().casefold(),
                        normalized(proof.get("value")),
                    )
                    for proof in eligible_job.get("corroboration") or []
                    if isinstance(proof, Mapping)
                    and str(proof.get("source") or "").strip().casefold()
                    == "authenticated-self-android"
                }
                if any(
                    (field, normalized(validated[field])) not in authenticated_proofs
                    for field in ("manufacturer", "model", "device_type")
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")

            if is_automated_identity_resolution_provenance(resolution_provenance):
                normalized_model = " ".join(validated["model"].casefold().split())
                advertised_models = {
                    " ".join(str(value or "").casefold().split())
                    for value in evidence.get("model_hints") or []
                }
                if normalized_model not in advertised_models or not (
                    source_matches_registered_official_domain(
                        validated["source_reference"],
                        validated["manufacturer"],
                    )
                ):
                    raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")

            now = utc_now()
            resolution_id = (
                f"identity-auto-{uuid4()}"
                if is_automated_identity_resolution_provenance(resolution_provenance)
                else f"identity-review-{uuid4()}"
            )
            resolution = {
                **{key: validated[key] for key in ("manufacturer", "device_type", "model", "canonical_name")},
                "history_resolution_id": resolution_id,
                "resolution_provenance": resolution_provenance,
            }
            if _catalog_reuse:
                resolution["catalog_reused"] = True
            if _device_scoped:
                resolution["device_scoped"] = True
            resolution_signature = build_resolution_signature(
                job_key=current_job_key,
                evidence_signature=current_signature,
                resolution=resolution,
                source_reference=validated["source_reference"],
                resolution_provenance=resolution_provenance,
            )
            if not _device_scoped:
                self._register_verified_product_catalog(
                    conn,
                    validated=validated,
                    provenance=resolution_provenance,
                    verified_at=now,
                )
            updated = conn.execute(
                """
                UPDATE identity_enrichment_jobs
                SET status = 'resolved', blocked_reason = NULL,
                    resolution_json = ?, source_reference = ?,
                    resolution_provenance = ?, resolution_signature = ?,
                    resolved_at = ?, updated_at = ?
                WHERE job_id = ? AND status = 'review_required'
                    AND evidence_signature = ? AND job_key = ?
                """,
                (
                    json.dumps(resolution, ensure_ascii=False, sort_keys=True),
                    validated["source_reference"],
                    resolution_provenance,
                    resolution_signature,
                    now,
                    now,
                    job_id,
                    current_signature,
                    current_job_key,
                ),
            )
            if updated.rowcount != 1:
                raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
            conn.execute(
                """
                INSERT INTO device_identity_history (
                    resolution_id, home_id, device_id, network_scope_id,
                    physical_mac, observed_at, identity_status, manufacturer,
                    device_type, model, canonical_name, confidence,
                    evidence_json, candidates_json, note, resolver_version
                ) VALUES (?, ?, ?, ?, ?, ?, 'manual_resolved', ?, ?, ?, ?, 1.0, ?, '[]', ?, ?)
                """,
                (
                    resolution_id,
                    job["home_id"],
                    job["device_id"],
                    network_scope_id,
                    physical_mac,
                    now,
                    validated["manufacturer"],
                    validated["device_type"],
                    validated["model"],
                    validated["canonical_name"],
                    json.dumps(
                        [
                            *resolution_history_evidence(job_id, resolution_provenance),
                            *(["verified-product-catalog-reuse"] if _catalog_reuse else []),
                            *(
                                ["device-scoped:authenticated-self-android"]
                                if _device_scoped
                                else []
                            ),
                        ],
                        ensure_ascii=False,
                    ),
                    (
                        "서버의 서명된 제품 카탈로그와 현재 장치의 구조화 단서가 정확히 일치한 재확인 결과입니다."
                        if _catalog_reuse
                        else "공식 제조사 웹 인용과 수집 단서가 정확히 일치한 자동 확인 결과입니다."
                        if is_automated_identity_resolution_provenance(
                            resolution_provenance
                        )
                        else "공식 출처를 확인한 운영자 검토 결과입니다."
                    ),
                    IDENTITY_ENRICHMENT_RESOLVER_VERSION,
                ),
            )
            resolved_row = conn.execute(
                "SELECT * FROM identity_enrichment_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            resolved = self._identity_enrichment_job_from_row(resolved_row)
            assert resolved is not None
        if _propagate_catalog:
            self.reconcile_verified_product_catalog_jobs()
        return resolved

    def resolve_device_scoped_identity_job(
        self,
        job_id: str,
        *,
        manufacturer: str,
        device_type: str,
        model: str,
        source_reference: str,
        resolution_provenance: str = IDENTITY_RESOLUTION_PROVENANCE_AUTOMATED_HTTP,
        expected_evidence_signature: str | None = None,
        expected_job_key: str | None = None,
    ) -> dict[str, Any]:
        """Resolve one L2-attested Android self job without catalog promotion."""

        return self.resolve_identity_enrichment_job(
            job_id,
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=source_reference,
            resolution_provenance=resolution_provenance,
            expected_evidence_signature=expected_evidence_signature,
            expected_job_key=expected_job_key,
            _propagate_catalog=False,
            _catalog_reuse=False,
            _device_scoped=True,
        )

    def reconcile_verified_product_catalog_jobs(
        self,
        *,
        limit: int = 200,
        should_stop: Callable[[], bool] | None = None,
    ) -> int:
        """Resolve safely matching queue rows from the signed global catalog.

        Only job/history state changes.  Scan membership and snapshots are
        never inserted, deleted, merged or rewritten.  ``limit`` bounds rows
        inspected, not merely page size.  Unmatched rows are durably marked for
        the exact signed catalog version so the next run continues forward.
        """

        catalog_entries = self.verified_product_catalog_entries()
        catalog_version = verified_catalog_reconcile_version(catalog_entries)
        if not catalog_entries or catalog_version is None:
            return 0
        bounded_limit = max(1, min(int(limit), 2000))
        rows = self._fetch_all(
            "SELECT * FROM identity_enrichment_jobs "
            "WHERE status = 'review_required' "
            "AND COALESCE(catalog_reconcile_version, '') <> ? "
            "ORDER BY first_seen_at, job_id LIMIT ?",
            (catalog_version, bounded_limit),
        )
        resolved_count = 0
        checked_without_match: list[tuple[str, str, str]] = []
        for row in rows:
            if should_stop is not None and should_stop():
                break
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                continue
            resolution = verified_catalog_resolution_for_job(job, catalog_entries)
            if resolution is None:
                checked_without_match.append(
                    (
                        str(job.get("job_id") or ""),
                        str(job.get("evidence_signature") or ""),
                        str(job.get("job_key") or ""),
                    )
                )
                continue
            try:
                self.resolve_identity_enrichment_job(
                    str(job["job_id"]),
                    manufacturer=resolution["manufacturer"],
                    device_type=resolution["device_type"],
                    model=resolution["model"],
                    source_reference=resolution["source_reference"],
                    resolution_provenance=resolution["resolution_provenance"],
                    expected_evidence_signature=str(job.get("evidence_signature") or ""),
                    expected_job_key=str(job.get("job_key") or ""),
                    _propagate_catalog=False,
                    _catalog_reuse=True,
                )
            except IdentityEnrichmentError:
                continue
            resolved_count += 1
        if checked_without_match:
            with self._lock, self._connect() as conn:
                for job_id, evidence_signature, job_key in checked_without_match:
                    conn.execute(
                        "UPDATE identity_enrichment_jobs "
                        "SET catalog_reconcile_version = ? "
                        "WHERE job_id = ? AND status = 'review_required' "
                        "AND evidence_signature = ? AND job_key = ? "
                        "AND COALESCE(catalog_reconcile_version, '') <> ?",
                        (
                            catalog_version,
                            job_id,
                            evidence_signature,
                            job_key,
                            catalog_version,
                        ),
                    )
        return resolved_count

    def reset_identity_research_backoff_for_version(self, version: str) -> int:
        """Grant each valid unresolved job one immediate retry per policy version.

        Attempt counters and the last-attempt audit timestamp are preserved;
        only the future eligibility time is cleared.  The per-row marker makes
        repeated service restarts a no-op for the same policy release.
        """

        normalized_version = str(version or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{5,127}", normalized_version):
            raise ValueError("invalid identity research policy version")
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM identity_enrichment_jobs "
                "WHERE status = 'review_required' "
                "AND COALESCE(research_policy_version, '') <> ?",
                (normalized_version,),
            ).fetchall()
            updated_count = 0
            now = utc_now()
            for row in rows:
                job = self._identity_enrichment_job_from_row(row)
                evidence = (job or {}).get("evidence")
                if not isinstance(job, Mapping) or not isinstance(evidence, Mapping):
                    continue
                if (
                    blocked_binding_reason(
                        str(job.get("network_scope_id") or "") or None,
                        str(job.get("physical_mac") or "") or None,
                        evidence,
                        device_id=job.get("device_id"),
                    )
                    is not None
                    or not identity_job_key_matches(job)
                    or not evidence_signature_matches(
                        evidence, job.get("evidence_signature")
                    )
                ):
                    continue
                updated = conn.execute(
                    """
                    UPDATE identity_enrichment_jobs
                    SET research_next_attempt_at = NULL,
                        research_policy_version = ?, updated_at = ?
                    WHERE job_id = ? AND status = 'review_required'
                      AND evidence_signature = ? AND job_key = ?
                      AND COALESCE(research_policy_version, '') <> ?
                    """,
                    (
                        normalized_version,
                        now,
                        job["job_id"],
                        job["evidence_signature"],
                        job["job_key"],
                        normalized_version,
                    ),
                )
                updated_count += int(updated.rowcount == 1)
        return updated_count

    def claim_identity_research_jobs(
        self,
        *,
        home_id: str,
        limit: int = 8,
        job_ids: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Fairly claim due jobs and persist exponential backoff before I/O."""

        bounded_limit = max(1, min(int(limit), 8))
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat().replace("+00:00", "Z")
        selected_ids = tuple(
            dict.fromkeys(
                str(value or "").strip()
                for value in (job_ids or ())
                if str(value or "").strip()
            )
        )[:200]
        if job_ids is not None and not selected_ids:
            return []
        claimed: list[dict[str, Any]] = []
        with self._lock, self._connect() as conn:
            selected_clause = ""
            selected_parameters: tuple[Any, ...] = ()
            if selected_ids:
                selected_clause = " AND job_id IN (" + ",".join("?" for _ in selected_ids) + ")"
                selected_parameters = selected_ids
            rows = conn.execute(
                f"""
                SELECT * FROM identity_enrichment_jobs
                WHERE home_id = ? AND status = 'review_required'
                  AND (research_next_attempt_at IS NULL OR research_next_attempt_at <= ?)
                  {selected_clause}
                ORDER BY COALESCE(research_last_attempt_at, first_seen_at) ASC,
                         first_seen_at ASC, job_id ASC
                LIMIT ?
                """,
                (home_id, now, *selected_parameters, bounded_limit),
            ).fetchall()
            for row in rows:
                attempts = max(0, int(row["research_attempt_count"] or 0)) + 1
                delay_seconds = min(6 * 60 * 60, 60 * (2 ** min(attempts - 1, 8)))
                next_attempt = (now_dt + timedelta(seconds=delay_seconds)).isoformat().replace(
                    "+00:00", "Z"
                )
                updated = conn.execute(
                    """
                    UPDATE identity_enrichment_jobs
                    SET research_attempt_count = ?, research_last_attempt_at = ?,
                        research_next_attempt_at = ?, updated_at = ?
                    WHERE job_id = ? AND home_id = ? AND status = 'review_required'
                      AND (research_next_attempt_at IS NULL OR research_next_attempt_at <= ?)
                    """,
                    (attempts, now, next_attempt, now, row["job_id"], home_id, now),
                )
                if updated.rowcount != 1:
                    continue
                claimed_row = conn.execute(
                    "SELECT * FROM identity_enrichment_jobs WHERE job_id = ?",
                    (row["job_id"],),
                ).fetchone()
                job = self._identity_enrichment_job_from_row(claimed_row)
                if job is not None:
                    claimed.append(job)
        return claimed

    def reject_identity_enrichment_job(self, job_id: str, *, reason: str) -> dict[str, Any]:
        normalized_reason = str(reason or "").strip().upper()
        if normalized_reason not in IDENTITY_ENRICHMENT_REJECT_REASONS:
            raise IdentityEnrichmentError("IDENTITY_MODEL_NOT_SPECIFIC")
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM identity_enrichment_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            job = self._identity_enrichment_job_from_row(row)
            if job is None:
                raise IdentityEnrichmentError("IDENTITY_JOB_NOT_FOUND")
            if job.get("status") == "resolved":
                raise IdentityEnrichmentError("IDENTITY_JOB_ALREADY_RESOLVED")
            conn.execute(
                "UPDATE identity_enrichment_jobs SET status = 'rejected', blocked_reason = ?, updated_at = ? "
                "WHERE job_id = ?",
                (f"REJECTED_{normalized_reason}", utc_now(), job_id),
            )
            rejected_row = conn.execute(
                "SELECT * FROM identity_enrichment_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            rejected = self._identity_enrichment_job_from_row(rejected_row)
            assert rejected is not None
            return rejected

    def _apply_approved_manual_identities(
        self,
        devices: list[dict[str, Any]],
        *,
        home_id: str,
        network_scope_id: str | None,
    ) -> list[dict[str, Any]]:
        if not devices or not is_strong_network_scope_id(network_scope_id):
            return devices
        ambiguous_macs = _ambiguous_physical_macs(devices)
        macs = sorted(
            {
                mac
                for device in devices
                if (mac := normalized_physical_mac(device.get("mac_address"))) is not None
                and mac not in ambiguous_macs
            }
        )
        evidence_bindings = sorted(
            {
                signature
                for device in devices
                if (
                    signature := stable_identity_evidence_signature(
                        structured_identity_evidence(device),
                        device_id=device.get("device_id"),
                    )
                )
                is not None
            }
        )
        if not macs and not evidence_bindings:
            return devices
        binding_clauses: list[str] = []
        binding_parameters: list[Any] = [home_id, network_scope_id]
        if macs:
            binding_clauses.append(
                f"upper(physical_mac) IN ({','.join('?' for _ in macs)})"
            )
            binding_parameters.extend(macs)
        if evidence_bindings:
            binding_clauses.append(
                f"evidence_binding_signature IN ({','.join('?' for _ in evidence_bindings)})"
            )
            binding_parameters.extend(evidence_bindings)
        rows = self._fetch_all(
            f"SELECT * FROM identity_enrichment_jobs WHERE home_id = ? AND network_scope_id = ? "
            f"AND status = 'resolved' AND ({' OR '.join(binding_clauses)}) "
            "ORDER BY resolved_at DESC",
            tuple(binding_parameters),
        )
        approved_by_mac: dict[str, dict[str, str]] = {}
        approved_by_evidence: dict[tuple[str, str], dict[str, str]] = {}
        for row in rows:
            job = self._identity_enrichment_job_from_row(row)
            if job is None or not evidence_signature_matches(job.get("evidence") or {}, job.get("evidence_signature")):
                continue
            resolution = job.get("resolution") or {}
            history_id = str(resolution.get("history_resolution_id") or "")
            history_row = self._fetch_one(
                "SELECT * FROM device_identity_history WHERE resolution_id = ? AND home_id = ?",
                (history_id, home_id),
            )
            if history_row is None:
                continue
            history = sqlite_row_to_dict(history_row) or {}
            try:
                history["identity_evidence"] = json.loads(history.get("evidence_json") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                history["identity_evidence"] = []
            trusted = trusted_identity_resolution(history, job)
            mac = normalized_physical_mac(job.get("physical_mac"))
            evidence_binding = str(job.get("evidence_binding_signature") or "")
            if trusted is None:
                continue
            approved_identity = {
                **trusted,
                "_resolution_provenance": str(
                    job.get("resolution_provenance")
                    or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
                ),
                "_device_scoped": resolution.get("device_scoped") is True,
            }
            if mac is not None:
                approved_by_mac.setdefault(mac, approved_identity)
            elif evidence_binding and not approved_identity["_device_scoped"]:
                approved_by_evidence.setdefault(
                    (evidence_binding, str(job.get("device_id") or "")),
                    approved_identity,
                )

        result: list[dict[str, Any]] = []
        for device in devices:
            # An approved identity proves what a device was, not that it
            # answered this scan.  Never let a prior/manual resolution revive
            # a current refusal-only or stale-ARP-only phantom observation.
            if bool(device.get("is_phantom")):
                result.append(device)
                continue
            physical_mac = normalized_physical_mac(device.get("mac_address"))
            if physical_mac in ambiguous_macs:
                physical_mac = None
            current_evidence_binding = stable_identity_evidence_signature(
                structured_identity_evidence(device),
                device_id=device.get("device_id"),
            )
            approved_identity = approved_by_mac.get(physical_mac or "")
            if (
                approved_identity is None
                and physical_mac is None
                and current_evidence_binding
            ):
                approved_identity = approved_by_evidence.get(
                    (
                        current_evidence_binding,
                        str(device.get("device_id") or ""),
                    )
                )
            if approved_identity is None:
                result.append(device)
                continue
            provenance = str(
                approved_identity.get("_resolution_provenance")
                or IDENTITY_RESOLUTION_PROVENANCE_OPERATOR
            )
            device_scoped = approved_identity.get("_device_scoped") is True
            trusted_fields = {
                key: value
                for key, value in approved_identity.items()
                if key not in {"_resolution_provenance", "_device_scoped"}
            }
            enriched = {
                **device,
                **trusted_fields,
                "identity_status": "manual_resolved",
                "identity_resolver_version": IDENTITY_ENRICHMENT_RESOLVER_VERSION,
                "identity_evidence": [f"official-source:{provenance}"],
                "identity_candidates": [],
                "identity_note": "공식 제조사 출처로 실제 제품을 확인했어요.",
                "identity_confidence": 1.0,
                "identity_family_verified": True,
                "is_resolved": True,
                "is_unresolved": False,
                "is_phantom": False,
            }
            if device_scoped:
                # Once the signed job/history has rebound the exact product to
                # the same home, strong scope and unique physical MAC, expose
                # it as a household product rather than a privileged scanner
                # marker.  Raw self claims never reach this branch.
                enriched = strip_untrusted_self_claims(enriched)
            enriched = bind_trusted_manual_identity(enriched)
            enriched.update(normalized_storage_fields(enriched))
            enriched = scoring_with_cve(enriched)
            scored = score_device(enriched)
            enriched.update(
                security_score=scored["score"],
                risk_level=scored["risk_level"],
                risk_summary=scored["summary"],
                recommended_actions=scored["recommended_actions"],
            )
            result.append(enriched)
        return result

    def _resolve_stored_device_id(self, device_id: str, home_id: str) -> str | None:
        """Resolve a public-safe or legacy device ID to the stored key.

        Historic rows may still use ``dev-192-168-...`` internally.  Their
        public projection is an opaque digest, while new scans are stored
        directly with opaque IDs.  This bridge keeps device detail and alias
        updates working during that transition without rewriting foreign-key
        references in a user's existing database.
        """
        latest_scan_devices = self._latest_observed_scan_devices(home_id=home_id)
        if latest_scan_devices is not None:
            for item in latest_scan_devices:
                raw_id = str(item.get("device_id") or "")
                if raw_id == device_id or public_device_id(raw_id, home_id) == device_id:
                    return raw_id
            legacy_ip = legacy_device_id_ip_address(device_id)
            if legacy_ip is not None:
                opaque_id = scoped_device_id(home_id, make_device_id(legacy_ip, ""))
                if any(str(item.get("device_id") or "") == opaque_id for item in latest_scan_devices):
                    return opaque_id
            return None

        return None

    def device(self, device_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        latest_scan_devices = self._latest_observed_scan_devices(home_id=home_id)
        if latest_scan_devices is not None:
            stored_id = self._resolve_stored_device_id(device_id, home_id)
            device = next((item for item in latest_scan_devices if item["device_id"] == stored_id), None)
            items = self._public_devices(self._apply_aliases([device], home_id)) if device is not None else []
            return items[0] if items else None

        return None

    def _device_alias_map(self, home_id: str = HOME["home_id"]) -> dict[str, str]:
        rows = self._fetch_all(
            "SELECT device_id, alias FROM device_aliases WHERE home_id = ?",
            (home_id,),
        )
        aliases = {str(row["device_id"]): str(row["alias"]) for row in rows}
        # Preserve an existing user alias when a legacy address-derived ID is
        # first seen by the opaque-ID scanner. A direct alias for the new key
        # still wins over this compatibility mapping.
        for stored_id, alias in tuple(aliases.items()):
            legacy_ip = legacy_device_id_ip_address(stored_id)
            if legacy_ip is not None:
                opaque_id = scoped_device_id(home_id, make_device_id(legacy_ip, ""))
                aliases.setdefault(opaque_id, alias)
        return aliases

    def _device_alias_records(self, home_id: str) -> list[dict[str, Any]]:
        return [
            sqlite_row_to_dict(row) or {}
            for row in self._fetch_all(
                """
                SELECT device_id, network_scope_id, physical_mac, alias
                FROM device_aliases WHERE home_id = ?
                """,
                (home_id,),
            )
        ]

    def _latest_valid_network_scope(self, home_id: str) -> tuple[bool, str | None]:
        scans = self._fetch_all(
            """
            SELECT scan_id, network_context_json, network_scope_id
            FROM scans
            WHERE home_id = ? AND scan_source = 'android-native'
            ORDER BY created_at DESC
            """,
            (home_id,),
        )
        for scan in scans:
            rows = self._fetch_all(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan["scan_id"],),
            )
            devices = [json.loads(row["device_snapshot_json"]) for row in rows]
            bounded = _validated_authoritative_snapshot(
                json.loads(scan["network_context_json"] or "{}"),
                devices,
            )
            if bounded is None:
                continue
            return True, scan["network_scope_id"]
        return False, None

    def _apply_aliases(
        self,
        devices: list[dict[str, Any]],
        home_id: str,
        *,
        network_scope_id: str | None = None,
        observed_scope_supplied: bool = False,
    ) -> list[dict[str, Any]]:
        """보호자가 직접 지정한 기기 별칭이 있으면 name 을 별칭으로 덮고 alias 필드를 첨부한다.

        실제 스캔 별칭은 IP-derived device_id 만으로 복원하지 않는다. 강한 네트워크
        범위와 물리 MAC이 모두 일치해야 하므로 DHCP IP 재사용이나 다른 집의 동일
        사설 CIDR이 이전 별칭을 새 기기에 붙일 수 없다.
        """
        records = self._device_alias_records(home_id)
        if not records:
            return devices
        if observed_scope_supplied:
            has_observed_scan = True
            active_scope = network_scope_id
        else:
            has_observed_scan, active_scope = self._latest_valid_network_scope(home_id)

        result: list[dict[str, Any]] = []
        for device in devices:
            device_id = str(device.get("device_id") or "")
            device_mac = normalized_physical_mac(device.get("mac_address"))
            alias = None
            for record in records:
                bound_scope = record.get("network_scope_id")
                bound_mac = normalized_physical_mac(record.get("physical_mac"))
                if is_strong_network_scope_id(bound_scope) and bound_mac:
                    if active_scope == bound_scope and device_mac == bound_mac:
                        alias = str(record.get("alias") or "") or None
                        break
            if alias:
                device = {**device, "alias": alias, "name": alias}
            result.append(device)
        return result

    @staticmethod
    def _public_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """현재 CVE를 먼저 재점수한 뒤 같은 공개 기준을 적용한다."""
        return [
            presented
            for device in devices
            if not is_self_observation(device)
            and (
                presented := apply_device_presentation(
                    score_device_with_current_cve(device)
                )
            ) is not None
        ]

    def set_device_alias(self, device_id: str, alias: str | None, home_id: str = HOME["home_id"]) -> None:
        if alias and not is_safe_device_alias(alias):
            raise ValueError("기기 별칭에는 확인된 제품 이름만 사용할 수 있습니다.")
        stored_id = self._resolve_stored_device_id(device_id, home_id) or device_id
        has_observed_scan, network_scope_id = self._latest_valid_network_scope(home_id)
        physical_mac = None
        if has_observed_scan and is_strong_network_scope_id(network_scope_id):
            current = self._latest_observed_scan_devices(home_id) or []
            matched = next(
                (item for item in current if str(item.get("device_id") or "") == stored_id),
                None,
            )
            physical_mac = normalized_physical_mac((matched or {}).get("mac_address"))
        with self._connect() as conn:
            if alias:
                if physical_mac:
                    conn.execute(
                        """
                        DELETE FROM device_aliases
                        WHERE home_id = ? AND network_scope_id = ? AND upper(physical_mac) = ?
                        """,
                        (home_id, network_scope_id, physical_mac),
                    )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO device_aliases (
                        home_id, device_id, network_scope_id, physical_mac, alias, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        home_id,
                        stored_id,
                        network_scope_id if physical_mac else None,
                        physical_mac,
                        alias,
                        utc_now(),
                    ),
                )
            else:
                if physical_mac:
                    conn.execute(
                        """
                        DELETE FROM device_aliases
                        WHERE home_id = ? AND (
                            device_id = ? OR (network_scope_id = ? AND upper(physical_mac) = ?)
                        )
                        """,
                        (home_id, stored_id, network_scope_id, physical_mac),
                    )
                else:
                    conn.execute(
                        "DELETE FROM device_aliases WHERE home_id = ? AND device_id = ?",
                        (home_id, stored_id),
                    )

    def dashboard(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        # phantom(미확증 유령 신호)은 device 목록·보호자 화면·홈 점수와 동일하게 기기 카운트·top_risks
        # 에서 제외한다(그러지 않으면 /dashboard device_count 가 /devices total 과 어긋난다).
        devices = [d for d in self.devices(home_id=home_id) if not _is_phantom_signal(d)]
        identity_findings = visible_identity_findings(
            self.identity_findings(home_id=home_id)
        )
        score = self.security_score(home_id=home_id)
        events = self.security_events(home_id=home_id)
        risky_devices = [device for device in devices if device["risk_level"] in {"red", "yellow"}]

        return {
            "home": {
                **self.home(home_id=home_id),
                "security_score": score["score"],
                "device_count": len(devices),
                "identified_device_count": len(devices),
                "identity_pending_count": len(identity_findings),
            },
            "summary": {
                "score": score["score"],
                "score_status": score["score_status"],
                "risk_level": score["risk_level"],
                "scan_complete": score["scan_complete"],
                "coverage_complete": score["coverage_complete"],
                "online_devices": sum(1 for device in devices if device["online"]),
                "high_risk_devices": confirmed_public_red_count(devices, identity_findings),
                "identity_pending_count": len(identity_findings),
                "recent_event_count": len(events),
            },
            "top_risks": [
                {
                    "device_id": device["device_id"],
                    "device_name": device["name"],
                    "risk_level": device["risk_level"],
                    "message": device.get("risk_summary") or "보안 상태를 다시 확인해 주세요.",
                }
                for device in risky_devices
            ],
            "identity_findings": identity_findings,
            "recent_events": events[:3],
            "guardian_status": {
                "connected_guardians": self.guardian_count(home_id=home_id),
                "last_alert_status": "앱 알림 대체 흐름으로 보호자에게 전달된 상태입니다.",
            },
        }

    def home(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        row = self._fetch_one("SELECT * FROM homes WHERE home_id = ?", (home_id,))
        if row is None:
            raise KeyError("home does not exist")
        return {
            "home_id": row["home_id"],
            "name": row["name"],
            "mode": row["mode"],
        }

    def security_score(self, home_id: str = HOME["home_id"]) -> dict[str, Any]:
        latest_context = self.latest_scan_context(home_id=home_id)
        has_scan = latest_context is not None
        partial_scan = scan_is_partial(latest_context)
        coverage_complete = None if not has_scan else not partial_scan
        _, summary = summarize_public_security(
            self._stored_devices(home_id),
            coverage_complete=coverage_complete,
        )
        pending_findings = visible_identity_findings(
            self.identity_findings(home_id=home_id)
        )
        if pending_findings and has_scan:
            summary = _hold_identity_incomplete_security(summary, pending_findings)
        if partial_scan:
            summary = project_partial_security(summary)
        return {
            "home_id": home_id,
            "score": summary["score"],
            "score_status": public_score_status(summary, coverage_complete=coverage_complete),
            "risk_level": summary["risk_level"],
            "summary": summary["summary"],
            "device_scores": summary["device_scores"],
            "identity_incomplete": bool(pending_findings),
            "identity_pending_count": len(pending_findings),
            "identity_findings": pending_findings,
            "scan_complete": coverage_complete is True,
            "coverage_complete": coverage_complete,
        }

    def security_events(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        # Build events from the validated current Android view. Historic table
        # rows lack source provenance and remain private, but actual current
        # risks continue to drive the resident event feed.
        observations = [
            *self.devices(home_id=home_id),
            *visible_identity_findings(self.identity_findings(home_id=home_id)),
        ]
        return _project_security_events(home_id, observations)

    def create_scan(
        self,
        scan_profile: str = "quick",
        scan_source: str = "android-native",
        network_context: dict[str, Any] | None = None,
        discovered_devices: list[dict[str, Any]] | None = None,
        home_id: str = HOME["home_id"],
    ) -> dict[str, Any]:
        if scan_source != _AUTHORITATIVE_SCAN_SOURCE:
            raise ValueError("unsupported scan source")
        return self._record_scan(
            scan_profile=scan_profile,
            scan_source=scan_source,
            network_context=network_context,
            discovered_devices=discovered_devices,
            home_id=home_id,
        )

    def record_windows_port_probe(
        self,
        *,
        network_context: dict[str, Any] | None,
        discovered_devices: list[dict[str, Any]],
        home_id: str,
        scan_profile: str = "internal-probe",
    ) -> dict[str, Any]:
        """Persist an internal host probe without entering mobile/public state."""

        return self._record_scan(
            scan_profile=scan_profile,
            scan_source="windows-port-probe",
            network_context=network_context,
            discovered_devices=discovered_devices,
            home_id=home_id,
        )

    def _record_scan(
        self,
        *,
        scan_profile: str,
        scan_source: str,
        network_context: dict[str, Any] | None,
        discovered_devices: list[dict[str, Any]] | None,
        home_id: str,
    ) -> dict[str, Any]:
        if discovered_devices is None:
            raise ValueError("discovered_devices is required")
        if not str(home_id or "").strip() or self._fetch_one(
            "SELECT 1 FROM homes JOIN users ON users.home_id = homes.home_id "
            "WHERE homes.home_id = ? LIMIT 1",
            (home_id,),
        ) is None:
            raise ValueError("authenticated home does not exist")
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            rejection_reasons = actual_android_scan_rejection_reasons(
                network_context,
                discovered_devices,
            )
            if rejection_reasons:
                raise ValueError("actual Android scan evidence is required")
        network_scope_id = derive_network_scope_id(
            home_id=home_id,
            network_context=network_context,
            discovered_devices=discovered_devices,
        )
        strong_scope_candidates = (
            derive_strong_network_scope_ids(
                home_id=home_id,
                network_context=network_context,
                discovered_devices=discovered_devices,
            )
            if scan_source == _AUTHORITATIVE_SCAN_SOURCE
            else ()
        )
        stored_network_context = normalize_stored_network_context(network_context)
        public_network_context = sanitize_public_network_context(stored_network_context)
        stored_devices, attested_self_job_devices = self._store_discovered_devices(
            discovered_devices,
            scan_source=scan_source,
            home_id=home_id,
            network_scope_id=network_scope_id,
        )
        history_self_job_devices = (
            self._authenticated_self_history_job_devices(
                stored_devices,
                home_id=home_id,
                current_scope_candidates=strong_scope_candidates,
            )
            if scan_source == _AUTHORITATIVE_SCAN_SOURCE
            else []
        )
        history_self_macs = {
            mac
            for device in history_self_job_devices
            if (mac := normalized_physical_mac(device.get("mac_address"))) is not None
        }
        attested_self_job_devices.extend(history_self_job_devices)
        projected_devices = self._apply_approved_manual_identities(
            stored_devices,
            home_id=home_id,
            network_scope_id=network_scope_id,
        )
        # The phone/tablet running the scan is a discovery observation, not a
        # household device.  Keep it in the private snapshot for self-device
        # detection, but exclude it from the resident list, score and counts
        # just like the SQLAlchemy repository does.  A catalog entry for the
        # scanner model must not make the scanner suddenly count as an IoT
        # appliance.
        household_devices = [device for device in projected_devices if not is_self_observation(device)]
        partial_scan = scan_is_partial(stored_network_context)
        public_devices, summary = summarize_public_security(
            self._apply_aliases(
                household_devices,
                home_id,
                network_scope_id=network_scope_id,
                observed_scope_supplied=True,
            ),
            coverage_complete=not partial_scan,
        )
        finding_source = (
            projected_devices
        )
        raw_identity_findings = build_public_identity_findings(
            [
                device
                for device in self._apply_aliases(
                    finding_source,
                    home_id,
                    network_scope_id=network_scope_id,
                    observed_scope_supplied=True,
                )
                if not is_self_observation(device)
            ],
            public_devices,
        )
        identity_findings = visible_identity_findings(raw_identity_findings)
        identity_incomplete = bool(identity_findings)
        incomplete_scan = partial_scan
        if partial_scan:
            summary = project_partial_security(summary)
        elif identity_findings:
            summary = _hold_identity_incomplete_security(summary, identity_findings)
        security_score = {
            "home_id": home_id,
            "score": summary["score"],
            "score_status": public_score_status(summary, coverage_complete=not partial_scan),
            "risk_level": summary["risk_level"],
            "summary": summary["summary"],
            "device_scores": summary["device_scores"],
            "identity_incomplete": bool(identity_findings),
            "identity_pending_count": len(identity_findings),
            "scan_complete": not incomplete_scan,
            "coverage_complete": not partial_scan,
        }
        # devices_found·high_risk_devices(저장값·FCM 알림 문구에 사용)는 phantom 을 제외한 실기기만
        # 센다. summary(점수)·device 목록과 동일 기준 — 그러지 않으면 알림 '기기 N대/위험 N대'가 화면과 어긋난다.
        real_devices = public_devices
        high_risk_devices = confirmed_public_red_count(real_devices, identity_findings)
        scan_id = f"scan-{uuid4()}"
        result = {
            "scan_id": scan_id,
            "home_id": home_id,
            "status": "partial" if incomplete_scan else "completed",
            "progress": 100,
            "scan_profile": scan_profile,
            "scan_source": scan_source,
            "network_context": public_network_context,
            "current_step": (
                PARTIAL_SCAN_STEP
                if partial_scan
                else IDENTITY_PENDING_STEP
                if identity_incomplete
                else "점검 완료"
            ),
            "devices_found": len(real_devices) + len(identity_findings),
            "identified_count": len(real_devices),
            "identity_pending_count": len(identity_findings),
            "high_risk_devices": high_risk_devices,
            "devices": public_devices,
            # Preserve every raw resolver candidate for the private repository
            # and HTTP defence layer. Public counters, score state and alerts
            # above use only resident-visible findings.
            "identity_findings": raw_identity_findings,
            "events": _project_security_events(home_id, [*real_devices, *identity_findings]),
            "security_score": security_score,
            "created_at": utc_now(),
        }
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (
                    scan_id, home_id, status, progress, scan_profile, current_step,
                    scan_source, network_context_json, network_scope_id, devices_found, high_risk_devices,
                    security_score_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result["scan_id"],
                    result["home_id"],
                    result["status"],
                    result["progress"],
                    result["scan_profile"],
                    result["current_step"],
                    result["scan_source"],
                    json.dumps(stored_network_context, ensure_ascii=False),
                    network_scope_id,
                    result["devices_found"],
                    result["high_risk_devices"],
                    json.dumps(result["security_score"], ensure_ascii=False),
                    result["created_at"],
                ),
            )
            # Keep unresolved observations in the private scan snapshot so a later
            # verified scan can merge evidence correctly.  Their public finding
            # is returned separately rather than silently dropping the detection.
            for device in stored_devices:
                conn.execute(
                    "INSERT INTO scan_devices (scan_id, device_snapshot_json) VALUES (?, ?)",
                    (scan_id, json.dumps(device, ensure_ascii=False)),
                )
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            finding_ids = {
                str(finding.get("device_id") or "") for finding in raw_identity_findings
            }
            # One upsert transaction owns the complete current job set.  A
            # second self-only call would supersede unresolved household jobs
            # that were absent from that smaller list.
            unresolved_job_devices = [
                device
                for device in stored_devices
                if public_device_id(device.get("device_id"), home_id) in finding_ids
                and normalized_physical_mac(device.get("mac_address"))
                not in history_self_macs
            ]
            self._upsert_identity_enrichment_jobs(
                [
                    *unresolved_job_devices,
                    *attested_self_job_devices,
                ],
                home_id=home_id,
                network_scope_id=network_scope_id,
                ambiguity_devices=stored_devices,
            )
        if scan_source == _AUTHORITATIVE_SCAN_SOURCE:
            self._create_notification(
                notification_type="scan_completed",
                title="보안 점검 일부 완료" if partial_scan else "보안 점검 완료",
                message=(
                    PARTIAL_SCAN_NOTIFICATION
                    if partial_scan
                    else scan_completed_message(real_devices, identity_findings, security_score)
                ),
                home_id=home_id,
                scan_id=scan_id,
                scan_source=scan_source,
            )
        return deepcopy(result)

    def _validated_scan_row_snapshot(
        self,
        row: sqlite3.Row,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Revalidate one exact stored Android row before public projection."""

        try:
            network_context = json.loads(row["network_context_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            network_context = {}
        device_rows = self._fetch_all(
            "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
            (row["scan_id"],),
        )
        devices: list[dict[str, Any]] = []
        for device_row in device_rows:
            try:
                snapshot = json.loads(device_row["device_snapshot_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(snapshot, dict):
                devices.append(snapshot)
        return _validated_authoritative_snapshot(network_context, devices)

    def scan_status(self, scan_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        row = self._fetch_one(
            "SELECT * FROM scans WHERE scan_id = ? AND home_id = ? AND scan_source = ?",
            (scan_id, home_id, _AUTHORITATIVE_SCAN_SOURCE),
        )
        if row is None:
            return None
        bounded = self._validated_scan_row_snapshot(row)
        if bounded is None:
            return None
        network_context, snapshots = bounded
        snapshots = apply_verified_product_catalog_projection(
            snapshots,
            self.verified_product_catalog_entries(),
        )
        snapshots = self._apply_approved_manual_identities(
            snapshots,
            home_id=home_id,
            network_scope_id=row["network_scope_id"],
        )
        aliased_snapshots = self._apply_aliases(
            [device for device in snapshots if not is_self_observation(device)],
            home_id,
            network_scope_id=row["network_scope_id"],
            observed_scope_supplied=True,
        )
        partial_scan = scan_is_partial(network_context)
        public_devices, summary = summarize_public_security(
            aliased_snapshots,
            coverage_complete=not partial_scan,
        )
        if partial_scan:
            summary = project_partial_security(summary)
        raw_findings = build_public_identity_findings(aliased_snapshots, public_devices)
        findings = visible_identity_findings(raw_findings)
        incomplete_scan = partial_scan
        return {
            "scan_id": row["scan_id"],
            "status": "partial" if incomplete_scan else "completed",
            "progress": row["progress"],
            "scan_source": row["scan_source"],
            "current_step": (
                PARTIAL_SCAN_STEP
                if partial_scan
                else IDENTITY_PENDING_STEP
                if findings
                else "점검 완료"
            ),
            "scan_complete": not incomplete_scan,
            "coverage_complete": not partial_scan,
            "identity_pending_count": len(findings),
            "score_status": public_score_status(summary, coverage_complete=not partial_scan),
            "devices_found": len(public_devices) + len(findings),
            "high_risk_devices": confirmed_public_red_count(public_devices, findings),
            "created_at": row["created_at"],
        }

    def scan_result(self, scan_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        row = self._fetch_one(
            "SELECT * FROM scans WHERE scan_id = ? AND home_id = ? AND scan_source = ?",
            (scan_id, home_id, _AUTHORITATIVE_SCAN_SOURCE),
        )
        if row is None:
            return None

        # Android authoritative scan은 '이번 스캔만'의 frozen snapshot 대신 devices()/대시보드와
        # 동일한 '병합된 현재 기기' 뷰를 돌려준다. native 스캔이 비결정적이라 매 스캔 일부 기기를
        # 놓치는데, scanResult 화면(앱은 이 응답의 devices 를 기기 탭에도 그대로 씀)과 대시보드가
        # 서로 다른 목록을 보이면 사용자에게는 '기기가 가끔 안 보임'으로 느껴진다. 세 화면을 같은
        # 소스로 통일한다. 비권위 내부 probe 기록은 공개 조회 경로에서 격리한다.
        if row["scan_source"] == _AUTHORITATIVE_SCAN_SOURCE:
            requested_snapshot = self._validated_scan_row_snapshot(row)
            if requested_snapshot is None:
                return None
            requested_context, _requested_devices = requested_snapshot
            stored_current = self._stored_devices(home_id)
            current_context = self.latest_scan_context(home_id) or requested_context
            requested_partial = scan_is_partial(requested_context)
            current_partial = scan_is_partial(current_context)
            partial_scan = requested_partial or current_partial
            current_devices, summary = summarize_public_security(
                stored_current,
                coverage_complete=not partial_scan,
            )
            # If the exact requested legacy row lost foreign observations, its
            # aggregate diagnostic must remain visible even when a newer valid
            # Android row supplies the current membership view.
            stored_context = requested_context if requested_partial else current_context
            # The merged device view intentionally retains strong identities
            # from recent scans, but unresolved findings describe this scan
            # only.  Using stored_current here made every historical weak
            # observation reappear as a new "needs identification" device.
            latest_observed = self._latest_scan_devices_only(home_id)
            finding_source = stored_current if latest_observed is None else latest_observed
            raw_current_findings = build_public_identity_findings(
                finding_source,
                current_devices,
            )
            current_findings = visible_identity_findings(raw_current_findings)
            if partial_scan:
                summary = project_partial_security(summary)
            elif current_findings:
                summary = _hold_identity_incomplete_security(summary, current_findings)
            incomplete_scan = partial_scan
            real_devices = current_devices
            return {
                "scan_id": row["scan_id"],
                "home_id": row["home_id"],
                "status": "partial" if incomplete_scan else "completed",
                "progress": row["progress"],
                "scan_profile": row["scan_profile"],
                "scan_source": row["scan_source"],
                "network_context": sanitize_public_network_context(stored_context),
                "current_step": (
                    PARTIAL_SCAN_STEP
                    if partial_scan
                    else IDENTITY_PENDING_STEP
                    if current_findings
                    else "점검 완료"
                ),
                "devices_found": len(real_devices) + len(current_findings),
                "identified_count": len(real_devices),
                "identity_pending_count": len(current_findings),
                "high_risk_devices": confirmed_public_red_count(real_devices, current_findings),
                "devices": current_devices,
                # The public HTTP boundary projects this raw evidence list.
                # Aggregate fields in this response are already derived from
                # ``current_findings`` and therefore cannot be inflated by a
                # bare transport-only resolver row.
                "identity_findings": raw_current_findings,
                "events": self.security_events(home_id=home_id),
                "security_score": {
                    "home_id": home_id,
                    "score": summary["score"],
                    "risk_level": summary["risk_level"],
                    "summary": summary["summary"],
                    "device_scores": summary["device_scores"],
                    "score_status": public_score_status(summary, coverage_complete=not partial_scan),
                    "identity_incomplete": bool(current_findings),
                    "identity_pending_count": len(current_findings),
                    "scan_complete": not incomplete_scan,
                    "coverage_complete": not partial_scan,
                },
                "created_at": row["created_at"],
            }

        return None

    def finalize_identity_researched_scan(
        self,
        scan_id: str,
        *,
        home_id: str = HOME["home_id"],
    ) -> bool:
        """Refresh a completed projection after research without duplicating alerts."""

        result = self.scan_result(scan_id, home_id=home_id)
        if result is None or result.get("status") != "completed":
            return False
        if max(0, int(result.get("identity_pending_count") or 0)):
            return False
        score = result.get("security_score")
        if (
            not isinstance(score, Mapping)
            or score.get("scan_complete") is not True
            or score.get("coverage_complete") is not True
        ):
            return False

        notification = sanitize_public_notification(
            {
                "title": "보안 점검 완료",
                "message": scan_completed_message(list(result.get("devices") or []), [], score),
            }
        )
        notification_id = "scan-complete-" + hashlib.sha256(
            f"{home_id}\0{scan_id}".encode("utf-8")
        ).hexdigest()[:32]
        now = utc_now()
        with self._lock, self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE scans
                SET status = 'completed', current_step = '점검 완료',
                    devices_found = ?, high_risk_devices = ?,
                    security_score_json = ?
                WHERE scan_id = ? AND home_id = ? AND scan_source = ?
                """,
                (
                    int(result.get("devices_found") or 0),
                    int(result.get("high_risk_devices") or 0),
                    json.dumps(dict(score), ensure_ascii=False),
                    scan_id,
                    home_id,
                    _AUTHORITATIVE_SCAN_SOURCE,
                ),
            )
            if updated.rowcount != 1:
                return False
            existing = conn.execute(
                """
                SELECT notification_id FROM notifications
                WHERE home_id = ? AND scan_id = ? AND scan_source = ?
                  AND type = 'scan_completed'
                LIMIT 1
                """,
                (home_id, scan_id, _AUTHORITATIVE_SCAN_SOURCE),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO notifications (
                        notification_id, home_id, type, title, message,
                        scan_id, scan_source, read, created_at
                    ) VALUES (?, ?, 'scan_completed', ?, ?, ?, ?, 0, ?)
                    """,
                    (
                        notification_id,
                        home_id,
                        notification["title"],
                        notification["message"],
                        scan_id,
                        _AUTHORITATIVE_SCAN_SOURCE,
                        now,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE notifications
                    SET title = ?, message = ?
                    WHERE home_id = ? AND scan_id = ? AND scan_source = ?
                      AND type = 'scan_completed'
                    """,
                    (
                        notification["title"],
                        notification["message"],
                        home_id,
                        scan_id,
                        _AUTHORITATIVE_SCAN_SOURCE,
                    ),
                )
        return True

    def _next_guardian_short_code(self) -> str:
        rows = self._fetch_all("SELECT short_code FROM guardian_invites WHERE short_code IS NOT NULL")
        existing_codes = {str(row["short_code"]).strip().upper() for row in rows if row["short_code"]}
        return generate_short_code(existing_codes)

    def create_guardian_invite(
        self,
        email: str,
        relation: str,
        ward_account_name: str | None = None,
        home_id: str = HOME["home_id"],
    ) -> dict[str, Any]:
        created_at = utc_now()
        short_code = self._next_guardian_short_code()
        invite = {
            "invite_id": f"invite-{uuid4()}",
            "home_id": home_id,
            "email": email,
            "relation": relation,
            "display_name": default_display_name(email, relation),
            "ward_account_name": clean_optional_name(ward_account_name),
            "short_code": short_code,
            "deep_link": build_deep_link(short_code),
            "status": "pending",
            "message": "보호자 초대 링크와 짧은 코드를 만들었어요.",
            "created_at": created_at,
            "expires_at": invite_expires_at(created_at),
            "accepted_at": None,
            "revoked_at": None,
            "last_viewed_at": None,
            "guardian_token_hash": None,
            "session_created_at": None,
            "session_last_used_at": None,
        }
        with self._lock, self._connect() as conn:
            if not str(home_id or "").strip() or conn.execute(
                """
                SELECT 1 FROM homes
                JOIN users ON users.home_id = homes.home_id
                WHERE homes.home_id = ? LIMIT 1
                """,
                (home_id,),
            ).fetchone() is None:
                raise ValueError("authenticated home does not exist")
            invite["ward_account_name"] = invite["ward_account_name"] or self._fallback_ward_account_name(conn, home_id)
            conn.execute(
                """
                INSERT INTO guardian_invites (
                    invite_id, home_id, email, relation, display_name, ward_account_name, short_code, deep_link,
                    status, message, created_at, expires_at, accepted_at, revoked_at, last_viewed_at,
                    guardian_token_hash, session_created_at, session_last_used_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invite["invite_id"],
                    invite["home_id"],
                    invite["email"],
                    invite["relation"],
                    invite["display_name"],
                    invite["ward_account_name"],
                    invite["short_code"],
                    invite["deep_link"],
                    invite["status"],
                    invite["message"],
                    invite["created_at"],
                    invite["expires_at"],
                    invite["accepted_at"],
                    invite["revoked_at"],
                    invite["last_viewed_at"],
                    invite["guardian_token_hash"],
                    invite["session_created_at"],
                    invite["session_last_used_at"],
                ),
            )
        self._create_notification(
            notification_type="guardian_invite",
            title="보호자 초대 전송",
            message=f"{email} 보호자에게 링크와 짧은 코드 초대를 만들었어요.",
            home_id=home_id,
        )
        return deepcopy(normalize_guardian_invite(invite))

    def guardians(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            """
            SELECT guardian_invites.* FROM guardian_invites
            JOIN homes ON homes.home_id = guardian_invites.home_id
            JOIN users ON users.home_id = homes.home_id
            WHERE guardian_invites.home_id = ?
            ORDER BY guardian_invites.rowid DESC
            """,
            (home_id,),
        )
        return [normalize_guardian_invite(sqlite_row_to_dict(row) or {}) for row in rows]

    def guardian_invite_summary(self, home_id: str = HOME["home_id"]) -> dict[str, int]:
        return guardian_invite_summary(self.guardians(home_id=home_id))

    def guardian_count(self, home_id: str = HOME["home_id"]) -> int:
        return self.guardian_invite_summary(home_id=home_id)["accepted"]

    def upsert_guardian_account(
        self,
        guardian_id: str,
        email: str,
        display_name: str | None = None,
        provider: str = "google",
    ) -> dict[str, Any]:
        now = utc_now()
        normalized = {
            "guardian_id": guardian_id.strip(),
            "email": email.strip().lower(),
            "display_name": (display_name or email).strip(),
            "provider": provider.strip().lower(),
            "created_at": now,
            "last_login_at": now,
        }
        if (
            not normalized["guardian_id"]
            or not normalized["email"]
            or not normalized["display_name"]
            or normalized["provider"] != "google"
        ):
            raise ValueError("verified Google guardian account is required")
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO guardian_accounts (
                    guardian_id, email, display_name, provider, created_at, last_login_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(guardian_id) DO UPDATE SET
                    email = excluded.email,
                    display_name = excluded.display_name,
                    provider = excluded.provider,
                    last_login_at = excluded.last_login_at
                """,
                (
                    normalized["guardian_id"],
                    normalized["email"],
                    normalized["display_name"],
                    normalized["provider"],
                    normalized["created_at"],
                    normalized["last_login_at"],
                ),
            )
        return self.guardian_account_by_id(normalized["guardian_id"]) or normalized

    def guardian_account_by_id(self, guardian_id: str) -> dict[str, Any] | None:
        row = self._fetch_one("SELECT * FROM guardian_accounts WHERE guardian_id = ?", (guardian_id,))
        return sqlite_row_to_dict(row)

    def accept_guardian_invite_for_account(
        self,
        invite_lookup: str,
        guardian: dict[str, Any],
    ) -> dict[str, Any]:
        lookup = normalize_invite_lookup(invite_lookup)
        if not lookup:
            return {
                "ok": False,
                "status_code": 400,
                "code": "GUARDIAN_INVITE_REQUIRED",
                "message": "초대 링크 또는 짧은 코드를 입력해 주세요.",
            }

        guardian_id = str(guardian.get("guardian_id") or "").strip()
        guardian_email = str(guardian.get("guardian_email") or guardian.get("email") or "").strip().lower()
        guardian_name = str(guardian.get("guardian_name") or guardian.get("display_name") or guardian_email).strip()
        if not guardian_id or not guardian_email:
            return {
                "ok": False,
                "status_code": 400,
                "code": "GUARDIAN_ACCOUNT_REQUIRED",
                "message": "보호자 Google 로그인이 먼저 필요합니다.",
            }

        accepted_at = utc_now()
        with self._lock, self._connect() as conn:
            invite_row = conn.execute(
                "SELECT * FROM guardian_invites WHERE invite_id = ? OR short_code = ?",
                (lookup, lookup.upper()),
            ).fetchone()
            if invite_row is None:
                return {
                    "ok": False,
                    "status_code": 404,
                    "code": "GUARDIAN_INVITE_404",
                    "message": "초대 코드를 찾을 수 없어요. 코드를 다시 확인해 주세요.",
                }

            invite_data = normalize_guardian_invite(sqlite_row_to_dict(invite_row) or {})
            invite_home_id = str(invite_data.get("home_id") or "").strip()
            home_exists = bool(
                invite_home_id
                and conn.execute(
                    """
                    SELECT 1 FROM homes
                    JOIN users ON users.home_id = homes.home_id
                    WHERE homes.home_id = ? LIMIT 1
                    """,
                    (invite_home_id,),
                ).fetchone()
            )
            if not home_exists:
                return {
                    "ok": False,
                    "status_code": 409,
                    "code": "GUARDIAN_INVITE_HOME_INVALID",
                    "message": "초대의 피보호자 집 정보를 확인하지 못했어요. 사용자에게 새 초대를 요청해 주세요.",
                }
            if invite_data.get("status") == "revoked":
                return {
                    "ok": False,
                    "status_code": 410,
                    "code": "GUARDIAN_INVITE_REVOKED",
                    "message": "취소된 보호자 초대입니다. 새 초대를 요청해 주세요.",
                }
            if invite_data.get("status") == "expired":
                return {
                    "ok": False,
                    "status_code": 410,
                    "code": "GUARDIAN_INVITE_EXPIRED",
                    "message": "만료된 보호자 초대입니다. 새 초대를 요청해 주세요.",
                }

            existing_link = conn.execute(
                "SELECT * FROM guardian_ward_links WHERE invite_id = ? AND status = 'active'",
                (invite_data["invite_id"],),
            ).fetchone()
            if existing_link is not None:
                if str(existing_link["home_id"] or "").strip() != invite_home_id:
                    return {
                        "ok": False,
                        "status_code": 409,
                        "code": "GUARDIAN_LINK_HOME_MISMATCH",
                        "message": "보호자 연결의 집 정보가 일치하지 않아요. 사용자에게 새 초대를 요청해 주세요.",
                    }
                if existing_link["guardian_id"] != guardian_id:
                    return {
                        "ok": False,
                        "status_code": 409,
                        "code": "GUARDIAN_INVITE_ALREADY_ACCEPTED",
                        "message": "이미 다른 보호자 계정에 추가된 초대입니다. 사용자에게 새 초대를 요청해 주세요.",
                    }
                account_values = {
                    "guardian_id": guardian_id,
                    "email": guardian_email,
                    "display_name": guardian_name or guardian_email,
                    "provider": str(guardian.get("provider") or "google"),
                    "created_at": accepted_at,
                    "last_login_at": accepted_at,
                }
                conn.execute(
                    """
                    INSERT INTO guardian_accounts (
                        guardian_id, email, display_name, provider, created_at, last_login_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(guardian_id) DO UPDATE SET
                        email = excluded.email,
                        display_name = excluded.display_name,
                        provider = excluded.provider,
                        last_login_at = excluded.last_login_at
                    """,
                    (
                        account_values["guardian_id"],
                        account_values["email"],
                        account_values["display_name"],
                        account_values["provider"],
                        account_values["created_at"],
                        account_values["last_login_at"],
                    ),
                )
                conn.execute(
                    """
                    UPDATE guardian_ward_links
                    SET last_viewed_at = ?
                    WHERE link_id = ?
                    """,
                    (accepted_at, existing_link["link_id"]),
                )
                conn.execute(
                    """
                    UPDATE guardian_invites
                    SET last_viewed_at = ?
                    WHERE invite_id = ?
                    """,
                    (accepted_at, invite_data["invite_id"]),
                )
                account_row = conn.execute(
                    "SELECT * FROM guardian_accounts WHERE guardian_id = ?",
                    (guardian_id,),
                ).fetchone()
                link_row = conn.execute(
                    "SELECT * FROM guardian_ward_links WHERE link_id = ?",
                    (existing_link["link_id"],),
                ).fetchone()
                updated_invite_row = conn.execute(
                    "SELECT * FROM guardian_invites WHERE invite_id = ?",
                    (invite_data["invite_id"],),
                ).fetchone()
                return {
                    "ok": True,
                    "guardian": sqlite_row_to_dict(account_row) or account_values,
                    "ward": self._guardian_ward_from_row(link_row),
                    "invite": normalize_guardian_invite(sqlite_row_to_dict(updated_invite_row) or invite_data),
                }

            any_existing_link = conn.execute(
                "SELECT * FROM guardian_ward_links WHERE invite_id = ? LIMIT 1",
                (invite_data["invite_id"],),
            ).fetchone()
            if invite_data.get("status") == "accepted" and any_existing_link is not None:
                return {
                    "ok": False,
                    "status_code": 409,
                    "code": "GUARDIAN_INVITE_ALREADY_ACCEPTED",
                    "message": "이미 사용된 초대입니다. 다시 연결하려면 사용자에게 새 초대를 요청해 주세요.",
                }

            account_values = {
                "guardian_id": guardian_id,
                "email": guardian_email,
                "display_name": guardian_name or guardian_email,
                "provider": str(guardian.get("provider") or "google"),
                "created_at": accepted_at,
                "last_login_at": accepted_at,
            }
            conn.execute(
                """
                INSERT INTO guardian_accounts (
                    guardian_id, email, display_name, provider, created_at, last_login_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(guardian_id) DO UPDATE SET
                    email = excluded.email,
                    display_name = excluded.display_name,
                    provider = excluded.provider,
                    last_login_at = excluded.last_login_at
                """,
                (
                    account_values["guardian_id"],
                    account_values["email"],
                    account_values["display_name"],
                    account_values["provider"],
                    account_values["created_at"],
                    account_values["last_login_at"],
                ),
            )

            ward_account_name = clean_optional_name(invite_data.get("ward_account_name")) or self._fallback_ward_account_name(conn, invite_home_id)
            link_values = {
                "link_id": f"ward-link-{uuid4()}",
                "guardian_id": guardian_id,
                "invite_id": invite_data["invite_id"],
                "home_id": invite_home_id,
                "ward_account_name": ward_account_name,
                "ward_alias": None,
                "ward_display_name": ward_account_name,
                "status": "active",
                "accepted_at": accepted_at,
                "revoked_at": None,
                "last_viewed_at": accepted_at,
            }
            conn.execute(
                """
                INSERT INTO guardian_ward_links (
                    link_id, guardian_id, invite_id, home_id, ward_account_name, ward_alias, ward_display_name,
                    status, accepted_at, revoked_at, last_viewed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    link_values["link_id"],
                    link_values["guardian_id"],
                    link_values["invite_id"],
                    link_values["home_id"],
                    link_values["ward_account_name"],
                    link_values["ward_alias"],
                    link_values["ward_display_name"],
                    link_values["status"],
                    link_values["accepted_at"],
                    link_values["revoked_at"],
                    link_values["last_viewed_at"],
                ),
            )
            conn.execute(
                """
                UPDATE guardian_invites
                SET last_viewed_at = ?,
                    accepted_at = COALESCE(accepted_at, ?),
                    ward_account_name = COALESCE(ward_account_name, ?),
                    status = 'accepted',
                    message = '보호자 계정에 연결됐어요.'
                WHERE invite_id = ? AND revoked_at IS NULL
                """,
                (accepted_at, accepted_at, ward_account_name, invite_data["invite_id"]),
            )
            account_row = conn.execute(
                "SELECT * FROM guardian_accounts WHERE guardian_id = ?",
                (guardian_id,),
            ).fetchone()
            link_row = conn.execute(
                "SELECT * FROM guardian_ward_links WHERE link_id = ?",
                (link_values["link_id"],),
            ).fetchone()
            updated_invite_row = conn.execute(
                "SELECT * FROM guardian_invites WHERE invite_id = ?",
                (invite_data["invite_id"],),
            ).fetchone()

        return {
            "ok": True,
            "guardian": sqlite_row_to_dict(account_row) or account_values,
            "ward": self._guardian_ward_from_row(link_row),
            "invite": normalize_guardian_invite(sqlite_row_to_dict(updated_invite_row) or invite_data),
        }

    def guardian_wards(self, guardian_id: str) -> list[dict[str, Any]]:
        rows = self._fetch_all(
            """
            SELECT links.* FROM guardian_ward_links AS links
            JOIN guardian_invites AS invites ON invites.invite_id = links.invite_id
            JOIN guardian_accounts AS accounts ON accounts.guardian_id = links.guardian_id
            JOIN homes ON homes.home_id = links.home_id
            JOIN users ON users.home_id = links.home_id
            WHERE links.guardian_id = ? AND links.status = 'active'
              AND links.revoked_at IS NULL
              AND invites.revoked_at IS NULL
              AND (invites.accepted_at IS NOT NULL OR LOWER(invites.status) = 'accepted')
              AND invites.home_id = links.home_id
              AND LOWER(TRIM(accounts.provider)) = 'google'
              AND TRIM(COALESCE(accounts.email, '')) <> ''
              AND TRIM(COALESCE(accounts.display_name, '')) <> ''
              AND users.role = 'user'
              AND TRIM(COALESCE(users.email, '')) <> ''
              AND TRIM(COALESCE(users.nickname, '')) <> ''
            ORDER BY links.accepted_at DESC
            """,
            (guardian_id,),
        )
        return [self._guardian_ward_from_row(row) for row in rows]

    def update_guardian_ward_alias(self, link_id: str, ward_alias: str | None) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        alias = clean_optional_name(ward_alias)
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM guardian_ward_links WHERE link_id = ?", (link_id,)).fetchone()
            if row is None:
                return None
            ward_account_name = clean_optional_name(row["ward_account_name"]) or self._fallback_ward_account_name(conn, row["home_id"])
            conn.execute(
                """
                UPDATE guardian_ward_links
                SET ward_account_name = ?,
                    ward_alias = ?,
                    ward_display_name = ?
                WHERE link_id = ?
                """,
                (ward_account_name, alias, alias or ward_account_name, link_id),
            )
            updated = conn.execute("SELECT * FROM guardian_ward_links WHERE link_id = ?", (link_id,)).fetchone()
        return self._guardian_ward_from_row(updated)

    def guardian_ward_link_by_id(self, link_id: str) -> dict[str, Any] | None:
        row = self._fetch_one(
            """
            SELECT links.* FROM guardian_ward_links AS links
            JOIN guardian_invites AS invites ON invites.invite_id = links.invite_id
            JOIN guardian_accounts AS accounts ON accounts.guardian_id = links.guardian_id
            JOIN homes ON homes.home_id = links.home_id
            JOIN users ON users.home_id = links.home_id
            WHERE links.link_id = ? AND invites.home_id = links.home_id
              AND (
                    (
                        links.status = 'active'
                        AND links.revoked_at IS NULL
                        AND invites.revoked_at IS NULL
                        AND (invites.accepted_at IS NOT NULL OR LOWER(invites.status) = 'accepted')
                    )
                    OR links.status = 'revoked'
              )
              AND LOWER(TRIM(accounts.provider)) = 'google'
              AND TRIM(COALESCE(accounts.email, '')) <> ''
              AND TRIM(COALESCE(accounts.display_name, '')) <> ''
              AND users.role = 'user'
              AND TRIM(COALESCE(users.email, '')) <> ''
              AND TRIM(COALESCE(users.nickname, '')) <> ''
            """,
            (link_id,),
        )
        return self._guardian_ward_from_row(row) if row else None

    def mark_guardian_ward_viewed(self, link_id: str) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        viewed_at = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE guardian_ward_links SET last_viewed_at = ? WHERE link_id = ?",
                (viewed_at, link_id),
            )
        return self.guardian_ward_link_by_id(link_id)

    def revoke_guardian_ward_link(self, link_id: str) -> dict[str, Any] | None:
        if self.guardian_ward_link_by_id(link_id) is None:
            return None
        revoked_at = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE guardian_ward_links
                SET status = 'revoked',
                    revoked_at = COALESCE(revoked_at, ?)
                WHERE link_id = ?
                """,
                (revoked_at, link_id),
            )
            updated = conn.execute(
                "SELECT * FROM guardian_ward_links WHERE link_id = ?",
                (link_id,),
            ).fetchone()
        return self._guardian_ward_from_row(updated) if updated else None

    def guardian_invite_by_id(self, invite_id: str) -> dict[str, Any] | None:
        row = self._fetch_one(
            """
            SELECT invites.* FROM guardian_invites AS invites
            JOIN homes ON homes.home_id = invites.home_id
            JOIN users ON users.home_id = invites.home_id
            WHERE invites.invite_id = ?
            """,
            (invite_id,),
        )
        data = sqlite_row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def guardian_invite_by_lookup(self, invite_lookup: str) -> dict[str, Any] | None:
        lookup = normalize_invite_lookup(invite_lookup)
        if not lookup:
            return None
        row = self._fetch_one(
            """
            SELECT invites.* FROM guardian_invites AS invites
            JOIN homes ON homes.home_id = invites.home_id
            JOIN users ON users.home_id = invites.home_id
            WHERE invites.invite_id = ? OR invites.short_code = ?
            """,
            (lookup, lookup.upper()),
        )
        data = sqlite_row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def guardian_invite_by_session_token(self, session_token: str) -> dict[str, Any] | None:
        token_hash = hash_guardian_session_token(session_token)
        if not token_hash:
            return None
        row = self._fetch_one(
            """
            SELECT invites.* FROM guardian_invites AS invites
            JOIN homes ON homes.home_id = invites.home_id
            JOIN users ON users.home_id = invites.home_id
            WHERE invites.guardian_token_hash = ?
            """,
            (token_hash,),
        )
        data = sqlite_row_to_dict(row)
        return normalize_guardian_invite(data) if data else None

    def mark_guardian_invite_viewed(self, invite_id: str, guardian_token_hash: str | None = None) -> dict[str, Any] | None:
        if self.guardian_invite_by_id(invite_id) is None:
            return None
        viewed_at = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE guardian_invites
                SET last_viewed_at = ?,
                    accepted_at = COALESCE(accepted_at, ?),
                    status = CASE WHEN status IN ('pending', 'sent') THEN 'accepted' ELSE status END,
                    guardian_token_hash = CASE WHEN ? IS NOT NULL THEN ? ELSE guardian_token_hash END,
                    session_created_at = CASE WHEN ? IS NOT NULL THEN COALESCE(session_created_at, ?) ELSE session_created_at END,
                    session_last_used_at = CASE WHEN ? IS NOT NULL THEN ? ELSE session_last_used_at END
                WHERE invite_id = ? AND revoked_at IS NULL
                """,
                (
                    viewed_at,
                    viewed_at,
                    guardian_token_hash,
                    guardian_token_hash,
                    guardian_token_hash,
                    viewed_at,
                    guardian_token_hash,
                    viewed_at,
                    invite_id,
                ),
            )
        invite = self.guardian_invite_by_id(invite_id)
        return invite

    def mark_guardian_session_used(self, invite_id: str) -> dict[str, Any] | None:
        if self.guardian_invite_by_id(invite_id) is None:
            return None
        viewed_at = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE guardian_invites
                SET last_viewed_at = ?,
                    session_last_used_at = ?
                WHERE invite_id = ? AND revoked_at IS NULL
                """,
                (viewed_at, viewed_at, invite_id),
            )
        invite = self.guardian_invite_by_id(invite_id)
        return invite

    def revoke_guardian_invite(self, invite_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        revoked_at = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE guardian_invites
                SET status = 'revoked',
                    revoked_at = ?,
                    message = '보호자 초대를 취소했어요.'
                WHERE invite_id = ? AND home_id = ?
                """,
                (revoked_at, invite_id, home_id),
            )
            conn.execute(
                """
                UPDATE guardian_ward_links
                SET status = 'revoked',
                    revoked_at = ?
                WHERE invite_id = ? AND home_id = ?
                """,
                (revoked_at, invite_id, home_id),
            )
        invite = self.guardian_invite_by_id(invite_id)
        if not invite or invite.get("home_id") != home_id:
            return None
        return invite

    def delete_guardian_invite(self, invite_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        """보호자 초대를 '실제로' 삭제한다(revoke=상태표시와 달리 행 자체 제거). 연결된 ward_link 도 함께 지운다.
        삭제 전 스냅샷을 반환하고, 없거나 다른 home 이면 None(404 용)."""
        invite = self.guardian_invite_by_id(invite_id)
        if not invite or invite.get("home_id") != home_id:
            return None
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM guardian_ward_links WHERE invite_id = ? AND home_id = ?", (invite_id, home_id))
            conn.execute("DELETE FROM guardian_invites WHERE invite_id = ? AND home_id = ?", (invite_id, home_id))
        return invite

    def purge_stale_guardian_invites(self, home_id: str = HOME["home_id"], older_than_days: int = 90) -> int:
        """오래된 '만료/취소' 초대 행을 정리한다(누적 방지). pending(아직 유효)·accepted(연결됨)는 보존한다.
        타임스탬프는 문자열 비교 대신 파싱해 비교(포맷 차이로 인한 오삭제 방지). 삭제 개수 반환."""
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        rows = self._fetch_all("SELECT * FROM guardian_invites WHERE home_id = ?", (home_id,))
        purge_ids: list[str] = []
        for row in rows:
            invite = sqlite_row_to_dict(row) or {}
            status = effective_invite_status(invite)
            if status == "revoked":
                stamp = parse_utc_text(invite.get("revoked_at")) or parse_utc_text(invite.get("created_at"))
            elif status == "expired":
                stamp = parse_utc_text(invite.get("expires_at")) or parse_utc_text(invite.get("created_at"))
            else:
                continue  # pending/accepted 는 정리 대상 아님
            if stamp is not None and stamp < cutoff:
                invite_id = invite.get("invite_id")
                if invite_id:
                    purge_ids.append(str(invite_id))
        if not purge_ids:
            return 0
        placeholders = ",".join("?" * len(purge_ids))
        with self._lock, self._connect() as conn:
            conn.execute(f"DELETE FROM guardian_ward_links WHERE invite_id IN ({placeholders})", purge_ids)
            conn.execute(f"DELETE FROM guardian_invites WHERE invite_id IN ({placeholders})", purge_ids)
        return len(purge_ids)

    def notifications(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]]:
        rows = self._fetch_all("SELECT * FROM notifications WHERE home_id = ? ORDER BY id DESC", (home_id,))
        notifications: list[dict[str, Any]] = []
        seen_scan_cards: set[tuple[str, str, str]] = set()
        for row in rows:
            if not self._notification_is_public(row, home_id):
                continue
            if str(row["type"] or "") == "scan_completed":
                key = (
                    str(row["home_id"] or ""),
                    str(row["scan_id"] or ""),
                    str(row["scan_source"] or ""),
                )
                if key in seen_scan_cards:
                    continue
                seen_scan_cards.add(key)
            notifications.append(
                sanitize_public_notification(self._notification_from_row(row))
            )
        return notifications

    def _notification_is_public(self, row: sqlite3.Row, home_id: str) -> bool:
        if str(row["type"] or "") != "scan_completed":
            return True
        scan_id = str(row["scan_id"] or "").strip()
        if str(row["scan_source"] or "") != _AUTHORITATIVE_SCAN_SOURCE or not scan_id:
            return False
        scan_row = self._fetch_one(
            """
            SELECT status, scan_source, security_score_json
            FROM scans WHERE scan_id = ? AND home_id = ?
            """,
            (scan_id, home_id),
        )
        if scan_row is None or str(scan_row["scan_source"] or "") != _AUTHORITATIVE_SCAN_SOURCE:
            return False
        try:
            score = json.loads(scan_row["security_score_json"] or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(score, Mapping):
            return False
        if str(scan_row["status"] or "") == "partial":
            return str(row["title"] or "") == "보안 점검 일부 완료"
        return (
            str(scan_row["status"] or "") == "completed"
            and str(row["title"] or "") == "보안 점검 완료"
            and score.get("scan_complete") is True
            and score.get("coverage_complete") is True
        )

    def mark_notification_read(self, notification_id: str, home_id: str = HOME["home_id"]) -> dict[str, Any] | None:
        existing = self._fetch_one(
            "SELECT * FROM notifications WHERE notification_id = ? AND home_id = ?",
            (notification_id, home_id),
        )
        if existing is None or not self._notification_is_public(existing, home_id):
            return None
        with self._connect() as conn:
            conn.execute("UPDATE notifications SET read = 1 WHERE notification_id = ? AND home_id = ?", (notification_id, home_id))
        row = self._fetch_one("SELECT * FROM notifications WHERE notification_id = ? AND home_id = ?", (notification_id, home_id))
        return sanitize_public_notification(self._notification_from_row(row)) if row else None

    def register_fcm_token(self, fcm_token: str, platform: str, user_id: str) -> dict[str, Any]:
        updated_at = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO fcm_tokens (fcm_token, platform, user_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fcm_token) DO UPDATE SET
                    platform = excluded.platform,
                    user_id = excluded.user_id,
                    updated_at = excluded.updated_at
                """,
                (fcm_token, platform, user_id, updated_at),
            )
        return {"registered": True, "platform": platform, "updated_at": updated_at}

    def delete_fcm_token(self, fcm_token: str, user_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM fcm_tokens WHERE fcm_token = ? AND user_id = ?", (fcm_token, user_id))
            return cursor.rowcount > 0

    def list_fcm_tokens(self, user_id: str | None = None) -> list[str]:
        if user_id:
            rows = self._fetch_all("SELECT fcm_token FROM fcm_tokens WHERE user_id = ?", (user_id,))
        else:
            rows = self._fetch_all("SELECT fcm_token FROM fcm_tokens")
        return [row["fcm_token"] for row in rows]

    # ---------------- 인증 세션 ----------------

    def create_auth_session(
        self,
        *,
        session_id: str,
        user_id: str,
        home_id: str,
        role: str,
        refresh_token_hash: str,
        expires_at: str,
        superseded_refresh_token_hash: str | None = None,
        activation_state: str = "active",
        handoff_predecessor_session_id: str | None = None,
        handoff_predecessor_refresh_token_hash: str | None = None,
        handoff_id_hash: str | None = None,
        handoff_expires_at: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        values = {
            "session_id": session_id,
            "user_id": user_id,
            "home_id": home_id,
            "role": role,
            "refresh_token_hash": refresh_token_hash,
            "previous_refresh_token_hash": None,
            "refresh_retry_id": None,
            "refresh_retry_until": None,
            "activation_state": activation_state,
            "handoff_predecessor_session_id": handoff_predecessor_session_id,
            "handoff_predecessor_refresh_token_hash": handoff_predecessor_refresh_token_hash,
            "handoff_id_hash": handoff_id_hash,
            "handoff_expires_at": handoff_expires_at,
            "handoff_completed_at": None,
            "created_at": now,
            "last_used_at": now,
            "expires_at": expires_at,
            "revoked_at": None,
        }
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO auth_sessions (
                    session_id, user_id, home_id, role, refresh_token_hash,
                    previous_refresh_token_hash, refresh_retry_id, refresh_retry_until,
                    activation_state, handoff_predecessor_session_id,
                    handoff_predecessor_refresh_token_hash, handoff_id_hash,
                    handoff_expires_at, handoff_completed_at,
                    created_at, last_used_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(values.values()),
            )
            # Legacy/internal callers can still use explicit supersession.  The
            # public Google callback intentionally never uses it: role changes
            # are staged and completed by complete_auth_handoff instead.
            if superseded_refresh_token_hash:
                conn.execute(
                    """
                    UPDATE auth_sessions
                    SET revoked_at = COALESCE(revoked_at, ?), last_used_at = ?
                    WHERE (refresh_token_hash = ? OR previous_refresh_token_hash = ?)
                      AND session_id != ?
                      AND revoked_at IS NULL
                    """,
                    (now, now, superseded_refresh_token_hash, superseded_refresh_token_hash, session_id),
                )
        return values

    def auth_session_by_id(self, session_id: str) -> dict[str, Any] | None:
        return sqlite_row_to_dict(self._fetch_one("SELECT * FROM auth_sessions WHERE session_id = ?", (session_id,)))

    def auth_session_by_refresh_hash(self, refresh_token_hash: str) -> dict[str, Any] | None:
        return sqlite_row_to_dict(
            self._fetch_one("SELECT * FROM auth_sessions WHERE refresh_token_hash = ?", (refresh_token_hash,))
        )

    def auth_session_by_previous_refresh_hash(self, refresh_token_hash: str) -> dict[str, Any] | None:
        return sqlite_row_to_dict(
            self._fetch_one(
                "SELECT * FROM auth_sessions WHERE previous_refresh_token_hash = ?",
                (refresh_token_hash,),
            )
        )

    def complete_auth_handoff(
        self,
        *,
        predecessor_refresh_token_hash: str,
        successor_refresh_token_hash: str,
        handoff_id_hash: str,
    ) -> dict[str, Any] | None:
        """Activate one staged successor and revoke its predecessor atomically.

        The caller has already HMACed every supplied secret.  This method
        deliberately accepts only those HMAC values and never writes raw
        refresh tokens or the handoff id.  An already-completed matching
        handoff returns the active successor so retry after response loss is
        safe and idempotent.
        """
        now = utc_now()
        with self._lock, self._connect() as conn:
            candidate = sqlite_row_to_dict(
                conn.execute(
                    "SELECT * FROM auth_sessions WHERE refresh_token_hash = ?",
                    (successor_refresh_token_hash,),
                ).fetchone()
            )
            if candidate is None or candidate.get("revoked_at"):
                return None
            if not (
                hmac.compare_digest(
                    str(candidate.get("handoff_predecessor_refresh_token_hash") or ""),
                    predecessor_refresh_token_hash,
                )
                and hmac.compare_digest(str(candidate.get("handoff_id_hash") or ""), handoff_id_hash)
                and candidate.get("handoff_predecessor_session_id")
            ):
                return None

            activation_state = str(candidate.get("activation_state") or "active")
            if activation_state == "active" and candidate.get("handoff_completed_at"):
                return candidate
            if activation_state != "pending":
                return None
            expires_at = parse_utc_text(candidate.get("handoff_expires_at"))
            if expires_at is None or expires_at <= datetime.now(UTC):
                return None

            predecessor_id = str(candidate["handoff_predecessor_session_id"])
            retired = conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, ?), last_used_at = ?
                WHERE session_id = ?
                  AND refresh_token_hash = ?
                  AND activation_state = 'active'
                  AND revoked_at IS NULL
                """,
                (now, now, predecessor_id, predecessor_refresh_token_hash),
            )
            if retired.rowcount != 1:
                return None
            activated = conn.execute(
                """
                UPDATE auth_sessions
                SET activation_state = 'active', handoff_completed_at = ?, last_used_at = ?
                WHERE session_id = ?
                  AND refresh_token_hash = ?
                  AND activation_state = 'pending'
                  AND revoked_at IS NULL
                """,
                (now, now, str(candidate["session_id"]), successor_refresh_token_hash),
            )
            if activated.rowcount != 1:
                # The surrounding connection context rolls both updates back.
                raise RuntimeError("auth handoff activation race")
            return sqlite_row_to_dict(
                conn.execute(
                    "SELECT * FROM auth_sessions WHERE session_id = ?",
                    (str(candidate["session_id"]),),
                ).fetchone()
            )

    def rotate_auth_session(
        self,
        *,
        session_id: str,
        previous_refresh_token_hash: str,
        refresh_token_hash: str,
        expires_at: str,
        refresh_retry_id: str | None = None,
        refresh_retry_until: str | None = None,
    ) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE auth_sessions
                SET refresh_token_hash = ?, previous_refresh_token_hash = ?,
                    refresh_retry_id = ?, refresh_retry_until = ?,
                    last_used_at = ?, expires_at = ?
                WHERE session_id = ? AND refresh_token_hash = ? AND revoked_at IS NULL
                """,
                (
                    refresh_token_hash,
                    previous_refresh_token_hash if refresh_retry_id else None,
                    refresh_retry_id,
                    refresh_retry_until,
                    utc_now(),
                    expires_at,
                    session_id,
                    previous_refresh_token_hash,
                ),
            )
            return cursor.rowcount == 1

    def recover_auth_session_rotation(
        self,
        *,
        session_id: str,
        previous_refresh_token_hash: str,
        refresh_retry_id: str,
        refresh_token_hash: str,
    ) -> bool:
        """Atomically attest that a pending rotation is still recoverable."""
        now = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE auth_sessions
                SET last_used_at = ?
                WHERE session_id = ?
                  AND previous_refresh_token_hash = ?
                  AND refresh_retry_id = ?
                  AND refresh_token_hash = ?
                  AND refresh_retry_until > ?
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    session_id,
                    previous_refresh_token_hash,
                    refresh_retry_id,
                    refresh_token_hash,
                    now,
                ),
            )
            return cursor.rowcount == 1

    def revoke_auth_session_by_refresh_hash(self, refresh_token_hash: str) -> bool:
        now = utc_now()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, ?), last_used_at = ?
                WHERE (refresh_token_hash = ? OR previous_refresh_token_hash = ?)
                  AND revoked_at IS NULL
                """,
                (now, now, refresh_token_hash, refresh_token_hash),
            )
            return cursor.rowcount == 1

    def revoke_auth_session_by_id(self, session_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, ?), last_used_at = ?
                WHERE session_id = ? AND revoked_at IS NULL
                """,
                (utc_now(), utc_now(), session_id),
            )
            return cursor.rowcount == 1

    def _initialize(self) -> None:
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            self._configure_database(conn)
            if self._schema_migration_applied(conn):
                # The marker suppresses release-wide schema/backfill work, not
                # runtime integrity checks.  Rows can become inconsistent
                # after the marker was written (for example, an interrupted
                # role handoff or legacy data imported into an existing DB),
                # so enforce these narrow invariants on every repository
                # startup without replaying the expensive scan migrations.
                self._purge_legacy_synthetic_state(conn)
                return
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    nickname TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email_verified INTEGER NOT NULL,
                    home_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS homes (
                    home_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    mode TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    home_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    manufacturer TEXT NOT NULL,
                    model TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    online INTEGER NOT NULL,
                    last_seen TEXT NOT NULL,
                    open_ports_json TEXT NOT NULL,
                    services_json TEXT NOT NULL,
                    default_credentials INTEGER NOT NULL,
                    encryption TEXT NOT NULL,
                    firmware TEXT NOT NULL,
                    vulnerabilities_json TEXT NOT NULL,
                    discovery_sources_json TEXT NOT NULL,
                    fingerprints_json TEXT NOT NULL,
                    risk_signals_json TEXT NOT NULL,
                    scan_source TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    is_unresolved INTEGER NOT NULL DEFAULT 0,
                    is_phantom INTEGER NOT NULL DEFAULT 0,
                    security_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    risk_summary TEXT NOT NULL,
                    recommended_actions_json TEXT NOT NULL,
                    risk_rank INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS device_identity_history (
                    resolution_id TEXT PRIMARY KEY,
                    home_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    network_scope_id TEXT,
                    physical_mac TEXT,
                    observed_at TEXT NOT NULL,
                    identity_status TEXT NOT NULL,
                    manufacturer TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    model TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    evidence_json TEXT NOT NULL,
                    candidates_json TEXT NOT NULL,
                    note TEXT NOT NULL,
                    resolver_version TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS identity_enrichment_jobs (
                    job_id TEXT PRIMARY KEY,
                    job_key TEXT NOT NULL UNIQUE,
                    home_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    network_scope_id TEXT,
                    physical_mac TEXT,
                    evidence_binding_signature TEXT,
                    status TEXT NOT NULL CHECK (
                        status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')
                    ),
                    blocked_reason TEXT,
                    evidence_json TEXT NOT NULL,
                    evidence_signature TEXT NOT NULL,
                    seen_count INTEGER NOT NULL CHECK (seen_count >= 1),
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolution_json TEXT,
                    source_reference TEXT,
                    resolution_provenance TEXT CHECK (
                        resolution_provenance IS NULL OR
                        resolution_provenance IN (
                            'operator-reviewed',
                            'automated-official-web-search',
                            'automated-official-http'
                        )
                    ),
                    resolution_signature TEXT,
                    research_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (research_attempt_count >= 0),
                    research_last_attempt_at TEXT,
                    research_next_attempt_at TEXT,
                    research_policy_version TEXT,
                    catalog_reconcile_version TEXT,
                    resolved_at TEXT,
                    FOREIGN KEY (home_id) REFERENCES homes(home_id) ON DELETE CASCADE,
                    CHECK (
                        status <> 'resolved' OR (
                            network_scope_id IS NOT NULL AND
                            (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND
                            resolution_json IS NOT NULL AND
                            source_reference IS NOT NULL AND
                            resolved_at IS NOT NULL
                        )
                    )
                );

                CREATE TABLE IF NOT EXISTS verified_product_catalog (
                    manufacturer TEXT NOT NULL,
                    manufacturer_key TEXT NOT NULL,
                    exact_model TEXT NOT NULL,
                    model_key TEXT NOT NULL,
                    device_type TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    provenance TEXT NOT NULL CHECK (
                        provenance IN (
                            'operator-reviewed',
                            'automated-official-web-search',
                            'automated-official-http'
                        )
                    ),
                    verified_at TEXT NOT NULL,
                    catalog_signature TEXT NOT NULL,
                    UNIQUE (manufacturer_key, model_key)
                );

                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    home_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    action_guide TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    home_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    scan_profile TEXT NOT NULL,
                    scan_source TEXT NOT NULL,
                    network_context_json TEXT NOT NULL,
                    network_scope_id TEXT,
                    current_step TEXT NOT NULL,
                    devices_found INTEGER NOT NULL,
                    high_risk_devices INTEGER NOT NULL,
                    security_score_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    device_snapshot_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guardian_invites (
                    invite_id TEXT PRIMARY KEY,
                    home_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    display_name TEXT,
                    ward_account_name TEXT,
                    short_code TEXT,
                    deep_link TEXT,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    accepted_at TEXT,
                    revoked_at TEXT,
                    last_viewed_at TEXT,
                    guardian_token_hash TEXT,
                    session_created_at TEXT,
                    session_last_used_at TEXT
                );

                CREATE TABLE IF NOT EXISTS guardian_accounts (
                    guardian_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    display_name TEXT,
                    provider TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guardian_ward_links (
                    link_id TEXT PRIMARY KEY,
                    guardian_id TEXT NOT NULL,
                    invite_id TEXT NOT NULL UNIQUE,
                    home_id TEXT NOT NULL,
                    ward_account_name TEXT,
                    ward_alias TEXT,
                    ward_display_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    revoked_at TEXT,
                    last_viewed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    notification_id TEXT NOT NULL UNIQUE,
                    home_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    scan_id TEXT,
                    scan_source TEXT,
                    read INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fcm_tokens (
                    fcm_token TEXT PRIMARY KEY,
                    platform TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    home_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    refresh_token_hash TEXT NOT NULL UNIQUE,
                    previous_refresh_token_hash TEXT,
                    refresh_retry_id TEXT,
                    refresh_retry_until TEXT,
                    activation_state TEXT NOT NULL DEFAULT 'active',
                    handoff_predecessor_session_id TEXT,
                    handoff_predecessor_refresh_token_hash TEXT,
                    handoff_id_hash TEXT,
                    handoff_expires_at TEXT,
                    handoff_completed_at TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS device_aliases (
                    home_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    network_scope_id TEXT,
                    physical_mac TEXT,
                    alias TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (home_id, device_id)
                );
                """
            )
            self._migrate_schema(conn)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS repository_migrations (
                    migration_id TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO repository_migrations (migration_id, applied_at)
                VALUES (?, ?)
                """,
                (_SQLITE_SCHEMA_MIGRATION_ID, utc_now()),
            )

    @staticmethod
    def _schema_migration_applied(conn: sqlite3.Connection) -> bool:
        marker_table = conn.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'repository_migrations'
            """
        ).fetchone()
        if marker_table is None:
            return False
        return conn.execute(
            "SELECT 1 FROM repository_migrations WHERE migration_id = ?",
            (_SQLITE_SCHEMA_MIGRATION_ID,),
        ).fetchone() is not None

    def _configure_database(self, conn: sqlite3.Connection) -> None:
        """Set database-wide options once per repository process.

        Reading the current journal mode does not request a write lock.  Only
        a database that has not yet entered WAL mode performs the mutating
        pragma, and ordinary API/worker request connections never execute it.
        """

        if str(self.db_path) == ":memory:":
            return
        current_mode = str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if current_mode == "wal":
            return
        selected_mode = str(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
        if selected_mode != "wal":
            raise RuntimeError(f"failed to enable SQLite WAL mode: {selected_mode}")

    def _migrate_schema(self, conn: sqlite3.Connection) -> None:
        self._ensure_column(conn, "devices", "services_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column(conn, "devices", "discovery_sources_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column(conn, "devices", "fingerprints_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column(conn, "devices", "risk_signals_json", "TEXT NOT NULL DEFAULT '[]'")
        self._ensure_column(conn, "devices", "scan_source", "TEXT")
        self._ensure_column(conn, "devices", "confidence", "REAL NOT NULL DEFAULT 0.85")
        self._ensure_column(conn, "devices", "is_unresolved", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "devices", "is_phantom", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "device_identity_history", "network_scope_id", "TEXT")
        self._ensure_column(conn, "device_identity_history", "physical_mac", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "resolution_provenance", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "resolution_signature", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "evidence_binding_signature", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_attempt_count", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_last_attempt_at", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_next_attempt_at", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "research_policy_version", "TEXT")
        self._ensure_column(conn, "identity_enrichment_jobs", "catalog_reconcile_version", "TEXT")
        # Old databases can contain ``resolved`` rows created before strong
        # scope/binding and signed-provenance rules existed.  Downgrade those
        # rows while the legacy table still accepts them; copying first would
        # make the new CHECK reject the entire startup migration.
        self._quarantine_unsigned_legacy_resolutions(conn)
        self._quarantine_invalid_legacy_resolutions(conn)
        self._migrate_identity_enrichment_status_constraint(conn)
        self._ensure_column(conn, "scans", "scan_source", "TEXT")
        self._ensure_column(conn, "scans", "network_context_json", "TEXT NOT NULL DEFAULT '{}'")
        self._ensure_column(conn, "scans", "network_scope_id", "TEXT")
        self._ensure_column(conn, "security_events", "home_id", "TEXT")
        self._ensure_column(conn, "guardian_invites", "home_id", "TEXT")
        self._ensure_column(conn, "guardian_invites", "display_name", "TEXT")
        self._ensure_column(conn, "guardian_invites", "ward_account_name", "TEXT")
        self._ensure_column(conn, "guardian_invites", "short_code", "TEXT")
        self._ensure_column(conn, "guardian_invites", "deep_link", "TEXT")
        self._ensure_column(conn, "guardian_invites", "expires_at", "TEXT")
        self._ensure_column(conn, "guardian_invites", "accepted_at", "TEXT")
        self._ensure_column(conn, "guardian_invites", "revoked_at", "TEXT")
        self._ensure_column(conn, "guardian_invites", "last_viewed_at", "TEXT")
        self._ensure_column(conn, "guardian_invites", "guardian_token_hash", "TEXT")
        self._ensure_column(conn, "guardian_invites", "session_created_at", "TEXT")
        self._ensure_column(conn, "guardian_invites", "session_last_used_at", "TEXT")
        self._ensure_column(conn, "guardian_ward_links", "ward_account_name", "TEXT")
        self._ensure_column(conn, "guardian_ward_links", "ward_alias", "TEXT")
        self._ensure_column(conn, "notifications", "home_id", "TEXT")
        self._ensure_column(conn, "notifications", "scan_id", "TEXT")
        self._ensure_column(conn, "notifications", "scan_source", "TEXT")
        self._ensure_column(conn, "auth_sessions", "previous_refresh_token_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "refresh_retry_id", "TEXT")
        self._ensure_column(conn, "auth_sessions", "refresh_retry_until", "TEXT")
        self._ensure_column(conn, "auth_sessions", "activation_state", "TEXT NOT NULL DEFAULT 'active'")
        self._ensure_column(conn, "auth_sessions", "handoff_predecessor_session_id", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_predecessor_refresh_token_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_id_hash", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_expires_at", "TEXT")
        self._ensure_column(conn, "auth_sessions", "handoff_completed_at", "TEXT")
        self._ensure_column(conn, "device_aliases", "network_scope_id", "TEXT")
        self._ensure_column(conn, "device_aliases", "physical_mac", "TEXT")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_guardian_invites_short_code ON guardian_invites(short_code)")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_guardian_invites_token_hash ON guardian_invites(guardian_token_hash) WHERE guardian_token_hash IS NOT NULL"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_guardian_accounts_email ON guardian_accounts(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_guardian ON guardian_ward_links(guardian_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_invite ON guardian_ward_links(invite_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_guardian_ward_links_status ON guardian_ward_links(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_previous_refresh ON auth_sessions(previous_refresh_token_hash)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_handoff_predecessor ON auth_sessions(handoff_predecessor_session_id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_identity_history_device "
            "ON device_identity_history(home_id, device_id, observed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_device_identity_history_physical_scope "
            "ON device_identity_history(home_id, network_scope_id, physical_mac, observed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home "
            "ON identity_enrichment_jobs(home_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_status_updated "
            "ON identity_enrichment_jobs(status, updated_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_identity_enrichment_jobs_home_status_seen "
            "ON identity_enrichment_jobs(home_id, status, last_seen_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_verified_product_catalog_model "
            "ON verified_product_catalog(model_key)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_home_scope_created_at "
            "ON scans(home_id, network_scope_id, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_auth_sessions_active_previous_refresh "
            "ON auth_sessions(previous_refresh_token_hash) "
            "WHERE previous_refresh_token_hash IS NOT NULL AND revoked_at IS NULL"
        )
        self._purge_legacy_synthetic_state(conn)
        self._backfill_guardian_invites(conn)
        self._backfill_guardian_ward_links(conn)
        self._normalize_legacy_public_device_data(conn)
        self._backfill_network_scope_ids(conn)
        self._supersede_stale_identity_jobs_from_latest_scans(conn)
        self._backfill_verified_product_catalog(conn)

    @staticmethod
    def _quarantine_unsigned_legacy_resolutions(conn: sqlite3.Connection) -> None:
        """Never manufacture provenance for a resolution created before signing."""

        conn.execute(
            """
            UPDATE identity_enrichment_jobs
            SET status = 'review_required',
                blocked_reason = 'UNSIGNED_LEGACY_RESOLUTION_REVIEW_REQUIRED',
                resolution_json = NULL, source_reference = NULL,
                resolution_provenance = NULL, resolution_signature = NULL,
                research_attempt_count = 0, research_last_attempt_at = NULL,
                research_next_attempt_at = NULL, resolved_at = NULL,
                updated_at = ?
            WHERE status = 'resolved'
              AND (resolution_signature IS NULL OR resolution_signature = '')
            """,
            (utc_now(),),
        )

    @staticmethod
    def _quarantine_invalid_legacy_resolutions(conn: sqlite3.Connection) -> None:
        """Downgrade signed legacy resolutions that cannot satisfy binding rules.

        This intentionally runs before the identity-job table is rebuilt with
        the current CHECK.  Evidence is retained in ``evidence_json`` for audit,
        while the untrusted resolution fields are cleared so it cannot be
        applied to a device.
        """

        rows = conn.execute(
            """
            SELECT job_id, network_scope_id, physical_mac,
                   evidence_binding_signature, resolution_json,
                   source_reference, resolution_provenance, resolved_at
            FROM identity_enrichment_jobs
            WHERE status = 'resolved'
            """
        ).fetchall()
        invalid_job_ids: list[str] = []
        for row in rows:
            scope_is_strong = is_strong_network_scope_id(row["network_scope_id"])
            physical_mac = normalized_physical_mac(row["physical_mac"])
            evidence_binding = str(row["evidence_binding_signature"] or "").strip()
            binding_is_valid = physical_mac is not None or bool(
                _STABLE_EVIDENCE_BINDING_SIGNATURE.fullmatch(evidence_binding)
            )
            resolution_is_complete = all(
                str(row[column] or "").strip()
                for column in ("resolution_json", "source_reference", "resolved_at")
            )
            provenance_is_valid = row["resolution_provenance"] in IDENTITY_RESOLUTION_PROVENANCES
            if not (
                scope_is_strong
                and binding_is_valid
                and resolution_is_complete
                and provenance_is_valid
            ):
                invalid_job_ids.append(str(row["job_id"]))

        if not invalid_job_ids:
            return
        updated_at = utc_now()
        for job_id in invalid_job_ids:
            conn.execute(
                """
                UPDATE identity_enrichment_jobs
                SET status = 'review_required',
                    blocked_reason = 'INVALID_LEGACY_RESOLUTION_REVIEW_REQUIRED',
                    resolution_json = NULL, source_reference = NULL,
                    resolution_provenance = NULL, resolution_signature = NULL,
                    research_attempt_count = 0, research_last_attempt_at = NULL,
                    research_next_attempt_at = NULL, resolved_at = NULL,
                    updated_at = ?
                WHERE job_id = ? AND status = 'resolved'
                """,
                (updated_at, job_id),
            )

    def _backfill_verified_product_catalog(self, conn: sqlite3.Connection) -> None:
        """Promote only fully signed historical resolutions to global facts."""

        rows = conn.execute(
            "SELECT * FROM identity_enrichment_jobs WHERE status = 'resolved' "
            "ORDER BY resolved_at, job_id"
        ).fetchall()
        for row in rows:
            job = self._identity_enrichment_job_from_row(row)
            resolution = (job or {}).get("resolution")
            if not isinstance(job, Mapping) or not isinstance(resolution, Mapping):
                continue
            resolution_id = str(resolution.get("history_resolution_id") or "")
            if not resolution_id:
                continue
            history_row = conn.execute(
                "SELECT * FROM device_identity_history WHERE resolution_id = ?",
                (resolution_id,),
            ).fetchone()
            if history_row is None:
                continue
            history = sqlite_row_to_dict(history_row) or {}
            try:
                identity_evidence = json.loads(history.get("evidence_json") or "[]")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            history["identity_evidence"] = (
                identity_evidence if isinstance(identity_evidence, list) else []
            )
            trusted = trusted_identity_resolution(history, job)
            if trusted is None:
                continue
            try:
                validated = validate_identity_resolution(
                    manufacturer=trusted["manufacturer"],
                    device_type=trusted["device_type"],
                    model=trusted["model"],
                    source_reference=job.get("source_reference"),
                )
                self._register_verified_product_catalog(
                    conn,
                    validated=validated,
                    provenance=str(job.get("resolution_provenance") or ""),
                    verified_at=str(job.get("resolved_at") or ""),
                )
            except IdentityEnrichmentError:
                # Conflicting or otherwise invalid historical facts remain in
                # their home audit trail but are not globalized.
                continue

    @staticmethod
    def _purge_legacy_synthetic_state(conn: sqlite3.Connection) -> None:
        """Delete only unmistakable legacy fixture principals and data.

        Earlier builds inserted one reserved local principal at startup. Exact
        identifiers are migration input, never defaults or selectable runtime
        data. Historic scan/device rows are deliberately retained: older
        migrations labelled pre-existing real observations with synthetic
        source defaults, so a source label alone is not deletion provenance.
        Public/current reads separately require a validated Android scan.
        """

        legacy_user_id = "user-0001"
        legacy_user_email = "tester@homeguardian.local"

        synthetic_guardian_ids = [
            str(row["guardian_id"])
            for row in conn.execute(
                "SELECT guardian_id FROM guardian_accounts WHERE provider = 'test'"
            ).fetchall()
        ]
        synthetic_invite_ids: list[str] = []
        if synthetic_guardian_ids:
            placeholders = ",".join("?" * len(synthetic_guardian_ids))
            synthetic_invite_ids = [
                str(row["invite_id"])
                for row in conn.execute(
                    f"SELECT invite_id FROM guardian_ward_links WHERE guardian_id IN ({placeholders})",
                    synthetic_guardian_ids,
                ).fetchall()
            ]
        if synthetic_invite_ids:
            invite_placeholders = ",".join("?" * len(synthetic_invite_ids))
            conn.execute(
                f"""
                UPDATE guardian_invites
                SET status = CASE WHEN revoked_at IS NULL THEN 'pending' ELSE 'revoked' END,
                    message = CASE
                        WHEN revoked_at IS NULL THEN '보호자 연결을 다시 진행해 주세요.'
                        ELSE message
                    END,
                    accepted_at = NULL,
                    last_viewed_at = NULL,
                    guardian_token_hash = NULL,
                    session_created_at = NULL,
                    session_last_used_at = NULL
                WHERE invite_id IN ({invite_placeholders})
                """,
                synthetic_invite_ids,
            )
        for guardian_id in synthetic_guardian_ids:
            conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (guardian_id,))
            conn.execute("DELETE FROM guardian_ward_links WHERE guardian_id = ?", (guardian_id,))
            conn.execute("DELETE FROM guardian_accounts WHERE guardian_id = ?", (guardian_id,))

        conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (legacy_user_id,))
        conn.execute("DELETE FROM fcm_tokens WHERE user_id = ?", (legacy_user_id,))
        conn.execute(
            "DELETE FROM users WHERE user_id = ? OR email = ?",
            (legacy_user_id, legacy_user_email),
        )
        conn.execute(
            "UPDATE guardian_ward_links SET status = 'revoked' "
            "WHERE revoked_at IS NOT NULL AND status <> 'revoked'"
        )

        # An accepted invite is real only while an active, same-home link is
        # backed by a complete Google guardian and a complete resident owner.
        # Reset broken legacy acceptance rather than deleting the resident's
        # original invitation intent.
        conn.execute(
            """
            UPDATE guardian_invites
            SET status = CASE WHEN revoked_at IS NULL THEN 'pending' ELSE 'revoked' END,
                message = CASE
                    WHEN revoked_at IS NULL THEN '보호자 연결을 다시 진행해 주세요.'
                    ELSE message
                END,
                accepted_at = NULL,
                last_viewed_at = NULL,
                guardian_token_hash = NULL,
                session_created_at = NULL,
                session_last_used_at = NULL
            WHERE (accepted_at IS NOT NULL OR LOWER(COALESCE(status, '')) = 'accepted')
              AND NOT EXISTS (
                    SELECT 1
                    FROM guardian_ward_links AS links
                    JOIN guardian_accounts AS accounts
                      ON accounts.guardian_id = links.guardian_id
                    JOIN homes ON homes.home_id = links.home_id
                    JOIN users ON users.home_id = links.home_id
                    WHERE links.invite_id = guardian_invites.invite_id
                      AND links.home_id = guardian_invites.home_id
                      AND links.status = 'active'
                      AND links.revoked_at IS NULL
                      AND LOWER(TRIM(accounts.provider)) = 'google'
                      AND TRIM(COALESCE(accounts.email, '')) <> ''
                      AND TRIM(COALESCE(accounts.display_name, '')) <> ''
                      AND users.role = 'user'
                      AND TRIM(COALESCE(users.email, '')) <> ''
                      AND TRIM(COALESCE(users.nickname, '')) <> ''
               )
            """
        )

        # Orphaned/mismatched guardian records must never cross a home boundary.
        conn.execute(
            """
            DELETE FROM guardian_ward_links
            WHERE home_id IS NULL OR TRIM(home_id) = ''
               OR NOT EXISTS (
                    SELECT 1 FROM homes
                    JOIN users ON users.home_id = homes.home_id
                    WHERE homes.home_id = guardian_ward_links.home_id
                      AND users.role = 'user'
                      AND TRIM(COALESCE(users.email, '')) <> ''
                      AND TRIM(COALESCE(users.nickname, '')) <> ''
               )
               OR NOT EXISTS (
                    SELECT 1 FROM guardian_invites
                    WHERE guardian_invites.invite_id = guardian_ward_links.invite_id
                      AND guardian_invites.home_id = guardian_ward_links.home_id
               )
               OR NOT EXISTS (
                    SELECT 1 FROM guardian_accounts
                    WHERE guardian_accounts.guardian_id = guardian_ward_links.guardian_id
                      AND LOWER(TRIM(guardian_accounts.provider)) = 'google'
                      AND TRIM(COALESCE(guardian_accounts.email, '')) <> ''
                      AND TRIM(COALESCE(guardian_accounts.display_name, '')) <> ''
               )
            """
        )
        conn.execute(
            """
            DELETE FROM guardian_invites
            WHERE home_id IS NULL OR TRIM(home_id) = ''
               OR NOT EXISTS (
                    SELECT 1 FROM homes
                    JOIN users ON users.home_id = homes.home_id
                    WHERE homes.home_id = guardian_invites.home_id
                      AND users.role = 'user'
                      AND TRIM(COALESCE(users.email, '')) <> ''
                      AND TRIM(COALESCE(users.nickname, '')) <> ''
               )
            """
        )


    @staticmethod
    def _backfill_guardian_invites(conn: sqlite3.Connection) -> None:
        rows = conn.execute("SELECT * FROM guardian_invites").fetchall()
        existing_codes = {str(row["short_code"]) for row in rows if row["short_code"]}
        for row in rows:
            data = sqlite_row_to_dict(row) or {}
            short_code = str(data.get("short_code") or "").strip().upper()
            if not short_code:
                short_code = generate_short_code(existing_codes)
                existing_codes.add(short_code)
            status = str(data.get("status") or "pending").lower()
            if status == "sent":
                status = "pending"
            created_at = str(data.get("created_at") or utc_now())
            display_name = data.get("display_name") or default_display_name(data.get("email"), data.get("relation"))
            home_id = str(data.get("home_id") or HOME["home_id"])
            ward_account_name = clean_optional_name(data.get("ward_account_name")) or SQLiteRepository._fallback_ward_account_name(conn, home_id)
            expires_at = data.get("expires_at") or invite_expires_at(created_at)
            deep_link = data.get("deep_link") or build_deep_link(short_code)
            conn.execute(
                """
                UPDATE guardian_invites
                SET display_name = ?,
                    ward_account_name = ?,
                    short_code = ?,
                    deep_link = ?,
                    status = ?,
                    expires_at = ?
                WHERE invite_id = ?
                """,
                (display_name, ward_account_name, short_code, deep_link, status, expires_at, data["invite_id"]),
            )

    @staticmethod
    def _backfill_guardian_ward_links(conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            """
            SELECT
                guardian_ward_links.*,
                guardian_invites.ward_account_name AS invite_ward_account_name
            FROM guardian_ward_links
            LEFT JOIN guardian_invites ON guardian_invites.invite_id = guardian_ward_links.invite_id
            """
        ).fetchall()
        for row in rows:
            data = sqlite_row_to_dict(row) or {}
            raw_display_name = clean_optional_name(data.get("ward_display_name"))
            ward_account_name = (
                clean_optional_name(data.get("ward_account_name"))
                or clean_optional_name(data.get("invite_ward_account_name"))
                or SQLiteRepository._fallback_ward_account_name(conn, str(data.get("home_id") or HOME["home_id"]))
            )
            ward_alias = clean_optional_name(data.get("ward_alias"))
            if ward_alias is None and raw_display_name and raw_display_name != ward_account_name:
                ward_alias = None if is_generic_ward_display_name(raw_display_name) else raw_display_name
            ward_display_name = ward_alias or ward_account_name
            conn.execute(
                """
                UPDATE guardian_ward_links
                SET ward_account_name = ?,
                    ward_alias = ?,
                    ward_display_name = ?
                WHERE link_id = ?
                """,
                (ward_account_name, ward_alias, ward_display_name, data["link_id"]),
            )

    @staticmethod
    def _fallback_ward_account_name(conn: sqlite3.Connection, home_id: str = HOME["home_id"]) -> str:
        row = conn.execute(
            "SELECT nickname, email FROM users WHERE home_id = ? ORDER BY rowid DESC LIMIT 1",
            (home_id,),
        ).fetchone()
        return (
            clean_optional_name(row["nickname"] if row else None)
            or clean_optional_name(row["email"] if row else None)
            or ""
        )

    @staticmethod
    def _normalize_legacy_public_device_data(conn: sqlite3.Connection) -> None:
        """Normalize legacy names in persisted rows without exposing scanner internals.

        Old versions stored temporary names directly in both the device table and
        frozen scan snapshots.  The snapshots still retain private discovery facts
        for later re-identification, but their public identity fields, historical
        notifications, events and aliases are rewritten or removed here.
        """
        device_rows = conn.execute("SELECT * FROM devices").fetchall()
        for row in device_rows:
            device = SQLiteRepository._device_from_row(row)
            fields = normalized_storage_fields(device)
            is_phantom = bool(
                device.get("is_phantom", False)
            ) or _is_unverified_presence_only_observation(device)
            conn.execute(
                """
                UPDATE devices
                SET name = ?, manufacturer = ?, model = ?, device_type = ?,
                    is_unresolved = ?, is_phantom = ?
                WHERE device_id = ?
                """,
                (
                    fields["name"],
                    fields["manufacturer"],
                    fields["model"],
                    fields["device_type"],
                    int(bool(fields.get("is_unresolved", False))),
                    int(is_phantom),
                    device["device_id"],
                ),
            )

        scan_rows = conn.execute(
            "SELECT scan_id, home_id, status, current_step, scan_source, "
            "network_context_json FROM scans"
        ).fetchall()
        for scan_row in scan_rows:
            scan_id = scan_row["scan_id"]
            home_id = scan_row["home_id"]
            snapshot_rows = conn.execute(
                "SELECT id, device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()
            normalized_snapshots: list[dict[str, Any]] = []
            for snapshot_row in snapshot_rows:
                try:
                    snapshot = json.loads(snapshot_row["device_snapshot_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(snapshot, dict):
                    continue
                snapshot.setdefault("home_id", home_id)
                snapshot.update(normalized_storage_fields(snapshot))
                if _is_unverified_presence_only_observation(snapshot):
                    snapshot["is_phantom"] = True
                conn.execute(
                    "UPDATE scan_devices SET device_snapshot_json = ? WHERE id = ?",
                    (json.dumps(snapshot, ensure_ascii=False), snapshot_row["id"]),
                )
                normalized_snapshots.append(snapshot)

            try:
                raw_scan_context = json.loads(scan_row["network_context_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_scan_context = {}
            public_snapshots = normalized_snapshots
            public_scan_context = raw_scan_context
            if (
                scan_row["scan_source"] == _AUTHORITATIVE_SCAN_SOURCE
                and not actual_android_scan_rejection_reasons(
                    raw_scan_context,
                    normalized_snapshots,
                )
            ):
                # Pre-v1 databases may contain private hosts outside the LAN
                # declared by the phone. Keep the raw legacy evidence private
                # and intact; apply the boundary only to derived public state.
                bounded = enforce_declared_subnet_boundary(
                    raw_scan_context,
                    normalized_snapshots,
                )
                public_snapshots = bounded.devices
                public_scan_context = bounded.network_context

            household_snapshots = [
                snapshot for snapshot in public_snapshots if not is_self_observation(snapshot)
            ]
            partial_scan = scan_is_partial(normalize_stored_network_context(public_scan_context))
            public_devices, summary = summarize_public_security(
                household_snapshots,
                coverage_complete=not partial_scan,
            )
            raw_identity_findings = build_public_identity_findings(
                household_snapshots,
                public_devices,
            )
            identity_findings = visible_identity_findings(raw_identity_findings)
            incomplete_scan = partial_scan
            if partial_scan:
                summary = project_partial_security(summary)
            elif identity_findings:
                summary = _hold_identity_incomplete_security(summary, identity_findings)
            real_devices = public_devices
            conn.execute(
                """
                UPDATE scans
                SET status = ?, current_step = ?, devices_found = ?,
                    high_risk_devices = ?, security_score_json = ?
                WHERE scan_id = ?
                """,
                (
                    "partial" if incomplete_scan else "completed",
                    (
                        PARTIAL_SCAN_STEP
                        if partial_scan
                        else IDENTITY_PENDING_STEP
                        if identity_findings
                        else "점검 완료"
                    ),
                    len(real_devices) + len(identity_findings),
                    confirmed_public_red_count(real_devices, identity_findings),
                    json.dumps(
                        {
                            "home_id": home_id,
                            "score": summary["score"],
                            "risk_level": summary["risk_level"],
                            "summary": summary["summary"],
                            "device_scores": summary["device_scores"],
                            "score_status": public_score_status(summary, coverage_complete=not partial_scan),
                            "identity_incomplete": bool(identity_findings),
                            "identity_pending_count": len(identity_findings),
                            "scan_complete": not incomplete_scan,
                            "coverage_complete": not partial_scan,
                        },
                        ensure_ascii=False,
                    ),
                    scan_id,
                ),
            )
            completion_copy = sanitize_public_notification(
                {
                    "title": "보안 점검 일부 완료" if partial_scan else "보안 점검 완료",
                    "message": (
                        PARTIAL_SCAN_NOTIFICATION
                        if partial_scan
                        else scan_completed_message(real_devices, identity_findings, summary)
                    ),
                }
            )
            conn.execute(
                """
                UPDATE notifications
                SET title = ?, message = ?
                WHERE home_id = ? AND scan_id = ? AND type = 'scan_completed'
                """,
                (
                    completion_copy["title"],
                    completion_copy["message"],
                    home_id,
                    scan_id,
                ),
            )

        for row in conn.execute("SELECT event_id, title, description, action_guide FROM security_events").fetchall():
            safe = sanitize_public_notification(
                {
                    "title": row["title"],
                    "message": row["description"],
                    "action_guide": row["action_guide"],
                }
            )
            conn.execute(
                "UPDATE security_events SET title = ?, description = ?, action_guide = ? WHERE event_id = ?",
                (
                    safe.get("title") or "보안 안내",
                    safe.get("message") or "보안 상태를 다시 확인해 주세요.",
                    safe.get("action_guide") or "다음 검사 후 확인된 기기만 알려드릴게요.",
                    row["event_id"],
                ),
            )

        for row in conn.execute("SELECT notification_id, title, message FROM notifications").fetchall():
            safe = sanitize_public_notification({"title": row["title"], "message": row["message"]})
            conn.execute(
                "UPDATE notifications SET title = ?, message = ? WHERE notification_id = ?",
                (
                    safe.get("title") or "보안 안내",
                    safe.get("message") or "보안 상태를 다시 확인해 주세요.",
                    row["notification_id"],
                ),
            )

        # Historical notification rows are evidence, not disposable cache.  The
        # public projection suppresses duplicate scan cards without deleting the
        # underlying audit trail.

        aliases = conn.execute("SELECT home_id, device_id, alias FROM device_aliases").fetchall()
        for alias in aliases:
            if not is_safe_device_alias(alias["alias"]):
                conn.execute(
                    "DELETE FROM device_aliases WHERE home_id = ? AND device_id = ?",
                    (alias["home_id"], alias["device_id"]),
                )

    @staticmethod
    def _supersede_stale_identity_jobs_from_latest_scans(
        conn: sqlite3.Connection,
    ) -> None:
        """Close stale enrichment work using each home's latest real phone scan.

        Older releases could leave review jobs active after the corresponding
        device disappeared or became evidence-resolved.  Reopening the database
        must reconcile those jobs without deleting their evidence/history.
        """

        home_rows = conn.execute(
            "SELECT DISTINCT home_id FROM scans WHERE scan_source = ?",
            (_AUTHORITATIVE_SCAN_SOURCE,),
        ).fetchall()
        updated_at = utc_now()
        for home_row in home_rows:
            home_id = str(home_row["home_id"] or "")
            candidates = conn.execute(
                """
                SELECT scan_id, network_context_json, network_scope_id, created_at
                FROM scans
                WHERE home_id = ? AND scan_source = ?
                ORDER BY created_at DESC, rowid DESC
                """,
                (home_id, _AUTHORITATIVE_SCAN_SOURCE),
            ).fetchall()
            latest: sqlite3.Row | None = None
            snapshots: list[dict[str, Any]] = []
            public_snapshots: list[dict[str, Any]] = []
            for candidate in candidates:
                candidate_snapshots: list[dict[str, Any]] = []
                for row in conn.execute(
                    "SELECT device_snapshot_json FROM scan_devices "
                    "WHERE scan_id = ? ORDER BY id ASC",
                    (candidate["scan_id"],),
                ).fetchall():
                    try:
                        snapshot = json.loads(row["device_snapshot_json"] or "{}")
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    if isinstance(snapshot, dict):
                        snapshot.setdefault("home_id", home_id)
                        candidate_snapshots.append(snapshot)
                try:
                    network_context = json.loads(candidate["network_context_json"] or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    network_context = {}
                validated = _validated_authoritative_snapshot(
                    network_context,
                    candidate_snapshots,
                )
                if validated is None:
                    continue
                latest = candidate
                snapshots = candidate_snapshots
                _bounded_context, public_snapshots = validated
                break
            if latest is None:
                continue
            household_snapshots = [
                snapshot for snapshot in public_snapshots if not is_self_observation(snapshot)
            ]
            public_devices, _summary = summarize_public_security(household_snapshots)
            finding_ids = {
                str(finding.get("device_id") or "")
                for finding in build_public_identity_findings(
                    household_snapshots,
                    public_devices,
                )
            }
            strong_scope = (
                str(latest["network_scope_id"])
                if is_strong_network_scope_id(latest["network_scope_id"])
                else None
            )
            prepared_jobs = _prepare_identity_enrichment_jobs(
                [
                    snapshot
                    for snapshot in snapshots
                    if public_device_id(snapshot.get("device_id"), home_id) in finding_ids
                ],
                home_id=home_id,
                network_scope_id=strong_scope,
                ambiguity_devices=snapshots,
            )
            active_job_keys = {
                str(prepared["job_key"]) for prepared in prepared_jobs
            }
            # Startup reconciliation may be the first code that sees a newer
            # canonical key format.  Upsert its replacement before superseding
            # the legacy row.  Unlike a real new scan this is replaying one
            # persisted observation, so seen_count must remain unchanged.
            for prepared in prepared_jobs:
                device = prepared["device"]
                evidence = prepared["evidence"]
                evidence_json = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
                observed_at = str(
                    device.get("last_seen") or latest["created_at"] or updated_at
                )
                conn.execute(
                    """
                    INSERT INTO identity_enrichment_jobs (
                        job_id, job_key, home_id, device_id, network_scope_id,
                        physical_mac, evidence_binding_signature, status,
                        blocked_reason, evidence_json, evidence_signature,
                        seen_count, first_seen_at, last_seen_at, updated_at,
                        resolution_json, source_reference, resolution_provenance,
                        resolution_signature, research_attempt_count,
                        research_last_attempt_at, research_next_attempt_at,
                        resolved_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL)
                    ON CONFLICT(job_key) DO UPDATE SET
                        device_id = excluded.device_id,
                        network_scope_id = excluded.network_scope_id,
                        physical_mac = excluded.physical_mac,
                        evidence_binding_signature = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_binding_signature
                            ELSE excluded.evidence_binding_signature
                        END,
                        status = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.status
                            ELSE excluded.status
                        END,
                        blocked_reason = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.blocked_reason
                            ELSE excluded.blocked_reason
                        END,
                        evidence_json = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_json
                            ELSE excluded.evidence_json
                        END,
                        evidence_signature = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.evidence_signature
                            ELSE excluded.evidence_signature
                        END,
                        research_attempt_count = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_attempt_count
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN 0
                            ELSE identity_enrichment_jobs.research_attempt_count
                        END,
                        research_last_attempt_at = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_last_attempt_at
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN NULL
                            ELSE identity_enrichment_jobs.research_last_attempt_at
                        END,
                        research_next_attempt_at = CASE
                            WHEN identity_enrichment_jobs.status IN ('resolved', 'rejected')
                                THEN identity_enrichment_jobs.research_next_attempt_at
                            WHEN identity_enrichment_jobs.evidence_signature <> excluded.evidence_signature
                                THEN NULL
                            ELSE identity_enrichment_jobs.research_next_attempt_at
                        END,
                        last_seen_at = excluded.last_seen_at,
                        updated_at = excluded.updated_at
                    """,
                    (
                        f"identity-job-{uuid4()}",
                        prepared["job_key"],
                        home_id,
                        str(device.get("device_id") or ""),
                        strong_scope,
                        prepared["physical_mac"],
                        prepared["evidence_binding_signature"],
                        prepared["status"],
                        prepared["blocked_reason"],
                        evidence_json,
                        build_evidence_signature(evidence),
                        observed_at,
                        observed_at,
                        observed_at,
                    ),
                )
            if active_job_keys:
                placeholders = ",".join("?" for _ in active_job_keys)
                conn.execute(
                    f"""
                    UPDATE identity_enrichment_jobs
                    SET status = 'superseded', blocked_reason = 'NOT_IN_LATEST_SCAN',
                        research_next_attempt_at = NULL, updated_at = ?
                    WHERE home_id = ? AND status IN ('review_required', 'blocked')
                      AND job_key NOT IN ({placeholders})
                    """,
                    (updated_at, home_id, *sorted(active_job_keys)),
                )
            else:
                conn.execute(
                    """
                    UPDATE identity_enrichment_jobs
                    SET status = 'superseded', blocked_reason = 'NOT_IN_LATEST_SCAN',
                        research_next_attempt_at = NULL, updated_at = ?
                    WHERE home_id = ? AND status IN ('review_required', 'blocked')
                    """,
                    (updated_at, home_id),
                )

    @staticmethod
    def _backfill_network_scope_ids(conn: sqlite3.Connection) -> None:
        """Backfill opaque scan scope ids and discard any legacy raw Wi-Fi ids."""

        scan_rows = conn.execute(
            "SELECT scan_id, home_id, scan_source, network_context_json, network_scope_id FROM scans"
        ).fetchall()
        for scan_row in scan_rows:
            try:
                raw_context = json.loads(scan_row["network_context_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_context = {}
            if not isinstance(raw_context, dict):
                raw_context = {}
            snapshot_rows = conn.execute(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan_row["scan_id"],),
            ).fetchall()
            snapshots: list[dict[str, Any]] = []
            for snapshot_row in snapshot_rows:
                try:
                    snapshot = json.loads(snapshot_row["device_snapshot_json"])
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                if isinstance(snapshot, dict):
                    snapshots.append(snapshot)
            scope_id = scan_row["network_scope_id"]
            if not scope_id and scan_row["scan_source"] in {_AUTHORITATIVE_SCAN_SOURCE, "windows-port-probe"}:
                scope_id = derive_network_scope_id(
                    home_id=str(scan_row["home_id"]),
                    network_context=raw_context,
                    discovered_devices=snapshots,
                )
            # normalize_stored_network_context intentionally omits SSID/BSSID.
            safe_context = normalize_stored_network_context(raw_context)
            conn.execute(
                "UPDATE scans SET network_context_json = ?, network_scope_id = ? WHERE scan_id = ?",
                (
                    json.dumps(safe_context, ensure_ascii=False),
                    scope_id,
                    scan_row["scan_id"],
                ),
            )

    @staticmethod
    def _migrate_identity_enrichment_status_constraint(conn: sqlite3.Connection) -> None:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'identity_enrichment_jobs'"
        ).fetchone()
        create_sql = str(row["sql"] or "") if row is not None else ""
        if (
            "'superseded'" in create_sql
            and "evidence_binding_signature IS NOT NULL" in create_sql
            and "'automated-official-http'" in create_sql
        ):
            return

        columns = (
            "job_id, job_key, home_id, device_id, network_scope_id, physical_mac, "
            "evidence_binding_signature, status, "
            "blocked_reason, evidence_json, evidence_signature, seen_count, first_seen_at, "
            "last_seen_at, updated_at, resolution_json, source_reference, resolution_provenance, "
            "resolution_signature, research_attempt_count, research_last_attempt_at, "
            "research_next_attempt_at, research_policy_version, catalog_reconcile_version, resolved_at"
        )
        original_count = int(
            conn.execute("SELECT COUNT(*) FROM identity_enrichment_jobs").fetchone()[0]
        )
        conn.execute("DROP TABLE IF EXISTS identity_enrichment_jobs_status_v2")
        conn.execute(
            """
            CREATE TABLE identity_enrichment_jobs_status_v2 (
                job_id TEXT PRIMARY KEY,
                job_key TEXT NOT NULL UNIQUE,
                home_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                network_scope_id TEXT,
                physical_mac TEXT,
                evidence_binding_signature TEXT,
                status TEXT NOT NULL CHECK (
                    status IN ('review_required', 'resolved', 'rejected', 'blocked', 'superseded')
                ),
                blocked_reason TEXT,
                evidence_json TEXT NOT NULL,
                evidence_signature TEXT NOT NULL,
                seen_count INTEGER NOT NULL CHECK (seen_count >= 1),
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolution_json TEXT,
                source_reference TEXT,
                    resolution_provenance TEXT CHECK (
                        resolution_provenance IS NULL OR
                        resolution_provenance IN (
                            'operator-reviewed',
                            'automated-official-web-search',
                            'automated-official-http'
                        )
                    ),
                resolution_signature TEXT,
                research_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (research_attempt_count >= 0),
                research_last_attempt_at TEXT,
                research_next_attempt_at TEXT,
                research_policy_version TEXT,
                catalog_reconcile_version TEXT,
                resolved_at TEXT,
                FOREIGN KEY (home_id) REFERENCES homes(home_id) ON DELETE CASCADE,
                CHECK (
                    status <> 'resolved' OR (
                        network_scope_id IS NOT NULL AND
                        (physical_mac IS NOT NULL OR evidence_binding_signature IS NOT NULL) AND
                        resolution_json IS NOT NULL AND source_reference IS NOT NULL AND
                        resolved_at IS NOT NULL
                    )
                )
            )
            """
        )
        conn.execute(
            f"INSERT INTO identity_enrichment_jobs_status_v2 ({columns}) "
            f"SELECT {columns} FROM identity_enrichment_jobs"
        )
        migrated_count = int(
            conn.execute("SELECT COUNT(*) FROM identity_enrichment_jobs_status_v2").fetchone()[0]
        )
        if migrated_count != original_count:
            raise RuntimeError("identity enrichment status migration row-count mismatch")
        conn.execute("DROP TABLE identity_enrichment_jobs")
        conn.execute(
            "ALTER TABLE identity_enrichment_jobs_status_v2 RENAME TO identity_enrichment_jobs"
        )

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _verified_identity_for_mac(
        self,
        conn: sqlite3.Connection,
        mac_address: str | None,
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, str] | None:
        """Find a prior catalog product bound to one strong scope and MAC."""
        mac = normalized_physical_mac(mac_address)
        if mac is None or not is_strong_network_scope_id(network_scope_id):
            return None

        # Bind history to the MAC captured at observation time.  Joining an old
        # history row to the mutable devices row by IP-derived device_id is
        # unsafe: DHCP can give that IP/device_id to a different MAC later.
        history_rows = conn.execute(
            """
            SELECT h.*
            FROM device_identity_history AS h
            WHERE h.home_id = ?
              AND h.network_scope_id = ?
              AND upper(h.physical_mac) = ?
              AND h.identity_status IN ('resolved', 'manual_resolved')
              AND h.confidence >= 0.9
            ORDER BY h.confidence DESC, h.observed_at DESC
            """,
            (home_id, network_scope_id, mac),
        ).fetchall()
        for row in history_rows:
            if row["identity_status"] == "manual_resolved":
                history = sqlite_row_to_dict(row) or {}
                try:
                    history["identity_evidence"] = json.loads(history.get("evidence_json") or "[]")
                except (TypeError, ValueError, json.JSONDecodeError):
                    history["identity_evidence"] = []
                job_rows = conn.execute(
                    "SELECT * FROM identity_enrichment_jobs "
                    "WHERE home_id = ? AND network_scope_id = ? "
                    "AND upper(physical_mac) = ? AND status = 'resolved' "
                    "ORDER BY resolved_at DESC",
                    (home_id, network_scope_id, mac),
                ).fetchall()
                for job_row in job_rows:
                    job = self._identity_enrichment_job_from_row(job_row)
                    if (
                        job is not None
                        and evidence_signature_matches(
                            job.get("evidence") or {}, job.get("evidence_signature")
                        )
                        and (trusted := trusted_identity_resolution(history, job)) is not None
                    ):
                        return trusted
                continue
            record = {
                **(sqlite_row_to_dict(row) or {}),
                "mac_address": mac,
                "identity_confidence": row["confidence"],
                "is_unresolved": 0,
                "is_phantom": 0,
                "scan_source": "android-native",
            }
            identity = verified_catalog_marker_identity(record)
            if identity:
                return identity

        # v0.x databases have no scoped history columns.  Recover only from a
        # private snapshot that itself has the exact strong scope and real MAC;
        # a mutable durable device row is not sufficient evidence.
        legacy_rows = conn.execute(
            """
            SELECT sd.device_snapshot_json
            FROM scans AS s
            JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
            WHERE s.home_id = ? AND s.network_scope_id = ?
              AND s.scan_source = 'android-native'
            ORDER BY s.created_at DESC, sd.id ASC
            LIMIT 200
            """,
            (home_id, network_scope_id),
        ).fetchall()
        for row in legacy_rows:
            try:
                snapshot = json.loads(row["device_snapshot_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict) or normalized_physical_mac(snapshot.get("mac_address")) != mac:
                continue
            if snapshot.get("identity_status") == "manual_resolved":
                continue
            identity = verified_catalog_marker_identity(snapshot)
            if identity:
                return identity
        return None

    def _verified_appliance_family_identity_for_mac(
        self,
        conn: sqlite3.Connection,
        mac_address: str | None,
        current_snapshot: Mapping[str, Any],
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, Any] | None:
        """Recover a same-MAC Family Hub family identity when the appliance sleeps.

        Family Hub's Spotify ZeroConf endpoint is intermittent.  A previous
        authoritative scan can nevertheless contain the appliance's own
        structured ``getInfo`` response.  Reuse is limited to that exact
        physical MAC and strong network scope.  Legacy rows without a stored
        scope additionally require the current observation's exact matching
        MAC-shaped Spotify mDNS token.  A raw service, OUI or IP alone never
        enters this path.  The returned model is the product family label, not
        a fabricated retail part number.
        """
        mac = normalized_physical_mac(mac_address)
        if mac is None or not is_strong_network_scope_id(network_scope_id):
            return None

        rows = conn.execute(
            """
            SELECT s.network_scope_id, s.created_at, sd.device_snapshot_json
            FROM scans AS s
            JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
            WHERE s.home_id = ?
              AND s.scan_source = 'android-native'
              AND CASE
                    WHEN json_valid(sd.device_snapshot_json)
                    THEN upper(replace(trim(json_extract(
                        sd.device_snapshot_json, '$.mac_address'
                    )), '-', ':'))
                    ELSE ''
                  END = ?
            ORDER BY s.created_at DESC, sd.id ASC
            LIMIT 400
            """,
            (home_id, mac),
        ).fetchall()
        for row in rows:
            identity = verified_family_hub_snapshot_identity(
                row["device_snapshot_json"],
                historical_scope_id=row["network_scope_id"],
                current_scope_id=network_scope_id,
                current_physical_mac=mac,
                current_snapshot_payload=current_snapshot,
            )
            if identity is not None:
                return identity
        return None

    def _verified_appliance_family_identity_for_advertised_token(
        self,
        conn: sqlite3.Connection,
        current_snapshot: Mapping[str, Any],
        home_id: str,
        network_scope_id: str | None,
    ) -> dict[str, Any] | None:
        """Recover Family Hub family identity without inventing a MAC binding.

        Android can lose neighbour-table access while the appliance still
        advertises its exact MAC-shaped Spotify mDNS instance.  The shared
        verifier accepts that token only when a prior authoritative snapshot
        bound the same self-advertised token to the same real physical MAC and
        captured a completed structured Family Hub ``getInfo`` response.
        Neither the token nor the current IP/device id is persisted as a MAC.
        """

        if not is_strong_network_scope_id(network_scope_id):
            return None
        advertised_token = exact_spotify_mdns_mac_token(current_snapshot)
        if advertised_token is None:
            return None
        rows = conn.execute(
            """
            SELECT s.network_scope_id, sd.device_snapshot_json
            FROM scans AS s
            JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
            WHERE s.home_id = ?
              AND s.scan_source = 'android-native'
              AND EXISTS (
                    SELECT 1
                    FROM json_each(
                        CASE
                          WHEN json_valid(sd.device_snapshot_json)
                          THEN sd.device_snapshot_json
                          ELSE '{}'
                        END,
                        '$.fingerprints'
                    ) AS fingerprint
                    WHERE fingerprint.type = 'text'
                      AND instr(CAST(fingerprint.value AS TEXT), ':') > 0
                      AND lower(trim(substr(
                            CAST(fingerprint.value AS TEXT),
                            1,
                            instr(CAST(fingerprint.value AS TEXT), ':') - 1
                          ))) = 'mdns-name'
                      AND upper(trim(substr(
                            CAST(fingerprint.value AS TEXT),
                            instr(CAST(fingerprint.value AS TEXT), ':') + 1
                          ))) = ?
                  )
            ORDER BY s.created_at DESC, sd.id ASC
            LIMIT 400
            """,
            (home_id, advertised_token),
        ).fetchall()
        for row in rows:
            identity = verified_family_hub_advertised_token_identity(
                row["device_snapshot_json"],
                current_snapshot,
                historical_scope_id=str(row["network_scope_id"] or ""),
                current_scope_id=network_scope_id,
                # ``binding_mac`` is absent on this path.  Let the shared
                # verifier inspect the current snapshot so that only the
                # scanner's explicit UNKNOWN-* placeholder is treated as
                # "physical MAC absent"; arbitrary malformed claims remain
                # conflicts.
                current_physical_mac=None,
            )
            if identity is not None:
                return identity
        return None

    def _authenticated_self_history_job_devices(
        self,
        current_devices: list[dict[str, Any]],
        *,
        home_id: str,
        current_scope_candidates: Sequence[str],
    ) -> list[dict[str, Any]]:
        """Mint private self jobs from repeated same-BSSID history only.

        Historical snapshots are loaded and decoded once per authoritative
        request.  The repository never rewrites a current neighbour as self;
        it creates only an in-process sentinel copy for the scoped resolver.
        """

        bssid_scopes = tuple(
            dict.fromkeys(
                str(scope or "").strip().casefold()
                for scope in current_scope_candidates
                if str(scope or "").strip().casefold().startswith("hgns1b-")
                and is_strong_network_scope_id(scope)
            )
        )
        if not current_devices or not bssid_scopes:
            return []

        placeholders = ",".join("?" for _ in bssid_scopes)
        rows = self._fetch_all(
            f"""
            SELECT s.scan_id, s.home_id, s.network_scope_id, s.scan_source,
                   sd.device_snapshot_json
            FROM scans AS s
            JOIN scan_devices AS sd ON sd.scan_id = s.scan_id
            WHERE s.home_id = ? AND s.scan_source = 'android-native'
              AND s.network_scope_id IN ({placeholders})
            ORDER BY s.created_at DESC, sd.id ASC
            LIMIT 800
            """,
            (home_id, *bssid_scopes),
        )
        records_by_ip: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            try:
                snapshot = json.loads(row["device_snapshot_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict) or not is_self_observation(snapshot):
                continue
            ip_address = str(snapshot.get("ip_address") or "").strip()
            if not ip_address:
                continue
            records_by_ip.setdefault(ip_address, []).append(
                {
                    "scan_id": str(row["scan_id"] or ""),
                    "home_id": str(row["home_id"] or ""),
                    "network_scope_id": str(row["network_scope_id"] or ""),
                    "scan_source": str(row["scan_source"] or ""),
                    "snapshot_payload": snapshot,
                }
            )
        if not records_by_ip:
            return []

        ambiguous_macs = _ambiguous_physical_macs(current_devices)
        claimed_macs: set[str] = set()
        job_devices: list[dict[str, Any]] = []
        for current in current_devices:
            if is_self_observation(current) or bool(current.get("is_phantom")):
                continue
            physical_mac = normalized_physical_mac(current.get("mac_address"))
            if (
                physical_mac is None
                or physical_mac in ambiguous_macs
                or physical_mac in claimed_macs
            ):
                continue
            ip_address = str(current.get("ip_address") or "").strip()
            identity = verified_authenticated_self_android_history_identity(
                records_by_ip.get(ip_address),
                current,
                home_id=home_id,
                current_scope_candidates=bssid_scopes,
                current_physical_mac=physical_mac,
            )
            if identity is None:
                continue
            manufacturer = str(identity.get("manufacturer") or "").strip()
            model = str(identity.get("model") or "").strip()
            device_type = str(identity.get("device_type") or "").strip().casefold()
            claim = {
                "device_id": current.get("device_id"),
                "name": "",
                "device_type": device_type,
                "manufacturer": manufacturer,
                "model": model,
                "ip_address": ip_address,
                "mac_address": physical_mac,
                "online": bool(current.get("online", True)),
                "open_ports": [],
                "services": ["self-device"],
                "discovery_sources": ["self"],
                "fingerprints": [
                    "self-android",
                    f"self-manufacturer:{manufacturer}",
                    f"self-model:{model}",
                ],
                "risk_signals": ["self_device"],
                "vulnerabilities": [],
                "confidence": 1.0,
                "scan_source": _AUTHORITATIVE_SCAN_SOURCE,
            }
            marked = bind_authenticated_self_android_claim(claim)
            if marked is None:
                continue
            claimed_macs.add(physical_mac)
            job_devices.append(marked)
        return job_devices

    def _store_discovered_devices(
        self,
        discovered_devices: list[dict[str, Any]],
        scan_source: str,
        home_id: str = HOME["home_id"],
        network_scope_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        # A client can serialize marker-looking strings but cannot serialize
        # the in-process object sentinel injected by the current-request L2
        # verifier.  Extract at most one primitive binding, then strip every
        # reserved value before normalization or persistence.
        raw_self_bindings = [
            binding
            for raw_device in discovered_devices
            if (binding := authenticated_self_android_binding(raw_device)) is not None
        ]
        self_binding = (
            raw_self_bindings[0]
            if len(raw_self_bindings) == 1
            and is_strong_network_scope_id(network_scope_id)
            else None
        )
        cleaned_devices = [
            strip_untrusted_authenticated_self_android(raw_device)
            for raw_device in discovered_devices
        ]
        stored_devices: list[dict[str, Any]] = []
        attested_self_job_devices: list[dict[str, Any]] = []
        phantom_mask = phantom_port_echo_mask(cleaned_devices)
        catalog_entries = self.verified_product_catalog_entries()
        ambiguous_macs = _ambiguous_physical_macs(cleaned_devices)
        if self_binding is not None and self_binding[1] in ambiguous_macs:
            self_binding = None
        with self._connect() as conn:
            for index, raw_device in enumerate(cleaned_devices):
                observed_mac = normalized_physical_mac(raw_device.get("mac_address"))
                binding_mac = None if observed_mac in ambiguous_macs else observed_mac
                historical_identity = self._verified_identity_for_mac(
                    conn,
                    binding_mac,
                    home_id,
                    network_scope_id,
                )
                if historical_identity is None:
                    historical_identity = self._verified_appliance_family_identity_for_mac(
                        conn,
                        binding_mac,
                        raw_device,
                        home_id,
                        network_scope_id,
                    )
                if (
                    historical_identity is None
                    and scan_source == _AUTHORITATIVE_SCAN_SOURCE
                    and observed_mac is None
                ):
                    historical_identity = (
                        self._verified_appliance_family_identity_for_advertised_token(
                            conn,
                            raw_device,
                            home_id,
                            network_scope_id,
                        )
                    )
                if historical_identity is not None:
                    if historical_identity.get("_history_kind") == "appliance_family":
                        historical_identity = bind_verified_appliance_family_history(
                            historical_identity
                        )
                    else:
                        historical_identity = bind_verified_catalog_history(
                            historical_identity
                        )
                device = normalize_observed_device(
                    raw_device,
                    scan_source=scan_source,
                    home_id=home_id,
                    verified_identity=historical_identity,
                    phantom_port_echo=phantom_mask[index],
                    catalog_entries=catalog_entries,
                )
                # Persist CVE matches with the private observation.  The public
                # presentation layer removes matching internals and exposes only
                # safe CVE identifiers/severity after the product is confirmed.
                device = _scoring_with_cve(device)
                scored = score_device(device)
                device.update(
                    {
                        "security_score": scored["score"],
                        "risk_level": scored["risk_level"],
                        "risk_summary": scored["summary"],
                        "recommended_actions": scored["recommended_actions"],
                    }
                )
                if scan_source == _AUTHORITATIVE_SCAN_SOURCE and not bool(
                    device.get("is_phantom")
                ):
                    # Only a real Android LAN observation may update durable
                    # current state. Non-authoritative internal scans keep their
                    # frozen API-compatible snapshot below, but can never
                    # replace the authoritative device row or identity history.
                    # Phantom/refusal-only telemetry is likewise retained only
                    # in the immutable scan snapshot; it must not become durable
                    # household-device or identity-history state.
                    conn.execute(
                        """
                        INSERT INTO devices (
                            device_id, home_id, name, device_type, manufacturer, model,
                            ip_address, mac_address, online, last_seen, open_ports_json,
                            services_json, default_credentials, encryption, firmware, vulnerabilities_json,
                            discovery_sources_json, fingerprints_json, risk_signals_json, scan_source, confidence,
                            is_unresolved, is_phantom, security_score, risk_level, risk_summary,
                            recommended_actions_json, risk_rank
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO UPDATE SET
                            name = excluded.name,
                            device_type = excluded.device_type,
                            manufacturer = excluded.manufacturer,
                            model = excluded.model,
                            ip_address = excluded.ip_address,
                            mac_address = excluded.mac_address,
                            online = excluded.online,
                            last_seen = excluded.last_seen,
                            open_ports_json = excluded.open_ports_json,
                            services_json = excluded.services_json,
                            default_credentials = excluded.default_credentials,
                            encryption = excluded.encryption,
                            firmware = excluded.firmware,
                            vulnerabilities_json = excluded.vulnerabilities_json,
                            discovery_sources_json = excluded.discovery_sources_json,
                            fingerprints_json = excluded.fingerprints_json,
                            risk_signals_json = excluded.risk_signals_json,
                            scan_source = excluded.scan_source,
                            confidence = excluded.confidence,
                            is_unresolved = excluded.is_unresolved,
                            is_phantom = excluded.is_phantom,
                            security_score = excluded.security_score,
                            risk_level = excluded.risk_level,
                            risk_summary = excluded.risk_summary,
                            recommended_actions_json = excluded.recommended_actions_json,
                            risk_rank = excluded.risk_rank
                        """,
                        device_row_values(device),
                    )
                    conn.execute(
                        """
                        INSERT INTO device_identity_history (
                            resolution_id, home_id, device_id, network_scope_id,
                            physical_mac, observed_at,
                            identity_status, manufacturer, device_type, model,
                            canonical_name, confidence, evidence_json,
                            candidates_json, note, resolver_version
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"identity-{uuid4()}",
                            home_id,
                            device["device_id"],
                            network_scope_id if is_strong_network_scope_id(network_scope_id) else None,
                            None
                            if normalized_physical_mac(device.get("mac_address")) in ambiguous_macs
                            else normalized_physical_mac(device.get("mac_address")),
                            device.get("last_seen") or utc_now(),
                            device.get("identity_status") or ("resolved" if device.get("is_resolved") else "unresolved"),
                            str(device.get("manufacturer") or ""),
                            str(device.get("device_type") or ""),
                            str(device.get("model") or ""),
                            str(device.get("canonical_name") or ""),
                            float(device.get("identity_confidence", device.get("confidence", 0.2)) or 0.2),
                            json.dumps(device.get("identity_evidence") or [], ensure_ascii=False),
                            json.dumps(device.get("identity_candidates") or [], ensure_ascii=False),
                            str(device.get("identity_note") or ""),
                            str(device.get("identity_resolver_version") or "server-identity-1.0.0"),
                        ),
                    )
                stored_devices.append(deepcopy(device))
        if self_binding is not None:
            matching_self = [
                device
                for device in stored_devices
                if is_self_observation(device)
                and (
                    str(device.get("ip_address") or "").strip(),
                    normalized_physical_mac(device.get("mac_address")),
                    str(device.get("manufacturer") or "").strip(),
                    str(device.get("model") or "").strip(),
                    str(device.get("device_type") or "").strip().casefold(),
                )
                == self_binding
            ]
            if len(matching_self) == 1:
                marked = bind_authenticated_self_android_claim(matching_self[0])
                if marked is not None:
                    attested_self_job_devices.append(marked)
        return stored_devices, attested_self_job_devices

    def _latest_observed_scan_devices(self, home_id: str = HOME["home_id"]) -> list[dict[str, Any]] | None:
        scans = self._fetch_all(
            """
            SELECT scan_id, network_context_json, network_scope_id, created_at
            FROM scans
            WHERE home_id = ? AND scan_source = 'android-native'
            ORDER BY created_at DESC
            """,
            (home_id,),
        )
        valid: list[tuple[str, str | None, dict[str, Any], list[dict[str, Any]]]] = []
        for scan in scans:
            rows = self._fetch_all(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan["scan_id"],),
            )
            devices = [json.loads(row["device_snapshot_json"]) for row in rows]
            bounded = _validated_authoritative_snapshot(
                json.loads(scan["network_context_json"] or "{}"),
                devices,
            )
            if bounded is None:
                continue
            network_context, devices = bounded
            valid.append((scan["created_at"], scan["network_scope_id"], network_context, devices))
        merged = merge_latest_observed_scans(valid)
        if merged is None:
            return None
        merged = apply_verified_product_catalog_projection(
            merged,
            self.verified_product_catalog_entries(),
        )
        return self._apply_approved_manual_identities(
            merged,
            home_id=home_id,
            network_scope_id=valid[0][1],
        )

    def _observed_scan_exists(self, home_id: str = HOME["home_id"]) -> bool:
        scans = self._fetch_all(
            """
            SELECT scan_id, network_context_json
            FROM scans
            WHERE home_id = ? AND scan_source = 'android-native'
            """,
            (home_id,),
        )
        for scan in scans:
            rows = self._fetch_all(
                "SELECT device_snapshot_json FROM scan_devices WHERE scan_id = ? ORDER BY id ASC",
                (scan["scan_id"],),
            )
            devices = [json.loads(row["device_snapshot_json"]) for row in rows]
            bounded = _validated_authoritative_snapshot(
                json.loads(scan["network_context_json"] or "{}"),
                devices,
            )
            if bounded is None:
                continue
            return True
        return False

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Open one transaction-scoped SQLite connection and always close it.

        ``sqlite3.Connection`` commits or rolls back when used in a ``with``
        block, but it does not close itself.  Every repository caller already
        uses ``with self._connect() as conn``; this wrapper preserves that
        contract while releasing the operating-system connection on every
        successful and exceptional path.
        """
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=_SQLITE_BUSY_TIMEOUT_MS / 1000,
        )
        try:
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={_SQLITE_BUSY_TIMEOUT_MS}")
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:
                yield conn
        finally:
            conn.close()

    def _fetch_one(self, query: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock, self._connect() as conn:
            return conn.execute(query, parameters).fetchone()

    def _fetch_all(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock, self._connect() as conn:
            return conn.execute(query, parameters).fetchall()

    def _create_notification(
        self,
        notification_type: str,
        title: str,
        message: str,
        home_id: str = HOME["home_id"],
        scan_id: str | None = None,
        scan_source: str | None = None,
    ) -> dict[str, Any]:
        if notification_type == "scan_completed" and (
            scan_source != _AUTHORITATIVE_SCAN_SOURCE or not str(scan_id or "").strip()
        ):
            raise ValueError("scan notification requires authoritative provenance")
        notification = sanitize_public_notification(
            {
                "notification_id": f"notif-{uuid4()}",
                "home_id": home_id,
                "type": notification_type,
                "title": title,
                "message": message,
                "read": False,
                "created_at": utc_now(),
            }
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO notifications (
                    notification_id, home_id, type, title, message,
                    scan_id, scan_source, read, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notification["notification_id"],
                    notification["home_id"],
                    notification["type"],
                    notification["title"],
                    notification["message"],
                    scan_id,
                    scan_source,
                    int(notification["read"]),
                    notification["created_at"],
                ),
            )
        return notification

    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "user_id": row["user_id"],
            "email": row["email"],
            "nickname": row["nickname"],
            "role": row["role"],
            "email_verified": bool(row["email_verified"]),
            "home_id": row["home_id"],
        }

    @staticmethod
    def _device_from_row(row: sqlite3.Row) -> dict[str, Any]:
        keys = set(row.keys())
        return {
            "device_id": row["device_id"],
            "home_id": row["home_id"] if "home_id" in keys else HOME["home_id"],
            "name": row["name"],
            "device_type": row["device_type"],
            "manufacturer": row["manufacturer"],
            "model": row["model"],
            "ip_address": row["ip_address"],
            "mac_address": row["mac_address"],
            "online": bool(row["online"]),
            "last_seen": row["last_seen"],
            "open_ports": json.loads(row["open_ports_json"]),
            "services": json.loads(row["services_json"]),
            "default_credentials": bool(row["default_credentials"]),
            "encryption": row["encryption"],
            "firmware": row["firmware"],
            "vulnerabilities": json.loads(row["vulnerabilities_json"]),
            "discovery_sources": json.loads(row["discovery_sources_json"]),
            "fingerprints": json.loads(row["fingerprints_json"]),
            "risk_signals": json.loads(row["risk_signals_json"]),
            "scan_source": row["scan_source"],
            "confidence": row["confidence"],
            "is_unresolved": bool(row["is_unresolved"]) if "is_unresolved" in keys else False,
            "is_phantom": bool(row["is_phantom"]) if "is_phantom" in keys else False,
            "security_score": row["security_score"],
            "risk_level": row["risk_level"],
            "risk_summary": row["risk_summary"],
            "recommended_actions": json.loads(row["recommended_actions_json"]),
        }

    @staticmethod
    def _notification_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "notification_id": row["notification_id"],
            "home_id": row["home_id"],
            "type": row["type"],
            "title": row["title"],
            "message": row["message"],
            "read": bool(row["read"]),
            "created_at": row["created_at"],
        }

    @staticmethod
    def _guardian_ward_from_row(row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            return {}
        keys = set(row.keys())
        ward_account_name = clean_optional_name(row["ward_account_name"] if "ward_account_name" in keys else None) or ""
        ward_alias = clean_optional_name(row["ward_alias"] if "ward_alias" in keys else None)
        ward_display_name = clean_optional_name(row["ward_display_name"]) or ward_alias or ward_account_name
        return {
            "link_id": row["link_id"],
            "guardian_id": row["guardian_id"],
            "invite_id": row["invite_id"],
            "home_id": row["home_id"],
            "ward_account_name": ward_account_name,
            "ward_alias": ward_alias,
            "ward_display_name": ward_display_name,
            "status": row["status"],
            "accepted_at": row["accepted_at"],
            "revoked_at": row["revoked_at"],
            "last_viewed_at": row["last_viewed_at"],
        }
