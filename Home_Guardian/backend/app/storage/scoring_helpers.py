"""Repository-neutral score and notification helpers.

These helpers deliberately do not import a repository instance. Both SQLite and
SQLAlchemy must calculate the same CVE-aware score and scan-completion message
without initializing a second storage backend as an import side effect.
"""

from __future__ import annotations

from collections.abc import Mapping
import math
from typing import Any

from ..services.cve_matcher import get_matcher
from ..services.device_identity import VENDOR_KO
from ..services.device_presentation import (
    apply_device_presentation,
    build_public_detected_connections,
    build_identity_finding,
    sanitize_public_payload,
)
from home_guardian_ml.hybrid_scoring import score_device_hybrid
from home_guardian_ml.scoring import (
    NO_TARGET_SECURITY_SUMMARY,
    SCORE_CALCULATION_FAILED_SUMMARY,
    summarize_home_security,
)

from .network_scope import normalized_physical_mac


SCORE_CALCULATION_FAILED_MESSAGE = SCORE_CALCULATION_FAILED_SUMMARY


def _public_observation_rank(device: dict[str, Any]) -> tuple[int, int, int, int]:
    """Rank same-MAC observations without treating a shared hostname as identity.

    A scanner can report one physical endpoint more than once through different
    protocol paths.  The frozen observations and research jobs remain separate,
    but the resident inventory needs one deterministic representative.  Prefer
    a resolved product, then a structured product clue, then a useful L2 label.
    """

    if apply_device_presentation(device) is not None:
        tier = 3
    else:
        cards = build_public_detected_connections([build_identity_finding(device)])
        if not cards:
            tier = 0
        elif cards[0].get("product_clue_verified") is True:
            tier = 2
        else:
            tier = 1
    return (
        tier,
        int(bool(str(device.get("model") or "").strip())),
        int(bool(str(device.get("manufacturer") or "").strip())),
        len(device.get("fingerprints") or []),
    )


def _public_observation_groups(
    devices: list[dict[str, Any]],
) -> list[tuple[int, list[int]]]:
    """Group only concrete same-MAC rows for public counting and scoring.

    Synthetic ``UNKNOWN-*`` rows intentionally keep independent observation
    identities.  A concrete physical MAC, however, represents one endpoint in
    a single authoritative scan even if service discovery emitted two rows.
    """

    groups: list[list[int]] = []
    group_by_mac: dict[str, int] = {}
    for index, device in enumerate(devices):
        physical_mac = normalized_physical_mac(device.get("mac_address"))
        if physical_mac is None:
            groups.append([index])
            continue
        group_index = group_by_mac.get(physical_mac)
        if group_index is None:
            group_by_mac[physical_mac] = len(groups)
            groups.append([index])
        else:
            groups[group_index].append(index)

    result: list[tuple[int, list[int]]] = []
    for members in groups:
        representative = max(
            members,
            key=lambda index: (_public_observation_rank(devices[index]), -index),
        )
        result.append((representative, members))
    return result


def _merged_scoring_observation(
    representative: dict[str, Any],
    members: list[dict[str, Any]],
) -> dict[str, Any]:
    """Score one physical endpoint once without discarding sibling risk facts."""

    merged = dict(representative)
    for field in (
        "open_ports",
        "services",
        "discovery_sources",
        "fingerprints",
        "risk_signals",
        "vulnerabilities",
    ):
        values: list[Any] = []
        for member in members:
            for value in member.get(field) or []:
                if value not in values:
                    values.append(value)
        merged[field] = values

    merged["default_credentials"] = any(
        bool(member.get("default_credentials")) for member in members
    )
    merged["online"] = any(bool(member.get("online", True)) for member in members)
    encryption_values = {
        str(member.get("encryption") or "").strip().casefold()
        for member in members
    }
    if encryption_values.intersection({"", "none", "open", "unencrypted"}):
        merged["encryption"] = "open"
    if str(merged.get("firmware") or "").strip().casefold() in {"", "unknown"}:
        verified_firmware = next(
            (
                str(member.get("firmware") or "").strip()
                for member in members
                if str(member.get("firmware") or "").strip().casefold()
                not in {"", "unknown"}
            ),
            "",
        )
        if verified_firmware:
            merged["firmware"] = verified_firmware
    return merged


def _private_duplicate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Keep a research row while removing its duplicate public presentation."""

    private_fields = (
        "device_id",
        "identity_status",
        "identity_note",
        "identity_evidence",
        "online",
        "last_seen",
        "risk_level",
        "risk_summary",
        "detected",
        "retry_after_scan",
    )
    return {field: finding[field] for field in private_fields if field in finding}


def _highest_pending_risk(members: list[dict[str, Any]]) -> str:
    levels = {str(member.get("risk_level") or "").strip() for member in members}
    return "red" if "red" in levels else "yellow"


def _internal_vendor_name(value: object) -> object:
    """Map presentation-only Korean labels back to catalog keys for legacy stored rows."""
    text = str(value or "").strip()
    for internal, display in VENDOR_KO.items():
        if text == display:
            return internal
    return value


def scoring_with_cve(device: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with matching CVEs merged before scoring/presentation."""
    matches = get_matcher().match_device(
        manufacturer=_internal_vendor_name(device.get("manufacturer")),
        model=device.get("model"),
        firmware=device.get("firmware"),
        risk_signals=device.get("risk_signals") or [],
        device_type=device.get("device_type"),
    )
    merged = [dict(item) for item in (device.get("vulnerabilities") or []) if isinstance(item, dict)]
    index_by_id = {
        str(item.get("cve_id")): index
        for index, item in enumerate(merged)
        if item.get("cve_id")
    }
    changed = False
    for match in matches:
        cve_id = str(match.get("cve_id") or "").strip()
        if not cve_id:
            continue
        vulnerability = {
            key: match.get(key)
            for key in (
                "cve_id",
                "severity",
                "cvss",
                "summary_ko",
                "remediation_ko",
                "source",
                "vendor",
                "product",
                "matched_on",
                "confidence",
            )
            if match.get(key) not in (None, "")
        }
        existing_index = index_by_id.get(cve_id)
        if existing_index is None:
            index_by_id[cve_id] = len(merged)
            merged.append(vulnerability)
            changed = True
            continue
        enriched_existing = {**vulnerability, **merged[existing_index]}
        if enriched_existing != merged[existing_index]:
            merged[existing_index] = enriched_existing
            changed = True
    if not changed:
        return device
    scored = dict(device)
    scored["vulnerabilities"] = merged
    return scored


def score_device_with_current_cve(device: dict[str, Any]) -> dict[str, Any]:
    """Atomically merge current CVEs and refresh the authoritative device risk."""

    enriched = dict(scoring_with_cve(device))
    scored = score_device_hybrid(enriched)
    enriched.update(
        security_score=scored["score"],
        risk_level=scored["risk_level"],
        risk_summary=scored["summary"],
        recommended_actions=scored["recommended_actions"],
    )
    return enriched


def summarize_public_security(
    devices: list[dict[str, Any]],
    *,
    coverage_complete: bool | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Score private observations, then expose only their public presentation.

    ``apply_device_presentation`` intentionally removes ports, fingerprints,
    firmware and risk signals.  Re-scoring that already-sanitized object loses
    real penalties (for example an open Telnet port).  Keep the two concerns
    separate: score the private input, then replace each score row's display
    name with the safe public device and recursively sanitize its explanation.
    """
    public_devices: list[dict[str, Any]] = []
    public_by_id: dict[str, dict[str, Any]] = {}
    scoring_inputs: list[dict[str, Any]] = []

    current_devices = [
        device
        for device in devices
        if isinstance(device, dict) and not bool(device.get("is_phantom"))
    ]
    for representative_index, member_indices in _public_observation_groups(current_devices):
        device = current_devices[representative_index]
        member_devices = [current_devices[index] for index in member_indices]
        scoring_device = _merged_scoring_observation(device, member_devices)
        scoring_device = scoring_with_cve(scoring_device)
        presented = apply_device_presentation(scoring_device)
        if presented is None:
            finding = build_identity_finding(device)
            connections = build_public_detected_connections([finding])
            presented = connections[0] if connections else None
            if presented is None:
                # A verified fresh neighbour entry proves that one current LAN
                # endpoint exists, even when its product identity is not yet
                # safe to display. Keep its real security signals in the
                # aggregate score, but do not add a public card or device-score
                # row with a fabricated/generic name.
                if (
                    finding.get("observed_service") == "neighbor-presence"
                    and finding.get("observed_service_verified") is True
                    and finding.get("observation_suffix_verified") is True
                ):
                    scoring_input = dict(scoring_device)
                    scoring_input["device_id"] = str(finding.get("device_id") or "")
                    if scoring_input["device_id"]:
                        scoring_inputs.append(scoring_input)
                continue
        device_id = str(presented.get("device_id") or "")
        if not device_id:
            continue
        if not bool(presented.get("is_identity_finding")):
            public_devices.append(presented)
        public_by_id[device_id] = presented
        # The scorer echoes its input ID in ``device_scores``.  Use the same
        # public-safe value the device DTO exposes so an old IP/MAC-based ID
        # cannot make its score row disappear during the lookup below.
        scoring_input = dict(scoring_device)
        scoring_input["device_id"] = device_id
        scoring_inputs.append(scoring_input)

    # Persistence and every public read path must use the same scorer.  The
    # aggregate remains repository-neutral; this explicit dependency injection
    # prevents a fresh /scan/result or /security/score response from silently
    # recomputing base-only scores after hybrid scores were stored.
    summary = summarize_home_security(
        scoring_inputs,
        device_scorer=score_device_hybrid,
        coverage_complete=coverage_complete,
    )
    public_scores: list[dict[str, Any]] = []
    for score in summary.get("device_scores", []):
        if not isinstance(score, dict):
            continue
        presented = public_by_id.get(str(score.get("device_id") or ""))
        if presented is None:
            continue
        safe_score = sanitize_public_payload(
            {
                **score,
                "device_id": presented.get("device_id"),
                "name": presented.get("name"),
                "is_identity_finding": bool(presented.get("is_identity_finding")),
            }
        )
        if safe_score.get("device_id") and safe_score.get("name"):
            presented.update(
                security_score=safe_score.get("score"),
                risk_level=safe_score.get("risk_level"),
                risk_summary=safe_score.get("summary"),
                recommended_actions=safe_score.get("recommended_actions") or [],
            )
            public_scores.append(safe_score)

    return public_devices, sanitize_public_payload(
        {
            "score": summary.get("score"),
            "risk_level": summary.get("risk_level"),
            "summary": summary.get("summary"),
            "device_scores": public_scores,
        }
    )


def valid_public_numeric_score(value: object) -> bool:
    """Return True only for a finite, non-boolean public score value."""

    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def public_score_status(
    summary: dict[str, Any],
    *,
    coverage_complete: bool | None,
) -> str:
    """Return the public score lifecycle without conflating empty and failed scans.

    ``not_started`` and ``held`` both carry a null score but mean different
    things. A partial scan may expose an explicitly projected finite aggregate
    as ``provisional``; it remains separate from whole-home completion. A
    completed scan with no non-self target is ``no_targets``. Completed scans
    with at least one valid score, including the fail-closed all-scorer-failure
    result (0/red), are ``final``.
    """

    if coverage_complete is None:
        return "not_started"
    if coverage_complete is False:
        return (
            "provisional"
            if summary.get("score_status") == "provisional"
            and valid_public_numeric_score(summary.get("score"))
            and not public_score_calculation_failed(summary)
            else "held"
        )
    if summary.get("score") is None:
        return "no_targets"
    return "final"


def public_score_calculation_failed(summary: Mapping[str, Any] | None) -> bool:
    """Return whether a completed aggregate is the explicit fail-closed result.

    A legitimate device can score zero, so the aggregate alone is insufficient.
    The fail-closed state requires a red zero aggregate and at least one non-self
    score row, with every such row retaining its per-device ``score=None`` error.
    """

    if not isinstance(summary, Mapping):
        return False
    if summary.get("score") != 0 or summary.get("risk_level") != "red":
        return False
    score_rows = summary.get("device_scores")
    if not isinstance(score_rows, list):
        return False
    non_self_rows = [
        row
        for row in score_rows
        if isinstance(row, Mapping) and not bool(row.get("is_self"))
    ]
    return bool(non_self_rows) and all(row.get("score") is None for row in non_self_rows)


def scan_completed_message(
    devices: list[dict[str, Any]],
    identity_findings: list[dict[str, Any]] | None = None,
    security_summary: Mapping[str, Any] | None = None,
) -> str:
    """Describe every evidence-backed device observation with one count unit."""

    findings = build_public_detected_connections(identity_findings or [])
    total = len(devices) + len(findings)
    if total == 0:
        aggregate_risk = str((security_summary or {}).get("risk_level") or "").strip().lower()
        if aggregate_risk == "red":
            return "현재 Wi-Fi에서 위험 신호를 확인했어요. 앱에서 점검 결과를 확인해 주세요."
        if aggregate_risk == "yellow":
            return "현재 Wi-Fi에서 주의 신호를 확인했어요. 앱에서 점검 결과를 확인해 주세요."
        return NO_TARGET_SECURITY_SUMMARY
    if public_score_calculation_failed(security_summary):
        return SCORE_CALCULATION_FAILED_MESSAGE
    red = confirmed_public_red_count(devices, findings)
    yellow = sum(1 for device in devices if device.get("risk_level") == "yellow") + sum(
        1 for finding in findings if finding.get("risk_level") == "yellow"
    )
    # ``identity_findings`` are real, independently observed devices whose
    # exact product identity is still unresolved.  Calling them "추가 연결"
    # makes them sound less real and exposes an implementation distinction to
    # the user.  Refusal-only telemetry is removed before this boundary, so all
    # rows here use the same device counter.
    subject = f"기기 {total}대"
    if red and yellow:
        return f"{subject}를 확인했고 위험 {red}대와 주의 {yellow}대를 찾았어요. 자세히 확인해 주세요."
    if red:
        return f"{subject}를 확인했고 위험 기기 {red}대를 찾았어요. 바로 확인해 주세요."
    if yellow:
        return f"{subject}를 확인했고 주의가 필요한 기기 {yellow}대를 찾았어요. 한 번 확인해 주세요."
    return f"{subject}를 확인했고 위험·주의 기기는 없었어요."


def confirmed_public_red_count(
    devices: list[dict[str, Any]],
    identity_findings: list[dict[str, Any]] | None = None,
) -> int:
    """Count confirmed red products and real unresolved observations.

    ``identity_findings`` is already the public projection of a detected,
    non-phantom observation.  A product name may still be unresolved while an
    independently observed security signal is red; withholding the score must
    never downgrade that warning to yellow.
    """

    visible_findings = build_public_detected_connections(identity_findings or [])
    return sum(1 for device in devices if device.get("risk_level") == "red") + sum(
        1
        for finding in visible_findings
        if finding.get("risk_level") == "red"
    )


def visible_identity_findings(
    identity_findings: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Keep private resolver rows only when they also qualify as public cards.

    Raw findings remain valuable for the evidence store and automatic identity
    research, but a bare TCP/mDNS/HTTP response is not a household device. A
    fresh L2 neighbour is retained because it proves one current local
    endpoint. All persisted counters, score state, alerts and completion gates use this
    filtered *raw* list.  Returning the original rows (rather than the public
    DTOs) lets the existing scoring and event projectors revalidate them at
    their own trust boundary without losing risk evidence.
    """

    raw = [item for item in (identity_findings or []) if isinstance(item, dict)]
    visible_ids = {
        str(item.get("device_id") or "").strip()
        for item in build_public_detected_connections(raw)
        if str(item.get("device_id") or "").strip()
    }
    if not visible_ids:
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for finding in raw:
        device_id = str(finding.get("device_id") or "").strip()
        if not device_id or device_id not in visible_ids or device_id in seen:
            continue
        seen.add(device_id)
        result.append(finding)
    return result


def build_public_identity_findings(
    observations: list[dict[str, Any]],
    public_devices: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Project unresolved observations without duplicating restored products.

    A weak current observation can inherit a previously verified product identity
    when the strong network scope and physical MAC still match.  In that case the
    same connection is already present in ``public_devices`` and must not also be
    counted as an unresolved finding.
    """

    public_ids = {
        str(device.get("device_id") or "")
        for device in (public_devices or [])
        if isinstance(device, dict) and device.get("device_id")
    }
    current_observations = [
        observation
        for observation in observations
        if isinstance(observation, dict) and not bool(observation.get("is_phantom"))
    ]
    groups = _public_observation_groups(current_observations)
    representative_by_index: dict[int, int] = {
        member_index: representative_index
        for representative_index, member_indices in groups
        for member_index in member_indices
    }
    members_by_representative: dict[int, list[dict[str, Any]]] = {
        representative_index: [current_observations[index] for index in member_indices]
        for representative_index, member_indices in groups
    }

    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, observation in enumerate(current_observations):
        if apply_device_presentation(observation) is not None:
            continue
        finding = build_identity_finding(observation)
        finding_id = str(finding.get("device_id") or "")
        if finding_id and (finding_id in public_ids or finding_id in seen_ids):
            continue
        if finding_id:
            seen_ids.add(finding_id)
        representative_index = representative_by_index[index]
        if representative_index != index:
            finding = _private_duplicate_finding(finding)
        else:
            pending_risk = _highest_pending_risk(
                members_by_representative[representative_index]
            )
            finding["risk_level"] = pending_risk
            finding["risk_summary"] = (
                "보안 위험 신호가 있어 먼저 확인이 필요해요."
                if pending_risk == "red"
                else "확인된 보안 신호를 기준으로 현재 상태를 계산했어요."
            )
        findings.append(finding)
    return findings
