"""Shared scan-state projections for repository parity."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .scoring_helpers import public_score_calculation_failed, valid_public_numeric_score


PARTIAL_SCAN_STEP = "일부 항목을 확인하지 못했어요"
PARTIAL_SCAN_NOTIFICATION = "일부 기기 확인이 끝나지 않았어요. Wi-Fi 연결을 확인한 뒤 다시 검사해 주세요."
IDENTITY_PENDING_STEP = "점검 완료"
PARTIAL_PROVISIONAL_SUMMARY = (
    "이번 점검에서 확인한 연결 기준 점수예요. 집 전체 최종 점수는 아니며, 다시 점검하면 달라질 수 있어요."
)
PARTIAL_PROVISIONAL_RED_SUMMARY = (
    "이번 점검에서 확인한 연결 기준 점수이며 집 전체 최종 점수는 아니에요. 확인된 위험 기기도 있어요. "
    "위험 안내를 먼저 확인한 뒤 다시 점검해 주세요."
)


def _has_confirmed_red(summary: Mapping[str, Any]) -> bool:
    device_scores = summary.get("device_scores")
    return (
        str(summary.get("risk_level") or "").lower() == "red"
        or int(summary.get("high_risk_devices") or 0) > 0
        or (
            isinstance(device_scores, list)
            and any(
                isinstance(item, Mapping) and str(item.get("risk_level") or "").lower() == "red"
                for item in device_scores
            )
        )
    )


def hold_partial_security(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Hold the numeric score without downgrading an already confirmed danger."""

    confirmed_red = _has_confirmed_red(summary)
    return {
        **dict(summary),
        "score": None,
        "score_status": "held",
        "risk_level": "red" if confirmed_red else "yellow",
        "summary": (
            "검사가 일부만 끝났고 확인된 위험 기기가 있어 점수를 확정하지 않았어요. 위험 안내를 먼저 확인한 뒤 다시 검사해 주세요."
            if confirmed_red
            else "검사가 일부만 끝나 안전 점수를 확정하지 않았어요. 연결을 확인한 뒤 다시 검사해 주세요."
        ),
    }


def project_partial_security(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve a real observed aggregate while marking it non-final.

    Partial coverage and score availability are separate facts. A finite score
    already produced from observed devices remains useful, but is explicitly
    provisional. Empty/no-target inputs and scorer failures remain held/null.
    """

    result = dict(summary)
    if not valid_public_numeric_score(result.get("score")) or public_score_calculation_failed(result):
        return hold_partial_security(result)

    confirmed_red = _has_confirmed_red(result)
    result.update(
        {
            "score_status": "provisional",
            "risk_level": "red" if confirmed_red else result.get("risk_level", "yellow"),
            "summary": (
                PARTIAL_PROVISIONAL_RED_SUMMARY
                if confirmed_red
                else PARTIAL_PROVISIONAL_SUMMARY
            ),
        }
    )
    return result


def annotate_identity_incomplete_security(
    summary: Mapping[str, Any],
    identity_findings: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Keep a final observation-based score while product enrichment continues.

    Identity resolution and network coverage are different checks.  A pending
    product lookup must not turn a physically complete LAN scan into a score
    outage or a retry loop. Confirmed red evidence remains red. A later exact
    model match may add CVE evidence and produces a newly calculated score,
    just like any later scan; the current scan itself is complete.
    """

    result = dict(summary)
    pending_count = len(identity_findings)
    confirmed_red = str(result.get("risk_level") or "").lower() == "red" or any(
        str(finding.get("risk_level") or "").lower() == "red"
        for finding in identity_findings
    )
    result.update(
        {
            "risk_level": "red" if confirmed_red else result.get("risk_level", "yellow"),
            "score_status": "final",
            "identity_incomplete": pending_count > 0,
            "identity_pending_count": pending_count,
            "summary": (
                "점검은 완료됐어요. 확인한 모든 연결의 보안 신호를 점수에 반영했어요. "
                "확인된 위험 기기가 있으니 위험 안내를 확인해 주세요."
                if confirmed_red
                else "점검은 완료됐어요. 확인한 모든 연결의 보안 신호를 점수에 반영했어요."
            ),
        }
    )
    return result
