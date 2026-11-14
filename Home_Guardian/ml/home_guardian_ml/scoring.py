"""규칙 기반 보안 점수 산출.

점수는 ML 정확도가 아니라 **규칙(열린 포트·기본 비밀번호·암호화·CVE severity)과
외부 보안 표준**에 근거한다. (ML 트래픽 모델 F1 0.99대는 별도 학술/RPi 트래픽 트랙이며
앱 device 점수에는 직접 쓰이지 않는다 — hybrid_scoring 은 lightweight 모델을 보수적으로만
반영한다.)

신호등 경계와 게이트의 근거(외부 표준을 컷오프 숫자 그대로 인용한 1차 출처는 없으므로
아래 원리에 기반한 **자체 보수 설계**임을 명시한다):

  1) CVSS v3.1/v4.0 (FIRST.org): 안전(None/Low)은 0.0~3.9 로 좁고(하위 ~39%),
     High 7.0+, Critical 9.0+. → 보안 도메인은 안전 구간을 좁게, 위험을 보수적으로 둔다.
  2) Saltzer & Schroeder(1975) fail-safe defaults: 기본은 "안전하지 않음", 강한 조건이
     충족될 때만 안전 판정.
  3) ETSI EN 303 645 / NIST IR 8425: 소비자 IoT 베이스라인은 점수가 아닌 항목별
     pass/fail. → 평균이 높아도 필수 항목(기본 비밀번호·암호화 등)에 결함이 있으면 안전 불가.

따라서 일반 앱(예: 50%만 넘어도 안전)보다 엄격하게 **90점 이상만 '안전'**으로 둔다.
"왜 94%가 안전인가"에 대한 답은: 단순 점수가 아니라 필수 보안 게이트를 통과한
90점 이상만 안전으로 보고, 위험 기기가 1대라도 있으면 평균이 높아도 안전으로 올리지
않는다는 것이다.
"""

from __future__ import annotations

import logging
from statistics import mean
from collections.abc import Callable
from typing import Any

DeviceScorer = Callable[[dict[str, Any]], dict[str, Any]]

NOT_STARTED_SECURITY_SUMMARY = "아직 점검 전이에요. 우리 집 Wi-Fi 점검을 시작해 주세요."
PARTIAL_SECURITY_SUMMARY = "점검이 일부만 끝나 점수를 확정하지 않았어요. 지금까지 확인된 결과는 보존했어요."
NO_TARGET_SECURITY_SUMMARY = "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."
SCORE_CALCULATION_FAILED_SUMMARY = (
    "점검은 완료됐지만 기기 점수를 계산하지 못했어요. "
    "기기별 실패 안내를 확인해 주세요."
)

# ── 신호등 경계 (자체 보수 설계) ─────────────────────────────────────────
SAFE_SCORE_THRESHOLD = 90      # 이상 → green(안전)
CAUTION_SCORE_THRESHOLD = 60   # 이상 → yellow(주의), 미만 → red(위험)

# 게이트: 점수가 높아도 필수 보안 항목에 결함이 있으면 안전(green) 진입을 막는다.
CAUTION_GATE_CAP = SAFE_SCORE_THRESHOLD - 1       # 89 — green 진입 차단(최대 주의)
CRITICAL_GATE_CAP = CAUTION_SCORE_THRESHOLD - 1   # 59 — 위험(red) 강등

DANGEROUS_PORT_PENALTIES = {
    23: (20, "Telnet 포트가 열려 있어 원격 접속 위험이 커요."),
    21: (12, "FTP 포트가 열려 있어 파일 접근 위험을 확인해야 해요."),
    554: (15, "카메라 영상 접근용 RTSP 포트가 열려 있어요."),
    1900: (5, "UPnP 기능이 켜져 있을 수 있어 외부 접속 설정을 확인해야 해요."),
    3702: (5, "ONVIF 카메라 탐색 신호가 보여 카메라 보안 설정 확인이 필요해요."),
}

VULNERABILITY_PENALTIES = {
    "critical": 20,
    "high": 15,
    "medium": 7,
    "low": 3,
}


def _parse_cvss(raw: Any) -> float | None:
    """cvss 가 숫자·숫자문자열·None 등 혼용으로 와도 안전하게 float 로 정규화한다.

    카탈로그 CVE 는 cvss 형식을 검증하지 않아 "9.5" 같은 문자열이 올 수 있다.
    이 경우 isinstance 검사만 하면 critical CVE 를 조용히 놓치므로 명시적으로 파싱한다.
    """
    if isinstance(raw, bool):
        return None
    # CVSS 는 0.0~10.0 범위. 범위를 벗어난 값(예: "999.5", "-5")은 클리핑해 잘못된 게이트 판정을 막는다.
    if isinstance(raw, (int, float)):
        return max(0.0, min(10.0, float(raw)))
    if isinstance(raw, str) and raw.strip():
        try:
            return max(0.0, min(10.0, float(raw.strip())))
        except ValueError:
            return None
    return None


def _evaluate_security_gate(
    device: dict[str, Any],
    risk_signals: set[str],
    is_camera_like: bool,
    open_ports: list[int],
) -> str | None:
    """필수 보안 항목 게이트.

    반환: ``"critical"`` 위험 강등 / ``"caution"`` 안전 차단(최대 주의) / ``None`` 제한 없음.

    근거: ETSI EN 303 645·NIST IR 8425 의 항목별 pass/fail, CVSS 의 High 7.0+/Critical 9.0+
    경계. 평균 점수가 높아도 아래 필수 항목 결함이 있으면 안전으로 올리지 않는다.
    """
    has_critical_cve = False
    has_high_cve = False
    for vulnerability in (device.get("vulnerabilities") or []):
        if not isinstance(vulnerability, dict):
            continue  # None·잘못된 형태 항목 건너뜀(크래시 방지)
        severity = str(vulnerability.get("severity", "")).lower()
        cvss_value = _parse_cvss(vulnerability.get("cvss"))
        if severity == "critical" or (cvss_value is not None and cvss_value >= 9.0):
            has_critical_cve = True
        elif severity == "high" or (cvss_value is not None and cvss_value >= 7.0):
            has_high_cve = True

    has_default = bool(device.get("default_credentials")) or "default_credentials_possible" in risk_signals
    camera_default_combo = is_camera_like and has_default
    telnet_open = 23 in open_ports or "telnet_open" in risk_signals
    # "unknown" 은 확인 불가일 뿐 미암호화 확정이 아니므로 게이트에서 제외한다.
    unencrypted = str(device.get("encryption", "")).lower() in {"", "none", "open"}

    # 사용자에게 "높은 위험"으로 안내하는 High/Critical CVE가 하나라도
    # 확인되면 기기 전체를 안전/주의로 둘 수 없다. 취약점 표시와 실제
    # 기기 분류가 서로 다른 신호를 내지 않도록 red 게이트를 적용한다.
    if has_critical_cve or has_high_cve or camera_default_combo:
        return "critical"
    if has_default or telnet_open or unencrypted:
        return "caution"
    return None


def score_device(device: dict[str, Any]) -> dict[str, Any]:
    score = 100
    reasons: list[str] = []
    actions: list[str] = []
    # None-safe: 필드가 None 값으로 존재해도(.get 의 default 는 키 누락 시에만 적용) 크래시하지 않게 한다.
    # 한 기기의 이상 데이터가 score_device 를 터뜨리면 /score·집계·보호자 알림 전체가 실패한다.
    risk_signals = set(str(signal) for signal in (device.get("risk_signals") or []))
    device_type = str(device.get("device_type") or "unknown").lower()
    open_ports = list(device.get("open_ports") or [])

    # 자기 자신(이 휴대폰)은 점검 대상이 아니다. 점수는 100 으로 고정하고
    # 보호자에게는 "내 휴대폰" 임을 알려 안내문구로 표시한다.
    if "self_device" in risk_signals:
        return {
            "device_id": device.get("device_id", "self"),
            "name": device.get("name", "내 휴대폰"),
            "score": 100,
            "risk_level": "green",
            "gate": None,
            "reasons": ["이 휴대폰은 검사 대상이 아니에요."],
            "recommended_actions": [
                "잠금 화면 비밀번호와 자동 업데이트만 켜져 있으면 충분해요.",
            ],
            "summary": "이 휴대폰은 검사 대상이 아니에요.",
            "is_self": True,
        }

    if device.get("default_credentials"):
        score -= 20
        reasons.append("기본 비밀번호 사용 가능성이 있어요.")
        actions.append("관리자 비밀번호를 가족만 아는 새 비밀번호로 바꿔 주세요.")
    elif "default_credentials_possible" in risk_signals:
        score -= 10
        reasons.append("관리자 페이지나 원격 접속 포트가 보여 기본 비밀번호 사용 여부를 확인해야 해요.")
        actions.append("기기 앱이나 관리자 페이지에서 초기 비밀번호가 바뀌었는지 확인해 주세요.")

    is_camera_like = device_type == "camera" or "camera_candidate" in risk_signals
    if is_camera_like:
        score -= 5
        reasons.append("카메라로 추정되는 기기라 사생활 보호 설정을 우선 확인해야 해요.")
        actions.append("카메라 렌즈, 원격 보기, 녹화 공유 설정을 먼저 확인해 주세요.")

    # 복합 위험 패턴: 카메라 후보 + 기본 비밀번호 가능성은 카메라 침해의 가장 흔한 경로다.
    if is_camera_like and (
        device.get("default_credentials") or "default_credentials_possible" in risk_signals
    ):
        score -= 10
        reasons.append("카메라 + 기본 비밀번호 가능성은 외부에서 영상 접근이 가능한 흔한 경로예요.")
        actions.append("카메라 관리자 비밀번호를 가장 먼저 바꾸고 외부 원격 보기를 차단해 주세요.")

    vulnerability_penalty = 0
    for vulnerability in (device.get("vulnerabilities") or []):
        if not isinstance(vulnerability, dict):
            continue  # None·잘못된 형태의 취약점 항목은 건너뛴다(크래시 방지)
        severity = str(vulnerability.get("severity", "low")).lower()
        penalty = VULNERABILITY_PENALTIES.get(severity, 3)
        vulnerability_penalty += penalty
        reasons.append(f"{vulnerability.get('cve_id', '알 수 없는 취약점')} 취약점이 발견됐어요.")
    if vulnerability_penalty:
        score -= min(vulnerability_penalty, 40)
        actions.append("제조사 앱이나 관리자 페이지에서 펌웨어 업데이트를 확인해 주세요.")

    port_penalty = 0
    for port in open_ports:
        if port in DANGEROUS_PORT_PENALTIES:
            penalty, reason = DANGEROUS_PORT_PENALTIES[port]
            port_penalty += penalty
            reasons.append(reason)
    if "http_admin_candidate" in risk_signals:
        port_penalty += 7
        reasons.append("웹 관리자 화면으로 보이는 서비스가 열려 있어요.")
    if "rtsp_open" in risk_signals and 554 not in open_ports:
        port_penalty += 10
        reasons.append("카메라 영상 스트림 신호가 감지됐어요.")
    if len(open_ports) >= 5:
        port_penalty += 10
        reasons.append("열린 포트가 많아 공격 표면이 넓어요.")
    if port_penalty:
        score -= min(port_penalty, 25)
        actions.append("사용하지 않는 원격 접속, UPnP, 포트포워딩 기능을 꺼 주세요.")

    if str(device.get("encryption", "")).lower() in {"", "none", "open"}:
        score -= 15
        reasons.append("암호화되지 않은 연결이 감지됐어요.")
        actions.append("가능하면 WPA2 이상 또는 HTTPS 설정을 사용해 주세요.")

    if device.get("online") is False:
        score -= 5
        reasons.append("기기가 오프라인이라 최신 상태를 확인하지 못했어요.")

    pre_gate_score = max(0, min(100, score))

    # 필수 보안 게이트: 점수가 높아도 핵심 결함이 있으면 안전(green)으로 못 올린다.
    gate = _evaluate_security_gate(device, risk_signals, is_camera_like, open_ports)
    score = pre_gate_score
    if gate == "critical":
        score = min(score, CRITICAL_GATE_CAP)
        if pre_gate_score > CRITICAL_GATE_CAP:
            reasons.append("필수 보안 항목에 심각한 결함이 있어 '위험'으로 분류했어요.")
    elif gate == "caution":
        score = min(score, CAUTION_GATE_CAP)
        if pre_gate_score > CAUTION_GATE_CAP:
            reasons.append("점수는 높지만 필수 보안 항목을 충족하지 못해 '안전'으로 보지 않았어요.")

    risk_level = risk_level_for_score(score)

    if not reasons:
        reasons.append("현재 큰 위험은 보이지 않아요.")
    if not actions:
        actions.append("정기 점검 때 다시 확인하면 충분해요.")

    return {
        "device_id": device.get("device_id", "unknown"),
        "name": device.get("name") or "이름 미확인 기기",
        "score": score,
        "risk_level": risk_level,
        "gate": gate,
        "reasons": reasons,
        "recommended_actions": actions,
        "summary": reasons[0],
    }


def _score_device_safe(
    device: dict[str, Any],
    device_scorer: DeviceScorer | None = None,
) -> dict[str, Any]:
    """device scorer 를 per-device 격리한다. 한 기기의 이상 데이터로 점수 산정이 터져도 전체 집계
    (/score·보호자 알림)가 죽지 않게, 실패 시 로깅(조용한 실패 금지) 후 '점검 전'(unknown) 으로 폴백한다.
    거짓 안심(green)도 거짓 경보(red)도 아닌 정직한 미상으로 둔다. scorer 를 주입하지 않으면
    기존 규칙 기반 ``score_device`` 를 쓴다."""
    try:
        return (device_scorer or score_device)(device)
    except Exception:  # noqa: BLE001 - 한 기기 실패가 전체 점수를 망치지 않도록 격리(로깅 동반)
        logging.getLogger("home_guardian").exception(
            "score_device 실패 — '점검 전'으로 폴백(device_id=%s)",
            device.get("device_id") if isinstance(device, dict) else None,
        )
        name = device.get("name") if isinstance(device, dict) else None
        return {
            "device_id": (device.get("device_id") if isinstance(device, dict) else None) or "unknown",
            "name": name or "이름 미확인 기기",
            "score": None,
            "risk_level": "unknown",
            "gate": None,
            "reasons": ["이 기기는 점검 정보를 읽지 못했어요."],
            "recommended_actions": ["다음 점검 때 다시 확인해 주세요."],
            "summary": "이 기기는 점검 정보를 읽지 못했어요.",
        }


def _is_phantom_signal(device: dict[str, Any]) -> bool:
    """미확증 유령 신호(단일 bare 포트·보강 0)인가. 앱은 phantom 을 '기기'가 아닌 'unverified 신호'로
    분리 표시(device 목록·보호자 화면에서 제외)하므로, 홈 보안 점수·위험 카운트에서도 제외해 화면과
    일치시킨다. phantom 은 운영 RPi 의 ARP/ping/프로브로 실재 안 함이 확인된 NAT 오탐이라, 점수에서
    빼도 실제 위험을 숨기지 않는다(실제 위험 기기는 보강신호가 있어 phantom 으로 분류되지 않는다)."""
    if not isinstance(device, dict):
        return False
    try:
        return bool(device.get("is_phantom")) or "phantom_signal" in (device.get("risk_signals") or [])
    except Exception:  # noqa: BLE001 - 이상 데이터로 판별 실패 시 '기기'로 간주(_score_device_safe 가 안전 폴백)
        return False


def summarize_home_security(
    devices: list[dict[str, Any]],
    *,
    device_scorer: DeviceScorer | None = None,
    coverage_complete: bool | None = None,
) -> dict[str, Any]:
    """Aggregate one home's scores using one explicitly selected device scorer.

    The default preserves the public rule-based API. Repository/public API paths
    inject ``score_device_hybrid`` so persisted rows and freshly aggregated
    responses cannot diverge when the lightweight model is available.

    ``coverage_complete`` is deliberately tri-state. Only explicit ``True``
    can turn an all-scorer-failure observation window into a fail-safe numeric
    danger result. A completed window with no non-self target stays explicitly
    unscored: completing discovery does not prove that every product was found
    or safe. ``False``/``None`` also keep edge states unscored so a partial or
    pre-scan response cannot look complete.
    """
    # phantom(미확증 유령 신호)은 '기기'가 아니므로 홈 점수·위험 집계에서 제외한다(device 목록·보호자
    # 화면과 동일 기준). 그러지 않으면 유령이 평균을 끌어내리거나 caution 카운트(FCM 알림)에 잡혀
    # '홈은 주의인데 화면엔 위험 기기가 없는' 모순이 생긴다.
    devices = [device for device in devices if not _is_phantom_signal(device)]
    if not devices:
        if coverage_complete is True:
            return {
                "score": None,
                "risk_level": "unknown",
                "device_scores": [],
                "summary": NO_TARGET_SECURITY_SUMMARY,
            }
        if coverage_complete is False:
            return {
                "score": None,
                "risk_level": "unknown",
                "device_scores": [],
                "summary": PARTIAL_SECURITY_SUMMARY,
            }
        return {
            "score": None,
            "risk_level": "unknown",
            "device_scores": [],
            "summary": NOT_STARTED_SECURITY_SUMMARY,
        }

    device_scores = [_score_device_safe(device, device_scorer) for device in devices]
    # 내 휴대폰(self) 은 점검 대상에서, 점수 산정 실패(점검 전·score=None) 기기는 평균/위험 카운트에서
    # 제외한다(평균이 None 에 터지지 않게). 출력 목록(device_scores)에는 폴백 기기도 그대로 남긴다.
    non_self_scores = [item for item in device_scores if not item.get("is_self")]
    scored_for_average = [item for item in non_self_scores if item.get("score") is not None]
    if not scored_for_average:
        if coverage_complete is True and not non_self_scores:
            return {
                "score": None,
                "risk_level": "unknown",
                "device_scores": device_scores,
                "summary": NO_TARGET_SECURITY_SUMMARY,
            }
        if coverage_complete is True:
            return {
                "score": 0,
                "risk_level": "red",
                "device_scores": device_scores,
                "summary": SCORE_CALCULATION_FAILED_SUMMARY,
            }
        if coverage_complete is False:
            return {
                "score": None,
                "risk_level": "unknown",
                "device_scores": device_scores,
                "summary": PARTIAL_SECURITY_SUMMARY,
            }
        return {
            "score": None,
            "risk_level": "unknown",
            "device_scores": device_scores,
            "summary": NOT_STARTED_SECURITY_SUMMARY,
        }

    average = round(mean(item["score"] for item in scored_for_average))
    high_risk = [item for item in scored_for_average if item["risk_level"] == "red"]
    critical_devices = [item for item in scored_for_average if item.get("gate") == "critical"]

    # 홈 전체 점수 게이트: 단순 평균이 위험 기기를 희석하지 못하게 한다.
    # 위험(red) 기기가 1대라도 있으면 안전(green) 진입을 막고, critical 기기면 위험으로 강등.
    home_score = average
    if critical_devices:
        home_score = min(home_score, CRITICAL_GATE_CAP)
    elif high_risk:
        home_score = min(home_score, CAUTION_GATE_CAP)

    return {
        "score": home_score,
        "risk_level": risk_level_for_score(home_score),
        "device_scores": device_scores,
        "summary": make_home_summary(home_score, len(high_risk)),
    }


def risk_level_for_score(score: int) -> str:
    """신호등 기준(자체 보수 설계): 90~100 green(안전), 60~89 yellow(주의), 0~59 red(위험).

    일반 앱보다 안전 구간을 좁게 둔다(CVSS 안전 0.0~3.9, fail-safe defaults 근거).
    """
    if score >= SAFE_SCORE_THRESHOLD:
        return "green"
    if score >= CAUTION_SCORE_THRESHOLD:
        return "yellow"
    return "red"


def make_home_summary(score: int, high_risk_count: int) -> str:
    if high_risk_count:
        return f"위험한 기기 {high_risk_count}대를 먼저 확인해 주세요."
    if score >= SAFE_SCORE_THRESHOLD:
        return "현재 홈 네트워크 상태가 안정적이에요."
    return "몇 가지 설정을 확인하면 더 안전해질 수 있어요."
