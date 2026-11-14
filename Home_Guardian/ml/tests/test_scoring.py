from home_guardian_ml.scoring import (
    CAUTION_SCORE_THRESHOLD,
    SAFE_SCORE_THRESHOLD,
    score_device,
    summarize_home_security,
)


def test_critical_gate_caps_camera_default_to_red():
    result = score_device(
        {"device_type": "camera", "default_credentials": True, "open_ports": [554], "encryption": "none"}
    )
    assert result["gate"] == "critical"
    assert result["score"] <= CAUTION_SCORE_THRESHOLD - 1
    assert result["risk_level"] == "red"


def test_high_cve_forces_actual_device_risk_to_red():
    result = score_device(
        {
            "open_ports": [],
            "default_credentials": False,
            "encryption": "wpa2",
            "vulnerabilities": [{"cve_id": "X", "severity": "high"}],
        }
    )
    assert result["gate"] == "critical"
    assert result["risk_level"] == "red"


def test_cvss_string_critical_is_detected():
    """cvss 가 문자열 '9.8' 로 와도 critical 게이트가 작동한다(정규화 회귀 방지)."""
    result = score_device(
        {
            "open_ports": [],
            "default_credentials": False,
            "encryption": "wpa2",
            "vulnerabilities": [{"cve_id": "X", "cvss": "9.8"}],
        }
    )
    assert result["gate"] == "critical"
    assert result["risk_level"] == "red"


def test_score_device_clamps_to_zero_for_many_risks():
    result = score_device(
        {
            "device_id": "bad",
            "name": "위험 기기",
            "default_credentials": True,
            "open_ports": [21, 23, 80, 443, 554, 1900],
            "encryption": "none",
            "vulnerabilities": [
                {"cve_id": "CVE-1", "severity": "critical"},
                {"cve_id": "CVE-2", "severity": "high"},
                {"cve_id": "CVE-3", "severity": "medium"},
            ],
        }
    )

    assert result["score"] == 0
    assert result["risk_level"] == "red"
    assert any("비밀번호" in action for action in result["recommended_actions"])


def test_score_device_returns_green_with_korean_fallback_for_safe_device():
    result = score_device(
        {
            "device_id": "safe",
            "name": "안전 기기",
            "open_ports": [443],
            "default_credentials": False,
            "encryption": "wpa2",
            "vulnerabilities": [],
        }
    )

    assert result["score"] == 100
    assert result["risk_level"] == "green"
    assert result["gate"] is None
    assert result["summary"] == "현재 큰 위험은 보이지 않아요."


def test_security_gate_blocks_green_even_when_score_is_high():
    """점수가 90이어도 필수 보안 항목(기본 비밀번호 가능성)을 충족 못하면 안전 불가.

    근거: ETSI EN 303 645·NIST IR 8425 의 항목별 pass/fail, Saltzer&Schroeder fail-safe defaults.
    """
    result = score_device(
        {
            "device_id": "gated",
            "name": "관리자 노출 기기",
            "open_ports": [],
            "default_credentials": False,
            "encryption": "wpa2",
            "risk_signals": ["default_credentials_possible"],
        }
    )

    assert result["score"] == SAFE_SCORE_THRESHOLD - 1  # 89 — green 진입 차단
    assert result["risk_level"] == "yellow"
    assert result["gate"] == "caution"
    assert any("안전" in reason for reason in result["reasons"])


def test_summarize_empty_devices_is_pre_scan_unknown_state():
    """기기 0대 = '아직 점검 전' 상태. 0점/red로 잘못된 위협 인상을 주지 않는다."""
    result = summarize_home_security([])

    assert result["score"] is None
    assert result["risk_level"] == "unknown"
    assert "점검" in result["summary"]


def test_summarize_home_blocks_safe_when_a_risky_device_exists():
    """위험(red) 기기가 1대라도 있으면 안전한 기기 평균에 희석되지 않고 최소 '주의'."""
    result = summarize_home_security(
        [
            {"device_id": "a", "open_ports": [], "default_credentials": False, "encryption": "wpa2"},
            {"device_id": "b", "open_ports": [23], "default_credentials": True, "encryption": "none"},
        ]
    )

    assert result["score"] == 72
    assert result["risk_level"] == "yellow"  # 평균은 72지만 위험 기기 1대로 green 차단
    assert len(result["device_scores"]) == 2


def test_summarize_home_critical_device_forces_red_despite_safe_majority():
    """카메라+기본비번(critical 게이트) 기기 1대면 안전 기기 다수에도 홈 전체가 위험."""
    safe = {"open_ports": [443], "default_credentials": False, "encryption": "wpa2"}
    result = summarize_home_security(
        [
            {"device_id": "a", **safe},
            {"device_id": "b", **safe},
            {"device_id": "c", **safe},
            {
                "device_id": "camera",
                "device_type": "camera",
                "default_credentials": True,
                "open_ports": [554],
                "encryption": "none",
            },
        ]
    )

    assert result["risk_level"] == "red"
    assert any(item.get("gate") == "critical" for item in result["device_scores"])


def test_summarize_excludes_phantom_signals_from_home_score_and_counts():
    """phantom(미확증 유령 신호)은 device 목록·보호자 화면과 동일하게 홈 점수·위험 카운트에서 제외돼야
    한다. 과거엔 유령(예: NAT 오탐 telnet 포트)이 평균을 끌어내리거나 caution(device_scores yellow,
    FCM 알림 사용)에 잡혀 '홈은 주의인데 화면엔 위험 기기 없음' 모순이 났다."""
    green_real = {"device_id": "r", "device_type": "iot", "open_ports": [], "encryption": "wpa2",
                  "vulnerabilities": [], "risk_signals": []}
    phantom = {"device_id": "p", "device_type": "iot", "open_ports": [23], "encryption": "unknown",
               "vulnerabilities": [], "risk_signals": ["phantom_signal"], "is_phantom": True}
    only_real = summarize_home_security([green_real])
    with_phantom = summarize_home_security([green_real, phantom])
    # phantom 이 점수를 끌어내리지 않는다(실기기만 반영).
    assert with_phantom["score"] == only_real["score"]
    assert with_phantom["risk_level"] == only_real["risk_level"]
    # device_scores(=FCM caution 산정 소스)에도 phantom 미포함.
    assert len(with_phantom["device_scores"]) == 1
    assert all(item["device_id"] != "p" for item in with_phantom["device_scores"])
    # 전부 phantom 이면 '점검 전'(unknown) — 유령만으로 위험/안전을 단정하지 않는다.
    assert summarize_home_security([phantom])["risk_level"] == "unknown"


def test_score_device_robust_to_malformed_device_data():
    """한 기기의 이상 데이터(None 필드, None 취약점 항목, 누락 필드)로 score_device 가 터지면
    /score·집계·보호자 알림 전체가 실패한다. None-safe + 잘못된 취약점 항목 skip 으로 견고화하되,
    유효한 취약점은 계속 처리(critical 누락 금지)해야 한다.
    """
    bad = [
        {"device_id": "a", "device_type": "camera", "open_ports": None, "vulnerabilities": [], "risk_signals": []},
        {"device_id": "b", "device_type": "router", "open_ports": [80], "vulnerabilities": [], "risk_signals": None},
        {"device_id": "c", "device_type": "camera", "open_ports": [80], "vulnerabilities": None, "risk_signals": []},
        {"device_id": "e"},  # 필드 거의 없음
        {"device_id": "g", "device_type": None, "open_ports": [80], "vulnerabilities": [None], "risk_signals": [None]},
    ]
    for device in bad:
        result = score_device(device)  # 크래시하면 실패
        assert "risk_level" in result and "score" in result

    # 집계도 한 기기 이상 데이터에 죽지 않는다
    summary = summarize_home_security(bad)
    assert summary["score"] is not None
    assert len(summary["device_scores"]) == len(bad)

    # 기능 유지: None 항목이 섞인 취약점 리스트에서도 유효한 critical 은 잡혀 red 가 된다
    mixed = score_device({
        "device_id": "d", "device_type": "camera", "open_ports": [80],
        "vulnerabilities": [None, {"cve_id": "X", "severity": "critical", "cvss": 9.8}],
        "risk_signals": ["camera_candidate"],
    })
    assert mixed["risk_level"] == "red"

def test_ml_can_never_downgrade_risk_only_weight_toward_danger(monkeypatch):
    """안전 속성(거짓 안심 차단): ML 이 활성이어도 critical/red 기기를 green/안전으로 내릴 수 없고,
    green/yellow 기기는 위험 쪽으로만 가중한다. 미래 ML 활성(RPi) 환경에서 hybrid_scoring 변경이
    이 속성을 깨면(ML 이 점수를 개선하면) 거짓 안심이 생기므로 회귀로 고정한다.
    """
    from home_guardian_ml import hybrid_scoring
    from home_guardian_ml.ml_predictor import MlPrediction

    # ML 이 강한 위험 신호(0.95)를 준다고 모킹
    def fake_predict(device):
        return MlPrediction(model="lightweight:stacking", attack_probability=0.95, metrics={})

    monkeypatch.setattr(hybrid_scoring, "predict_attack_probability", fake_predict)

    # critical CVE 기기(rule-based red) → ML 이 위험이라 해도 여전히 red, 점수 안 오름
    red_dev = {"device_id": "r", "device_type": "camera", "open_ports": [80, 554],
               "vulnerabilities": [{"cve_id": "X", "severity": "critical", "cvss": 9.8}],
               "risk_signals": ["camera_candidate"], "encryption": "unknown"}
    red = hybrid_scoring.score_device_hybrid(red_dev)
    assert red["risk_level"] == "red"
    assert red["score"] <= 59  # critical 게이트 유지, ML 이 끌어올리지 못함

    # 깨끗한 green 기기 → ML 이 위험이라 보면 위험 쪽으로 내려갈 뿐(절대 더 안전해지지 않음)
    green_dev = {"device_id": "g", "device_type": "computer", "open_ports": [],
                 "vulnerabilities": [], "risk_signals": [], "encryption": "unknown"}
    base_score = 100
    blended = hybrid_scoring.score_device_hybrid(green_dev)
    assert blended["score"] <= base_score  # ML 은 점수를 올리지 못한다(위험쪽만)

def test_summarize_isolates_per_device_scoring_failure():
    """한 기기의 이상 데이터로 score_device 가 터져도 summarize_home_security(전체 /score·보호자 알림)
    가 죽지 않는다. 실패 기기는 '점검 전'(unknown, score=None)으로 폴백돼 목록엔 남고, 평균/위험 카운트
    에서는 제외된다(거짓 안심/경보 아님). 정상 기기의 critical 위험은 그대로 집계에 반영된다.
    """
    class _Bad(dict):
        def get(self, key, default=None):
            if key == "risk_signals":
                raise RuntimeError("강제 크래시")
            return super().get(key, default)

    devices = [
        {"device_id": "a", "device_type": "camera", "open_ports": [80, 554],
         "vulnerabilities": [{"cve_id": "X", "severity": "critical", "cvss": 9.8}],
         "risk_signals": ["camera_candidate"], "encryption": "unknown"},
        _Bad({"device_id": "bad", "name": "이상한 기기"}),
        {"device_id": "c", "device_type": "computer", "open_ports": [], "vulnerabilities": [],
         "risk_signals": [], "encryption": "unknown"},
    ]
    summary = summarize_home_security(devices)  # 크래시하면 실패
    assert summary["score"] is not None  # 평균이 None 에 안 터짐
    assert len(summary["device_scores"]) == 3  # 실패 기기도 목록에 남음
    assert summary["risk_level"] == "red"  # 정상 critical 기기 위험 반영
    bad = next(d for d in summary["device_scores"] if d["device_id"] == "bad")
    assert bad["risk_level"] == "unknown" and bad["score"] is None  # 폴백(거짓 안심/경보 아님)

