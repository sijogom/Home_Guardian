from __future__ import annotations

from app.services.device_presentation import public_device_id
from app.storage.scoring_helpers import (
    public_score_status,
    scoring_with_cve,
    summarize_public_security,
    visible_identity_findings,
)
from home_guardian_ml import hybrid_scoring
from home_guardian_ml.ml_predictor import MlPrediction
from home_guardian_ml.scoring import score_device


def test_visible_identity_findings_keep_typed_rows_but_not_transport_only_rows():
    transport_only = {
        "device_id": "transport-only",
        "detected": True,
        "display_name": "",
        "observed_service": "tcp-service",
        "observed_service_verified": True,
        "observed_port": 8443,
        "observed_port_verified": True,
        "risk_level": "red",
    }
    typed_camera = {
        "device_id": "typed-camera",
        "detected": True,
        "display_name": "Hikvision 카메라",
        "observed_type": "camera",
        "observed_type_verified": True,
        "observed_manufacturer": "Hikvision",
        "observed_manufacturer_verified": True,
        "observed_service": "onvif",
        "observed_service_verified": True,
        "identity_evidence": ["ONVIF 카메라 종류 단서"],
        "risk_level": "yellow",
    }

    visible = visible_identity_findings([transport_only, typed_camera])

    assert visible == [typed_camera]
    # The repository keeps the private raw finding untouched for research.
    assert transport_only["risk_level"] == "red"


def test_public_security_scores_use_the_same_opaque_id_as_legacy_devices(monkeypatch):
    raw_device_id = "device-fe80::1"
    public_device_id_value = public_device_id(raw_device_id, "home-score-ipv6")
    prediction_calls: list[str] = []

    def predict_as_risky(device):
        prediction_calls.append(str(device.get("device_id")))
        return MlPrediction(model="lightweight:stacking", attack_probability=0.8, metrics={})

    monkeypatch.setattr(hybrid_scoring, "predict_attack_probability", predict_as_risky)
    raw_device = {
        "device_id": raw_device_id,
        "home_id": "home-score-ipv6",
        "device_type": "router",
        "manufacturer": "iptime(EFM)",
        "model": "A3004",
        "identity_status": "resolved",
        "identity_confidence": 0.96,
        "identity_resolver_version": "server-identity-1.0.0",
        "identity_candidates": [
            {
                "label": "ipTIME 공유기 (A3004)",
                "kind": "서버 카탈로그 확정",
                "catalog_id": "iptime-router",
            }
        ],
        "discovery_sources": ["ssdp"],
        "open_ports": [],
        "risk_signals": [],
        "vulnerabilities": [],
        "encryption": "wpa2",
    }
    base = score_device(scoring_with_cve(raw_device))
    assert base["risk_level"] in {"green", "yellow"}
    devices, security = summarize_public_security(
        [
            raw_device,
            {
                **raw_device,
                "device_id": "self-device",
                "risk_signals": ["self_device"],
            },
        ],
        coverage_complete=True,
    )

    expected_hybrid_score = round(base["score"] * 0.85 + (100 - 80) * 0.15)
    public_scores = {score["device_id"]: score for score in security["device_scores"]}

    assert devices[0]["device_id"] == public_device_id_value
    assert public_scores[public_device_id_value]["score"] == expected_hybrid_score
    assert public_scores[public_device_id_value]["ml_attack_probability"] == 0.8
    assert public_scores[public_device_id_value]["ml_model"] == "lightweight:stacking"
    assert security["score"] == expected_hybrid_score
    # Hybrid scorer returns before ML inference for the scanner's own phone,
    # and the aggregate excludes its fixed 100 score.
    assert prediction_calls == [public_device_id_value]
    assert raw_device_id not in str(security)

    # No deployed model is an ordinary rule-score fallback, not an unknown or
    # a second scoring policy.
    monkeypatch.setattr(hybrid_scoring, "predict_attack_probability", lambda _device: None)
    _, fallback = summarize_public_security([raw_device], coverage_complete=True)
    fallback_score = fallback["device_scores"][0]
    assert fallback_score["score"] == base["score"]
    assert fallback_score["risk_level"] == base["risk_level"]
    assert fallback_score["ml_attack_probability"] is None
    assert fallback_score["ml_model"] is None

    # A critical rule gate remains red and its score cannot be lifted by ML in
    # the actual public projection path.
    monkeypatch.setattr(hybrid_scoring, "predict_attack_probability", predict_as_risky)
    critical_device = {
        **raw_device,
        "device_id": "critical-device",
        "vulnerabilities": [{"cve_id": "CVE-TEST-CRITICAL", "severity": "critical", "cvss": 9.8}],
    }
    critical_base = score_device(scoring_with_cve(critical_device))
    _, critical = summarize_public_security([critical_device], coverage_complete=True)
    assert critical_base["risk_level"] == "red"
    assert critical["risk_level"] == "red"
    assert critical["score"] == critical_base["score"]

    # Public device cards receive the same refreshed score as the aggregate.
    # A High CVE must never coexist with a green/safe card.
    high_device = {
        **raw_device,
        "device_id": "high-device",
        "vulnerabilities": [{"cve_id": "CVE-TEST-HIGH", "severity": "high", "cvss": 8.1}],
    }
    high_devices, high_summary = summarize_public_security([high_device], coverage_complete=True)
    assert high_devices[0]["risk_level"] == "red"
    assert high_devices[0]["security_score"] <= 59
    assert high_summary["device_scores"][0]["risk_level"] == "red"

    # Coverage is the only authority that can distinguish edge states. A
    # completed scan with no non-self target remains unscored and explicitly
    # says that there was nothing to evaluate; pre-scan/partial also remain
    # unscored but carry different lifecycle states at the public boundary.
    _, empty_complete = summarize_public_security([], coverage_complete=True)
    _, empty_partial = summarize_public_security([], coverage_complete=False)
    _, empty_pre_scan = summarize_public_security([])
    assert empty_complete["score"] is None and empty_complete["risk_level"] == "unknown"
    assert empty_complete["summary"] == "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."
    assert public_score_status(empty_complete, coverage_complete=True) == "no_targets"
    assert empty_partial["score"] is None and empty_partial["risk_level"] == "unknown"
    assert empty_partial["summary"] == "점검이 일부만 끝나 점수를 확정하지 않았어요. 지금까지 확인된 결과는 보존했어요."
    assert public_score_status(empty_partial, coverage_complete=False) == "held"
    assert empty_pre_scan["score"] is None and empty_pre_scan["risk_level"] == "unknown"
    assert empty_pre_scan["summary"] == "아직 점검 전이에요. 우리 집 Wi-Fi 점검을 시작해 주세요."
    assert public_score_status(empty_pre_scan, coverage_complete=None) == "not_started"

    prediction_calls.clear()
    self_device = {**raw_device, "device_id": "self-device", "risk_signals": ["self_device"]}
    _, self_only = summarize_public_security([self_device], coverage_complete=True)
    assert self_only["score"] is None and self_only["risk_level"] == "unknown"
    assert public_score_status(self_only, coverage_complete=True) == "no_targets"
    assert prediction_calls == []

    # A complete scan with real targets must never be final+null. If every
    # per-device scorer fails, preserve each failure row and fail safe to 0/red.
    def fail_scoring(_device):
        raise RuntimeError("forced scorer failure")

    monkeypatch.setattr(hybrid_scoring, "predict_attack_probability", fail_scoring)
    _, failed_complete = summarize_public_security([raw_device], coverage_complete=True)
    _, failed_partial = summarize_public_security([raw_device], coverage_complete=False)
    assert failed_complete["score"] == 0 and failed_complete["risk_level"] == "red"
    assert failed_complete["device_scores"][0]["score"] is None
    assert failed_complete["device_scores"][0]["risk_level"] == "unknown"
    assert "계산하지 못했어요" in failed_complete["summary"]
    assert public_score_status(failed_complete, coverage_complete=True) == "final"
    assert failed_partial["score"] is None and failed_partial["risk_level"] == "unknown"
    assert failed_partial["summary"] == "점검이 일부만 끝나 점수를 확정하지 않았어요. 지금까지 확인된 결과는 보존했어요."
    assert public_score_status(failed_partial, coverage_complete=False) == "held"
