"""규칙 기반 점수 + ML 모델 결합 헬퍼.

학습된 모델이 있으면 ML 공격 확률을 ``score_device`` 결과에 가중 평균으로 반영한다.
모델이 없으면 기존 규칙 점수를 그대로 사용해 회귀를 만들지 않는다.
"""

from __future__ import annotations

from typing import Any

from .ml_predictor import MlPrediction, predict_attack_probability
from .scoring import risk_level_for_score, score_device


def score_device_hybrid(device: dict[str, Any]) -> dict[str, Any]:
    base = score_device(device)
    # 자기 자신은 ML 위험도 보정에서 제외. score_device 가 이미 self 표시함.
    if base.get("is_self"):
        base["ml_attack_probability"] = None
        base["ml_model"] = None
        return base
    prediction: MlPrediction | None = predict_attack_probability(device)
    if prediction is None:
        base["ml_attack_probability"] = None
        base["ml_model"] = None
        return base

    # ML 결과는 보수적으로 적용:
    # - 규칙 기반이 이미 red(위험) 이면 ML 가중으로 점수를 올리지 않음 (false negative 방지)
    # - 규칙 기반이 green/yellow 인데 ML 이 강한 위험 신호(≥0.5) 를 보면 위험 쪽으로 가중
    base = dict(base)
    base["ml_attack_probability"] = round(prediction.attack_probability, 4)
    base["ml_model"] = prediction.model

    if base.get("risk_level") == "red":
        # 이미 위험 — 규칙 기반 결과 유지
        if prediction.attack_probability >= 0.5 and "ML 모델도 이상 신호로 판단했어요." not in base["reasons"]:
            base["reasons"].append("ML 모델도 이상 신호로 판단했어요.")
        return base

    if prediction.attack_probability < 0.5:
        # ML 이 안전 쪽으로 봤으면 규칙 기반 결과 유지
        return base

    # ML 이 위험 쪽 → 점수 일부 가중 (85:15)
    ml_risk = int(round(prediction.attack_probability * 100))
    blended = int(round(base["score"] * 0.85 + (100 - ml_risk) * 0.15))
    blended_level = risk_level_for_score(blended)
    base["score"] = blended
    base["risk_level"] = blended_level
    if "ML 모델이 이상 신호로 판단했어요." not in base["reasons"]:
        base["reasons"].append("ML 모델이 이상 신호로 판단했어요.")
    return base


def ml_model_metrics() -> dict[str, Any] | None:
    """학습된 모델 metrics.json 을 우선순위 순서로 반환. UI/문서 노출용.

    - ``inference``: 실제 device 점수에 사용되는 lightweight 8피처 모델 (없으면 null)
    - ``traffic_datasets``: 풀 피처(42~46) 트래픽 모델 metrics 목록. 학술 성과/향후 트래픽
      캡처 확장 트랙용. 현재 인퍼런스에는 사용되지 않음을 명시.
    - ``primary``: 클라이언트가 한 데이터셋만 표시할 때 우선 사용할 항목 (inference 우선,
      없으면 traffic 첫 번째).
    """
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "ml" / "training" / "output"
    traffic_summaries: list[dict[str, Any]] = []
    for dataset in ("unsw-nb15", "ton-iot", "cic-iot-2023"):
        metrics_path = root / dataset / "metrics.json"
        if metrics_path.exists():
            try:
                traffic_summaries.append(json.loads(metrics_path.read_text(encoding="utf-8")))
            except Exception:  # pragma: no cover
                continue

    inference_summary: dict[str, Any] | None = None
    inference_path = root / "lightweight" / "metrics.json"
    if inference_path.exists():
        try:
            inference_summary = json.loads(inference_path.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover
            inference_summary = None

    if not traffic_summaries and inference_summary is None:
        return None

    primary = inference_summary or (traffic_summaries[0] if traffic_summaries else None)
    return {
        "inference": inference_summary,
        "traffic_datasets": traffic_summaries,
        "primary": primary,
        # 기존 호환: 클라이언트가 datasets 필드를 쓰던 경우를 위해 통합 목록도 제공.
        "datasets": ([inference_summary] if inference_summary else []) + traffic_summaries,
    }
