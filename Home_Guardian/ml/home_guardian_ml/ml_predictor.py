"""학습된 모델을 로드해 기기별 공격 가능성 점수를 제공하는 inference 헬퍼.

훈련 단계는 ``ml/training/train.py`` 가 담당하고, 모델 파일이 없거나 의존성이
없는 환경에서는 None 을 반환해 기존 규칙 기반 점수가 그대로 사용되도록 한다.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_ROOT = PROJECT_ROOT / "ml" / "training" / "output"

_DANGEROUS_PORTS = {21, 22, 23, 53, 80, 139, 443, 445, 554, 1900, 3702, 8080, 8443, 8899, 25565, 32400}


@dataclass
class MlPrediction:
    model: str
    attack_probability: float
    metrics: dict[str, Any]


def _safe_import_joblib():
    try:
        import joblib  # type: ignore[import-not-found]
        return joblib
    except Exception:  # pragma: no cover - 의존성 없는 환경 fallback
        return None


@lru_cache(maxsize=8)
def _load_model(dataset_key: str, model_name: str):
    """Load one immutable inference model per worker process.

    Public projections can rescore hundreds of historical observations during
    database normalization at process start. Reloading the same joblib artifact
    for every row made Raspberry Pi startup exceed the deployment health window.
    Estimators are only read for ``predict_proba`` here, so this cache is safe
    and bounded.
    """
    joblib = _safe_import_joblib()
    if joblib is None:
        return None
    path = MODEL_ROOT / dataset_key / f"{model_name}.joblib"
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:  # pragma: no cover - 모델 파일 손상
        return None


@lru_cache(maxsize=8)
def _load_metrics(dataset_key: str) -> dict[str, Any] | None:
    path = MODEL_ROOT / dataset_key / "metrics.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # pragma: no cover
        return None


def device_feature_vector(device: dict[str, Any]) -> list[float]:
    """학습 피처와 100% 일치시키지 않고도 ML 신호로 쓸 수 있는 압축 피처.

    실제 모델이 학습된 데이터셋의 피처와 다르더라도, 의미 있는 신호를 만들기 위해
    공통 패턴(열린 포트 수, 위험 포트 노출, 위험 신호 수)을 추출한다. 정확한 학습 피처
    매칭이 필요한 경우는 device_fingerprint_vector 를 직접 모델에 넣어야 한다.
    """
    open_ports = list(device.get("open_ports") or [])
    risk_signals = list(device.get("risk_signals") or [])
    services = list(device.get("services") or [])
    dangerous = [port for port in open_ports if port in _DANGEROUS_PORTS]
    fingerprint = [
        float(len(open_ports)),
        float(len(dangerous)),
        float(len(risk_signals)),
        float(len(services)),
        float(1 if device.get("default_credentials") else 0),
        float(1 if any(port in (23, 22) for port in open_ports) else 0),
        float(1 if any(port in (554, 3702) for port in open_ports) else 0),
        float(1 if any(port in (1900, 8899) for port in open_ports) else 0),
    ]
    return fingerprint


def predict_attack_probability(device: dict[str, Any]) -> MlPrediction | None:
    """학습된 모델이 있으면 공격 확률 추정, 없으면 None.

    인퍼런스 우선순위:
    1. ``lightweight`` (공개 트래픽 열을 LAN 스캔의 8개 신호에 대응시킨 proxy 피처)
       — 모바일 스캔 결과에 즉시 사용할 수 있지만 현장 공격 분류 정확도를 뜻하지 않음
    2. 풀 트래픽 모델(42~46피처) — feature 차원이 맞을 때만 사용 (e.g. RPi 트래픽 캡처)

    풀 트래픽 모델은 학술 metrics 와 향후 트래픽 캡처 확장 트랙용이라 차원 미스매치 시
    조용히 폴백한다.
    """
    # 빈/무신호 device(예: API 에 빈 객체 전송)는 all-zeros 벡터가 되어 인공적으로 낮은 공격
    # 확률이 나오므로, ML 을 쓰지 않고 규칙 기반(None 반환)으로 폴백한다.
    if not isinstance(device, dict) or not (
        device.get("open_ports") or device.get("risk_signals") or device.get("services")
    ):
        return None
    vector = device_feature_vector(device)

    # 1) lightweight 8피처 모델 우선. Stacking 앙상블이 있으면 그쪽 먼저 (개요서 명시 모델).
    lightweight_metrics = _load_metrics("lightweight")
    if lightweight_metrics is not None:
        for model_name in ("stacking", "random_forest"):
            model = _load_model("lightweight", model_name)
            if model is None:
                continue
            expected = getattr(model, "n_features_in_", None)
            if expected is not None and len(vector) != expected:
                continue
            try:
                probability = float(model.predict_proba([vector])[0][1])
            except Exception:  # pragma: no cover
                continue
            return MlPrediction(
                model=f"lightweight:{model_name}",
                attack_probability=probability,
                metrics=lightweight_metrics,
            )

    # 2) 풀 트래픽 모델 폴백 (피처 차원이 맞을 때만)
    metrics = _load_metrics("unsw-nb15") or _load_metrics("ton-iot") or _load_metrics("cic-iot-2023")
    if metrics is None:
        return None
    dataset_key = metrics.get("dataset") or "unsw-nb15"
    model = _load_model(dataset_key, "random_forest")
    if model is None:
        return None
    expected = getattr(model, "n_features_in_", None)
    if expected is not None and len(vector) != expected:
        return None
    try:
        probability = float(model.predict_proba([vector])[0][1])
    except Exception:  # pragma: no cover
        return None
    return MlPrediction(
        model=f"{dataset_key}:random_forest",
        attack_probability=probability,
        metrics=metrics,
    )
