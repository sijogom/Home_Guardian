"""Random Forest + Isolation Forest + Stacking 학습 + F-Score 측정.

이 스크립트는 ``datasets.load_dataset`` 으로 받은 DataFrame 을 학습/검증으로 split 한 뒤
다음 세 모델을 학습/평가하고 ``ml/training/output/`` 에 결과를 남긴다.

- RandomForestClassifier (지도 학습 baseline)
- IsolationForest (비지도 이상치 탐지, 평가 시 -1=공격, 1=정상 매핑)
- StackingClassifier (RF + GradientBoosting + ExtraTrees → LogisticRegression meta)

출력:
- ``output/{dataset}/{model}.joblib`` — 모델 파일
- ``output/{dataset}/metrics.json`` — F1, precision, recall, accuracy 등
- ``output/summary.json`` — 전체 데이터셋 결과 요약
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
    IsolationForest,
    RandomForestClassifier,
    StackingClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .datasets import iter_available_datasets, load_dataset

OUTPUT_ROOT = Path(__file__).resolve().parent / "output"


@dataclass
class ModelMetrics:
    model: str
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    confusion_matrix: list[list[int]]
    fit_seconds: float
    predict_seconds: float


def _safe_roc_auc(y_true: np.ndarray, y_score: np.ndarray | None) -> float | None:
    if y_score is None:
        return None
    if len(np.unique(y_true)) < 2:
        return None
    try:
        return float(roc_auc_score(y_true, y_score))
    except ValueError:
        return None


def _metrics(name: str, y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None, fit_seconds: float, predict_seconds: float) -> ModelMetrics:
    return ModelMetrics(
        model=name,
        accuracy=float(accuracy_score(y_true, y_pred)),
        precision=float(precision_score(y_true, y_pred, zero_division=0)),
        recall=float(recall_score(y_true, y_pred, zero_division=0)),
        f1=float(f1_score(y_true, y_pred, zero_division=0)),
        roc_auc=_safe_roc_auc(y_true, y_score),
        confusion_matrix=confusion_matrix(y_true, y_pred).astype(int).tolist(),
        fit_seconds=round(fit_seconds, 3),
        predict_seconds=round(predict_seconds, 3),
    )


def train_random_forest(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray) -> tuple[RandomForestClassifier, ModelMetrics]:
    start = time.perf_counter()
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        random_state=7,
        class_weight="balanced_subsample",
    )
    model.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    pred = model.predict(x_test)
    score = model.predict_proba(x_test)[:, 1]
    predict_seconds = time.perf_counter() - start

    return model, _metrics("random_forest", y_test, pred, score, fit_seconds, predict_seconds)


def train_isolation_forest(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray) -> tuple[IsolationForest, ModelMetrics]:
    # IsolationForest 는 비지도. 정상(0)만으로 학습한 뒤 공격을 이상치로 잡는다.
    normal_mask = y_train == 0
    if normal_mask.sum() < 100:
        # 정상 샘플이 너무 적으면 전체로 학습.
        train_features = x_train
    else:
        train_features = x_train[normal_mask]
    start = time.perf_counter()
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=7,
        n_jobs=-1,
    )
    model.fit(train_features)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    raw_pred = model.predict(x_test)            # 1=정상, -1=이상치
    decision = -model.score_samples(x_test)     # 클수록 더 이상치 → 공격 확률 점수
    pred = (raw_pred == -1).astype(np.int64)
    predict_seconds = time.perf_counter() - start

    return model, _metrics("isolation_forest", y_test, pred, decision, fit_seconds, predict_seconds)


def train_stacking(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray) -> tuple[StackingClassifier, ModelMetrics]:
    estimators = [
        ("rf", RandomForestClassifier(n_estimators=120, n_jobs=-1, random_state=7, class_weight="balanced_subsample")),
        ("gb", GradientBoostingClassifier(n_estimators=100, random_state=7)),
        ("et", ExtraTreesClassifier(n_estimators=120, n_jobs=-1, random_state=7, class_weight="balanced")),
    ]
    final_estimator = LogisticRegression(max_iter=2000, n_jobs=-1)
    model = StackingClassifier(estimators=estimators, final_estimator=final_estimator, n_jobs=-1, passthrough=False)
    start = time.perf_counter()
    model.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    pred = model.predict(x_test)
    if hasattr(model, "predict_proba"):
        score = model.predict_proba(x_test)[:, 1]
    else:
        score = None
    predict_seconds = time.perf_counter() - start
    return model, _metrics("stacking", y_test, pred, score, fit_seconds, predict_seconds)


def train_boosting_stacking(
    x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, y_test: np.ndarray
) -> tuple[StackingClassifier, ModelMetrics]:
    """Home Guardian 차별 base learner 구성: XGBoost + LightGBM + CatBoost → LogisticRegression meta.

    사용자 본인 기존 특허(논문 1: RF+IF+Stacking(RF+GB+ET) / 논문 2: CNN+BiLSTM+Attention) 와
    base learner 구성이 완전히 달라 특허 신규성 확보 + 2025/2026 gradient boosting 추세 반영.
    """
    from xgboost import XGBClassifier  # type: ignore[import-not-found]
    from lightgbm import LGBMClassifier  # type: ignore[import-not-found]
    from catboost import CatBoostClassifier  # type: ignore[import-not-found]

    estimators = [
        (
            "xgb",
            XGBClassifier(
                n_estimators=300,
                max_depth=6,
                learning_rate=0.1,
                n_jobs=-1,
                random_state=7,
                eval_metric="logloss",
                tree_method="hist",
            ),
        ),
        (
            "lgbm",
            LGBMClassifier(
                n_estimators=300,
                max_depth=-1,
                learning_rate=0.1,
                n_jobs=-1,
                random_state=7,
                class_weight="balanced",
                verbose=-1,
            ),
        ),
        (
            "cat",
            CatBoostClassifier(
                iterations=300,
                depth=6,
                learning_rate=0.1,
                random_seed=7,
                auto_class_weights="Balanced",
                verbose=False,
                allow_writing_files=False,
            ),
        ),
    ]
    final_estimator = LogisticRegression(max_iter=2000)
    model = StackingClassifier(
        estimators=estimators,
        final_estimator=final_estimator,
        n_jobs=1,  # gradient boosting 들이 내부적으로 멀티스레드라 stacking 외부 n_jobs=1 안전
        passthrough=False,
    )
    start = time.perf_counter()
    model.fit(x_train, y_train)
    fit_seconds = time.perf_counter() - start

    start = time.perf_counter()
    pred = model.predict(x_test)
    score = model.predict_proba(x_test)[:, 1] if hasattr(model, "predict_proba") else None
    predict_seconds = time.perf_counter() - start
    return model, _metrics("boosting_stacking", y_test, pred, score, fit_seconds, predict_seconds)


def run_dataset(key: str, max_rows: int | None, output_root: Path) -> dict:
    print(f"[{key}] 데이터 로드 (max_rows={max_rows})", flush=True)
    df = load_dataset(key, max_rows=max_rows)
    print(f"[{key}] shape={df.shape}, attack_ratio={float(df['label'].mean()):.3f}", flush=True)

    y = df["label"].astype(np.int64).to_numpy()
    x = df.drop(columns=["label"]).to_numpy(dtype=np.float64, na_value=0.0)

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=7, stratify=y)
    print(f"[{key}] train={x_train.shape}, test={x_test.shape}", flush=True)

    dataset_output = output_root / key
    dataset_output.mkdir(parents=True, exist_ok=True)
    feature_columns = [col for col in df.columns if col != "label"]
    (dataset_output / "features.json").write_text(json.dumps(feature_columns, ensure_ascii=False, indent=2), encoding="utf-8")

    metrics_list: list[ModelMetrics] = []

    rf_model, rf_metrics = train_random_forest(x_train, y_train, x_test, y_test)
    joblib.dump(rf_model, dataset_output / "random_forest.joblib")
    metrics_list.append(rf_metrics)
    print(f"  random_forest      F1={rf_metrics.f1:.4f}, recall={rf_metrics.recall:.4f}, precision={rf_metrics.precision:.4f}", flush=True)

    if_model, if_metrics = train_isolation_forest(x_train, y_train, x_test, y_test)
    joblib.dump(if_model, dataset_output / "isolation_forest.joblib")
    metrics_list.append(if_metrics)
    print(f"  isolation_forest   F1={if_metrics.f1:.4f}, recall={if_metrics.recall:.4f}, precision={if_metrics.precision:.4f}", flush=True)

    stack_model, stack_metrics = train_stacking(x_train, y_train, x_test, y_test)
    joblib.dump(stack_model, dataset_output / "stacking.joblib")
    metrics_list.append(stack_metrics)
    print(f"  stacking           F1={stack_metrics.f1:.4f}, recall={stack_metrics.recall:.4f}, precision={stack_metrics.precision:.4f}", flush=True)

    # Home Guardian 차별 모델 (사용자 본인 특허 base learner 와 비충돌)
    try:
        boost_model, boost_metrics = train_boosting_stacking(x_train, y_train, x_test, y_test)
        joblib.dump(boost_model, dataset_output / "boosting_stacking.joblib")
        metrics_list.append(boost_metrics)
        print(
            f"  boosting_stacking  F1={boost_metrics.f1:.4f}, recall={boost_metrics.recall:.4f}, precision={boost_metrics.precision:.4f}",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 - 의존성 미설치 환경 등은 학습 자체를 막지 않는다
        print(f"  boosting_stacking 학습 실패: {exc}", flush=True)

    dataset_metrics = {
        "dataset": key,
        "rows_loaded": int(df.shape[0]),
        "feature_count": int(x.shape[1]),
        "attack_ratio_train": float(y_train.mean()),
        "attack_ratio_test": float(y_test.mean()),
        "models": [asdict(metric) for metric in metrics_list],
    }
    (dataset_output / "metrics.json").write_text(json.dumps(dataset_metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    return dataset_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Home Guardian ML 학습 (RF + IF + Stacking)")
    parser.add_argument(
        "--datasets",
        nargs="*",
        default=None,
        help="학습할 데이터셋 키 (unsw-nb15 / ton-iot / cic-iot-2023). 비우면 사용 가능한 데이터셋 전부.",
    )
    parser.add_argument("--max-rows", type=int, default=200_000, help="각 데이터셋에서 사용할 최대 행 수")
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT, help="결과 저장 폴더")
    args = parser.parse_args()

    output_root = args.output_root.resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    if args.datasets:
        targets = [(key, None) for key in args.datasets]
    else:
        targets = [(key, None) for key, _ in iter_available_datasets()]

    if not targets:
        raise SystemExit("학습할 데이터셋을 찾지 못했습니다. datasets/ 폴더를 확인해 주세요.")

    # 기존 summary 와 merge: 다른 데이터셋의 이전 결과를 덮어쓰지 않는다.
    summary_path = output_root / "summary.json"
    existing: dict[str, dict] = {}
    if summary_path.exists():
        try:
            for item in json.loads(summary_path.read_text(encoding="utf-8")):
                key = item.get("dataset")
                if key:
                    existing[key] = item
        except Exception:  # noqa: BLE001
            existing = {}

    for key, _ in targets:
        try:
            existing[key] = run_dataset(key, max_rows=args.max_rows, output_root=output_root)
        except Exception as exc:  # noqa: BLE001 — 학습 실패는 다음 데이터셋으로 넘어가야 한다.
            print(f"[{key}] 학습 실패: {exc}", flush=True)
            existing[key] = {"dataset": key, "error": str(exc)}

    summary = list(existing.values())
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[완료] {summary_path} 에 학습 결과를 저장했습니다.", flush=True)


if __name__ == "__main__":
    main()
