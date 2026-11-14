"""학습용 데이터셋 로더.

세 데이터셋(CIC-IoT-2023, UNSW-NB15, ToN-IoT)에서 공격/정상 분류 학습용
DataFrame 을 만든다. 각 데이터셋의 컬럼 구조가 달라서 통합 피처 집합으로
정규화한 뒤 0/1 label 만 사용한다.

- 출력: pandas.DataFrame, 모든 피처 numeric, 마지막 컬럼 ``label`` (0=정상, 1=공격)
- 결측치는 0으로 채우고, 카테고리 컬럼은 빈도 기반 정수 인코딩한다. 현재 로더는
  분할 전 전체 입력 DataFrame의 빈도를 사용하므로 이 지표는 전처리 누수 가능성이 있는
  내부 holdout 결과다. 출판용 평가는 train-only 전처리 파이프라인으로 다시 수행해야 한다.
- CIC-IoT-2023은 13GB 단일 CSV를 앞쪽 청크부터 읽고 목표 행 수에 도달하면 멈춘다.
  현재 100,000행 실행은 첫 100,000행만 사용하며 전체 파일의 stratified 표본이 아니다.
- ToN-IoT 로더는 `type`만 제거하고 `src_ip`·`dst_ip`를 빈도 인코딩해 유지한다. IP가
  공격 라벨의 proxy가 될 수 있으므로 현재 높은 F1을 네트워크 일반화 성능으로 해석하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

DATASET_ROOT = Path(__file__).resolve().parents[3] / "datasets"


@dataclass
class DatasetSpec:
    name: str
    description: str
    path: Path

    def exists(self) -> bool:
        return self.path.exists()


SPECS = {
    "unsw-nb15": DatasetSpec(
        name="UNSW-NB15",
        description="Cyber Range, 2015 (현재 로컬 configured CSV 82,332행, label 0/1 + attack_cat)",
        path=DATASET_ROOT / "UNSW-NB15" / "raw" / "UNSW_NB15_training-set.csv",
    ),
    "ton-iot": DatasetSpec(
        name="ToN-IoT",
        description="UNSW Canberra, 2020 (network log, label + type)",
        path=DATASET_ROOT / "ToN-IoT" / "raw" / "train_test_network.csv",
    ),
    "cic-iot-2023": DatasetSpec(
        name="CIC-IoT-2023",
        description="CIC, 2023 (single 13GB CSV, 47 features, label)",
        path=DATASET_ROOT / "CIC-IoT-2023" / "raw" / "ciciot23.csv",
    ),
}


def _frequency_encode(series: pd.Series) -> pd.Series:
    """현재 입력 전체의 빈도를 인코딩한다.

    이 함수 자체는 train/test 경계를 알지 못한다. 현재 학습 경로처럼 분할 전에 호출하면
    테스트 분포가 인코딩 값에 반영되므로 출판용 평가는 train에서 fit한 encoder가 필요하다.
    """
    text = series.astype(str)
    counts = text.value_counts(dropna=False)
    return text.map(counts).fillna(0).astype(np.int64)


def _to_numeric(df: pd.DataFrame) -> pd.DataFrame:
    """모든 비-label 컬럼을 float 로 강제 변환.

    먼저 ``pd.to_numeric`` 으로 숫자 변환을 시도하고, 실패한 행이 하나라도 있으면
    해당 컬럼을 빈도(frequency) 기반 정수로 인코딩한다. UNSW-NB15 의 ``proto`` (udp/tcp),
    ToN-IoT의 ``src_ip`` 같은 식별자 컬럼도 수치화되지만, 이는 정보 누수나 일반화에
    안전하다는 뜻이 아니다. 현재 함수는 입력 전체의 빈도를 사용한다.
    """
    out = df.copy()
    for column in out.columns:
        if column == "label":
            continue
        series = out[column]
        numeric = pd.to_numeric(series, errors="coerce")
        if numeric.notna().all():
            out[column] = numeric
        else:
            out[column] = _frequency_encode(series)
    cleaned = out.replace([np.inf, -np.inf], np.nan).fillna(0)
    label = cleaned.get("label")
    feature_columns = [col for col in cleaned.columns if col != "label"]
    cleaned[feature_columns] = cleaned[feature_columns].astype(np.float64, copy=False)
    if label is not None:
        cleaned["label"] = label
    return cleaned


def load_unsw_nb15(path: Path, max_rows: int | None = None, random_state: int = 7) -> pd.DataFrame:
    """현재 지정 CSV 하나를 읽는다.

    공식 UNSW-NB15의 별도 held-out partition을 평가에 사용하는 로더가 아니며, 호출부는
    이 반환값을 다시 행 단위로 분할한다.
    """
    df = pd.read_csv(path)
    df.columns = [str(name).strip() for name in df.columns]
    # 잘 알려진 메타 컬럼 제거. attack_cat 은 label 과 강하게 상관되어 leakage.
    drop = [column for column in ["id", "attack_cat"] if column in df.columns]
    df = df.drop(columns=drop)
    if "label" not in df.columns:
        raise ValueError("UNSW-NB15 dataset must contain a 'label' column")
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=random_state)
    df = _to_numeric(df)
    df["label"] = df["label"].astype(np.int64)
    return df


def load_ton_iot(path: Path, max_rows: int | None = None, random_state: int = 7) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.columns = [str(name).strip() for name in df.columns]
    # 'type'은 attack_cat과 동급이라 제거한다. 다만 src_ip/dst_ip는 현재 유지되어
    # frequency encoding되므로 IP가 라벨 proxy가 되는 누수 위험은 남아 있다.
    drop = [column for column in ["type"] if column in df.columns]
    df = df.drop(columns=drop)
    if "label" not in df.columns:
        raise ValueError("ToN-IoT dataset must contain a 'label' column")
    if max_rows is not None and len(df) > max_rows:
        df = df.sample(n=max_rows, random_state=random_state)
    df = _to_numeric(df)
    df["label"] = df["label"].astype(np.int64)
    return df


def load_cic_iot(path: Path, max_rows: int = 200_000, chunksize: int = 100_000, random_state: int = 7) -> pd.DataFrame:
    """13GB CSV를 앞쪽 청크부터 읽어 행을 표본화한다.

    label 컬럼이 공격 종류 텍스트('BenignTraffic' 외 다수 공격명)라 0/1 로 변환한다.
    파일 전체를 순회한 stratified sampling이 아니다. 특히 ``max_rows=100_000``과 기본
    ``chunksize=100_000`` 조합은 첫 청크에서 목표량을 채우고 즉시 중단한다.
    """
    rows_per_chunk = max(1, max_rows // max(1, max_rows // chunksize))
    samples: list[pd.DataFrame] = []
    rng = np.random.default_rng(random_state)
    collected = 0
    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        chunk.columns = [str(name).strip() for name in chunk.columns]
        if "label" not in chunk.columns:
            continue
        take = min(rows_per_chunk, len(chunk), max_rows - collected)
        if take <= 0:
            break
        idx = rng.choice(len(chunk), size=take, replace=False)
        samples.append(chunk.iloc[idx].reset_index(drop=True))
        collected += take
        if collected >= max_rows:
            break
    if not samples:
        raise RuntimeError(f"Could not read any rows from {path}")
    df = pd.concat(samples, ignore_index=True)
    # label 정리: 'BenignTraffic' 또는 'Benign' 외에는 모두 공격(1).
    raw_label = df["label"].astype(str).str.strip().str.lower()
    df["label"] = np.where(raw_label.isin(["benigntraffic", "benign", "0", "normal"]), 0, 1).astype(np.int64)
    df = _to_numeric(df)
    df["label"] = df["label"].astype(np.int64)
    return df


def load_dataset(key: str, max_rows: int | None) -> pd.DataFrame:
    spec = SPECS[key]
    if not spec.exists():
        raise FileNotFoundError(f"{spec.name} 데이터셋을 찾을 수 없습니다: {spec.path}")
    if key == "unsw-nb15":
        return load_unsw_nb15(spec.path, max_rows=max_rows)
    if key == "ton-iot":
        return load_ton_iot(spec.path, max_rows=max_rows)
    if key == "cic-iot-2023":
        return load_cic_iot(spec.path, max_rows=max_rows or 200_000)
    raise KeyError(f"Unknown dataset key: {key}")


def iter_available_datasets() -> Iterable[tuple[str, DatasetSpec]]:
    for key, spec in SPECS.items():
        if spec.exists():
            yield key, spec
