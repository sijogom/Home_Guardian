"""LAN 스캔 8피처 lightweight 모델 학습.

목적: 풀 트래픽 모델(42~46 피처)은 device_feature_vector(8피처)와 차원이 안 맞아
모바일 LAN 스캔 결과에 직접 인퍼런스로 쓸 수 없다. 이 스크립트는 공개 데이터셋
CIC-IoT-2023 및 UNSW-NB15의 **raw 행**에서 LAN 스캔 신호와 의미상 가까운
8피처를 추출해 RandomForest와 Stacking을 학습한다. 합성 데이터가 아니라 공개
데이터셋 원본 라벨(0=정상, 1=공격)을 사용하지만, 트래픽 컬럼을 LAN 관측으로 바꾼
proxy이므로 실제 가정망 기기 탐지 정확도를 뜻하지 않는다. 저장된 단일 holdout 결과는
RF F1=0.5662, Stacking F1=0.4195이며 `ml_predictor`는 Stacking을 먼저 선택한다.

이 수치는 `random_state=7`의 행 단위 80:20 분할에서 계산한 공격 클래스 binary F1이다.
기기·세션·시간 단위 분리, 반복 seed, 외부 네트워크 검증이 없으므로 설계 목표 달성이나
현장 성능의 근거로 사용하지 않는다.

8피처 (``home_guardian_ml.ml_predictor.device_feature_vector`` 와 1:1 매칭):
0. open_ports_count          — 활성 service flag 합
1. dangerous_ports_count     — {Telnet, SMTP, SSH, IRC, FTP} 합
2. risk_signals_count        — TCP anomaly flag (fin+syn+rst+urg) 정규화 합 + 위험 서비스
3. services_count            — {HTTP, HTTPS, DNS, Telnet, SMTP, SSH, IRC} 합
4. default_credentials_flag  — Telnet 또는 (FTP 의 경우 is_ftp_login)
5. telnet_or_ssh_open        — Telnet 또는 SSH
6. rtsp_or_onvif_open        — IRC (botnet C&C 채널, IoT 카메라 침해 자주 사용) — proxy
7. upnp_or_iot_camera_open   — ARP + DHCP + ICMP 트래픽 — proxy

`IRC→RTSP/ONVIF`, `ARP/DHCP/ICMP→UPnP·카메라`, `FTP/SMTP→기본 인증정보` 매핑은
학습용 근사치일 뿐, 해당 제품·서비스가 실제 관측됐다는 증거로 사용하지 않는다.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    ExtraTreesClassifier,
    GradientBoostingClassifier,
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

from .datasets import SPECS

OUTPUT_DIR = Path(__file__).resolve().parent / "output" / "lightweight"

FEATURE_NAMES = [
    "open_ports_count",
    "dangerous_ports_count",
    "risk_signals_count",
    "services_count",
    "default_credentials",
    "telnet_or_ssh_open",
    "rtsp_or_onvif_open",
    "upnp_or_iot_camera_open",
]


def extract_features_from_cic(df: pd.DataFrame) -> np.ndarray:
    """CIC-IoT-2023 raw 행에서 8피처 derive.

    binary 서비스 플래그(HTTP/HTTPS/DNS/Telnet/SMTP/SSH/IRC) 와 프로토콜 플래그(TCP/UDP/
    ARP/DHCP/ICMP) 가 LAN 스캔 신호와 의미 매핑된다.
    """
    def col(name: str) -> np.ndarray:
        if name not in df.columns:
            return np.zeros(len(df), dtype=np.float64)
        return pd.to_numeric(df[name], errors="coerce").fillna(0).to_numpy(dtype=np.float64)

    http = (col("HTTP") > 0).astype(np.float64)
    https = (col("HTTPS") > 0).astype(np.float64)
    dns = (col("DNS") > 0).astype(np.float64)
    telnet = (col("Telnet") > 0).astype(np.float64)
    smtp = (col("SMTP") > 0).astype(np.float64)
    ssh = (col("SSH") > 0).astype(np.float64)
    irc = (col("IRC") > 0).astype(np.float64)
    tcp = (col("TCP") > 0).astype(np.float64)
    udp = (col("UDP") > 0).astype(np.float64)
    arp = (col("ARP") > 0).astype(np.float64)
    dhcp = (col("DHCP") > 0).astype(np.float64)
    icmp = (col("ICMP") > 0).astype(np.float64)

    fin_count = col("fin_count")
    syn_count = col("syn_count")
    rst_count = col("rst_count")
    urg_count = col("urg_count")

    services_count = http + https + dns + telnet + smtp + ssh + irc
    dangerous_ports_count = telnet + smtp + ssh + irc
    # TCP 이상 flag 가 비정상적으로 많거나 위험 서비스가 응답 → risk signal
    anomaly_flag_excess = (
        (fin_count > fin_count.mean() + fin_count.std()).astype(np.float64)
        + (syn_count > syn_count.mean() + syn_count.std()).astype(np.float64)
        + (rst_count > rst_count.mean() + rst_count.std()).astype(np.float64)
        + (urg_count > 0).astype(np.float64)
    )
    risk_signals_count = anomaly_flag_excess + dangerous_ports_count

    open_ports_count = (services_count + tcp + udp).clip(0, 12)
    default_credentials = ((telnet + smtp) > 0).astype(np.float64)
    telnet_or_ssh_open = ((telnet + ssh) > 0).astype(np.float64)
    rtsp_or_onvif_open = irc  # proxy (IRC = botnet C&C, IoT 카메라 침해 흔한 채널)
    upnp_or_iot_camera_open = ((arp + dhcp + icmp) > 0).astype(np.float64)

    features = np.column_stack(
        [
            open_ports_count,
            dangerous_ports_count,
            risk_signals_count,
            services_count,
            default_credentials,
            telnet_or_ssh_open,
            rtsp_or_onvif_open,
            upnp_or_iot_camera_open,
        ]
    )
    return features


# CIC-IoT-2023 공격 카테고리 중 LAN 스캔 신호와 관련성이 있다고 가정한 proxy 부류.
# 이 선택 자체가 실제 LAN 스캔 검출 가능성을 입증하지는 않는다. DDoS/DoS/Mirai 같은
# 트래픽 폭주는 현재 피처와 직접 대응하지 않아 제외한다.
LAN_DETECTABLE_ATTACK_LABELS = {
    "recon-hostdiscovery",
    "recon-osscan",
    "recon-portscan",
    "recon-pingsweep",
    "vulnerabilityscan",
    "mitm-arpspoofing",
    "dns_spoofing",
    "dictionarybrutforce",
    "dictionarybruteforce",
    "backdoor_malware",
    "browserhijacking",
    "sqlinjection",
    "commandinjection",
    "xss",
    "uploading_attack",
}

BENIGN_LABELS = {"benigntraffic", "benign", "0", "normal"}


def load_cic_iot_lan_subset(path: Path, target_per_class: int = 15_000, chunksize: int = 100_000, random_state: int = 7) -> pd.DataFrame:
    """CIC-IoT-2023 에서 LAN 관련 proxy 카테고리를 추출해 정상과 balanced.

    - 정상(BenignTraffic) target_per_class 행
    - LAN 관련 proxy 공격(Recon-*, VulnerabilityScan, MITM-ArpSpoofing, BruteForce, DNS_Spoofing,
      Injection, Backdoor 등) target_per_class 행
    - DDoS/DoS/Mirai 트래픽 폭주는 LAN 스캔에서 검출 불가하므로 제외
    """
    rng = np.random.default_rng(random_state)
    benign_rows: list[pd.DataFrame] = []
    attack_rows: list[pd.DataFrame] = []
    benign_collected = 0
    attack_collected = 0

    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        chunk.columns = [str(name).strip() for name in chunk.columns]
        if "label" not in chunk.columns:
            continue
        raw_label = chunk["label"].astype(str).str.strip().str.lower()
        is_benign = raw_label.isin(BENIGN_LABELS)
        is_lan_attack = raw_label.isin(LAN_DETECTABLE_ATTACK_LABELS)

        benign_chunk = chunk[is_benign]
        attack_chunk = chunk[is_lan_attack]

        if benign_collected < target_per_class and len(benign_chunk) > 0:
            take = min(len(benign_chunk), target_per_class - benign_collected)
            benign_rows.append(benign_chunk.iloc[:take])
            benign_collected += take
        if attack_collected < target_per_class and len(attack_chunk) > 0:
            take = min(len(attack_chunk), target_per_class - attack_collected)
            attack_rows.append(attack_chunk.iloc[:take])
            attack_collected += take
        if benign_collected >= target_per_class and attack_collected >= target_per_class:
            break

    if not benign_rows or not attack_rows:
        raise RuntimeError(f"Could not collect selected LAN-related proxy rows from {path}")
    df = pd.concat(benign_rows + attack_rows, ignore_index=True)
    raw_label = df["label"].astype(str).str.strip().str.lower()
    df["label"] = np.where(raw_label.isin(BENIGN_LABELS), 0, 1).astype(np.int64)
    df = df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    _ = rng  # 명시적 사용 표시
    return df


def extract_features_from_unsw(df: pd.DataFrame) -> np.ndarray:
    """UNSW-NB15 raw 행에서 8피처 derive.

    service 카테고리(ssh/ftp/smtp/snmp/irc/...) 와 proto 카테고리(tcp/udp/icmp), is_ftp_login 을
    LAN 스캔 의미 피처로 매핑.
    """
    service = df["service"].astype(str).str.lower().str.strip() if "service" in df.columns else pd.Series([""] * len(df))
    proto = df["proto"].astype(str).str.lower().str.strip() if "proto" in df.columns else pd.Series([""] * len(df))

    def col_num(name: str) -> np.ndarray:
        if name not in df.columns:
            return np.zeros(len(df), dtype=np.float64)
        return pd.to_numeric(df[name], errors="coerce").fillna(0).to_numpy(dtype=np.float64)

    is_ssh = (service == "ssh").astype(np.float64).to_numpy()
    is_ftp = service.isin({"ftp", "ftp-data"}).astype(np.float64).to_numpy()
    is_smtp = (service == "smtp").astype(np.float64).to_numpy()
    is_snmp = (service == "snmp").astype(np.float64).to_numpy()
    is_irc = (service == "irc").astype(np.float64).to_numpy()
    is_dns = (service == "dns").astype(np.float64).to_numpy()
    is_http = service.isin({"http", "ssl"}).astype(np.float64).to_numpy()
    is_dhcp = (service == "dhcp").astype(np.float64).to_numpy()
    has_service = (service != "-").astype(np.float64).to_numpy()

    is_tcp = (proto == "tcp").astype(np.float64).to_numpy()
    is_udp = (proto == "udp").astype(np.float64).to_numpy()
    is_icmp = (proto == "icmp").astype(np.float64).to_numpy()

    is_ftp_login = col_num("is_ftp_login")
    is_sm_ips_ports = col_num("is_sm_ips_ports")
    dur = col_num("dur")
    rate = col_num("rate")

    dangerous_ports_count = is_ssh + is_ftp + is_smtp + is_snmp + is_irc
    services_count = is_ssh + is_ftp + is_smtp + is_snmp + is_irc + is_dns + is_http
    open_ports_count = (services_count + has_service + is_tcp + is_udp).clip(0, 12)

    # 위험 신호: 위험 서비스 + FTP 로그인 + 비정상 rate/dur
    rate_median = float(np.median(rate)) if rate.size > 0 else 0.0
    dur_median = float(np.median(dur)) if dur.size > 0 else 0.0
    high_rate = (rate > rate_median).astype(np.float64)
    long_dur = (dur > dur_median).astype(np.float64)
    risk_signals_count = dangerous_ports_count + is_ftp_login + is_sm_ips_ports + high_rate + long_dur

    default_credentials = ((is_ftp_login + is_smtp + is_ftp) > 0).astype(np.float64)
    telnet_or_ssh_open = is_ssh  # UNSW-NB15 에는 telnet 없음
    rtsp_or_onvif_open = is_irc  # IRC = botnet C&C proxy
    upnp_or_iot_camera_open = ((is_udp + is_icmp + is_dhcp) > 0).astype(np.float64)

    features = np.column_stack(
        [
            open_ports_count,
            dangerous_ports_count,
            risk_signals_count,
            services_count,
            default_credentials,
            telnet_or_ssh_open,
            rtsp_or_onvif_open,
            upnp_or_iot_camera_open,
        ]
    )
    return features


def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> tuple[RandomForestClassifier, float]:
    fit_start = time.perf_counter()
    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        random_state=7,
        class_weight="balanced_subsample",
    )
    model.fit(X_train, y_train)
    return model, time.perf_counter() - fit_start


def train_stacking(X_train: np.ndarray, y_train: np.ndarray) -> tuple[StackingClassifier, float]:
    """개요서의 Stacking 구성에 대응한다. RF + GradientBoosting + ExtraTrees → LogReg."""
    estimators = [
        ("rf", RandomForestClassifier(n_estimators=120, n_jobs=-1, random_state=7, class_weight="balanced_subsample")),
        ("gb", GradientBoostingClassifier(n_estimators=100, random_state=7)),
        ("et", ExtraTreesClassifier(n_estimators=120, n_jobs=-1, random_state=7, class_weight="balanced")),
    ]
    final_estimator = LogisticRegression(max_iter=2000, n_jobs=-1)
    model = StackingClassifier(estimators=estimators, final_estimator=final_estimator, n_jobs=-1, passthrough=False)
    fit_start = time.perf_counter()
    model.fit(X_train, y_train)
    return model, time.perf_counter() - fit_start


def evaluate(model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    predict_start = time.perf_counter()
    pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_test)[:, 1]
    else:
        proba = pred.astype(float)
    predict_seconds = time.perf_counter() - predict_start
    return {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, proba)),
        "confusion_matrix": confusion_matrix(y_test, pred).astype(int).tolist(),
        "predict_seconds": round(predict_seconds, 3),
    }


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    cic_spec = SPECS["cic-iot-2023"]
    unsw_spec = SPECS["unsw-nb15"]
    if not cic_spec.exists():
        raise SystemExit(f"CIC-IoT-2023 데이터셋이 없습니다: {cic_spec.path}")
    if not unsw_spec.exists():
        raise SystemExit(f"UNSW-NB15 데이터셋이 없습니다: {unsw_spec.path}")

    print("[lightweight] CIC-IoT-2023 에서 LAN 관련 proxy 행 추출 (정상 + Recon/MITM/BruteForce/Spoofing/Injection)")
    cic_df = load_cic_iot_lan_subset(cic_spec.path, target_per_class=15_000)
    print(f"[lightweight] CIC LAN-subset shape={cic_df.shape}, attack_ratio={float(cic_df['label'].mean()):.3f}")
    cic_X = extract_features_from_cic(cic_df)
    cic_y = cic_df["label"].astype(np.int64).to_numpy()

    # UNSW-NB15 에서도 LAN 관련 proxy 카테고리를 사용: Reconnaissance + Backdoor + Shellcode + Exploits
    print("[lightweight] UNSW-NB15 LAN 관련 proxy 행 추출 (Reconnaissance/Backdoor/Shellcode/Exploits/정상)")
    unsw_full = pd.read_csv(unsw_spec.path)
    unsw_full.columns = [str(name).strip() for name in unsw_full.columns]
    if "attack_cat" in unsw_full.columns:
        attack_cat = unsw_full["attack_cat"].astype(str).str.strip().str.lower()
        lan_mask = attack_cat.isin({"reconnaissance", "backdoor", "shellcode", "exploits", "normal", "-"})
        unsw_df = unsw_full[lan_mask | (unsw_full["label"] == 0)].copy()
    else:
        unsw_df = unsw_full
    print(f"[lightweight] UNSW LAN-subset shape={unsw_df.shape}, attack_ratio={float(unsw_df['label'].mean()):.3f}")
    unsw_X = extract_features_from_unsw(unsw_df)
    unsw_y = unsw_df["label"].astype(np.int64).to_numpy()

    # 두 데이터셋 표본 결합. 데이터셋 간 차이를 제거하거나 현장 일반화를 보장하지 않는다.
    X = np.vstack([cic_X, unsw_X])
    y = np.concatenate([cic_y, unsw_y])
    print(f"[lightweight] 결합 X.shape={X.shape}, attack_ratio={float(y.mean()):.3f}")

    # 단일 seed의 행 단위 holdout이다. 동일 기기·세션·시간 누수를 막는 group split이나
    # 외부 네트워크 검증이 아니므로 아래 metrics는 내부 표본 지표로만 해석한다.
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=7, stratify=y)

    print("[lightweight] RandomForest 학습 시작")
    rf_model, rf_fit_seconds = train_random_forest(X_train, y_train)
    rf_metrics = evaluate(rf_model, X_test, y_test)
    rf_metrics["fit_seconds"] = round(rf_fit_seconds, 3)
    print(f"  RF F1={rf_metrics['f1']:.4f}, precision={rf_metrics['precision']:.4f}, recall={rf_metrics['recall']:.4f}, ROC-AUC={rf_metrics['roc_auc']:.4f}")

    print("[lightweight] Stacking 학습 시작")
    stack_model, stack_fit_seconds = train_stacking(X_train, y_train)
    stack_metrics = evaluate(stack_model, X_test, y_test)
    stack_metrics["fit_seconds"] = round(stack_fit_seconds, 3)
    print(f"  Stacking F1={stack_metrics['f1']:.4f}, precision={stack_metrics['precision']:.4f}, recall={stack_metrics['recall']:.4f}, ROC-AUC={stack_metrics['roc_auc']:.4f}")

    joblib.dump(rf_model, OUTPUT_DIR / "random_forest.joblib")
    joblib.dump(stack_model, OUTPUT_DIR / "stacking.joblib")

    metrics = {
        "dataset": "lightweight-cic-unsw-8feat",
        "description": (
            "Lightweight 8-feature LAN scan inference model. Combined training on CIC-IoT-2023 "
            "(class-balanced sampling) and UNSW-NB15 (full training set), mapping each dataset's "
            "binary service/protocol flags and categorical service/proto columns to LAN scan "
            "semantic proxy features. No synthetic data. Labels are each dataset's original 0/1. "
            "Metrics use one random_state=7 row-level 80/20 holdout and are not field accuracy. "
            "The full 42~46 feature traffic models in ../{unsw-nb15,ton-iot,cic-iot-2023}/ are kept "
            "for academic F1 metrics and future traffic-capture extension (RPi mode)."
        ),
        "source": {
            "datasets": [
                "CIC-IoT-2023 (selected LAN-related attack-category proxy rows)",
                "UNSW-NB15 (selected LAN-related attack-category proxy rows)",
            ],
            "cic_attack_categories": sorted(LAN_DETECTABLE_ATTACK_LABELS),
            "unsw_attack_categories": ["Reconnaissance", "Backdoor", "Shellcode", "Exploits"],
            "rows_cic": int(cic_X.shape[0]),
            "rows_unsw": int(unsw_X.shape[0]),
            "total_rows": int(X.shape[0]),
            "feature_count": 8,
            "feature_names": FEATURE_NAMES,
            "note": (
                "Trained on raw rows from CIC-IoT-2023 and UNSW-NB15 restricted to attack categories "
                "selected as LAN-related proxies (port scans, vulnerability scans, "
                "ARP/DNS spoofing, brute-force, backdoor/exploit traffic). DDoS/DoS/Mirai flood "
                "categories are intentionally excluded — they require traffic capture (RPi extension "
                "track) and are not represented by this LAN-scan proxy model. This offline holdout is "
                "not field accuracy or evidence that every network device is detectable."
            ),
        },
        "attack_ratio_train": float(y_train.mean()),
        "attack_ratio_test": float(y_test.mean()),
        "models": [
            {"model": "random_forest", **rf_metrics},
            {"model": "stacking", **stack_metrics},
        ],
    }
    (OUTPUT_DIR / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[lightweight] 저장: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
