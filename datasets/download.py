"""
홈 가디언 (Home Guardian) — 데이터셋 다운로드 스크립트

사용법:
    python datasets/download.py --dataset cic-iot-2023
    python datasets/download.py --dataset unsw-nb15
    python datasets/download.py --dataset all
    python datasets/download.py --list
"""

import argparse
import os
import sys
import urllib.request
import zipfile
from pathlib import Path

# 스크립트 기준으로 datasets/ 폴더 경로 설정
DATASETS_DIR = Path(__file__).parent.resolve()

DATASETS = {
    "cic-iot-2023": {
        "name": "CIC-IoT-Dataset 2023",
        "base_url": "http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/CSV/",
        "description": "메인 데이터셋 — 33종 IoT 공격 유형, ML IDS 학습·평가",
        "dest": DATASETS_DIR / "CIC-IoT-2023" / "raw",
        "manual": True,
        "instructions": [
            "1. 브라우저에서 http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/ 접속",
            "2. CSV/ 폴더에서 필요한 파일 다운로드",
            "3. datasets/CIC-IoT-2023/raw/ 폴더에 저장",
            "",
            "또는 wget 사용:",
            "  wget -r -np -nH --cut-dirs=2 http://cicresearch.ca/IOTDataset/CIC_IOT_Dataset2023/CSV/",
        ],
    },
    "ton-iot": {
        "name": "ToN-IoT",
        "description": "보조 데이터셋 — IoT/IIoT 텔레메트리, 일반화 검증",
        "dest": DATASETS_DIR / "ToN-IoT" / "raw",
        "manual": True,
        "instructions": [
            "1. https://research.unsw.edu.au/projects/toniot-datasets 접속",
            "2. 'HERE' 링크 클릭 → SharePoint 페이지",
            "3. 필요한 CSV 파일 다운로드",
            "4. datasets/ToN-IoT/raw/ 폴더에 저장",
            "",
            "문의: Dr Nour Moustafa (데이터 제공처 공식 안내 페이지)",
        ],
    },
    "unsw-nb15": {
        "name": "UNSW-NB15",
        "description": "교차검증 데이터셋 — 9종 공격, 49개 특성, 254만 건",
        "dest": DATASETS_DIR / "UNSW-NB15" / "raw",
        "manual": True,
        "instructions": [
            "1. https://research.unsw.edu.au/projects/unsw-nb15-dataset 접속",
            "2. 'HERE' 링크 클릭 → SharePoint 페이지",
            "3. CSV 파일 4개 다운로드 (UNSW-NB15_1.csv ~ _4.csv)",
            "4. datasets/UNSW-NB15/raw/ 폴더에 저장",
        ],
    },
    "oui": {
        "name": "IEEE OUI Database",
        "description": "MAC 주소 → 제조사 매핑 (IoT 기기 식별용)",
        "url": "https://standards-oui.ieee.org/oui/oui.csv",
        "dest": DATASETS_DIR / "CIC-IoT-2023" / "raw",  # 공통 유틸리티로 사용
        "filename": "oui.csv",
        "manual": False,
    },
}


def download_file(url: str, dest_path: Path) -> bool:
    """URL에서 파일 다운로드"""
    try:
        print(f"  다운로드 중: {url}")
        print(f"  저장 경로: {dest_path}")
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        req = urllib.request.Request(url, headers={"User-Agent": "HomeGuardian/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            total = response.headers.get("Content-Length")
            if total:
                total = int(total)
                print(f"  파일 크기: {total / 1024 / 1024:.1f} MB")

            with open(dest_path, "wb") as f:
                downloaded = 0
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        print(f"\r  진행: {pct:.1f}%", end="", flush=True)

        print(f"\n  완료: {dest_path}")
        return True

    except Exception as e:
        print(f"\n  실패: {e}")
        return False


def show_manual_instructions(dataset_info: dict):
    """수동 다운로드 안내 표시"""
    print(f"\n  [{dataset_info['name']}] 수동 다운로드가 필요합니다:")
    print()
    for line in dataset_info["instructions"]:
        print(f"    {line}")
    print()
    print(f"  저장 위치: {dataset_info['dest']}")


def process_dataset(key: str):
    """데이터셋 다운로드 처리"""
    if key not in DATASETS:
        print(f"알 수 없는 데이터셋: {key}")
        print(f"사용 가능: {', '.join(DATASETS.keys())}")
        return False

    info = DATASETS[key]
    print(f"\n{'='*60}")
    print(f"[{info['name']}] {info['description']}")
    print(f"{'='*60}")

    # 저장 폴더 생성
    info["dest"].mkdir(parents=True, exist_ok=True)

    if info.get("manual"):
        show_manual_instructions(info)
        return True

    # 자동 다운로드
    dest_file = info["dest"] / info["filename"]
    if dest_file.exists():
        print(f"  이미 존재: {dest_file}")
        overwrite = input("  덮어쓸까요? (y/N): ").strip().lower()
        if overwrite != "y":
            print("  건너뜁니다.")
            return True

    return download_file(info["url"], dest_file)


def list_datasets():
    """데이터셋 목록 표시"""
    print("\n사용 가능한 데이터셋:")
    print(f"{'─'*60}")
    for key, info in DATASETS.items():
        manual = " [수동]" if info.get("manual") else " [자동]"
        print(f"  {key:20s}{manual}  {info['description']}")
    print(f"{'─'*60}")
    print("\n사용법: python download.py --dataset <이름>")
    print("전부 다운로드: python download.py --dataset all")


def check_status():
    """각 데이터셋 폴더의 파일 현황 확인"""
    print("\n데이터셋 현황:")
    print(f"{'─'*60}")
    for key, info in DATASETS.items():
        dest = info["dest"]
        if dest.exists():
            files = list(dest.iterdir())
            csv_files = [f for f in files if f.suffix == ".csv"]
            pcap_files = [f for f in files if f.suffix == ".pcap"]
            total_size = sum(f.stat().st_size for f in files if f.is_file())
            size_mb = total_size / 1024 / 1024

            if files:
                status = f"CSV {len(csv_files)}개, PCAP {len(pcap_files)}개, 총 {size_mb:.1f}MB"
            else:
                status = "비어있음 — 다운로드 필요"
        else:
            status = "폴더 없음"

        print(f"  {info['name']:25s} {status}")

    print(f"{'─'*60}")


def main():
    parser = argparse.ArgumentParser(description="홈 가디언 데이터셋 다운로드 관리")
    parser.add_argument("--dataset", type=str, help="다운로드할 데이터셋 (또는 'all')")
    parser.add_argument("--list", action="store_true", help="사용 가능한 데이터셋 목록")
    parser.add_argument("--status", action="store_true", help="현재 다운로드 상태 확인")

    args = parser.parse_args()

    if args.list:
        list_datasets()
        return

    if args.status:
        check_status()
        return

    if not args.dataset:
        list_datasets()
        print("\n현재 상태:")
        check_status()
        return

    if args.dataset == "all":
        for key in DATASETS:
            process_dataset(key)
    else:
        process_dataset(args.dataset)


if __name__ == "__main__":
    main()
