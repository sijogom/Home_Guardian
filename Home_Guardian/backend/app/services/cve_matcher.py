"""디바이스 fingerprint → NVD/CVE 매칭 + 한국어 변환 서비스.

매칭 우선순위:
1. 검증된 오프라인 참조 카탈로그(``backend/app/data/iot_cve_catalog.json``) — 가정용 IoT 주요 vendor의 확인된 CVE.
   즉시 반환, 네트워크/지연 없음.
2. (옵션) NVD API 2.0 동적 조회 — ``nvdlib`` 가 설치되어 있고 ``HG_NVD_LOOKUP=1`` 일 때만.
   결과는 in-memory 캐시에 저장해 NVD rate limit(5 req/30s, no key) 회피.

설계 의도:
- 디바이스가 vendor/model 을 노출하지 않으면 카탈로그 매칭이 안 되는 게 정상.
  → 빈 list 반환, 점수 계산은 규칙 기반으로 폴백.
- 일반 신호(telnet/rtsp/default credential) 는 vendor 와 무관하게 ``generic_signals`` 로 한국어 안내 매핑.
- 한국어 문구는 사회적 약자(고령자/장애인)를 우선 사용자로 둔다 — 기술 용어 최소화.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

from .device_identity import _GENERIC_MANUFACTURERS, _GENERIC_MODELS

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "iot_cve_catalog.json"

# NVD 조회 결과 캐시 TTL(24시간). 같은 (vendor, product)는 하루에 한 번만 라이브 조회한다.
_NVD_TTL_SECONDS = 24 * 60 * 60
_NVD_CACHE_VERSION = 1
_NVD_CACHE_MAX_BYTES = 2 * 1024 * 1024
_NVD_CACHE_MAX_ENTRIES = 512
_NVD_CACHE_MAX_RESULTS_PER_KEY = 20

_LOGGER = logging.getLogger("home_guardian.cve_matcher")


class CveMatcher:
    def __init__(self) -> None:
        self._catalog = self._load_catalog()
        self._nvd_cache_path = self._resolve_nvd_cache_path()
        # NVD 결과는 요청 중에는 메모리에서 읽되, 운영 경로가 설정된 경우 재시작 뒤에도 같은 근거를
        # 즉시 복구한다. 그렇지 않으면 배포 직후 첫 화면만 green/no-CVE 로 되돌아갔다가 다음 조회에서
        # red/high 로 바뀌어 같은 기기의 위험 판정이 흔들린다.
        self._nvd_cache: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = (
            self._load_persistent_nvd_cache()
        )
        # NVD 라이브 조회를 '요청 스레드 밖'(백그라운드 워커)에서 처리하기 위한 상태.
        # 라이브 조회는 NVD rate limit(키 없으면 5req/30s → nvdlib 이 호출당 ~6초 지연)으로 느려서
        # 요청 핸들러(getScanResult/devices/dashboard)에서 동기로 부르면 모바일 8초 타임아웃을 넘긴다.
        # → 요청은 캐시만 즉시 읽고, 미스면 백그라운드 조회를 예약하고 빈 결과로 반환한다.
        self._nvd_lock = threading.Lock()
        self._nvd_inflight: set[tuple[str, str]] = set()
        self._nvd_queue: "queue.Queue[tuple[str, str | None, str | None, tuple[str, str]]] | None" = None
        # 카탈로그 vendor → alias 역인덱스
        self._alias_to_vendor: dict[str, str] = {}
        for vendor_key, vendor_data in self._catalog.get("vendors", {}).items():
            for alias in vendor_data.get("aliases", []):
                self._alias_to_vendor[alias.strip().lower()] = vendor_key

    @staticmethod
    def _load_catalog() -> dict[str, Any]:
        try:
            return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        except Exception:  # pragma: no cover - 카탈로그 파일 손상
            return {"vendors": {}, "generic_signals": {}}

    @staticmethod
    def _resolve_nvd_cache_path() -> Path | None:
        configured = os.environ.get("HG_NVD_CACHE_PATH", "").strip()
        return Path(configured) if configured else None

    def _load_persistent_nvd_cache(self) -> dict[tuple[str, str], tuple[float, list[dict[str, Any]]]]:
        path = self._nvd_cache_path
        if path is None:
            return {}
        try:
            if not path.is_file():
                return {}
            if path.stat().st_size > _NVD_CACHE_MAX_BYTES:
                raise ValueError("NVD cache file exceeds size limit")
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("version") != _NVD_CACHE_VERSION:
                raise ValueError("unsupported NVD cache format")
            entries = payload.get("entries")
            if not isinstance(entries, list):
                raise ValueError("invalid NVD cache entries")

            now = time.time()
            restored: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = {}
            for entry in entries[:_NVD_CACHE_MAX_ENTRIES]:
                if not isinstance(entry, dict):
                    continue
                manufacturer = entry.get("manufacturer")
                model = entry.get("model")
                fetched_at = entry.get("fetched_at")
                results = entry.get("results")
                if not isinstance(manufacturer, str) or not isinstance(model, str):
                    continue
                if not manufacturer.strip() or not model.strip() or len(manufacturer) > 256 or len(model) > 256:
                    continue
                if not isinstance(fetched_at, (int, float)) or not isinstance(results, list):
                    continue
                fetched_at = float(fetched_at)
                # 만료 항목도 복구한다. _lookup_nvd 가 stale 값을 즉시 반환하면서 백그라운드 갱신하므로,
                # TTL 경계에서 이미 확인한 High CVE가 사라져 green 으로 되돌아가는 창을 만들지 않는다.
                if fetched_at < 0 or fetched_at > now + 60:
                    continue
                safe_results = [dict(item) for item in results[:_NVD_CACHE_MAX_RESULTS_PER_KEY] if isinstance(item, dict)]
                restored[(manufacturer.strip().lower(), model.strip().lower())] = (fetched_at, safe_results)
            return restored
        except Exception:
            _LOGGER.warning("지속 NVD 캐시를 읽지 못해 빈 캐시로 시작합니다: %s", path, exc_info=True)
            return {}

    def _persist_nvd_cache(
        self, snapshot: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]]
    ) -> None:
        path = self._nvd_cache_path
        if path is None:
            return
        entries: list[dict[str, Any]] = []
        for (manufacturer, model), (fetched_at, results) in list(snapshot.items())[:_NVD_CACHE_MAX_ENTRIES]:
            entries.append(
                {
                    "manufacturer": manufacturer,
                    "model": model,
                    "fetched_at": fetched_at,
                    "results": [dict(item) for item in results[:_NVD_CACHE_MAX_RESULTS_PER_KEY]],
                }
            )
        payload = {"version": _NVD_CACHE_VERSION, "entries": entries}
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temp_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        except Exception:
            _LOGGER.warning("지속 NVD 캐시를 저장하지 못했습니다: %s", path, exc_info=True)
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _store_nvd_result(
        self,
        cache_key: tuple[str, str],
        results: list[dict[str, Any]],
        *,
        fetched_at: float | None = None,
    ) -> None:
        timestamp = time.time() if fetched_at is None else float(fetched_at)
        safe_results = [dict(item) for item in results[:_NVD_CACHE_MAX_RESULTS_PER_KEY] if isinstance(item, dict)]
        with self._nvd_lock:
            self._nvd_cache[cache_key] = (timestamp, safe_results)
            snapshot = dict(self._nvd_cache)
        self._persist_nvd_cache(snapshot)

    def match_device(
        self,
        manufacturer: str | None,
        model: str | None,
        firmware: str | None = None,
        risk_signals: Iterable[str] | None = None,
        device_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """디바이스 정보로 known CVE 목록 반환 (한국어 변환 포함)."""
        results: list[dict[str, Any]] = []

        # 1) 로컬 카탈로그 매칭
        vendor_key = self._resolve_vendor(manufacturer)
        if vendor_key:
            vendor_data = self._catalog["vendors"][vendor_key]
            product_match_key = self._resolve_product(vendor_data, model, device_type)
            if product_match_key:
                for cve in vendor_data["products"].get(product_match_key, []):
                    results.append(
                        {
                            **cve,
                            "source": "catalog",
                            "vendor": vendor_key,
                            "product": product_match_key,
                            "matched_on": "vendor+product",
                        }
                    )

        # 2) (옵션) NVD API 2.0 동적 조회
        if os.environ.get("HG_NVD_LOOKUP") == "1":
            results.extend(self._lookup_nvd(manufacturer, model, firmware))

        # 3) generic 신호 매핑 (vendor 와 무관)
        for signal in risk_signals or []:
            mapping = self._catalog.get("generic_signals", {}).get(str(signal))
            if mapping:
                results.append(
                    {
                        "signal": signal,
                        "severity": "medium",
                        "summary_ko": mapping.get("summary_ko"),
                        "remediation_ko": mapping.get("remediation_ko"),
                        "source": "generic_signal",
                    }
                )

        # 4) 취약/EOL 서버 배너 매칭: firmware/model 에 담긴 HTTP Server 배너의 known 취약 시그니처.
        #    예) Boa 웹서버(0.94.x, 2005 단종) → CVE-2022-45956 인증 우회. vendor 식별과 무관하게 잡으므로,
        #    제조사 미확인 공유기라도 배너만으로 위험을 놓치지 않는다(실측: 192.168.1.1 Boa/0.94.14rc21).
        banner_blob = " ".join(filter(None, [str(firmware or ""), str(model or "")])).lower()
        if banner_blob:
            for sig in self._catalog.get("vulnerable_server_banners", {}).values():
                needle = str(sig.get("match", "")).strip().lower()
                # 단어 경계 매칭: 'boa' 같은 짧은 배너 시그니처가 'keyboard'·'boat' 의 부분문자열로
                # 오탐되지 않도록 \b 로 토큰 경계를 강제한다(진짜 배너 'Boa/0.94' 는 '/' 가 경계라 매칭).
                if needle and re.search(r"\b" + re.escape(needle) + r"\b", banner_blob):
                    results.append(
                        {
                            "cve_id": sig.get("cve_id"),
                            "severity": sig.get("severity", "medium"),
                            "cvss": sig.get("cvss"),
                            "summary_ko": sig.get("summary_ko"),
                            "remediation_ko": sig.get("remediation_ko"),
                            "source": "server_banner",
                            "matched_on": "firmware_banner",
                        }
                    )

        # 중복 제거 (cve_id 또는 signal 기준)
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for item in results:
            key = str(item.get("cve_id") or item.get("signal") or id(item))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _resolve_vendor(self, manufacturer: str | None) -> str | None:
        if not manufacturer:
            return None
        candidate = manufacturer.strip().lower()
        if candidate in self._alias_to_vendor:
            return self._alias_to_vendor[candidate]
        # 부분 매칭(예: "samsung electronics co. ltd" → samsung). 긴 alias 를 먼저 시도해 더 구체적인
        # 매칭을 우선한다("lg electronics" > "lg"). ASCII alias 는 단어 경계로만 매칭한다 — 단순
        # 부분문자열이면 짧은 alias 가 무관한 제조사에 오매칭된다(실측: "lg"⊂"calgary"/"bulgari"/
        # "belgian", "hik"⊂"hikari" → 엉뚱한 벤더 critical CVE 부착·거짓 red). CJK(한글 등) alias 는
        # 단어 사이 공백이 없어 \b 경계가 부정확하므로 부분문자열 매칭을 유지한다("삼성"⊂"삼성전자" 는
        # 바람직하고, 한국어 브랜드명은 짧아도 우연 충돌 위험이 낮다).
        for alias in sorted(self._alias_to_vendor, key=len, reverse=True):
            if not alias:
                continue
            matched = (
                re.search(r"\b" + re.escape(alias) + r"\b", candidate)
                if alias.isascii()
                else alias in candidate
            )
            if matched:
                return self._alias_to_vendor[alias]
        return None

    @staticmethod
    def _resolve_product(vendor_data: dict[str, Any], model: str | None, device_type: str | None = None) -> str | None:
        products = vendor_data.get("products", {})
        # 구분자 정규화: 실제 기기는 모델을 "Family_HUB"(언더스코어)처럼 광고한다(삼성 패밀리허브
        # getInfo 실측). "_" 를 공백으로 통일하지 않으면 product 키("family hub")와 exact 매칭이 깨지고,
        # 'hub' 부분문자열 hint 가 "family_hub" 의 "hub" 를 잡아 엉뚱한 SmartThings Hub CVE 에 오매칭된다.
        model_lower = (model or "").strip().lower().replace("_", " ")
        category_hints = {
            "camera": ["ip camera", "cam"],
            "router": ["router", "archer router"],
            "tv": ["webos tv"],
            "nas": ["nas"],
            "fridge": ["family hub"],
            "speaker": ["speaker"],
            "audio": ["speaker"],
            "hub": ["smartthings hub", "hue bridge"],
            "light": ["hue bridge", "smart light"],
            "plug": ["smart plug", "plug"],
        }
        if model_lower and model_lower not in {"lan fingerprint", "unknown"}:
            if model_lower in products:
                return model_lower
            for product_key in products:
                if product_key.lower() in model_lower or model_lower in product_key.lower():
                    return product_key
            # 모델명에 카메라/router/tv 등 키워드가 있으면 같은 카테고리 product 매칭 시도
            for hint, candidates in category_hints.items():
                if hint in model_lower:
                    for candidate in candidates:
                        if candidate in products:
                            return candidate
        # model 이 빈약해도 device_type(종류)으로 같은 카테고리 product 매칭(제조사가 일치할 때만).
        if device_type:
            for candidate in category_hints.get(device_type, []):
                if candidate in products:
                    return candidate
            # 정확한 키가 없어도 product 키에 카테고리 키워드(또는 종류명)가 포함되면 매칭한다.
            # 예: device_type='camera' → 'tapo camera' / 'ip camera' 제품에 모두 대응(과매칭 방지 위해
            # 제조사가 이미 일치한 상태에서만 동작).
            hints = [*category_hints.get(device_type, []), device_type]
            for product_key in products:
                pk = product_key.lower()
                if any(hint in pk for hint in hints):
                    return product_key
        return None

    def _nvd_cache_key(self, manufacturer: str | None, model: str | None) -> tuple[str, str] | None:
        """라이브 NVD 조회 대상이면 캐시 키를 반환, 아니면 None.

        제조사·모델이 미상 placeholder("확인 안 됨"/"LAN fingerprint" 등)면 NVD 키워드 질의가
        무의미할 뿐 아니라, 쓰레기 키워드("Seongji LAN fingerprint")가 무관한 CVE 에 오매칭되거나
        rate limit(5req/30s) 으로 응답을 수십 초 지연시킨다 → 식별된 기기만 조회한다.
        """
        if not manufacturer or not model:
            return None
        if manufacturer.strip().lower() in _GENERIC_MANUFACTURERS or model.strip().lower() in _GENERIC_MODELS:
            return None
        return (manufacturer.strip().lower(), model.strip().lower())

    def _lookup_nvd(
        self, manufacturer: str | None, model: str | None, firmware: str | None
    ) -> list[dict[str, Any]]:
        """요청 경로용 NVD 조회: 캐시에 있으면 즉시 반환, 미스면 백그라운드 조회를 예약하고 빈 list 반환.

        라이브 NVD 호출은 절대 이 메서드(=요청 스레드)에서 동기로 하지 않는다. NVD 는 키 없으면
        호출당 ~6초 지연이 강제돼, 식별 기기 2대만 돼도 응답이 모바일 8초 타임아웃을 넘겨
        "요청 시간이 초과됐습니다"(스캔 결과 0대) 가 났다. 카탈로그/배너/generic 매칭은 동기로
        충분히 빠르므로 NVD 보강만 비동기로 분리한다 — 결과는 다음 조회(스캔/새로고침)부터 반영된다.
        """
        cache_key = self._nvd_cache_key(manufacturer, model)
        if cache_key is None:
            return []
        now = time.time()
        stale_results: list[dict[str, Any]] = []
        with self._nvd_lock:
            cached = self._nvd_cache.get(cache_key)
            if cached and (now - cached[0]) < _NVD_TTL_SECONDS:
                return cached[1]
            if cached:
                stale_results = cached[1]
            if cache_key in self._nvd_inflight:
                return stale_results  # 갱신 중에도 마지막으로 확인한 위험 근거는 유지한다.
            self._nvd_inflight.add(cache_key)
        # 예약은 별도 try 로 감싼다: 스레드 시작 실패(RuntimeError: can't start a new thread) 등으로
        # 예약이 깨지면 inflight 키가 영구히 남아 그 기기의 NVD 보강이 재시작까지 차단된다 → 롤백한다.
        try:
            self._enqueue_nvd_fetch(manufacturer, model, firmware, cache_key)
        except Exception:  # pragma: no cover - 스레드/큐 자원 고갈 등 드문 경로
            with self._nvd_lock:
                self._nvd_inflight.discard(cache_key)
            _LOGGER.warning("NVD 백그라운드 조회 예약 실패 — inflight 롤백: %s", cache_key, exc_info=True)
        return stale_results

    def _enqueue_nvd_fetch(
        self, manufacturer: str | None, model: str | None, firmware: str | None, cache_key: tuple[str, str]
    ) -> None:
        worker_queue = self._ensure_nvd_worker()
        worker_queue.put((manufacturer, model, firmware, cache_key))

    def _ensure_nvd_worker(self) -> "queue.Queue[tuple[str, str | None, str | None, tuple[str, str]]]":
        """백그라운드 NVD 워커 큐를 (필요 시 처음) 생성한다. 단일 데몬 스레드가 순차 처리해
        NVD rate limit 을 자연히 직렬화하고, 어떤 요청도 막지 않는다."""
        with self._nvd_lock:
            if self._nvd_queue is None:
                new_queue: "queue.Queue[tuple[str, str | None, str | None, tuple[str, str]]]" = queue.Queue()
                # 스레드를 '먼저' 띄우고, 성공한 뒤에만 큐를 게시한다. start() 가 실패하면 _nvd_queue 는
                # None 으로 남아 다음 호출에서 재시도되고, 소비자 없는 좀비 큐가 생기지 않는다.
                threading.Thread(
                    target=self._nvd_worker_loop, args=(new_queue,), name="nvd-lookup-worker", daemon=True
                ).start()
                self._nvd_queue = new_queue
            return self._nvd_queue

    def _nvd_worker_loop(self, worker_queue: "queue.Queue[tuple[str, str | None, str | None, tuple[str, str]]]") -> None:
        while True:
            manufacturer, model, firmware, cache_key = worker_queue.get()
            try:
                try:
                    results = self._fetch_nvd(manufacturer, model, firmware)
                except Exception:  # pragma: no cover - NVD API rate limit / 네트워크 오류
                    # 조회 실패와 '정상 조회 결과 0건'은 다르다. 실패를 []로 저장하면 이미 확인한 High CVE를
                    # 지우고 24시간 green 으로 고정하므로, 기존 메모리/지속 캐시를 그대로 보존한다.
                    _LOGGER.warning("NVD 백그라운드 조회 실패: %s", cache_key, exc_info=True)
                else:
                    self._store_nvd_result(cache_key, results)
            finally:
                with self._nvd_lock:
                    self._nvd_inflight.discard(cache_key)
                worker_queue.task_done()

    def _fetch_nvd(
        self, manufacturer: str | None, model: str | None, firmware: str | None
    ) -> list[dict[str, Any]]:
        """실제 NVD API 2.0 동기 조회(백그라운드 워커 전용). nvdlib 미설치 시 빈 list.

        호출 시점에 (vendor, product)는 placeholder 가 아님이 보장된다(_nvd_cache_key 가 검증).
        """
        try:
            import nvdlib  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover - 의존성 미설치 환경
            raise RuntimeError("nvdlib is unavailable") from exc

        keyword = f"{manufacturer} {model}"
        cves = nvdlib.searchCVE(keywordSearch=keyword, limit=5)
        results: list[dict[str, Any]] = []
        for cve in cves:
            severity = "medium"
            cvss = 0.0
            metric = getattr(cve, "v31score", None) or getattr(cve, "v30score", None) or getattr(cve, "v2score", None)
            if metric is not None:
                try:
                    cvss = max(0.0, min(10.0, float(metric)))
                except (ValueError, TypeError):
                    # NVD 가 "N/A" 같은 비정상 값을 줄 수 있다. 점수를 알 수 없으면 unknown 으로 둔다.
                    cvss = 0.0
                    severity = "unknown"
                else:
                    if cvss >= 9.0:
                        severity = "critical"
                    elif cvss >= 7.0:
                        severity = "high"
                    elif cvss >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
            results.append(
                {
                    "cve_id": getattr(cve, "id", ""),
                    "severity": severity,
                    "cvss": cvss,
                    "summary_ko": f"{manufacturer} {model} 에 알려진 보안 문제가 보고됐어요. ({getattr(cve, 'id', '')})",
                    "remediation_ko": "제조사 앱이나 관리자 페이지에서 펌웨어 업데이트를 적용해 주세요.",
                    "source": "nvd-api",
                    "vendor": str(manufacturer).lower(),
                    "product": str(model).lower(),
                    "matched_on": "nvd-keyword",
                }
            )
        return results


_DEFAULT_MATCHER: CveMatcher | None = None


def get_matcher() -> CveMatcher:
    global _DEFAULT_MATCHER
    if _DEFAULT_MATCHER is None:
        _DEFAULT_MATCHER = CveMatcher()
    return _DEFAULT_MATCHER
