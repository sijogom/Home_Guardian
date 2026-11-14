"""CveMatcher 의 NVD 동적조회 가드 검증.

라이브 운영에서 기기목록 enrich 가 미상 기기("확인 안 됨"/"LAN fingerprint")까지 NVD 에
질의해 ① 무의미·오매칭 위험 ② rate limit(5req/30s)으로 수십 초 지연이 발생했다.
식별된(제조사·모델이 placeholder 가 아닌) 기기만 NVD 를 조회해야 한다.
"""

from __future__ import annotations

import sys
import time
import types

from app.services.cve_matcher import CveMatcher


class _FakeNvdlib(types.ModuleType):
    """searchCVE 호출 여부를 기록하는 가짜 nvdlib."""

    def __init__(self, delay: float = 0.0) -> None:
        super().__init__("nvdlib")
        self.calls: list[str] = []
        self._delay = delay

    def searchCVE(self, keywordSearch: str = "", limit: int = 5):  # noqa: N803 - nvdlib 시그니처 모방
        if self._delay:
            time.sleep(self._delay)  # NVD rate-limit/네트워크 지연 모사
        self.calls.append(keywordSearch)
        return []


def _with_fake_nvd(monkeypatch, delay: float = 0.0) -> _FakeNvdlib:
    fake = _FakeNvdlib(delay=delay)
    monkeypatch.setitem(sys.modules, "nvdlib", fake)
    return fake


def _drain_nvd_worker(matcher: CveMatcher, timeout: float = 5.0) -> None:
    """백그라운드 NVD 워커가 예약된 조회를 모두 처리할 때까지 대기(테스트 결정성 확보)."""
    worker_queue = matcher._nvd_queue
    if worker_queue is None:
        return
    deadline = time.time() + timeout
    while not worker_queue.empty() and time.time() < deadline:
        time.sleep(0.01)
    worker_queue.join()


def test_nvd_skipped_for_placeholder_manufacturer(monkeypatch):
    fake = _with_fake_nvd(monkeypatch)
    matcher = CveMatcher()
    result = matcher._lookup_nvd("확인 안 됨", "LAN fingerprint", None)
    assert result == []
    _drain_nvd_worker(matcher)
    assert fake.calls == []  # placeholder 는 NVD 를 부르지 않는다(예약조차 안 함)


def test_nvd_skipped_for_placeholder_model(monkeypatch):
    fake = _with_fake_nvd(monkeypatch)
    matcher = CveMatcher()
    # 제조사는 실값(Seongji=칩벤더)이라도 모델이 placeholder 면 키워드가 쓰레기가 된다.
    assert matcher._lookup_nvd("Seongji", "LAN fingerprint", None) == []
    _drain_nvd_worker(matcher)
    assert fake.calls == []


def test_nvd_fetched_in_background_for_identified_device(monkeypatch):
    """식별된 기기는 NVD 를 조회하되, '요청 경로'는 즉시 빈 list 를 반환하고 실제 조회는
    백그라운드 워커가 수행해 캐시를 채운다(요청 스레드는 NVD 를 기다리지 않는다)."""
    fake = _with_fake_nvd(monkeypatch)
    matcher = CveMatcher()
    # 요청 경로: 캐시 미스 → 즉시 [] (동기 NVD 호출 없음)
    assert matcher._lookup_nvd("EFM Networks", "ipTIME BE3600QCA", None) == []
    # 백그라운드 워커가 조회를 끝낼 때까지 대기 후 검증
    _drain_nvd_worker(matcher)
    assert fake.calls == ["EFM Networks ipTIME BE3600QCA"]  # 식별 기기는 (백그라운드로) NVD 조회
    # 캐시가 채워졌으므로 다음 요청은 캐시에서 즉시 반환된다.
    assert matcher._nvd_cache_key("EFM Networks", "ipTIME BE3600QCA") in matcher._nvd_cache


def test_nvd_cache_survives_server_restart(monkeypatch, tmp_path):
    """이미 확인한 High CVE 근거는 서버 재시작 뒤 첫 요청에서도 복구되어야 한다.

    메모리 캐시만 쓰면 배포 직후 Raspberry Pi 카드가 잠시 green 이었다가 NVD 재조회 후 red 로 바뀐다.
    지속 캐시는 요청 경로를 막지 않으면서 그 cold-start 오판을 막는다.
    """
    cache_path = tmp_path / "nvd-cache-v1.json"
    monkeypatch.setenv("HG_NVD_CACHE_PATH", str(cache_path))
    key = ("raspberry pi", "raspberry pi 5 model b")
    high_cve = [
        {
            "cve_id": "CVE-2026-0001",
            "severity": "high",
            "cvss": 8.1,
            "source": "nvd-api",
        }
    ]

    first_process = CveMatcher()
    first_process._store_nvd_result(key, high_cve)
    assert cache_path.is_file()

    restarted_process = CveMatcher()
    assert restarted_process._lookup_nvd("Raspberry Pi", "Raspberry Pi 5 Model B", None) == high_cve
    assert key not in restarted_process._nvd_inflight  # 캐시 적중이므로 라이브 재조회 예약 없음


def test_invalid_persistent_nvd_cache_fails_closed(monkeypatch, tmp_path):
    cache_path = tmp_path / "nvd-cache-v1.json"
    cache_path.write_text('{"version":1,"entries":"broken"}', encoding="utf-8")
    monkeypatch.setenv("HG_NVD_CACHE_PATH", str(cache_path))

    matcher = CveMatcher()

    assert matcher._nvd_cache == {}


def test_expired_high_cve_is_returned_while_refresh_is_scheduled(monkeypatch, tmp_path):
    cache_path = tmp_path / "nvd-cache-v1.json"
    monkeypatch.setenv("HG_NVD_CACHE_PATH", str(cache_path))
    key = ("raspberry pi", "raspberry pi 5 model b")
    high_cve = [{"cve_id": "CVE-2026-0001", "severity": "high", "source": "nvd-api"}]

    writer = CveMatcher()
    writer._store_nvd_result(key, high_cve, fetched_at=time.time() - (25 * 60 * 60))

    restarted = CveMatcher()
    scheduled: list[tuple[str, str]] = []
    monkeypatch.setattr(
        restarted,
        "_enqueue_nvd_fetch",
        lambda _manufacturer, _model, _firmware, cache_key: scheduled.append(cache_key),
    )

    assert restarted._lookup_nvd("Raspberry Pi", "Raspberry Pi 5 Model B", None) == high_cve
    assert scheduled == [key]


def test_nvd_refresh_failure_preserves_existing_high_cve(monkeypatch, tmp_path):
    cache_path = tmp_path / "nvd-cache-v1.json"
    monkeypatch.setenv("HG_NVD_CACHE_PATH", str(cache_path))
    key = ("raspberry pi", "raspberry pi 5 model b")
    high_cve = [{"cve_id": "CVE-2026-0001", "severity": "high", "source": "nvd-api"}]

    matcher = CveMatcher()
    matcher._store_nvd_result(key, high_cve, fetched_at=time.time() - (25 * 60 * 60))
    monkeypatch.setattr(matcher, "_fetch_nvd", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")))

    assert matcher._lookup_nvd("Raspberry Pi", "Raspberry Pi 5 Model B", None) == high_cve
    _drain_nvd_worker(matcher)
    assert matcher._nvd_cache[key][1] == high_cve
    assert CveMatcher()._nvd_cache[key][1] == high_cve


def test_inflight_rolled_back_when_scheduling_fails(monkeypatch):
    """예약(스레드 시작/큐 put)이 실패하면 inflight 키를 롤백해야 한다. 롤백이 없으면 그 (vendor, model)
    의 NVD 보강이 프로세스 재시작까지 영구 차단된다(감사 확정 이슈). 예외는 요청으로 전파되지 않는다."""
    _with_fake_nvd(monkeypatch)
    matcher = CveMatcher()

    def _boom(*_args, **_kwargs):
        raise RuntimeError("can't start a new thread")

    monkeypatch.setattr(matcher, "_enqueue_nvd_fetch", _boom)
    key = matcher._nvd_cache_key("EFM Networks", "ipTIME BE3600QCA")
    # 예약 실패가 요청으로 새지 않고 [] 반환
    assert matcher._lookup_nvd("EFM Networks", "ipTIME BE3600QCA", None) == []
    # inflight 가 롤백돼 다음 조회가 다시 예약될 수 있어야 한다(영구 차단 금지)
    assert key not in matcher._nvd_inflight


def test_request_path_does_not_block_on_slow_nvd(monkeypatch):
    """회귀 가드(근본 원인): HG_NVD_LOOKUP=1 운영에서 getScanResult 가 기기마다 라이브 NVD 를
    동기 호출해 rate-limit 지연(키 없으면 호출당 ~6초)으로 모바일 8초 타임아웃을 넘겨
    "요청 시간이 초과됐습니다"(스캔 0대) 가 났다. match_device 는 NVD 가 아무리 느려도
    요청 스레드에서 즉시 반환해야 한다."""
    monkeypatch.setenv("HG_NVD_LOOKUP", "1")
    _with_fake_nvd(monkeypatch, delay=2.0)  # NVD 가 2초 걸리는 상황
    matcher = CveMatcher()
    start = time.perf_counter()
    matcher.match_device("EFM Networks", "ipTIME BE3600QCA", device_type="router")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"요청이 NVD 를 기다림({elapsed:.2f}s) — 8초 타임아웃 재발 위험"


def test_family_hub_underscore_resolves_to_family_hub_product_not_smartthings():
    """실제 냉장고 모델 'Family_HUB'(언더스코어, getInfo modelDisplayName 실측값)가 'family hub'
    제품으로 정규화 매칭되고, 'hub' 부분문자열로 'smartthings hub' 제품에 오매칭되지 않는다.

    카탈로그의 실제 CVE 유무와 무관하게 '제품 키 해석' 자체를 검증한다. (과거 이 자리에 있던
    CVE-2019-15799/CVE-2018-15399 는 NVD 대조 결과 각각 Zyxel GS1900 스위치/Cisco ASA 의 CVE 로
    밝혀진 환각 항목이라 카탈로그에서 제거됐다 — 그 가짜 CVE 에 의존하지 않도록 테스트를 정정함.)"""
    matcher = CveMatcher()
    samsung_data = matcher._catalog["vendors"]["samsung"]
    assert matcher._resolve_product(samsung_data, "Family_HUB") == "family hub"   # 언더스코어 정규화
    assert matcher._resolve_product(samsung_data, "Family Hub") == "family hub"   # 공백 변형도 동일
    assert matcher._resolve_product(samsung_data, "Family_HUB") != "smartthings hub"  # 'hub' 부분문자열 오매칭 금지


def test_catalog_match_unaffected_by_nvd_guard():
    """NVD 가드는 로컬 카탈로그 매칭에 영향을 주지 않는다(ipTIME NAS → CVE-2020-7847, 파일업로드 RCE)."""
    matcher = CveMatcher()
    matches = matcher.match_device("EFM Networks", "ipTIME NAS2dual", device_type="nas")
    cve_ids = [m.get("cve_id") for m in matches if m.get("source") == "catalog"]
    assert "CVE-2020-7847" in cve_ids


def test_vulnerable_server_banner_boa_flagged_even_without_vendor():
    """제조사 미상이어도 firmware/model 의 HTTP Server 배너가 known 취약 서버(Boa, 2005 단종)면
    CVE 를 잡아 위험을 놓치지 않는다. 실측: 사용자 LAN 의 192.168.1.1 공유기가 Boa/0.94.14rc21
    배너를 노출하는데 제조사 미확인이라 green 으로 오판(미탐)했음. CVE-2022-45956(HEAD 인증우회, CWE-863).
    """
    matcher = CveMatcher()
    hits = matcher.match_device(
        manufacturer="알 수 없음", model="Boa/0.94.14rc21", firmware="Boa 0.94.14rc21", device_type="router"
    )
    banner_hits = [h for h in hits if h.get("source") == "server_banner"]
    assert any(h.get("cve_id") == "CVE-2022-45956" for h in banner_hits)  # 미탐 방지
    # 오탐 방지: 일반/안전 배너(Httpd)는 잡지 않는다
    safe = matcher.match_device(manufacturer="EFM Networks", model="ipTIME", firmware="Httpd/1.0", device_type="router")
    assert not [h for h in safe if h.get("source") == "server_banner"]
    # firmware/model 없으면 배너 매칭 자체가 없다(빈 입력 안전)
    none_in = matcher.match_device(manufacturer="Samsung", model=None, firmware=None, device_type="phone")
    assert not [h for h in none_in if h.get("source") == "server_banner"]
    # 오탐 방지(부분문자열): 'boa' 가 'keyboard'·'boat' 안에 들어가도 배너로 오인하지 않는다(단어 경계).
    # 무선 키보드·boAt 스피커가 Boa 웹서버 CVE 로 거짓경보되면 사회적 약자에게 crying-wolf 가 된다.
    for benign in ("Wireless Keyboard K380", "boAt Stone 650 speaker", "Seaboard module"):
        fp = matcher.match_device(manufacturer=None, model=benign, firmware=None, device_type="unknown")
        assert not [h for h in fp if h.get("source") == "server_banner"], f"오탐: {benign}"
    # 진짜 Boa 배너는 firmware 단독('Server: Boa/0.94.13')으로도 잡힌다(경계 '/'·공백)
    fw_only = matcher.match_device(manufacturer=None, model=None, firmware="Server: Boa/0.94.13", device_type="router")
    assert any(h.get("cve_id") == "CVE-2022-45956" for h in fw_only if h.get("source") == "server_banner")

def test_every_catalog_product_is_reachable_by_device_type():
    """카탈로그의 모든 제품(CVE 보유)이 model 없이 device_type 만으로 매칭돼야 한다. 운영에서 기기는
    model 이 'LAN fingerprint' placeholder 인 경우가 많아, 제품 키가 _resolve_product 의 category_hints
    로 도달 불가능하면 그 CVE 는 영구 미탐(dead entry)이 된다. 새 제품 추가 시 종류 매핑 누락을 잡는다.
    """
    import json
    from pathlib import Path
    catalog_path = Path(__file__).resolve().parent.parent / "app" / "data" / "iot_cve_catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    matcher = CveMatcher()
    # 제품 키 → 운영에서 device_identity 가 내는 종류
    prod_type = {
        "smartthings hub": "hub", "webos tv": "tv", "ip camera": "camera", "archer router": "router",
        "tapo camera": "camera", "nas": "nas", "router": "router", "cam": "camera", "speaker": "speaker",
        "smart plug": "plug", "hue bridge": "hub", "family hub": "fridge",
    }
    unreachable = []
    for vendor_key, vendor in catalog["vendors"].items():
        alias = (vendor.get("aliases") or [vendor_key])[0]
        for product, cves in vendor.get("products", {}).items():
            if not cves:
                continue  # 빈 제품(향후 실 CVE 자리)은 검사 제외
            device_type = prod_type.get(product, "unknown")
            want = {c["cve_id"] for c in cves}
            got = {c.get("cve_id") for c in matcher.match_device(manufacturer=alias, model=None, device_type=device_type)}
            if not (want & got):
                unreachable.append((vendor_key, product, device_type))
    assert not unreachable, f"device_type 만으로 미도달(dead) 제품: {unreachable}"

def test_multi_source_cve_assembly_dedup():
    """한 기기가 벤더 카탈로그 CVE + generic_signals + 서버배너 CVE 를 동시에 트리거해도 세 소스가
    모두 조립되고 중복 없이 반환된다(후속58 검증을 회귀 가드로 고정)."""
    matcher = CveMatcher()
    hits = matcher.match_device(
        manufacturer="Hikvision", model="Boa/0.94.14rc21", firmware="Boa/0.94",
        risk_signals=["telnet_open", "rtsp_open", "default_credentials_possible"], device_type="camera",
    )
    sources = {h.get("source") for h in hits}
    assert {"catalog", "generic_signal", "server_banner"} <= sources  # 세 소스 모두
    ids = [h.get("cve_id") or h.get("signal") for h in hits]
    assert len(ids) == len(set(ids))  # 중복 0
    assert "CVE-2021-36260" in ids and "telnet_open" in ids and "CVE-2022-45956" in ids


def test_vendor_resolves_from_full_legal_manufacturer_name():
    """실기기는 UPnP/getInfo 로 전체 법인명을 보고한다(예 'Hangzhou Hikvision Digital Technology Co., Ltd.').
    _resolve_vendor 부분매칭(alias 가 법인명에 포함)이 이를 잡아 CVE 미탐을 막는다(후속56 회귀 가드)."""
    matcher = CveMatcher()
    cases = [
        ("Hangzhou Hikvision Digital Technology Co., Ltd.", "camera", "CVE-2017-7921"),
        ("ASUSTeK COMPUTER INC.", "router", "CVE-2017-6549"),
        ("Reolink Innovation Limited", "camera", "CVE-2020-25169"),
        ("Sonos, Inc.", "speaker", "CVE-2018-11316"),
    ]
    for manufacturer, device_type, expected in cases:
        ids = [c.get("cve_id") for c in matcher.match_device(manufacturer=manufacturer, model=None, device_type=device_type)]
        assert expected in ids, f"{manufacturer} 전체 법인명에서 {expected} 미탐"


def test_short_vendor_alias_does_not_match_inside_unrelated_word():
    """짧은 alias("lg" 2자, "hik" 3자)가 무관한 제조사명의 단어 *내부*에 우연히 박혀도 매칭하면 안 된다.
    단순 부분문자열이면 'lg'⊂'calgary'/'bulgari'/'belgian', 'hik'⊂'hikari' 가 LG/Hikvision 으로 오매칭돼,
    엉뚱한 기기에 그 벤더의 critical CVE 가 붙고 거짓 red 가 난다 → 단어 경계 매칭으로 차단."""
    matcher = CveMatcher()
    for manufacturer in ("Bulgari", "Belgian Telecom", "Calgary Scientific", "Algo Communication", "Hikari Networks"):
        assert matcher._resolve_vendor(manufacturer) is None, f"{manufacturer} 가 짧은 alias 부분문자열로 오매칭됨"
    # 단어 경계가 맞는 실제 벤더는 보존(영문 풀네임·한국어 풀네임 모두). CJK 는 \b 가 부정확해 부분문자열
    # 유지: "삼성"⊂"삼성전자" 는 매칭돼야(미탐 방지).
    assert matcher._resolve_vendor("LG Electronics") == "lg"
    assert matcher._resolve_vendor("Hangzhou Hikvision Digital Technology") == "hikvision"
    assert matcher._resolve_vendor("삼성전자") == "samsung"

