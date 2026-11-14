"""서버 중심 기기 식별 — 제품 카탈로그 + 광고 근거 + OUI 보조 조회.

5월회의 반영: 임시 네트워크 라벨만 보여 사용자가 위험을 이해하지 못한다는
멘토 지적에 대응. 단순 차단이 아니라 **검증된 제조사·모델명이 제대로 뜨는 것**이 목표다.

  - IEEE 등록 MA-L/MA-M/MA-S 전체(`backend/app/data/oui.csv`)를 로드해 MAC의
    36→28→24비트 최장 등록 접두사 순으로 제조사를 식별한다.
  - 모델명(native 가 mDNS/SSDP/HTTP 배너에서 추출한 model/nameHint)과 device_type 을 조합해
    "삼성 냉장고", "Hikvision 카메라" 같은 친숙한 이름을 만든다.
  - 서버 카탈로그와 품번이 맞으면 ``resolved``로 등록하고, 아직 맞지 않으면
    후보·근거·재검사 상태를 기록해 탐지 자체를 숨기지 않는다.
  - 보호자가 직접 별칭을 지정하면 항상 그것이 우선한다.

정직성: OUI/모델명은 보조 라벨이며 정확한 기기 식별을 보장하지 않는다.
"""

from __future__ import annotations

import csv
import functools
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import unicodedata
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

UNKNOWN_MAC_PREFIX = "UNKNOWN-"
OUI_CSV_PATH = Path(__file__).resolve().parent.parent / "data" / "oui.csv"
PRODUCT_CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "device_product_catalog.json"
_SERVER_REGISTRATION_PROOF = object()
_VERIFIED_CATALOG_HISTORY_PROOF = object()

# Repository-only proof for an appliance product family recovered from a
# recent, same-household observation.  A Family Hub refrigerator can stop
# answering Spotify ZeroConf while asleep; the proof is therefore limited to
# a same-scope, same-physical-MAC observation that previously contained the
# appliance's own structured getInfo response.  It is not a client-controlled
# string and never supplies a retail part number that the appliance did not
# advertise.
_VERIFIED_APPLIANCE_FAMILY_HISTORY_PROOF = object()

# 제조사 영어명 → 고령자에게 친숙한 한국어 표기(주요 brand 만; 나머지는 영어 brand 유지).
VENDOR_KO: dict[str, str] = {
    "Samsung": "삼성", "LG": "LG", "Apple": "애플", "Google": "구글",
    "Xiaomi": "샤오미", "TP-Link": "티피링크", "ASUS": "에이수스",
    "Netgear": "넷기어", "iptime(EFM)": "ipTIME", "EFM": "ipTIME",
    "Sony": "소니", "Tuya": "투야", "Hikvision": "하이크비전", "Dahua": "다후아",
    "KT": "KT",
    "Raspberry Pi": "Raspberry Pi",
    # OUI 등록기관명이 그대로 노출되면 고령자에게는 제품 제조사로
    # 이해하기 어렵다. OUI는 모델번호의 근거가 아니므로 모델은 계속
    # 비워 두고, 확인된 회사명만 친숙한 브랜드로 표기한다.
    "ASRock Incorporation": "ASRock",
    "Micro-Star INTL": "MSI",
    "Micro-Star INTL CO., LTD.": "MSI",
    "EFM Networks": "ipTIME",
}

# org name 안에 나타나면 그 brand 로 정규화할 키워드(긴 정식 회사명 → 친숙 brand).
VENDOR_KEYWORDS: dict[str, str] = {
    "samsung": "Samsung", "familyhub": "Samsung", "family hub": "Samsung", "family_hub": "Samsung",
    "lg electronics": "LG", "lge": "LG", "thinq": "LG", "lg-smart-device": "LG",
    "kt corporation": "KT", "kt corp": "KT", "olleh": "KT", "gigagenie": "KT",
    "apple": "Apple", "google": "Google", "nest": "Google",
    "xiaomi": "Xiaomi", "tp-link": "TP-Link", "tplink": "TP-Link",
    "asustek": "ASUS", "asus": "ASUS", "netgear": "Netgear",
    "hikvision": "Hikvision", "dahua": "Dahua", "tuya": "Tuya",
    "sony": "Sony", "nokia": "Nokia", "huawei": "Huawei", "amazon": "Amazon",
    "espressif": "Espressif", "raspberry": "Raspberry Pi", "intel": "Intel",
    "efm networks": "iptime(EFM)", "iptime": "iptime(EFM)",
    # 자기-광고 브랜드(mDNS 서비스타입/ONVIF 에 브랜드명이 그대로 실림). 빠져 있으면 제조사 미추출 →
    # CVE 매처가 vendor 를 못 풀어 미탐된다. 아래는 카탈로그에 CVE 가 있는 브랜드(미탐 직접 수정):
    "sonos": "Sonos", "reolink": "Reolink", "amcrest": "Amcrest", "wyze": "Wyze",
    "ezviz": "EZVIZ", "vivotek": "Vivotek", "foscam": "Foscam",
    # 브랜드 표시 개선(현재 카탈로그 CVE 는 없지만 사회적 약자에게 'Roborock 로봇청소기'처럼 명확):
    "roborock": "Roborock", "ecovacs": "Ecovacs",
    "nanoleaf": "Nanoleaf", "lifx": "LIFX", "yeelight": "Yeelight",
}

# 모델명 접두 → 제조사(예: 삼성 SM-/RF-/QN-, 멘토 예시 "SM 으로 뜨면 삼성").
MODEL_PREFIX_VENDOR: dict[str, str] = {
    "SM-": "Samsung", "RF": "Samsung", "QN": "Samsung", "UN": "Samsung",
    "WF": "Samsung", "WW": "Samsung", "RB": "Samsung",
    "OLED": "LG", "SQ": "LG", "RT-": "ASUS",
}

# AirPlay/RAOP publishes Apple hardware identifiers such as ``Mac15,6``.
# Match the complete identifier shape instead of adding a broad ``MAC`` prefix:
# arbitrary models such as ``machine123`` must never become Apple products.
APPLE_MAC_HARDWARE_MODEL_RE = re.compile(r"^Mac\d{1,3},\d{1,3}$", re.IGNORECASE)

DEVICE_TYPE_LABELS: dict[str, str] = {
    "camera": "카메라", "router": "공유기", "fridge": "냉장고", "tv": "TV",
    "speaker": "스피커", "audio": "오디오 기기", "lock": "도어록", "plug": "스마트 플러그",
    "hub": "스마트 허브", "phone": "휴대폰", "tablet": "태블릿", "computer": "컴퓨터", "nas": "NAS/저장장치",
    "printer": "프린터", "iot": "IoT 기기", "web-device": "네트워크 연결",
    "light": "스마트 조명", "robot": "로봇청소기", "thermostat": "온도조절기",
    "air_conditioner": "에어컨",
}

# The backend is the only component allowed to decide whether a scan has a
# household-product identity.  Scanner-side category hints (``web-device``,
# ``iot`` and ``unknown``) are deliberately not public identities.
IDENTITY_RESOLVER_VERSION = "server-identity-1.0.0"
IDENTITY_STATUS_RESOLVED = "resolved"
IDENTITY_STATUS_ENRICHING = "enriching"
IDENTITY_STATUS_UNRESOLVED = "unresolved"
IDENTITY_STATUS_MANUAL = "manual_resolved"
PUBLIC_IDENTITY_TYPES = frozenset(
    key for key in DEVICE_TYPE_LABELS if key not in {"web-device", "iot", "audio"}
)

# Model-code families are intentionally conservative.  A prefix is useful
# only when it is accompanied by a product-like code; it is never treated as
# a manufacturer by itself unless the rest of the observation corroborates it.
MODEL_PREFIX_DEVICE_TYPE: tuple[tuple[str, str], ...] = (
    ("RF", "fridge"), ("RB", "fridge"), ("FAMILY", "fridge"),
    ("QN", "tv"), ("UN", "tv"), ("OLED", "tv"), ("BRAVIA", "tv"),
    ("SQ", "air_conditioner"),
    ("SM-T", "tablet"), ("SM-", "phone"), ("IPHONE", "phone"), ("IPAD", "phone"),
    ("ARCHER", "router"), ("DECO", "router"), ("TL-", "router"),
    ("RT-", "router"), ("DSL-", "router"), ("ROG", "router"),
    ("NAS", "nas"), ("IPC-", "camera"), ("DS-", "camera"),
    ("NVR", "nas"), ("HOMEPOD", "speaker"), ("CHROMECAST", "tv"),
    # AirPlay/RAOP advertises Mac hardware identifiers (for example
    # ``Mac14,9``).  These are Apple computer model codes, not audio-product
    # names; resolving them here prevents an AirPlay endpoint from becoming
    # the misleading public label "오디오 기기".
    ("MAC", "computer"),
    ("ROBOROCK", "robot"), ("MJSX", "robot"),
)


_CATALOG_SOURCE_DATE_KINDS = {"published", "document_version", "retrieved"}
# A product fact may become global only when its source belongs to this
# explicit trust registry.  Host suffix matching is intentionally forbidden:
# ``sites.google.com`` and vendor-looking rented subdomains must never become
# official product evidence.  Supporting a new manufacturer therefore
# requires an explicit vendor/host entry and a bounded path rule here (and, for
# live HTTP lookup, a corresponding profile in official_product_sources.json).
_OFFICIAL_PRODUCT_SOURCE_HOSTS_BY_VENDOR: dict[str, frozenset[str]] = {
    "Raspberry Pi": frozenset(
        {"raspberrypi.com", "www.raspberrypi.com", "pip.raspberrypi.com"}
    ),
    "Sonos": frozenset({"sonos.com", "www.sonos.com", "support.sonos.com"}),
    "Apple": frozenset({"apple.com", "www.apple.com", "support.apple.com"}),
    "Samsung": frozenset(
        {"samsung.com", "www.samsung.com", "samsungsvc.co.kr", "www.samsungsvc.co.kr"}
    ),
    "LG": frozenset(
        {
            "lg.com",
            "www.lg.com",
            "lge.com",
            "www.lge.com",
            "lge.co.kr",
            "www.lge.co.kr",
            "apiv2.lge.co.kr",
        }
    ),
    "KT": frozenset({"kt.com", "www.kt.com", "product.kt.com"}),
    "iptime(EFM)": frozenset(
        {"iptime.com", "www.iptime.com", "efm-net.com", "www.efm-net.com"}
    ),
    "Xiaomi": frozenset({"mi.com", "www.mi.com", "xiaomi.com", "www.xiaomi.com"}),
    "TP-Link": frozenset({"tp-link.com", "www.tp-link.com"}),
    "ASUS": frozenset({"asus.com", "www.asus.com"}),
    "Netgear": frozenset({"netgear.com", "www.netgear.com", "kb.netgear.com"}),
    "Hikvision": frozenset(
        {"hikvision.com", "www.hikvision.com", "us-legacy.hikvision.com"}
    ),
    "Dahua": frozenset({"dahuasecurity.com", "www.dahuasecurity.com"}),
    "Sony": frozenset({"sony.com", "www.sony.com", "support.sony.com"}),
    "Google": frozenset(
        {"store.google.com", "support.google.com", "nest.com", "www.nest.com"}
    ),
    "Roborock": frozenset({"roborock.com", "www.roborock.com", "us.roborock.com"}),
    "Ecovacs": frozenset({"ecovacs.com", "www.ecovacs.com"}),
}

_OFFICIAL_PRODUCT_SOURCE_PATH_PATTERNS_BY_HOST: dict[str, tuple[str, ...]] = {
    "pip.raspberrypi.com": (r"/categories/[0-9a-z._/-]+",),
    "raspberrypi.com": (r"/(?:products|documentation)(?:/.*)?",),
    "www.raspberrypi.com": (r"/(?:products|documentation)(?:/.*)?",),
    "sonos.com": (r"/(?:[a-z]{2}-[a-z]{2}/)?(?:guides|products|support|shop)(?:/.*)?",),
    "www.sonos.com": (r"/(?:[a-z]{2}-[a-z]{2}/)?(?:guides|products|support|shop)(?:/.*)?",),
    "support.sonos.com": (
        r"/(?:products|article|articles|guides)(?:/.*)?",
        r"/[a-z]{2}(?:-[a-z]{2})?/products/[0-9a-z-]+/?",
    ),
    "apple.com": (r"/(?:mac|homepod|apple-tv|products|support)(?:/.*)?",),
    "www.apple.com": (r"/(?:mac|homepod|apple-tv|products|support)(?:/.*)?",),
    "support.apple.com": (
        r"/(?:[a-z]{2}(?:-[a-z]{2})?/)?[0-9]{5,}/?",
        r"/(?:search|products|guide|manuals)(?:/.*)?",
    ),
    "samsung.com": (
        r"/products(?:/.*)?",
        r"/(?:[a-z]{2}(?:_[a-z]{2})?|latin_en|sec)/(?:[^/]+)(?:/.*)?",
    ),
    "www.samsung.com": (
        r"/products(?:/.*)?",
        r"/(?:[a-z]{2}(?:_[a-z]{2})?|latin_en|sec)/(?:[^/]+)(?:/.*)?",
    ),
    "samsungsvc.co.kr": (r"/(?:products|product|support|download)(?:/.*)?",),
    "www.samsungsvc.co.kr": (r"/(?:products|product|support|download)(?:/.*)?",),
    "lg.com": (r"/(?:products|support)(?:/.*)?", r"/(?:global|[a-z]{2}(?:-[a-z]{2})?)/(?:[^/]+)(?:/.*)?"),
    "www.lg.com": (r"/(?:products|support)(?:/.*)?", r"/(?:global|[a-z]{2}(?:-[a-z]{2})?)/(?:[^/]+)(?:/.*)?"),
    "lge.com": (r"/(?:products|product|support|search)(?:/.*)?",),
    "www.lge.com": (r"/(?:products|product|support|search)(?:/.*)?",),
    "lge.co.kr": (r"/(?:products|product|support|search|tvs)(?:/.*)?",),
    "www.lge.co.kr": (r"/(?:products|product|support|search|tvs)(?:/.*)?",),
    "apiv2.lge.co.kr": (
        r"/searchsvc/ajax/v1/search/spt-psp-cst-sm-model",
    ),
    "kt.com": (r"/(?:products|product|support)(?:/.*)?",),
    "www.kt.com": (r"/(?:products|product|support)(?:/.*)?",),
    "product.kt.com": (
        r"/wdic/productdetail\.do/?",
        r"/(?:products|router)(?:/.*)?",
    ),
    "iptime.com": (r"/(?:iptime|products)(?:/.*)?",),
    "www.iptime.com": (r"/(?:iptime|products)(?:/.*)?",),
    "efm-net.com": (r"/(?:products|product|support)(?:/.*)?",),
    "www.efm-net.com": (r"/(?:products|product|support)(?:/.*)?",),
    "mi.com": (r"/(?:global/)?(?:products|product|search)(?:/.*)?",),
    "www.mi.com": (r"/(?:global/)?(?:products|product|search)(?:/.*)?",),
    "xiaomi.com": (r"/(?:global/)?(?:products|product|search)(?:/.*)?",),
    "www.xiaomi.com": (r"/(?:global/)?(?:products|product|search)(?:/.*)?",),
    "tp-link.com": (r"/products(?:/.*)?", r"/[a-z]{2}/(?:home-networking|support|search)(?:/.*)?"),
    "www.tp-link.com": (r"/products(?:/.*)?", r"/[a-z]{2}/(?:home-networking|support|search)(?:/.*)?"),
    "asus.com": (r"/products(?:/.*)?", r"/[a-z]{2}/(?:networking-iot-servers|support)(?:/.*)?"),
    "www.asus.com": (r"/products(?:/.*)?", r"/[a-z]{2}/(?:networking-iot-servers|support)(?:/.*)?"),
    "netgear.com": (r"/(?:home|support|search|products)(?:/.*)?",),
    "www.netgear.com": (r"/(?:home|support|search|products)(?:/.*)?",),
    "kb.netgear.com": (r"/(?:products|app|article|support)(?:/.*)?",),
    "sony.com": (r"/(?:electronics/support/product|products|support)(?:/.*)?",),
    "www.sony.com": (r"/(?:electronics/support/product|products|support)(?:/.*)?",),
    "support.sony.com": (r"/(?:products|product|support)(?:/.*)?",),
    "hikvision.com": (r"/(?:en/)?(?:products|product|search|support)(?:/.*)?",),
    "www.hikvision.com": (r"/(?:en/)?(?:products|product|search|support)(?:/.*)?",),
    "us-legacy.hikvision.com": (r"/sites/default/files/data_sheet/[0-9a-z._/-]+",),
    "dahuasecurity.com": (r"/(?:products|product|search|support)(?:/.*)?",),
    "www.dahuasecurity.com": (r"/(?:products|product|search|support)(?:/.*)?",),
    "store.google.com": (r"/(?:product|category|search)(?:/.*)?",),
    "support.google.com": (
        r"/(?:chromecast|googlenest|googletv|pixelphone)/answer/[1-9][0-9]{2,}/?",
    ),
    "nest.com": (r"/(?:products|product|support)(?:/.*)?",),
    "www.nest.com": (r"/(?:products|product|support)(?:/.*)?",),
    "roborock.com": (r"/(?:products|product|pages|support)(?:/.*)?",),
    "www.roborock.com": (r"/(?:products|product|pages|support)(?:/.*)?",),
    "us.roborock.com": (r"/(?:products|product|pages|support)(?:/.*)?",),
    "ecovacs.com": (r"/(?:products|product|support|[a-z]{2}/shop)(?:/.*)?",),
    "www.ecovacs.com": (r"/(?:products|product|support|[a-z]{2}/shop)(?:/.*)?",),
}

_OFFICIAL_PRODUCT_SOURCE_BLOCKED_PATH_SEGMENTS = frozenset(
    {
        "community",
        "discussions",
        "forum",
        "forums",
        "groups",
        "login",
        "out",
        "post",
        "posts",
        "question",
        "questions",
        "redirect",
        "redirector",
        "thread",
        "threads",
        "usercontent",
        "user",
        "users",
    }
)
_VERIFIED_CATALOG_OVERLAY_PROVENANCES = frozenset(
    {
        "operator-reviewed",
        "automated-official-web-search",
        "automated-official-http",
    }
)
_OPTIONAL_LITERAL_MODEL_GROUP = re.compile(r"\(\?:[0-9A-Za-z._/+:-]+\)\?")


def canonical_registered_official_product_source(
    source: object,
    manufacturer: object,
) -> str | None:
    """Return a stable URL only for one explicitly trusted product source.

    Trust is a tuple of canonical manufacturer, exact FQDN, standard HTTPS
    port and an allow-listed path shape.  The only accepted query is the
    language-only ``hl`` parameter on a Google support article already used by
    the static catalog; it is stripped from the returned stable URL.  No query
    is ever persisted in a dynamic catalog row.
    """

    text = str(source or "").strip()
    if not text or len(text) > 2048:
        return None
    try:
        parsed = urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        return None
    host = str(parsed.hostname).strip(".").casefold()
    maker = normalize_vendor_name(str(manufacturer or "").strip())
    trusted_hosts = _OFFICIAL_PRODUCT_SOURCE_HOSTS_BY_VENDOR.get(maker)
    if not trusted_hosts or host not in trusted_hosts:
        return None

    path = parsed.path or "/"
    if (
        not path.startswith("/")
        or "%" in path
        or "\\" in path
        or "//" in path
        or "\x00" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
    ):
        return None
    path_key = path.casefold()
    path_segments = {segment for segment in path_key.split("/") if segment}
    if path_segments & _OFFICIAL_PRODUCT_SOURCE_BLOCKED_PATH_SEGMENTS:
        return None
    patterns = _OFFICIAL_PRODUCT_SOURCE_PATH_PATTERNS_BY_HOST.get(host, ())
    if not patterns or not any(re.fullmatch(pattern, path_key) for pattern in patterns):
        return None

    if parsed.query:
        # The existing Google catalog reference carries only a presentation
        # language.  Accept and remove exactly that harmless shape; tracking,
        # search, model, resident and arbitrary query data remain rejected.
        if not (
            host == "support.google.com"
            and re.fullmatch(r"hl=[a-z]{2}(?:-[a-z]{2})?", parsed.query.casefold())
        ):
            return None
    return urlunsplit(("https", host, path, "", ""))


def is_registered_official_product_source(
    source: object,
    manufacturer: object,
) -> bool:
    """Return whether *source* is already in the strict persisted URL shape."""

    try:
        parsed = urlsplit(str(source or "").strip())
    except ValueError:
        return False
    return (
        not parsed.query
        and not parsed.fragment
        and canonical_registered_official_product_source(source, manufacturer)
        is not None
    )


def _is_conservative_catalog_model_pattern(value: str) -> bool:
    """Accept only bounded, whole-model regular expressions.

    The product catalog is curated rather than user supplied, but rejecting
    wildcard-style patterns here prevents a later catalog edit from turning a
    structured vendor hint into an arbitrary exact model match.
    """

    pattern = value.strip()
    if not (
        3 <= len(pattern) <= 160
        and pattern.startswith("^")
        and pattern.endswith("$")
    ):
        return False

    # The accepted grammar describes only a finite set of literal model codes.
    # ``\\s+`` permits harmless spacing differences, and a non-capturing
    # optional group permits a documented suffix such as ``(?:NS-M)?``.  Broad
    # character classes, alternation, captures and arbitrary repetition are
    # deliberately rejected even when the expression is anchored.
    body = pattern[1:-1]
    body = _OPTIONAL_LITERAL_MODEL_GROUP.sub("", body)
    body = body.replace(r"\s+", " ")
    # DB overlay entries deliberately use ``^re.escape(model)$``. Accept only
    # escaped forms of the same finite literal punctuation; regex operators,
    # character classes and unbounded repetition remain invalid.
    body = re.sub(r"\\([ .,_/+:\-])", r"\1", body)
    if any(character in body for character in r"\\[]{}()*+?|"):
        return False
    return bool(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z .,_/+:-]*", body))


def _validated_product_catalog_entry(raw: Any) -> dict[str, Any] | None:
    """Validate one provenance-bearing catalog entry.

    Catalog metadata is intentionally mandatory.  Exact model patterns are
    accepted only when the entry also lists at least one model copied from the
    cited official source and every regex is exercised by such a model.  This
    is a local integrity check; runtime scans never fetch manufacturer sites.
    """

    if not isinstance(raw, dict):
        return None
    required = (
        "catalog_id",
        "manufacturer",
        "display_manufacturer",
        "product_label",
        "device_type",
        "catalog_scope",
        "source_url",
        "source_title",
        "source_version",
        "source_date",
        "source_date_kind",
        "verified_at",
    )
    if not all(str(raw.get(key) or "").strip() for key in required):
        return None

    manufacturer = str(raw["manufacturer"]).strip()
    source_url = canonical_registered_official_product_source(
        raw["source_url"], manufacturer
    )
    if source_url is None:
        return None
    try:
        source_date = date.fromisoformat(str(raw["source_date"]).strip())
        verified_at = date.fromisoformat(str(raw["verified_at"]).strip())
    except ValueError:
        return None
    if verified_at < source_date:
        return None
    source_date_kind = str(raw["source_date_kind"]).strip()
    if source_date_kind not in _CATALOG_SOURCE_DATE_KINDS:
        return None

    patterns = raw.get("model_patterns")
    aliases = raw.get("aliases")
    verified_models = raw.get("verified_models")
    if not isinstance(patterns, list) or not isinstance(aliases, list) or not isinstance(verified_models, list):
        return None
    cleaned_patterns = [str(value).strip() for value in patterns if str(value).strip()]
    cleaned_aliases = [str(value).strip().lower() for value in aliases if str(value).strip()]
    cleaned_models = [str(value).strip() for value in verified_models if str(value).strip()]
    if (
        not cleaned_aliases
        or len(cleaned_aliases) != len(set(cleaned_aliases))
        or len(cleaned_models) != len(set(cleaned_models))
        or len(cleaned_patterns) != len(set(cleaned_patterns))
        or any(not _is_conservative_catalog_model_pattern(pattern) for pattern in cleaned_patterns)
    ):
        return None

    compiled_patterns: list[re.Pattern[str]] = []
    try:
        compiled_patterns = [re.compile(pattern, flags=re.IGNORECASE) for pattern in cleaned_patterns]
    except re.error:
        return None

    catalog_scope = str(raw["catalog_scope"]).strip()
    if catalog_scope == "official_model_pattern":
        if not compiled_patterns or not cleaned_models:
            return None
        if any(not any(pattern.fullmatch(model) for model in cleaned_models) for pattern in compiled_patterns):
            return None
        if any(not any(pattern.fullmatch(model) for pattern in compiled_patterns) for model in cleaned_models):
            return None
    elif catalog_scope == "official_family_only":
        if compiled_patterns or cleaned_models:
            return None
    else:
        return None

    return {
        "catalog_id": str(raw["catalog_id"]).strip(),
        "manufacturer": manufacturer,
        "display_manufacturer": str(raw["display_manufacturer"]).strip(),
        "product_label": str(raw["product_label"]).strip(),
        "device_type": str(raw["device_type"]).strip(),
        "catalog_scope": catalog_scope,
        "model_patterns": cleaned_patterns,
        "verified_models": cleaned_models,
        "aliases": cleaned_aliases,
        "source_url": source_url,
        "source_title": str(raw["source_title"]).strip(),
        "source_version": str(raw["source_version"]).strip(),
        "source_date": str(raw["source_date"]).strip(),
        "source_date_kind": source_date_kind,
        "verified_at": str(raw["verified_at"]).strip(),
    }


@functools.lru_cache(maxsize=1)
def _load_product_catalog() -> tuple[dict[str, Any], ...]:
    """Load the server-owned product catalog once per process.

    The catalog is deliberately local and versioned with the API.  A scan is
    never sent to an arbitrary third-party search provider, and a model is
    never invented from a port number.  New products can be added to this
    file and become available to the next scan without changing the mobile
    client contract.
    """
    try:
        with PRODUCT_CATALOG_PATH.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as exc:
        raise RuntimeError(
            f"device product catalog could not be read: {PRODUCT_CATALOG_PATH}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            f"device product catalog is not valid JSON: {PRODUCT_CATALOG_PATH}"
        ) from exc
    if not isinstance(payload, list):
        raise RuntimeError("device product catalog root must be a JSON array")
    if not payload:
        raise RuntimeError("device product catalog must contain provenance entries")
    entries: list[dict[str, Any]] = []
    catalog_ids: set[str] = set()
    for index, raw in enumerate(payload):
        entry = _validated_product_catalog_entry(raw)
        if entry is None:
            catalog_id = str(raw.get("catalog_id") or "<missing>") if isinstance(raw, dict) else "<invalid>"
            raise RuntimeError(
                "device product catalog entry failed provenance validation: "
                f"index={index}, catalog_id={catalog_id}"
            )
        if entry["catalog_id"] in catalog_ids:
            raise RuntimeError(
                "device product catalog contains duplicate catalog_id: "
                f"{entry['catalog_id']}"
            )
        catalog_ids.add(entry["catalog_id"])
        entries.append(entry)
    return tuple(entries)


def _verified_catalog_overlay_key(value: object, *, manufacturer: bool = False) -> str:
    """Use the same NFKC/casefold key contract as verified catalog storage."""

    text = str(value or "").strip()
    if manufacturer:
        text = normalize_vendor_name(text)
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text)).casefold()


def _verified_catalog_overlay_id(
    manufacturer: object,
    exact_model: object,
    device_type: object,
) -> str:
    digest_payload = "\x1f".join(
        (
            _verified_catalog_overlay_key(manufacturer, manufacturer=True),
            _verified_catalog_overlay_key(exact_model),
            str(device_type or "").strip().casefold(),
        )
    )
    return "verified-product-" + hashlib.sha256(
        digest_payload.encode("utf-8")
    ).hexdigest()[:24]


def _validated_verified_catalog_overlay_entry(raw: Any) -> dict[str, Any] | None:
    """Convert one repository-verified global product row to catalog schema.

    The repository verifies ``catalog_signature`` before returning a row.  The
    resolver repeats that HMAC check at this boundary so an accidental direct
    caller cannot turn a merely well-shaped row into a trusted product fact.
    """

    if not isinstance(raw, dict):
        return None
    required = (
        "manufacturer",
        "manufacturer_key",
        "exact_model",
        "model_key",
        "device_type",
        "source_url",
        "provenance",
        "verified_at",
        "catalog_signature",
    )
    if not all(str(raw.get(key) or "").strip() for key in required):
        return None
    # Lazy import avoids the module-import cycle: identity_enrichment uses the
    # device identity validators while its catalog verifier is needed only
    # when a runtime overlay is actually supplied.
    try:
        from .identity_enrichment import verified_product_catalog_entry_matches

        if not verified_product_catalog_entry_matches(raw):
            return None
    except (ImportError, RuntimeError, TypeError, ValueError):
        return None

    manufacturer = normalize_vendor_name(str(raw["manufacturer"]).strip())
    exact_model = str(raw["exact_model"]).strip()
    device_type = str(raw["device_type"]).strip().casefold()
    provenance = str(raw["provenance"]).strip()
    signature = str(raw["catalog_signature"]).strip().casefold()
    verified_at_raw = str(raw["verified_at"]).strip()
    try:
        if "T" in verified_at_raw:
            verified_date = datetime.fromisoformat(
                verified_at_raw.replace("Z", "+00:00")
            ).date()
        else:
            verified_date = date.fromisoformat(verified_at_raw)
    except ValueError:
        return None
    if (
        _verified_catalog_overlay_key(manufacturer, manufacturer=True)
        != str(raw["manufacturer_key"]).strip().casefold()
        or _verified_catalog_overlay_key(exact_model)
        != str(raw["model_key"]).strip().casefold()
        or provenance not in _VERIFIED_CATALOG_OVERLAY_PROVENANCES
        or not re.fullmatch(r"[0-9a-f]{64}", signature)
        or not is_product_manufacturer(manufacturer)
        or not is_concrete_product_model(exact_model, manufacturer)
        or device_type not in PUBLIC_IDENTITY_TYPES
    ):
        return None

    display_manufacturer = VENDOR_KO.get(manufacturer, manufacturer)
    type_label = DEVICE_TYPE_LABELS.get(device_type)
    if not display_manufacturer or not type_label:
        return None
    aliases = list(
        dict.fromkeys(
            str(alias).strip().casefold()
            for alias in (manufacturer, display_manufacturer)
            if str(alias).strip()
        )
    )
    catalog_id = _verified_catalog_overlay_id(
        manufacturer, exact_model, device_type
    )
    candidate = {
        "catalog_id": catalog_id,
        "manufacturer": manufacturer,
        "display_manufacturer": display_manufacturer,
        "product_label": f"{display_manufacturer} {type_label}",
        "device_type": device_type,
        "catalog_scope": "official_model_pattern",
        "model_patterns": [f"^{re.escape(exact_model)}$"],
        "verified_models": [exact_model],
        "aliases": aliases,
        "source_url": str(raw["source_url"]).strip(),
        "source_title": f"{display_manufacturer} {exact_model} 공식 제품 출처",
        "source_version": provenance,
        "source_date": verified_date.isoformat(),
        "source_date_kind": "retrieved",
        "verified_at": verified_date.isoformat(),
    }
    entry = _validated_product_catalog_entry(candidate)
    if entry is None:
        return None
    entry["catalog_origin"] = "verified_product_catalog_overlay"
    entry["resolution_provenance"] = provenance
    return entry


def _product_catalog_with_overlay(
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
) -> tuple[dict[str, Any], ...]:
    """Merge DB rows after static entries without weakening static facts.

    Static entries are authoritative for an existing maker/model pair. An
    overlay with that pair is suppressed whether its type agrees or conflicts.
    Conflicting duplicate overlay rows are dropped as a group rather than
    selecting one based on input order.
    """

    static_entries = _load_product_catalog()
    if catalog_entries is None or not isinstance(catalog_entries, (list, tuple)):
        return static_entries

    static_pairs: set[tuple[str, str]] = set()
    for entry in static_entries:
        maker_key = _verified_catalog_overlay_key(
            entry.get("manufacturer"), manufacturer=True
        )
        for model in entry.get("verified_models", []):
            static_pairs.add((maker_key, _verified_catalog_overlay_key(model)))

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for raw in catalog_entries:
        entry = _validated_verified_catalog_overlay_entry(raw)
        if entry is None:
            continue
        pair = (
            _verified_catalog_overlay_key(entry["manufacturer"], manufacturer=True),
            _verified_catalog_overlay_key(entry["verified_models"][0]),
        )
        if pair in static_pairs:
            continue
        grouped.setdefault(pair, []).append(entry)

    overlay_entries: list[dict[str, Any]] = []
    for pair in sorted(grouped):
        entries = grouped[pair]
        if len({str(entry["device_type"]) for entry in entries}) != 1:
            continue
        overlay_entries.append(min(entries, key=lambda entry: str(entry["catalog_id"])))
    return (*static_entries, *overlay_entries)

# native fingerprint 에서 MAC 을 추출한다. mDNS 응답 이름에 MAC 이 실려 오는 경우가 있다:
#   "mdns-name:<이름> [AA:BB:CC:DD:EE:FF]"  /  "mdns-name:AABBCCDDEEFF"(구분자 없는 12자리)
# Android 는 /proc/net/arp 가 막혀 ARP MAC 을 못 얻지만, mDNS 광고 이름의 MAC 은 살릴 수 있다.
_FP_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}")
_FP_BARE_MAC_RE = re.compile(r"^[0-9A-Fa-f]{12}$")

_NEIGHBOR_MAC_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"\S+\s+(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+\S+"
)
_LOCAL_NEIGHBOR_CACHE: dict[str, tuple[float, str | None]] = {}
_LOCAL_NEIGHBOR_CACHE_TTL_SECONDS = 15.0
_SAFE_NEIGHBOR_PROBE_PORTS = (80, 139, 445, 443, 1900, 17654)


def _read_local_neighbor_mac(ip_address: str) -> str | None:
    """Read one MAC from the server's local ARP table without exposing it.

    Android cannot reliably read ``/proc/net/arp``.  The Raspberry Pi backend
    is on the same home LAN, so it can use its own kernel neighbour table as a
    second evidence source.  This is only an internal OUI input; the public
    DevicePresentation boundary still removes the address.
    """
    try:
        target = ipaddress.ip_address(ip_address)
    except ValueError:
        return None
    if target.version != 4 or not target.is_private:
        return None
    try:
        lines = Path("/proc/net/arp").read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return None
    for line in lines:
        match = _NEIGHBOR_MAC_RE.search(line.strip())
        if not match or match.group("ip") != str(target):
            continue
        mac = match.group("mac").upper()
        if mac != "00:00:00:00:00:00":
            return mac
    return None


def local_neighbor_mac(ip_address: str, open_ports: list[int] | tuple[int, ...] = ()) -> str | None:
    """Resolve an observed private host's MAC using the backend LAN.

    The first lookup is passive.  If the kernel has not populated ARP yet,
    make at most four short TCP connects to ports the scanner already observed
    (plus the common discovery ports).  No port is promoted to a product name;
    this only lets the existing IEEE OUI resolver recover the manufacturer.
    """
    try:
        target = ipaddress.ip_address(str(ip_address).strip())
    except ValueError:
        return None
    if target.version != 4 or not target.is_private:
        return None
    key = str(target)
    now = time.monotonic()
    cached = _LOCAL_NEIGHBOR_CACHE.get(key)
    if cached and now - cached[0] < _LOCAL_NEIGHBOR_CACHE_TTL_SECONDS:
        return cached[1]

    mac = _read_local_neighbor_mac(key)
    if mac is None:
        candidates: list[int] = []
        for port in (*open_ports, *_SAFE_NEIGHBOR_PROBE_PORTS):
            try:
                value = int(port)
            except (TypeError, ValueError):
                continue
            if value in _SAFE_NEIGHBOR_PROBE_PORTS and value not in candidates:
                candidates.append(value)
            if len(candidates) >= 4:
                break
        for port in candidates:
            try:
                with socket.create_connection((key, port), timeout=0.18):
                    pass
            except OSError:
                continue
            mac = _read_local_neighbor_mac(key)
            if mac is not None:
                break
    _LOCAL_NEIGHBOR_CACHE[key] = (now, mac)
    return mac

# mDNS service type / SSDP 신호 → device_type. native 가 종류를 단정(예: spotify→speaker)하지 않게
# 백엔드가 신호로 재판정한다. 키는 fingerprint/service 문자열(소문자)에 포함되는 토큰(순서=우선순위).
_SIGNAL_DEVICE_TYPE: list[tuple[str, str]] = [
    # 가전 제품명(명확) — 기능 신호(spotify-connect 등 겸용 기능)보다 우선해야 한다.
    # 삼성 패밀리허브 getInfo modelDisplayName 실측값은 "Family_HUB"(언더스코어). 표기 변형 모두 수용.
    ("familyhub", "fridge"), ("family hub", "fridge"), ("family_hub", "fridge"),
    ("refrigerator", "fridge"), ("냉장고", "fridge"),
    # LG ThinQ service is shared by several appliance families.  Only an
    # explicit AC/product token is strong enough to classify it as an AC.
    ("air_conditioner", "air_conditioner"), ("air-conditioner", "air_conditioner"),
    ("air conditioner", "air_conditioner"), ("aircon", "air_conditioner"),
    ("air_con", "air_conditioner"), ("lg_ac", "air_conditioner"),
    ("lge_ac", "air_conditioner"), ("smart-air", "air_conditioner"),
    ("internetgatewaydevice", "router"),
    ("wanconnectiondevice", "router"),
    ("_workstation", "computer"),
    ("_googlecast", "tv"), ("chromecast", "tv"),
    ("_airplay", "tv"), ("appletv", "tv"), ("apple-tv", "tv"),
    ("_androidtvremote", "tv"), ("samsungmsf", "tv"), ("samsungtv", "tv"),
    # Spotify getInfo 의 deviceType(구체값) → 종류. 구체 타입이 있으면 그걸 쓴다.
    ("spotify-type:tv", "tv"), ("spotify-type:computer", "computer"),
    ("spotify-type:cast_video", "tv"), ("spotify-type:stb", "tv"),
    ("spotify-type:avr", "audio"), ("spotify-type:speaker", "speaker"),
    ("spotify-type:audio_dongle", "speaker"), ("spotify-type:cast_audio", "speaker"),
    # 주의: 구체 타입이 없는 일반 _spotify-connect 만으로는 종류를 단정하지 않는다.
    # Spotify Connect 는 스피커뿐 아니라 TV·AVR·냉장고(삼성 패밀리허브)·자동차에도 실리므로
    # "audio"로 추정하면 휴면(getInfo 미응답) 냉장고가 '오디오 기기'로 오탐된다. → 종류 미상으로 둔다.
    # RAOP stays an internal protocol category only; ``audio`` is excluded from
    # public product types below. Sonos still requires an exact advertised model,
    # and a resolved Sonos product is presented as a speaker.
    ("_raop", "audio"), ("sonos", "speaker"),
    ("_ipp", "printer"), ("_printer", "printer"), ("officejet", "printer"), ("laserjet", "printer"),
    ("_axis-video", "camera"), ("_onvif", "camera"), ("_rtsp", "camera"),
    ("networkvideotransmitter", "camera"),
    # _hap/_homekit/_matter 는 전구·도어락·플러그 등 모든 종류가 쓰는 프로토콜이라 'hub' 로 단정하면
    # 오탐이다. 실제 허브(Bridge)는 위 ci 검사(ci=2)에서 'hub' 로 잡힌다. ci 미캡처 시엔 종류 미상이므로
    # 'hub' 가 아니라 정직한 일반값 'iot'(IoT 기기)로 둔다. smartthings 는 허브 '제품'이라 hub 유지.
    ("_hap", "iot"), ("_homekit", "iot"), ("_matter", "iot"), ("smartthings", "hub"),
    # 최신 IoT 종류 보강(스마트조명·음성비서·로봇청소기·도어록·온도조절기·스마트플러그)
    # _hue._tcp 는 Philips Hue '브리지'가 광고하는 서비스다(전구는 Zigbee 라 IP 가 없음) → 허브.
    # 전구 자체는 HomeKit 노출 시 위 ci=5 로 light 가 된다. nanoleaf/lifx/yeelight 는 직접 WiFi 조명이라 light 유지.
    ("_hue", "hub"), ("nanoleaf", "light"), ("lifx", "light"), ("yeelight", "light"),
    ("_amzn", "speaker"), ("alexa", "speaker"), ("echo-", "speaker"), ("nest-audio", "speaker"), ("nestmini", "speaker"),
    ("_roku", "tv"), ("_viziocast", "tv"), ("webos", "tv"),
    # DIAL(urn:dial-multiscreen-org, SSDP ST 로 광고) 은 스마트TV·셋톱박스 등 '영상 표시/캐스팅 타겟'
    # 전용 프로토콜이라 tv. 스피커(HomePod/Sonos/Nest)는 DIAL 을 광고하지 않아 오탐 위험 낮음.
    # MediaRenderer 는 TV·AVR·사운드바(오디오)가 함께 써 모호하므로 매핑하지 않는다(오디오 오탐 방지).
    ("dial-multiscreen", "tv"),
    ("_august", "lock"), ("doorlock", "lock"), ("smartlock", "lock"), ("samsung-shp", "lock"), ("도어락", "lock"), ("도어록", "lock"),
    ("roborock", "robot"), ("ecovacs", "robot"), ("vacuum", "robot"), ("로봇청소기", "robot"),
    ("ecobee", "thermostat"), ("nest-thermostat", "thermostat"), ("thermostat", "thermostat"),
    ("_kasa", "plug"), ("smartplug", "plug"), ("hs100", "plug"), ("hs110", "plug"),
    ("_miio", "iot"),
]

# 제조사 placeholder(실제 브랜드 아님) — 이름에 그대로 쓰면 "OUI 확인 필요 공유기" 같은 전문용어가
# 노출돼 사회적 약자가 못 알아본다. 구버전 스캐너가 남긴 "OUI 확인 필요" 등도 미상으로 처리한다.
_GENERIC_MANUFACTURERS = {
    "", "알 수 없음", "확인 안 됨", "unknown", "lan fingerprint", "none", "oui 확인 필요", "확인 필요",
}
_GENERIC_MODELS = {"", "lan fingerprint", "unknown", "none"}

# Product families and protocol/platform names are useful search clues, but
# they are not a model number.  A family token may coexist with a concrete
# model in separate advertisements (for example Spotify ``Family Hub`` plus
# UPnP ``RF85C90``); in that case the concrete model wins.  A family token by
# itself must remain an unresolved observation.
_FAMILY_ONLY_MODEL_KEYS = frozenset(
    {
        "audio",
        "bravia",
        "camera",
        "chromecast",
        "computer",
        "familyhub",
        "googletv",
        "homepod",
        "iot",
        "printer",
        "raspberrypi",
        "refrigerator",
        "roborock",
        "router",
        "rpi",
        "sonos",
        "speaker",
        "television",
        "tv",
    }
)

_FAMILY_HUB_ALIASES = frozenset({"familyhub", "family hub", "family_hub"})


def _is_family_hub_alias(value: object) -> bool:
    """Return whether a value names the Family Hub product family only."""
    compact = re.sub(r"[\s_-]+", "", _clean(value)).casefold()
    return compact in {
        re.sub(r"[\s_-]+", "", alias).casefold()
        for alias in _FAMILY_HUB_ALIASES
    }
_NON_PRODUCT_MANUFACTURER_KEYS = frozenset(
    {
        "broadcom",
        "espressif",
        "intel",
        "mediatek",
        "qualcomm",
        "realtek",
        "seongji",
    }
)
_NON_PRODUCT_MODEL_PREFIXES = (
    "esp32",
    "esp8266",
    "rtl",
)
_SERVER_SOFTWARE_MODEL_TOKENS = (
    "apache",
    "boa/",
    "busybox",
    "caddy",
    "httpd",
    "lighttpd",
    "nginx",
    "openresty",
    "x-powered-by",
)
_NAMED_PRODUCT_MODEL_KEYS_BY_MANUFACTURER: dict[str, frozenset[str]] = {
    "Apple": frozenset({"homepodmini"}),
    "Google": frozenset({"chromecastultra", "nestaudio", "nestmini"}),
    "Sonos": frozenset(
        {
            "amp",
            "arc",
            "beam",
            "five",
            "move",
            "playbar",
            "playbase",
            "port",
            "ray",
            "roam",
            "sonosamp",
            "sonosarc",
            "sonosbeam",
            "sonosfive",
            "sonosmove",
            "sonosone",
            "sonosport",
            "sonosray",
            "sonosroam",
            "sonossub",
            "sub",
        }
    ),
}
_RASPBERRY_PI_BOARD_MODEL_RE = re.compile(
    r"^Raspberry\s+Pi\s+\d+\s+Model\s+[A-Za-z]+(?:\s+Rev(?:ision)?\s+[0-9A-Za-z.]+)?$",
    flags=re.IGNORECASE,
)

# Spotify Connect getInfo 의 brandDisplayName/modelDisplayName 이 OSS 소프트웨어 리시버
# (librespot/go-librespot/spotifyd 등) 기본값이면 실제 하드웨어 OEM 이 아니다 → 제조사로 쓰지 않는다.
# 예: Raspberry Pi 에서 raspotify 가 돌면 brandDisplayName="librespot" 이지만 제조사는 Raspberry Pi.
_SOFTWARE_RECEIVER_BRANDS = {
    "librespot", "go-librespot", "go librespot", "golibrespot", "devgianlu",
    "spotifyd", "raspotify", "spocon", "vollibrespot", "spotify",
}

# org name 에서 떼어낼 회사 접미사/수식어(친숙 brand 추출용).
_VENDOR_SUFFIX_RE = re.compile(
    r"\s+(Co\.?|Ltd\.?|Inc\.?|Corp\.?|Corporation|LLC|GmbH|Limited|Company|"
    r"Technologies|Technology|Electronics?|Digital|Communications?|International|"
    r"Headquarters|Networks?|Systems?|Group|Holdings?|Indust(?:ry|ries))\b.*$",
    re.IGNORECASE,
)


_IEEE_REGISTRY_PREFIX_LENGTHS = {"MA-L": 6, "MA-M": 7, "MA-S": 9}


@functools.lru_cache(maxsize=1)
def _load_oui_db() -> dict[str, str]:
    """IEEE MA-L/MA-M/MA-S CSV를 접두사 길이를 보존해 최초 1회 로드한다.

    갱신 스크립트는 세 공식 CSV를 동일 헤더의 단일 파일로 병합한다. 예전
    MA-L 전용 파일도 읽을 수 있지만 Assignment를 24비트로 잘라 저장하지
    않으므로 더 구체적인 MA-M(28비트)·MA-S(36비트) 등록이 가려지지 않는다.
    """
    db: dict[str, str] = {}
    ambiguous_prefixes: set[str] = set()
    if not OUI_CSV_PATH.exists():
        return db
    try:
        with OUI_CSV_PATH.open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            next(reader, None)  # header: Registry,Assignment,Organization Name,Organization Address
            for row in reader:
                if len(row) >= 3:
                    registry = row[0].strip().upper()
                    prefix = row[1].strip().upper().replace(":", "").replace("-", "")
                    org = row[2].strip().strip('"')
                    expected_length = _IEEE_REGISTRY_PREFIX_LENGTHS.get(registry)
                    if (
                        expected_length is not None
                        and len(prefix) == expected_length
                        and all(character in "0123456789ABCDEF" for character in prefix)
                        and org
                    ):
                        if prefix in ambiguous_prefixes:
                            continue
                        previous = db.get(prefix)
                        if previous is None:
                            db[prefix] = org
                        elif previous != org:
                            # IEEE's public files retain a few historic
                            # assignments with multiple organizations.  Such a
                            # prefix is not a safe manufacturer fact; keep the
                            # device visible but leave its maker unresolved.
                            db.pop(prefix, None)
                            ambiguous_prefixes.add(prefix)
    except (OSError, UnicodeError, csv.Error):  # pragma: no cover
        return {}
    return db


def normalize_vendor_name(org_name: str) -> str:
    """긴 정식 회사명을 친숙한 brand 로 정규화. 예: 'Samsung Electronics Co.,Ltd' → 'Samsung'."""
    text = " ".join(
        unicodedata.normalize("NFKC", org_name).strip().strip('"').split()
    )
    lower = text.lower()
    # EFM is the corporation behind the ipTIME product brand.  Treat its OUI
    # name, product brand and the historical combined spelling as one catalog
    # maker key so a DB overlay cannot shadow the same static ipTIME product.
    if lower in {"efm", "efm networks", "iptime(efm)", "iptime (efm)"}:
        return "iptime(EFM)"
    for keyword, vendor in VENDOR_KEYWORDS.items():
        if keyword in lower:
            return vendor
    head = text.split(",")[0].strip()
    cleaned = _VENDOR_SUFFIX_RE.sub("", head).strip()
    result = cleaned or head
    words = result.split()
    if len(words) > 3:
        result = " ".join(words[:3])
    return result or text[:30]


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


# IEEE OUI 에 '실제 브랜드가 아닌' 등록값. 사용자(사회적 약자)에게 제조사로 노출하면 의미 불명이고,
# MA-L의 'IEEE Registration Authority'는 MA-M/MA-S 하위 접두사의 실제 등록
# 조직이 아니므로, 최장 접두사에도 실제 조직이 없을 때 제품 제조사에서 제외한다.
_NON_BRAND_OUI_ORGS = {"private", "ieee registration authority"}


def vendor_from_oui(mac: str) -> str | None:
    hexmac = mac.upper().replace("-", "").replace(":", "")
    if len(hexmac) != 12 or any(character not in "0123456789ABCDEF" for character in hexmac):
        return None
    first_octet = int(hexmac[:2], 16)
    # Multicast and locally administered/randomized addresses do not carry an
    # IEEE-assigned manufacturer identity, even if their first digits happen
    # to overlap a public registry entry.
    if first_octet & 0x03:
        return None
    db = _load_oui_db()
    org = next(
        (db[prefix] for prefix in (hexmac[:9], hexmac[:7], hexmac[:6]) if prefix in db),
        None,
    )
    if not org or org.strip().lower() in _NON_BRAND_OUI_ORGS:
        return None
    return normalize_vendor_name(org)


def vendor_from_text(*texts: str) -> str | None:
    joined = " ".join(t.lower() for t in texts if t)
    for keyword, vendor in VENDOR_KEYWORDS.items():
        if keyword in joined:
            return vendor
    return None


def _fingerprint_value(fingerprints: list[str], *prefixes: str) -> str | None:
    """fingerprint 목록에서 `prefix` 로 시작하는 첫 항목의 값(접두 뒤 문자열)을 반환."""
    for fp in fingerprints:
        lower = fp.lower()
        for prefix in prefixes:
            if lower.startswith(prefix.lower()):
                value = fp[len(prefix):].strip()
                if value:
                    return value
    return None


_ADVERTISED_BRAND_PREFIXES = (
    "spotify-brand:",
    "mdns-txt:manufacturer=",
    "airplay-manufacturer:",
    "mdns-txt:usb_mfg=",
    "upnp-manufacturer:",
    "http-manufacturer:",
)
_ADVERTISED_MODEL_PREFIXES = (
    "spotify-model:",
    "mdns-txt:md=",
    "mdns-txt:model=",
    "mdns-txt:am=",
    "mdns-txt:usb_mdl=",
    "upnp-model:",
    "http-model:",
)
_HTTP_PRODUCT_PREFIX = "http-product:"


def _normalized_model_key(value: str) -> str:
    return "".join(character for character in _clean(value).casefold() if character.isalnum())


def _is_disallowed_product_model(model: str) -> bool:
    lowered = model.casefold()
    key = _normalized_model_key(model)
    return (
        len(key) < 3
        or lowered in _GENERIC_MODELS
        or lowered in _SOFTWARE_RECEIVER_BRANDS
        or key in _FAMILY_ONLY_MODEL_KEYS
        or key.startswith(("familyhub", "bravia"))
        or key.startswith(_NON_PRODUCT_MODEL_PREFIXES)
        or any(token in lowered for token in _SERVER_SOFTWARE_MODEL_TOKENS)
    )


def is_concrete_product_model(
    value: str | None,
    manufacturer: str | None = None,
) -> bool:
    """Return whether *value* identifies a product model rather than a family.

    The resolver accepts code-shaped part numbers (RF85C90, A3004NS-M,
    Mac14,9). A small set of real named variants (for example Sonos Arc) is
    accepted only together with its matching structured manufacturer. Bare
    brands, locations, product families and protocol categories are never
    promoted. Raspberry Pi is special: only a concrete board model is a
    product identity.
    """
    model = _clean(value)
    if not model:
        return False
    if _is_disallowed_product_model(model):
        return False
    key = _normalized_model_key(model)
    if key.startswith("raspberrypi"):
        return bool(_RASPBERRY_PI_BOARD_MODEL_RE.fullmatch(model))
    if any(character.isdigit() for character in key):
        return True
    if not manufacturer:
        return False
    brand = normalize_vendor_name(_clean(manufacturer))
    return key in _NAMED_PRODUCT_MODEL_KEYS_BY_MANUFACTURER.get(brand, frozenset())


def is_product_manufacturer(value: str | None) -> bool:
    manufacturer = _clean(value)
    if not manufacturer:
        return False
    lowered = normalize_vendor_name(manufacturer).casefold()
    return (
        lowered not in _GENERIC_MANUFACTURERS
        and lowered not in _SOFTWARE_RECEIVER_BRANDS
        and not any(
            lowered == key or lowered.startswith(f"{key} ")
            for key in _NON_PRODUCT_MANUFACTURER_KEYS
        )
    )


def advertised_brand_candidates(fingerprints: list[str]) -> list[str]:
    """Collect every structured manufacturer advertisement, deduplicated."""
    candidates: dict[str, str] = {}
    for fingerprint in fingerprints:
        raw = _clean(fingerprint)
        lowered = raw.casefold()
        for prefix in _ADVERTISED_BRAND_PREFIXES:
            if not lowered.startswith(prefix.casefold()):
                continue
            value = _clean(raw[len(prefix) :])
            low_value = value.casefold()
            if not value or low_value in _SOFTWARE_RECEIVER_BRANDS or low_value in _GENERIC_MANUFACTURERS:
                break
            normalized = normalize_vendor_name(value)
            candidates.setdefault(normalized.casefold(), normalized)
            break
    return list(candidates.values())


def advertised_brands_conflict(fingerprints: list[str]) -> bool:
    return len(advertised_brand_candidates(fingerprints)) > 1


def brand_from_advertised(fingerprints: list[str]) -> str | None:
    """기기가 애플리케이션 계층에서 스스로 알린 권위 있는 브랜드를 반환.

    Spotify Connect getInfo 의 brandDisplayName, AirPlay/UPnP 의 manufacturer 처럼 OEM 이 자기
    펌웨어에 넣은 값이라, VENDOR_KEYWORDS 에 없는 브랜드(Sonos/Denon/Bose 등)도 그대로 식별된다.
    특정 IP/MAC 하드코딩이 아니라 어느 집 기기든 동일하게 동작한다. 단 OSS 소프트웨어 리시버
    기본값(librespot 등)과 일반 placeholder 는 하드웨어 제조사가 아니므로 제외한다.
    """
    candidates = advertised_brand_candidates(fingerprints)
    return candidates[0] if len(candidates) == 1 else None


def _current_spotify_family_hub_getinfo_proven(fingerprints: list[str]) -> bool:
    """Require one complete structured Family Hub getInfo evidence bundle.

    ``spotify-getinfo-done`` alone proves only that a ZeroConf endpoint
    returned structured JSON.  A raw mDNS instance name or an open port must
    not be able to borrow that marker and become a Samsung refrigerator.  The
    current observation therefore needs all three parts emitted by the same
    getInfo collection path: completion, an unambiguous Samsung brand field,
    and a Family Hub model or remote-name field.
    """

    normalized = [_clean(value) for value in fingerprints if _clean(value)]
    if not any(value.casefold() == "spotify-getinfo-done" for value in normalized):
        return False

    spotify_brands = {
        normalize_vendor_name(value.split(":", 1)[1]).casefold()
        for value in normalized
        if value.casefold().startswith("spotify-brand:")
        and _clean(value.split(":", 1)[1])
    }
    if spotify_brands != {"samsung"}:
        return False

    for value in normalized:
        lowered = value.casefold()
        if not lowered.startswith(("spotify-model:", "spotify-name:")):
            continue
        advertised = value.split(":", 1)[1]
        compact = re.sub(r"[\s_-]+", "", advertised).casefold()
        if "familyhub" in compact:
            return True
    return False


def _brand_from_verified_vendor_service(fingerprints: list[str]) -> str | None:
    """Return a brand only for an exact, vendor-owned service identifier.

    This is intentionally much narrower than :func:`vendor_from_text`. It is
    used only to corroborate a structured advertised model/category, never to
    turn a friendly name such as ``mdns-name:Samsung-TV`` into manufacturer
    proof. LG ThinQ's vendor-specific service is retained because its model
    and product-category TXT records are an existing verified scan path.
    """
    for fingerprint in fingerprints:
        value = str(fingerprint).strip().lower()
        if not value.startswith("mdns-type:"):
            continue
        service_type = value.split(":", 1)[1].lstrip(".")
        if service_type.startswith("_lg-smart-device._tcp"):
            return "LG"
    return None


def advertised_model_candidates(fingerprints: list[str]) -> list[str]:
    """Collect all structured model advertisements without source priority."""
    candidates: dict[str, str] = {}
    for fingerprint in fingerprints:
        raw = _clean(fingerprint)
        lowered = raw.casefold()
        for prefix in _ADVERTISED_MODEL_PREFIXES:
            if not lowered.startswith(prefix.casefold()):
                continue
            value = _clean(raw[len(prefix) :])
            # AirPlay/RAOP uses ``md`` for a comma-separated capability bitmap
            # (for example ``0,1,2``), not a product model.  Treating that
            # bitmap as a second model conflicts with the authoritative
            # ``model``/``am`` value such as ``Mac14,9`` and leaves a real Mac
            # unresolved.  This is a protocol-shape guard, not a device or
            # household-specific label.
            if prefix == "mdns-txt:md=" and re.fullmatch(r"\d+(?:,\d+)+", value):
                break
            if value and value.casefold() not in _GENERIC_MODELS and value.casefold() not in _SOFTWARE_RECEIVER_BRANDS:
                candidates.setdefault(_normalized_model_key(value), value)
            break
    return list(candidates.values())


def http_product_candidates(fingerprints: list[str]) -> list[str]:
    """Return product strings from structured HTTP fields.

    ``productName`` is often a friendly full name (for example
    ``"ipTIME A3004NS-M"``), not a model token.  Keep it separate from
    ``advertised_model_candidates`` so it cannot create a model conflict or
    become exact without a catalog pattern match.
    """
    candidates: dict[str, str] = {}
    for fingerprint in fingerprints:
        raw = _clean(fingerprint)
        if not raw.casefold().startswith(_HTTP_PRODUCT_PREFIX):
            continue
        value = _clean(raw[len(_HTTP_PRODUCT_PREFIX) :])
        if value:
            candidates.setdefault(value.casefold(), value)
    return list(candidates.values())


def advertised_models_conflict(fingerprints: list[str]) -> bool:
    brand = brand_from_advertised(fingerprints)
    concrete = [
        value
        for value in advertised_model_candidates(fingerprints)
        if is_concrete_product_model(value, brand)
    ]
    return len({_normalized_model_key(value) for value in concrete}) > 1


def model_from_advertised(fingerprints: list[str]) -> str | None:
    """Return the sole concrete advertised product model.

    Family-only advertisements are ignored when a concrete part number exists.
    If separate structured sources advertise different concrete models, neither
    is selected; the observation must remain unresolved until the conflict is
    cleared by a later scan.
    """
    candidates = [
        value
        for value in advertised_model_candidates(fingerprints)
        if not _is_disallowed_product_model(value)
    ]
    brand = brand_from_advertised(fingerprints)
    concrete: dict[str, str] = {}
    for value in candidates:
        if is_concrete_product_model(value, brand):
            concrete.setdefault(_normalized_model_key(value), value)
    if len(concrete) == 1:
        return next(iter(concrete.values()))
    if len(concrete) > 1:
        return None
    weak = {_normalized_model_key(value): value for value in candidates}
    return next(iter(weak.values())) if len(weak) == 1 else None


def name_from_advertised(fingerprints: list[str]) -> str | None:
    """기기가 광고한 사용자 친화 이름(googlecast TXT `fn`, Spotify remoteName, UPnP friendlyName).

    사용자가 직접 정한 이름(예: "거실 TV")이라 생성 이름("구글 TV")보다 의미 있는 표시명이다.
    이름이 MAC 이거나 비었거나 generic placeholder 면 친근한 이름이 아니므로 제외한다.
    """
    value = _fingerprint_value(
        fingerprints, "mdns-txt:fn=", "spotify-name:", "mdns-txt:friendlyname=", "netbios-name:"
    )
    if not value:
        return None
    text = value.strip()
    bare = text.replace(":", "").replace("-", "")
    if not text or _FP_BARE_MAC_RE.match(bare) or _FP_MAC_RE.search(text):
        return None
    if text.lower() in _GENERIC_MODELS or text.lower() in _SOFTWARE_RECEIVER_BRANDS:
        return None
    # 브랜드명을 포함하는 이름(예 "Samsung-FamilyHub")은 기기 기본 이름일 가능성이 커,
    # 한국어 생성 이름("삼성 냉장고")이 더 친숙하다. 순수 사용자 지정 이름("거실 TV")만 채택한다.
    if vendor_from_text(text):
        return None
    return text


def vendor_from_model_prefix(model: str) -> str | None:
    normalized = model.strip()
    if APPLE_MAC_HARDWARE_MODEL_RE.fullmatch(normalized):
        return "Apple"
    upper = normalized.upper()
    for prefix, vendor in MODEL_PREFIX_VENDOR.items():
        if upper.startswith(prefix):
            return vendor
    return None


def mac_from_fingerprints(fingerprints: list[str]) -> str | None:
    """Never promote an advertised fingerprint value to a physical MAC.

    mDNS instance names, SSDP USNs and friendly-name fields are controlled by
    the advertising endpoint. A value that merely *looks* like a MAC is still
    application-layer evidence, not an ARP/neighbor-table observation. Keep
    the original fingerprint for product matching, but require ``mac_address``
    to come from the native neighbor scan or the backend neighbor table.

    The helper remains as a compatibility boundary for older callers. Its
    invariant is deliberately strict: fingerprint text can never become an
    address-derived device ID, history key, OUI lookup or alias key.
    """
    del fingerprints
    return None


def bind_verified_catalog_history(device: dict[str, Any]) -> dict[str, Any]:
    """Bind repository-verified catalog history to one in-process resolution.

    The repository may call this only after ``verified_catalog_identity`` has
    matched the same physical MAC inside the same strong network scope.  The
    object sentinel cannot be supplied by a scanner payload or legacy row, so
    the human-readable ``server-history:*`` evidence string remains diagnostic
    and never grants exact provenance by itself.
    """
    result = dict(device)
    result["_verified_catalog_history_proof"] = _VERIFIED_CATALOG_HISTORY_PROOF
    return result


def bind_verified_appliance_family_history(device: dict[str, Any]) -> dict[str, Any]:
    """Bind repository-verified appliance-family history to one resolution.

    This is intentionally separate from exact catalog history.  It allows a
    sleeping Family Hub to remain a truthful ``삼성 냉장고 (Family Hub)`` when
    the device has previously self-reported that product family on the same
    physical MAC and network scope, while keeping the missing retail model
    number explicit.
    """
    result = dict(device)
    result["_verified_appliance_family_history_proof"] = _VERIFIED_APPLIANCE_FAMILY_HISTORY_PROOF
    return result


# HomeKit(_hap) 액세서리 카테고리(mDNS TXT 'ci=N', Apple HAP 공식값). _hap 만 보고 'hub' 로 단정하면
# HomeKit 조명·도어록·카메라가 전부 hub 로 오분류된다(_spotify-connect→audio 와 같은 과잉단정).
# ci 가 실제 종류를 주므로 우선 사용한다. 값은 Apple HAP 레퍼런스 구현(HAP-NodeJS Categories enum)으로
# 검증함 — 미검증 값은 두지 않는다(환각 방지). 라벨이 없는 종류(센서·팬·에어컨·공기청정기)는 'iot' 로 둔다.
_HOMEKIT_CATEGORY_TYPE = {
    "2": "hub",          # Bridge
    "3": "iot",          # Fan
    "5": "light",        # Lighting
    "6": "lock",         # Locks
    "7": "plug",         # Outlet
    "8": "plug",         # Switch
    "9": "thermostat",   # Thermostat
    "10": "iot",         # Sensor
    "17": "camera",      # IP Camera
    "18": "camera",      # Video Doorbell(카메라 내장)
    "19": "iot",         # Air Purifier
    "21": "iot",         # Air Conditioner
    "26": "speaker",     # Speaker
    "31": "tv",          # Television
    "33": "router",      # WiFi Router
    "34": "audio",       # Audio Receiver
    "35": "tv",          # TV Set Top Box
    "36": "tv",          # TV Streaming Stick
}

# _googlecast/_airplay 는 TV 와 스마트 스피커가 함께 쓰는 프로토콜이라 'tv' 로 단정하면 Nest Mini·
# Google Home·HomePod 같은 스피커를 TV 로 오탐한다. 광고된 모델명이 스피커 계열이면 speaker 로 본다
# (ci 검사와 같은 원리 — 기기가 스스로 알린 모델로 판단, IP/MAC 하드코딩 아님, 어느 집 기기든 동일).
_CAST_SPEAKER_MODEL_HINTS = (
    "nest mini", "nest audio", "google home", "homepod", "audioaccessory", "chromecast audio",
)


def _cast_speaker_override(blob: str) -> str | None:
    """_googlecast/_airplay 기기의 광고 모델이 '순수 스피커'면 'speaker' 반환(아니면 None).

    cast/airplay 는 TV 와 스피커가 공유하는 프로토콜이라 'tv' 단정은 Nest Mini·HomePod 를 오탐한다.
    단 'hub'(Nest Hub 등)는 화면이 있는 디스플레이라 스피커가 아니므로 제외한다(speaker→tv 폴백).
    구분자(하이픈/언더스코어)를 공백으로 정규화해 'Nest Mini'·'nest-mini'·'nestmini' 를 모두 잡는다.
    """
    if "_googlecast" not in blob and "_airplay" not in blob:
        return None
    blob_norm = blob.replace("-", " ").replace("_", " ")
    if "hub" in blob_norm:  # Nest Hub 등 디스플레이는 스피커로 단정하지 않는다
        return None
    if any(hint in blob_norm for hint in _CAST_SPEAKER_MODEL_HINTS):
        return "speaker"
    return None


def device_type_from_signals(
    fingerprints: list[str], services: list[str], open_ports: list[int]
) -> str | None:
    """mDNS/SSDP 신호로 device_type 을 추정. 명확한 신호가 없으면 None(포트 추정에 맡김)."""
    # HomeKit ci 카테고리가 있으면 실제 종류를 우선한다(_hap→hub 과잉단정 교정, 모든 HomeKit IoT 대상).
    for fp in fingerprints:
        low = str(fp).lower()
        if low.startswith("mdns-txt:ci="):
            ci = low.split("=", 1)[1].strip()
            if ci in _HOMEKIT_CATEGORY_TYPE:
                return _HOMEKIT_CATEGORY_TYPE[ci]
    blob = " ".join([*fingerprints, *services]).lower()
    # cast/airplay 스피커 보정: 일반 _googlecast/_airplay→tv 매핑보다 먼저 적용.
    cast_speaker = _cast_speaker_override(blob)
    if cast_speaker:
        return cast_speaker
    for token, device_type in _SIGNAL_DEVICE_TYPE:
        if token in blob:
            return device_type
    # SMB(파일 공유)만 보이고 다른 단서가 없으면 PC/NAS 후보(컴퓨터).
    if {139, 445}.intersection(open_ports):
        return "computer"
    return None


def strong_device_type_from_signals(fingerprints: list[str], services: list[str]) -> str | None:
    """Return a category only from an explicitly structured protocol field.

    Friendly names, hostnames and arbitrary fingerprint text are controlled by
    the endpoint and are not category proof. In particular,
    ``mdns-name:onvif-camera`` must not be treated as an ONVIF response. Weak
    protocols such as RTSP and Google Cast also remain internal clues only.
    """
    normalized_services = {_clean(value).lower() for value in services if _clean(value)}
    mdns_types: list[str] = []
    cast_model_values: list[str] = []

    spotify_type_map = {
        "tv": "tv",
        "computer": "computer",
        "cast_video": "tv",
        "stb": "tv",
        "avr": "audio",
        "speaker": "speaker",
        "audio_dongle": "speaker",
        "cast_audio": "speaker",
    }
    product_type_map = {
        "air_conditioner": "air_conditioner",
        "air-conditioner": "air_conditioner",
        "air conditioner": "air_conditioner",
        "aircon": "air_conditioner",
        "air_con": "air_conditioner",
        "lg_ac": "air_conditioner",
        "lge_ac": "air_conditioner",
    }

    for fingerprint in fingerprints:
        low = _clean(fingerprint).lower()
        if low.startswith("mdns-txt:ci="):
            category = low.split("=", 1)[1].strip()
            if category in _HOMEKIT_CATEGORY_TYPE:
                return _HOMEKIT_CATEGORY_TYPE[category]
            continue
        if low.startswith("spotify-type:"):
            spotify_type = low.split(":", 1)[1].strip()
            if spotify_type in spotify_type_map:
                return spotify_type_map[spotify_type]
            continue
        if low.startswith("mdns-txt:product="):
            product_type = low.split("=", 1)[1].strip()
            if product_type in product_type_map:
                return product_type_map[product_type]
            continue
        if low.startswith("http-device-type:"):
            http_type = low.split(":", 1)[1].strip().replace("-", "_")
            if http_type in PUBLIC_IDENTITY_TYPES:
                return http_type
            normalized_label = re.sub(r"\s+", " ", http_type.replace("_", " "))
            for key, label in DEVICE_TYPE_LABELS.items():
                if key in PUBLIC_IDENTITY_TYPES and normalized_label == label.casefold():
                    return key
            continue
        if low.startswith("mdns-type:"):
            mdns_types.append(low.split(":", 1)[1].strip().lstrip("."))
            continue
        if low.startswith(("mdns-txt:md=", "mdns-txt:model=", "mdns-txt:am=")):
            cast_model_values.append(low.split("=", 1)[1].strip())
            continue
        if low.startswith(("onvif-ws-discovery", "ws-discovery:", "ws-discovery ")):
            return "camera"
        if low.startswith(("upnp-type:", "ssdp-st:")):
            advertised_type = low.split(":", 1)[1].strip()
            if "internetgatewaydevice" in advertised_type or "wanconnectiondevice" in advertised_type:
                return "router"

    if normalized_services.intersection({"onvif", "ws-discovery"}):
        return "camera"
    if normalized_services.intersection({"ipp", "printer"}):
        return "printer"

    cast_service_types = {
        service_type
        for service_type in mdns_types
        if service_type.startswith(("_googlecast._tcp", "_airplay._tcp"))
    }
    if cast_service_types and _cast_speaker_override(
        " ".join([*cast_service_types, *cast_model_values])
    ):
        return "speaker"

    mdns_type_map: tuple[tuple[str, str], ...] = (
        ("_workstation._tcp", "computer"),
        ("_onvif._tcp", "camera"),
        ("_axis-video._tcp", "camera"),
        ("_raop._tcp", "audio"),
        ("_ipp._tcp", "printer"),
        ("_printer._tcp", "printer"),
        ("_hue._tcp", "hub"),
        ("_nanoleaf._tcp", "light"),
        ("_lifx._tcp", "light"),
        ("_yeelight._tcp", "light"),
        ("_amzn._tcp", "speaker"),
        ("_august._tcp", "lock"),
        ("_ecobee._tcp", "thermostat"),
        ("_kasa._tcp", "plug"),
        ("_roborock._tcp", "robot"),
        ("_ecovacs._tcp", "robot"),
    )
    for service_type in mdns_types:
        for prefix, device_type in mdns_type_map:
            if service_type.startswith(prefix):
                return device_type

    return None


def identify_device(
    device: dict[str, Any],
    *,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, Any]:
    """Compatibility entry point that delegates to the single resolver.

    The former implementation maintained a second inference tree and could
    create a product-like label from an OUI, category or port clue. Returning
    the central resolver contract prevents future callers from bypassing the
    catalog/model provenance boundary.
    """
    if catalog_entries is None:
        return resolve_device_identity(device)
    return resolve_device_identity(device, catalog_entries=catalog_entries)


def _model_prefix_device_type(model: str) -> str | None:
    if not is_concrete_product_model(model):
        return None
    normalized = _clean(model).upper().replace("_", "")
    if not normalized:
        return None
    for prefix, device_type in MODEL_PREFIX_DEVICE_TYPE:
        if normalized.startswith(prefix.replace("_", "")):
            compact = "".join(character for character in normalized if character.isalnum())
            if len(compact) >= 4 and any(character.isdigit() for character in compact):
                return device_type
    return None


def _catalog_text(device: dict[str, Any]) -> str:
    values: list[str] = []
    for key in ("manufacturer", "model", "name"):
        value = _clean(device.get(key))
        if value:
            values.append(value)
    values.extend(str(value) for value in (device.get("fingerprints") or []) if str(value).strip())
    return " ".join(values).lower()


def _catalog_vendor_value_matches(entry: dict[str, Any], value: str | None) -> bool:
    """Match one vendor value against both internal and resident display names.

    Storage may contain the internal key (``Samsung``) or the presentation
    label (``삼성``).  Both are safe only when they map to the same concrete
    catalog row; arbitrary translated/free-form manufacturer text is rejected.
    """
    observed = _clean(value)
    if not observed:
        return False
    internal = _clean(entry.get("manufacturer"))
    display = _clean(entry.get("display_manufacturer"))
    canonical_display = _clean(VENDOR_KO.get(normalize_vendor_name(internal), internal))
    observed_keys = {observed.casefold(), normalize_vendor_name(observed).casefold()}
    catalog_keys = {
        internal.casefold(),
        normalize_vendor_name(internal).casefold(),
        display.casefold(),
        canonical_display.casefold(),
    }
    return bool(observed_keys.intersection(key for key in catalog_keys if key))


def _catalog_vendor_matches(entry: dict[str, Any], device: dict[str, Any], text: str) -> bool:
    if _catalog_vendor_value_matches(entry, _clean(device.get("manufacturer"))):
        return True
    normalized_vendor = vendor_from_text(_clean(device.get("manufacturer")), _clean(device.get("name")))
    if normalized_vendor and _catalog_vendor_value_matches(entry, normalized_vendor):
        return True
    entry_vendor = normalize_vendor_name(entry["manufacturer"]).lower()
    if entry_vendor and entry_vendor in text:
        return True
    return any(alias in text for alias in entry.get("aliases", []))


def _catalog_exact_model(entry: dict[str, Any], observed: object) -> str | None:
    """Return the catalog's canonical model for one exact observation.

    Dynamic rows use the same NFKC/casefold/whitespace key as DB uniqueness,
    so harmless full-width or repeated-space advertisements still match the
    signed fact.  The returned value is always the verified canonical model,
    never the scanner spelling.  Static patterns retain their finite,
    provenance-validated regex contract.
    """

    raw_observed = _clean(observed)
    if not raw_observed:
        return None
    observed_key = _verified_catalog_overlay_key(raw_observed)
    for verified_model in entry.get("verified_models", []):
        canonical = _clean(verified_model)
        if canonical and _verified_catalog_overlay_key(canonical) == observed_key:
            return canonical
    if entry.get("catalog_origin") == "verified_product_catalog_overlay":
        return None
    for pattern in entry.get("model_patterns", []):
        try:
            if re.fullmatch(pattern, raw_observed, flags=re.IGNORECASE):
                return raw_observed
        except re.error:
            continue
    return None


def _catalog_model_from_http_product(
    entry: dict[str, Any],
    product_values: list[str],
) -> str | None:
    """Extract a catalog-shaped model token from an HTTP ``productName``.

    A number of appliances return ``productName`` as a full value such as
    ``"ipTIME A3004NS-M"`` while omitting ``modelName``.  Matching the
    server-owned catalog pattern inside that structured field recovers the
    actual part number without treating arbitrary HTML text as a model.
    """
    for product in product_values:
        tokens = [product, *re.findall(r"[0-9A-Za-z][0-9A-Za-z._+/-]{2,95}", product)]
        for token in tokens:
            canonical = _catalog_exact_model(entry, token)
            if canonical and is_concrete_product_model(
                canonical, str(entry.get("manufacturer") or "")
            ):
                return canonical
    return None


def search_product_catalog(
    device: dict[str, Any],
    *,
    limit: int = 5,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> list[dict[str, Any]]:
    """Search the server catalog using observed product evidence.

    Results are candidates, not guesses.  An exact model pattern plus a
    corroborating vendor/type signal can resolve a product; a vendor/type or
    alias-only match remains an ``enriching`` candidate and is shown as a
    server lookup in progress.
    """
    text = _catalog_text(device)
    model = _clean(device.get("model"))
    fingerprints = [str(value) for value in (device.get("fingerprints") or [])]
    advertised_model = model_from_advertised(fingerprints)
    http_products = http_product_candidates(fingerprints)
    model_conflict = advertised_models_conflict(fingerprints)
    brand_conflict = advertised_brands_conflict(fingerprints)
    lower_fingerprints = [value.lower() for value in fingerprints]
    server_registration = device.get("_server_registration_proof") is _SERVER_REGISTRATION_PROOF
    catalog_history = (
        device.get("_verified_catalog_history_proof")
        is _VERIFIED_CATALOG_HISTORY_PROOF
    )
    # A structured model outranks a copied/raw scanner field.  Raw fields may
    # still find internal catalog candidates, but never become exact without
    # an authoritative server registration.
    observed_model = advertised_model or (model if not model_conflict else "")
    current_type = _clean(device.get("device_type"))

    strong_type = strong_device_type_from_signals(fingerprints, list(device.get("services") or []))
    advertised_brand = brand_from_advertised(fingerprints)
    normalized_advertised_brand = normalize_vendor_name(advertised_brand) if advertised_brand else None
    verified_service_brand = _brand_from_verified_vendor_service(fingerprints)
    advertised_service_brand_conflict = bool(
        normalized_advertised_brand
        and verified_service_brand
        and normalize_vendor_name(verified_service_brand) != normalized_advertised_brand
    )
    matches: list[dict[str, Any]] = []
    for entry in _product_catalog_with_overlay(catalog_entries):
        vendor_match = _catalog_vendor_matches(entry, device, text)
        entry_vendor = normalize_vendor_name(str(entry["manufacturer"]))
        model_type = _model_prefix_device_type(observed_model)
        type_match = (
            current_type == entry["device_type"]
            or strong_type == entry["device_type"]
            or model_type == entry["device_type"]
        )
        catalog_product_model = _catalog_model_from_http_product(entry, http_products)
        entry_observed_model = observed_model or catalog_product_model or ""
        canonical_catalog_model = _catalog_exact_model(entry, entry_observed_model)
        model_match = bool(
            canonical_catalog_model
            and is_concrete_product_model(
                canonical_catalog_model, str(entry["manufacturer"])
            )
        )
        alias_match = any(alias in text for alias in entry.get("aliases", []))
        structured_model_match = bool(
            advertised_model
            and observed_model
            and _verified_catalog_overlay_key(advertised_model)
            == _verified_catalog_overlay_key(observed_model)
            and not model_conflict
        )
        structured_http_product_match = bool(
            catalog_product_model
            and http_products
            and any(
                fingerprint.casefold().startswith("http-manufacturer:")
                for fingerprint in fingerprints
            )
            and not brand_conflict
        )
        structured_service_vendor_match = any(
            alias
            and any(
                fingerprint.startswith(("mdns-type:", "upnp-type:", "spotify-type:"))
                and alias in fingerprint
                for fingerprint in lower_fingerprints
            )
            for alias in entry.get("aliases", [])
        )
        structured_http_vendor_match = any(
            fingerprint.startswith("http-title:")
            and vendor_from_text(fingerprint) == entry_vendor
            for fingerprint in lower_fingerprints
        )
        model_prefix_vendor_match = bool(
            advertised_model
            and not advertised_brand
            and not brand_conflict
            and vendor_from_model_prefix(advertised_model) == entry_vendor
        )
        structured_vendor_match = bool(
            not brand_conflict
            and not advertised_service_brand_conflict
            and (
                normalized_advertised_brand == entry_vendor
                or (
                    not advertised_brand
                    and (
                        structured_service_vendor_match
                        or structured_http_vendor_match
                        or model_prefix_vendor_match
                    )
                )
            )
        )
        exact_provenance = bool(
            server_registration
            or catalog_history
            or (
                (structured_model_match or structured_http_product_match)
                and structured_vendor_match
                and not model_conflict
                and not brand_conflict
            )
        )
        score = (7 if model_match else 0) + (3 if vendor_match else 0) + (2 if type_match else 0) + (1 if alias_match else 0)
        if score < 3:
            continue
        # A manufacturer-only hit is not a useful product candidate.  Keep a
        # family candidate only when the observed type, alias or model also
        # supports that catalog entry; this avoids showing unrelated Samsung
        # TV/fridge rows just because the vendor string was present.
        if vendor_match and not (model_match or type_match or alias_match):
            continue
        # A broad model prefix (for example ``X123``) is not enough to claim
        # a brand.  Keep it as a candidate only when the type or another
        # vendor signal corroborates it.
        if model_match and not (vendor_match or alias_match or type_match):
            continue
        exact = bool(
            model_match
            and canonical_catalog_model
            and is_concrete_product_model(canonical_catalog_model, str(entry["manufacturer"]))
            and exact_provenance
            and (vendor_match or alias_match or structured_vendor_match)
            and (type_match or current_type in {"", "unknown", "web-device", "iot"})
        )
        matches.append(
            {
                "catalog_id": entry["catalog_id"],
                "manufacturer": entry["manufacturer"],
                "display_manufacturer": entry["display_manufacturer"],
                "product_label": entry["product_label"],
                "device_type": entry["device_type"],
                "model": canonical_catalog_model if model_match and canonical_catalog_model else "",
                "score": score,
                "match_kind": "exact_model" if exact else "candidate",
                "confidence": min(0.99, 0.5 + (score * 0.06)),
                "source": str(entry.get("catalog_origin") or "server_product_catalog"),
                "source_url": entry["source_url"],
                "source_title": entry["source_title"],
                "source_version": entry["source_version"],
                "source_date": entry["source_date"],
                "source_date_kind": entry["source_date_kind"],
                "verified_at": entry["verified_at"],
                "resolution_provenance": str(entry.get("resolution_provenance") or ""),
            }
        )
    matches.sort(key=lambda item: (item["match_kind"] != "exact_model", -item["score"], item["catalog_id"]))
    return matches[: max(1, min(int(limit), 10))]


def _stored_exact_catalog_identity(
    record: dict[str, Any],
    *,
    manufacturer: str,
    model: str,
    device_type: str,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, str] | None:
    """Revalidate a persisted exact-catalog marker against today's catalog.

    Identity-history rows intentionally do not retain raw fingerprints.  They
    do retain the resolver's bounded catalog candidate (catalog id, exact kind
    and model-bearing label).  That marker is accepted only for a previously
    resolved high-confidence row and only while the current server catalog
    still agrees on manufacturer, concrete model pattern and product type.
    Arbitrary legacy manufacturer/model text therefore cannot use this path.
    """
    raw_candidates = record.get("identity_candidates")
    if not isinstance(raw_candidates, list):
        raw_candidates = record.get("candidates_json")
        if isinstance(raw_candidates, str):
            try:
                raw_candidates = json.loads(raw_candidates)
            except (TypeError, ValueError, json.JSONDecodeError):
                raw_candidates = []
    if not isinstance(raw_candidates, list):
        return None

    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        if _clean(candidate.get("kind")) != "서버 카탈로그 확정":
            continue
        catalog_id = _clean(candidate.get("catalog_id"))
        label = _clean(candidate.get("label"))
        if not catalog_id or not _verified_catalog_overlay_key(label).endswith(
            _verified_catalog_overlay_key(f"({model})")
        ):
            continue
        current_catalog = _product_catalog_with_overlay(catalog_entries)
        entry = next(
            (
                item
                for item in current_catalog
                if str(item.get("catalog_id") or "") == catalog_id
            ),
            None,
        )
        expected_dynamic_id = _verified_catalog_overlay_id(
            manufacturer, model, device_type
        )
        if entry is None and catalog_id == expected_dynamic_id:
            # A dynamic product may later be curated into the static catalog,
            # which deliberately suppresses the duplicate overlay and changes
            # its catalog_id.  Rebind only to a unique current row with the
            # same canonical maker/model/type tuple; arbitrary legacy markers
            # and family-level matches cannot use this migration path.
            promoted = [
                item
                for item in current_catalog
                if _catalog_vendor_value_matches(item, manufacturer)
                and (not device_type or str(item.get("device_type") or "") == device_type)
                and _catalog_exact_model(item, model) is not None
            ]
            if len(promoted) == 1:
                entry = promoted[0]
        if not entry:
            continue
        if not _catalog_vendor_value_matches(entry, manufacturer):
            continue
        if device_type and str(entry["device_type"]) != device_type:
            continue
        canonical_model = _catalog_exact_model(entry, model)
        if canonical_model is None:
            continue
        return {
            # Preserve the already-presented manufacturer spelling (for
            # example the Korean display label). The current catalog row has
            # just revalidated that it maps to the same canonical maker.
            "manufacturer": manufacturer,
            "model": canonical_model,
            "device_type": str(entry["device_type"]),
            "evidence": "서버에 이전에 확인된 품번과 현재 장치 대조",
        }
    return None


def verified_catalog_marker_identity(
    record: dict[str, Any] | None,
    *,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, str] | None:
    """Revalidate one resolver-owned exact-catalog marker for presentation.

    A legacy ``resolved`` flag or a plausible manufacturer/model string is not
    product provenance.  The presentation boundary may trust a persisted row
    only when it carries this resolver version's bounded exact candidate and
    today's catalog still agrees with its concrete model and category.  MAC and
    network-scope continuity are separate repository concerns handled by
    :func:`verified_catalog_identity` when history is reused.
    """
    if not isinstance(record, dict):
        return None
    effective_catalog_entries = catalog_entries
    if effective_catalog_entries is None:
        bound_entries = record.get("_verified_catalog_overlay_entries")
        if isinstance(bound_entries, (list, tuple)):
            # Each bound row is self-authenticating: the overlay loader below
            # rechecks its server HMAC, registered official source, canonical
            # maker/model keys and concrete product type.  Keeping the proof
            # JSON-shaped lets repository snapshots persist it without trusting
            # an arbitrary resolver flag supplied by a scanner.
            effective_catalog_entries = bound_entries
    if _clean(record.get("identity_status")) != IDENTITY_STATUS_RESOLVED:
        return None
    resolver_version = _clean(
        record.get("identity_resolver_version") or record.get("resolver_version")
    )
    if resolver_version != IDENTITY_RESOLVER_VERSION:
        return None
    try:
        confidence = float(
            record.get("identity_confidence", record.get("confidence")) or 0
        )
    except (TypeError, ValueError):
        confidence = 0
    if confidence < 0.9:
        return None
    manufacturer = _clean(record.get("manufacturer"))
    model = _clean(record.get("model"))
    device_type = _clean(record.get("device_type"))
    if (
        not is_product_manufacturer(manufacturer)
        or not is_concrete_product_model(model, manufacturer)
        or device_type not in PUBLIC_IDENTITY_TYPES
    ):
        return None
    return _stored_exact_catalog_identity(
        record,
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
        catalog_entries=effective_catalog_entries,
    )


def verified_catalog_identity(
    record: dict[str, Any] | None,
    *,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, str] | None:
    """Return a previously stored identity only when it is a catalog-backed product.

    A sleeping device may stop advertising mDNS/HTTP details on the next scan.
    Reusing every old label would be unsafe because an address can be reused,
    so the repository calls this helper only for the same physical MAC and
    still requires a prior resolved row with a real model plus an exact server
    catalog match.  This is a data-backed identity handoff, not a model guess
    or a hard-coded IP/MAC rule.
    """
    if not isinstance(record, dict):
        return None
    if str(record.get("scan_source") or "") != "android-native":
        return None
    if bool(record.get("is_unresolved")) or bool(record.get("is_phantom")):
        return None
    try:
        confidence = float(record.get("identity_confidence", record.get("confidence")) or 0)
    except (TypeError, ValueError):
        confidence = 0
    manufacturer = _clean(record.get("manufacturer"))
    model = _clean(record.get("model"))
    device_type = _clean(record.get("device_type"))
    mac = _clean(record.get("mac_address"))
    if confidence < 0.9 or not manufacturer or not model or not mac or mac.upper().startswith(UNKNOWN_MAC_PREFIX):
        return None
    if not is_concrete_product_model(model, manufacturer):
        return None
    stored_exact = verified_catalog_marker_identity(
        record, catalog_entries=catalog_entries
    )
    if stored_exact:
        return stored_exact
    historical_fingerprints: list[Any]
    raw_fingerprints = record.get("fingerprints")
    if isinstance(raw_fingerprints, list):
        historical_fingerprints = raw_fingerprints
    elif isinstance(record.get("fingerprints_json"), str):
        try:
            parsed_fingerprints = json.loads(record["fingerprints_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            parsed_fingerprints = []
        historical_fingerprints = parsed_fingerprints if isinstance(parsed_fingerprints, list) else []
    else:
        historical_fingerprints = []
    matches = search_product_catalog(
        {
            "manufacturer": manufacturer,
            "model": model,
            "device_type": device_type,
            "name": _clean(record.get("name")),
            "fingerprints": historical_fingerprints,
        },
        limit=1,
        catalog_entries=catalog_entries,
    )
    exact = matches[0] if matches and matches[0].get("match_kind") == "exact_model" else None
    if not exact or not exact.get("model"):
        return None
    return {
        "manufacturer": manufacturer,
        "model": model,
        "device_type": str(exact.get("device_type") or device_type),
        "evidence": "서버에 이전에 확인된 품번과 현재 장치 대조",
    }


def _catalog_evidence_labels(matches: list[dict[str, Any]]) -> list[str]:
    if not matches:
        return []
    if matches[0].get("match_kind") == "exact_model":
        return ["서버 제품 카탈로그·품번 대조"] if _clean(matches[0].get("model")) else ["서버 제품 카탈로그·제품군 대조"]
    return ["서버 제품 카탈로그 후보 검색"]


@functools.lru_cache(maxsize=1)
def _running_host_hardware_model() -> str:
    """Return the deployment host model when the backend can prove it locally.

    This is intentionally a server-side registration signal, not a guess from
    a port, OUI, or hostname.  Raspberry Pi OS exposes the board model through
    the device-tree file; a deployment may also provide the same non-secret
    value explicitly for distributions that do not mount it.
    """
    configured = _clean(os.getenv("HG_SERVER_DEVICE_MODEL"))
    if configured:
        return configured[:120]
    for path in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            value = Path(path).read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore")
        except OSError:
            continue
        value = _clean(value)
        if value:
            return value[:120]
    return ""


@functools.lru_cache(maxsize=1)
def _running_host_ipv4_addresses() -> frozenset[str]:
    """Collect local IPv4 addresses for server-host identity matching.

    The optional environment value is a deployment hint, not a resident
    device label.  The route probe uses UDP connect semantics and does not send
    application data; it simply asks the OS which local interface it would use.
    """
    candidate_hints: set[str] = set()
    route_addresses: set[str] = set()
    configured = os.getenv("HG_SERVER_DEVICE_IPS", "")
    for value in configured.split(","):
        try:
            parsed = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        if parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified:
            candidate_hints.add(str(parsed))
    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, socket.AF_INET):
            value = item[4][0]
            parsed = ipaddress.ip_address(value)
            if parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified:
                candidate_hints.add(str(parsed))
    except (OSError, ValueError):
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 9))
            value = probe.getsockname()[0]
            parsed = ipaddress.ip_address(value)
            if parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified:
                route_addresses.add(str(parsed))
        finally:
            probe.close()
    except OSError:
        pass

    # Environment and hostname values are hints only.  DNS may be stale and a
    # deployment variable may outlive a DHCP reassignment.  Ask the kernel to
    # bind each hinted address before accepting it as currently assigned to a
    # local interface.  A stale hint therefore cannot attach the Raspberry Pi
    # board model to another resident device that later receives that address.
    assigned = set(route_addresses)
    for candidate in candidate_hints:
        if candidate in assigned:
            continue
        try:
            verifier = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                verifier.bind((candidate, 0))
                bound_ip = verifier.getsockname()[0]
            finally:
                verifier.close()
        except OSError:
            continue
        if bound_ip == candidate:
            assigned.add(candidate)
    return frozenset(assigned)


def server_registered_identity(device: dict[str, Any]) -> dict[str, str] | None:
    """Return a verified identity when an observation is the API host itself."""
    raw_ip = _clean(device.get("ip_address"))
    try:
        observed_ip = ipaddress.ip_address(raw_ip)
    except ValueError:
        return None
    if observed_ip.version != 4 or str(observed_ip) not in _running_host_ipv4_addresses():
        return None
    hardware = _running_host_hardware_model()
    if "raspberry pi" not in hardware.casefold():
        return None
    model_match = re.search(r"Raspberry\s+Pi\s+\d+\s+Model\s+[A-Za-z]+", hardware, flags=re.IGNORECASE)
    if not model_match:
        # ``Raspberry Pi`` is a board family, not a product model.  Local host
        # registration is authoritative only when the OS exposes the concrete
        # board generation and variant.
        return None
    model = model_match.group(0).strip()
    return {
        "manufacturer": "Raspberry Pi",
        "model": model[:96],
        "device_type": "computer",
        "evidence": "서버 호스트 하드웨어 등록",
    }


def _identity_evidence_labels(device: dict[str, Any], *, vendor_source: str | None, model_source: str | None) -> list[str]:
    """Convert private discovery facts into short, resident-safe evidence labels."""
    labels: list[str] = []
    fingerprints = [str(value).lower() for value in (device.get("fingerprints") or [])]
    sources = {str(value).lower() for value in (device.get("discovery_sources") or [])}
    if any(value.startswith(("mdns-txt:", "mdns-type:")) for value in fingerprints) or "mdns" in sources:
        labels.append("기기 이름·서비스 광고")
    if any(value.startswith(("upnp-", "ssdp-")) for value in fingerprints) or "ssdp" in sources:
        labels.append("네트워크 기기 설명")
    if any(value.startswith(("onvif-", "ws-discovery:")) for value in fingerprints) or "onvif" in sources or "ws-discovery" in sources:
        labels.append("카메라 응답 정보")
    if any(value.startswith("dhcp-hostname:") for value in fingerprints) or "dhcp-lease" in sources:
        labels.append("공유기가 알려준 기기 이름")
    if any(value.startswith(("spotify-", "airplay-")) for value in fingerprints):
        labels.append("제품이 보낸 모델 정보")
    if any(
        value.startswith(("http-manufacturer:", "http-model:", "http-product:", "http-device-type:"))
        for value in fingerprints
    ):
        labels.append("기기 HTTP 정보")
    if "server-history" in sources or any(value.startswith("server-history:") for value in fingerprints):
        labels.append("서버에 이전에 확인된 제품 정보")
    if vendor_source == "model_code" or model_source == "advertised":
        labels.append("제품 품번 단서")
    elif vendor_source == "server_registration":
        labels.append("서버 호스트 하드웨어 등록")
    elif vendor_source in {"advertised", "text"}:
        labels.append("제품 제조사 광고")
    elif vendor_source == "oui":
        labels.append("네트워크 제조사 조회 단서")
    if not labels and device.get("open_ports"):
        labels.append("열려 있는 네트워크 서비스")
    return list(dict.fromkeys(labels))


def resolve_device_identity(
    device: dict[str, Any],
    *,
    catalog_entries: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, Any]:
    """Resolve one raw observation on the server.

    This function intentionally never invents a user-facing fallback label.
    When a product code is not yet provable it returns an
    ``enriching``/``unresolved`` record with safe
    candidates and evidence so the observation can be retried and shown as an
    identity finding instead of disappearing.
    """
    manufacturer_raw = _clean(device.get("manufacturer"))
    model_raw = _clean(device.get("model"))
    name_raw = _clean(device.get("name"))
    fingerprints = [str(value) for value in (device.get("fingerprints") or [])]
    services = [str(value) for value in (device.get("services") or [])]
    ports = [int(value) for value in (device.get("open_ports") or []) if str(value).isdigit()]
    current_type = _clean(device.get("device_type"))
    trusted_appliance_family_history = (
        device.get("_verified_appliance_family_history_proof")
        is _VERIFIED_APPLIANCE_FAMILY_HISTORY_PROOF
    )
    registered_identity = server_registered_identity(device)
    if registered_identity:
        # The API host is a real, locally verified board.  Treat this as a
        # registration fact so the server itself is not left as a generic
        # computer in the household inventory.
        manufacturer_raw = registered_identity["manufacturer"]
        model_raw = registered_identity["model"]
        current_type = registered_identity["device_type"]
        fingerprints.append("server-registration:raspberry-pi")
    catalog_device = {
        **device,
        "manufacturer": manufacturer_raw,
        "model": model_raw,
        "device_type": current_type,
        "fingerprints": fingerprints,
        # A fingerprint is endpoint-controlled text.  Only the local host
        # verification above can mint this in-process sentinel, so a client
        # cannot unlock exact catalog provenance with a forged
        # ``server-registration:*`` string or request field.
        "_server_registration_proof": (
            _SERVER_REGISTRATION_PROOF if registered_identity else None
        ),
    }
    catalog_matches = search_product_catalog(
        catalog_device, catalog_entries=catalog_entries
    )
    catalog_match = catalog_matches[0] if catalog_matches else None

    advertised_brand = brand_from_advertised(fingerprints)
    advertised_model = model_from_advertised(fingerprints)
    advertised_brand_conflict = advertised_brands_conflict(fingerprints)
    advertised_model_conflict = advertised_models_conflict(fingerprints)
    text_brand = vendor_from_text(model_raw, name_raw, " ".join(fingerprints))
    model_brand = vendor_from_model_prefix(model_raw)
    oui_brand = vendor_from_oui(_clean(device.get("mac_address")))

    vendor: str | None = None
    vendor_source: str | None = None
    if registered_identity:
        vendor = registered_identity["manufacturer"]
        vendor_source = "server_registration"
    for candidate, source in (
        (manufacturer_raw if manufacturer_raw.lower() not in _GENERIC_MANUFACTURERS else None, "raw"),
        (advertised_brand, "advertised"),
        (text_brand, "text"),
        (model_brand, "model_code"),
        (oui_brand, "oui"),
    ):
        if vendor is not None:
            break
        if candidate and candidate.lower() not in _SOFTWARE_RECEIVER_BRANDS:
            vendor = normalize_vendor_name(candidate)
            vendor_source = source
            break

    model = registered_identity["model"] if registered_identity else advertised_model
    model_source = "server_registration" if registered_identity else ("advertised" if advertised_model else None)
    if (
        not model
        and not advertised_model_conflict
        and model_raw.lower() not in _GENERIC_MODELS
        and model_raw
    ):
        model = model_raw
        model_source = "raw"

    family_hub_signal = any(
        _is_family_hub_alias(value)
        or "familyhub" in re.sub(r"[\s_-]+", "", _clean(value)).casefold()
        for value in [*fingerprints, model_raw, name_raw]
    )
    # A complete structured Samsung + Family Hub getInfo bundle is valid on a
    # first scan in any household.  The completion marker by itself, a raw mDNS
    # name, and port 17654 are deliberately insufficient.  Historical proof is
    # needed only when the same physical appliance no longer answers getInfo.
    family_hub_getinfo_proven = _current_spotify_family_hub_getinfo_proven(
        fingerprints
    )

    # A server catalog hit outranks a weak scanner hint.  The catalog entry is
    # still only a candidate until its model pattern and a corroborating
    # manufacturer/type signal agree, so this cannot turn a port number into a
    # fabricated product.
    if catalog_match and catalog_match.get("match_kind") == "exact_model":
        vendor = str(catalog_match.get("manufacturer") or vendor or "") or vendor
        vendor_source = "catalog"
        model = str(catalog_match.get("model") or model or "") or model
        model_source = "catalog"

    # Family Hub reports ``deviceType=SPEAKER`` even though the product is a
    # refrigerator.  When the same response also contains the Family Hub
    # product token, the product token is the stronger category evidence.
    inferred_type = (
        "fridge"
        if family_hub_getinfo_proven and family_hub_signal
        else strong_device_type_from_signals(fingerprints, services)
    )
    if inferred_type not in PUBLIC_IDENTITY_TYPES:
        model_type = _model_prefix_device_type(model or "")
        inferred_type = model_type if model_type in PUBLIC_IDENTITY_TYPES else None
    if inferred_type not in PUBLIC_IDENTITY_TYPES:
        weak_type = device_type_from_signals(fingerprints, services, sorted(ports))
        # Preserve an explicit native type for ambiguous protocol-only
        # observations (for example a webOS TV also advertising RTSP).  Weak
        # port/service guesses may fill only an empty/placeholder type.
        if current_type not in PUBLIC_IDENTITY_TYPES:
            inferred_type = weak_type if weak_type in PUBLIC_IDENTITY_TYPES else None
        else:
            inferred_type = current_type
    if (
        catalog_match
        and catalog_match.get("match_kind") == "exact_model"
        and str(catalog_match.get("device_type") or "") in PUBLIC_IDENTITY_TYPES
    ):
        inferred_type = str(catalog_match["device_type"])

    # A raw server/OUI string is not enough to claim an exact consumer product.
    product_code_proven = is_concrete_product_model(model, vendor)
    catalog_exact = bool(
        catalog_match
        and catalog_match.get("match_kind") == "exact_model"
        and _clean(catalog_match.get("model"))
    )
    strong_type = strong_device_type_from_signals(fingerprints, services)
    normalized_advertised_brand = normalize_vendor_name(advertised_brand) if advertised_brand else None
    structured_brand_match = bool(vendor and normalized_advertised_brand == vendor)
    verified_service_brand = _brand_from_verified_vendor_service(fingerprints)
    advertised_service_brand_conflict = bool(
        advertised_brand
        and verified_service_brand
        and normalize_vendor_name(verified_service_brand) != normalize_vendor_name(advertised_brand)
    )
    model_family_type = _model_prefix_device_type(model or "")
    model_vendor = vendor_from_model_prefix(model or "")
    catalog_model_vendor_conflict = bool(
        vendor
        and any(
            _clean(match.get("model"))
            and normalize_vendor_name(str(match.get("manufacturer") or "")) != vendor
            for match in catalog_matches
        )
    )

    # Generic name/service text is useful as an internal candidate, but it is
    # not manufacturer proof. A non-catalog product code becomes a resolved
    # identity only when the device advertised the model and either:
    #   * an explicit manufacturer field agrees with a strong category,
    #   * the product-code prefix proves the same vendor and category, or
    #   * a narrowly verified vendor service (currently LG ThinQ) agrees with
    #     both an advertised model and a strong category.
    # This blocks ``mdns-name:Samsung`` + ``_rtsp`` and
    # ``netbios-name:LG`` + ``_googlecast`` from becoming products.
    structured_identity = bool(
        model_source == "advertised"
        and not advertised_brand_conflict
        and not advertised_model_conflict
        and not advertised_service_brand_conflict
        and not catalog_model_vendor_conflict
        and vendor
        and inferred_type
        and (
            (structured_brand_match and strong_type == inferred_type)
            or (model_vendor == vendor and model_family_type == inferred_type)
            or (verified_service_brand == vendor and strong_type == inferred_type)
        )
    )
    exact_product = bool(
        vendor
        and is_product_manufacturer(vendor)
        and inferred_type
        and product_code_proven
        and (catalog_exact or structured_identity or bool(registered_identity))
    )
    # Desktop/laptop computers frequently do not expose a board model over the
    # LAN.  We can still make a truthful family-level identity when the server
    # independently verifies the MAC OUI and the host answers SMB ports.  This
    # is deliberately narrower than accepting a client-supplied manufacturer:
    # the OUI must resolve to the same normalized brand and conflicting
    # advertisements must be absent.  It never claims a model or product code.
    oui_matches_vendor = bool(
        oui_brand
        and vendor
        and VENDOR_KO.get(normalize_vendor_name(oui_brand), normalize_vendor_name(oui_brand)).casefold()
        == VENDOR_KO.get(normalize_vendor_name(vendor), normalize_vendor_name(vendor)).casefold()
    )
    family_vendor_proven = (
        vendor_source == "oui"
        or (vendor_source == "raw" and oui_matches_vendor)
    )
    family_identity = bool(
        not exact_product
        and family_vendor_proven
        and oui_matches_vendor
        and vendor
        and is_product_manufacturer(vendor)
        and inferred_type == "computer"
        and not model
        and not advertised_brand_conflict
        and not advertised_model_conflict
        and not advertised_service_brand_conflict
        and not catalog_model_vendor_conflict
        and bool({139, 445}.intersection(ports))
    )
    # A Family Hub refrigerator may be asleep during the current scan, so its
    # ZeroConf getInfo fields are absent even though the same physical device
    # previously self-reported the product family.  The repository-only proof
    # keeps this path distinct from a raw Family Hub string: no family alias
    # alone can resolve a product, and no retail part number is inferred.
    family_hub_identity = bool(
        not exact_product
        and (trusted_appliance_family_history or family_hub_getinfo_proven)
        and family_hub_signal
        and (
            normalize_vendor_name(vendor or "").casefold() == "samsung"
            or _clean(vendor).casefold() == VENDOR_KO["Samsung"].casefold()
        )
        and inferred_type == "fridge"
        and not advertised_brand_conflict
        and not advertised_model_conflict
        and not advertised_service_brand_conflict
        and not catalog_model_vendor_conflict
    )
    family_verified = exact_product or family_identity or family_hub_identity

    status = IDENTITY_STATUS_RESOLVED if (exact_product or family_identity or family_hub_identity) else (
        IDENTITY_STATUS_ENRICHING if (vendor or inferred_type or fingerprints or services or ports) else IDENTITY_STATUS_UNRESOLVED
    )
    manufacturer_label = VENDOR_KO.get(vendor or "", vendor or "")
    type_label = DEVICE_TYPE_LABELS.get(inferred_type or "", "")
    # The strict proof above already established the device-advertised product
    # family.  Server augmentation deliberately transports structured
    # fingerprints without copying them into the raw model field, so derive the
    # family display value from that proof rather than requiring a duplicate
    # untrusted raw model string.
    display_model = "Family Hub" if family_hub_identity else _clean(model)
    canonical_name = None
    if status == IDENTITY_STATUS_RESOLVED and manufacturer_label and type_label:
        canonical_name = f"{manufacturer_label} {type_label}"
        if display_model:
            canonical_name += f" ({display_model})"
        canonical_name = canonical_name[:96]

    candidates: list[dict[str, str]] = []
    candidate_labels: set[str] = set()
    for match in catalog_matches:
        candidate_model = _clean(match.get("model"))
        label = str(match.get("product_label") or "").strip()
        if candidate_model:
            label = f"{label} ({candidate_model})"
        if label and label not in candidate_labels:
            candidate_labels.add(label)
            candidates.append(
                {
                    "label": label[:120],
                    "kind": "서버 카탈로그 확정" if match.get("match_kind") == "exact_model" else "서버 카탈로그 후보",
                    "catalog_id": str(match.get("catalog_id") or "")[:80],
                    "confidence": str(match.get("confidence") or "0.0"),
                }
            )
    if family_hub_identity and "삼성 냉장고 (Family Hub)" not in candidate_labels:
        candidate_labels.add("삼성 냉장고 (Family Hub)")
        candidates.append(
            {
                "label": "삼성 냉장고 (Family Hub)",
                "kind": "동일 기기에서 이전 확인된 제품군",
                "confidence": "0.92",
            }
        )
    if status != IDENTITY_STATUS_RESOLVED:
        if manufacturer_label and type_label:
            if model:
                label = f"{manufacturer_label} {type_label} ({_clean(model)})"
                if label not in candidate_labels:
                    candidate_labels.add(label)
                    candidates.append({"label": label, "kind": "품번 대조"})
            else:
                label = f"{manufacturer_label} {type_label} 품번 확인 중"
                if label not in candidate_labels:
                    candidate_labels.add(label)
                    candidates.append({"label": label, "kind": "품번 조회"})
        elif type_label:
            label = f"{type_label} 제품 정보 확인 중"
            if label not in candidate_labels:
                candidate_labels.add(label)
                candidates.append({"label": label, "kind": "제품 종류"})
        elif manufacturer_label:
            label = f"{manufacturer_label} 제품 정보 확인 중"
            if label not in candidate_labels:
                candidates.append({"label": label, "kind": "제조사 단서"})

    evidence = _identity_evidence_labels(device, vendor_source=vendor_source, model_source=model_source)
    if family_identity and "네트워크 제조사 조회 단서" not in evidence:
        evidence.append("네트워크 제조사 조회 단서")
    if family_hub_identity:
        evidence.extend(
            [
                (
                    "기기 자체 getInfo로 확인된 제품군"
                    if family_hub_getinfo_proven
                    else "동일 기기에서 이전 확인된 제품군"
                ),
                (
                    "Family Hub 냉장고 getInfo 응답"
                    if family_hub_getinfo_proven
                    else "Family Hub 냉장고 getInfo 이력"
                ),
            ]
        )
    evidence.extend(_catalog_evidence_labels(catalog_matches))
    if registered_identity:
        evidence.append(registered_identity["evidence"])
    evidence = list(dict.fromkeys(evidence))
    if status == IDENTITY_STATUS_RESOLVED:
        if family_hub_identity:
            note = (
                "기기 자체가 삼성 Family Hub 냉장고 제품군을 응답했어요. "
                "현재 기기가 정확한 소매 품번을 광고하지 않아 품번은 표시하지 않아요."
                if family_hub_getinfo_proven
                else "동일 기기에서 삼성 Family Hub 냉장고 제품군을 확인했어요. 현재 기기가 정확한 소매 품번을 광고하지 않아 품번은 표시하지 않아요."
            )
            confidence = 0.94 if family_hub_getinfo_proven else 0.92
        elif family_identity:
            note = "서버가 네트워크 제조사와 컴퓨터 종류를 확인했어요. 기기가 품번을 제공하지 않아 모델은 표시하지 않아요."
            confidence = 0.84
        else:
            note = "서버가 제품 카탈로그와 기기 광고 품번을 대조해 등록했어요."
            confidence = float(catalog_match.get("confidence", 0.96)) if catalog_exact and catalog_match else (0.96 if model_source == "advertised" else 0.9)
    elif status == IDENTITY_STATUS_ENRICHING:
        note = "서버가 수집한 단서를 제품 카탈로그와 대조하고 있어요. 다음 검사에서 품번을 다시 확인해요."
        confidence = 0.55 if (vendor or inferred_type) else 0.35
    else:
        note = "기기는 감지됐고 서버가 식별 단서를 더 모으는 중이에요. 안전한 기기로 단정하지 않아요."
        confidence = 0.2

    result = {
        "identity_status": status,
        "identity_resolver_version": IDENTITY_RESOLVER_VERSION,
        "manufacturer": vendor or "",
        "model": display_model if display_model else ("" if family_hub_identity else _clean(model)),
        "device_type": inferred_type or "",
        "canonical_name": canonical_name or "",
        "identity_candidates": candidates,
        "identity_evidence": evidence,
        "identity_family_verified": family_verified,
        "identity_note": note,
        "identity_confidence": confidence,
        "is_resolved": status in {IDENTITY_STATUS_RESOLVED, IDENTITY_STATUS_MANUAL},
        "is_unresolved": status not in {IDENTITY_STATUS_RESOLVED, IDENTITY_STATUS_MANUAL},
    }
    if (
        catalog_exact
        and catalog_match
        and catalog_match.get("source") == "verified_product_catalog_overlay"
        and isinstance(catalog_entries, (list, tuple))
    ):
        # The presentation API predates dynamic overlays. Bind only the exact
        # matched DB fact, not the whole global catalog. The row remains
        # JSON-serializable and is trusted only after its HMAC and official
        # source contract are revalidated by the overlay loader.
        matched_catalog_id = str(catalog_match.get("catalog_id") or "")
        matched_maker_key = _verified_catalog_overlay_key(
            catalog_match.get("manufacturer"), manufacturer=True
        )
        matched_model_key = _verified_catalog_overlay_key(catalog_match.get("model"))
        matched_device_type = str(catalog_match.get("device_type") or "")
        bound_entries: list[dict[str, Any]] = []
        for raw in catalog_entries:
            if not isinstance(raw, dict):
                continue
            if (
                _verified_catalog_overlay_key(
                    raw.get("manufacturer"), manufacturer=True
                )
                != matched_maker_key
                or _verified_catalog_overlay_key(raw.get("exact_model"))
                != matched_model_key
                or str(raw.get("device_type") or "").casefold()
                != matched_device_type
            ):
                continue
            validated = _validated_verified_catalog_overlay_entry(raw)
            if (
                validated is not None
                and str(validated.get("catalog_id") or "") == matched_catalog_id
            ):
                bound_entries.append(dict(raw))
                break
        if bound_entries:
            result["_verified_catalog_overlay_entries"] = bound_entries
    return result
