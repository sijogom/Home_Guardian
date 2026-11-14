"""API-key-free product verification against bounded manufacturer endpoints.

This service is deliberately separate from the optional AI web-search path.
It sends only one already-observed, structured model code to a small, versioned
allow-list of manufacturer-owned HTTPS endpoints.  LAN addresses, MACs,
hostnames, home identifiers and opaque job identifiers never leave the server.

An HTTP response is not accepted merely because it contains a model-like
string.  Resolution requires either an exact JSON-LD ``Product`` identifier,
or an exact model token in both a detail URL and its title/H1.  A profile may
also declare a manufacturer catalog endpoint, but its structured result must
bind the exact manufacturer and model and the scan must already contain a
structured device-type proof.
"""

from __future__ import annotations

import codecs
import hashlib
import http.client
import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

from .device_identity import (
    DEVICE_TYPE_LABELS,
    MODEL_PREFIX_DEVICE_TYPE,
    MODEL_PREFIX_VENDOR,
    PUBLIC_IDENTITY_TYPES,
    normalize_vendor_name,
)
from .identity_enrichment import (
    IdentityEnrichmentError,
    blocked_binding_reason,
    evidence_signature_matches,
    identity_job_key_matches,
    source_matches_registered_official_domain,
    verified_product_catalog_keys,
)
from .identity_research import (
    _corroborated_models,
    _eligible_job,
    _requires_device_scoped_resolution,
    _result_matches_evidence,
    _structured_proofs,
)


OFFICIAL_PRODUCT_SOURCES_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "official_product_sources.json"
)
_MAX_BATCH_SIZE = 8
_MAX_ENDPOINTS_PER_JOB = 2
_MAX_REDIRECTS = 2
_MAX_RESPONSE_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 16 * 1024
_REQUEST_TIMEOUT_SECONDS = 2.0
_TOTAL_TIMEOUT_SECONDS = 6.0
_MAX_RESOLVED_IP_ATTEMPTS = 4
_USER_AGENT = "HomeGuardian-OfficialProductLookup/1.0"
_OFFICIAL_LOOKUP_POLICY_REVISION = "official-http-v6"
_MODEL_TOKEN_RE = re.compile(r"^(?=.{2,48}$)(?=.*[0-9])[0-9A-Za-z][0-9A-Za-z._/+(), -]*$")
_OPAQUE_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{15,95}$")
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_HTML_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_JSON_CONTENT_TYPES = frozenset({"application/json", "application/ld+json"})
_ASUS_DISCOVERY_JSON_CONTENT_TYPES = _JSON_CONTENT_TYPES | {"text/json"}
_PRODUCT_MODEL_FIELDS = ("model", "sku", "mpn", "productID")
_CATALOG_MANUFACTURER_FIELDS = ("manufacturer", "brand", "maker")
_STRUCTURED_DEVICE_TYPE_FIELDS = ("category", "productType", "additionalType")
_ACTIVE_PARSERS = frozenset(
    {
        "samsung_support_product",
        "tp_link_product",
        "iptime_download_category",
        "lg_support_product",
        "sonos_support_product",
        "asus_support_product",
    }
)
_SPECIAL_ENDPOINT_KIND_BY_PARSER = {
    "lg_support_product": "lg_support_discovery",
    "sonos_support_product": "sonos_support_product",
    "asus_support_product": "asus_support_discovery",
}
_LG_DISCOVERY_TEMPLATE = (
    "https://apiv2.lge.co.kr/searchsvc/ajax/v1/search/"
    "spt-psp-cst-sm-model?keyword={model}"
)
_SONOS_DETAIL_TEMPLATE_RE = re.compile(
    r"https://support\.sonos\.com/[a-z]{2}(?:-[a-z]{2})?/products/\{model_slug\}/?"
)
_ASUS_DISCOVERY_TEMPLATE = (
    "https://www.asus.com/support/api/product.asmx/GetPDSupportTab?"
    "website=us&pdhashedid=&pdid=99999&siteID=www&sitelang=&model={model}"
)
_ASUS_BRANCH_NAMES = {
    "asus-wifi-routers": "ASUS WiFi Routers",
    "asus-gaming-routers": "ASUS Gaming Routers",
}
_DNS_SLOTS = threading.BoundedSemaphore(value=2)


class OfficialProductLookupFailure(RuntimeError):
    """A bounded failure whose code contains no request or device data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OfficialHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


class OfficialProductTransport(Protocol):
    def __call__(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        timeout_seconds: float,
        max_response_bytes: int,
        resolved_ip: str,
        method: str = "GET",
        body: bytes | None = None,
    ) -> OfficialHttpResponse | Mapping[str, Any]: ...


class OfficialDnsResolver(Protocol):
    def __call__(self, hostname: str) -> Sequence[str]: ...


@dataclass(frozen=True)
class OfficialProductLookupJobOutcome:
    job_id: str
    eligible: bool
    attempted: bool
    resolved: bool
    error_code: str | None = None


@dataclass(frozen=True)
class OfficialProductLookupOutcome:
    enabled: bool
    eligible_count: int
    attempted_count: int
    fetched_page_count: int
    resolved_count: int
    pending_count: int
    failed_count: int = 0
    scoped_match_count: int = 0
    error_code: str | None = None
    job_outcomes: tuple[OfficialProductLookupJobOutcome, ...] = ()

    @property
    def unresolved_job_ids(self) -> tuple[str, ...]:
        return tuple(
            item.job_id for item in self.job_outcomes if item.job_id and not item.resolved
        )


@dataclass(frozen=True)
class OfficialProductCanaryOutcome:
    manufacturer: str
    device_type: str
    known_model: str
    known_matched: bool
    known_source_url: str | None
    known_error_code: str | None
    known_elapsed_seconds: float
    impossible_model: str
    impossible_rejected: bool
    impossible_error_code: str | None
    impossible_elapsed_seconds: float


@dataclass(frozen=True)
class _Endpoint:
    kind: str
    url_template: str
    expected_device_type: str | None = None


@dataclass(frozen=True)
class _CanaryCase:
    known_model: str
    impossible_model: str
    device_type: str


@dataclass(frozen=True)
class _TrustProfile:
    manufacturer: str
    enabled: bool
    official_fqdns: frozenset[str]
    parser: str | None
    manufacturer_terms: tuple[str, ...]
    device_type_terms: Mapping[str, tuple[str, ...]]
    canaries: tuple[_CanaryCase, ...]
    endpoints: tuple[_Endpoint, ...]


@dataclass(frozen=True)
class _Candidate:
    manufacturer: str
    device_type: str
    model: str
    source_reference: str


@dataclass(frozen=True)
class _SamsungDiscoveryBinding:
    base_model: str
    full_model: str
    goods_id: str
    device_type_term: str


@dataclass(frozen=True)
class _LgSupportBinding:
    detail_path: str
    super_category: str
    category: str


@dataclass(frozen=True)
class _AsusSupportBinding:
    detail_url: str
    overview_url: str
    category_url: str
    branch_name: str


class _ProductHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._title_depth = 0
        self._h1_depth = 0
        self._script_depth = 0
        self._product_name_depth = 0
        self._product_model_depth = 0
        self._positive_cell_depth = 0
        self._sonos_product_name_depth = 0
        self._title_parts: list[str] = []
        self._h1_parts: list[str] = []
        self._script_parts: list[str] = []
        self._product_name_parts: list[str] = []
        self._product_model_parts: list[str] = []
        self._positive_cell_parts: list[str] = []
        self._sonos_product_name_parts: list[str] = []
        self._positive_cell_title = ""
        self._positive_cell_alt = ""
        self.json_ld_documents: list[str] = []
        self.canonical_urls: list[str] = []
        self.meta_values: dict[str, list[str]] = {}
        self.product_names: list[str] = []
        self.product_models: list[str] = []
        self.positive_cells: list[tuple[str, str, str]] = []
        self.sonos_product_names: list[str] = []

    @property
    def title(self) -> str:
        return " ".join(" ".join(self._title_parts).split())

    @property
    def headings(self) -> tuple[str, ...]:
        value = " ".join(" ".join(self._h1_parts).split())
        return (value,) if value else ()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        attributes = {str(key).casefold(): str(value or "") for key, value in attrs}
        if lowered == "title":
            self._title_depth += 1
        elif lowered == "h1":
            self._h1_depth += 1
            if attributes.get("data-test-id", "").casefold() == "psp-product-name":
                self._sonos_product_name_depth += 1
                self._sonos_product_name_parts = []
        elif lowered == "script":
            script_type = attributes.get("type", "").split(";", 1)[0].strip().casefold()
            if script_type == "application/ld+json":
                self._script_depth += 1
                self._script_parts = []
        elif lowered == "link":
            rel_values = {item.casefold() for item in attributes.get("rel", "").split()}
            href = attributes.get("href", "").strip()
            if "canonical" in rel_values and href:
                self.canonical_urls.append(href)
        elif lowered == "meta":
            key = (
                attributes.get("property")
                or attributes.get("name")
                or attributes.get("itemprop")
                or ""
            ).strip().casefold()
            content = attributes.get("content", "").strip()
            if key and content:
                self.meta_values.setdefault(key, []).append(content)
        elif lowered == "p":
            classes = {item.casefold() for item in attributes.get("class", "").split()}
            if "name" in classes:
                self._product_name_depth += 1
                self._product_name_parts = []
            if "model" in classes:
                self._product_model_depth += 1
                self._product_model_parts = []
        elif lowered == "td":
            title = attributes.get("title", "").strip()
            alt = attributes.get("alt", "").strip()
            if title and alt:
                self._positive_cell_depth += 1
                self._positive_cell_parts = []
                self._positive_cell_title = title
                self._positive_cell_alt = alt

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered == "title" and self._title_depth:
            self._title_depth -= 1
        elif lowered == "h1":
            if self._h1_depth:
                self._h1_depth -= 1
            if self._sonos_product_name_depth:
                self._sonos_product_name_depth -= 1
                value = " ".join(" ".join(self._sonos_product_name_parts).split())
                if value:
                    self.sonos_product_names.append(value)
                self._sonos_product_name_parts = []
        elif lowered == "script" and self._script_depth:
            self._script_depth -= 1
            document = "".join(self._script_parts).strip()
            if document:
                self.json_ld_documents.append(document)
            self._script_parts = []
        elif lowered == "p" and self._product_name_depth:
            self._product_name_depth -= 1
            value = " ".join(" ".join(self._product_name_parts).split())
            if value:
                self.product_names.append(value)
            self._product_name_parts = []
        elif lowered == "p" and self._product_model_depth:
            self._product_model_depth -= 1
            value = " ".join(" ".join(self._product_model_parts).split())
            if value:
                self.product_models.append(value)
            self._product_model_parts = []
        elif lowered == "td" and self._positive_cell_depth:
            self._positive_cell_depth -= 1
            value = " ".join(" ".join(self._positive_cell_parts).split())
            self.positive_cells.append(
                (self._positive_cell_title, self._positive_cell_alt, value)
            )
            self._positive_cell_parts = []
            self._positive_cell_title = ""
            self._positive_cell_alt = ""

    def handle_data(self, data: str) -> None:
        if self._script_depth:
            self._script_parts.append(data)
        elif self._title_depth:
            self._title_parts.append(data)
        elif self._h1_depth:
            self._h1_parts.append(data)
        if self._product_name_depth:
            self._product_name_parts.append(data)
        if self._product_model_depth:
            self._product_model_parts.append(data)
        if self._positive_cell_depth:
            self._positive_cell_parts.append(data)
        if self._sonos_product_name_depth:
            self._sonos_product_name_parts.append(data)


class _SonosTaxonomyParser(HTMLParser):
    """Extract product links only from the official Speakers taxonomy block."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._target_article_depth = 0
        self._heading_depth = 0
        self._anchor_depth = 0
        self._heading_parts: list[str] = []
        self._anchor_parts: list[str] = []
        self._anchor_href = ""
        self.headings: list[str] = []
        self.anchors: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        attributes = {str(key).casefold(): str(value or "") for key, value in attrs}
        if lowered == "article":
            if self._target_article_depth:
                self._target_article_depth += 1
            elif (
                _normalized_exact(attributes.get("data-test-id"))
                == "pbp-grid-speakers content-module"
            ):
                self._target_article_depth = 1
        elif self._target_article_depth and lowered == "h3":
            self._heading_depth += 1
            self._heading_parts = []
        elif self._target_article_depth and lowered == "a":
            self._anchor_depth += 1
            self._anchor_href = attributes.get("href", "").strip()
            self._anchor_parts = []

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if self._target_article_depth and lowered == "h3" and self._heading_depth:
            self._heading_depth -= 1
            value = " ".join(" ".join(self._heading_parts).split())
            if value:
                self.headings.append(value)
            self._heading_parts = []
        elif self._target_article_depth and lowered == "a" and self._anchor_depth:
            self._anchor_depth -= 1
            value = " ".join(" ".join(self._anchor_parts).split())
            if self._anchor_href and value:
                self.anchors.append((self._anchor_href, value))
            self._anchor_href = ""
            self._anchor_parts = []
        elif lowered == "article" and self._target_article_depth:
            self._target_article_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._heading_depth:
            self._heading_parts.append(data)
        if self._anchor_depth:
            self._anchor_parts.append(data)


def _normalized_exact(value: object) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).strip().casefold().split())


def _contains_exact_token(value: object, token: object) -> bool:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    expected = unicodedata.normalize("NFKC", str(token or "")).strip().casefold()
    if not expected or len(expected) > 48:
        return False
    return re.search(rf"(?<![0-9a-z]){re.escape(expected)}(?![0-9a-z])", text) is not None


def _registered_official_host(host: str, manufacturer: str) -> bool:
    # Some registered hosts require a product/support prefix.  Trying these
    # inert paths reuses the central registration policy without importing its
    # private registry or performing network I/O.
    probe_paths = (
        "/products/hg-host-check",
        "/product/hg-host-check",
        "/chromecast/answer/123/",
        "/searchsvc/ajax/v1/search/spt-psp-cst-sm-model",
    )
    return any(
        source_matches_registered_official_domain(
            f"https://{host}{path}", manufacturer
        )
        for path in probe_paths
    )


def _validated_host(value: object, manufacturer: str) -> str:
    host = str(value or "").strip().strip(".").casefold()
    if (
        not _FQDN_RE.fullmatch(host)
        or host.endswith(".local")
        or host in {"localhost", "localhost.localdomain"}
        or not _registered_official_host(host, manufacturer)
    ):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")


def _url_components_are_safe(url: str, allowed_hosts: frozenset[str]) -> bool:
    if not isinstance(url, str) or not url or len(url) > 2048:
        return False
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return False
    host = str(parsed.hostname or "").strip(".").casefold()
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or host not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or host.endswith(".local")
    ):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    decoded_path = unquote(parsed.path or "/")
    if "\\" in decoded_path or "\x00" in decoded_path:
        return False
    if any(segment in {".", ".."} for segment in decoded_path.split("/")):
        return False
    return True


def _profile_text_list(value: object, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 16 or (not value and not allow_empty):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
    result: list[str] = []
    for item in value:
        text = " ".join(str(item or "").strip().split())
        if not text or len(text) > 64 or any(character in text for character in "\r\n\x00"):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
        result.append(text)
    if len(set(item.casefold() for item in result)) != len(result):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
    return tuple(result)


def _load_profiles(path: Path | None = None) -> tuple[_TrustProfile, ...]:
    source_path = path or OFFICIAL_PRODUCT_SOURCES_PATH
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID") from exc
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "profiles"}:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
    if raw.get("schema_version") != 2 or not isinstance(raw.get("profiles"), list):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
    if not 1 <= len(raw["profiles"]) <= 32:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")

    profiles: list[_TrustProfile] = []
    seen_manufacturers: set[str] = set()
    for item in raw["profiles"]:
        if not isinstance(item, Mapping) or "enabled" not in item:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
        enabled = item.get("enabled")
        expected_keys = (
            {
                "manufacturer",
                "enabled",
                "official_fqdns",
                "canary",
                "positive_proof",
                "endpoints",
            }
            if enabled is True
            else {
                "manufacturer",
                "enabled",
                "official_fqdns",
                "disabled_reason",
                "endpoints",
            }
        )
        if not isinstance(enabled, bool) or set(item) != expected_keys:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")

        manufacturer = normalize_vendor_name(str(item.get("manufacturer") or "").strip())
        manufacturer_key = manufacturer.casefold()
        hosts_raw = item.get("official_fqdns")
        endpoints_raw = item.get("endpoints")
        if (
            not manufacturer
            or manufacturer_key in seen_manufacturers
            or not isinstance(hosts_raw, list)
            or not 1 <= len(hosts_raw) <= 8
            or not isinstance(endpoints_raw, list)
            or not 1 <= len(endpoints_raw) <= _MAX_ENDPOINTS_PER_JOB
        ):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
        hosts = frozenset(_validated_host(value, manufacturer) for value in hosts_raw)
        if len(hosts) != len(hosts_raw):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")

        endpoints: list[_Endpoint] = []
        for endpoint in endpoints_raw:
            if not isinstance(endpoint, Mapping) or not set(endpoint).issubset(
                {"kind", "url_template", "expected_device_type"}
            ) or not {"kind", "url_template"}.issubset(endpoint):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            kind = str(endpoint.get("kind") or "").strip()
            template = str(endpoint.get("url_template") or "").strip()
            expected_type = (
                _normalized_type(endpoint.get("expected_device_type"))
                if endpoint.get("expected_device_type") is not None
                else None
            )
            placeholder_count = sum(
                template.count(token) for token in ("{model}", "{model_slug}")
            )
            if (
                kind
                not in {
                    "detail",
                    "authoritative_catalog",
                    "authoritative_category",
                    "samsung_model_discovery",
                    "lg_support_discovery",
                    "sonos_support_product",
                    "asus_support_discovery",
                }
                or len(template) > 512
                or (
                    kind == "samsung_model_discovery"
                    and placeholder_count != 0
                )
                or (
                    kind != "samsung_model_discovery"
                    and placeholder_count != 1
                )
                or ("expected_device_type" in endpoint and expected_type is None)
                or (kind == "authoritative_category" and expected_type is None)
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            rendered = template.replace("{model}", "HGTEST123").replace(
                "{model_slug}", "hgtest123"
            )
            if "{" in rendered or "}" in rendered or not _url_components_are_safe(rendered, hosts):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            endpoints.append(
                _Endpoint(
                    kind=kind,
                    url_template=template,
                    expected_device_type=expected_type,
                )
            )

        parser: str | None = None
        manufacturer_terms: tuple[str, ...] = ()
        device_type_terms: dict[str, tuple[str, ...]] = {}
        canaries: list[_CanaryCase] = []
        if enabled:
            proof = item.get("positive_proof")
            if (
                not isinstance(proof, Mapping)
                or set(proof) != {"parser", "manufacturer_terms", "device_type_terms"}
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            parser = str(proof.get("parser") or "").strip()
            manufacturer_terms = _profile_text_list(proof.get("manufacturer_terms"))
            raw_type_terms = proof.get("device_type_terms")
            if parser not in _ACTIVE_PARSERS or not isinstance(raw_type_terms, Mapping):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            for raw_type, raw_terms in raw_type_terms.items():
                normalized_type = _normalized_type(raw_type)
                if normalized_type is None or normalized_type in device_type_terms:
                    raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
                device_type_terms[normalized_type] = _profile_text_list(
                    raw_terms,
                    allow_empty=parser == "iptime_download_category",
                )
            raw_canary = item.get("canary")
            raw_canaries = (
                [raw_canary]
                if isinstance(raw_canary, Mapping)
                else raw_canary
                if isinstance(raw_canary, list)
                else []
            )
            if not 1 <= len(raw_canaries) <= 8:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            seen_canary_types: set[str] = set()
            for canary in raw_canaries:
                if (
                    not isinstance(canary, Mapping)
                    or set(canary)
                    != {"known_model", "impossible_model", "device_type"}
                ):
                    raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
                canary_known = str(canary.get("known_model") or "").strip()
                canary_impossible = str(canary.get("impossible_model") or "").strip()
                canary_type = _normalized_type(canary.get("device_type"))
                if (
                    not _MODEL_TOKEN_RE.fullmatch(canary_known)
                    or not _MODEL_TOKEN_RE.fullmatch(canary_impossible)
                    or _normalized_exact(canary_known)
                    == _normalized_exact(canary_impossible)
                    or canary_type is None
                    or canary_type in seen_canary_types
                    or canary_type not in device_type_terms
                    or not any(
                        endpoint.expected_device_type in {None, canary_type}
                        for endpoint in endpoints
                    )
                ):
                    raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
                seen_canary_types.add(canary_type)
                canaries.append(
                    _CanaryCase(
                        known_model=canary_known,
                        impossible_model=canary_impossible,
                        device_type=canary_type,
                    )
                )
            if parser == "iptime_download_category" and not all(
                endpoint.kind == "authoritative_category"
                and endpoint.expected_device_type is not None
                for endpoint in endpoints
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            if any(
                endpoint.kind == "samsung_model_discovery"
                for endpoint in endpoints
            ) and (
                parser != "samsung_support_product"
                or any(
                    endpoint.kind == "samsung_model_discovery"
                    and urlsplit(endpoint.url_template).path
                    != "/sec/xhr/prdMdlSearch/"
                    for endpoint in endpoints
                )
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            special_kind = _SPECIAL_ENDPOINT_KIND_BY_PARSER.get(parser)
            if special_kind is not None and (
                len(endpoints) != 1 or endpoints[0].kind != special_kind
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            if parser == "lg_support_product" and (
                endpoints[0].url_template != _LG_DISCOVERY_TEMPLATE
                or endpoints[0].expected_device_type is not None
                or hosts != frozenset({"apiv2.lge.co.kr", "www.lge.co.kr"})
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            if parser == "sonos_support_product" and (
                not _SONOS_DETAIL_TEMPLATE_RE.fullmatch(endpoints[0].url_template)
                or endpoints[0].expected_device_type != "speaker"
                or hosts != frozenset({"support.sonos.com"})
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
            if parser == "asus_support_product" and (
                endpoints[0].url_template != _ASUS_DISCOVERY_TEMPLATE
                or endpoints[0].expected_device_type != "router"
                or hosts != frozenset({"www.asus.com"})
            ):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")
        else:
            disabled_reason = " ".join(str(item.get("disabled_reason") or "").split())
            if not disabled_reason or len(disabled_reason) > 160:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_INVALID")

        seen_manufacturers.add(manufacturer_key)
        profiles.append(
            _TrustProfile(
                manufacturer=manufacturer,
                enabled=enabled,
                official_fqdns=hosts,
                parser=parser,
                manufacturer_terms=manufacturer_terms,
                device_type_terms=device_type_terms,
                canaries=tuple(canaries),
                endpoints=tuple(endpoints),
            )
        )
    return tuple(profiles)


def _render_endpoint(endpoint: _Endpoint, model: str) -> str:
    encoded = quote(model, safe="")
    slug = quote(re.sub(r"[^0-9A-Za-z]+", "-", model).strip("-").casefold(), safe="-")
    return endpoint.url_template.replace("{model}", encoded).replace("{model_slug}", slug)


def _default_dns_resolver(hostname: str) -> Sequence[str]:
    try:
        records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_FAILED") from exc
    return tuple(dict.fromkeys(record[4][0] for record in records if record[4]))


def _resolve_dns_with_deadline(
    hostname: str,
    resolver: OfficialDnsResolver,
    *,
    deadline: float,
) -> Sequence[str]:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
    if not _DNS_SLOTS.acquire(blocking=False):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_BUSY")

    result_queue: queue.Queue[tuple[bool, object]] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            result_queue.put((True, resolver(hostname)), block=False)
        except BaseException as exc:  # worker must always release its bounded slot
            try:
                result_queue.put((False, exc), block=False)
            except queue.Full:
                pass
        finally:
            _DNS_SLOTS.release()

    threading.Thread(
        target=run,
        name="home-guardian-official-dns",
        daemon=True,
    ).start()
    try:
        succeeded, value = result_queue.get(timeout=remaining)
    except queue.Empty as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT") from exc
    if time.monotonic() >= deadline:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
    if not succeeded:
        if isinstance(value, OfficialProductLookupFailure):
            raise value
        if isinstance(value, (OSError, TimeoutError, ValueError)):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_FAILED") from value
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_FAILED")
    if isinstance(value, (str, bytes)):
        return (str(value),)
    if not isinstance(value, Sequence):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_FAILED")
    return value


def _public_resolved_ips(
    hostname: str,
    resolver: OfficialDnsResolver,
    *,
    deadline: float,
) -> tuple[str, ...]:
    values = _resolve_dns_with_deadline(hostname, resolver, deadline=deadline)
    if isinstance(values, (str, bytes)):
        values = (str(values),)
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for raw in values:
        value = str(raw or "").split("%", 1)[0].strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_REJECTED") from exc
        if not address.is_global:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_REJECTED")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_DNS_FAILED")
    # Raspberry Pi installations commonly have no usable IPv6 route even when a
    # vendor publishes AAAA records. Keep every answer pinned and validated, but
    # try IPv4 first and fall back only across this prevalidated DNS result set.
    ordered = sorted(addresses, key=lambda address: address.version != 4)
    return tuple(str(address) for address in ordered[:_MAX_RESOLVED_IP_ATTEMPTS])


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, resolved_ip: str, *, timeout: float) -> None:
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._resolved_ip = resolved_ip

    def connect(self) -> None:  # pragma: no cover - exercised only by live network I/O
        raw_socket = socket.create_connection((self._resolved_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _pinned_https_transport(
    *,
    url: str,
    headers: Mapping[str, str],
    timeout_seconds: float,
    max_response_bytes: int,
    resolved_ip: str,
    method: str = "GET",
    body: bytes | None = None,
) -> OfficialHttpResponse:
    parsed = urlsplit(url)
    host = str(parsed.hostname or "")
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    request_budget = min(float(timeout_seconds), _REQUEST_TIMEOUT_SECONDS)
    deadline = time.monotonic() + request_budget
    connection = _PinnedHTTPSConnection(
        host,
        resolved_ip,
        timeout=request_budget,
    )
    try:
        connection.request(method, target, body=body, headers=dict(headers))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        response = connection.getresponse()
        response_headers = {key.casefold(): value for key, value in response.getheaders()}
        body = bytearray()
        while len(body) <= max_response_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read(
                min(_READ_CHUNK_BYTES, max_response_bytes + 1 - len(body))
            )
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > max_response_bytes:
            del body[max_response_bytes:]
            response_headers["x-home-guardian-body-truncated"] = "1"
        return OfficialHttpResponse(response.status, response_headers, bytes(body))
    except OfficialProductLookupFailure:
        raise
    except (OSError, TimeoutError, http.client.HTTPException, ssl.SSLError) as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TRANSPORT_FAILED") from exc
    finally:
        connection.close()


def _coerce_response(value: OfficialHttpResponse | Mapping[str, Any]) -> OfficialHttpResponse:
    if isinstance(value, OfficialHttpResponse):
        response = value
    elif isinstance(value, Mapping):
        body = value.get("body", b"")
        if isinstance(body, str):
            body = body.encode("utf-8")
        if not isinstance(body, bytes) or not isinstance(value.get("headers", {}), Mapping):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_INVALID_RESPONSE")
        try:
            status = int(value.get("status_code") or value.get("status") or 0)
        except (TypeError, ValueError) as exc:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_INVALID_RESPONSE") from exc
        response = OfficialHttpResponse(status, dict(value.get("headers") or {}), body)
    else:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_INVALID_RESPONSE")
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_RESPONSE_TOO_LARGE")
    return OfficialHttpResponse(
        status_code=response.status_code,
        headers={str(key).casefold(): str(item) for key, item in response.headers.items()},
        body=response.body,
    )


def _fetch_page(
    url: str,
    *,
    profile: _TrustProfile,
    transport: OfficialProductTransport,
    resolver: OfficialDnsResolver,
    deadline: float,
    method: str = "GET",
    body: bytes | None = None,
    request_headers: Mapping[str, str] | None = None,
) -> tuple[str, OfficialHttpResponse, int]:
    normalized_method = str(method or "GET").strip().upper()
    if normalized_method not in {"GET", "POST"}:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REQUEST_REJECTED")
    if normalized_method == "GET" and body is not None:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REQUEST_REJECTED")
    if normalized_method == "POST" and (not isinstance(body, bytes) or len(body) > 256):
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REQUEST_REJECTED")
    current = url
    seen: set[str] = set()
    pages = 0
    for redirect_count in range(_MAX_REDIRECTS + 1):
        if time.monotonic() >= deadline:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
        if current in seen or not _url_components_are_safe(current, profile.official_fqdns):
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_URL_REJECTED")
        seen.add(current)
        host = str(urlsplit(current).hostname or "").casefold()
        resolved_ips = _public_resolved_ips(host, resolver, deadline=deadline)
        raw_response: OfficialHttpResponse | Mapping[str, Any] | None = None
        last_transport_failure: OfficialProductLookupFailure | None = None
        for resolved_ip in resolved_ips:
            remaining = min(_REQUEST_TIMEOUT_SECONDS, deadline - time.monotonic())
            if remaining <= 0:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
            try:
                transport_args: dict[str, Any] = {
                    "url": current,
                    "headers": {
                        "Accept": "application/ld+json, application/json, text/html;q=0.9",
                        "Accept-Encoding": "identity",
                        "User-Agent": _USER_AGENT,
                        **dict(request_headers or {}),
                    },
                    "timeout_seconds": remaining,
                    "max_response_bytes": _MAX_RESPONSE_BYTES,
                    "resolved_ip": resolved_ip,
                }
                if normalized_method != "GET":
                    transport_args.update(
                        {"method": normalized_method, "body": body}
                    )
                raw_response = transport(**transport_args)
                break
            except OfficialProductLookupFailure as exc:
                if exc.code != "OFFICIAL_LOOKUP_TRANSPORT_FAILED":
                    raise
                last_transport_failure = exc
            except TimeoutError as exc:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT") from exc
            except (OSError, ValueError) as exc:
                last_transport_failure = OfficialProductLookupFailure(
                    "OFFICIAL_LOOKUP_TRANSPORT_FAILED"
                )
                last_transport_failure.__cause__ = exc
        if raw_response is None:
            raise last_transport_failure or OfficialProductLookupFailure(
                "OFFICIAL_LOOKUP_TRANSPORT_FAILED"
            )
        if time.monotonic() >= deadline:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_TIMEOUT")
        response = _coerce_response(raw_response)
        pages += 1
        if response.status_code in _REDIRECT_STATUSES:
            if normalized_method != "GET":
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REDIRECT_REJECTED")
            if redirect_count >= _MAX_REDIRECTS:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REDIRECT_REJECTED")
            location = response.headers.get("location", "").strip()
            if not location or len(location) > 2048:
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REDIRECT_REJECTED")
            redirected = urljoin(current, location)
            if not _url_components_are_safe(redirected, profile.official_fqdns):
                raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REDIRECT_REJECTED")
            current = redirected
            continue
        if response.status_code != 200:
            raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_HTTP_REJECTED")
        return current, response, pages
    raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_REDIRECT_REJECTED")


def _content_type(headers: Mapping[str, str]) -> str:
    return str(headers.get("content-type") or "").split(";", 1)[0].strip().casefold()


def _decode_body(
    response: OfficialHttpResponse,
    *,
    allowed_content_types: frozenset[str] | None = None,
) -> str:
    content_type = _content_type(response.headers)
    accepted = allowed_content_types or (_HTML_CONTENT_TYPES | _JSON_CONTENT_TYPES)
    if content_type not in accepted:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_CONTENT_REJECTED")
    try:
        if response.headers.get("x-home-guardian-body-truncated") == "1":
            return codecs.getincrementaldecoder("utf-8")("strict").decode(
                response.body,
                final=False,
            )
        return response.body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_CONTENT_REJECTED") from exc


def _samsung_discovery_binding(
    response: OfficialHttpResponse,
    *,
    profile: _TrustProfile,
    model: str,
    device_type: str,
) -> _SamsungDiscoveryBinding | None:
    """Parse Samsung's exact-model XHR result as discovery, never as proof.

    The response only selects a full support SKU.  Resolution still requires a
    second, manufacturer-owned support page whose full SKU, base model,
    category and support state all agree with this record.
    """

    if _content_type(response.headers) not in _JSON_CONTENT_TYPES:
        return None
    try:
        payload = json.loads(_decode_body(response))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, Mapping):
        return None
    info = payload.get("prdMdlInfo")
    if not isinstance(info, Mapping):
        return None
    base_model = " ".join(str(info.get("prdMdlName") or "").strip().split())
    full_model = " ".join(str(info.get("prdMdlCd") or "").strip().split())
    goods_id = str(info.get("goodsId") or "").strip()
    type_term = " ".join(str(info.get("prdIaName") or "").strip().split())
    if (
        _normalized_exact(base_model) != _normalized_exact(model)
        or not full_model.startswith(base_model)
        or not re.fullmatch(r"[A-Z0-9]{3,16}", full_model[len(base_model) :])
        or not re.fullmatch(r"G[0-9]{6,16}", goods_id)
        or _normalized_exact(type_term)
        not in {
            _normalized_exact(term)
            for term in profile.device_type_terms.get(device_type, ())
        }
    ):
        return None
    return _SamsungDiscoveryBinding(
        base_model=base_model,
        full_model=full_model,
        goods_id=goods_id,
        device_type_term=type_term,
    )


def _json_mapping(
    response: OfficialHttpResponse,
    *,
    allow_asus_text_json: bool = False,
) -> Mapping[str, Any] | None:
    accepted = (
        _ASUS_DISCOVERY_JSON_CONTENT_TYPES
        if allow_asus_text_json
        else _JSON_CONTENT_TYPES
    )
    if _content_type(response.headers) not in accepted:
        return None
    try:
        payload = json.loads(_decode_body(response, allowed_content_types=accepted))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, Mapping) else None


def _lg_support_binding(
    response: OfficialHttpResponse,
    *,
    profile: _TrustProfile,
    model: str,
    device_type: str,
) -> _LgSupportBinding | None:
    """Bind one exact LG support record; the record is discovery, not proof."""

    payload = _json_mapping(response)
    if (
        payload is None
        or payload.get("status") != 200
        or str(payload.get("message") or "").strip().casefold() != "ok"
        or not isinstance(payload.get("data"), Mapping)
    ):
        return None
    info = payload["data"].get("info")
    if not isinstance(info, Mapping):
        return None
    expected = _normalized_exact(model)
    if any(
        _normalized_exact(info.get(field)) != expected
        for field in ("modelId", "modelName")
    ):
        return None
    market_model = str(info.get("mktModelName") or "").strip()
    display_model = str(info.get("modelDisplayName") or "").strip()
    # LG's live support record for some TV SKUs publishes a null
    # ``mktModelName``.  Never accept a conflicting value: the documented
    # display model is the required exact fallback only when that field is
    # genuinely absent.
    if market_model:
        if _normalized_exact(market_model) != expected:
            return None
    elif _normalized_exact(display_model) != expected:
        return None
    detail_path = str(info.get("modelUrlPath") or "").strip()
    expected_path = f"/support/product-{model}"
    if detail_path != expected_path or "?" in detail_path or "#" in detail_path:
        return None
    super_category = " ".join(str(info.get("superCategoryName") or "").split())
    category = " ".join(str(info.get("categoryName") or "").split())
    allowed = {
        _normalized_exact(term)
        for term in profile.device_type_terms.get(device_type, ())
    }
    if (
        not super_category
        or not category
        or _normalized_exact(super_category) not in allowed
        or _normalized_exact(category) not in allowed
    ):
        return None
    return _LgSupportBinding(
        detail_path=detail_path,
        super_category=super_category,
        category=category,
    )


def _asus_helpdesk_base(
    raw_url: object,
    *,
    profile: _TrustProfile,
    model_slug: str,
) -> tuple[str, str] | None:
    if not isinstance(raw_url, str) or not _url_components_are_safe(
        raw_url, profile.official_fqdns
    ):
        return None
    parsed = urlsplit(raw_url)
    if str(parsed.hostname or "").casefold() != "www.asus.com":
        return None
    path_match = re.fullmatch(
        r"/us/networking-iot-servers/wifi-routers/"
        r"(?P<branch>asus-wifi-routers|asus-gaming-routers)/"
        r"(?P<slug>[0-9a-z-]+)/helpdesk_[0-9a-z_-]+/?",
        unquote(parsed.path).casefold(),
    )
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return None
    if (
        path_match is None
        or path_match.group("slug") != model_slug.casefold()
        or query != [("model2Name", model_slug)]
    ):
        return None
    branch = path_match.group("branch")
    base_path = (
        "/us/networking-iot-servers/wifi-routers/"
        f"{branch}/{model_slug.casefold()}"
    )
    return base_path, branch


def _asus_support_binding(
    response: OfficialHttpResponse,
    *,
    profile: _TrustProfile,
    model: str,
) -> _AsusSupportBinding | None:
    """Validate every ASUS HelpDesk URL before deriving one techspec detail."""

    payload = _json_mapping(response, allow_asus_text_json=True)
    if (
        payload is None
        or str(payload.get("Status") or "") != "SUCCESS"
        or str(payload.get("Message") or "") != "SUCCESS"
        or not isinstance(payload.get("Result"), Mapping)
    ):
        return None
    result = payload["Result"]
    if _normalized_exact(result.get("PDMarketName")) != _normalized_exact(model):
        return None
    objects = result.get("Obj")
    if not isinstance(objects, list) or not 1 <= len(objects) <= 16:
        return None

    urls: list[object] = []
    for item in objects:
        if not isinstance(item, Mapping) or not isinstance(item.get("Items"), list):
            return None
        urls.append(item.get("Url"))
        if len(item["Items"]) > 16:
            return None
        for nested in item["Items"]:
            if not isinstance(nested, Mapping):
                return None
            urls.append(nested.get("Url"))
    if not urls or len(urls) > 64:
        return None

    model_slug = re.sub(r"[^0-9A-Za-z]+", "-", model).strip("-")
    bases: set[tuple[str, str]] = set()
    for raw_url in urls:
        parsed = _asus_helpdesk_base(
            raw_url,
            profile=profile,
            model_slug=model_slug,
        )
        if parsed is None:
            return None
        bases.add(parsed)
    if len(bases) != 1:
        return None
    base_path, branch = next(iter(bases))
    origin = "https://www.asus.com"
    return _AsusSupportBinding(
        detail_url=f"{origin}{base_path}/techspec/",
        overview_url=f"{origin}{base_path}/",
        category_url=f"{origin}{base_path.rsplit('/', 1)[0]}/",
        branch_name=_ASUS_BRANCH_NAMES[branch],
    )


def _sonos_taxonomy_matches(
    response: OfficialHttpResponse,
    *,
    index_url: str,
    detail_url: str,
    profile: _TrustProfile,
    model: str,
    device_type: str,
) -> bool:
    if _content_type(response.headers) not in _HTML_CONTENT_TYPES:
        return False
    parser = _SonosTaxonomyParser()
    try:
        parser.feed(_decode_body(response))
        parser.close()
    except (ValueError, RuntimeError):
        return False
    allowed_headings = {
        _normalized_exact(term)
        for term in profile.device_type_terms.get(device_type, ())
    }
    if not parser.headings or any(
        _normalized_exact(value) not in allowed_headings for value in parser.headings
    ):
        return False
    matches: set[str] = set()
    for raw_href, text in parser.anchors:
        if _normalized_exact(text) != _normalized_exact(model):
            continue
        candidate = urljoin(index_url, raw_href)
        if not _url_components_are_safe(candidate, profile.official_fqdns):
            return False
        parsed = urlsplit(candidate)
        if parsed.query or parsed.fragment:
            return False
        matches.add(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")))
    return matches == {detail_url}


def _walk_mappings(value: object, *, max_nodes: int = 512) -> list[Mapping[str, Any]]:
    found: list[Mapping[str, Any]] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while stack and visited < max_nodes:
        current, depth = stack.pop()
        visited += 1
        if depth > 12:
            continue
        if isinstance(current, Mapping):
            found.append(current)
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
    return found


def _field_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return (str(value),)
    if isinstance(value, Mapping):
        name = value.get("name")
        return (str(name),) if isinstance(name, (str, int, float)) else ()
    if isinstance(value, list):
        return tuple(item for value_item in value for item in _field_strings(value_item))[:16]
    return ()


def _mapping_has_exact_model(mapping: Mapping[str, Any], model: str) -> bool:
    expected = _normalized_exact(model)
    return any(
        _normalized_exact(value) == expected
        for field in _PRODUCT_MODEL_FIELDS
        for value in _field_strings(mapping.get(field))
    )


def _mapping_has_exact_manufacturer(mapping: Mapping[str, Any], manufacturer: str) -> bool:
    expected = normalize_vendor_name(manufacturer).casefold()
    values = [
        normalize_vendor_name(value).casefold()
        for field in _CATALOG_MANUFACTURER_FIELDS
        for value in _field_strings(mapping.get(field))
        if value.strip()
    ]
    return bool(values) and set(values) == {expected}


def _is_json_ld_product(mapping: Mapping[str, Any]) -> bool:
    values = _field_strings(mapping.get("@type"))
    return any(value.casefold() == "product" for value in values)


def _safe_product_source(
    raw_source: object,
    *,
    base_url: str,
    profile: _TrustProfile,
) -> str | None:
    if not isinstance(raw_source, str) or not raw_source.strip():
        return None
    candidate = urljoin(base_url, raw_source.strip())
    if not _url_components_are_safe(candidate, profile.official_fqdns):
        return None
    parsed = urlsplit(candidate)
    without_query = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    if not source_matches_registered_official_domain(without_query, profile.manufacturer):
        return None
    return without_query


def _contains_positive_term(value: object, term: object) -> bool:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    expected = unicodedata.normalize("NFKC", str(term or "")).strip().casefold()
    if not expected:
        return False
    return (
        re.search(
            rf"(?<![0-9a-z가-힣]){re.escape(expected)}(?![0-9a-z가-힣])",
            text,
        )
        is not None
    )


def _has_manufacturer_term(profile: _TrustProfile, values: Sequence[object]) -> bool:
    return any(
        _contains_positive_term(value, term)
        for value in values
        for term in profile.manufacturer_terms
    )


def _has_device_type_term(
    profile: _TrustProfile,
    device_type: str,
    values: Sequence[object],
) -> bool:
    return any(
        _contains_positive_term(value, term)
        for value in values
        for term in profile.device_type_terms.get(device_type, ())
    )


def _mapping_has_exact_device_type(
    mapping: Mapping[str, Any],
    *,
    profile: _TrustProfile,
    device_type: str,
) -> bool:
    values = tuple(
        value
        for field in _STRUCTURED_DEVICE_TYPE_FIELDS
        for value in _field_strings(mapping.get(field))
        if str(value).strip()
    )
    expected = {
        _normalized_exact(device_type),
        _normalized_exact(DEVICE_TYPE_LABELS.get(device_type, "")),
        *(
            _normalized_exact(term)
            for term in profile.device_type_terms.get(device_type, ())
        ),
    }
    expected.discard("")
    return bool(values) and all(_normalized_exact(value) in expected for value in values)


def _canonical_source(
    parser: _ProductHtmlParser,
    *,
    final_url: str,
    profile: _TrustProfile,
    require_declared: bool,
) -> str | None:
    final_source = _safe_product_source(
        final_url,
        base_url=final_url,
        profile=profile,
    )
    if final_source is None:
        return None
    declared = {
        source
        for raw in parser.canonical_urls
        if (
            source := _safe_product_source(
                raw,
                base_url=final_url,
                profile=profile,
            )
        )
        is not None
    }
    if require_declared and final_source not in declared:
        return None
    return final_source


def _alnum_key(value: object) -> str:
    return "".join(
        character
        for character in unicodedata.normalize("NFKC", str(value or "")).casefold()
        if character.isalnum()
    )


def _asus_breadcrumb_matches(
    parser: _ProductHtmlParser,
    *,
    binding: _AsusSupportBinding,
    model: str,
) -> bool:
    breadcrumbs: list[Mapping[str, Any]] = []
    for raw_document in parser.json_ld_documents[:32]:
        try:
            document = json.loads(raw_document)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        breadcrumbs.extend(
            mapping
            for mapping in _walk_mappings(document)
            if any(
                value.casefold() == "breadcrumblist"
                for value in _field_strings(mapping.get("@type"))
            )
        )
    if len(breadcrumbs) != 1:
        return False
    elements = breadcrumbs[0].get("itemListElement")
    if not isinstance(elements, list) or len(elements) != 4:
        return False
    by_position: dict[int, Mapping[str, Any]] = {}
    for element in elements:
        if not isinstance(element, Mapping):
            return False
        try:
            position = int(element.get("position"))
        except (TypeError, ValueError):
            return False
        if position in by_position:
            return False
        by_position[position] = element
    if set(by_position) != {1, 2, 3, 4}:
        return False
    if (
        _normalized_exact(by_position[2].get("name")) != "wifi routers"
        or _normalized_exact(by_position[3].get("name"))
        != _normalized_exact(binding.branch_name)
        or _normalized_exact(by_position[4].get("name")) != _normalized_exact(model)
    ):
        return False
    return (
        str(by_position[3].get("item") or "").strip() == binding.category_url
        and str(by_position[4].get("item") or "").strip() == binding.overview_url
    )


def _html_profile_candidate(
    parser: _ProductHtmlParser,
    body: str,
    *,
    final_url: str,
    endpoint: _Endpoint,
    profile: _TrustProfile,
    model: str,
    device_type: str,
    samsung_binding: _SamsungDiscoveryBinding | None = None,
    lg_binding: _LgSupportBinding | None = None,
    asus_binding: _AsusSupportBinding | None = None,
    sonos_taxonomy_verified: bool = False,
) -> _Candidate | None:
    if endpoint.expected_device_type not in {None, device_type}:
        return None

    if profile.parser == "samsung_support_product":
        meta_identity = tuple(parser.meta_values.get("og:site_name", ())) + tuple(
            parser.meta_values.get("name", ())
        )
        expected_code = samsung_binding.full_model if samsung_binding else model
        expected_name = samsung_binding.base_model if samsung_binding else model
        escaped_code = re.escape(expected_code)
        escaped_name = re.escape(expected_name)
        goods_pattern = (
            re.escape(samsung_binding.goods_id)
            if samsung_binding
            else r"G[0-9]{6,16}"
        )
        has_support_binding = all(
            re.search(pattern, body, re.IGNORECASE) is not None
            for pattern in (
                rf"\bmdlCode\s*:\s*['\"]{escaped_code}['\"]",
                rf"\bmdlNm\s*:\s*['\"]{escaped_name}['\"]",
                rf"\bgoodsId\s*:\s*['\"]{goods_pattern}['\"]",
                r"\bsupportYn\s*:\s*['\"]Y['\"]",
            )
        )
        path_segments = [
            segment for segment in unquote(urlsplit(final_url).path).split("/") if segment
        ]
        if (
            not has_support_binding
            or not path_segments
            or _normalized_exact(path_segments[-1])
            != _normalized_exact(expected_code)
            or not any(
                _normalized_exact(value) == _normalized_exact(expected_name)
                for value in parser.product_models
            )
            or not _has_manufacturer_term(profile, meta_identity)
            or (
                samsung_binding is None
                and not _has_device_type_term(
                    profile, device_type, parser.product_names
                )
            )
            or (
                samsung_binding is not None
                and _normalized_exact(samsung_binding.device_type_term)
                not in {
                    _normalized_exact(term)
                    for term in profile.device_type_terms.get(device_type, ())
                }
            )
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=False,
        )
    elif profile.parser == "tp_link_product":
        image_values = tuple(parser.meta_values.get("og:image", ()))
        model_key = _alnum_key(model)
        has_model_asset = any(
            (parsed := urlsplit(value)).scheme.casefold() == "https"
            and str(parsed.hostname or "").strip(".").casefold() == "static.tp-link.com"
            and model_key in _alnum_key(unquote(parsed.path))
            for value in image_values
        )
        if (
            not _contains_exact_token(parser.title, model)
            or not _has_manufacturer_term(profile, (parser.title,))
            or not _has_device_type_term(
                profile,
                device_type,
                (parser.title, *parser.headings),
            )
            or not has_model_asset
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=True,
        )
    elif profile.parser == "iptime_download_category":
        if endpoint.kind != "authoritative_category" or endpoint.expected_device_type != device_type:
            return None
        parsed_final = urlsplit(final_url)
        if (
            parsed_final.path.casefold() != "/iptime/etc/down_prd_list.php"
            or "pct_id=15" not in parsed_final.query.casefold().split("&")
        ):
            return None
        expected_cells = {
            _normalized_exact(f"{term} {model}") for term in profile.manufacturer_terms
        }
        if not any(
            _normalized_exact(title) in expected_cells
            and _normalized_exact(alt) in expected_cells
            and _normalized_exact(text) in expected_cells
            for title, alt, text in parser.positive_cells
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=False,
        )
    elif profile.parser == "lg_support_product":
        if (
            endpoint.kind != "lg_support_discovery"
            or lg_binding is None
            or urlsplit(final_url).path != lg_binding.detail_path
            or not _contains_exact_token(parser.title, model)
            or not any(
                _contains_exact_token(value, model) for value in parser.headings
            )
            or not _has_manufacturer_term(profile, (parser.title, *parser.headings))
            or not _contains_positive_term(body, lg_binding.super_category)
            or not _contains_positive_term(body, lg_binding.category)
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=False,
        )
    elif profile.parser == "sonos_support_product":
        meta_identity = tuple(parser.meta_values.get("og:site_name", ()))
        if (
            endpoint.kind != "sonos_support_product"
            or not sonos_taxonomy_verified
            or len(parser.sonos_product_names) != 1
            or _normalized_exact(parser.sonos_product_names[0])
            != _normalized_exact(model)
            or not _contains_exact_token(parser.title, model)
            or {_normalized_exact(value) for value in meta_identity}
            != {"sonos support"}
            or not _has_manufacturer_term(profile, (parser.title,))
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=True,
        )
    elif profile.parser == "asus_support_product":
        if (
            endpoint.kind != "asus_support_discovery"
            or asus_binding is None
            or final_url != asus_binding.detail_url
            or not _contains_exact_token(parser.title, model)
            or not _has_manufacturer_term(profile, (parser.title,))
            or not _has_device_type_term(profile, device_type, (parser.title,))
            or not _asus_breadcrumb_matches(
                parser,
                binding=asus_binding,
                model=model,
            )
        ):
            return None
        source = _canonical_source(
            parser,
            final_url=final_url,
            profile=profile,
            require_declared=True,
        )
    else:
        return None

    if source is None:
        return None
    return _Candidate(profile.manufacturer, device_type, model, source)


def _candidate_from_response(
    response: OfficialHttpResponse,
    *,
    final_url: str,
    endpoint: _Endpoint,
    profile: _TrustProfile,
    model: str,
    device_type: str,
    samsung_binding: _SamsungDiscoveryBinding | None = None,
    lg_binding: _LgSupportBinding | None = None,
    asus_binding: _AsusSupportBinding | None = None,
    sonos_taxonomy_verified: bool = False,
) -> _Candidate | None:
    if not _profile_model_family_matches(profile, model, device_type):
        return None
    body = _decode_body(response)
    content_type = _content_type(response.headers)
    documents: list[object] = []
    title = ""
    headings: tuple[str, ...] = ()
    if content_type in _JSON_CONTENT_TYPES:
        try:
            documents.append(json.loads(body))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    else:
        parser = _ProductHtmlParser()
        try:
            parser.feed(body)
            parser.close()
        except (ValueError, RuntimeError):
            return None
        title = parser.title
        headings = parser.headings
        for raw_document in parser.json_ld_documents[:32]:
            try:
                documents.append(json.loads(raw_document))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue

    if profile.parser not in _SPECIAL_ENDPOINT_KIND_BY_PARSER:
        for document in documents:
            for mapping in _walk_mappings(document):
                if not _is_json_ld_product(mapping) or not _mapping_has_exact_model(
                    mapping, model
                ):
                    continue
                if not _mapping_has_exact_manufacturer(mapping, profile.manufacturer):
                    continue
                if not _mapping_has_exact_device_type(
                    mapping,
                    profile=profile,
                    device_type=device_type,
                ):
                    continue
                raw_source = mapping.get("url") or mapping.get("@id")
                source = _safe_product_source(
                    raw_source,
                    base_url=final_url,
                    profile=profile,
                )
                if source:
                    return _Candidate(profile.manufacturer, device_type, model, source)

    if content_type in _HTML_CONTENT_TYPES:
        return _html_profile_candidate(
            parser,
            body,
            final_url=final_url,
            endpoint=endpoint,
            profile=profile,
            model=model,
            device_type=device_type,
            samsung_binding=samsung_binding,
            lg_binding=lg_binding,
            asus_binding=asus_binding,
            sonos_taxonomy_verified=sonos_taxonomy_verified,
        )
    return None


def _candidate_from_endpoint(
    endpoint: _Endpoint,
    *,
    profile: _TrustProfile,
    model: str,
    device_type: str,
    transport: OfficialProductTransport,
    resolver: OfficialDnsResolver,
    deadline: float,
) -> tuple[_Candidate | None, int]:
    if endpoint.expected_device_type not in {None, device_type}:
        return None, 0
    if endpoint.kind == "lg_support_discovery":
        discovery_url, discovery_response, discovery_pages = _fetch_page(
            _render_endpoint(endpoint, model),
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
            request_headers={"Accept": "application/json"},
        )
        if discovery_url != _render_endpoint(endpoint, model):
            return None, discovery_pages
        binding = _lg_support_binding(
            discovery_response,
            profile=profile,
            model=model,
            device_type=device_type,
        )
        if binding is None:
            return None, discovery_pages
        detail_url = f"https://www.lge.co.kr{binding.detail_path}"
        final_url, detail_response, detail_pages = _fetch_page(
            detail_url,
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
        )
        if final_url != detail_url:
            return None, discovery_pages + detail_pages
        return (
            _candidate_from_response(
                detail_response,
                final_url=final_url,
                endpoint=endpoint,
                profile=profile,
                model=model,
                device_type=device_type,
                lg_binding=binding,
            ),
            discovery_pages + detail_pages,
        )

    if endpoint.kind == "sonos_support_product":
        detail_url = _render_endpoint(endpoint, model)
        final_url, detail_response, detail_pages = _fetch_page(
            detail_url,
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
        )
        if final_url != detail_url:
            return None, detail_pages
        parsed_detail = urlsplit(detail_url)
        detail_segments = [
            segment for segment in parsed_detail.path.split("/") if segment
        ]
        if len(detail_segments) != 3 or detail_segments[1].casefold() != "products":
            return None, detail_pages
        index_url = urlunsplit(
            (
                parsed_detail.scheme,
                parsed_detail.netloc,
                f"/{detail_segments[0]}/products",
                "",
                "",
            )
        )
        final_index_url, index_response, index_pages = _fetch_page(
            index_url,
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
        )
        taxonomy_verified = final_index_url == index_url and _sonos_taxonomy_matches(
            index_response,
            index_url=index_url,
            detail_url=detail_url,
            profile=profile,
            model=model,
            device_type=device_type,
        )
        return (
            _candidate_from_response(
                detail_response,
                final_url=final_url,
                endpoint=endpoint,
                profile=profile,
                model=model,
                device_type=device_type,
                sonos_taxonomy_verified=taxonomy_verified,
            ),
            detail_pages + index_pages,
        )

    if endpoint.kind == "asus_support_discovery":
        rendered_discovery = _render_endpoint(endpoint, model)
        discovery_url, discovery_response, discovery_pages = _fetch_page(
            rendered_discovery,
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
            request_headers={"Accept": "application/json, text/json"},
        )
        if discovery_url != rendered_discovery:
            return None, discovery_pages
        binding = _asus_support_binding(
            discovery_response,
            profile=profile,
            model=model,
        )
        if binding is None:
            return None, discovery_pages
        final_url, detail_response, detail_pages = _fetch_page(
            binding.detail_url,
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
        )
        if final_url != binding.detail_url:
            return None, discovery_pages + detail_pages
        return (
            _candidate_from_response(
                detail_response,
                final_url=final_url,
                endpoint=endpoint,
                profile=profile,
                model=model,
                device_type=device_type,
                asus_binding=binding,
            ),
            discovery_pages + detail_pages,
        )

    if endpoint.kind != "samsung_model_discovery":
        final_url, response, pages = _fetch_page(
            _render_endpoint(endpoint, model),
            profile=profile,
            transport=transport,
            resolver=resolver,
            deadline=deadline,
        )
        return (
            _candidate_from_response(
                response,
                final_url=final_url,
                endpoint=endpoint,
                profile=profile,
                model=model,
                device_type=device_type,
            ),
            pages,
        )

    discovery_url, discovery_response, discovery_pages = _fetch_page(
        endpoint.url_template,
        profile=profile,
        transport=transport,
        resolver=resolver,
        deadline=deadline,
        method="POST",
        body=f"prdMdlName={quote(model, safe='')}".encode("ascii"),
        request_headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    binding = _samsung_discovery_binding(
        discovery_response,
        profile=profile,
        model=model,
        device_type=device_type,
    )
    if binding is None:
        return None, discovery_pages
    parsed_discovery = urlsplit(discovery_url)
    detail_url = urlunsplit(
        (
            parsed_discovery.scheme,
            parsed_discovery.netloc,
            f"/sec/support/model/{quote(binding.full_model, safe='-')}/",
            "",
            "",
        )
    )
    detail_url, detail_response, detail_pages = _fetch_page(
        detail_url,
        profile=profile,
        transport=transport,
        resolver=resolver,
        deadline=deadline,
    )
    candidate = _candidate_from_response(
        detail_response,
        final_url=detail_url,
        endpoint=endpoint,
        profile=profile,
        model=model,
        device_type=device_type,
        samsung_binding=binding,
    )
    return candidate, discovery_pages + detail_pages


def _model_prefix_vendor(model: str) -> str | None:
    upper = model.upper()
    return next(
        (
            normalize_vendor_name(vendor)
            for prefix, vendor in sorted(
                MODEL_PREFIX_VENDOR.items(), key=lambda item: len(item[0]), reverse=True
            )
            if upper.startswith(prefix.upper())
        ),
        None,
    )


def _model_prefix_type(model: str) -> str | None:
    upper = model.upper()
    return next(
        (
            device_type
            for prefix, device_type in sorted(
                MODEL_PREFIX_DEVICE_TYPE, key=lambda item: len(item[0]), reverse=True
            )
            if upper.startswith(prefix.upper())
        ),
        None,
    )


def _profile_model_family_matches(
    profile: _TrustProfile,
    model: str,
    device_type: str,
) -> bool:
    """Apply parser-specific model-family proof without device hardcoding.

    Samsung and LG support routes serve many product families at the same URL.
    The shared device-identity prefix tables therefore have to independently
    bind both the manufacturer and the claimed product type before page
    contents can be considered.  Other profiles retain their parser contracts.
    """

    if profile.parser not in {"samsung_support_product", "lg_support_product"}:
        return True
    prefix_vendor = _model_prefix_vendor(model)
    prefix_type = _model_prefix_type(model)
    return (
        prefix_vendor is not None
        and normalize_vendor_name(prefix_vendor).casefold()
        == profile.manufacturer.casefold()
        and prefix_type == device_type
    )


def _normalized_type(value: object) -> str | None:
    normalized = str(value or "").strip().casefold()
    if normalized in PUBLIC_IDENTITY_TYPES:
        return normalized
    for key, label in DEVICE_TYPE_LABELS.items():
        if key in PUBLIC_IDENTITY_TYPES and _normalized_exact(label) == _normalized_exact(value):
            return key
    return None


def _safe_official_evidence_list(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        return []
    result: list[str] = []
    for item in value:
        text = " ".join(str(item or "").strip().split())
        if not text or len(text) > 96 or any(character in text for character in "\r\n\x00"):
            return []
        result.append(text)
    return list(dict.fromkeys(result))


def _eligible_official_job(job: Mapping[str, Any]) -> dict[str, Any] | None:
    standard = _eligible_job(job)
    if standard is not None:
        return standard

    # The optional AI schema intentionally accepts compact code tokens only.
    # Official manufacturer pages also use exact display models containing a
    # single space (for example ``Archer AX73``).  Preserve all repository CAS
    # and binding checks while allowing that strictly bounded official shape.
    job_id = str(job.get("job_id") or "")
    evidence = job.get("evidence")
    if (
        job.get("status") != "review_required"
        or not _OPAQUE_JOB_ID_RE.fullmatch(job_id)
        or not isinstance(evidence, Mapping)
        or blocked_binding_reason(
            str(job.get("network_scope_id") or "") or None,
            str(job.get("physical_mac") or "") or None,
            evidence,
            device_id=job.get("device_id"),
        )
        is not None
        or not identity_job_key_matches(job)
        or not evidence_signature_matches(evidence, job.get("evidence_signature"))
    ):
        return None
    model_hints = _safe_official_evidence_list(evidence.get("model_hints"))
    models = [model for model in model_hints if _MODEL_TOKEN_RE.fullmatch(model)]
    if len(models) != 1 or " " not in models[0]:
        return None
    proofs = _structured_proofs(evidence)
    concrete_models = _corroborated_models(evidence, models, proofs)
    if len(concrete_models) != 1:
        return None
    safe_evidence = {
        key: values
        for key in (
            "manufacturer_hints",
            "model_hints",
            "device_type_hints",
            "service_hints",
        )
        if (values := _safe_official_evidence_list(evidence.get(key)))
    }
    safe_evidence["model_hints"] = concrete_models
    return {
        "job_id": job_id,
        "evidence": safe_evidence,
        "corroboration": proofs,
        "expected_evidence_signature": str(job.get("evidence_signature") or ""),
        "expected_job_key": str(job.get("job_key") or ""),
    }


def _lookup_target(
    eligible: Mapping[str, Any],
    profiles: Mapping[str, _TrustProfile],
) -> tuple[_TrustProfile, str, str] | None:
    evidence = eligible.get("evidence")
    corroboration = eligible.get("corroboration")
    if not isinstance(evidence, Mapping) or not isinstance(corroboration, list):
        return None
    models = {
        str(value).strip()
        for value in evidence.get("model_hints") or []
        if _MODEL_TOKEN_RE.fullmatch(str(value or "").strip())
    }
    if len(models) != 1:
        return None
    model = next(iter(models))

    hinted_manufacturers = {
        normalize_vendor_name(str(value))
        for value in evidence.get("manufacturer_hints") or []
        if str(value or "").strip()
    }
    prefix_vendor = _model_prefix_vendor(model)
    if prefix_vendor:
        hinted_manufacturers.add(prefix_vendor)
    proof_manufacturers = {
        normalize_vendor_name(str(proof.get("value") or "")).casefold()
        for proof in corroboration
        if isinstance(proof, Mapping)
        and str(proof.get("kind") or "").casefold() == "manufacturer"
        and str(proof.get("value") or "").strip()
    }
    if len(proof_manufacturers) != 1:
        return None
    proof_manufacturer = next(iter(proof_manufacturers))
    profile = profiles.get(proof_manufacturer)
    if profile is None or not profile.enabled:
        return None
    if any(
        value.casefold() != proof_manufacturer for value in hinted_manufacturers
    ):
        return None

    proof_types = {
        normalized
        for proof in corroboration
        if isinstance(proof, Mapping)
        and str(proof.get("kind") or "").casefold() == "device_type"
        and (normalized := _normalized_type(proof.get("value"))) is not None
    }
    hinted_types = {
        normalized
        for value in evidence.get("device_type_hints") or []
        if (normalized := _normalized_type(value)) is not None
    }
    prefix_type = _model_prefix_type(model)
    if len(proof_types) != 1:
        return None
    device_type = next(iter(proof_types))
    if any(value != device_type for value in hinted_types) or (
        prefix_type is not None and prefix_type != device_type
    ):
        return None
    if device_type not in profile.device_type_terms:
        return None
    if not _profile_model_family_matches(profile, model, device_type):
        return None
    return profile, model, device_type


def eligible_official_product_job_ids(
    jobs: Sequence[Mapping[str, Any]],
    *,
    profiles_path: str | Path | None = None,
) -> tuple[str, ...]:
    """Return job ids that can use an enabled official profile, without I/O.

    Profile parsing, repository signatures/bindings and the structured
    manufacturer/model/type proof contract are all evaluated before a caller
    advances retry state.  The result preserves input order so repositories
    can atomically claim only the selected due rows.
    """

    profiles = _load_profiles(Path(profiles_path) if profiles_path else None)
    by_manufacturer = {
        profile.manufacturer.casefold(): profile for profile in profiles if profile.enabled
    }
    eligible_ids: list[str] = []
    seen: set[str] = set()
    for job in jobs:
        if not isinstance(job, Mapping):
            continue
        eligible = _eligible_official_job(job)
        if eligible is None or _lookup_target(eligible, by_manufacturer) is None:
            continue
        job_id = str(job.get("job_id") or "")
        if job_id and job_id not in seen:
            seen.add(job_id)
            eligible_ids.append(job_id)
    return tuple(eligible_ids)


def official_product_lookup_policy_version(
    *,
    profiles_path: str | Path | None = None,
) -> str:
    """Return a stable marker for one validated lookup/profile policy.

    Repositories persist this marker per unresolved job when a release grants
    one immediate retry.  Hashing the validated profile bytes means a profile
    change receives exactly one new retry, while ordinary service restarts do
    not repeatedly clear a six-hour backoff.
    """

    path = Path(profiles_path) if profiles_path else OFFICIAL_PRODUCT_SOURCES_PATH
    _load_profiles(path)
    try:
        profile_bytes = path.read_bytes()
    except OSError as exc:
        raise OfficialProductLookupFailure("OFFICIAL_LOOKUP_PROFILE_UNAVAILABLE") from exc
    digest = hashlib.sha256(
        _OFFICIAL_LOOKUP_POLICY_REVISION.encode("ascii") + b"\0" + profile_bytes
    ).hexdigest()[:20]
    return f"{_OFFICIAL_LOOKUP_POLICY_REVISION}-{digest}"


def validate_official_product_canaries(
    *,
    transport: OfficialProductTransport | None = None,
    resolver: OfficialDnsResolver | None = None,
    profiles_path: str | Path | None = None,
) -> tuple[OfficialProductCanaryOutcome, ...]:
    """Run bounded read-only known/impossible checks for enabled profiles."""

    profiles = _load_profiles(Path(profiles_path) if profiles_path else None)
    client = transport or _pinned_https_transport
    dns_resolver = resolver or _default_dns_resolver
    outcomes: list[OfficialProductCanaryOutcome] = []

    def evaluate(
        profile: _TrustProfile,
        model: str,
        device_type: str,
    ) -> tuple[_Candidate | None, str | None, float]:
        started = time.monotonic()
        first_error: str | None = None
        for endpoint in profile.endpoints:
            if endpoint.expected_device_type not in {None, device_type}:
                continue
            try:
                candidate, _pages = _candidate_from_endpoint(
                    endpoint,
                    profile=profile,
                    model=model,
                    device_type=device_type,
                    transport=client,
                    resolver=dns_resolver,
                    deadline=time.monotonic() + _TOTAL_TIMEOUT_SECONDS,
                )
                if candidate is not None:
                    return candidate, None, time.monotonic() - started
            except OfficialProductLookupFailure as exc:
                first_error = first_error or exc.code
        return None, first_error, time.monotonic() - started

    for profile in profiles:
        if not profile.enabled:
            continue
        for canary in profile.canaries:
            known, known_error, known_elapsed = evaluate(
                profile,
                canary.known_model,
                canary.device_type,
            )
            impossible, impossible_error, impossible_elapsed = evaluate(
                profile,
                canary.impossible_model,
                canary.device_type,
            )
            outcomes.append(
                OfficialProductCanaryOutcome(
                    manufacturer=profile.manufacturer,
                    device_type=canary.device_type,
                    known_model=canary.known_model,
                    known_matched=known is not None,
                    known_source_url=known.source_reference if known else None,
                    known_error_code=known_error,
                    known_elapsed_seconds=known_elapsed,
                    impossible_model=canary.impossible_model,
                    impossible_rejected=impossible is None
                    and impossible_error
                    in {None, "OFFICIAL_LOOKUP_HTTP_REJECTED"},
                    impossible_error_code=impossible_error,
                    impossible_elapsed_seconds=impossible_elapsed,
                )
            )
    return tuple(outcomes)


def lookup_claimed_official_products(
    repository: Any,
    jobs: Sequence[Mapping[str, Any]],
    *,
    transport: OfficialProductTransport | None = None,
    resolver: OfficialDnsResolver | None = None,
    profiles_path: str | Path | None = None,
) -> OfficialProductLookupOutcome:
    """Try API-key-free official lookup for an already-claimed batch.

    This entry point never calls ``claim_identity_research_jobs``.  A scheduler
    can therefore claim once, run this deterministic resolver, and pass only
    ``outcome.unresolved_job_ids`` to an optional AI fallback without advancing
    backoff twice.  ``jobs`` are the signed repository mappings returned by the
    claim method; arbitrary evidence mappings fail closed in ``_eligible_job``.
    """

    claimed = [job for job in jobs[:_MAX_BATCH_SIZE] if isinstance(job, Mapping)]
    all_job_ids = tuple(str(job.get("job_id") or "") for job in claimed)
    try:
        profiles = _load_profiles(Path(profiles_path) if profiles_path else None)
    except OfficialProductLookupFailure as exc:
        return OfficialProductLookupOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            fetched_page_count=0,
            resolved_count=0,
            pending_count=len(claimed),
            failed_count=len(claimed) or 1,
            error_code=exc.code,
            job_outcomes=tuple(
                OfficialProductLookupJobOutcome(
                    job_id=job_id,
                    eligible=False,
                    attempted=False,
                    resolved=False,
                    error_code=exc.code,
                )
                for job_id in all_job_ids
            ),
        )
    by_manufacturer = {
        profile.manufacturer.casefold(): profile for profile in profiles if profile.enabled
    }
    eligible_by_id = {
        str(job.get("job_id") or ""): eligible
        for job in claimed
        if (eligible := _eligible_official_job(job)) is not None
    }
    targets = [
        (eligible, target)
        for eligible in eligible_by_id.values()
        if (target := _lookup_target(eligible, by_manufacturer)) is not None
    ]
    target_ids = {str(eligible["job_id"]) for eligible, _target in targets}
    job_results: dict[str, OfficialProductLookupJobOutcome] = {
        job_id: OfficialProductLookupJobOutcome(
            job_id=job_id,
            eligible=job_id in target_ids,
            attempted=False,
            resolved=False,
        )
        for job_id in all_job_ids
    }
    if not targets:
        return OfficialProductLookupOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            fetched_page_count=0,
            resolved_count=0,
            pending_count=len(claimed),
            job_outcomes=tuple(job_results[job_id] for job_id in all_job_ids),
        )

    client = transport or _pinned_https_transport
    dns_resolver = resolver or _default_dns_resolver
    deadline = time.monotonic() + _TOTAL_TIMEOUT_SECONDS
    attempted_count = 0
    fetched_page_count = 0
    resolved_count = 0
    scoped_matched_job_ids: set[str] = set()
    failed_count = 0
    first_error: str | None = None
    product_groups: dict[
        tuple[str, str, str],
        list[tuple[dict[str, Any], tuple[_TrustProfile, str, str]]],
    ] = {}
    for eligible, target in targets:
        profile, model, device_type = target
        try:
            manufacturer_key, model_key = verified_product_catalog_keys(
                profile.manufacturer,
                model,
            )
        except IdentityEnrichmentError:
            continue
        product_groups.setdefault(
            (manufacturer_key, model_key, device_type),
            [],
        ).append((eligible, target))

    for group in product_groups.values():
        eligible, (profile, model, device_type) = group[0]
        job_id = str(eligible["job_id"])
        if time.monotonic() >= deadline:
            failed_count += 1
            first_error = first_error or "OFFICIAL_LOOKUP_TIMEOUT"
            job_results[job_id] = OfficialProductLookupJobOutcome(
                job_id=job_id,
                eligible=True,
                attempted=False,
                resolved=False,
                error_code="OFFICIAL_LOOKUP_TIMEOUT",
            )
            break
        attempted_count += 1
        job_results[job_id] = OfficialProductLookupJobOutcome(
            job_id=job_id,
            eligible=True,
            attempted=True,
            resolved=False,
        )
        resolved = False
        job_error: str | None = None
        endpoints = tuple(
            endpoint
            for endpoint in profile.endpoints
            if endpoint.expected_device_type in {None, device_type}
        )[:_MAX_ENDPOINTS_PER_JOB]
        for endpoint_index, endpoint in enumerate(endpoints):
            try:
                candidate, page_count = _candidate_from_endpoint(
                    endpoint,
                    profile=profile,
                    model=model,
                    device_type=device_type,
                    transport=client,
                    resolver=dns_resolver,
                    deadline=deadline,
                )
                fetched_page_count += page_count
                if candidate is None:
                    continue
                group_matched = False
                for group_index, (sibling, _sibling_target) in enumerate(group):
                    sibling_job_id = str(sibling["job_id"])
                    result = {
                        "job_id": sibling_job_id,
                        "manufacturer": candidate.manufacturer,
                        "device_type": candidate.device_type,
                        "model": candidate.model,
                        "official_source_url": candidate.source_reference,
                        "matched": True,
                    }
                    validated = _result_matches_evidence(result, sibling)
                    if validated is None:
                        continue
                    device_scoped = _requires_device_scoped_resolution(sibling)
                    if device_scoped:
                        scoped_matched_job_ids.add(sibling_job_id)
                    try:
                        resolver_method = (
                            repository.resolve_device_scoped_identity_job
                            if device_scoped
                            else repository.resolve_identity_enrichment_job
                        )
                        resolver_method(
                            sibling_job_id,
                            manufacturer=validated["manufacturer"],
                            device_type=validated["device_type"],
                            model=validated["model"],
                            source_reference=validated["source_reference"],
                            resolution_provenance="automated-official-http",
                            expected_evidence_signature=sibling[
                                "expected_evidence_signature"
                            ],
                            expected_job_key=sibling["expected_job_key"],
                        )
                    except IdentityEnrichmentError as exc:
                        if exc.code != "IDENTITY_JOB_ALREADY_RESOLVED":
                            job_results[sibling_job_id] = OfficialProductLookupJobOutcome(
                                job_id=sibling_job_id,
                                eligible=True,
                                attempted=group_index == 0,
                                resolved=False,
                                error_code="OFFICIAL_LOOKUP_BINDING_REJECTED",
                            )
                            continue
                    resolved_count += 1
                    group_matched = True
                    job_results[sibling_job_id] = OfficialProductLookupJobOutcome(
                        job_id=sibling_job_id,
                        eligible=True,
                        attempted=group_index == 0,
                        resolved=True,
                    )
                if group_matched:
                    resolved = True
                    break
            except OfficialProductLookupFailure as exc:
                job_error = exc.code
                if (
                    endpoint_index + 1 < len(endpoints)
                    and exc.code
                    in {
                        "OFFICIAL_LOOKUP_HTTP_REJECTED",
                        "OFFICIAL_LOOKUP_CONTENT_REJECTED",
                        "OFFICIAL_LOOKUP_TRANSPORT_FAILED",
                    }
                ):
                    continue
                break
            except (OSError, TimeoutError, ValueError):
                job_error = "OFFICIAL_LOOKUP_FAILED"
                break
        if resolved:
            continue
        if job_error:
            failed_count += 1
            first_error = first_error or job_error
            job_results[job_id] = OfficialProductLookupJobOutcome(
                job_id=job_id,
                eligible=True,
                attempted=True,
                resolved=False,
                error_code=job_error,
            )
    outcomes = tuple(job_results[job_id] for job_id in all_job_ids)
    return OfficialProductLookupOutcome(
        enabled=True,
        eligible_count=len(targets),
        attempted_count=attempted_count,
        fetched_page_count=fetched_page_count,
        resolved_count=resolved_count,
        pending_count=sum(not item.resolved for item in outcomes),
        failed_count=failed_count,
        scoped_match_count=len(scoped_matched_job_ids),
        error_code=first_error if resolved_count == 0 and failed_count else None,
        job_outcomes=outcomes,
    )


def lookup_pending_official_products(
    repository: Any,
    *,
    home_id: str,
    transport: OfficialProductTransport | None = None,
    resolver: OfficialDnsResolver | None = None,
    profiles_path: str | Path | None = None,
    max_jobs: int = _MAX_BATCH_SIZE,
) -> OfficialProductLookupOutcome:
    """Preflight profile/job eligibility, then claim one bounded queue batch.

    The repository currently claims by home and limit, not by explicit job id.
    This wrapper therefore guarantees that an invalid profile or a queue with
    no eligible official profile consumes no retry/backoff.  Mixed eligible and
    ineligible queues still require the repository's normal ordered claim.
    """

    bounded_jobs = max(1, min(int(max_jobs), _MAX_BATCH_SIZE))
    try:
        profiles = _load_profiles(Path(profiles_path) if profiles_path else None)
    except OfficialProductLookupFailure as exc:
        return OfficialProductLookupOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            fetched_page_count=0,
            resolved_count=0,
            pending_count=0,
            failed_count=1,
            error_code=exc.code,
        )
    pending = repository.identity_enrichment_jobs(
        status_filter="review_required", limit=200, home_id=home_id
    )
    eligible_ids = eligible_official_product_job_ids(
        pending,
        profiles_path=profiles_path,
    )
    if not eligible_ids:
        return OfficialProductLookupOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            fetched_page_count=0,
            resolved_count=0,
            pending_count=len(pending),
            job_outcomes=tuple(
                OfficialProductLookupJobOutcome(
                    job_id=str(job.get("job_id") or ""),
                    eligible=False,
                    attempted=False,
                    resolved=False,
                )
                for job in pending
                if isinstance(job, Mapping)
            ),
        )
    claimed = repository.claim_identity_research_jobs(
        home_id=home_id,
        limit=bounded_jobs,
        job_ids=eligible_ids,
    )
    outcome = lookup_claimed_official_products(
        repository,
        claimed,
        transport=transport,
        resolver=resolver,
        profiles_path=profiles_path,
    )
    remaining = repository.identity_enrichment_jobs(
        status_filter="review_required", limit=200, home_id=home_id
    )
    return OfficialProductLookupOutcome(
        enabled=outcome.enabled,
        eligible_count=outcome.eligible_count,
        attempted_count=outcome.attempted_count,
        fetched_page_count=outcome.fetched_page_count,
        resolved_count=outcome.resolved_count,
        pending_count=len(remaining),
        failed_count=outcome.failed_count,
        scoped_match_count=outcome.scoped_match_count,
        error_code=outcome.error_code,
        job_outcomes=outcome.job_outcomes,
    )


__all__ = [
    "OFFICIAL_PRODUCT_SOURCES_PATH",
    "OfficialDnsResolver",
    "OfficialHttpResponse",
    "OfficialProductCanaryOutcome",
    "OfficialProductLookupFailure",
    "OfficialProductLookupJobOutcome",
    "OfficialProductLookupOutcome",
    "OfficialProductTransport",
    "eligible_official_product_job_ids",
    "lookup_claimed_official_products",
    "lookup_pending_official_products",
    "official_product_lookup_policy_version",
    "validate_official_product_canaries",
]
