from __future__ import annotations

import json
import os
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

from .device_identity import (
    DEVICE_TYPE_LABELS,
    MODEL_PREFIX_DEVICE_TYPE,
    MODEL_PREFIX_VENDOR,
    PUBLIC_IDENTITY_TYPES,
    is_concrete_product_model,
    normalize_vendor_name,
)
from .identity_enrichment import (
    IdentityEnrichmentError,
    blocked_binding_reason,
    evidence_signature_matches,
    identity_job_key_matches,
    source_matches_registered_official_domain,
    validate_identity_resolution,
)


_RESPONSES_URL = "https://api.openai.com/v1/responses"
_AI_RESEARCH_FLAG = "HG_IDENTITY_AI_RESEARCH_ENABLED"
_LEGACY_RESEARCH_FLAG = "HG_IDENTITY_RESEARCH_ENABLED"
_MAX_BATCH_SIZE = 8
_MAX_RESPONSE_BYTES = 256 * 1024
_TOTAL_TIMEOUT_SECONDS = 4.8
_RESPONSES_TIMEOUT_SECONDS = 4.5
_OPAQUE_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{15,95}$")
_AUTOMATED_MODEL_CODE_RE = re.compile(
    r"^(?=.{2,48}$)(?=.*[0-9])[0-9A-Za-z][0-9A-Za-z._/+()-]*$"
)
_STRONG_NETWORK_SCOPE_RE = re.compile(r"^hgns1[gb]-[0-9a-f]{32}$")
_PHYSICAL_MAC_RE = re.compile(r"^[0-9A-F]{12}$")
_ALLOWED_EVIDENCE_KEYS = (
    "manufacturer_hints",
    "model_hints",
    "device_type_hints",
    "service_hints",
)
_PROOF_KINDS = frozenset({"manufacturer", "model", "device_type"})
_AUTHENTICATED_SELF_ANDROID_SOURCE = "authenticated-self-android"
_PROOF_SOURCES = frozenset(
    {
        _AUTHENTICATED_SELF_ANDROID_SOURCE,
        "airplay",
        "googlecast",
        "ipp",
        "mdns",
        "onvif",
        "physical-mac-oui",
        "spotify",
        "upnp",
        "ws-discovery",
    }
)
_RESULT_KEYS = frozenset(
    {
        "job_id",
        "manufacturer",
        "device_type",
        "model",
        "official_source_url",
        "matched",
    }
)


class IdentityResearchTransport(Protocol):
    def __call__(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any],
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...


class IdentityResearchFailure(RuntimeError):
    """A privacy-safe failure whose message never contains request data."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class IdentityResearchOutcome:
    enabled: bool
    eligible_count: int
    attempted_count: int
    resolved_count: int
    pending_count: int
    error_code: str | None = None


@dataclass(frozen=True)
class CitationEvidence:
    url: str
    title: str
    start_index: int
    end_index: int


def _urllib_transport(
    *,
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, Any],
    timeout_seconds: float,
) -> Mapping[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers=dict(headers),
        method="POST",
    )
    try:
        with urlopen(request, timeout=min(float(timeout_seconds), _TOTAL_TIMEOUT_SECONDS)) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_TRANSPORT_FAILED") from exc
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_RESPONSE_TOO_LARGE")
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE") from exc
    if not isinstance(decoded, Mapping):
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    return decoded


def identity_ai_research_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return the explicit optional-AI switch without inspecting credentials.

    The AI-specific name takes precedence.  The legacy flag remains supported
    for existing installations until their auth.env is migrated.  A stored API
    key never enables network access by itself.
    """

    config = os.environ if environ is None else environ
    flag_name = (
        _AI_RESEARCH_FLAG if _AI_RESEARCH_FLAG in config else _LEGACY_RESEARCH_FLAG
    )
    return str(config.get(flag_name) or "").strip() == "1"


def identity_research_readiness(
    environ: Mapping[str, str] | None = None,
) -> tuple[bool, str]:
    """Report optional AI-fallback readiness, never core scanner health."""

    config = os.environ if environ is None else environ
    if not identity_ai_research_enabled(config):
        return False, "disabled"
    api_key = str(config.get("OPENAI_API_KEY") or "").strip()
    if not re.fullmatch(r"sk-[A-Za-z0-9_-]{17,}", api_key):
        return False, "invalid_api_key"
    model = str(config.get("HG_IDENTITY_RESEARCH_MODEL") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}", model):
        return False, "invalid_model"
    return True, "ready"


def _normalized_exact(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
    text = re.sub(r"[\s._/\\-]+", " ", text)
    return " ".join(text.split())


def _normalized_type_hint(value: object) -> str | None:
    normalized = _normalized_exact(value)
    if normalized in PUBLIC_IDENTITY_TYPES:
        return normalized
    for key, label in DEVICE_TYPE_LABELS.items():
        if key in PUBLIC_IDENTITY_TYPES and normalized == _normalized_exact(label):
            return key
    return None


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


def _safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = " ".join(str(item or "").strip().split())
        if text and len(text) <= 96:
            result.append(text)
    return list(dict.fromkeys(result))[:32]


def _has_actual_physical_mac(value: object) -> bool:
    compact = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return bool(
        _PHYSICAL_MAC_RE.fullmatch(compact)
        and compact not in {"000000000000", "020000000000", "FFFFFFFFFFFF"}
        and not (int(compact[:2], 16) & 1)
    )


def _structured_proofs(evidence: Mapping[str, Any]) -> list[dict[str, str]]:
    raw_proofs = evidence.get("structured_provenance")
    if not isinstance(raw_proofs, list) or len(raw_proofs) > 64:
        return []
    proofs: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in raw_proofs:
        if not isinstance(raw, Mapping) or set(raw) != {"kind", "source", "value"}:
            return []
        kind = str(raw.get("kind") or "").strip().casefold()
        source = str(raw.get("source") or "").strip().casefold()
        value = " ".join(str(raw.get("value") or "").strip().split())
        if (
            kind not in _PROOF_KINDS
            or source not in _PROOF_SOURCES
            or not value
            or len(value) > 96
        ):
            return []
        key = (kind, source, value)
        if key not in seen:
            seen.add(key)
            proofs.append({"kind": kind, "source": source, "value": value})
    return proofs


def _proof_values(
    proofs: list[dict[str, str]],
    *,
    kind: str,
    value: object | None = None,
) -> list[dict[str, str]]:
    expected = _normalized_exact(value) if value is not None else None
    return [
        proof
        for proof in proofs
        if proof["kind"] == kind
        and (expected is None or _normalized_exact(proof["value"]) == expected)
    ]


def _authenticated_self_android_claim(
    evidence: Mapping[str, Any],
    model: str,
    proofs: list[dict[str, str]],
) -> tuple[str, str] | None:
    """Validate one repository-authenticated Android Build identity claim.

    This source is created only by the server after it validates the signed
    self-device observation.  It may replace cross-protocol corroboration only
    when the complete manufacturer/model/type triple is singular, agrees with
    every persisted hint/proof, and the model-family tables independently
    agree with both manufacturer and type.  The caller still has to verify the
    strong network-scope and physical-MAC job binding.
    """

    self_proofs = [
        proof
        for proof in proofs
        if proof["source"] == _AUTHENTICATED_SELF_ANDROID_SOURCE
    ]
    by_kind = {
        kind: {
            _normalized_exact(proof["value"])
            for proof in self_proofs
            if proof["kind"] == kind
        }
        for kind in _PROOF_KINDS
    }
    if any(len(values) != 1 for values in by_kind.values()):
        return None

    claimed_model = next(iter(by_kind["model"]))
    if claimed_model != _normalized_exact(model):
        return None
    claimed_vendor = normalize_vendor_name(
        next(
            proof["value"]
            for proof in self_proofs
            if proof["kind"] == "manufacturer"
        )
    ).casefold()
    claimed_type = _normalized_type_hint(
        next(
            proof["value"]
            for proof in self_proofs
            if proof["kind"] == "device_type"
        )
    )
    prefix_vendor = _model_prefix_vendor(model)
    prefix_type = _model_prefix_type(model)
    if (
        not claimed_vendor
        or claimed_type is None
        or prefix_vendor is None
        or normalize_vendor_name(prefix_vendor).casefold() != claimed_vendor
        or prefix_type != claimed_type
    ):
        return None

    hinted_vendors = {
        normalize_vendor_name(value).casefold()
        for value in _safe_string_list(evidence.get("manufacturer_hints"))
    }
    hinted_models = {
        _normalized_exact(value)
        for value in _safe_string_list(evidence.get("model_hints"))
    }
    hinted_types = {
        normalized
        for value in _safe_string_list(evidence.get("device_type_hints"))
        if (normalized := _normalized_type_hint(value)) is not None
    }
    if (
        hinted_vendors != {claimed_vendor}
        or hinted_models != {claimed_model}
        or hinted_types != {claimed_type}
    ):
        return None

    proof_vendors = {
        normalize_vendor_name(proof["value"]).casefold()
        for proof in _proof_values(proofs, kind="manufacturer")
    }
    proof_models = {
        _normalized_exact(proof["value"])
        for proof in _proof_values(proofs, kind="model")
    }
    proof_types = {
        normalized
        for proof in _proof_values(proofs, kind="device_type")
        if (normalized := _normalized_type_hint(proof["value"])) is not None
    }
    if (
        proof_vendors != {claimed_vendor}
        or proof_models != {claimed_model}
        or proof_types != {claimed_type}
        or len(_proof_values(proofs, kind="device_type")) != sum(
            1
            for proof in _proof_values(proofs, kind="device_type")
            if _normalized_type_hint(proof["value"]) is not None
        )
    ):
        return None
    return claimed_vendor, claimed_type


def _corroborated_models(
    evidence: Mapping[str, Any],
    models: list[str],
    proofs: list[dict[str, str]],
) -> list[str]:
    hinted_vendors = {
        normalize_vendor_name(value).casefold()
        for value in _safe_string_list(evidence.get("manufacturer_hints"))
    }
    oui_vendors = {
        normalize_vendor_name(proof["value"]).casefold()
        for proof in _proof_values(proofs, kind="manufacturer")
        if proof["source"] == "physical-mac-oui"
    }
    structured_vendors = {
        normalize_vendor_name(proof["value"]).casefold()
        for proof in _proof_values(proofs, kind="manufacturer")
        if proof["source"] != "physical-mac-oui"
    }
    if len(oui_vendors) > 1 or len(structured_vendors) > 1:
        return []

    corroborated: list[str] = []
    for model in models:
        model_sources = {
            proof["source"]
            for proof in _proof_values(proofs, kind="model", value=model)
        }
        if not model_sources:
            continue
        if (
            _AUTHENTICATED_SELF_ANDROID_SOURCE in model_sources
            and _authenticated_self_android_claim(evidence, model, proofs) is None
        ):
            continue
        prefix_vendor = _model_prefix_vendor(model)
        expected_vendors = set(hinted_vendors)
        if prefix_vendor:
            expected_vendors.add(normalize_vendor_name(prefix_vendor).casefold())
        if oui_vendors and (
            not expected_vendors
            or any(vendor not in oui_vendors for vendor in expected_vendors)
        ):
            continue
        if oui_vendors and structured_vendors and oui_vendors != structured_vendors:
            continue

        if len(model_sources) >= 2:
            corroborated.append(model)
            continue

        if model_sources == {_AUTHENTICATED_SELF_ANDROID_SOURCE} and (
            _authenticated_self_android_claim(evidence, model, proofs) is not None
        ):
            corroborated.append(model)
            continue

        # A single self-advertised model can be bound only when a fresh,
        # globally administered physical-MAC OUI agrees and another protocol
        # independently proves a concrete category.
        if len(oui_vendors) != 1:
            continue
        model_source = next(iter(model_sources))
        type_proofs = _proof_values(proofs, kind="device_type")
        if any(proof["source"] != model_source for proof in type_proofs):
            corroborated.append(model)
    return corroborated


def _result_has_corroboration(
    result: Mapping[str, Any],
    job: Mapping[str, Any],
) -> bool:
    proofs = job.get("corroboration")
    if not isinstance(proofs, list):
        return False
    model = str(result.get("model") or "")
    model_sources = {
        proof["source"]
        for proof in _proof_values(proofs, kind="model", value=model)
    }
    if not model_sources:
        return False
    returned_vendor = normalize_vendor_name(
        str(result.get("manufacturer") or "")
    ).casefold()
    oui_vendors = {
        normalize_vendor_name(proof["value"]).casefold()
        for proof in _proof_values(proofs, kind="manufacturer")
        if proof["source"] == "physical-mac-oui"
    }
    advertised_vendors = {
        normalize_vendor_name(proof["value"]).casefold()
        for proof in _proof_values(proofs, kind="manufacturer")
        if proof["source"] != "physical-mac-oui"
    }
    if (
        (oui_vendors and oui_vendors != {returned_vendor})
        or any(vendor != returned_vendor for vendor in advertised_vendors)
    ):
        return False
    if _AUTHENTICATED_SELF_ANDROID_SOURCE in model_sources:
        if (
            job.get("authenticated_self_android_binding") is not True
            or not isinstance(job.get("evidence"), Mapping)
            or _authenticated_self_android_claim(
                job["evidence"],
                model,
                proofs,
            )
            != (returned_vendor, _normalized_type_hint(result.get("device_type")))
        ):
            return False
        return True
    if len(model_sources) >= 2:
        return True
    if oui_vendors != {returned_vendor}:
        return False
    returned_type = _normalized_type_hint(result.get("device_type"))
    model_source = next(iter(model_sources))
    return any(
        proof["source"] != model_source
        and _normalized_type_hint(proof["value"]) == returned_type
        for proof in _proof_values(proofs, kind="device_type")
    )


def _eligible_job(job: Mapping[str, Any]) -> dict[str, Any] | None:
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
    ):
        return None
    if not evidence_signature_matches(
        evidence,
        job.get("evidence_signature"),
    ):
        return None
    manufacturer_hints = _safe_string_list(evidence.get("manufacturer_hints"))
    model_hints = _safe_string_list(evidence.get("model_hints"))
    model_candidates = [
        model
        for model in model_hints
        if _AUTOMATED_MODEL_CODE_RE.fullmatch(model)
        and (
            any(
            is_concrete_product_model(model, normalize_vendor_name(manufacturer))
            for manufacturer in (manufacturer_hints or [""])
            )
            or _model_prefix_vendor(model) is not None
            or _model_prefix_type(model) is not None
        )
    ]
    proofs = _structured_proofs(evidence)
    concrete_models = _corroborated_models(evidence, model_candidates, proofs)
    if not concrete_models:
        return None
    authenticated_self_models = [
        model
        for model in concrete_models
        if _AUTHENTICATED_SELF_ANDROID_SOURCE
        in {
            proof["source"]
            for proof in _proof_values(proofs, kind="model", value=model)
        }
    ]
    if authenticated_self_models and (
        len(concrete_models) != 1
        or not _STRONG_NETWORK_SCOPE_RE.fullmatch(
            str(job.get("network_scope_id") or "")
        )
        or not _has_actual_physical_mac(job.get("physical_mac"))
    ):
        return None
    safe_evidence = {
        key: _safe_string_list(evidence.get(key))
        for key in _ALLOWED_EVIDENCE_KEYS
        if _safe_string_list(evidence.get(key))
    }
    safe_evidence["model_hints"] = concrete_models
    safe_job = {
        "job_id": job_id,
        "evidence": safe_evidence,
        "corroboration": proofs,
        "expected_evidence_signature": str(job.get("evidence_signature") or ""),
        "expected_job_key": str(job.get("job_key") or ""),
    }
    if authenticated_self_models:
        safe_job["authenticated_self_android_binding"] = True
    return safe_job


def _requires_device_scoped_resolution(job: Mapping[str, Any]) -> bool:
    """Return whether a match must stay scoped to this signed observation.

    Android ``Build`` fields identify the client software/hardware claim, but
    without Play Integrity or hardware-backed key attestation they do not
    authorize a globally reusable product fact.  Official pages may still be
    checked for that exact observation; callers must not invoke the repository
    resolver whose current contract promotes every resolution into the global
    verified-product catalog.
    """

    return job.get("authenticated_self_android_binding") is True


def _request_payload(jobs: list[dict[str, Any]], model: str) -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "maxItems": _MAX_BATCH_SIZE,
                "items": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string"},
                        "manufacturer": {"type": "string"},
                        "device_type": {"type": "string"},
                        "model": {"type": "string"},
                        "official_source_url": {"type": "string"},
                        "matched": {"type": "boolean"},
                    },
                    "required": sorted(_RESULT_KEYS),
                    "additionalProperties": False,
                },
            }
        },
        "required": ["results"],
        "additionalProperties": False,
    }
    prompt = {
        "task": (
            "각 단서의 정확한 실제 제품만 제조사 공식 웹사이트에서 확인하세요. "
            "모델 단서와 정확히 일치하지 않거나 공식 출처가 없으면 matched=false로 답하세요."
        ),
        "jobs": [
            {"job_id": job["job_id"], "evidence": job["evidence"]}
            for job in jobs
        ],
    }
    return {
        "model": model,
        "store": False,
        "tools": [{"type": "web_search"}],
        "input": json.dumps(prompt, ensure_ascii=False, separators=(",", ":")),
        "text": {
            "format": {
                "type": "json_schema",
                "name": "home_guardian_identity_research",
                "description": "Official product identity matches for opaque jobs.",
                "strict": True,
                "schema": schema,
            }
        },
        "max_output_tokens": 1400,
    }


def _response_text_and_citations(response: Mapping[str, Any]) -> tuple[str, list[CitationEvidence]]:
    if response.get("status") != "completed":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    texts: list[str] = []
    citations: list[CitationEvidence] = []
    for output in response.get("output") or []:
        if not isinstance(output, Mapping) or output.get("type") != "message":
            continue
        for content in output.get("content") or []:
            if not isinstance(content, Mapping) or content.get("type") != "output_text":
                continue
            if isinstance(content.get("text"), str):
                texts.append(content["text"])
            for annotation in content.get("annotations") or []:
                if not isinstance(annotation, Mapping) or annotation.get("type") != "url_citation":
                    continue
                url = annotation.get("url")
                if not isinstance(url, str):
                    nested = annotation.get("url_citation")
                    url = nested.get("url") if isinstance(nested, Mapping) else None
                if isinstance(url, str) and url.startswith("https://"):
                    try:
                        start_index = int(annotation.get("start_index"))
                        end_index = int(annotation.get("end_index"))
                    except (TypeError, ValueError):
                        continue
                    citations.append(
                        CitationEvidence(
                            url=url,
                            title=str(annotation.get("title") or "")[:256],
                            start_index=start_index,
                            end_index=end_index,
                        )
                    )
    if not texts and isinstance(response.get("output_text"), str):
        texts.append(str(response["output_text"]))
    if len(texts) != 1:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    return texts[0], citations


def _strict_results(text: str) -> list[Mapping[str, Any]]:
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE") from exc
    if not isinstance(decoded, Mapping) or set(decoded) != {"results"}:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    results = decoded.get("results")
    if not isinstance(results, list) or len(results) > _MAX_BATCH_SIZE:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    validated: list[Mapping[str, Any]] = []
    for result in results:
        if not isinstance(result, Mapping) or set(result) != _RESULT_KEYS:
            raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
        if not isinstance(result.get("matched"), bool) or not all(
            isinstance(result.get(key), str)
            for key in _RESULT_KEYS - {"matched"}
        ):
            raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
        validated.append(result)
    return validated


def _skip_json_whitespace(text: str, cursor: int) -> int:
    while cursor < len(text) and text[cursor] in " \t\r\n":
        cursor += 1
    return cursor


def _strict_result_spans(
    text: str,
    results: list[Mapping[str, Any]],
) -> list[tuple[int, int]]:
    """Locate each strict result object without trusting model-provided offsets."""

    decoder = json.JSONDecoder()
    cursor = _skip_json_whitespace(text, 0)
    if cursor >= len(text) or text[cursor] != "{":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    cursor = _skip_json_whitespace(text, cursor + 1)
    try:
        key, cursor = decoder.raw_decode(text, cursor)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE") from exc
    cursor = _skip_json_whitespace(text, cursor)
    if key != "results" or cursor >= len(text) or text[cursor] != ":":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    cursor = _skip_json_whitespace(text, cursor + 1)
    if cursor >= len(text) or text[cursor] != "[":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    cursor += 1

    spans: list[tuple[int, int]] = []
    for index, expected in enumerate(results):
        cursor = _skip_json_whitespace(text, cursor)
        if index:
            if cursor >= len(text) or text[cursor] != ",":
                raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
            cursor = _skip_json_whitespace(text, cursor + 1)
        start = cursor
        try:
            decoded, end = decoder.raw_decode(text, start)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE") from exc
        if not isinstance(decoded, Mapping) or dict(decoded) != dict(expected):
            raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
        spans.append((start, end))
        cursor = end

    cursor = _skip_json_whitespace(text, cursor)
    if cursor >= len(text) or text[cursor] != "]":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    cursor = _skip_json_whitespace(text, cursor + 1)
    if cursor >= len(text) or text[cursor] != "}":
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    if _skip_json_whitespace(text, cursor + 1) != len(text):
        raise IdentityResearchFailure("IDENTITY_RESEARCH_INVALID_RESPONSE")
    return spans


def _mapping_string_value_span(
    text: str,
    *,
    object_start: int,
    object_end: int,
    target_key: str,
    expected_value: str,
) -> tuple[int, int] | None:
    """Return the exact JSON string-token span for one field in an object."""

    decoder = json.JSONDecoder()
    cursor = _skip_json_whitespace(text, object_start)
    if cursor >= object_end or text[cursor] != "{":
        return None
    cursor += 1
    while True:
        cursor = _skip_json_whitespace(text, cursor)
        if cursor >= object_end:
            return None
        if text[cursor] == "}":
            return None
        try:
            key, key_end = decoder.raw_decode(text, cursor)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(key, str):
            return None
        cursor = _skip_json_whitespace(text, key_end)
        if cursor >= object_end or text[cursor] != ":":
            return None
        value_start = _skip_json_whitespace(text, cursor + 1)
        try:
            value, value_end = decoder.raw_decode(text, value_start)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if value_end > object_end:
            return None
        if key == target_key:
            if not isinstance(value, str) or value != expected_value:
                return None
            return value_start, value_end
        cursor = _skip_json_whitespace(text, value_end)
        if cursor >= object_end or text[cursor] != ",":
            return None
        cursor += 1


def _result_matches_evidence(
    result: Mapping[str, Any],
    job: Mapping[str, Any],
) -> dict[str, str] | None:
    if result.get("matched") is not True:
        return None
    if not _result_has_corroboration(result, job):
        return None
    evidence = job.get("evidence")
    if not isinstance(evidence, Mapping):
        return None
    model = str(result.get("model") or "")
    model_hints = _safe_string_list(evidence.get("model_hints"))
    if _normalized_exact(model) not in {_normalized_exact(item) for item in model_hints}:
        return None

    manufacturer = str(result.get("manufacturer") or "")
    returned_vendor = normalize_vendor_name(manufacturer).casefold()
    hinted_vendors = {
        normalize_vendor_name(item).casefold()
        for item in _safe_string_list(evidence.get("manufacturer_hints"))
    }
    prefix_vendor = _model_prefix_vendor(model)
    if returned_vendor not in hinted_vendors and (
        prefix_vendor is None or returned_vendor != prefix_vendor.casefold()
    ):
        return None

    device_type = str(result.get("device_type") or "").strip().casefold()
    hinted_types = {
        normalized
        for item in _safe_string_list(evidence.get("device_type_hints"))
        if (normalized := _normalized_type_hint(item)) is not None
    }
    prefix_type = _model_prefix_type(model)
    if device_type not in PUBLIC_IDENTITY_TYPES or (
        device_type not in hinted_types and device_type != prefix_type
    ):
        return None
    try:
        validated = validate_identity_resolution(
            manufacturer=manufacturer,
            device_type=device_type,
            model=model,
            source_reference=result.get("official_source_url"),
        )
    except IdentityEnrichmentError:
        return None
    if not source_matches_registered_official_domain(
        validated["source_reference"],
        validated["manufacturer"],
    ):
        return None
    return validated


def _contains_exact_model_token(text: object, model: object) -> bool:
    haystack = unicodedata.normalize("NFKC", str(text or "")).casefold()
    needle = unicodedata.normalize("NFKC", str(model or "")).casefold()
    if not needle or len(needle) > 48:
        return False
    return re.search(
        rf"(?<![0-9a-z]){re.escape(needle)}(?![0-9a-z])",
        haystack,
    ) is not None


def _citation_can_prove_model(url: str, title: str, model: str) -> bool:
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        return False
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or port not in {None, 443}
        or parsed.query
        or parsed.fragment
    ):
        return False
    path = unquote(parsed.path or "")
    lowered_segments = {segment.casefold() for segment in path.split("/") if segment}
    if lowered_segments & {"redirect", "redirector", "out", "login", "search"}:
        return False
    return (
        len(model) >= 4
        and (
            _contains_exact_model_token(path, model)
            or _contains_exact_model_token(title, model)
        )
    )


def _citation_span_proves_result(
    output_text: str,
    citation: CitationEvidence,
    *,
    job_id: str,
    model: str,
    source: str,
    expected_result: Mapping[str, Any],
    result_start: int,
    result_end: int,
) -> bool:
    if (
        citation.start_index < 0
        or citation.end_index <= citation.start_index
        or citation.end_index > len(output_text)
        or citation.end_index - citation.start_index > 2048
        or result_start < 0
        or result_end <= result_start
        or result_end > len(output_text)
        or citation.start_index < result_start
        or citation.end_index > result_end
    ):
        return False
    try:
        decoded_result = json.loads(output_text[result_start:result_end])
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(decoded_result, Mapping) or dict(decoded_result) != dict(expected_result):
        return False
    source_span = _mapping_string_value_span(
        output_text,
        object_start=result_start,
        object_end=result_end,
        target_key="official_source_url",
        expected_value=source,
    )
    if source_span is None:
        return False
    source_start, source_end = source_span
    return (
        citation.start_index == source_start
        and citation.end_index == source_end
        and str(decoded_result.get("job_id") or "") == job_id
        and _normalized_exact(decoded_result.get("model")) == _normalized_exact(model)
    )


def research_pending_identities(
    repository: Any,
    *,
    home_id: str,
    transport: IdentityResearchTransport | None = None,
    environ: Mapping[str, str] | None = None,
    claimed_jobs: list[Mapping[str, Any]] | None = None,
) -> IdentityResearchOutcome:
    """Run the optional AI fallback for one bounded, privacy-safe batch.

    ``claimed_jobs`` is used by the background orchestrator after the
    deterministic official lookup.  Supplying it is the only way to reuse the
    same persisted claim/backoff window; the legacy direct-call path still
    claims its own batch for compatibility with existing maintenance tools.
    """

    config = os.environ if environ is None else environ
    ready, readiness_code = identity_research_readiness(config)
    enabled = identity_ai_research_enabled(config)
    api_key = str(config.get("OPENAI_API_KEY") or "").strip()
    pending_jobs = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=200,
        home_id=home_id,
    )
    pending_count = len(pending_jobs)
    if not ready:
        return IdentityResearchOutcome(
            enabled=False,
            eligible_count=0,
            attempted_count=0,
            resolved_count=0,
            pending_count=pending_count,
            error_code=(
                "IDENTITY_RESEARCH_DISABLED"
                if not enabled
                else f"IDENTITY_RESEARCH_{readiness_code.upper()}"
            ),
        )

    if claimed_jobs is None:
        selected_jobs = repository.claim_identity_research_jobs(
            home_id=home_id,
            limit=_MAX_BATCH_SIZE,
        )
    else:
        selected_jobs = list(claimed_jobs)[:_MAX_BATCH_SIZE]
    eligible = [
        safe
        for job in selected_jobs
        if (safe := _eligible_job(job)) is not None
        and not _requires_device_scoped_resolution(safe)
    ][:_MAX_BATCH_SIZE]
    if not eligible:
        return IdentityResearchOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            resolved_count=0,
            pending_count=pending_count,
        )

    model = str(config.get("HG_IDENTITY_RESEARCH_MODEL") or "").strip()
    payload = _request_payload(eligible, model)
    client = transport or _urllib_transport
    started_at = time.monotonic()
    try:
        raw_response = client(
            url=_RESPONSES_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            payload=payload,
            timeout_seconds=_RESPONSES_TIMEOUT_SECONDS,
        )
        output_text, citations = _response_text_and_citations(raw_response)
        results = _strict_results(output_text)
        result_spans = _strict_result_spans(output_text, results)
    except (IdentityResearchFailure, TimeoutError, OSError, ValueError):
        return IdentityResearchOutcome(
            enabled=True,
            eligible_count=len(eligible),
            attempted_count=len(eligible),
            resolved_count=0,
            pending_count=pending_count,
            error_code="IDENTITY_RESEARCH_FAILED",
        )

    eligible_by_id = {item["job_id"]: item for item in eligible}
    candidates: list[tuple[Mapping[str, Any], dict[str, str], str]] = []
    seen_job_ids: set[str] = set()
    for result_index, result in enumerate(results):
        job_id = str(result.get("job_id") or "")
        if job_id in seen_job_ids or job_id not in eligible_by_id:
            continue
        seen_job_ids.add(job_id)
        source = str(result.get("official_source_url") or "")
        matching_citation = next(
            (
                citation
                for citation in citations
                if citation.url == source
                and _citation_can_prove_model(
                    source,
                    citation.title,
                    str(result.get("model") or ""),
                )
                and _citation_span_proves_result(
                    output_text,
                    citation,
                    job_id=job_id,
                    model=str(result.get("model") or ""),
                    source=source,
                    expected_result=result,
                    result_start=result_spans[result_index][0],
                    result_end=result_spans[result_index][1],
                )
            ),
            None,
        )
        if matching_citation is None:
            continue
        validated = _result_matches_evidence(result, eligible_by_id[job_id])
        if validated is None:
            continue
        candidates.append((result, validated, source))

    resolved_count = 0
    for _result, validated, source in candidates:
        if time.monotonic() - started_at > _TOTAL_TIMEOUT_SECONDS:
            continue
        job_id = str(_result.get("job_id") or "")
        try:
            repository.resolve_identity_enrichment_job(
                job_id,
                manufacturer=validated["manufacturer"],
                device_type=validated["device_type"],
                model=validated["model"],
                source_reference=validated["source_reference"],
                resolution_provenance="automated-official-web-search",
                expected_evidence_signature=eligible_by_id[job_id][
                    "expected_evidence_signature"
                ],
                expected_job_key=eligible_by_id[job_id]["expected_job_key"],
            )
        except IdentityEnrichmentError:
            continue
        resolved_count += 1

    remaining = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=200,
        home_id=home_id,
    )
    return IdentityResearchOutcome(
        enabled=True,
        eligible_count=len(eligible),
        attempted_count=len(eligible),
        resolved_count=resolved_count,
        pending_count=len(remaining),
    )


__all__ = [
    "IdentityResearchFailure",
    "IdentityResearchOutcome",
    "IdentityResearchTransport",
    "CitationEvidence",
    "identity_ai_research_enabled",
    "identity_research_readiness",
    "research_pending_identities",
]
