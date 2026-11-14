from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.identity_enrichment import (
    IdentityEnrichmentError,
    build_evidence_signature,
    build_identity_job_key,
    stable_identity_evidence_signature,
)
from app.services.device_identity import canonical_registered_official_product_source
from app.services.official_product_lookup import (
    OfficialHttpResponse,
    lookup_claimed_official_products,
    lookup_pending_official_products,
    validate_official_product_canaries,
)
from app.services.identity_research import research_pending_identities
from app.services import official_product_lookup as official_lookup_module
from app.identity_research_worker import run_identity_research_worker
from app.storage.sqlite_repository import SQLiteRepository


HOME_ID = "home-official-lookup"
MODEL = "RF85C90N1AP"
DETAIL_URL = f"https://www.samsung.com/sec/support/model/{MODEL}/"
PHONE_MODEL = "SM-F956N"
PHONE_FULL_MODEL = "SM-F956NZWFKOO"
PHONE_GOODS_ID = "G000395038"
PHONE_DETAIL_URL = (
    f"https://www.samsung.com/sec/support/model/{PHONE_FULL_MODEL}/"
)
TABLET_MODEL = "SM-T720"
TABLET_FULL_MODEL = "SM-T720NZSAKOO"
TABLET_GOODS_ID = "G100157599"
TABLET_DETAIL_URL = (
    f"https://www.samsung.com/sec/support/model/{TABLET_FULL_MODEL}/"
)


@pytest.fixture(autouse=True)
def identity_secret(monkeypatch):
    monkeypatch.setenv("HG_AUTH_TOKEN_SECRET", "official-lookup-test-secret-value-123456789")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def _job(
    *,
    job_id: str = "identity-job-00001",
    device_id: str = "opaque-device-one",
    model: str | None = MODEL,
    manufacturer: str = "Samsung",
    device_type: str = "fridge",
    physical_mac: str | None = None,
    include_manufacturer_proof: bool = True,
    include_type_proof: bool = True,
    extra_provenance: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    provenance: list[dict[str, str]] = []
    if include_manufacturer_proof:
        provenance.append(
            {"kind": "manufacturer", "source": "upnp", "value": manufacturer}
        )
    if model:
        provenance.extend(
            [
                {"kind": "model", "source": "upnp", "value": model},
                {"kind": "model", "source": "mdns", "value": model},
            ]
        )
    if include_type_proof:
        provenance.append(
            {"kind": "device_type", "source": "upnp", "value": device_type}
        )
    provenance.extend(extra_provenance or [])
    evidence: dict[str, Any] = {
        "manufacturer_hints": [manufacturer],
        "device_type_hints": [device_type],
        "service_hints": ["upnp"],
        "structured_provenance": provenance,
    }
    if model:
        evidence["model_hints"] = [model]
    binding = stable_identity_evidence_signature(evidence, device_id=device_id)
    scope = "hgns1b-0123456789abcdef0123456789abcdef"
    job_key = build_identity_job_key(
        home_id=HOME_ID,
        device_id=device_id,
        network_scope_id=scope,
        physical_mac=physical_mac,
        evidence_binding_signature=binding,
    )
    return {
        "job_id": job_id,
        "home_id": HOME_ID,
        "device_id": device_id,
        "network_scope_id": scope,
        "physical_mac": physical_mac,
        "status": "review_required",
        "evidence": evidence,
        "evidence_signature": build_evidence_signature(evidence),
        "evidence_binding_signature": binding,
        "job_key": job_key,
    }


class FakeRepository:
    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs
        self.claim_count = 0
        self.resolve_calls: list[dict[str, Any]] = []
        self.scoped_resolve_calls: list[dict[str, Any]] = []

    def identity_enrichment_jobs(
        self, *, status_filter: str, limit: int, home_id: str
    ) -> list[dict[str, Any]]:
        assert home_id == HOME_ID
        return [job for job in self.jobs if job["status"] == status_filter][:limit]

    def claim_identity_research_jobs(self, *, home_id: str, limit: int, job_ids=None):
        assert home_id == HOME_ID
        self.claim_count += 1
        selected = set(job_ids) if job_ids is not None else None
        return [
            job
            for job in self.jobs
            if job["status"] == "review_required"
            and (selected is None or job["job_id"] in selected)
        ][:limit]

    def resolve_identity_enrichment_job(self, job_id: str, **kwargs):
        job = next(job for job in self.jobs if job["job_id"] == job_id)
        if kwargs.get("expected_evidence_signature") != job["evidence_signature"]:
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        if kwargs.get("expected_job_key") != job["job_key"]:
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        self.resolve_calls.append({"job_id": job_id, **kwargs})
        job["status"] = "resolved"
        return job

    def resolve_device_scoped_identity_job(self, job_id: str, **kwargs):
        job = next(job for job in self.jobs if job["job_id"] == job_id)
        if kwargs.get("expected_evidence_signature") != job["evidence_signature"]:
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        if kwargs.get("expected_job_key") != job["job_key"]:
            raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")
        self.scoped_resolve_calls.append({"job_id": job_id, **kwargs})
        job["status"] = "resolved"
        return job


class FakeTransport:
    def __init__(self, handler=None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.handler = handler or self._detail_response

    @staticmethod
    def _detail_response(**_kwargs):
        body = (
            "<!doctype html><html><head>"
            '<meta property="og:site_name" content="Samsung sec">'
            "</head><body>"
            f"<script>var data = {{ mdlCode: '{MODEL}', goodsId: 'G000292313', "
            f"mdlNm: '{MODEL}', supportYn: 'Y' }};</script>"
            '<div class="prod-name">'
            '<p class="name">BESPOKE 냉장고 4도어 856L</p>'
            f'<p class="model">{MODEL}</p>'
            "</div></body></html>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html; charset=utf-8"}, body)

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.handler(**kwargs)


def _public_dns(_hostname: str) -> list[str]:
    return ["8.8.8.8"]


def _authenticated_self_android_job(
    *,
    manufacturer: str = "Samsung",
    device_type: str = "phone",
    source: str = "authenticated-self-android",
    physical_mac: str | None = "DA:F5:1E:FE:00:0A",
    model: str = PHONE_MODEL,
    network_scope_id: str = "hgns1b-0123456789abcdef0123456789abcdef",
    additional_model_source: str | None = None,
) -> dict[str, Any]:
    job = _job(
        job_id="identity-job-phone-0001",
        device_id="opaque-phone-one",
        manufacturer=manufacturer,
        device_type=device_type,
        model=model,
        physical_mac=physical_mac,
    )
    structured_provenance = [
        {"kind": "manufacturer", "source": source, "value": manufacturer},
        {"kind": "model", "source": source, "value": model},
        {"kind": "device_type", "source": source, "value": device_type},
    ]
    if additional_model_source:
        structured_provenance.append(
            {
                "kind": "model",
                "source": additional_model_source,
                "value": model,
            }
        )
    evidence = {
        "manufacturer_hints": [manufacturer],
        "model_hints": [model],
        "device_type_hints": [device_type],
        "service_hints": ["self-android"],
        "structured_provenance": structured_provenance,
    }
    binding = stable_identity_evidence_signature(
        evidence,
        device_id=job["device_id"],
    )
    job.update(
        {
            "network_scope_id": network_scope_id,
            "evidence": evidence,
            "evidence_signature": build_evidence_signature(evidence),
            "evidence_binding_signature": binding,
            "job_key": build_identity_job_key(
                home_id=HOME_ID,
                device_id=job["device_id"],
                network_scope_id=network_scope_id,
                physical_mac=physical_mac,
                evidence_binding_signature=binding,
            ),
        }
    )
    return job


class SamsungMobileTransport:
    def __init__(
        self,
        *,
        model: str = PHONE_MODEL,
        full_model: str = PHONE_FULL_MODEL,
        goods_id: str = PHONE_GOODS_ID,
        category: str = "스마트폰",
        nonexistent: bool = False,
        detail_goods_id: str | None = None,
    ):
        self.calls: list[dict[str, Any]] = []
        self.model = model
        self.full_model = full_model
        self.goods_id = goods_id
        self.category = category
        self.nonexistent = nonexistent
        self.detail_goods_id = detail_goods_id or goods_id
        self.detail_url = (
            f"https://www.samsung.com/sec/support/model/{full_model}/"
        )

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["url"] == "https://www.samsung.com/sec/xhr/prdMdlSearch/":
            assert kwargs.get("method") == "POST"
            if self.nonexistent:
                assert kwargs.get("body", b"").startswith(b"prdMdlName=SM-")
            else:
                assert kwargs.get("body") == f"prdMdlName={self.model}".encode("ascii")
            info = None
            if not self.nonexistent:
                info = {
                    "prdMdlCd": self.full_model,
                    "prdMdlName": self.model,
                    "prdIaName": self.category,
                    "goodsId": self.goods_id,
                }
            return OfficialHttpResponse(
                200,
                {"Content-Type": "application/json; charset=UTF-8"},
                json.dumps({"prdMdlInfo": info}, ensure_ascii=False).encode(),
            )
        assert kwargs["url"] == self.detail_url
        body = (
            "<!doctype html><html><head>"
            '<meta property="og:site_name" content="Samsung sec">'
            "</head><body>"
            f"<script>var data = {{ mdlCode: '{self.full_model}', "
            f"mdlNm: '{self.model}', goodsId: '{self.detail_goods_id}', "
            "supportYn: 'Y' };</script>"
            '<div class="prod-name"><p class="name"></p>'
            f'<p class="model">{self.model}</p></div>'
            "</body></html>"
        ).encode()
        return OfficialHttpResponse(
            200,
            {"Content-Type": "text/html; charset=UTF-8"},
            body,
        )


class SamsungCanaryTransport:
    _DISCOVERY = {
        PHONE_MODEL: (PHONE_FULL_MODEL, PHONE_GOODS_ID, "스마트폰"),
        TABLET_MODEL: (TABLET_FULL_MODEL, TABLET_GOODS_ID, "태블릿"),
    }

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        url = kwargs["url"]
        if url == "https://www.samsung.com/sec/xhr/prdMdlSearch/":
            assert kwargs.get("method") == "POST"
            model = kwargs.get("body", b"").decode("ascii").removeprefix(
                "prdMdlName="
            )
            record = self._DISCOVERY.get(model)
            info = None
            if record is not None:
                full_model, goods_id, category = record
                info = {
                    "prdMdlCd": full_model,
                    "prdMdlName": model,
                    "prdIaName": category,
                    "goodsId": goods_id,
                }
            return OfficialHttpResponse(
                200,
                {"Content-Type": "application/json; charset=UTF-8"},
                json.dumps({"prdMdlInfo": info}, ensure_ascii=False).encode(),
            )
        if url == DETAIL_URL:
            return FakeTransport._detail_response()
        if url == PHONE_DETAIL_URL:
            return SamsungMobileTransport()(**kwargs)
        if url == TABLET_DETAIL_URL:
            return SamsungMobileTransport(
                model=TABLET_MODEL,
                full_model=TABLET_FULL_MODEL,
                goods_id=TABLET_GOODS_ID,
                category="태블릿",
            )(**kwargs)
        return OfficialHttpResponse(404, {"Content-Type": "text/html"}, b"")


def _write_profile(
    path: Path,
    *,
    host: str = "www.samsung.com",
    kind: str = "detail",
    template: str | None = None,
    enabled: bool = True,
) -> Path:
    endpoints = [
        {
            "kind": kind,
            "url_template": template
            or f"https://{host}/sec/support/model/{{model}}/",
            **(
                {"expected_device_type": "fridge"}
                if kind == "authoritative_category"
                else {}
            ),
        }
    ]
    profile: dict[str, Any] = {
        "manufacturer": "Samsung",
        "enabled": enabled,
        "official_fqdns": [host],
        "endpoints": endpoints,
    }
    if enabled:
        profile.update(
            {
                "canary": {
                    "known_model": MODEL,
                    "impossible_model": "HGNOTREAL999",
                    "device_type": "fridge",
                },
                "positive_proof": {
                    "parser": "samsung_support_product",
                    "manufacturer_terms": ["Samsung"],
                    "device_type_terms": {"fridge": ["냉장고", "refrigerator"]},
                },
            }
        )
    else:
        profile["disabled_reason"] = "Fixture profile is intentionally disabled."
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "profiles": [profile],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_api_key_free_exact_detail_match_resolves_with_cas_binding():
    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport()

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 1
    assert outcome.unresolved_job_ids == ()
    assert repository.claim_count == 0
    assert repository.resolve_calls == [
        {
            "job_id": job["job_id"],
            "manufacturer": "Samsung",
            "device_type": "fridge",
            "model": MODEL,
            "source_reference": DETAIL_URL,
            "resolution_provenance": "automated-official-http",
            "expected_evidence_signature": job["evidence_signature"],
            "expected_job_key": job["job_key"],
        }
    ]


def test_authenticated_android_sm_f956n_uses_official_discovery_then_exact_support_page():
    job = _authenticated_self_android_job()
    repository = FakeRepository([job])
    transport = SamsungMobileTransport()

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 1
    assert outcome.scoped_match_count == 1
    assert outcome.pending_count == 0
    assert outcome.fetched_page_count == 2
    assert [call["url"] for call in transport.calls] == [
        "https://www.samsung.com/sec/xhr/prdMdlSearch/",
        PHONE_DETAIL_URL,
    ]
    assert repository.resolve_calls == []
    assert len(repository.scoped_resolve_calls) == 1
    assert repository.scoped_resolve_calls[0]["job_id"] == job["job_id"]
    assert outcome.job_outcomes[0].resolved is True
    assert outcome.job_outcomes[0].error_code is None


def test_authenticated_android_sm_t720_uses_exact_tablet_category_and_support_page():
    job = _authenticated_self_android_job(
        device_type="tablet",
        model=TABLET_MODEL,
    )
    repository = FakeRepository([job])
    transport = SamsungMobileTransport(
        model=TABLET_MODEL,
        full_model=TABLET_FULL_MODEL,
        goods_id=TABLET_GOODS_ID,
        category="태블릿",
    )

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 1
    assert outcome.scoped_match_count == 1
    assert outcome.pending_count == 0
    assert outcome.fetched_page_count == 2
    assert [call["url"] for call in transport.calls] == [
        "https://www.samsung.com/sec/xhr/prdMdlSearch/",
        TABLET_DETAIL_URL,
    ]
    assert repository.resolve_calls == []
    assert len(repository.scoped_resolve_calls) == 1
    assert repository.scoped_resolve_calls[0]["job_id"] == job["job_id"]
    assert outcome.job_outcomes[0].resolved is True
    assert outcome.job_outcomes[0].error_code is None


def test_authenticated_android_scoped_repository_rejection_stays_pending():
    job = _authenticated_self_android_job(
        device_type="tablet",
        model=TABLET_MODEL,
    )
    repository = FakeRepository([job])

    def reject_scoped(job_id: str, **kwargs):
        repository.scoped_resolve_calls.append({"job_id": job_id, **kwargs})
        raise IdentityEnrichmentError("IDENTITY_BINDING_REQUIRED")

    repository.resolve_device_scoped_identity_job = reject_scoped
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=SamsungMobileTransport(
            model=TABLET_MODEL,
            full_model=TABLET_FULL_MODEL,
            goods_id=TABLET_GOODS_ID,
            category="태블릿",
        ),
        resolver=_public_dns,
    )

    assert outcome.scoped_match_count == 1
    assert outcome.resolved_count == 0
    assert outcome.pending_count == 1
    assert outcome.failed_count == 0
    assert repository.resolve_calls == []
    assert len(repository.scoped_resolve_calls) == 1
    assert outcome.job_outcomes[0].resolved is False
    assert outcome.job_outcomes[0].error_code == "OFFICIAL_LOOKUP_BINDING_REJECTED"


def test_authenticated_android_match_is_not_sent_to_optional_ai_or_resolver():
    job = _authenticated_self_android_job()
    repository = FakeRepository([job])
    called = False

    def transport(**_kwargs):
        nonlocal called
        called = True
        raise AssertionError("scoped Build claim must not reach optional AI")

    outcome = research_pending_identities(
        repository,
        home_id=HOME_ID,
        claimed_jobs=[job],
        transport=transport,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "1",
            "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz123456",
            "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
        },
    )

    assert called is False
    assert outcome.eligible_count == 0
    assert outcome.attempted_count == 0
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_authenticated_android_with_extra_model_signal_still_cannot_seed_catalog():
    job = _authenticated_self_android_job(additional_model_source="mdns")
    repository = FakeRepository([job])
    transport = SamsungMobileTransport()

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.scoped_match_count == 1
    assert outcome.resolved_count == 1
    assert outcome.pending_count == 0
    assert outcome.fetched_page_count == 2
    assert repository.resolve_calls == []
    assert len(repository.scoped_resolve_calls) == 1
    assert outcome.job_outcomes[0].resolved is True
    assert outcome.job_outcomes[0].error_code is None


def test_samsung_canaries_cover_fridge_phone_and_tablet_positive_and_impossible(
    tmp_path,
):
    raw = json.loads(
        official_lookup_module.OFFICIAL_PRODUCT_SOURCES_PATH.read_text(
            encoding="utf-8"
        )
    )
    raw["profiles"] = [raw["profiles"][0]]
    profiles_path = tmp_path / "samsung-canaries.json"
    profiles_path.write_text(
        json.dumps(raw, ensure_ascii=False),
        encoding="utf-8",
    )
    transport = SamsungCanaryTransport()

    outcomes = validate_official_product_canaries(
        transport=transport,
        resolver=_public_dns,
        profiles_path=profiles_path,
    )

    by_type = {outcome.device_type: outcome for outcome in outcomes}
    assert set(by_type) == {"fridge", "phone", "tablet"}
    assert all(outcome.known_matched for outcome in outcomes)
    assert all(outcome.impossible_rejected for outcome in outcomes)
    assert by_type["fridge"].known_source_url == DETAIL_URL
    assert by_type["phone"].known_source_url == PHONE_DETAIL_URL
    assert by_type["tablet"].known_source_url == TABLET_DETAIL_URL
    posted_models = {
        call["body"].decode("ascii").removeprefix("prdMdlName=")
        for call in transport.calls
        if call["url"] == "https://www.samsung.com/sec/xhr/prdMdlSearch/"
    }
    assert {
        PHONE_MODEL,
        "SM-FHGNOTREAL999",
        TABLET_MODEL,
        "SM-THGNOTREAL999",
    }.issubset(posted_models)


def test_samsung_discovery_nonexistent_model_stays_unresolved_without_detail_fetch():
    job = _authenticated_self_android_job(model="SM-F999N")
    repository = FakeRepository([job])
    transport = SamsungMobileTransport(nonexistent=True)

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 0
    assert len(transport.calls) == 1
    assert repository.resolve_calls == []


def test_samsung_tablet_discovery_nonexistent_model_stays_unresolved():
    job = _authenticated_self_android_job(
        device_type="tablet",
        model="SM-T999",
    )
    repository = FakeRepository([job])
    transport = SamsungMobileTransport(
        model="SM-T999",
        full_model="SM-T999NZSAKOO",
        goods_id=TABLET_GOODS_ID,
        category="태블릿",
        nonexistent=True,
    )

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 0
    assert len(transport.calls) == 1
    assert repository.resolve_calls == []


def test_samsung_tablet_discovery_rejects_phone_category_before_detail_fetch():
    job = _authenticated_self_android_job(
        device_type="tablet",
        model=TABLET_MODEL,
    )
    repository = FakeRepository([job])
    transport = SamsungMobileTransport(
        model=TABLET_MODEL,
        full_model=TABLET_FULL_MODEL,
        goods_id=TABLET_GOODS_ID,
        category="스마트폰",
    )

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 0
    assert len(transport.calls) == 1
    assert repository.resolve_calls == []


def test_samsung_discovery_and_support_page_goods_ids_must_match():
    job = _authenticated_self_android_job()
    repository = FakeRepository([job])
    transport = SamsungMobileTransport(detail_goods_id="G999999999")

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.resolved_count == 0
    assert len(transport.calls) == 2
    assert repository.resolve_calls == []


@pytest.mark.parametrize(
    "job",
    [
        _authenticated_self_android_job(manufacturer="LG"),
        _authenticated_self_android_job(device_type="fridge"),
        _authenticated_self_android_job(source="self-android"),
        _authenticated_self_android_job(physical_mac=None),
        _authenticated_self_android_job(physical_mac="02:00:00:00:00:00"),
        _authenticated_self_android_job(
            network_scope_id="hgns1s-0123456789abcdef0123456789abcdef"
        ),
    ],
    ids=(
        "wrong-maker",
        "wrong-type",
        "unreserved-source",
        "missing-mac",
        "placeholder-mac",
        "weak-network-scope",
    ),
)
def test_authenticated_android_claim_mismatch_or_missing_binding_never_fetches(job):
    repository = FakeRepository([job])
    transport = SamsungMobileTransport()

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )

    assert outcome.eligible_count == 0
    assert outcome.resolved_count == 0
    assert transport.calls == []
    assert repository.resolve_calls == []


def test_same_exact_product_batch_uses_one_official_get_and_resolves_each_job():
    jobs = [
        _job(job_id=f"identity-job-shared-{index:02d}", device_id=f"device-{index:02d}")
        for index in range(8)
    ]
    repository = FakeRepository(jobs)
    transport = FakeTransport()

    outcome = lookup_claimed_official_products(
        repository,
        jobs,
        transport=transport,
        resolver=_public_dns,
    )

    assert len(transport.calls) == 1
    assert outcome.attempted_count == 1
    assert outcome.resolved_count == 8
    assert outcome.unresolved_job_ids == ()
    assert {call["job_id"] for call in repository.resolve_calls} == {
        job["job_id"] for job in jobs
    }


def test_eighty_four_same_product_jobs_need_only_one_external_get(tmp_path):
    repository = SQLiteRepository(db_path=tmp_path / "official-84.sqlite3")
    repository.upsert_user(
        {
            "user_id": "owner-official-84",
            "email": "official84@example.invalid",
            "nickname": "official84",
            "role": "user",
            "email_verified": True,
            "home_id": HOME_ID,
        }
    )
    jobs = [
        _job(
            job_id=f"identity-job-shared-{index:03d}",
            device_id=f"device-shared-{index:03d}",
        )
        for index in range(84)
    ]
    with repository._connect() as conn:
        conn.executemany(
            """
            INSERT INTO identity_enrichment_jobs (
                job_id, job_key, home_id, device_id, network_scope_id,
                physical_mac, evidence_binding_signature, status, blocked_reason,
                evidence_json, evidence_signature, seen_count, first_seen_at,
                last_seen_at, updated_at, research_attempt_count
            ) VALUES (?, ?, ?, ?, ?, NULL, ?, 'review_required', NULL, ?, ?, 1, ?, ?, ?, 0)
            """,
            [
                (
                    job["job_id"],
                    job["job_key"],
                    job["home_id"],
                    job["device_id"],
                    job["network_scope_id"],
                    job["evidence_binding_signature"],
                    json.dumps(job["evidence"], ensure_ascii=False, sort_keys=True),
                    job["evidence_signature"],
                    f"2026-08-28T00:{index // 60:02d}:{index % 60:02d}Z",
                    f"2026-08-28T00:{index // 60:02d}:{index % 60:02d}Z",
                    f"2026-08-28T00:{index // 60:02d}:{index % 60:02d}Z",
                )
                for index, job in enumerate(jobs)
            ],
        )
    transport = FakeTransport()

    outcome = run_identity_research_worker(
        repository,
        official_lookup=lambda repo, *, claimed_jobs: lookup_claimed_official_products(
            repo,
            claimed_jobs,
            transport=transport,
            resolver=_public_dns,
        ),
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "0",
            "HG_IDENTITY_RESEARCH_BATCH_SIZE": "8",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "8",
        },
        monotonic=lambda: 0.0,
    )

    assert len(transport.calls) == 1
    assert outcome.claimed_count == 8
    assert outcome.official_attempted_count == 1
    stored = repository.identity_enrichment_jobs(home_id=HOME_ID, limit=200)
    assert len(stored) == 84
    assert {job["status"] for job in stored} == {"resolved"}


def test_pending_wrapper_claims_exactly_once():
    repository = FakeRepository([_job()])
    outcome = lookup_pending_official_products(
        repository,
        home_id=HOME_ID,
        transport=FakeTransport(),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 1
    assert repository.claim_count == 1


def test_no_exact_model_never_fetches():
    job = _job(model=None, physical_mac="02:11:22:33:44:55")
    repository = FakeRepository([job])
    transport = FakeTransport()

    outcome = lookup_claimed_official_products(
        repository, [job], transport=transport, resolver=_public_dns
    )

    assert outcome.eligible_count == 0
    assert outcome.attempted_count == 0
    assert outcome.unresolved_job_ids == (job["job_id"],)
    assert transport.calls == []


def test_partial_title_model_does_not_resolve():
    def partial(**_kwargs):
        body = f"<title>Samsung RF85C90N1</title><h1>RF85C90N1</h1>".encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(partial),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_unregistered_profile_host_is_rejected_before_fetch(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json", host="products.example.org")
    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport()

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
        profiles_path=profile,
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_PROFILE_INVALID"
    assert outcome.resolved_count == 0
    assert transport.calls == []


def test_ip_literal_profile_is_rejected_before_dns_or_fetch(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json", host="127.0.0.1")
    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport()
    dns_calls: list[str] = []

    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda host: dns_calls.append(host) or ["8.8.8.8"],
        profiles_path=profile,
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_PROFILE_INVALID"
    assert dns_calls == []
    assert transport.calls == []


def test_redirect_to_non_profile_host_is_rejected_without_following():
    def redirect(**_kwargs):
        return OfficialHttpResponse(
            302,
            {"Location": "https://attacker.example/product/RF85C90N1AP"},
            b"",
        )

    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport(redirect)
    outcome = lookup_claimed_official_products(
        repository, [job], transport=transport, resolver=_public_dns
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_REDIRECT_REJECTED"
    assert outcome.resolved_count == 0
    assert len(transport.calls) == 1


@pytest.mark.parametrize(
    "resolved_ip",
    ["192.168.0.2", "127.0.0.1", "169.254.1.3", "::1", "fc00::1"],
)
def test_private_or_non_global_dns_is_rejected_before_fetch(resolved_ip):
    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport()
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda _host: [resolved_ip],
    )
    assert outcome.error_code == "OFFICIAL_LOOKUP_DNS_REJECTED"
    assert transport.calls == []


def test_all_dns_answers_are_validated_before_any_transport_attempt():
    job = _job(job_id="identity-job-02001", device_id="mixed-dns-answer")
    repository = FakeRepository([job])
    transport = FakeTransport()
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda _host: ["8.8.8.8", "192.168.0.2"],
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_DNS_REJECTED"
    assert transport.calls == []


def test_transport_failure_retries_next_prevalidated_dns_answer():
    def fail_first_ip(**kwargs):
        if kwargs["resolved_ip"] == "8.8.8.8":
            raise OSError("first CDN address is unreachable")
        return FakeTransport._detail_response()

    job = _job(job_id="identity-job-02002", device_id="dns-ip-fallback")
    repository = FakeRepository([job])
    transport = FakeTransport(fail_first_ip)
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda _host: ["8.8.8.8", "1.1.1.1"],
    )

    assert outcome.resolved_count == 1
    assert [call["resolved_ip"] for call in transport.calls] == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_http_response_is_not_retried_on_another_dns_answer(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json")
    transport = FakeTransport(
        lambda **_kwargs: OfficialHttpResponse(
            503, {"Content-Type": "text/html"}, b"unavailable"
        )
    )
    job = _job(job_id="identity-job-02003", device_id="dns-http-no-retry")
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda _host: ["8.8.8.8", "1.1.1.1"],
        profiles_path=profile,
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_HTTP_REJECTED"
    assert [call["resolved_ip"] for call in transport.calls] == ["8.8.8.8"]


def test_transport_fallback_is_bounded_to_four_dns_answers(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json")

    def unreachable(**_kwargs):
        raise OSError("unreachable")

    job = _job(job_id="identity-job-02004", device_id="dns-bounded-fallback")
    repository = FakeRepository([job])
    transport = FakeTransport(unreachable)
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=lambda _host: [
            "8.8.8.8",
            "1.1.1.1",
            "9.9.9.9",
            "208.67.222.222",
            "208.67.220.220",
        ],
        profiles_path=profile,
    )

    assert outcome.error_code == "OFFICIAL_LOOKUP_TRANSPORT_FAILED"
    assert len(transport.calls) == 4


def test_oversized_response_is_rejected():
    def oversized(**_kwargs):
        return OfficialHttpResponse(
            200,
            {"Content-Type": "text/html"},
            b"x" * (256 * 1024 + 1),
        )

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(oversized),
        resolver=_public_dns,
    )
    assert outcome.error_code == "OFFICIAL_LOOKUP_RESPONSE_TOO_LARGE"
    assert outcome.resolved_count == 0


def test_timeout_is_bounded_failure():
    def timeout(**_kwargs):
        raise TimeoutError("fixture timeout")

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(timeout),
        resolver=_public_dns,
    )
    assert outcome.error_code == "OFFICIAL_LOOKUP_TIMEOUT"
    assert outcome.failed_count == 1
    assert outcome.resolved_count == 0


def test_catalog_plain_text_model_occurrence_is_not_product_proof(tmp_path):
    profile = _write_profile(
        tmp_path / "profiles.json",
        kind="authoritative_catalog",
        template="https://www.samsung.com/sec/catalog?q={model}",
    )

    def search_page(**_kwargs):
        body = (
            f"<title>Search results for {MODEL}</title>"
            f"<h1>Samsung {MODEL}</h1><p>{MODEL}</p>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(search_page),
        resolver=_public_dns,
        profiles_path=profile,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_catalog_requires_exact_structured_model_manufacturer_and_type_proof(tmp_path):
    profile = _write_profile(
        tmp_path / "profiles.json",
        kind="authoritative_catalog",
        template="https://www.samsung.com/sec/catalog?q={model}",
    )

    def catalog(**_kwargs):
        return OfficialHttpResponse(
            200,
            {"Content-Type": "application/json"},
            json.dumps(
                {
                    "products": [
                        {
                            "@type": "Product",
                            "brand": {"@type": "Brand", "name": "Samsung"},
                            "model": MODEL,
                            "category": "냉장고",
                            "url": DETAIL_URL,
                        }
                    ]
                }
            ).encode(),
        )

    proven_job = _job(job_id="identity-job-00021")
    unproven_job = _job(job_id="identity-job-00022", include_type_proof=False)
    proven_repo = FakeRepository([proven_job])
    unproven_repo = FakeRepository([unproven_job])
    proven = lookup_claimed_official_products(
        proven_repo,
        [proven_job],
        transport=FakeTransport(catalog),
        resolver=_public_dns,
        profiles_path=profile,
    )
    unproven = lookup_claimed_official_products(
        unproven_repo,
        [unproven_job],
        transport=FakeTransport(catalog),
        resolver=_public_dns,
        profiles_path=profile,
    )
    assert proven.resolved_count == 1
    assert unproven.resolved_count == 0


def test_json_ld_partial_model_and_wrong_manufacturer_are_rejected(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json")

    def mismatch(**_kwargs):
        body = json.dumps(
            {
                "@context": "https://schema.org",
                "@type": "Product",
                "brand": {"@type": "Brand", "name": "LG"},
                "model": "RF85C90N1",
                "url": DETAIL_URL,
            }
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "application/ld+json"}, body)

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(mismatch),
        resolver=_public_dns,
        profiles_path=profile,
    )
    assert outcome.resolved_count == 0


def test_request_contains_model_but_no_lan_or_job_identifiers():
    job = _job()
    repository = FakeRepository([job])
    transport = FakeTransport()
    outcome = lookup_claimed_official_products(
        repository, [job], transport=transport, resolver=_public_dns
    )
    assert outcome.resolved_count == 1
    serialized_request = json.dumps(transport.calls, ensure_ascii=False)
    assert MODEL in serialized_request
    for forbidden in (
        HOME_ID,
        job["job_id"],
        job["device_id"],
        job["network_scope_id"],
        "192.168.",
        "AA:BB:",
        "OPENAI_API_KEY",
        "Authorization",
    ):
        assert forbidden not in serialized_request


def test_duplicate_models_remain_bound_to_distinct_jobs():
    first = _job(job_id="identity-job-01001", device_id="opaque-device-one")
    second = _job(job_id="identity-job-01002", device_id="opaque-device-two")
    assert first["job_key"] != second["job_key"]
    repository = FakeRepository([first, second])
    outcome = lookup_claimed_official_products(
        repository,
        [first, second],
        transport=FakeTransport(),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 2
    assert {call["job_id"] for call in repository.resolve_calls} == {
        first["job_id"],
        second["job_id"],
    }
    assert {
        call["job_id"]: call["expected_job_key"] for call in repository.resolve_calls
    } == {
        first["job_id"]: first["job_key"],
        second["job_id"]: second["job_key"],
    }


def test_reflected_soft_404_title_h1_and_url_are_not_positive_product_proof():
    def reflected(**kwargs):
        requested_model = kwargs["url"].rstrip("/").rsplit("/", 1)[-1]
        body = (
            "<html><head>"
            f"<title>Samsung 냉장고 {requested_model}</title>"
            '<meta property="og:site_name" content="Samsung sec">'
            "</head><body>"
            f"<h1>{requested_model} 냉장고</h1>"
            "<p>요청한 페이지를 찾을 수 없습니다.</p>"
            "</body></html>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)

    job = _job()
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(reflected),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


@pytest.mark.parametrize(
    "body",
    [
        (
            f"<script>var x={{mdlCode:'{MODEL}',mdlNm:'{MODEL}',"
            "goodsId:'G000292313',supportYn:'Y'}};</script>"
            '<div class="prod-name"><p class="name">BESPOKE 냉장고</p>'
            f'<p class="model">{MODEL}</p></div>'
        ),
        (
            '<meta property="og:site_name" content="Samsung sec">'
            f"<script>var x={{mdlCode:'{MODEL}',mdlNm:'{MODEL}',"
            "goodsId:'G000292313',supportYn:'Y'}};</script>"
            '<div class="prod-name"><p class="name">BESPOKE 가전제품</p>'
            f'<p class="model">{MODEL}</p></div>'
        ),
    ],
)
def test_html_positive_selector_still_requires_response_manufacturer_and_type_proof(body):
    job = _job(job_id="identity-job-01501", device_id="response-proof-missing")
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(
            lambda **_kwargs: OfficialHttpResponse(
                200,
                {"Content-Type": "text/html"},
                body.encode(),
            )
        ),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


@pytest.mark.parametrize(
    "product",
    [
        {"@type": "Product", "model": MODEL, "category": "냉장고", "url": DETAIL_URL},
        {
            "@type": "Product",
            "brand": "Samsung",
            "manufacturer": "LG",
            "model": MODEL,
            "category": "냉장고",
            "url": DETAIL_URL,
        },
        {"@type": "Product", "brand": "Samsung", "model": MODEL, "url": DETAIL_URL},
        {
            "@type": "Product",
            "brand": "Samsung",
            "model": MODEL,
            "category": ["냉장고", "공유기"],
            "url": DETAIL_URL,
        },
    ],
)
def test_json_ld_product_missing_or_conflicting_manufacturer_and_type_is_rejected(product):
    job = _job(job_id="identity-job-01502", device_id="jsonld-proof-invalid")
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=FakeTransport(
            lambda **_kwargs: OfficialHttpResponse(
                200,
                {"Content-Type": "application/ld+json"},
                json.dumps(product).encode(),
            )
        ),
        resolver=_public_dns,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


@pytest.mark.parametrize(
    "job",
    [
        _job(
            job_id="identity-job-02001",
            device_id="manufacturer-proof-missing",
            include_manufacturer_proof=False,
        ),
        _job(
            job_id="identity-job-02002",
            device_id="manufacturer-proof-conflict",
            extra_provenance=[
                {"kind": "manufacturer", "source": "mdns", "value": "LG"}
            ],
        ),
        _job(
            job_id="identity-job-02003",
            device_id="type-proof-missing",
            include_type_proof=False,
        ),
        _job(
            job_id="identity-job-02004",
            device_id="type-proof-conflict",
            extra_provenance=[
                {"kind": "device_type", "source": "mdns", "value": "router"}
            ],
        ),
    ],
)
def test_missing_or_conflicting_structured_manufacturer_and_type_proofs_never_fetch(job):
    repository = FakeRepository([job])
    transport = FakeTransport()
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )
    assert outcome.eligible_count == 0
    assert outcome.attempted_count == 0
    assert outcome.resolved_count == 0
    assert transport.calls == []


def test_dns_call_obeys_total_deadline_and_transport_is_never_called(monkeypatch):
    monkeypatch.setattr(official_lookup_module, "_TOTAL_TIMEOUT_SECONDS", 0.05)
    release = threading.Event()

    def blocked_dns(_hostname: str):
        release.wait(0.2)
        return ["8.8.8.8"]

    job = _job(job_id="identity-job-03001", device_id="dns-deadline")
    repository = FakeRepository([job])
    transport = FakeTransport()
    started = time.monotonic()
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=blocked_dns,
    )
    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 0.5
    assert outcome.error_code == "OFFICIAL_LOOKUP_TIMEOUT"
    assert outcome.resolved_count == 0
    assert transport.calls == []


def test_timed_out_dns_workers_are_bounded_without_unlimited_thread_submission():
    release = threading.Event()
    calls: list[str] = []

    def never_before_release(hostname: str):
        calls.append(hostname)
        release.wait()
        return ["8.8.8.8"]

    for index in range(2):
        with pytest.raises(official_lookup_module.OfficialProductLookupFailure) as failure:
            official_lookup_module._resolve_dns_with_deadline(
                f"www{index}.samsung.com",
                never_before_release,
                deadline=time.monotonic() + 0.02,
            )
        assert failure.value.code == "OFFICIAL_LOOKUP_TIMEOUT"
    with pytest.raises(official_lookup_module.OfficialProductLookupFailure) as saturated:
        official_lookup_module._resolve_dns_with_deadline(
            "www2.samsung.com",
            never_before_release,
            deadline=time.monotonic() + 0.1,
        )
    assert saturated.value.code == "OFFICIAL_LOOKUP_DNS_BUSY"
    assert len(calls) == 2
    release.set()
    acquired = 0
    try:
        for _ in range(2):
            assert official_lookup_module._DNS_SLOTS.acquire(timeout=1.0)
            acquired += 1
    finally:
        for _ in range(acquired):
            official_lookup_module._DNS_SLOTS.release()


def test_disabled_profile_never_claims_resolves_dns_or_fetches(tmp_path):
    profile = _write_profile(tmp_path / "profiles.json", enabled=False)
    repository = FakeRepository([_job()])
    transport = FakeTransport()
    dns_calls: list[str] = []
    outcome = lookup_pending_official_products(
        repository,
        home_id=HOME_ID,
        transport=transport,
        resolver=lambda hostname: dns_calls.append(hostname) or ["8.8.8.8"],
        profiles_path=profile,
    )
    assert outcome.eligible_count == 0
    assert outcome.pending_count == 1
    assert repository.claim_count == 0
    assert dns_calls == []
    assert transport.calls == []


def test_invalid_enabled_profile_schema_does_not_consume_claim_backoff(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "profiles": [
                    {
                        "manufacturer": "Samsung",
                        "enabled": True,
                        "official_fqdns": ["www.samsung.com"],
                        "endpoints": [
                            {
                                "kind": "detail",
                                "url_template": "https://www.samsung.com/sec/support/model/{model}/",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    repository = FakeRepository([_job()])
    outcome = lookup_pending_official_products(
        repository,
        home_id=HOME_ID,
        transport=FakeTransport(),
        resolver=_public_dns,
        profiles_path=path,
    )
    assert outcome.error_code == "OFFICIAL_LOOKUP_PROFILE_INVALID"
    assert repository.claim_count == 0


def _canary_response(url: str) -> OfficialHttpResponse:
    if "samsung.com" in url:
        requested = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        if requested != MODEL:
            body = (
                f"<title>Samsung 냉장고 {requested}</title>"
                '<meta property="og:site_name" content="Samsung sec">'
                f"<h1>{requested} 냉장고</h1>"
            ).encode()
        else:
            body = FakeTransport._detail_response().body
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)
    if "tp-link.com" in url:
        requested_slug = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        if requested_slug != "archer-ax73":
            return OfficialHttpResponse(404, {"Content-Type": "text/html"}, b"")
        body = (
            "<html><head>"
            '<link rel="canonical" href="https://www.tp-link.com/kr/home-networking/wifi-router/archer-ax73/">'
            '<title>Archer AX73 | AX5400 듀얼 밴드 기가비트 Wi-Fi 6 공유기 | TP-Link 대한민국</title>'
            '<meta property="og:image" content="https://static.tp-link.com/upload/Archer_AX73(US)1.0_A.jpg">'
            "</head><body><h1>AX5400 듀얼 밴드 기가비트 Wi-Fi 6 공유기</h1></body></html>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)
    if "iptime.com" in url:
        body = (
            '<table><tr><td title="ipTIME AX6000M" alt="ipTIME AX6000M">'
            "ipTIME AX6000M</td></tr></table>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)
    raise AssertionError(url)


@pytest.mark.parametrize(
    ("manufacturer", "device_type", "known_model", "impossible_model", "stable_source"),
    [
        (
            "Samsung",
            "fridge",
            MODEL,
            "HGNOTREAL999",
            DETAIL_URL,
        ),
        (
            "TP-Link",
            "router",
            "Archer AX73",
            "HGNOTREAL999",
            "https://www.tp-link.com/kr/home-networking/wifi-router/archer-ax73/",
        ),
        (
            "iptime(EFM)",
            "router",
            "AX6000M",
            "HGNOTREAL999",
            "https://www.iptime.com/iptime/etc/down_prd_list.php",
        ),
    ],
)
def test_enabled_profile_known_model_matches_and_impossible_model_does_not(
    manufacturer,
    device_type,
    known_model,
    impossible_model,
    stable_source,
):
    known_job = _job(
        job_id="identity-job-04001",
        device_id=f"known-{manufacturer}",
        manufacturer=manufacturer,
        model=known_model,
        device_type=device_type,
    )
    known_repository = FakeRepository([known_job])
    known = lookup_claimed_official_products(
        known_repository,
        [known_job],
        transport=FakeTransport(lambda **kwargs: _canary_response(kwargs["url"])),
        resolver=_public_dns,
    )
    assert known.resolved_count == 1
    assert known_repository.resolve_calls[0]["source_reference"] == stable_source
    assert "?" not in stable_source and "#" not in stable_source

    impossible_job = _job(
        job_id="identity-job-04002",
        device_id=f"impossible-{manufacturer}",
        manufacturer=manufacturer,
        model=impossible_model,
        device_type=device_type,
    )
    impossible_repository = FakeRepository([impossible_job])
    impossible = lookup_claimed_official_products(
        impossible_repository,
        [impossible_job],
        transport=FakeTransport(lambda **kwargs: _canary_response(kwargs["url"])),
        resolver=_public_dns,
    )
    assert impossible.resolved_count == 0
    assert impossible_repository.resolve_calls == []


LG_TV_MODEL = "OLED77C4FNA"
LG_AC_MODEL = "SQ06BCPWAJ"
LG_IMPOSSIBLE = "HGNOTAREALLGMODEL999"
SONOS_MODEL = "Era 100"
SONOS_IMPOSSIBLE = "HGNOTREAL999"
ASUS_MODEL = "RT-AX86U Pro"
ASUS_IMPOSSIBLE = "HGNOTREAL999"


def _lookup_vendor(
    *,
    manufacturer: str,
    model: str,
    device_type: str,
    transport,
):
    job = _job(
        job_id="identity-job-vendor-0001",
        device_id=f"vendor-{manufacturer}-{device_type}",
        manufacturer=manufacturer,
        model=model,
        device_type=device_type,
    )
    repository = FakeRepository([job])
    outcome = lookup_claimed_official_products(
        repository,
        [job],
        transport=transport,
        resolver=_public_dns,
    )
    return outcome, repository


class LgSupportTransport:
    _CATEGORIES = {
        LG_TV_MODEL: ("TV / 프로젝터", "올레드 TV"),
        LG_AC_MODEL: ("에어컨/환기", "벽걸이형 에어컨"),
    }

    def __init__(
        self,
        *,
        info_updates: Mapping[str, Any] | None = None,
        schema_drift: bool = False,
        generic_redirect: bool = False,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.info_updates = dict(info_updates or {})
        self.schema_drift = schema_drift
        self.generic_redirect = generic_redirect

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        url = kwargs["url"]
        parsed = urlsplit(url)
        if parsed.hostname == "apiv2.lge.co.kr":
            model = parse_qs(parsed.query)["keyword"][0]
            info: object = None
            if model in self._CATEGORIES:
                super_category, category = self._CATEGORIES[model]
                info = {
                    "modelId": model,
                    "modelName": model,
                    "mktModelName": None if model == LG_TV_MODEL else model,
                    "modelDisplayName": model,
                    "modelUrlPath": f"/support/product-{model}",
                    "superCategoryName": super_category,
                    "categoryName": category,
                }
                info.update(self.info_updates)
                if self.schema_drift:
                    info = [info]
            return OfficialHttpResponse(
                200,
                {"Content-Type": "application/json"},
                json.dumps(
                    {
                        "status": 200,
                        "message": "OK",
                        "data": {"info": info, "linkUrl": None},
                    },
                    ensure_ascii=False,
                ).encode(),
            )
        if parsed.path == "/support":
            return OfficialHttpResponse(
                200,
                {"Content-Type": "text/html"},
                b"<title>\xea\xb3\xa0\xea\xb0\x9d\xec\xa7\x80\xec\x9b\x90 | LG\xec\xa0\x84\xec\x9e\x90</title>",
            )
        model = parsed.path.removeprefix("/support/product-")
        if self.generic_redirect:
            return OfficialHttpResponse(302, {"Location": "/support"}, b"")
        super_category, category = self._CATEGORIES[model]
        body = (
            "<html><head>"
            f"<title>{model} | 고객지원 | LG전자</title>"
            "</head><body>"
            f"<h1>{model} 제품 정보</h1>"
            f'<p class="desc">{super_category} &gt; {category}</p>'
            "</body></html>"
        ).encode()
        return OfficialHttpResponse(
            200,
            {"Content-Type": "text/html; charset=UTF-8"},
            body,
        )


class SonosSupportTransport:
    def __init__(
        self,
        *,
        detail_name: str = SONOS_MODEL,
        site_name: str = "Sonos Support",
        taxonomy_heading: str = "Speakers",
        taxonomy_name: str = SONOS_MODEL,
        taxonomy_href: str = "/en/products/era-100",
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.detail_name = detail_name
        self.site_name = site_name
        self.taxonomy_heading = taxonomy_heading
        self.taxonomy_name = taxonomy_name
        self.taxonomy_href = taxonomy_href

    def _index(self) -> OfficialHttpResponse:
        body = (
            '<article data-test-id="pbp-grid-speakers content-module">'
            f"<h3>{self.taxonomy_heading}</h3>"
            f'<a href="{self.taxonomy_href}"><span>{self.taxonomy_name}</span></a>'
            "</article>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        url = kwargs["url"]
        path = urlsplit(url).path
        if path == "/en/products":
            return self._index()
        if path.endswith("/hgnotreal999"):
            return OfficialHttpResponse(302, {"Location": "/en/products"}, b"")
        body = (
            "<html><head>"
            f"<title>{self.detail_name} Help and Support | Sonos</title>"
            f'<meta property="og:site_name" content="{self.site_name}">'
            '<link rel="canonical" href="https://support.sonos.com/en/products/era-100">'
            "</head><body>"
            f'<h1 data-test-id="psp-product-name">{self.detail_name}</h1>'
            "</body></html>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)


class AsusSupportTransport:
    def __init__(
        self,
        *,
        market_name: str = ASUS_MODEL,
        helpdesk_url: str | None = None,
        conflicting_branch: bool = False,
        schema_drift: bool = False,
        detail_title: str | None = None,
        breadcrumb_type: str = "WiFi Routers",
        breadcrumb_model: str = ASUS_MODEL,
        generic_redirect: bool = False,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.market_name = market_name
        self.helpdesk_url = helpdesk_url
        self.conflicting_branch = conflicting_branch
        self.schema_drift = schema_drift
        self.detail_title = detail_title or (
            f"{ASUS_MODEL} - Tech Specs｜WiFi Routers｜ASUS USA"
        )
        self.breadcrumb_type = breadcrumb_type
        self.breadcrumb_model = breadcrumb_model
        self.generic_redirect = generic_redirect

    @staticmethod
    def _base(branch: str = "asus-gaming-routers") -> str:
        return (
            "https://www.asus.com/us/networking-iot-servers/wifi-routers/"
            f"{branch}/rt-ax86u-pro"
        )

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        url = kwargs["url"]
        parsed = urlsplit(url)
        if parsed.path == "/support/api/product.asmx/GetPDSupportTab":
            requested = parse_qs(parsed.query)["model"][0]
            if requested == ASUS_IMPOSSIBLE:
                payload = {"Result": None, "Status": "FAIL", "Message": "FAIL"}
                return OfficialHttpResponse(
                    200,
                    {"Content-Type": "text/json"},
                    json.dumps(payload).encode(),
                )
            base = self._base()
            helpdesk = self.helpdesk_url or (
                f"{base}/HelpDesk_Download/?model2Name=RT-AX86U-Pro"
            )
            objects: object = [
                {
                    "Name": "Driver & Tools",
                    "Type": "HelpDesk_Download",
                    "Url": helpdesk,
                    "Items": [],
                }
            ]
            if self.conflicting_branch:
                objects.append(
                    {
                        "Name": "FAQ",
                        "Type": "HelpDesk_Knowledge",
                        "Url": (
                            f"{self._base('asus-wifi-routers')}/HelpDesk_Knowledge/"
                            "?model2Name=RT-AX86U-Pro"
                        ),
                        "Items": [],
                    }
                )
            if self.schema_drift:
                objects = {"unexpected": objects}
            payload = {
                "Result": {
                    "PDMarketName": self.market_name,
                    "PDImgUrl": "https://www.asus.com/media/product.png",
                    "Obj": objects,
                },
                "Status": "SUCCESS",
                "Message": "SUCCESS",
            }
            return OfficialHttpResponse(
                200,
                {"Content-Type": "application/json"},
                json.dumps(payload).encode(),
            )
        if parsed.path.endswith("/asus-gaming-routers/"):
            return OfficialHttpResponse(
                200,
                {"Content-Type": "text/html"},
                b"<title>ASUS Gaming Routers</title>",
            )
        if self.generic_redirect:
            return OfficialHttpResponse(302, {"Location": "../"}, b"")
        base = self._base()
        breadcrumb = {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Networking / IoT / Servers", "item": ""},
                {"@type": "ListItem", "position": 2, "name": self.breadcrumb_type, "item": ""},
                {"@type": "ListItem", "position": 3, "name": "ASUS Gaming Routers", "item": f"{base.rsplit('/', 1)[0]}/"},
                {"@type": "ListItem", "position": 4, "name": self.breadcrumb_model, "item": f"{base}/"},
            ],
        }
        body = (
            "<html><head>"
            f"<title>{self.detail_title}</title>"
            f'<link rel="canonical" href="{base}/techspec/">'
            f'<script type="application/ld+json">{json.dumps(breadcrumb)}</script>'
            "</head><body></body></html>"
        ).encode()
        return OfficialHttpResponse(200, {"Content-Type": "text/html"}, body)


@pytest.mark.parametrize(
    ("model", "device_type", "source"),
    [
        (LG_TV_MODEL, "tv", f"https://www.lge.co.kr/support/product-{LG_TV_MODEL}"),
        (LG_AC_MODEL, "air_conditioner", f"https://www.lge.co.kr/support/product-{LG_AC_MODEL}"),
    ],
)
def test_lg_exact_support_discovery_and_detail_resolve_tv_and_air_conditioner(
    model, device_type, source
):
    transport = LgSupportTransport()
    outcome, repository = _lookup_vendor(
        manufacturer="LG",
        model=model,
        device_type=device_type,
        transport=transport,
    )
    assert outcome.resolved_count == 1
    assert len(transport.calls) == 2
    assert repository.resolve_calls[0]["source_reference"] == source


@pytest.mark.parametrize(
    "transport",
    [
        LgSupportTransport(info_updates={"modelName": f"{LG_AC_MODEL}X"}),
        LgSupportTransport(info_updates={"mktModelName": f"{LG_AC_MODEL}X"}),
        LgSupportTransport(info_updates={"modelUrlPath": "/support/product-SQ06BCPWAJX"}),
        LgSupportTransport(info_updates={"categoryName": "올레드 TV"}),
        LgSupportTransport(schema_drift=True),
        LgSupportTransport(generic_redirect=True),
    ],
)
def test_lg_fuzzy_wrong_type_path_schema_and_generic_redirect_fail_closed(transport):
    outcome, repository = _lookup_vendor(
        manufacturer="LG",
        model=LG_AC_MODEL,
        device_type="air_conditioner",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_lg_null_market_model_requires_exact_display_model_fallback():
    transport = LgSupportTransport(
        info_updates={
            "mktModelName": None,
            "modelDisplayName": f"{LG_TV_MODEL}X",
        }
    )
    outcome, repository = _lookup_vendor(
        manufacturer="LG",
        model=LG_TV_MODEL,
        device_type="tv",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_lg_cross_type_and_impossible_models_are_rejected_before_detail():
    cross_transport = LgSupportTransport()
    cross, _repository = _lookup_vendor(
        manufacturer="LG",
        model=LG_TV_MODEL,
        device_type="air_conditioner",
        transport=cross_transport,
    )
    impossible_transport = LgSupportTransport()
    impossible, _repository = _lookup_vendor(
        manufacturer="LG",
        model=LG_IMPOSSIBLE,
        device_type="air_conditioner",
        transport=impossible_transport,
    )
    assert cross.resolved_count == impossible.resolved_count == 0
    assert len(cross_transport.calls) == 0
    assert len(impossible_transport.calls) == 0


def test_sonos_detail_and_speaker_taxonomy_both_required():
    transport = SonosSupportTransport()
    outcome, repository = _lookup_vendor(
        manufacturer="Sonos",
        model=SONOS_MODEL,
        device_type="speaker",
        transport=transport,
    )
    assert outcome.resolved_count == 1
    assert len(transport.calls) == 2
    assert repository.resolve_calls[0]["source_reference"] == (
        "https://support.sonos.com/en/products/era-100"
    )


@pytest.mark.parametrize(
    "transport",
    [
        SonosSupportTransport(detail_name="Era 100 SL"),
        SonosSupportTransport(site_name="Not Sonos"),
        SonosSupportTransport(taxonomy_heading="Home Theater"),
        SonosSupportTransport(taxonomy_name="Era 100 SL"),
        SonosSupportTransport(taxonomy_href="https://attacker.example/era-100"),
    ],
)
def test_sonos_substring_wrong_vendor_type_and_host_path_fail_closed(transport):
    outcome, repository = _lookup_vendor(
        manufacturer="Sonos",
        model=SONOS_MODEL,
        device_type="speaker",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_sonos_impossible_generic_landing_redirect_is_rejected():
    transport = SonosSupportTransport()
    outcome, repository = _lookup_vendor(
        manufacturer="Sonos",
        model=SONOS_IMPOSSIBLE,
        device_type="speaker",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []
    assert [urlsplit(call["url"]).path for call in transport.calls] == [
        "/en/products/hgnotreal999",
        "/en/products",
    ]


def test_asus_discovery_all_urls_and_techspec_breadcrumb_resolve():
    transport = AsusSupportTransport()
    outcome, repository = _lookup_vendor(
        manufacturer="ASUS",
        model=ASUS_MODEL,
        device_type="router",
        transport=transport,
    )
    assert outcome.resolved_count == 1
    assert len(transport.calls) == 2
    assert repository.resolve_calls[0]["source_reference"] == (
        "https://www.asus.com/us/networking-iot-servers/wifi-routers/"
        "asus-gaming-routers/rt-ax86u-pro/techspec/"
    )


@pytest.mark.parametrize(
    "transport",
    [
        AsusSupportTransport(market_name="RT-AX86U"),
        AsusSupportTransport(
            helpdesk_url=(
                "https://attacker.example/us/networking-iot-servers/wifi-routers/"
                "asus-gaming-routers/rt-ax86u-pro/HelpDesk_Download/"
                "?model2Name=RT-AX86U-Pro"
            )
        ),
        AsusSupportTransport(
            helpdesk_url=(
                "https://www.asus.com/us/networking-iot-servers/wifi-routers/"
                "not-allowed/rt-ax86u-pro/HelpDesk_Download/?model2Name=RT-AX86U-Pro"
            )
        ),
        AsusSupportTransport(conflicting_branch=True),
        AsusSupportTransport(schema_drift=True),
        AsusSupportTransport(detail_title=f"{ASUS_MODEL} - Tech Specs｜WiFi Routers｜Other"),
        AsusSupportTransport(breadcrumb_type="Laptops"),
        AsusSupportTransport(breadcrumb_model="RT-AX86U"),
        AsusSupportTransport(generic_redirect=True),
    ],
)
def test_asus_fuzzy_wrong_host_path_conflict_schema_vendor_type_and_redirect_fail_closed(
    transport,
):
    outcome, repository = _lookup_vendor(
        manufacturer="ASUS",
        model=ASUS_MODEL,
        device_type="router",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []


def test_asus_impossible_status_fail_does_not_fetch_detail():
    transport = AsusSupportTransport()
    outcome, repository = _lookup_vendor(
        manufacturer="ASUS",
        model=ASUS_IMPOSSIBLE,
        device_type="router",
        transport=transport,
    )
    assert outcome.resolved_count == 0
    assert repository.resolve_calls == []
    assert len(transport.calls) == 1


def test_new_profile_canaries_run_full_known_and_impossible_flows(tmp_path):
    source = json.loads(
        official_lookup_module.OFFICIAL_PRODUCT_SOURCES_PATH.read_text(encoding="utf-8")
    )
    transports = {
        "LG": LgSupportTransport(),
        "Sonos": SonosSupportTransport(),
        "ASUS": AsusSupportTransport(),
    }
    expected_counts = {"LG": 2, "Sonos": 1, "ASUS": 1}
    for manufacturer, transport in transports.items():
        profile = next(
            item for item in source["profiles"] if item["manufacturer"] == manufacturer
        )
        path = tmp_path / f"{manufacturer.casefold()}-profile.json"
        path.write_text(
            json.dumps(
                {"schema_version": source["schema_version"], "profiles": [profile]},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        outcomes = validate_official_product_canaries(
            transport=transport,
            resolver=_public_dns,
            profiles_path=path,
        )
        assert len(outcomes) == expected_counts[manufacturer]
        assert all(item.known_matched and item.impossible_rejected for item in outcomes)


def test_sonos_locale_detail_and_lg_discovery_host_are_narrowly_registered():
    assert canonical_registered_official_product_source(
        "https://support.sonos.com/en/products/era-100", "Sonos"
    ) == "https://support.sonos.com/en/products/era-100"
    assert (
        canonical_registered_official_product_source(
            "https://support.sonos.com/en/community/era-100", "Sonos"
        )
        is None
    )
    assert canonical_registered_official_product_source(
        "https://apiv2.lge.co.kr/searchsvc/ajax/v1/search/spt-psp-cst-sm-model",
        "LG",
    ) == "https://apiv2.lge.co.kr/searchsvc/ajax/v1/search/spt-psp-cst-sm-model"
