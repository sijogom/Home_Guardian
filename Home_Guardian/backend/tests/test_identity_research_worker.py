from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from app import main as main_module
from app import identity_research_worker as worker_module
from app.identity_research_worker import (
    run_identity_research_worker,
    wake_identity_research_worker,
)
from app.services.identity_research import IdentityResearchOutcome
from app.services.identity_research import identity_research_readiness
from app.services.identity_enrichment import (
    build_evidence_signature,
    build_identity_job_key,
    stable_identity_evidence_signature,
)


def _job(job_id: str, home_id: str, first_seen: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "home_id": home_id,
        "status": "review_required",
        "first_seen_at": first_seen,
        "research_last_attempt_at": None,
    }


class _Repository:
    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs
        self.claimed_homes: list[str] = []
        self.due_home_ids_calls = 0

    def identity_enrichment_jobs(
        self,
        *,
        status_filter: str | None = None,
        limit: int = 100,
        home_id: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = [
            job
            for job in self.jobs
            if (status_filter is None or job["status"] == status_filter)
            and (home_id is None or job["home_id"] == home_id)
        ]
        return rows[:limit]

    def claim_identity_research_jobs(
        self,
        *,
        home_id: str,
        limit: int = 8,
        job_ids=None,
    ) -> list[dict[str, Any]]:
        self.claimed_homes.append(home_id)
        selected = set(job_ids) if job_ids is not None else None
        claimed = [
            job
            for job in self.jobs
            if job["home_id"] == home_id
            and job["status"] == "review_required"
            and not job.get("research_last_attempt_at")
            and (selected is None or job["job_id"] in selected)
        ][:limit]
        for job in claimed:
            job["research_last_attempt_at"] = "2026-08-28T00:00:00Z"
        return claimed

    def identity_research_due_home_ids(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
    ) -> list[str]:
        self.due_home_ids_calls += 1
        homes: dict[str, str] = {}
        for job in self.jobs:
            if job["status"] != "review_required":
                continue
            home_id = str(job["home_id"])
            first_seen = str(job.get("first_seen_at") or "")
            homes[home_id] = min(homes.get(home_id, first_seen), first_seen)
        ordered = [
            home_id
            for home_id, _ in sorted(homes.items(), key=lambda item: (item[1], item[0]))
        ]
        return ordered[offset : offset + limit]

    def identity_research_due_jobs(
        self,
        *,
        home_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        rows = [
            job
            for job in self.jobs
            if job["home_id"] == home_id
            and job["status"] == "review_required"
            and not job.get("research_last_attempt_at")
        ]
        return rows[offset : offset + limit]


def _official_outcome(*, attempted: int, resolved: int) -> SimpleNamespace:
    return SimpleNamespace(attempted_count=attempted, resolved_count=resolved)


def _structured_job(
    *,
    job_id: str,
    home_id: str,
    first_seen: str,
    manufacturer: str,
    model: str,
    device_type: str,
) -> dict[str, Any]:
    evidence = {
        "manufacturer_hints": [manufacturer],
        "model_hints": [model],
        "device_type_hints": [device_type],
        "service_hints": ["upnp"],
        "structured_provenance": [
            {"kind": "manufacturer", "source": "upnp", "value": manufacturer},
            {"kind": "model", "source": "upnp", "value": model},
            {"kind": "model", "source": "mdns", "value": model},
            {"kind": "device_type", "source": "upnp", "value": device_type},
        ],
    }
    device_id = f"device-{job_id}"
    binding = stable_identity_evidence_signature(evidence, device_id=device_id)
    scope = "hgns1b-0123456789abcdef0123456789abcdef"
    return {
        "job_id": job_id,
        "home_id": home_id,
        "device_id": device_id,
        "network_scope_id": scope,
        "physical_mac": None,
        "evidence_binding_signature": binding,
        "status": "review_required",
        "evidence": evidence,
        "evidence_signature": build_evidence_signature(evidence),
        "job_key": build_identity_job_key(
            home_id=home_id,
            device_id=device_id,
            network_scope_id=scope,
            physical_mac=None,
            evidence_binding_signature=binding,
        ),
        "first_seen_at": first_seen,
        "research_last_attempt_at": None,
    }


def test_worker_visits_never_attempted_homes_fairly_and_ai_flag_zero_wins() -> None:
    repository = _Repository(
        [
            _job("job-newer", "home-newer", "2026-08-28T02:00:00Z"),
            _job("job-older", "home-older", "2026-08-28T01:00:00Z"),
        ]
    )
    ai_calls = 0

    def official(_repository, *, claimed_jobs):
        return _official_outcome(attempted=len(claimed_jobs), resolved=0)

    def ai(*_args, **_kwargs):
        nonlocal ai_calls
        ai_calls += 1
        raise AssertionError("AI fallback must stay disabled")

    outcome = run_identity_research_worker(
        repository,
        official_lookup=official,
        ai_research=ai,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "0",
            "HG_IDENTITY_RESEARCH_ENABLED": "1",
            "OPENAI_API_KEY": "sk-preserved-but-never-used-000000",
            "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "2",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == ["home-older", "home-newer"]
    assert outcome.official_attempted_count == 2
    assert outcome.ai_enabled is False
    assert outcome.ai_ready is False
    assert ai_calls == 0


def test_legacy_ai_flag_is_used_only_when_new_flag_is_absent() -> None:
    credentials = {
        "HG_IDENTITY_RESEARCH_ENABLED": "1",
        "OPENAI_API_KEY": "sk-test-worker-key-000000000000",
        "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
    }
    assert identity_research_readiness(credentials) == (True, "ready")
    assert identity_research_readiness(
        {**credentials, "HG_IDENTITY_AI_RESEARCH_ENABLED": "0"}
    ) == (False, "disabled")


def test_worker_reuses_same_claim_for_ai_only_after_official_failure() -> None:
    job = _job("job-one", "home-one", "2026-08-28T01:00:00Z")
    repository = _Repository([job])
    ai_job_ids: list[str] = []

    def official(_repository, *, claimed_jobs):
        assert [item["job_id"] for item in claimed_jobs] == ["job-one"]
        return _official_outcome(attempted=1, resolved=0)

    def ai(_repository, *, home_id, environ, claimed_jobs):
        assert home_id == "home-one"
        assert environ["HG_IDENTITY_AI_RESEARCH_ENABLED"] == "1"
        ai_job_ids.extend(str(item["job_id"]) for item in claimed_jobs)
        for item in claimed_jobs:
            item["status"] = "resolved"
        return IdentityResearchOutcome(True, 1, 1, 1, 0)

    outcome = run_identity_research_worker(
        repository,
        official_lookup=official,
        ai_research=ai,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "1",
            "HG_IDENTITY_RESEARCH_ENABLED": "0",
            "OPENAI_API_KEY": "sk-test-worker-key-000000000000",
            "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == ["home-one"]
    assert ai_job_ids == ["job-one"]
    assert outcome.claimed_count == 1
    assert outcome.ai_attempted_count == 1
    assert outcome.ai_resolved_count == 1
    assert outcome.remaining_count == 0


def test_worker_skips_ai_when_official_lookup_resolves_claim() -> None:
    job = _job("job-one", "home-one", "2026-08-28T01:00:00Z")
    repository = _Repository([job])

    def official(_repository, *, claimed_jobs):
        claimed_jobs[0]["status"] = "resolved"
        return _official_outcome(attempted=1, resolved=1)

    outcome = run_identity_research_worker(
        repository,
        official_lookup=official,
        ai_research=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("resolved official result must not invoke AI")
        ),
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "1",
            "OPENAI_API_KEY": "sk-test-worker-key-000000000000",
            "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
        },
        monotonic=lambda: 0.0,
    )

    assert outcome.official_resolved_count == 1
    assert outcome.ai_attempted_count == 0
    assert outcome.remaining_count == 0


def test_worker_enforces_batch_and_deadline_bounds() -> None:
    repository = _Repository(
        [
            _job("job-one", "home-one", "2026-08-28T01:00:00Z"),
            _job("job-two", "home-two", "2026-08-28T02:00:00Z"),
        ]
    )
    bounded = run_identity_research_worker(
        repository,
        official_lookup=lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=len(claimed_jobs), resolved=0
        ),
        environ={"HG_IDENTITY_RESEARCH_MAX_BATCHES": "1"},
        monotonic=lambda: 0.0,
    )
    assert bounded.batches_processed == 1
    assert repository.claimed_homes == ["home-one"]

    expired_repository = _Repository([_job("job-three", "home-three", "2026-08-28T03:00:00Z")])
    ticks = iter((0.0, 2.0, 2.0))
    expired = run_identity_research_worker(
        expired_repository,
        official_lookup=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("deadline must prevent lookup")
        ),
        environ={"HG_IDENTITY_RESEARCH_RUNTIME_SECONDS": "1"},
        monotonic=lambda: next(ticks),
    )
    assert expired.deadline_reached is True
    assert expired.batches_processed == 0


def test_worker_catalog_reconcile_is_bounded_and_shares_runtime_deadline() -> None:
    class CatalogRepository(_Repository):
        def __init__(self) -> None:
            super().__init__([_job("job-catalog-deadline", "home-catalog", "2026-08-28T01:00:00Z")])
            self.reconcile_limits: list[int] = []
            self.reconcile_inspected = 0

        def reconcile_verified_product_catalog_jobs(self, *, limit, should_stop):
            self.reconcile_limits.append(limit)
            for _ in range(limit):
                if should_stop():
                    break
                self.reconcile_inspected += 1
            return 0

    repository = CatalogRepository()
    ticks = iter((0.0, 0.0, 0.0, 2.0, 2.0, 2.0))
    outcome = run_identity_research_worker(
        repository,
        official_lookup=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("expired shared deadline must prevent lookup")
        ),
        environ={
            "HG_IDENTITY_RESEARCH_RUNTIME_SECONDS": "1",
            "HG_IDENTITY_RESEARCH_RECONCILE_LIMIT": "7",
        },
        monotonic=lambda: next(ticks),
    )

    assert repository.reconcile_limits == [7]
    assert repository.reconcile_inspected == 1
    assert repository.claimed_homes == []
    assert outcome.deadline_reached is True


def test_worker_does_not_start_catalog_reconcile_after_deadline() -> None:
    class ExpiredCatalogRepository(_Repository):
        def __init__(self) -> None:
            super().__init__([_job("job-catalog-expired", "home-catalog-expired", "2026-08-28T01:00:00Z")])
            self.reconcile_calls = 0

        def reconcile_verified_product_catalog_jobs(self, **_kwargs):
            self.reconcile_calls += 1
            raise AssertionError("reconcile must not start after the runtime deadline")

    repository = ExpiredCatalogRepository()
    ticks = iter((0.0, 2.0, 2.0, 2.0))
    outcome = run_identity_research_worker(
        repository,
        official_lookup=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("expired worker must not perform lookup")
        ),
        environ={"HG_IDENTITY_RESEARCH_RUNTIME_SECONDS": "1"},
        monotonic=lambda: next(ticks),
    )

    assert repository.reconcile_calls == 0
    assert repository.claimed_homes == []
    assert outcome.deadline_reached is True


def test_worker_drains_multiple_batches_from_one_large_home_in_one_run() -> None:
    repository = _Repository(
        [
            _job(
                f"job-academy-{index:02d}",
                "home-academy",
                f"2026-08-28T01:{index:02d}:00Z",
            )
            for index in range(17)
        ]
    )

    outcome = run_identity_research_worker(
        repository,
        official_lookup=lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=len(claimed_jobs), resolved=0
        ),
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "0",
            "HG_IDENTITY_RESEARCH_BATCH_SIZE": "8",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "3",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == ["home-academy"] * 3
    assert outcome.batches_processed == 3
    assert outcome.claimed_count == 17
    assert outcome.official_attempted_count == 17


def test_repository_due_home_query_prevents_global_job_window_starvation() -> None:
    noisy = [
        _job(f"job-noisy-{index:03d}", "home-noisy", f"2026-08-28T02:{index % 60:02d}:00Z")
        for index in range(200)
    ]
    starved = _job("job-starved", "home-starved", "2026-08-28T00:00:00Z")
    repository = _Repository([*noisy, starved])

    outcome = run_identity_research_worker(
        repository,
        official_lookup=lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=len(claimed_jobs), resolved=0
        ),
        environ={"HG_IDENTITY_RESEARCH_MAX_BATCHES": "1"},
        monotonic=lambda: 0.0,
    )

    assert repository.due_home_ids_calls == 1
    assert repository.claimed_homes == ["home-starved"]
    assert outcome.batches_processed == 1


def test_two_hundred_unsupported_homes_do_not_hide_next_supported_home(monkeypatch) -> None:
    unsupported = [
        _structured_job(
            job_id=f"identity-job-lg-home-{index:03d}",
            home_id=f"home-lg-{index:03d}",
            first_seen=f"2026-08-28T01:{index % 60:02d}:00Z",
            manufacturer="LG",
            model="FQ18HDWHN2",
            device_type="air_conditioner",
        )
        for index in range(200)
    ]
    supported = _structured_job(
        job_id="identity-job-samsung-home-200",
        home_id="home-samsung-200",
        first_seen="2026-08-28T03:00:00Z",
        manufacturer="Samsung",
        model="RF85C90N1AP",
        device_type="fridge",
    )
    repository = _Repository([*unsupported, supported])
    monkeypatch.setattr(
        worker_module,
        "_default_official_lookup",
        lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=len(claimed_jobs), resolved=0
        ),
    )

    outcome = run_identity_research_worker(
        repository,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "0",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "1",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == ["home-samsung-200"]
    assert outcome.claimed_count == 1


def test_two_hundred_unsupported_jobs_do_not_hide_old_supported_tail(monkeypatch) -> None:
    home_id = "home-mixed-201"
    unsupported = [
        _structured_job(
            job_id=f"identity-job-lg-tail-{index:03d}",
            home_id=home_id,
            first_seen=f"2026-08-28T01:{index // 60:02d}:{index % 60:02d}Z",
            manufacturer="LG",
            model="FQ18HDWHN2",
            device_type="air_conditioner",
        )
        for index in range(200)
    ]
    supported = _structured_job(
        job_id="identity-job-samsung-tail-200",
        home_id=home_id,
        first_seen="2026-08-28T04:00:00Z",
        manufacturer="Samsung",
        model="RF85C90N1AP",
        device_type="fridge",
    )
    repository = _Repository([*unsupported, supported])
    monkeypatch.setattr(
        worker_module,
        "_default_official_lookup",
        lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=len(claimed_jobs), resolved=0
        ),
    )

    outcome = run_identity_research_worker(
        repository,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "0",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "1",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == [home_id]
    assert outcome.claimed_count == 1
    assert supported["research_last_attempt_at"] is not None
    assert all(job["research_last_attempt_at"] is None for job in unsupported)


def test_ai_ready_claims_structured_job_without_official_profile(monkeypatch) -> None:
    job = _structured_job(
        job_id="identity-job-lg-ai-ready",
        home_id="home-lg-ai-ready",
        first_seen="2026-08-28T04:00:00Z",
        manufacturer="LG",
        model="FQ18HDWHN2",
        device_type="air_conditioner",
    )
    repository = _Repository([job])
    monkeypatch.setattr(
        worker_module,
        "_default_official_lookup",
        lambda _repository, *, claimed_jobs: _official_outcome(
            attempted=0, resolved=0
        ),
    )

    def ai(_repository, *, home_id, environ, claimed_jobs):
        assert home_id == "home-lg-ai-ready"
        assert [item["job_id"] for item in claimed_jobs] == [job["job_id"]]
        claimed_jobs[0]["status"] = "resolved"
        return IdentityResearchOutcome(True, 1, 1, 1, 0)

    outcome = run_identity_research_worker(
        repository,
        ai_research=ai,
        environ={
            "HG_IDENTITY_AI_RESEARCH_ENABLED": "1",
            "OPENAI_API_KEY": "sk-test-worker-key-000000000000",
            "HG_IDENTITY_RESEARCH_MODEL": "gpt-5-mini",
            "HG_IDENTITY_RESEARCH_MAX_BATCHES": "1",
        },
        monotonic=lambda: 0.0,
    )

    assert repository.claimed_homes == ["home-lg-ai-ready"]
    assert outcome.claimed_count == 1
    assert outcome.ai_resolved_count == 1


def test_wake_marker_contains_no_household_data(tmp_path: Path) -> None:
    wake = tmp_path / "identity-research" / "wake"
    wake.parent.mkdir()
    assert wake_identity_research_worker(
        {"HG_IDENTITY_RESEARCH_WAKE_PATH": str(wake)}
    )
    assert wake.read_bytes() == b""


def test_api_health_does_not_depend_on_optional_ai_configuration(monkeypatch) -> None:
    monkeypatch.setenv("HG_IDENTITY_AI_RESEARCH_ENABLED", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "invalid-but-optional")
    monkeypatch.setenv("HG_IDENTITY_RESEARCH_MODEL", "../invalid")
    assert main_module.health()["data"]["status"] == "healthy"


def test_scan_handler_only_wakes_background_research() -> None:
    source = inspect.getsource(main_module.start_security_scan)
    assert "wake_identity_research_worker()" in source
    assert "research_pending_identities(" not in source
    assert source.index("repository.create_scan(") < source.index(
        "wake_identity_research_worker()"
    )


def test_systemd_path_timer_and_manifest_recovery_contract() -> None:
    workspace = Path(__file__).resolve().parents[3]
    deploy = workspace / "Home_Guardian_Server" / "deploy"
    service = (deploy / "systemd" / "home-guardian-identity-research.service").read_text(
        encoding="utf-8"
    )
    path_unit = (deploy / "systemd" / "home-guardian-identity-research.path").read_text(
        encoding="utf-8"
    )
    timer = (deploy / "systemd" / "home-guardian-identity-research.timer").read_text(
        encoding="utf-8"
    )
    source_manifest = (deploy / "manifests" / "source-runtime-files.txt").read_text(
        encoding="utf-8"
    )
    server_manifest = (deploy / "manifests" / "server-runtime-files.txt").read_text(
        encoding="utf-8"
    )
    install = (deploy / "scripts" / "remote-install.sh").read_text(encoding="utf-8")
    deploy_script = (deploy / "scripts" / "deploy.ps1").read_text(encoding="utf-8")

    assert "/usr/bin/flock --nonblock" in service
    assert "TimeoutStartSec=60s" in service
    assert "EnvironmentFile=/etc/home-guardian/auth.env" in service
    assert "PathChanged=/srv/home-guardian/runtime/identity-research/wake" in path_unit
    assert "OnBootSec=2min" in timer
    assert "OnUnitInactiveSec=1min" in timer
    assert "backend/app/identity_research_worker.py" in source_manifest
    assert "backend/app/services/official_product_lookup.py" in source_manifest
    for name in (
        "home-guardian-identity-research.service",
        "home-guardian-identity-research.path",
        "home-guardian-identity-research.timer",
    ):
        assert f"deploy/systemd/{name}" in server_manifest
    assert "OPENAI_API_KEY must be omitted when identity research is disabled" not in install
    assert "HG_IDENTITY_AI_RESEARCH_ENABLED" in install
    assert "systemctl start \"${IDENTITY_RESEARCH_SERVICE_NAME}.service\"" in install
    assert "home-guardian-identity-research.path home-guardian-identity-research.timer" in install
    assert "managed_units=(home-guardian-api.service home-guardian-identity-research.service" in deploy_script
    assert "systemctl stop home-guardian-identity-research.path" in deploy_script

    enable_triggers = install.index(
        "sudo systemctl enable home-guardian-identity-research.path home-guardian-identity-research.timer"
    )
    restart_api = install.index('sudo systemctl restart "${SERVICE_NAME}.service"', enable_triggers)
    first_health = install.index("if ! verify_service_health; then", restart_api)
    identity_smoke = install.index(
        'sudo systemctl start "${IDENTITY_RESEARCH_SERVICE_NAME}.service"', first_health
    )
    start_triggers = install.index(
        "sudo systemctl start home-guardian-identity-research.path home-guardian-identity-research.timer",
        identity_smoke,
    )
    second_health = install.index(
        "verify_service_health || fail 'background trigger start disturbed API health'",
        start_triggers,
    )
    assert enable_triggers < restart_api < first_health < identity_smoke < start_triggers < second_health

    baseline_start = deploy_script.index('case "${old_enabled[${unit}]}" in')
    baseline_end = deploy_script.index("  esac", baseline_start)
    baseline_case = deploy_script[baseline_start:baseline_end]
    assert "enabled|enabled-runtime|disabled|static|indirect|not-found" in baseline_case
    for unsupported in ("masked", "masked-runtime", "linked", "linked-runtime", "alias"):
        assert unsupported not in baseline_case
    normalize_activating = deploy_script.index(
        "[ \"${current_active}\" = 'activating' ]"
    )
    stop_research_triggers = deploy_script.index(
        "sudo systemctl stop home-guardian-identity-research.path home-guardian-identity-research.timer"
    )
    quiesce_wait = deploy_script.index("for attempt in $(seq 1 65); do", stop_research_triggers)
    stop_api = deploy_script.index("sudo systemctl stop home-guardian-api.service", quiesce_wait)
    assert normalize_activating < stop_research_triggers < quiesce_wait < stop_api
