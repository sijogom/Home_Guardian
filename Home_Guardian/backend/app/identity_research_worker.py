from __future__ import annotations

import json
import hashlib
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .services.identity_research import (
    IdentityResearchOutcome,
    _eligible_job,
    identity_ai_research_enabled,
    identity_research_readiness,
    research_pending_identities,
)


_DEFAULT_WAKE_PATH = Path("/srv/home-guardian/runtime/identity-research/wake")
_GLOBAL_JOB_LIMIT = 200
_DEFAULT_CATALOG_RECONCILE_LIMIT = 200
_DEFAULT_BATCH_SIZE = 8
_DEFAULT_MAX_BATCHES = 8
_DEFAULT_RUNTIME_SECONDS = 45.0


OfficialLookup = Callable[..., Any]
AiResearch = Callable[..., IdentityResearchOutcome]


@dataclass(frozen=True)
class IdentityResearchWorkerOutcome:
    pending_seen: int
    homes_seen: int
    batches_processed: int
    claimed_count: int
    official_attempted_count: int
    official_resolved_count: int
    ai_attempted_count: int
    ai_resolved_count: int
    remaining_count: int
    deadline_reached: bool
    ai_enabled: bool
    ai_ready: bool


def _bounded_int(
    config: Mapping[str, str],
    key: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        value = int(str(config.get(key) or default).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _bounded_float(
    config: Mapping[str, str],
    key: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(str(config.get(key) or default).strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(value, maximum))


def _job_age_key(job: Mapping[str, Any]) -> tuple[int, str, str, str]:
    attempted = str(job.get("research_last_attempt_at") or "")
    first_seen = str(job.get("first_seen_at") or "")
    # Never-attempted homes sort before attempted homes.  ISO-8601 timestamps
    # preserve chronological order, and job_id is only an internal tie-breaker.
    return (
        0 if not attempted else 1,
        attempted or first_seen,
        first_seen,
        str(job.get("job_id") or ""),
    )


def _fair_home_ids(jobs: Sequence[Mapping[str, Any]]) -> list[str]:
    by_home: dict[str, list[Mapping[str, Any]]] = {}
    for job in jobs:
        home_id = str(job.get("home_id") or "").strip()
        if home_id:
            by_home.setdefault(home_id, []).append(job)
    return [
        home_id
        for home_id, _items in sorted(
            by_home.items(),
            key=lambda item: (min(_job_age_key(job) for job in item[1]), item[0]),
        )
    ]


def _due_home_ids(repository: Any, jobs: Sequence[Mapping[str, Any]]) -> list[str]:
    due_home_ids = getattr(repository, "identity_research_due_home_ids", None)
    if not callable(due_home_ids):
        return _fair_home_ids(jobs)
    result: list[str] = []
    seen: set[str] = set()
    offset = 0
    while True:
        try:
            raw_home_ids = due_home_ids(limit=_GLOBAL_JOB_LIMIT, offset=offset)
        except TypeError:
            # Compatibility for injected repositories that predate paging.
            raw_home_ids = due_home_ids(limit=_GLOBAL_JOB_LIMIT)
            offset = -1
        for raw in raw_home_ids:
            home_id = str(raw or "").strip()
            if home_id and home_id not in seen:
                seen.add(home_id)
                result.append(home_id)
        if offset < 0 or len(raw_home_ids) < _GLOBAL_JOB_LIMIT:
            break
        offset += len(raw_home_ids)
    return result


def _default_official_lookup(repository: Any, *, claimed_jobs: list[Mapping[str, Any]]) -> Any:
    from .services.official_product_lookup import lookup_claimed_official_products

    return lookup_claimed_official_products(
        repository,
        claimed_jobs,
    )


def _identity_research_policy_version() -> str:
    from .services.identity_enrichment import IDENTITY_ENRICHMENT_RESOLVER_VERSION
    from .services.official_product_lookup import official_product_lookup_policy_version

    payload = (
        f"{IDENTITY_ENRICHMENT_RESOLVER_VERSION}\0"
        f"{official_product_lookup_policy_version()}"
    ).encode("utf-8")
    return "identity-policy-v1-" + hashlib.sha256(payload).hexdigest()[:24]


def _claimable_job_ids(
    jobs: Sequence[Mapping[str, Any]],
    *,
    ai_ready: bool,
    use_default_official_lookup: bool,
) -> tuple[str, ...]:
    """Preflight both research engines before repository retry state changes."""

    if not use_default_official_lookup:
        # An injected test/maintenance resolver is its own capability contract.
        return tuple(
            dict.fromkeys(
                str(job.get("job_id") or "")
                for job in jobs
                if str(job.get("job_id") or "")
            )
        )

    from .services.official_product_lookup import eligible_official_product_job_ids

    try:
        official_ids = set(eligible_official_product_job_ids(jobs))
    except Exception:  # fail closed: invalid profiles must consume no job backoff
        official_ids = set()
    ai_ids = {
        str(job.get("job_id") or "")
        for job in jobs
        if ai_ready and _eligible_job(job) is not None
    }
    return tuple(
        job_id
        for job in jobs
        if (job_id := str(job.get("job_id") or ""))
        and job_id in official_ids | ai_ids
    )


def _claimable_due_job_ids(
    repository: Any,
    *,
    home_id: str,
    batch_size: int,
    ai_ready: bool,
    use_default_official_lookup: bool,
) -> tuple[str, ...]:
    due_jobs = getattr(repository, "identity_research_due_jobs", None)
    if not callable(due_jobs):
        pending = repository.identity_enrichment_jobs(
            status_filter="review_required",
            limit=_GLOBAL_JOB_LIMIT,
            home_id=home_id,
        )
        return _claimable_job_ids(
            pending,
            ai_ready=ai_ready,
            use_default_official_lookup=use_default_official_lookup,
        )[:batch_size]

    selected: list[str] = []
    seen: set[str] = set()
    offset = 0
    while len(selected) < batch_size:
        page = due_jobs(
            home_id=home_id,
            limit=_GLOBAL_JOB_LIMIT,
            offset=offset,
        )
        if not page:
            break
        for job_id in _claimable_job_ids(
            page,
            ai_ready=ai_ready,
            use_default_official_lookup=use_default_official_lookup,
        ):
            if job_id not in seen:
                seen.add(job_id)
                selected.append(job_id)
                if len(selected) >= batch_size:
                    break
        if len(page) < _GLOBAL_JOB_LIMIT:
            break
        offset += len(page)
    return tuple(selected)


def _still_pending_claimed_jobs(
    repository: Any,
    *,
    home_id: str,
    claimed_jobs: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    claimed_ids = {
        str(job.get("job_id") or "")
        for job in claimed_jobs
        if str(job.get("job_id") or "")
    }
    if not claimed_ids:
        return []
    current = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=_GLOBAL_JOB_LIMIT,
        home_id=home_id,
    )
    return [
        job
        for job in current
        if str(job.get("job_id") or "") in claimed_ids
    ]


def run_identity_research_worker(
    repository: Any,
    *,
    official_lookup: OfficialLookup | None = None,
    ai_research: AiResearch = research_pending_identities,
    environ: Mapping[str, str] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> IdentityResearchWorkerOutcome:
    """Process globally pending homes without exposing household identifiers.

    One persisted claim is shared by the deterministic official lookup and the
    optional AI fallback.  Repository claim/backoff remains the concurrency
    authority; systemd additionally serializes worker processes with ``flock``.
    """

    config = os.environ if environ is None else environ
    batch_size = _bounded_int(
        config,
        "HG_IDENTITY_RESEARCH_BATCH_SIZE",
        _DEFAULT_BATCH_SIZE,
        minimum=1,
        maximum=8,
    )
    max_batches = _bounded_int(
        config,
        "HG_IDENTITY_RESEARCH_MAX_BATCHES",
        _DEFAULT_MAX_BATCHES,
        minimum=1,
        maximum=32,
    )
    runtime_seconds = _bounded_float(
        config,
        "HG_IDENTITY_RESEARCH_RUNTIME_SECONDS",
        _DEFAULT_RUNTIME_SECONDS,
        minimum=1.0,
        maximum=50.0,
    )
    started_at = monotonic()
    deadline = started_at + runtime_seconds
    reconcile_limit = _bounded_int(
        config,
        "HG_IDENTITY_RESEARCH_RECONCILE_LIMIT",
        _DEFAULT_CATALOG_RECONCILE_LIMIT,
        minimum=1,
        maximum=2000,
    )
    reset_backoff = getattr(
        repository, "reset_identity_research_backoff_for_version", None
    )
    if callable(reset_backoff):
        try:
            reset_backoff(_identity_research_policy_version())
        except Exception:
            # A missing/invalid profile release must not erase prior backoff.
            pass
    reconcile_catalog = getattr(
        repository, "reconcile_verified_product_catalog_jobs", None
    )
    if callable(reconcile_catalog) and monotonic() < deadline:
        try:
            reconcile_catalog(
                limit=reconcile_limit,
                should_stop=lambda: monotonic() >= deadline,
            )
        except Exception:
            # Network research remains independently available; the catalog
            # reconciler is fail-closed and never mutates scan membership.
            pass
    pending_jobs = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=_GLOBAL_JOB_LIMIT,
    )
    home_ids = _due_home_ids(repository, pending_jobs)
    ai_enabled = identity_ai_research_enabled(config)
    ai_ready, _readiness_code = identity_research_readiness(config)
    ai_can_research = ai_enabled and ai_ready
    lookup = official_lookup or _default_official_lookup

    batches_processed = 0
    claimed_count = 0
    official_attempted_count = 0
    official_resolved_count = 0
    ai_attempted_count = 0
    ai_resolved_count = 0
    deadline_reached = False

    # Round-robin homes and revisit each one while it still has due work.  A
    # single academy/home can legitimately contribute dozens of distinct
    # devices; processing only one eight-job batch per timer tick would leave
    # an 84-device scan pending for many minutes despite available runtime.
    home_queue = list(home_ids)
    while home_queue:
        home_id = home_queue.pop(0)
        if batches_processed >= max_batches or monotonic() >= deadline:
            deadline_reached = monotonic() >= deadline
            break
        claimable_ids = _claimable_due_job_ids(
            repository,
            home_id=home_id,
            batch_size=batch_size,
            ai_ready=ai_can_research,
            use_default_official_lookup=official_lookup is None,
        )
        if not claimable_ids:
            continue
        claimed = repository.claim_identity_research_jobs(
            home_id=home_id,
            limit=batch_size,
            job_ids=claimable_ids,
        )
        if not claimed:
            continue
        batches_processed += 1
        claimed_count += len(claimed)

        try:
            official = lookup(repository, claimed_jobs=list(claimed))
            official_attempted_count += max(
                0, int(getattr(official, "attempted_count", 0) or 0)
            )
            official_resolved_count += max(
                0, int(getattr(official, "resolved_count", 0) or 0)
            )
        except Exception:  # noqa: BLE001 - keep jobs review_required; never log private evidence
            official = None

        unresolved = _still_pending_claimed_jobs(
            repository,
            home_id=home_id,
            claimed_jobs=claimed,
        )
        if not unresolved or not ai_enabled or not ai_ready or monotonic() >= deadline:
            if unresolved and monotonic() >= deadline:
                deadline_reached = True
        else:
            try:
                ai = ai_research(
                    repository,
                    home_id=home_id,
                    environ=config,
                    claimed_jobs=list(unresolved),
                )
                ai_attempted_count += max(0, int(ai.attempted_count or 0))
                ai_resolved_count += max(0, int(ai.resolved_count or 0))
            except Exception:  # noqa: BLE001 - fail closed without printing secrets/evidence
                pass
        # Requeue behind all other homes.  The repository's due/backoff query
        # is authoritative: once this home has no more due rows, the next
        # claim returns an empty list and it is not queued again.
        if (
            len(claimed) >= batch_size
            and not deadline_reached
            and batches_processed < max_batches
        ):
            home_queue.append(home_id)

    remaining = repository.identity_enrichment_jobs(
        status_filter="review_required",
        limit=_GLOBAL_JOB_LIMIT,
    )
    return IdentityResearchWorkerOutcome(
        pending_seen=len(pending_jobs),
        homes_seen=len(home_ids),
        batches_processed=batches_processed,
        claimed_count=claimed_count,
        official_attempted_count=official_attempted_count,
        official_resolved_count=official_resolved_count,
        ai_attempted_count=ai_attempted_count,
        ai_resolved_count=ai_resolved_count,
        remaining_count=len(remaining),
        deadline_reached=deadline_reached,
        ai_enabled=ai_enabled,
        ai_ready=ai_ready,
    )


def identity_research_wake_path(environ: Mapping[str, str] | None = None) -> Path | None:
    config = os.environ if environ is None else environ
    configured = str(config.get("HG_IDENTITY_RESEARCH_WAKE_PATH") or "").strip()
    if configured:
        path = Path(configured)
    elif str(config.get("HG_RUNTIME_ENV") or "").strip().casefold() == "production":
        path = _DEFAULT_WAKE_PATH
    else:
        return None
    return path if path.is_absolute() else None


def wake_identity_research_worker(environ: Mapping[str, str] | None = None) -> bool:
    """Touch a zero-content wake marker; never serialize LAN or account data."""

    path = identity_research_wake_path(environ)
    if path is None or not path.parent.is_dir() or path.is_symlink():
        return False
    flags = os.O_WRONLY | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o640)
    try:
        os.ftruncate(descriptor, 0)
    finally:
        os.close(descriptor)
    try:
        os.utime(path, None, follow_symlinks=False)
    except NotImplementedError:
        # Windows test hosts do not expose follow_symlinks for utime.  The
        # descriptor was already opened with O_NOFOLLOW where available.
        if path.is_symlink():
            return False
        os.utime(path, None)
    return True


def _main() -> int:
    if sys.argv[1:] == ["--check"]:
        from .storage import repository

        required = (
            "identity_enrichment_jobs",
            "claim_identity_research_jobs",
            "resolve_identity_enrichment_job",
        )
        return 0 if all(callable(getattr(repository, name, None)) for name in required) else 2
    if sys.argv[1:]:
        return 2
    from .storage import repository

    outcome = run_identity_research_worker(repository)
    # Only aggregate counts and configuration booleans enter the journal.
    print(json.dumps(asdict(outcome), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "IdentityResearchWorkerOutcome",
    "identity_research_wake_path",
    "run_identity_research_worker",
    "wake_identity_research_worker",
]
