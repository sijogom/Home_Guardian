"""Shared, isolated backend-test environment.

This module is imported by pytest before any test module imports the FastAPI
application.  Keeping the database and test-only authentication settings here
prevents collection order from selecting the developer database by accident.
"""

import os
import hashlib
import inspect
from pathlib import Path

import pytest


TEST_DB_PATH = Path(__file__).resolve().parents[2] / ".tmp" / "home_guardian_test.sqlite3"
TEST_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
if TEST_DB_PATH.exists():
    TEST_DB_PATH.unlink()

# Force the local SQLite fixture even when a developer shell contains a server
# DATABASE_URL.  Individual tests may monkeypatch these values temporarily.
os.environ["DATABASE_URL"] = ""
os.environ["HOME_GUARDIAN_DB_PATH"] = str(TEST_DB_PATH)
os.environ["HG_AUTH_TOKEN_SECRET"] = "test-only-home-guardian-auth-secret-at-least-32-characters"
os.environ["GOOGLE_CLIENT_ID"] = "123456789012-backendtest.apps.googleusercontent.com"
os.environ["HG_IDENTITY_RESEARCH_ENABLED"] = "1"
os.environ["OPENAI_API_KEY"] = "sk-test-only-identity-research-key-000000"
os.environ["HG_IDENTITY_RESEARCH_MODEL"] = "gpt-5-mini"


def bind_repository_home(repo, home_id: str):
    """Provision and bind one explicit owner scope for repository unit tests."""

    owner_key = hashlib.sha256(home_id.encode("utf-8")).hexdigest()[:16]
    repo.upsert_user(
        {
            "user_id": f"repository-fixture-owner-{owner_key}",
            "email": f"{owner_key}@repository-fixture.invalid",
            "nickname": f"저장소 테스트 사용자 {owner_key[:6]}",
            "role": "user",
            "email_verified": True,
            "home_id": home_id,
        }
    )
    for name in dir(repo):
        method = getattr(repo, name)
        if not callable(method):
            continue
        try:
            signature = inspect.signature(method)
        except (TypeError, ValueError):
            continue
        if "home_id" not in signature.parameters:
            continue

        def scoped(*args, __method=method, __signature=signature, **kwargs):
            bound = __signature.bind_partial(*args, **kwargs)
            if "home_id" not in bound.arguments:
                kwargs["home_id"] = home_id
            return __method(*args, **kwargs)

        setattr(repo, name, scoped)
    return repo


@pytest.fixture(autouse=True)
def block_external_identity_research_in_api_tests(monkeypatch):
    """Keep the full suite offline; direct service tests inject their transport."""

    from app.services.identity_research import IdentityResearchOutcome

    def offline_api_research(repo, *, home_id: str):
        pending = len(
            repo.identity_enrichment_jobs(
                status_filter="review_required",
                limit=200,
                home_id=home_id,
            )
        )
        return IdentityResearchOutcome(
            enabled=True,
            eligible_count=0,
            attempted_count=0,
            resolved_count=0,
            pending_count=pending,
        )

    monkeypatch.setattr("app.main.research_pending_identities", offline_api_research)
