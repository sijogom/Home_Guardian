import pytest

from app.services import google_oauth
from app.services.google_oauth import authenticate


VALID_CLIENT_ID = "123456789012-googleoauthunit.apps.googleusercontent.com"


def test_google_auth_returns_verified_claims(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", VALID_CLIENT_ID)

    def verified(token, audience):
        assert token == "signed-id-token"
        assert audience == VALID_CLIENT_ID
        return {
            "aud": VALID_CLIENT_ID,
            "sub": "google-subject-1",
            "email": "Owner@Example.com",
            "email_verified": True,
        }

    monkeypatch.setattr(google_oauth, "_verify_id_token", verified)

    result = authenticate(code=None, id_token_value="signed-id-token", redirect_uri=None)

    assert result.provider == "google"
    assert result.mode == "oauth"
    assert result.user == {
        "user_id": "google-subject-1",
        "email": "owner@example.com",
        "nickname": "owner@example.com",
        "role": "user",
        "email_verified": True,
        "home_id": "",
    }


@pytest.mark.parametrize(
    "claims",
    [
        None,
        {"aud": "987654321098-wrong.apps.googleusercontent.com", "sub": "subject", "email": "x@example.com", "email_verified": True},
        {"aud": VALID_CLIENT_ID, "sub": "subject", "email": "x@example.com", "email_verified": False},
    ],
)
def test_google_auth_rejects_unverified_or_wrong_audience_claims(monkeypatch, claims):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", VALID_CLIENT_ID)
    monkeypatch.setattr(google_oauth, "_verify_id_token", lambda _token, _audience: claims)

    with pytest.raises(ValueError):
        authenticate(code=None, id_token_value="signed-id-token", redirect_uri=None)


def test_google_auth_rejects_malformed_client_id_before_token_verification(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "malformed client id")
    monkeypatch.setattr(
        google_oauth,
        "_verify_id_token",
        lambda *_args: pytest.fail("malformed configuration must fail before verification"),
    )

    with pytest.raises(ValueError, match="GOOGLE_CLIENT_ID"):
        authenticate(code=None, id_token_value="signed-id-token", redirect_uri=None)


def test_google_auth_has_no_development_fallback(monkeypatch):
    """No environment flag can bypass Google verification."""
    monkeypatch.delenv("GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.setenv("ALLOW_DEV_GOOGLE_OAUTH", "1")
    # No runtime marker is deliberately treated as production as well.
    monkeypatch.delenv("HG_RUNTIME_ENV", raising=False)

    with pytest.raises(ValueError, match="GOOGLE_CLIENT_ID"):
        authenticate(code=None, id_token_value=None, redirect_uri=None)

    monkeypatch.setenv("HG_RUNTIME_ENV", "test")
    with pytest.raises(ValueError, match="GOOGLE_CLIENT_ID"):
        authenticate(code=None, id_token_value=None, redirect_uri=None)
