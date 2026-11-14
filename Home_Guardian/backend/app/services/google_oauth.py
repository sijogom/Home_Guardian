"""Google OAuth ID token 검증.

운영 모드(기본): ``GOOGLE_CLIENT_ID`` 환경변수가 설정되어 있고 모바일이 보낸 ``id_token``
이 그 client_id 로 발급된 것이면 사용자 메타(email, name, sub)를 반환.
검증 실패하면 ``ValueError`` 를 발생시키고, 호출자는 401 로 응답한다.

테스트에서는 이 함수 자체를 monkeypatch한다. 실제 런타임에는 토큰 검증을
우회하거나 빈 사용자를 반환하는 대체 인증 경로가 없다.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


_GOOGLE_CLIENT_ID_PATTERN = re.compile(
    r"^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$"
)


@dataclass
class GoogleOAuthResult:
    user: dict[str, Any]
    provider: str
    mode: str
    raw_claims: dict[str, Any] | None


def _verify_id_token(id_token_value: str, client_id: str) -> dict[str, Any] | None:
    try:
        from google.oauth2 import id_token  # type: ignore[import-not-found]
        from google.auth.transport import requests as google_requests  # type: ignore[import-not-found]
    except Exception:
        return None
    try:
        return id_token.verify_oauth2_token(id_token_value, google_requests.Request(), client_id)
    except Exception:
        return None


def google_client_id() -> str:
    """Return the configured OAuth client id only when its basic shape is valid."""

    configured = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    if not configured:
        raise ValueError("GOOGLE_CLIENT_ID 환경변수가 필요합니다.")
    if len(configured) > 512 or _GOOGLE_CLIENT_ID_PATTERN.fullmatch(configured) is None:
        raise ValueError("GOOGLE_CLIENT_ID 형식이 올바르지 않습니다.")
    return configured


def authenticate(code: str | None, id_token_value: str | None, redirect_uri: str | None) -> GoogleOAuthResult:
    """Google 로그인 검증. 실제 검증 성공 시에만 사용자 메타를 반환한다.

    실패 시 ``ValueError`` 발생. 운영 환경에서는 호출자가 401 로 응답해야 한다.
    """
    _ = redirect_uri  # 검증에는 사용하지 않음 (감사 로그 등 외부 용도용)
    _ = code

    client_id = google_client_id()
    if not id_token_value:
        raise ValueError("Google id_token 이 필요합니다.")
    claims = _verify_id_token(id_token_value, client_id)
    if not claims or claims.get("aud") != client_id:
        raise ValueError("Google ID token 검증에 실패했습니다.")
    subject = str(claims.get("sub") or "").strip()
    email = str(claims.get("email") or "").strip().lower()
    if not subject or not email or claims.get("email_verified") is not True:
        raise ValueError("Google 계정 식별 정보가 부족합니다.")
    return GoogleOAuthResult(
        user={
            "user_id": subject,
            "email": email,
            "nickname": str(claims.get("name") or claims.get("given_name") or email),
            "role": "user",
            "email_verified": True,
            "home_id": "",
        },
        provider="google",
        mode="oauth",
        raw_claims=claims,
    )
