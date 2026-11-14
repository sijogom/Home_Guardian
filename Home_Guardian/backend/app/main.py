from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Mapping

import logging

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .api_response import error_response, success_response
from .scan_validation import (
    actual_android_scan_rejection_reasons,
    enforce_declared_subnet_boundary,
    scan_coverage_complete,
    scan_is_partial,
    strip_untrusted_self_claims,
)
from .services import fcm as fcm_service
from .services import google_oauth as google_oauth_service
from .services.cve_matcher import get_matcher as get_cve_matcher
from .services.device_presentation import (
    apply_device_presentation,
    build_public_detected_connections,
    is_safe_device_alias,
    public_device_id,
    sanitize_public_notification,
    sanitize_public_network_context,
    sanitize_public_payload,
    project_public_identity_history,
)
from .services.identity_enrichment import (
    IdentityEnrichmentError,
    authenticated_self_android_evidence,
    project_identity_enrichment_job,
)
from .services.identity_research import research_pending_identities
from .services.server_protocol_probe import augment_android_observations
from .identity_research_worker import wake_identity_research_worker
from .storage import repository
from .storage.constants import default_home_id_for_user
from .storage.guardian_invites import (
    guardian_invite_summary,
)
from .storage.scoring_helpers import (
    SCORE_CALCULATION_FAILED_MESSAGE,
    confirmed_public_red_count,
    public_score_calculation_failed,
)
from .storage.scan_state import hold_partial_security, project_partial_security

_ML_PATH = Path(__file__).resolve().parents[2] / "ml"
if str(_ML_PATH) not in sys.path:
    sys.path.append(str(_ML_PATH))

from home_guardian_ml.hybrid_scoring import ml_model_metrics  # noqa: E402
from home_guardian_ml.ml_predictor import device_feature_vector, predict_attack_probability  # noqa: E402

API_PREFIX = "/api/v1"
AUTH_HEADER = "authorization"
IDENTITY_REVIEW_HEADER = "x-home-guardian-identity-review-secret"
GUARDIAN_LOOKUP_WINDOW_SECONDS = 5 * 60
GUARDIAN_LOOKUP_MAX_FAILURES = 8
_guardian_lookup_failures: dict[str, list[float]] = {}

# 보안: 운영에선 Swagger/openapi 자동 문서를 노출하지 않는다(공격 표면 매핑 방지). secure-by-default —
# 기본 비활성, 개발 시 HG_ENABLE_DOCS=1 로만 켠다. 서버 env 변경 없이 배포만으로 운영 문서가 닫힌다.
_DOCS_ENABLED = os.environ.get("HG_ENABLE_DOCS", "0") == "1"

app = FastAPI(
    title="Home Guardian API",
    version="1.0.0",
    description=(
        "디지털 취약계층 대상 스마트홈 IoT 보안 점검 백엔드 API. "
        "Android 앱이 같은 공유기 Wi-Fi 안에서 탐색한 결과를 받아 위험 점수와 조치 안내를 반환한다."
    ),
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    # 인증은 Authorization Bearer 헤더 기반이고 쿠키를 쓰지 않으므로
    # allow_credentials 는 불필요하다. allow_origins="*" 와 allow_credentials=True 조합은
    # Starlette 가 요청 origin 을 반사해 모든 출처에 credentials 를 허용하는 보안 안티패턴이라 False 로 둔다.
    # (모바일 클라이언트는 CORS 를 적용받지 않으므로 영향 없음.)
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GoogleCallbackRequest(BaseModel):
    # Android type OAuth client 의 id_token 직접 검증 흐름에서는 클라이언트가 code 를
    # 백엔드로 전달하지 않는다 (PKCE code → id_token 교환을 클라이언트가 수행 후 id_token 만 전송).
    # 따라서 code 는 optional 이며, 실제 인증 검증은 google_oauth.authenticate 가 담당한다.
    # 길이 경계(보안): OAuth 값은 실제로 짧다(code 수백 자, id_token JWT 1~2KB, redirect_uri URL).
    # 거대 입력으로 검증 전 메모리를 낭비하지 않게 넉넉히 제한한다.
    code: str | None = Field(default=None, max_length=4096)
    id_token: str | None = Field(default=None, max_length=8192)
    redirect_uri: str | None = Field(default=None, max_length=2048)
    role: str = Field(default="user", pattern="^(user|guardian)$")
    # A role change proves possession of the currently active local refresh
    # token.  The callback does *not* revoke it: it stages a short-lived
    # successor that must be completed with possession of both refresh tokens.
    # The raw value is accepted only for this request and is immediately
    # HMAC-hashed; neither the raw value nor its hash is returned or logged.
    previous_refresh_token: str | None = Field(default=None, min_length=32, max_length=512)


class RefreshSessionRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)
    # The mobile client persists this non-secret idempotency key before sending a
    # refresh request.  It lets a retry recover the same rotated token if the
    # server committed the rotation but the response was lost.
    refresh_attempt_id: str | None = Field(default=None, min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=512)


class IdentityEnrichmentResolveRequest(BaseModel):
    manufacturer: str = Field(min_length=1, max_length=96)
    device_type: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=96)
    source_reference: str = Field(min_length=8, max_length=512)


class IdentityEnrichmentRejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=64)


class AuthHandoffCompleteRequest(BaseModel):
    """Proof required to activate a staged Google role successor.

    All three fields are high-entropy values.  The repository retains only
    keyed HMAC values for them, so a database read cannot be used to finish a
    handoff or refresh a session.
    """

    previous_refresh_token: str = Field(min_length=32, max_length=512)
    successor_refresh_token: str = Field(min_length=32, max_length=512)
    handoff_id: str = Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class DiscoveredDeviceRequest(BaseModel):
    # 입력 경계: 스캔 페이로드는 인증된 클라이언트(앱)에서 오지만, 악의적 앱/MITM 의 거대 입력으로
    # 메모리·저장·UI 가 망가지지 않도록 길이를 제한한다. 한도는 네이티브 실출력(/24 최대 254 기기,
    # 기기당 fingerprint 수십 개, 필드 수십 자)보다 넉넉히 잡아 정상 스캔은 거부되지 않는다.
    device_id: str | None = Field(default=None, max_length=256)
    name: str | None = Field(default=None, max_length=512)
    device_type: str | None = Field(default=None, max_length=64)
    manufacturer: str | None = Field(default=None, max_length=256)
    model: str | None = Field(default=None, max_length=256)
    ip_address: str = Field(max_length=64)
    mac_address: str | None = Field(default=None, max_length=64)
    online: bool = True
    last_seen: str | None = Field(default=None, max_length=64)
    open_ports: list[int] = Field(default_factory=list, max_length=512)
    services: list[str] = Field(default_factory=list, max_length=512)
    default_credentials: bool = False
    encryption: str = Field(default="unknown", max_length=64)
    firmware: str = Field(default="unknown", max_length=256)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    discovery_sources: list[str] = Field(default_factory=list, max_length=64)
    fingerprints: list[str] = Field(default_factory=list, max_length=512)
    risk_signals: list[str] = Field(default_factory=list, max_length=64)
    confidence: float = Field(default=0.65, ge=0, le=1)


class ScanRequest(BaseModel):
    scan_profile: str = Field(default="quick", pattern="^(quick|standard)$")
    scan_source: Literal["android-native"] = "android-native"
    network_context: dict[str, Any]
    # 한 스캔의 기기 수 상한(네이티브 /24 최대 254 보다 넉넉). 거대 페이로드 메모리 DoS 방지.
    devices: list[DiscoveredDeviceRequest] = Field(max_length=512)


class GuardianInviteRequest(BaseModel):
    email: str
    relation: str = Field(default="보호자", min_length=1, max_length=20)
    ward_name: str | None = Field(default=None, max_length=80)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return validate_email_text(value)

    @field_validator("ward_name")
    @classmethod
    def normalize_ward_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = " ".join(value.strip().split())
        return text or None


class GuardianLinkAcceptRequest(BaseModel):
    invite: str = Field(min_length=1, max_length=128)
    # The explicit account selector must exactly match the authenticated Bearer
    # session. Request data never creates or substitutes a guardian identity.
    guardian_id: str | None = Field(default=None, min_length=1, max_length=160)


class GuardianWardAliasRequest(BaseModel):
    guardian_id: str = Field(min_length=1, max_length=160)
    ward_alias: str | None = Field(default=None, max_length=80)

    @field_validator("ward_alias")
    @classmethod
    def normalize_ward_alias(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return " ".join(value.strip().split())


class DeviceAliasRequest(BaseModel):
    alias: str | None = Field(default=None, max_length=80)

    @field_validator("alias")
    @classmethod
    def normalize_alias(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = " ".join(value.strip().split())
        if text and not is_safe_device_alias(text):
            raise ValueError("확인된 기기 이름을 입력해 주세요.")
        return text or None


class FcmTokenRequest(BaseModel):
    fcm_token: str = Field(min_length=1, max_length=4096)
    platform: str = Field(pattern="^(android|ios)$")


class DeleteFcmTokenRequest(BaseModel):
    fcm_token: str = Field(min_length=1, max_length=4096)


class MlPredictRequest(BaseModel):
    # 길이 경계(보안): scan 입력과 동일 원리로 거대 페이로드 DoS 를 막는다.
    open_ports: list[int] = Field(default_factory=list, max_length=512)
    services: list[str] = Field(default_factory=list, max_length=512)
    risk_signals: list[str] = Field(default_factory=list, max_length=64)
    device_type: str | None = Field(default=None, max_length=64)
    default_credentials: bool = False
    encryption: str = Field(default="unknown", max_length=64)


@dataclass(frozen=True)
class HomeScope:
    user_id: str
    home_id: str
    role: str = "user"


# 토큰 서명 시크릿은 절대 소스/문서에 노출하지 않는다. 운영(라즈베리파이)은 반드시 systemd
# drop-in 에 HG_AUTH_TOKEN_SECRET(충분히 긴 무작위 값)을 설정한다.
# 환경과 관계없이 이 값이 없으면 준비 상태가 되지 않는다.
ACCESS_TOKEN_TTL_SECONDS = int(os.environ.get("HG_ACCESS_TOKEN_TTL_SECONDS", "900"))
REFRESH_TOKEN_TTL_DAYS = int(os.environ.get("HG_REFRESH_TOKEN_TTL_DAYS", "30"))
REFRESH_RESPONSE_RECOVERY_SECONDS = int(os.environ.get("HG_REFRESH_RESPONSE_RECOVERY_SECONDS", "600"))
# A staged role successor is deliberately short lived.  It is not an active
# session until its predecessor, successor and one-time handoff id are all
# presented to /auth/handoff/complete.
AUTH_HANDOFF_TTL_SECONDS = int(os.environ.get("HG_AUTH_HANDOFF_TTL_SECONDS", "600"))


def auth_token_secret() -> bytes:
    configured = os.environ.get("HG_AUTH_TOKEN_SECRET", "").strip()
    if configured:
        if len(configured) < 32:
            raise RuntimeError("HG_AUTH_TOKEN_SECRET must be at least 32 characters")
        return configured.encode("utf-8")
    raise RuntimeError("HG_AUTH_TOKEN_SECRET is required")


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _session_expiry(days: int = REFRESH_TOKEN_TTL_DAYS) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat().replace("+00:00", "Z")


def _parse_utc(value: object) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError):
        return None


def _refresh_token_hash(refresh_token: str) -> str:
    return hmac.new(auth_token_secret(), refresh_token.encode("utf-8"), hashlib.sha256).hexdigest()


def _refresh_response_recovery_expiry() -> str:
    return (datetime.now(UTC) + timedelta(seconds=REFRESH_RESPONSE_RECOVERY_SECONDS)).isoformat().replace("+00:00", "Z")


def _auth_handoff_expiry() -> str:
    return (datetime.now(UTC) + timedelta(seconds=AUTH_HANDOFF_TTL_SECONDS)).isoformat().replace("+00:00", "Z")


def _derive_rotated_refresh_token(previous_refresh_token: str, refresh_attempt_id: str) -> str:
    """Derive a retryable successor without persisting any raw refresh token.

    The current request supplies the old token; the database contains only its
    HMAC hash, the idempotency key, and the successor hash.  A retry with the
    same key can therefore recreate exactly one successor after response loss.
    """
    material = b"home-guardian-refresh-rotation-v1\0" + previous_refresh_token.encode("utf-8") + b"\0" + refresh_attempt_id.encode("ascii")
    return _b64url_encode(hmac.new(auth_token_secret(), material, hashlib.sha512).digest())


def _scope_from_user(user: dict[str, Any]) -> HomeScope:
    user_id = str(user.get("user_id") or "").strip()
    role = str(user.get("role") or "user").strip() or "user"
    if role not in {"user", "guardian"}:
        raise ValueError("unsupported role")
    home_id = "" if role == "guardian" else str(user.get("home_id") or "").strip()
    if not user_id or (role == "user" and not home_id):
        raise ValueError("invalid session scope")
    return HomeScope(user_id=user_id, home_id=home_id, role=role)


def issue_access_token(scope: HomeScope, session_id: str) -> str:
    now = int(time.time())
    payload = {
        "user_id": scope.user_id,
        "home_id": scope.home_id,
        "role": scope.role,
        "sid": session_id,
        "iat": now,
        "jti": secrets.token_urlsafe(12),
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    encoded_payload = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = _b64url_encode(hmac.new(auth_token_secret(), encoded_payload.encode("ascii"), hashlib.sha256).digest())
    return f"hg.{encoded_payload}.{signature}"


def issue_token_pair(user: dict[str, Any]) -> dict[str, Any]:
    """Create one immediately active session for a first/direct login.

    Role replacement never calls this helper with a predecessor.  Replacing a
    valid role session is a two-phase handoff so a lost callback response can
    never log the person out of their working session.
    """
    scope = _scope_from_user(user)
    session_id = f"session-{secrets.token_urlsafe(24)}"
    refresh_token = secrets.token_urlsafe(48)
    repository.create_auth_session(
        session_id=session_id,
        user_id=scope.user_id,
        home_id=scope.home_id,
        role=scope.role,
        refresh_token_hash=_refresh_token_hash(refresh_token),
        expires_at=_session_expiry(),
    )
    return {
        "access_token": issue_access_token(scope, session_id),
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
    }


def issue_pending_auth_handoff_pair(
    user: dict[str, Any],
    *,
    predecessor_session: dict[str, Any],
    predecessor_refresh_token_hash: str,
) -> dict[str, Any]:
    """Stage, but do not activate, a Google-authenticated replacement role.

    The candidate's access token is intentionally unusable while the database
    row is ``pending``.  The mobile app stores both raw refresh values and the
    opaque handoff id only in SecureStore, then completes the handoff.  The
    repository receives HMAC values only and keeps old/new activation in one
    transaction.
    """
    scope = _scope_from_user(user)
    session_id = f"session-{secrets.token_urlsafe(24)}"
    refresh_token = secrets.token_urlsafe(48)
    handoff_id = secrets.token_urlsafe(48)
    handoff_expires_at = _auth_handoff_expiry()
    repository.create_auth_session(
        session_id=session_id,
        user_id=scope.user_id,
        home_id=scope.home_id,
        role=scope.role,
        refresh_token_hash=_refresh_token_hash(refresh_token),
        expires_at=_session_expiry(),
        activation_state="pending",
        handoff_predecessor_session_id=str(predecessor_session["session_id"]),
        handoff_predecessor_refresh_token_hash=predecessor_refresh_token_hash,
        handoff_id_hash=_refresh_token_hash(handoff_id),
        handoff_expires_at=handoff_expires_at,
    )
    return {
        "access_token": issue_access_token(scope, session_id),
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "handoff": {
            "id": handoff_id,
            "expires_at": handoff_expires_at,
        },
    }


def _active_session_scope(session: dict[str, Any] | None) -> HomeScope | None:
    if not session or session.get("revoked_at") or str(session.get("activation_state") or "active") != "active":
        return None
    expires_at = _parse_utc(session.get("expires_at"))
    if expires_at is None or expires_at <= datetime.now(UTC):
        return None
    try:
        scope = _scope_from_user(session)
    except ValueError:
        return None
    if scope.role == "user":
        principal = repository.user_by_id(scope.user_id)
        if principal is None:
            return None
        principal_email = str(principal.get("email") or "").strip().lower()
        principal_name = str(principal.get("nickname") or "").strip()
        if (
            not principal_email
            or not principal_name
            or str(principal.get("role") or "user") != "user"
            or str(principal.get("home_id") or "").strip() != scope.home_id
        ):
            return None
        try:
            home = repository.home(home_id=scope.home_id)
        except (KeyError, ValueError):
            return None
        if str(home.get("home_id") or "").strip() != scope.home_id:
            return None
        return scope

    guardian = repository.guardian_account_by_id(scope.user_id)
    if (
        guardian is None
        or not str(guardian.get("email") or "").strip()
        or not str(guardian.get("display_name") or "").strip()
        or str(guardian.get("provider") or "").strip().lower() != "google"
    ):
        return None
    return scope


def _recover_refresh_rotation(
    body: RefreshSessionRequest,
    previous_refresh_token_hash: str,
) -> tuple[HomeScope, dict[str, Any], str] | None:
    """Return the deterministic successor for a committed, retried rotation."""
    if not body.refresh_attempt_id:
        return None
    session = repository.auth_session_by_previous_refresh_hash(previous_refresh_token_hash)
    scope = _active_session_scope(session)
    retry_until = _parse_utc((session or {}).get("refresh_retry_until"))
    if scope is None or session is None or retry_until is None or retry_until <= datetime.now(UTC):
        return None
    stored_attempt_id = str(session.get("refresh_retry_id") or "")
    if not hmac.compare_digest(stored_attempt_id, body.refresh_attempt_id):
        return None
    next_refresh_token = _derive_rotated_refresh_token(body.refresh_token, body.refresh_attempt_id)
    next_refresh_token_hash = _refresh_token_hash(next_refresh_token)
    if not hmac.compare_digest(next_refresh_token_hash, str(session.get("refresh_token_hash") or "")):
        return None
    if not repository.recover_auth_session_rotation(
        session_id=str(session["session_id"]),
        previous_refresh_token_hash=previous_refresh_token_hash,
        refresh_retry_id=body.refresh_attempt_id,
        refresh_token_hash=next_refresh_token_hash,
    ):
        return None
    return scope, session, next_refresh_token


def scope_from_access_token(token: str) -> HomeScope | None:
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != "hg":
        return None
    _, encoded_payload, signature = parts
    expected = _b64url_encode(hmac.new(auth_token_secret(), encoded_payload.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
    except Exception:
        return None
    try:
        expires_at = int(payload.get("exp"))
    except (TypeError, ValueError):
        return None
    if expires_at <= int(time.time()):
        return None
    session_id = str(payload.get("sid") or "").strip()
    session = repository.auth_session_by_id(session_id) if session_id else None
    scope = _active_session_scope(session)
    if scope is None:
        return None
    if (
        str(payload.get("user_id") or "") != scope.user_id
        or str(payload.get("home_id") or "") != scope.home_id
        or str(payload.get("role") or "") != scope.role
    ):
        return None
    return scope


def require_home_scope(request: Request) -> HomeScope:
    auth_header = request.headers.get(AUTH_HEADER, "").strip()
    if auth_header.lower().startswith("bearer "):
        scope = scope_from_access_token(auth_header[7:].strip())
        if scope and scope.role != "guardian" and scope.home_id:
            return scope
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "AUTH_REQUIRED", "message": "로그인이 필요한 요청입니다."},
    )


def require_guardian_scope(request: Request, guardian_id: str | None) -> HomeScope:
    auth_header = request.headers.get(AUTH_HEADER, "").strip()
    if auth_header.lower().startswith("bearer "):
        scope = scope_from_access_token(auth_header[7:].strip())
        if scope and scope.role == "guardian" and (guardian_id is None or scope.user_id == guardian_id):
            return scope
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "GUARDIAN_AUTH_REQUIRED", "message": "보호자 Google 로그인이 먼저 필요합니다."},
    )


def validate_email_text(value: str) -> str:
    # 길이 경계(보안): 이메일은 DB 저장·표시로 흐르므로 거대 입력을 막는다. RFC 5321 의 실질 상한 254 자.
    if len(value) > 254:
        raise ValueError("올바른 이메일 주소를 입력해 주세요.")
    if "@" not in value or "." not in value.rsplit("@", 1)[-1]:
        raise ValueError("올바른 이메일 주소를 입력해 주세요.")
    return value


def guardian_lookup_rate_key(request: Request) -> str:
    client_host = request.client.host if request.client else "unknown"
    # X-Forwarded-For is client-controlled unless this process is reached
    # through an explicitly trusted reverse proxy. Trusting it unconditionally
    # lets a direct caller evade the invitation-code rate limit by changing the
    # header for each request.
    trusted_proxy_hosts = {
        host.strip()
        for host in os.environ.get("HG_TRUSTED_PROXY_HOSTS", "").split(",")
        if host.strip()
    }
    if client_host not in trusted_proxy_hosts:
        return client_host

    # nginx overwrites X-Real-IP with $remote_addr. Do not use
    # X-Forwarded-For here: the standard append form can retain a client
    # supplied first value even when nginx itself is trusted.
    real_ip = request.headers.get("x-real-ip", "").strip()
    return real_ip or client_host


def _canonical_ip_address(value: object) -> str | None:
    """Return one canonical IP address without resolving host names."""
    try:
        parsed = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(parsed)


def _canonical_ipv4_address(value: object) -> str | None:
    canonical = _canonical_ip_address(value)
    if canonical is None:
        return None
    parsed = ipaddress.ip_address(canonical)
    return canonical if isinstance(parsed, ipaddress.IPv4Address) else None


def trusted_scan_client_ip(request: Request) -> str | None:
    """Derive the scan caller address without trusting client-set headers.

    A direct Android request is authoritative only when it supplies no proxy
    headers.  When the direct peer is an explicitly configured reverse proxy,
    the production nginx contract overwrites both ``X-Real-IP`` and
    ``X-Forwarded-For`` with the same immediate client address.  Requiring the
    two canonical values to agree prevents a retained or spoofed forwarding
    chain from being promoted into same-LAN identity proof.
    """

    client = getattr(request, "client", None)
    direct_host = _canonical_ip_address(getattr(client, "host", None))
    headers = getattr(request, "headers", None)
    if direct_host is None or headers is None:
        return None
    if str(headers.get("forwarded", "")).strip():
        return None

    real_ip_raw = str(headers.get("x-real-ip", "")).strip()
    forwarded_for_raw = str(headers.get("x-forwarded-for", "")).strip()
    trusted_proxy_hosts = {
        canonical
        for raw_host in os.environ.get("HG_TRUSTED_PROXY_HOSTS", "").split(",")
        if (canonical := _canonical_ip_address(raw_host)) is not None
    }
    if direct_host not in trusted_proxy_hosts:
        # A direct caller has no legitimate reason to send reverse-proxy
        # identity headers.  Do not merely ignore them: withhold the stronger
        # current-self attestation path for this request.
        if real_ip_raw or forwarded_for_raw:
            return None
        return _canonical_ipv4_address(direct_host)

    if not real_ip_raw or not forwarded_for_raw or "," in forwarded_for_raw:
        return None
    real_ip = _canonical_ipv4_address(real_ip_raw)
    forwarded_for = _canonical_ipv4_address(forwarded_for_raw)
    if real_ip is None or forwarded_for is None or real_ip != forwarded_for:
        return None
    return real_ip


def _identity_review_request_is_local(request: Request) -> bool:
    """Fail closed unless every observable hop identifies a loopback caller.

    The production nginx forwards ``/api/v1`` to this process over loopback, so
    checking ``request.client`` alone would mistake every proxied internet
    request for a local operator.  nginx overwrites ``X-Real-IP`` and appends
    the actual peer to ``X-Forwarded-For``; requiring all supplied addresses to
    be loopback also makes client-supplied prefix values harmless.  An RFC 7239
    ``Forwarded`` header is not part of the deployment contract and is rejected
    instead of being parsed permissively.
    """

    if request.headers.get("forwarded", "").strip() or request.client is None:
        return False
    addresses = [request.client.host]
    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip:
        addresses.append(real_ip)
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        addresses.extend(part.strip() for part in forwarded_for.split(","))
    for address in addresses:
        try:
            if not address or not ipaddress.ip_address(address).is_loopback:
                return False
        except ValueError:
            return False
    return True


def require_identity_review_access(request: Request) -> None:
    """Authorize one internal identity-review request without reflecting secrets."""

    configured = os.environ.get("HG_IDENTITY_REVIEW_SECRET", "").strip()
    supplied = request.headers.get(IDENTITY_REVIEW_HEADER, "")
    # Compare fixed-length digests so missing, short, and long header values all
    # take the same compare path.  The configured secret itself is never logged
    # or copied into an exception response.
    configured_digest = hashlib.sha256(configured.encode("utf-8")).digest()
    supplied_digest = hashlib.sha256(supplied.encode("utf-8")).digest()
    secret_matches = hmac.compare_digest(configured_digest, supplied_digest)
    if len(configured) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "IDENTITY_REVIEW_DISABLED",
                "message": "기기 식별 검토 기능이 이 서버에서 비활성화되어 있습니다.",
            },
        )
    if not _identity_review_request_is_local(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "IDENTITY_REVIEW_LOCAL_ONLY",
                "message": "기기 식별 검토는 서버 내부 연결에서만 사용할 수 있습니다.",
            },
        )
    if not secret_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "IDENTITY_REVIEW_DISABLED",
                "message": "기기 식별 검토 요청을 확인할 수 없습니다.",
            },
        )


def _raise_identity_enrichment_http_error(exc: IdentityEnrichmentError) -> None:
    response_by_code = {
        "IDENTITY_JOB_NOT_FOUND": (
            status.HTTP_404_NOT_FOUND,
            "검토할 기기 식별 작업을 찾을 수 없습니다.",
        ),
        "IDENTITY_BINDING_REQUIRED": (
            status.HTTP_409_CONFLICT,
            "현재 공유기와 실제 기기에 안전하게 연결된 작업만 승인할 수 있습니다.",
        ),
        "IDENTITY_MODEL_NOT_SPECIFIC": (
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "제조사, 품목, 실제 모델 또는 품번과 공식 출처를 다시 확인해 주세요.",
        ),
        "IDENTITY_JOB_ALREADY_RESOLVED": (
            status.HTTP_409_CONFLICT,
            "이미 승인된 기기 식별 작업입니다.",
        ),
    }
    http_status, message = response_by_code.get(
        exc.code,
        (status.HTTP_422_UNPROCESSABLE_CONTENT, "기기 식별 검토 내용을 다시 확인해 주세요."),
    )
    raise HTTPException(
        status_code=http_status,
        detail={"code": exc.code, "message": message},
    ) from exc


@app.middleware("http")
async def identity_review_network_boundary(request: Request, call_next):
    """Apply the internal boundary before routing or request-body validation."""

    if request.url.path.startswith(f"{API_PREFIX}/internal/identity-enrichment/"):
        try:
            require_identity_review_access(request)
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {}
            return JSONResponse(
                status_code=exc.status_code,
                content=error_response(
                    code=str(detail.get("code") or "IDENTITY_REVIEW_DISABLED"),
                    message=str(
                        detail.get("message")
                        or "기기 식별 검토 요청을 확인할 수 없습니다."
                    ),
                    details={},
                ),
            )
    return await call_next(request)


def prune_guardian_lookup_failures(key: str, now: float | None = None) -> list[float]:
    current = now or time.monotonic()
    failures = [ts for ts in _guardian_lookup_failures.get(key, []) if current - ts < GUARDIAN_LOOKUP_WINDOW_SECONDS]
    if failures:
        _guardian_lookup_failures[key] = failures
    else:
        _guardian_lookup_failures.pop(key, None)
    return failures


def ensure_guardian_lookup_allowed(request: Request) -> str:
    key = guardian_lookup_rate_key(request)
    if len(prune_guardian_lookup_failures(key)) >= GUARDIAN_LOOKUP_MAX_FAILURES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "GUARDIAN_INVITE_RATE_LIMITED",
                "message": "초대 코드를 여러 번 틀렸어요. 잠시 후 다시 시도하거나 사용자에게 새 초대를 요청해 주세요.",
            },
        )
    return key


def record_guardian_lookup_failure(key: str) -> None:
    prune_guardian_lookup_failures(key)
    _guardian_lookup_failures.setdefault(key, []).append(time.monotonic())


def clear_guardian_lookup_failures(key: str) -> None:
    _guardian_lookup_failures.pop(key, None)


def reject_non_actual_android_scan(request: ScanRequest) -> None:
    reasons = actual_android_scan_rejection_reasons(request.network_context, request.devices)
    if not reasons:
        return

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "code": "SCAN_ACTUAL_DEVICE_REQUIRED",
            "message": "현재 공유기 Wi-Fi 점검 정보를 확인하지 못해 결과를 저장하지 않았어요. Android 실기기를 같은 공유기 Wi-Fi에 연결해 다시 실행해 주세요.",
            "details": {"reasons": reasons},
        },
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, __: RequestValidationError) -> JSONResponse:
    """Return a safe public 422 response without reflecting request values.

    FastAPI's default validation body can include the rejected ``input`` value.
    Scanner payloads and authentication requests can contain device identifiers,
    network addresses, or refresh secrets, so the public response deliberately
    carries no field-level validation detail.
    """
    if request.url.path.startswith(f"{API_PREFIX}/internal/identity-enrichment/"):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=error_response(
                code="IDENTITY_MODEL_NOT_SPECIFIC",
                message="제조사, 품목, 실제 모델 또는 품번과 공식 출처를 다시 확인해 주세요.",
                details={},
            ),
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=error_response(
            code="INPUT_CHECK_REQUIRED",
            message="입력한 내용을 다시 확인해 주세요. 일부 정보의 길이 또는 형식이 맞지 않아요.",
            details={},
        ),
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
    code = detail.get("code", "HTTP_ERROR")
    message = detail.get("message", "요청을 처리할 수 없습니다.")
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response(code=code, message=message, details=detail.get("details", {})),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    """예기치 못한 오류도 일관된 error_response(JSON)로 반환한다(비구조화 500 응답 방지)."""
    logging.getLogger("home_guardian").exception("unhandled error", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response(
            code="INTERNAL_ERROR",
            message="일시적인 오류가 발생했어요. 잠시 후 다시 시도해 주세요.",
            details={},
        ),
    )


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        auth_token_secret()
        google_oauth_service.google_client_id()
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "AUTH_CONFIGURATION_REQUIRED", "message": "인증 설정을 확인한 뒤 다시 시작해 주세요."},
        ) from exc
    return success_response(
        {
            "status": "healthy",
            "service": "home-guardian-backend",
            "version": "1.0.0",
            "port": 8010,
        }
    )


@app.get(
    f"{API_PREFIX}/internal/identity-enrichment/jobs",
    include_in_schema=False,
)
def identity_enrichment_jobs(
    request: Request,
    status_filter: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    require_identity_review_access(request)
    jobs = repository.identity_enrichment_jobs(
        status_filter=status_filter,
        limit=limit,
    )
    return success_response(
        {"jobs": [project_identity_enrichment_job(job) for job in jobs]}
    )


@app.post(
    f"{API_PREFIX}/internal/identity-enrichment/jobs/{{job_id}}/resolve",
    include_in_schema=False,
)
def resolve_identity_enrichment_job(
    job_id: str,
    body: IdentityEnrichmentResolveRequest,
    request: Request,
) -> dict[str, Any]:
    require_identity_review_access(request)
    try:
        job = repository.resolve_identity_enrichment_job(
            job_id,
            manufacturer=body.manufacturer,
            device_type=body.device_type,
            model=body.model,
            source_reference=body.source_reference,
        )
    except IdentityEnrichmentError as exc:
        _raise_identity_enrichment_http_error(exc)
    return success_response(project_identity_enrichment_job(job))


@app.post(
    f"{API_PREFIX}/internal/identity-enrichment/jobs/{{job_id}}/reject",
    include_in_schema=False,
)
def reject_identity_enrichment_job(
    job_id: str,
    body: IdentityEnrichmentRejectRequest,
    request: Request,
) -> dict[str, Any]:
    require_identity_review_access(request)
    try:
        job = repository.reject_identity_enrichment_job(job_id, reason=body.reason)
    except IdentityEnrichmentError as exc:
        _raise_identity_enrichment_http_error(exc)
    return success_response(project_identity_enrichment_job(job))


@app.post(f"{API_PREFIX}/auth/google/callback")
def google_callback(request: GoogleCallbackRequest) -> dict[str, Any]:
    try:
        result = google_oauth_service.authenticate(
            code=request.code,
            id_token_value=request.id_token,
            redirect_uri=request.redirect_uri,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_GOOGLE_FAILED", "message": str(exc)},
        ) from exc

    # A supplied predecessor must be an *active* session.  Do this before
    # creating any successor so a guessed, revoked or pending token can never
    # create a session that later replaces another person's role.
    predecessor_session: dict[str, Any] | None = None
    predecessor_refresh_token_hash: str | None = None
    if request.previous_refresh_token:
        predecessor_refresh_token_hash = _refresh_token_hash(request.previous_refresh_token)
        predecessor_session = repository.auth_session_by_refresh_hash(predecessor_refresh_token_hash)
        if _active_session_scope(predecessor_session) is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "code": "AUTH_HANDOFF_PREDECESSOR_INVALID",
                    "message": "기존 로그인 정보를 확인하지 못했어요. 기존 로그인은 그대로 유지됩니다.",
                },
            )

    user = dict(result.user)
    if user and request.role == "guardian":
        user["user_id"] = f"guardian-{user.get('user_id')}"
        user["role"] = "guardian"
        user["home_id"] = ""
        if hasattr(repository, "upsert_guardian_account"):
            repository.upsert_guardian_account(
                guardian_id=user["user_id"],
                email=str(user.get("email") or ""),
                display_name=str(user.get("nickname") or user.get("name") or user.get("email") or ""),
            )
    elif user:
        user["role"] = "user"
        user["home_id"] = default_home_id_for_user(user.get("user_id"))
        if hasattr(repository, "upsert_user"):
            user = repository.upsert_user(user)

    if not user:
        tokens: dict[str, Any] = {}
    elif predecessor_session is not None and predecessor_refresh_token_hash is not None:
        # The predecessor stays active until the client has durably stored the
        # candidate and calls /auth/handoff/complete with proof of both sides.
        tokens = issue_pending_auth_handoff_pair(
            user,
            predecessor_session=predecessor_session,
            predecessor_refresh_token_hash=predecessor_refresh_token_hash,
        )
    else:
        tokens = issue_token_pair(user)
    return success_response({"user": user, **tokens, "provider": result.provider, "auth_mode": result.mode})


@app.get(f"{API_PREFIX}/auth/me")
def me(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    user = repository.user_by_id(scope.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_SESSION_INVALID", "message": "로그인 정보를 다시 확인해 주세요."},
        )
    return success_response(user)


def _session_user(scope: HomeScope) -> dict[str, Any]:
    if scope.role != "guardian":
        user = repository.user_by_id(scope.user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"code": "AUTH_SESSION_INVALID", "message": "로그인 정보를 다시 확인해 주세요."},
            )
        return user
    account = repository.guardian_account_by_id(scope.user_id)
    if account is None or not str(account.get("email") or "").strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_SESSION_INVALID", "message": "보호자 로그인 정보를 다시 확인해 주세요."},
        )
    return {
        "user_id": scope.user_id,
        "email": str((account or {}).get("email") or ""),
        "nickname": str((account or {}).get("display_name") or (account or {}).get("email") or "보호자"),
        "role": "guardian",
        "home_id": "",
        "email_verified": True,
    }


def _guardian_identity_from_scope(scope: HomeScope) -> dict[str, Any]:
    """Load the guardian identity tied to the authenticated session.

    Google callback creates this account before issuing its session.  The
    Missing or incomplete accounts fail closed; request data never supplies a
    guardian identity.
    """
    account = repository.guardian_account_by_id(scope.user_id)
    email = str((account or {}).get("email") or "").strip().lower()
    provider = str((account or {}).get("provider") or "").strip().lower()
    if account and email and provider == "google":
        return {
            "guardian_id": scope.user_id,
            "guardian_email": email,
            "guardian_name": str(account.get("display_name") or email).strip() or email,
            "provider": provider,
        }
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "GUARDIAN_ACCOUNT_REQUIRED", "message": "Google guardian account is required."},
    )


_PARTIAL_SCAN_STEP = "일부 기기를 확인하지 못했어요"


def _held_security_score(score: Mapping[str, Any] | None) -> dict[str, Any]:
    """Hold a score without discarding already-computed per-device evidence."""

    result = hold_partial_security(score if isinstance(score, Mapping) else {})
    result.update(
        {
            "scan_complete": False,
            "coverage_complete": False,
        }
    )
    return result


def _partial_security_score(score: Mapping[str, Any] | None) -> dict[str, Any]:
    """Expose an observed-only score without presenting it as a whole-home result."""

    result = project_partial_security(score if isinstance(score, Mapping) else {})
    result.update(
        {
            "scan_complete": False,
            "coverage_complete": False,
        }
    )
    return result


def _identity_research_status(pending_count: int) -> str:
    return "review_required" if pending_count > 0 else "complete"


def _apply_public_identity_contract(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Keep pending identity rows distinct from confirmed product cards.

    Resolver findings remain private inputs to confirmed-red aggregation.  The
    app also receives a separate ``detected_connections`` projection for
    observations with a non-generic structured label. Bare transport responses
    are not public observations and cannot restore a legacy pending count.
    """

    result = dict(payload)
    confirmed_rows = result.get("devices")
    if not isinstance(confirmed_rows, list) and isinstance(result.get("items"), list):
        confirmed_rows = result.get("items")
    confirmed_ids = (
        {
            str(item.get("device_id") or "").strip()
            for item in confirmed_rows
            if isinstance(item, Mapping)
            and str(item.get("device_id") or "").strip()
        }
        if isinstance(confirmed_rows, list)
        else set()
    )
    has_internal_confirmed_ids = "_confirmed_device_ids" in result
    internal_confirmed_ids = result.pop("_confirmed_device_ids", [])
    if isinstance(internal_confirmed_ids, list):
        confirmed_ids.update(
            str(value or "").strip()
            for value in internal_confirmed_ids
            if str(value or "").strip()
        )

    raw_findings = result.get("identity_findings")
    detected_connections = [
        item
        for item in build_public_detected_connections(raw_findings)
        if str(item.get("device_id") or "").strip() not in confirmed_ids
    ]
    # Public counts are derived from the same evidence projection as the rows
    # themselves.  In particular, an old snapshot may still declare a pending
    # count for refusal-only transport noise even though it has no current
    # structured observation.  Trusting that stored integer would recreate the
    # very phantom rows removed at the repository read boundary.
    pending_count = len(detected_connections)
    research_status = _identity_research_status(pending_count)
    result["identity_pending_count"] = pending_count
    result["identity_incomplete"] = pending_count > 0
    result["identity_research_status"] = research_status
    result["detected_connections"] = detected_connections
    result["evidence_backed_observation_count"] = len(detected_connections)
    result["unresolved_observation_count"] = pending_count
    result["identity_findings"] = []

    detected_ids = {
        str(item.get("device_id") or "").strip()
        for item in detected_connections
        if str(item.get("device_id") or "").strip()
    }
    if "devices_found" in result and (
        confirmed_rows is not None or has_internal_confirmed_ids
    ):
        # Keep the public count identical to the distinct cards that can be
        # rendered. Repository/private snapshot counts may include diagnostic
        # presence rows that do not satisfy the public evidence contract.
        result["devices_found"] = len(confirmed_ids | detected_ids)
        if "identified_count" in result:
            result["identified_count"] = len(confirmed_ids)

    security_score = result.get("security_score")
    transport_score_partial = (
        result.get("coverage_complete") is False
        or result.get("score_status") in {"held", "provisional"}
        or (
            isinstance(security_score, Mapping)
            and (
                security_score.get("coverage_complete") is False
                or security_score.get("score_status") in {"held", "provisional"}
            )
        )
    )

    if transport_score_partial and "score" in result:
        result = _partial_security_score(result)

    home = result.get("home")
    if isinstance(home, Mapping):
        result["home"] = {
            **home,
            "identity_pending_count": pending_count,
            "identity_incomplete": pending_count > 0,
            "identity_research_status": research_status,
        }
    summary = result.get("summary")
    if isinstance(summary, Mapping):
        projected_summary = {
            **summary,
            "identity_pending_count": pending_count,
            "identity_incomplete": pending_count > 0,
            "identity_research_status": research_status,
        }
        result["summary"] = _partial_security_score(projected_summary) if transport_score_partial else projected_summary
    elif pending_count and isinstance(summary, str):
        # Score endpoints use a top-level string summary. Never echo the
        # repository's internal identity-queue wording to residents.
        result["summary"] = _partial_security_score(result)["summary"] if transport_score_partial else summary

    # Normalize the nested score from the same projected rows even when no
    # observations remain public. Legacy snapshots can otherwise expose
    # top-level ``identity_pending_count=0`` while retaining a stale nested
    # ``identity_incomplete=true`` and non-zero count.
    if isinstance(result.get("security_score"), Mapping):
        score_payload = dict(result["security_score"])
        if transport_score_partial:
            score_payload = _partial_security_score(score_payload)
        elif pending_count > 0:
            score_payload.update(
                {
                    "score_status": "final",
                    "scan_complete": True,
                    "coverage_complete": True,
                }
            )
        score_payload.update(
            {
                "identity_incomplete": pending_count > 0,
                "identity_pending_count": pending_count,
                "identity_research_status": research_status,
            }
        )
        result["security_score"] = score_payload

    if pending_count <= 0:
        return result

    # Product enrichment is independent from physical scan coverage.  A real
    # connection without a model number stays visible, contributes its observed
    # security facts, and does not turn a completed scan into a retry loop.
    if "current_step" in result and not transport_score_partial:
        result["current_step"] = "점검 완료"
    if not transport_score_partial:
        result["scan_complete"] = True
        result["coverage_complete"] = True
    return result


def _apply_scan_completion_contract(
    result: Mapping[str, Any],
    network_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project explicit scanner completeness into one consistent public DTO."""

    projected = dict(result)
    context = network_context if isinstance(network_context, Mapping) else projected.get("network_context")
    partial = scan_is_partial(context if isinstance(context, Mapping) else None)
    coverage_complete = scan_coverage_complete(context if isinstance(context, Mapping) else None)
    if coverage_complete is not None:
        projected["coverage_complete"] = coverage_complete
        projected["scan_complete"] = not partial
    elif partial:
        projected["coverage_complete"] = False
        projected["scan_complete"] = False

    if not partial:
        return projected

    # A bounded scan can finish its execution while failing to cover every
    # candidate. Keep progress at 100 (the run ended), preserve any score that
    # was actually calculated from observed devices, and mark it provisional.
    if projected.get("status") in {None, "completed", "partial"}:
        projected["status"] = "partial"
    projected["current_step"] = _PARTIAL_SCAN_STEP
    if isinstance(projected.get("security_score"), Mapping):
        projected["security_score"] = _partial_security_score(projected["security_score"])
    return projected


def _latest_scan_context(home_id: str) -> Mapping[str, Any] | None:
    if not hasattr(repository, "latest_scan_context"):
        return None
    context = repository.latest_scan_context(home_id=home_id)
    return context if isinstance(context, Mapping) else None


def _apply_partial_home_contract(payload: Mapping[str, Any], home_id: str) -> dict[str, Any]:
    """Keep dashboard/score projections explicitly non-final after a partial scan."""

    result = dict(payload)
    if not scan_is_partial(_latest_scan_context(home_id)):
        return result

    result["scan_complete"] = False
    result["coverage_complete"] = False
    if "device_scores" in result:
        return _partial_security_score(result)

    projected_summary: dict[str, Any] | None = None
    summary = result.get("summary")
    if isinstance(summary, Mapping):
        projected_summary = _partial_security_score(summary)
        result["summary"] = {
            **projected_summary,
            "scan_complete": False,
            "coverage_complete": False,
            "message": projected_summary["summary"],
        }
    home = result.get("home")
    if isinstance(home, Mapping):
        result["home"] = {
            **home,
            "security_score": projected_summary.get("score") if projected_summary else None,
            "scan_complete": False,
        }
    return result


def _refresh_session_response(scope: HomeScope, session: dict[str, Any], refresh_token: str) -> dict[str, Any]:
    return success_response(
        {
            "user": _session_user(scope),
            "access_token": issue_access_token(scope, str(session["session_id"])),
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
    )


@app.get(f"{API_PREFIX}/auth/session")
def auth_session(request: Request) -> dict[str, Any]:
    auth_header = request.headers.get(AUTH_HEADER, "").strip()
    scope = scope_from_access_token(auth_header[7:].strip()) if auth_header.lower().startswith("bearer ") else None
    if scope is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_SESSION_INVALID", "message": "로그인 정보를 다시 확인해 주세요."},
        )
    return success_response({"user": _session_user(scope), "role": scope.role})


@app.post(f"{API_PREFIX}/auth/refresh")
def refresh_auth_session(body: RefreshSessionRequest) -> dict[str, Any]:
    previous_hash = _refresh_token_hash(body.refresh_token)
    session = repository.auth_session_by_refresh_hash(previous_hash)
    scope = _active_session_scope(session)
    if scope is None or session is None:
        recovered = _recover_refresh_rotation(body, previous_hash)
        if recovered is not None:
            recovered_scope, recovered_session, recovered_refresh_token = recovered
            return _refresh_session_response(recovered_scope, recovered_session, recovered_refresh_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTH_SESSION_INVALID", "message": "로그인 정보를 다시 확인해 주세요."},
        )

    # A persisted idempotency key yields a deterministic successor, so a
    # response-loss retry can recreate it without any plaintext server storage.
    next_refresh_token = (
        _derive_rotated_refresh_token(body.refresh_token, body.refresh_attempt_id)
        if body.refresh_attempt_id
        else secrets.token_urlsafe(48)
    )
    next_hash = _refresh_token_hash(next_refresh_token)
    rotated = repository.rotate_auth_session(
        session_id=str(session["session_id"]),
        previous_refresh_token_hash=previous_hash,
        refresh_token_hash=next_hash,
        expires_at=_session_expiry(),
        refresh_retry_id=body.refresh_attempt_id,
        refresh_retry_until=_refresh_response_recovery_expiry() if body.refresh_attempt_id else None,
    )
    if not rotated:
        recovered = _recover_refresh_rotation(body, previous_hash)
        if recovered is not None:
            recovered_scope, recovered_session, recovered_refresh_token = recovered
            return _refresh_session_response(recovered_scope, recovered_session, recovered_refresh_token)
        # A parallel refresh can lose this compare-and-swap race after another request
        # already persisted a valid successor token. That conflict is not a logout event.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "AUTH_REFRESH_CONFLICT", "message": "로그인 정보를 새로 고치는 중입니다. 잠시 후 다시 시도해 주세요."},
        )
    return success_response(
        {
            "user": _session_user(scope),
            "access_token": issue_access_token(scope, str(session["session_id"])),
            "refresh_token": next_refresh_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        }
    )


@app.post(f"{API_PREFIX}/auth/logout")
def logout_auth_session(body: LogoutRequest) -> dict[str, Any]:
    repository.revoke_auth_session_by_refresh_hash(_refresh_token_hash(body.refresh_token))
    return success_response({"revoked": True})


@app.post(f"{API_PREFIX}/auth/handoff/complete")
def complete_auth_handoff(body: AuthHandoffCompleteRequest) -> dict[str, Any]:
    """Finish a staged role change with possession of both refresh secrets.

    The repository transaction flips the candidate to active and revokes the
    predecessor together.  Retrying the exact request after a lost response
    returns the same active successor; malformed or mismatched values fail
    closed without changing either session.
    """
    successor = repository.complete_auth_handoff(
        predecessor_refresh_token_hash=_refresh_token_hash(body.previous_refresh_token),
        successor_refresh_token_hash=_refresh_token_hash(body.successor_refresh_token),
        handoff_id_hash=_refresh_token_hash(body.handoff_id),
    )
    scope = _active_session_scope(successor)
    if successor is None or scope is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "AUTH_HANDOFF_INVALID",
                "message": "로그인 전환 정보를 확인하지 못했어요. 기존 로그인을 계속 사용할 수 있습니다.",
            },
        )
    return _refresh_session_response(scope, successor, body.successor_refresh_token)


@app.get(f"{API_PREFIX}/dashboard")
def dashboard(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    payload = repository.dashboard(home_id=scope.home_id)
    return success_response(
        _apply_public_identity_contract(
            _apply_partial_home_contract(payload, scope.home_id)
        )
    )


def _enrich_with_cve(device: dict[str, Any]) -> dict[str, Any]:
    """디바이스 응답에 NVD/CVE 매칭 결과를 채워 반환. 원본 device 는 변경하지 않는다."""
    # 본인 휴대폰(self_device)은 검사 대상이 아니다(scoring 이 100/green·"검사 대상 아님" 고정).
    # 검사 대상이 아닌 기기에 CVE 경고를 붙이면 표시가 모순되고, 불필요한 라이브 NVD 조회로
    # 응답이 지연된다. identify_device 가 self 를 보강하지 않는 것과 같은 원칙.
    if "self_device" in (device.get("risk_signals") or []):
        return device
    matcher = get_cve_matcher()
    matches = matcher.match_device(
        manufacturer=device.get("manufacturer"),
        model=device.get("model"),
        firmware=device.get("firmware"),
        risk_signals=device.get("risk_signals") or [],
        device_type=device.get("device_type"),
    )
    if not matches:
        return device
    enriched = dict(device)
    existing = list(enriched.get("vulnerabilities") or [])
    # 카탈로그/NVD 매칭은 cve_id 가 있는 항목만 vulnerabilities 에 추가.
    # generic_signals 매칭은 별도 필드로 노출해 UI 가 신호별 안내문구로 활용.
    for item in matches:
        if "cve_id" in item:
            existing.append(
                {
                    "cve_id": item["cve_id"],
                    "severity": item.get("severity", "medium"),
                    "cvss": item.get("cvss"),
                    "summary_ko": item.get("summary_ko"),
                    "remediation_ko": item.get("remediation_ko"),
                    "source": item.get("source"),
                    "vendor": item.get("vendor"),
                    "product": item.get("product"),
                    "matched_on": item.get("matched_on"),
                    "confidence": item.get("confidence"),
                }
            )
    enriched["vulnerabilities"] = existing
    enriched["risk_explanations"] = [
        {
            "signal": item.get("signal"),
            "summary_ko": item.get("summary_ko"),
            "remediation_ko": item.get("remediation_ko"),
        }
        for item in matches
        if item.get("source") == "generic_signal"
    ]
    return enriched


# 저장 시점에 보강된 이름("정체불명 기기"/"임시 인터넷 신호")은 조회 때 fallback 이 아니라
# identity 가 note 를 다시 주지 않는다 → name 패턴으로 안내문구/플래그를 복원한다.
def _enrich_with_identity(device: dict[str, Any]) -> dict[str, Any]:
    """OUI/모델명 추정으로 제조사·이름을 보강하고 정체불명/오탐 기기를 안내한다.

    별칭(repository 가 name 에 이미 반영)이 있으면 임시 이름이 아니므로 이름은 덮지 않는다.
    """
    # Repository public reads have already passed through apply_device_presentation().
    # They intentionally no longer carry raw IP/MAC/fingerprint evidence, so treating
    # them as a fresh scanner observation would make a valid public DTO unresolved on
    # its second pass.  This is a repository-bound idempotency path, not a way for a
    # raw scan request to assert its own identity: scanner rows always retain those
    # private evidence fields until the repository projection has verified them.
    if (
        device.get("is_resolved") is True
        and isinstance(device.get("canonical_name"), str)
        and bool(device["canonical_name"].strip())
        and "ip_address" not in device
        and "mac_address" not in device
        and "fingerprints" not in device
    ):
        return sanitize_public_payload(device)

    presented = apply_device_presentation(device)
    if presented is None:
        return {
            "device_id": public_device_id(device.get("device_id"), device.get("home_id")),
            "is_unresolved": True,
        }
    return presented


def _enrich_device(device: dict[str, Any]) -> dict[str, Any]:
    # 방어적: 한 기기의 이상 데이터로 enrich 가 터져도 전체 기기 목록(이 함수는 6+ 곳에서
    # 컴프리헨션으로 호출됨)이 500 으로 사라지지 않게 한다. 실패 시 원본 기기를 그대로 반환해
    # '식별 보강은 없지만 기기는 보이는' 우아한 강등을 한다. 조용한 실패 금지 → 예외를 로깅한다.
    try:
        already_public = (
            device.get("is_resolved") is True
            and isinstance(device.get("canonical_name"), str)
            and bool(device["canonical_name"].strip())
            and "ip_address" not in device
            and "mac_address" not in device
            and "fingerprints" not in device
        )
        # Repository reads already perform CVE merge + scoring on private
        # evidence. Only raw/internal callers still need enrichment here;
        # enriching an already-public DTO would recreate the stale-score race.
        enriched = device if already_public else _enrich_with_cve(device)
        return _enrich_with_identity(enriched)
    except Exception as exc:  # noqa: BLE001 - 한 기기 실패가 전체 스캔을 망치지 않도록 격리
        safe_exception_class = (
            type(exc).__name__
            if type(exc).__name__
            in {"KeyError", "LookupError", "RuntimeError", "TypeError", "ValueError"}
            else "UnexpectedError"
        )
        # Exception messages and stack frames can contain raw probe payloads,
        # household IP/MAC/SSID values or tokens.  Emit only a fixed event and
        # a tightly allowlisted class name.
        logging.getLogger("home_guardian").warning(
            "DEVICE_ENRICH_FAILED exception_class=%s", safe_exception_class
        )
        return {
            "device_id": public_device_id(device.get("device_id"), device.get("home_id")),
            "is_unresolved": True,
        }


def _is_phantom(device: dict[str, Any]) -> bool:
    """5001 유령 등 '확인되지 않은 신호'(실제 집 안 기기가 아님)인지. 메인 기기 목록에서 분리한다."""
    return (
        bool(device.get("is_phantom"))
        or bool(device.get("is_unresolved"))
        or "phantom_signal" in (device.get("risk_signals") or [])
    )


def _split_real_and_phantom(devices: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    real = [d for d in devices if not _is_phantom(d)]
    phantom = [d for d in devices if _is_phantom(d)]
    return real, phantom


@app.get(f"{API_PREFIX}/devices")
def devices(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    enriched = [_enrich_device(item) for item in repository.devices(home_id=scope.home_id)]
    items, _ = _split_real_and_phantom(enriched)
    identity_findings = repository.identity_findings(home_id=scope.home_id)
    return success_response(
        _apply_public_identity_contract(
            {
            "items": items,
            # `total` is the count of verified household products. Detection
            # candidates stay available in the separate identity_findings
            # collection and must never inflate the device count.
            "total": len(items),
            "identified_count": len(items),
            "identity_pending_count": len(identity_findings),
            "identity_findings": identity_findings,
            }
        )
    )


@app.get(f"{API_PREFIX}/devices/{{device_id}}/identity-history")
def device_identity_history(device_id: str, request: Request) -> dict[str, Any]:
    """Return the server's product-identification attempts for one device.

    This is intentionally read-only.  The scanner keeps collecting private
    evidence, the server catalog resolver records every attempt, and the app
    can explain why a product is still being checked without exposing an IP,
    MAC address, port, chipset or temporary device label.
    """
    scope = require_home_scope(request)
    stored_items = repository.identity_history(device_id=device_id, home_id=scope.home_id, limit=50)
    if not stored_items:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "IDENTITY_HISTORY_404", "message": "이 기기의 식별 기록을 찾을 수 없습니다."},
        )
    items = [project_public_identity_history(item, home_id=scope.home_id) for item in stored_items]
    return success_response({"items": items, "total": len(items)})


@app.get(f"{API_PREFIX}/devices/{{device_id}}")
def device_detail(device_id: str, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    device = repository.device(device_id, home_id=scope.home_id)
    if device is None:
        finding = next(
            (item for item in repository.identity_findings(home_id=scope.home_id) if item.get("device_id") == device_id),
            None,
        )
        if finding is None:
            # A legacy mobile cache may still use the pre-v1 address-derived
            # id.  The repository resolves that id only inside its private
            # history bridge; use the public id returned by that bridge to
            # select the same finding without echoing the legacy value.
            history_ids = {
                str(item.get("device_id") or "")
                for item in repository.identity_history(device_id=device_id, home_id=scope.home_id, limit=50)
            }
            if history_ids:
                finding = next(
                    (item for item in repository.identity_findings(home_id=scope.home_id) if item.get("device_id") in history_ids),
                    None,
                )
        if finding is not None:
            detected = build_public_detected_connections([finding])
            if detected:
                return success_response(
                    {
                        **detected[0],
                        "identity_research_status": "review_required",
                    }
                )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "DEVICE_404", "message": "기기를 찾을 수 없습니다."},
        )
    enriched = _enrich_device(device)
    if _is_phantom(enriched):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "DEVICE_404", "message": "기기를 찾을 수 없어요."},
        )
    return success_response(enriched)


@app.patch(f"{API_PREFIX}/devices/{{device_id}}")
def update_device_alias(device_id: str, body: DeviceAliasRequest, request: Request) -> dict[str, Any]:
    """보호자가 기기 이름(별칭)을 직접 지정/초기화한다. 5월회의 '알 수 없는 기기' 대응."""
    scope = require_home_scope(request)
    device = repository.device(device_id, home_id=scope.home_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "DEVICE_404", "message": "기기를 찾을 수 없습니다."},
        )
    repository.set_device_alias(device_id, body.alias, home_id=scope.home_id)
    updated = repository.device(device_id, home_id=scope.home_id)
    return success_response(_enrich_device(updated if updated is not None else device))


@app.post(f"{API_PREFIX}/security/scan")
def start_security_scan(scan_request: ScanRequest, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    reject_non_actual_android_scan(scan_request)
    network_context = dict(scan_request.network_context)
    discovered_devices = [device.model_dump() for device in scan_request.devices]
    if scan_request.scan_source == "android-native":
        # The app is an evidence collector, not an authority for scan scope.
        # Filter before the server probe so a foreign observation cannot steer
        # server-side endpoint probing or product resolution.
        bounded = enforce_declared_subnet_boundary(network_context, discovered_devices)
        network_context = bounded.network_context
        discovered_devices = bounded.devices
        # Android can be prevented from reaching some LAN services by Wi-Fi
        # isolation or platform socket policy.  The production Raspberry Pi
        # may add only a verified protocol response; it never supplies a
        # product label from an IP address or a port number.
        scan_client_ip = trusted_scan_client_ip(request)
        if scan_client_ip is None:
            discovered_devices = augment_android_observations(
                discovered_devices,
                network_context,
            )
        else:
            discovered_devices = augment_android_observations(
                discovered_devices,
                network_context,
                trusted_client_ip=scan_client_ip,
            )
        # Defense in depth: the server collector has its own exact-host scope,
        # but all combined evidence crosses this one final boundary before
        # persistence.  Only an aggregate rejection count is retained.
        bounded = enforce_declared_subnet_boundary(
            network_context,
            discovered_devices,
            prior_dropped=bounded.dropped_count,
            prior_quarantined_endpoints=bounded.quarantined_endpoint_count,
        )
        network_context = bounded.network_context
        # Only a current-request proof object created by the server's peer/L2/
        # fresh-neighbour verifier may retain native self markers.  A client or
        # a disabled/failed probe can still submit the endpoint, but it remains
        # an ordinary device and identity candidate instead of disappearing
        # from counts, cards or the private enrichment queue.
        discovered_devices = [
            dict(device)
            if authenticated_self_android_evidence(device) is not None
            else strip_untrusted_self_claims(device)
            for device in bounded.devices
        ]
    result = repository.create_scan(
        scan_profile=scan_request.scan_profile,
        scan_source=scan_request.scan_source,
        network_context=network_context,
        discovered_devices=discovered_devices,
        home_id=scope.home_id,
    )
    # External product lookup never runs in this HTTP request.  The marker is
    # zero-content and therefore contains no home, account, IP, MAC or evidence
    # data; a systemd path unit wakes the bounded background worker.
    try:
        wake_identity_research_worker()
    except OSError:
        # The timer is the restart/missed-wake recovery path.  A marker I/O
        # failure must not turn an otherwise valid LAN scan into an API error.
        pass
    result = _apply_public_identity_contract(
        _apply_scan_completion_contract(result, network_context)
    )

    # 실행이 끝나면 등록된 FCM 토큰에 결과를 알린다. 부분 점검은 아래
    # title/body helper에서 완료/안전 알림으로 표현하지 않는다.
    push_outcome = _broadcast_scan_completed_push(result, user_id=scope.user_id)

    response = {
        "scan_id": result["scan_id"],
        "status": result["status"],
        "progress": result["progress"],
        "scan_source": result["scan_source"],
        "current_step": result["current_step"],
        "network_context": sanitize_public_network_context(result.get("network_context")),
        "devices_found": result["devices_found"],
        "identified_count": result.get("identified_count", result["devices_found"]),
        "identity_pending_count": result.get("identity_pending_count", 0),
        "identity_research_status": result.get("identity_research_status", "complete"),
        "high_risk_devices": result["high_risk_devices"],
        "detected_connections": result.get("detected_connections", []),
        "evidence_backed_observation_count": result.get(
            "evidence_backed_observation_count", 0
        ),
        "unresolved_observation_count": result.get(
            "unresolved_observation_count",
            result.get("identity_pending_count", 0),
        ),
        "identity_findings": [],
        # FCM 공급자 예외·토큰 조각·구현 상태가 future 코드에서 다시 섞여도
        # 이 공개 경계에서는 발송 성공/실패 개수만 보인다.
        "push_result": fcm_service.public_delivery_summary(push_outcome),
    }
    score_payload = result.get("security_score")
    for field in ("scan_complete", "coverage_complete"):
        value = result.get(field)
        if not isinstance(value, bool) and isinstance(score_payload, Mapping):
            value = score_payload.get(field)
        if isinstance(value, bool):
            response[field] = value
    return success_response(response)


def _scan_push_title_body(scan_result: dict[str, Any]) -> tuple[str, str, int]:
    """스캔 완료 푸시의 제목·본문. 위험(red)뿐 아니라 '주의(yellow)' 기기도 반영한다. 그러지 않으면
    알려진 취약점으로 yellow 가 된 기기(예 라우터 CVE)가 있어도 "안전 검사를 마쳤어요·위험 0대" 로만
    떠 사용자가 안심해 놓친다(앱 내 알림 scan_completed_message 와 동일 기준). 반환: (title, body, caution)."""
    high_risk = int(scan_result.get("high_risk_devices") or 0)
    devices_found = int(scan_result.get("devices_found") or 0)
    security_score = scan_result.get("security_score") or {}
    device_scores = security_score.get("device_scores") or []
    caution = sum(1 for item in device_scores if item.get("risk_level") == "yellow")
    if scan_result.get("status") == "partial" or scan_result.get("scan_complete") is False:
        if high_risk > 0:
            return (
                "위험한 기기가 발견됐어요",
                f"확인된 위험 {high_risk}대가 있어요. 일부 점검은 끝나지 않아 다시 점검해야 해요.",
                caution,
            )
        return (
            "점검을 모두 마치지 못했어요",
            "Wi-Fi 연결을 확인한 뒤 다시 점검해 주세요. 현재 결과만으로 안전하다고 판단하지 않아요.",
            caution,
        )
    if devices_found <= 0:
        return (
            "보안 점검을 마쳤어요",
            "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요.",
            0,
        )
    if public_score_calculation_failed(security_score):
        return "보안 점수를 계산하지 못했어요", SCORE_CALCULATION_FAILED_MESSAGE, 0
    if high_risk > 0:
        body = f"기기 {devices_found}대 확인 · 위험 {high_risk}대" + (f" · 주의 {caution}대" if caution else "")
        return "위험한 기기가 발견됐어요", body, caution
    if caution > 0:
        return "확인이 필요한 기기가 있어요", f"기기 {devices_found}대 확인 · 주의 {caution}대", caution
    return "안전 검사를 마쳤어요", f"기기 {devices_found}대 확인 · 위험·주의 기기 없음", caution


# FCM 발송에 둘 요청 내 시간 상한(초). 실제 push(messaging.send)는 외부 네트워크 호출이라
# 느리거나 막히면 scan POST 응답이 모바일 8초 타임아웃을 넘길 수 있다. 상한 내 끝나면 실제
# 결과를, 넘으면 백그라운드로 계속 보낸다. 공개 응답은 어떤 경우에도
# 공급자 구현 상태 대신 현재까지의 성공/실패 개수만 반환한다.
# (무토큰/무credential 경로는 즉시 반환되므로 상한에 걸리지 않아 기존 동작·테스트가 보존된다.)
_PUSH_DEADLINE_SECONDS = 2.0
# 요청당 새 스레드를 만들지 않고 '유한' 풀로 발송한다. 느린 FCM + 동시 스캔에도 스레드 수가
# max_workers 로 묶여 무한 증식하지 않는다(단일 라즈베리파이 자원 보호). 풀이 가득 차면 submit 은
# 큐잉되고 future.result(deadline) 가 상한을 지켜 요청은 항상 빠르게 끝난다.
_PUSH_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="fcm-broadcast")


def _broadcast_scan_completed_push(scan_result: dict[str, Any], user_id: str | None = None) -> dict[str, Any]:
    tokens = repository.list_fcm_tokens(user_id=user_id) if hasattr(repository, "list_fcm_tokens") else []
    if not tokens:
        return fcm_service.public_delivery_summary()
    high_risk = int(scan_result.get("high_risk_devices") or 0)
    devices_found = int(scan_result.get("devices_found") or 0)
    title, body, caution = _scan_push_title_body(scan_result)
    data = {
        "type": "scan_completed",
        "scan_id": str(scan_result.get("scan_id") or ""),
        "high_risk": str(high_risk),
        "caution": str(caution),
        "devices_found": str(devices_found),
        "scan_complete": "false" if scan_result.get("status") == "partial" or scan_result.get("scan_complete") is False else "true",
    }

    def remove_invalid_token(token: str) -> None:
        if user_id is not None and hasattr(repository, "delete_fcm_token"):
            repository.delete_fcm_token(token, user_id=user_id)

    future = _PUSH_EXECUTOR.submit(
        fcm_service.broadcast,
        tokens=tokens,
        title=title,
        body=body,
        data=data,
        on_invalid_token=remove_invalid_token,
    )
    try:
        return future.result(timeout=_PUSH_DEADLINE_SECONDS)
    except FutureTimeoutError:
        # 상한 초과: 발송은 풀 워커에서 계속된다. 아직 확정된 결과가 없으므로
        # 주민 공개 응답에는 0/0만 반환하고, 내부 구현 상태는 노출하지 않는다.
        return fcm_service.public_delivery_summary()


@app.get(f"{API_PREFIX}/security/scan/{{scan_id}}/status")
def scan_status(scan_id: str, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    result = repository.scan_status(scan_id, home_id=scope.home_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_404", "message": "점검 결과를 찾을 수 없습니다."},
        )
    snapshot = repository.scan_result(scan_id, home_id=scope.home_id)
    if snapshot and isinstance(snapshot.get("identity_findings"), list):
        result = {
            **result,
            "devices_found": snapshot.get("devices_found", result.get("devices_found", 0)),
            "identified_count": snapshot.get("identified_count", result.get("identified_count", 0)),
            "identity_pending_count": snapshot.get("identity_pending_count", len(snapshot["identity_findings"])),
            # The public boundary recomputes the count from these evidence
            # rows instead of trusting a legacy aggregate integer.
            "identity_findings": snapshot["identity_findings"],
            "_confirmed_device_ids": [
                str(item.get("device_id") or "").strip()
                for item in (snapshot.get("devices") or [])
                if isinstance(item, Mapping) and str(item.get("device_id") or "").strip()
            ],
        }
    context = snapshot.get("network_context") if isinstance(snapshot, Mapping) else None
    return success_response(
        _apply_public_identity_contract(
            _apply_scan_completion_contract(result, context)
        )
    )


@app.get(f"{API_PREFIX}/security/scans/{{scan_id}}")
def scan_result(scan_id: str, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    result = repository.scan_result(scan_id, home_id=scope.home_id)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "SCAN_404", "message": "점검 결과를 찾을 수 없습니다."},
        )
    # Repository implementations also project this field, but keep the public
    # HTTP boundary defensive for legacy rows and future storage backends.
    result = dict(result)
    result["network_context"] = sanitize_public_network_context(result.get("network_context"))
    if isinstance(result.get("devices"), list):
        enriched = [_enrich_device(device) for device in result["devices"]]
        real, _ = _split_real_and_phantom(enriched)
        result["devices"] = real
        result["identified_count"] = len(real)
        result.setdefault("devices_found", len(real) + len(result.get("identity_findings") or []))
        result["high_risk_devices"] = confirmed_public_red_count(
            real,
            result.get("identity_findings"),
        )
    if isinstance(result.get("identity_findings"), list):
        result["identity_pending_count"] = len(result["identity_findings"])
    if isinstance(result.get("events"), list):
        result["events"] = [
            {
                **event,
                "title": sanitize_public_notification(
                    {"title": event.get("title"), "message": event.get("description")}
                )["title"],
                "description": sanitize_public_notification(
                    {"title": event.get("title"), "message": event.get("description")}
                )["message"],
            }
            for event in result["events"]
        ]
        # Keep the complete event object on the same central sanitizer; title/description
        # alone would leave an old action guide or nested payload unfiltered.
        result["events"] = [sanitize_public_notification(event) for event in result["events"]]
    result = _apply_scan_completion_contract(result, result.get("network_context"))
    return success_response(_apply_public_identity_contract(result))


@app.get(f"{API_PREFIX}/security/score")
def security_score(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    score = repository.security_score(home_id=scope.home_id)
    return success_response(
        _apply_public_identity_contract(
            _apply_partial_home_contract(score, scope.home_id)
        )
    )


@app.get(f"{API_PREFIX}/security/events")
def security_events(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    events = []
    for event in repository.security_events(home_id=scope.home_id):
        safe = sanitize_public_notification(
            {"title": event.get("title"), "message": event.get("description")}
        )
        events.append({**event, "title": safe["title"], "description": safe["message"]})
    events = [sanitize_public_notification(event) for event in events]
    return success_response({"items": events, "total": len(events)})


@app.post(f"{API_PREFIX}/guardians/invite")
def invite_guardian(invite_request: GuardianInviteRequest, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    return success_response(
        repository.create_guardian_invite(
            email=invite_request.email,
            relation=invite_request.relation,
            ward_account_name=invite_request.ward_name,
            home_id=scope.home_id,
        )
    )


@app.get(f"{API_PREFIX}/notifications")
def notifications(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    items = [sanitize_public_notification(item) for item in repository.notifications(home_id=scope.home_id)]
    unread_count = sum(1 for item in items if not item["read"])
    return success_response({"items": items, "unread_count": unread_count})


@app.post(f"{API_PREFIX}/auth/fcm-token")
def register_fcm_token(token_request: FcmTokenRequest, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    return success_response(repository.register_fcm_token(token_request.fcm_token, token_request.platform, user_id=scope.user_id))


@app.delete(f"{API_PREFIX}/auth/fcm-token")
def delete_fcm_token(token_request: DeleteFcmTokenRequest, request: Request) -> JSONResponse:
    scope = require_home_scope(request)
    deleted = repository.delete_fcm_token(token_request.fcm_token, user_id=scope.user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "AUTH_083", "message": "등록되지 않은 FCM 토큰입니다."},
        )
    return JSONResponse(status_code=status.HTTP_204_NO_CONTENT, content=None)


@app.get(f"{API_PREFIX}/guardians")
def guardians(request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    # 목록을 읽을 때마다 오래된 만료/취소 초대를 정리한다(누적 방지, 별도 인프라 없이 self-cleaning).
    # pending(유효)·accepted(연결됨)는 보존하므로 활성 관계엔 영향이 없다.
    if hasattr(repository, "purge_stale_guardian_invites"):
        try:
            repository.purge_stale_guardian_invites(home_id=scope.home_id)
        except Exception:  # noqa: BLE001 - 정리 실패가 목록 조회를 막지 않게 격리(로깅)
            logging.getLogger("home_guardian").warning("초대 정리(purge) 실패 — 목록은 그대로 반환", exc_info=True)
    items = repository.guardians(home_id=scope.home_id)
    summary = repository.guardian_invite_summary(home_id=scope.home_id) if hasattr(repository, "guardian_invite_summary") else guardian_invite_summary(items)
    return success_response({"items": items, "total": len(items), "summary": summary})


# 보호자(원격 타인)에게 보내면 안 되는 기기 개인식별 필드. 보호자는 위험 판단·조치에 필요한
# 정보(이름/종류/제조사/모델/위험도/취약점/조치)만 받고, LAN 식별자(MAC/IP/fingerprint)는 받지 않는다.
_GUARDIAN_HIDDEN_DEVICE_FIELDS = ("mac_address", "ip_address", "fingerprints")


def _guardian_safe_device(device: dict[str, Any]) -> dict[str, Any]:
    """보호자에게 노출할 기기 객체에서 개인 식별 정보를 제거한다(MAC/IP/fingerprint + MAC 을 담은 device_id)."""
    # `devices` in the guardian dashboard has already been enriched through the
    # repository public projection. Reuse that verified DTO rather than asking the
    # identity resolver to infer a product from a deliberately redacted object.
    presented = _enrich_with_identity(device)
    safe = {k: v for k, v in presented.items() if k not in _GUARDIAN_HIDDEN_DEVICE_FIELDS}
    raw_id = str(device.get("device_id") or "")
    # device_id 는 device-{MAC} 형태라 그대로 보내면 MAC 이 새어나간다 → 비가역 해시로 마스킹(키 안정성 유지).
    safe["device_id"] = ("ward-" + hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]) if raw_id else "ward-unknown"
    return safe


def _guardian_home_snapshot(home_id: str) -> dict[str, Any]:
    """Load one home-scoped, phantom-free snapshot shared by guardian list/detail responses."""
    dashboard = _apply_public_identity_contract(
        _apply_partial_home_contract(repository.dashboard(home_id=home_id), home_id)
    )
    devices = [
        device
        for device in (_enrich_device(item) for item in repository.devices(home_id=home_id))
        if not _is_phantom(device)
    ]
    identity_findings = repository.identity_findings(home_id=home_id)
    identity_pending_count = len(build_public_detected_connections(identity_findings))
    notifications = [sanitize_public_notification(item) for item in repository.notifications(home_id=home_id)]
    return {
        "dashboard": dashboard,
        "devices": devices,
        "safe_devices": [_guardian_safe_device(device) for device in devices],
        "identity_pending_count": identity_pending_count,
        "notifications": notifications,
    }


def _guardian_ward_summary(
    home_id: str,
    *,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = snapshot or _guardian_home_snapshot(home_id)
    dashboard = current["dashboard"]
    devices = current["devices"]
    identity_pending_count = int(current["identity_pending_count"])
    unread = [item for item in current["notifications"] if not item.get("read")]
    summary = dashboard.get("summary", {}) if isinstance(dashboard.get("summary"), dict) else {}
    return {
        "score": summary.get("score"),
        "score_status": summary.get("score_status"),
        "risk_level": summary.get("risk_level"),
        "scan_complete": summary.get("scan_complete", dashboard.get("scan_complete")),
        "coverage_complete": summary.get("coverage_complete", dashboard.get("coverage_complete")),
        "device_count": len(devices),
        "high_risk_devices": sum(1 for device in devices if device.get("risk_level") == "red"),
        "caution_devices": sum(1 for device in devices if device.get("risk_level") == "yellow"),
        "identity_pending_count": identity_pending_count,
        "identity_research_status": _identity_research_status(identity_pending_count),
        "unread_notifications": len(unread),
    }


def _format_guardian_ward(
    ward: dict[str, Any],
    *,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    home_id = str(ward.get("home_id") or "")
    current = snapshot or (_guardian_home_snapshot(home_id) if home_id else None)
    return {
        "link_id": ward.get("link_id"),
        "guardian_id": ward.get("guardian_id"),
        "invite_id": ward.get("invite_id"),
        "home_id": ward.get("home_id"),
        "ward_account_name": ward.get("ward_account_name"),
        "ward_alias": ward.get("ward_alias"),
        "ward_display_name": ward.get("ward_display_name"),
        "status": ward.get("status"),
        "accepted_at": ward.get("accepted_at"),
        "revoked_at": ward.get("revoked_at"),
        "last_viewed_at": ward.get("last_viewed_at"),
        "summary": _guardian_ward_summary(home_id, snapshot=current) if current else None,
        "devices": list(current["safe_devices"]) if current else [],
    }


def _guardian_wards_payload(guardian_id: str) -> dict[str, Any]:
    if not hasattr(repository, "guardian_wards"):
        return {"items": [], "total": 0}
    snapshots: dict[str, dict[str, Any]] = {}
    items: list[dict[str, Any]] = []
    for ward in repository.guardian_wards(guardian_id):
        home_id = str(ward.get("home_id") or "")
        snapshot = None
        if home_id:
            snapshot = snapshots.get(home_id)
            if snapshot is None:
                snapshot = _guardian_home_snapshot(home_id)
                snapshots[home_id] = snapshot
        items.append(_format_guardian_ward(ward, snapshot=snapshot))
    return {"items": items, "total": len(items)}


def _guardian_dashboard_payload(
    invite_data: dict[str, Any],
    ward: dict[str, Any] | None = None,
) -> dict[str, Any]:
    home_id = str((ward or {}).get("home_id") or invite_data.get("home_id") or "").strip()
    if not home_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "GUARDIAN_HOME_SCOPE_MISSING", "message": "피보호자 집 연결 정보를 확인하지 못했어요."},
        )
    # 목록 preview와 상세가 같은 home-scoped snapshot을 사용해 기기 누락·개수 불일치를 막는다.
    # snapshot 로더에서 phantom을 제외하고 보호자용 개인정보 비노출 DTO를 함께 생성한다.
    snapshot = _guardian_home_snapshot(home_id)
    devices = snapshot["devices"]
    safe_devices = snapshot["safe_devices"]
    identity_pending_count = int(snapshot["identity_pending_count"])
    high_risk = [d for d in devices if d.get("risk_level") == "red"]
    # 보호자가 고령자 집을 원격으로 본다 — 위험(red)뿐 아니라 '주의(yellow)' 기기(예 라우터 CVE)도
    # 알려야 high_risk 0대만 보고 안심해 놓치지 않는다(앱 알림/푸시와 동일 기준).
    caution = [d for d in devices if d.get("risk_level") == "yellow"]
    notifications = snapshot["notifications"]
    ward_summary = _guardian_ward_summary(home_id, snapshot=snapshot)
    payload = {
        "invite": {
            "invite_id": invite_data.get("invite_id"),
            "email": invite_data.get("email"),
            "relation": invite_data.get("relation"),
            "display_name": invite_data.get("display_name"),
            "short_code": invite_data.get("short_code"),
            "deep_link": invite_data.get("deep_link"),
            "status": invite_data.get("status"),
            "status_label": invite_data.get("status_label"),
            "expires_at": invite_data.get("expires_at"),
            "accepted_at": invite_data.get("accepted_at"),
            "last_viewed_at": invite_data.get("last_viewed_at"),
        },
        "ward": _format_guardian_ward(ward, snapshot=snapshot) if ward else None,
        "ward_summary": ward_summary,
        "devices": list(safe_devices),
        "high_risk_devices": [_guardian_safe_device(d) for d in high_risk[:10]],
        "caution_devices": [_guardian_safe_device(d) for d in caution[:10]],
        "identity_pending_count": identity_pending_count,
        "identity_research_status": _identity_research_status(identity_pending_count),
        "identity_findings": [],
        "recent_notifications": notifications[:10],
        "read_only": True,
        "scope": "guardian-read-only",
    }
    return payload


@app.post(f"{API_PREFIX}/guardian-mode/links/accept")
def accept_guardian_link(body: GuardianLinkAcceptRequest, request: Request) -> dict[str, Any]:
    """보호자 Google 로그인 이후 초대 코드를 피보호자 연결로 1회 수락한다."""
    scope = require_guardian_scope(request, body.guardian_id)
    rate_key = ensure_guardian_lookup_allowed(request)
    result = repository.accept_guardian_invite_for_account(
        body.invite,
        _guardian_identity_from_scope(scope),
    )
    if not result.get("ok"):
        if str(result.get("code", "")).startswith("GUARDIAN_INVITE"):
            record_guardian_lookup_failure(rate_key)
        raise HTTPException(
            status_code=int(result.get("status_code") or status.HTTP_400_BAD_REQUEST),
            detail={"code": result.get("code"), "message": result.get("message")},
        )
    clear_guardian_lookup_failures(rate_key)
    guardian_id = result["guardian"]["guardian_id"]
    wards = _guardian_wards_payload(guardian_id)
    active_ward = _format_guardian_ward(result["ward"])
    return success_response(
        {
            "guardian": result["guardian"],
            "wards": wards["items"],
            "total": wards["total"],
            "active_ward": active_ward,
            "dashboard": _guardian_dashboard_payload(
                result["invite"],
                ward=result["ward"],
            ),
        }
    )


@app.get(f"{API_PREFIX}/guardian-mode/wards")
def guardian_mode_wards(request: Request, guardian_id: str | None = None) -> dict[str, Any]:
    if not guardian_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "GUARDIAN_ACCOUNT_REQUIRED", "message": "보호자 Google 로그인이 먼저 필요합니다."},
        )
    require_guardian_scope(request, guardian_id)
    return success_response(_guardian_wards_payload(guardian_id))


@app.get(f"{API_PREFIX}/guardian-mode/wards/{{link_id}}/dashboard")
def guardian_mode_ward_dashboard(link_id: str, request: Request, guardian_id: str | None = None) -> dict[str, Any]:
    if not guardian_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "GUARDIAN_ACCOUNT_REQUIRED", "message": "보호자 Google 로그인이 먼저 필요합니다."},
        )
    require_guardian_scope(request, guardian_id)
    link = repository.guardian_ward_link_by_id(link_id) if hasattr(repository, "guardian_ward_link_by_id") else None
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_LINK_404", "message": "보호자 연결을 찾을 수 없습니다."},
        )
    if link.get("guardian_id") != guardian_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "GUARDIAN_LINK_FORBIDDEN", "message": "이 보호자 계정에 연결된 대상이 아닙니다."},
        )
    if link.get("status") == "revoked":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"code": "GUARDIAN_LINK_REVOKED", "message": "취소된 보호자 연결입니다. 새 초대를 요청해 주세요."},
        )
    invite_data = (
        repository.guardian_invite_by_id(link["invite_id"]) if hasattr(repository, "guardian_invite_by_id") else None
    )
    if invite_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_INVITE_404", "message": "초대 정보를 찾을 수 없습니다."},
        )
    if invite_data.get("status") == "revoked":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"code": "GUARDIAN_LINK_REVOKED", "message": "취소된 보호자 연결입니다. 새 초대를 요청해 주세요."},
        )
    if hasattr(repository, "mark_guardian_ward_viewed"):
        link = repository.mark_guardian_ward_viewed(link_id) or link
    return success_response(_guardian_dashboard_payload(invite_data, ward=link))


@app.patch(f"{API_PREFIX}/guardian-mode/wards/{{link_id}}")
def update_guardian_ward_alias(link_id: str, body: GuardianWardAliasRequest, request: Request) -> dict[str, Any]:
    require_guardian_scope(request, body.guardian_id)
    link = repository.guardian_ward_link_by_id(link_id) if hasattr(repository, "guardian_ward_link_by_id") else None
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_LINK_404", "message": "보호자 연결을 찾을 수 없습니다."},
        )
    if link.get("guardian_id") != body.guardian_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "GUARDIAN_LINK_FORBIDDEN", "message": "이 보호자 계정에 연결된 대상이 아닙니다."},
        )
    if link.get("status") == "revoked":
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"code": "GUARDIAN_LINK_REVOKED", "message": "취소된 보호자 연결입니다. 새 초대를 요청해 주세요."},
        )
    updated = (
        repository.update_guardian_ward_alias(link_id, body.ward_alias)
        if hasattr(repository, "update_guardian_ward_alias")
        else link
    )
    return success_response(_format_guardian_ward(updated or link))


@app.delete(f"{API_PREFIX}/guardian-mode/wards/{{link_id}}")
def remove_guardian_ward_link(link_id: str, request: Request, guardian_id: str | None = None) -> dict[str, Any]:
    if not guardian_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "GUARDIAN_ACCOUNT_REQUIRED", "message": "보호자 Google 로그인이 먼저 필요합니다."},
        )
    require_guardian_scope(request, guardian_id)
    link = repository.guardian_ward_link_by_id(link_id) if hasattr(repository, "guardian_ward_link_by_id") else None
    if link is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_LINK_404", "message": "보호자 연결을 찾을 수 없습니다."},
        )
    if link.get("guardian_id") != guardian_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "GUARDIAN_LINK_FORBIDDEN", "message": "이 보호자 계정에 연결된 대상이 아닙니다."},
        )
    if link.get("status") != "revoked" and hasattr(repository, "revoke_guardian_ward_link"):
        link = repository.revoke_guardian_ward_link(link_id) or link
    return success_response(_format_guardian_ward(link))


@app.get(f"{API_PREFIX}/guardian-mode/dashboard")
def guardian_mode_dashboard() -> dict[str, Any]:
    """v0.x의 초대 코드·기기 토큰 직접 조회 경로를 명시적으로 폐기한다.

    v1에서는 Google로 확인된 보호자 계정만 초대를 수락하고, 해당 계정의 ward
    경로로 읽기 전용 진단을 조회할 수 있다. 이전의 짧은 코드 또는
    X-Guardian-Session 값만으로 가정 데이터를 돌려주던 동작은 허용하지 않는다.
    """
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "code": "GUARDIAN_LEGACY_SESSION_RETIRED",
            "message": "보호자 Google 로그인 후 초대 코드를 연결해 주세요.",
        },
    )


@app.patch(f"{API_PREFIX}/guardians/{{invite_id}}/revoke")
def revoke_guardian_invite(invite_id: str, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    invite = repository.revoke_guardian_invite(invite_id, home_id=scope.home_id) if hasattr(repository, "revoke_guardian_invite") else None
    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_INVITE_404", "message": "취소할 보호자 초대를 찾을 수 없습니다."},
        )
    return success_response(invite)


@app.delete(f"{API_PREFIX}/guardians/{{invite_id}}")
def delete_guardian_invite(invite_id: str, request: Request) -> dict[str, Any]:
    """보호자 초대를 목록에서 '실제로 삭제'한다(취소=상태 표시와 달리 행 제거). 삭제된 초대를 반환."""
    scope = require_home_scope(request)
    invite = repository.delete_guardian_invite(invite_id, home_id=scope.home_id) if hasattr(repository, "delete_guardian_invite") else None
    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "GUARDIAN_INVITE_404", "message": "삭제할 보호자 초대를 찾을 수 없습니다."},
        )
    return success_response(invite)


@app.patch(f"{API_PREFIX}/notifications/{{notification_id}}/read")
def mark_notification_read(notification_id: str, request: Request) -> dict[str, Any]:
    scope = require_home_scope(request)
    notification = repository.mark_notification_read(notification_id, home_id=scope.home_id)
    if notification is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOTIFICATION_404", "message": "알림을 찾을 수 없습니다."},
        )
    return success_response(sanitize_public_notification(notification))


@app.get(f"{API_PREFIX}/ml/metrics")
def ml_metrics() -> dict[str, Any]:
    """학습된 모델의 F1/precision/recall/ROC-AUC 등 metrics 노출.

    학습된 모델이 없으면 ``available=False`` 와 안내 메시지를 반환.
    """
    metrics = ml_model_metrics()
    if metrics is None:
        return success_response(
            {
                "available": False,
                "message": "학습된 모델이 없습니다. ml/training/train.py 를 먼저 실행해 주세요.",
            }
        )
    return success_response({"available": True, "metrics": metrics})


@app.post(f"{API_PREFIX}/ml/predict")
def ml_predict(request: MlPredictRequest) -> dict[str, Any]:
    """단일 기기 정보에 대해 학습된 모델로 공격 확률을 추정.

    모델이 없으면 ``available=False`` 와 0.0 확률을 반환해 클라이언트가 안전하게 폴백.
    """
    device_payload = request.model_dump()
    prediction = predict_attack_probability(device_payload)
    if prediction is None:
        return success_response(
            {
                "available": False,
                "attack_probability": 0.0,
                "feature_vector": device_feature_vector(device_payload),
                "message": "학습된 모델이 없거나 입력 차원이 맞지 않습니다.",
            }
        )
    return success_response(
        {
            "available": True,
            "model": prediction.model,
            "attack_probability": round(prediction.attack_probability, 4),
            "feature_vector": device_feature_vector(device_payload),
        }
    )
