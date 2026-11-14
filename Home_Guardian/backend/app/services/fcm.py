"""FCM(Firebase Cloud Messaging) push 발송 wrapper.

``FIREBASE_CREDENTIALS`` 환경변수가 JSON service account 파일 경로를 가리키면
firebase-admin SDK 로 실제 push 를 보낸다. 공개 API에는 발송 성공/실패 개수만
반환한다. 공급자 오류·토큰·자격증명 정보는 공개 결과와 로그 모두에 싣지 않는다.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

_initialized = False
_init_lock = threading.Lock()
_messaging_module: Any = None
_LOGGER = logging.getLogger("home_guardian.fcm")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,79}$")
_SAFE_FCM_ERROR_CODES = frozenset(
    {
        "INVALID_ARGUMENT",
        "INTERNAL",
        "QUOTA_EXCEEDED",
        "SENDER_ID_MISMATCH",
        "THIRD_PARTY_AUTH_ERROR",
        "UNAVAILABLE",
        "UNREGISTERED",
    }
)


@dataclass(frozen=True)
class PushResult:
    ok: bool
    invalid_token: bool = False


def _safe_identifier(value: object, fallback: str) -> str:
    text = str(value or "").strip()
    return text if _SAFE_IDENTIFIER.fullmatch(text) else fallback


def _safe_error_code(error: Exception) -> str | None:
    """Return only a controlled provider error code, never an exception message."""
    code = getattr(error, "code", None)
    if isinstance(code, str):
        normalized = code.strip().upper()
        if normalized in _SAFE_FCM_ERROR_CODES:
            return normalized
    return None


def _is_unregistered_error(error: Exception) -> bool:
    """Identify a permanently invalid registration token without exposing it.

    Firebase Admin currently raises ``UnregisteredError`` for this condition,
    while test doubles and some SDK versions expose the provider code instead.
    Supporting both shapes keeps token cleanup stable across SDK upgrades.
    """
    return _safe_error_code(error) == "UNREGISTERED" or type(error).__name__ == "UnregisteredError"


def _log_fcm_failure(operation: str, error: Exception) -> None:
    """Keep operational diagnosis without emitting a token, secret, or raw provider text."""
    fields = {
        "operation": _safe_identifier(operation, "unknown"),
        "error_type": _safe_identifier(type(error).__name__, "UnknownError"),
    }
    code = _safe_error_code(error)
    if code:
        fields["provider_code"] = code
    _LOGGER.warning("FCM delivery failure: %s", fields)


def _public_delivery_count(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def public_delivery_summary(
    result: Mapping[str, object] | None = None,
    *,
    sent: object = 0,
    failed: object = 0,
) -> dict[str, int]:
    """Project every delivery outcome to the stable resident-facing API contract.

    Only counts are public. This intentionally strips provider modes, exception
    text, token fragments, message IDs, and asynchronous implementation detail.
    """
    if isinstance(result, Mapping):
        sent = result.get("sent", 0)
        failed = result.get("failed", 0)
    return {"sent": _public_delivery_count(sent), "failed": _public_delivery_count(failed)}


def _initialize_admin() -> bool:
    global _initialized, _messaging_module
    if _initialized:
        return _messaging_module is not None

    with _init_lock:
        if _initialized:
            return _messaging_module is not None
        _initialized = True
        credentials_path = os.environ.get("FIREBASE_CREDENTIALS")
        if not credentials_path or not os.path.exists(credentials_path):
            return False
        try:
            import firebase_admin  # type: ignore[import-not-found]
            from firebase_admin import credentials, messaging  # type: ignore[import-not-found]
        except Exception as error:
            _log_fcm_failure("sdk_import", error)
            return False
        try:
            if not firebase_admin._apps:
                firebase_admin.initialize_app(credentials.Certificate(credentials_path))
            _messaging_module = messaging
            return True
        except Exception as error:
            _log_fcm_failure("initialization", error)
            return False


def is_configured() -> bool:
    return _initialize_admin()


def send_push(token: str, title: str, body: str, data: dict[str, str] | None = None) -> PushResult:
    if not _initialize_admin() or _messaging_module is None:
        _LOGGER.warning("FCM delivery unavailable: provider initialization did not complete")
        return PushResult(ok=False)
    try:
        message = _messaging_module.Message(
            token=token,
            notification=_messaging_module.Notification(title=title, body=body),
            data=data or {},
            android=_messaging_module.AndroidConfig(
                priority="high",
                notification=_messaging_module.AndroidNotification(channel_id="home-guardian-default"),
            ),
        )
        _messaging_module.send(message)
        return PushResult(ok=True)
    except Exception as error:  # pragma: no cover - 실제 SDK/네트워크 오류
        _log_fcm_failure("send", error)
        return PushResult(ok=False, invalid_token=_is_unregistered_error(error))


def broadcast(
    tokens: list[str],
    title: str,
    body: str,
    data: dict[str, str] | None = None,
    *,
    on_invalid_token: Callable[[str], object] | None = None,
) -> dict[str, int]:
    if not tokens:
        return public_delivery_summary()
    if not _initialize_admin():
        _LOGGER.warning("FCM broadcast unavailable: requested_count=%d", len(tokens))
        return public_delivery_summary(failed=len(tokens))
    sent = 0
    failed = 0
    for token in tokens:
        result = send_push(token, title, body, data)
        if result.ok:
            sent += 1
        else:
            failed += 1
            if result.invalid_token and on_invalid_token is not None:
                try:
                    on_invalid_token(token)
                except Exception as error:  # pragma: no cover - 저장소 I/O 오류
                    _log_fcm_failure("invalid_token_cleanup", error)
    return public_delivery_summary(sent=sent, failed=failed)
