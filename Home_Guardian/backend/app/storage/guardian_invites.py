from __future__ import annotations

import secrets
import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

INVITE_TTL_DAYS = 14
INVITE_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
GUARDIAN_SESSION_TOKEN_BYTES = 32
STATUS_LABELS = {
    "pending": "초대 대기",
    "accepted": "연결됨",
    "expired": "만료",
    "revoked": "초대 취소",
}
GENERIC_WARD_DISPLAY_NAMES = {"", "보호자", "가족", "이웃", "친구", "도우미", "보호 대상", "피보호자"}


def utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc_text(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).strip()
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def invite_expires_at(created_at: str | None = None) -> str:
    base = parse_utc_text(created_at) or datetime.now(UTC)
    return utc_text(base + timedelta(days=INVITE_TTL_DAYS))


def generate_short_code(existing_codes: set[str] | None = None) -> str:
    existing = existing_codes or set()
    for _ in range(100):
        raw = "".join(secrets.choice(INVITE_CODE_ALPHABET) for _ in range(8))
        code = f"{raw[:4]}-{raw[4:]}"
        if code not in existing:
            return code
    raise RuntimeError("고유한 보호자 초대 코드를 만들지 못했습니다.")


def build_deep_link(short_code: str) -> str:
    return f"homeguardian://join?invite={short_code}"


def generate_guardian_session_token() -> str:
    return secrets.token_urlsafe(GUARDIAN_SESSION_TOKEN_BYTES)


def hash_guardian_session_token(token: str | None) -> str:
    text = str(token or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def default_display_name(email: str | None, relation: str | None) -> str:
    relation_text = str(relation or "").strip()
    if relation_text:
        return relation_text
    local_part = str(email or "").split("@", 1)[0].strip()
    return local_part or "보호자"


def clean_optional_name(value: Any, max_length: int = 80) -> str | None:
    text = " ".join(str(value or "").strip().split())
    if not text:
        return None
    return text[:max_length]


def is_generic_ward_display_name(value: Any) -> bool:
    text = clean_optional_name(value) or ""
    return text in GENERIC_WARD_DISPLAY_NAMES


def normalize_invite_lookup(value: str | None) -> str:
    if not value:
        return ""
    text = unquote(str(value).strip())
    parsed = urlparse(text)
    query = parse_qs(parsed.query)
    for key in ("invite", "code", "invite_id"):
        if query.get(key):
            text = query[key][0]
            break
    text = text.strip()
    compact = "".join(ch for ch in text.upper() if ch.isalnum())
    if len(compact) == 8:
        return f"{compact[:4]}-{compact[4:]}"
    return text


def effective_invite_status(invite: dict[str, Any], now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    raw_status = str(invite.get("status") or "pending").strip().lower()
    if invite.get("revoked_at") or raw_status == "revoked":
        return "revoked"
    if invite.get("accepted_at") or raw_status == "accepted":
        return "accepted"
    expires_at = parse_utc_text(invite.get("expires_at"))
    if expires_at and expires_at < current:
        return "expired"
    if raw_status in {"pending", "sent"}:
        return "pending"
    return raw_status if raw_status in STATUS_LABELS else "pending"


def normalize_guardian_invite(invite: dict[str, Any]) -> dict[str, Any]:
    data = dict(invite)
    data.pop("guardian_token_hash", None)
    data.pop("session_created_at", None)
    data.pop("session_last_used_at", None)
    short_code = str(data.get("short_code") or "").strip().upper()
    data["short_code"] = short_code
    data["display_name"] = data.get("display_name") or default_display_name(data.get("email"), data.get("relation"))
    data["ward_account_name"] = clean_optional_name(data.get("ward_account_name"))
    data["expires_at"] = data.get("expires_at") or invite_expires_at(data.get("created_at"))
    data["accepted_at"] = data.get("accepted_at")
    data["revoked_at"] = data.get("revoked_at")
    data["last_viewed_at"] = data.get("last_viewed_at")
    data["deep_link"] = data.get("deep_link") or (build_deep_link(short_code) if short_code else "")
    data["status"] = effective_invite_status(data)
    data["status_label"] = STATUS_LABELS[data["status"]]
    return data


def guardian_invite_summary(invites: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(invites), "pending": 0, "accepted": 0, "expired": 0, "revoked": 0}
    for invite in invites:
        status = effective_invite_status(invite)
        if status in summary:
            summary[status] += 1
    return summary
