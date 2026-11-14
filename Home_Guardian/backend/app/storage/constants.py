from __future__ import annotations

import hashlib

HOME = {
    # Repository callers must provide an authenticated home scope.  The empty
    # value exists only for backwards-compatible optional method signatures;
    # initialization never inserts it and API authentication never issues it.
    "home_id": "",
    "name": "우리집",
    "mode": "basic",
}


def default_home_id_for_user(user_id: str | None) -> str:
    """Return a stable per-user home id without exposing the raw account id."""
    normalized = str(user_id or "").strip()
    if not normalized:
        raise ValueError("user_id is required")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"home-{digest}"
