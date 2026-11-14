from __future__ import annotations

import logging

from app.services import fcm


class _ProviderFailure(RuntimeError):
    code = "UNREGISTERED"


class _FailingMessaging:
    class Message:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class Notification:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class AndroidConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class AndroidNotification:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    @staticmethod
    def send(_message):
        raise _ProviderFailure("provider rejected token=fcm-secret-token-should-never-appear-in-output")


def test_broadcast_returns_counts_only_and_redacts_provider_failure_from_logs(monkeypatch, caplog):
    token = "fcm-secret-token-should-never-appear-in-output"
    removed_tokens: list[str] = []
    monkeypatch.setattr(fcm, "_initialize_admin", lambda: True)
    monkeypatch.setattr(fcm, "_messaging_module", _FailingMessaging)

    with caplog.at_level(logging.WARNING, logger="home_guardian.fcm"):
        result = fcm.broadcast(
            tokens=[token],
            title="검사 완료",
            body="일반 사용자용 알림",
            data={"scan_id": "scan-safe"},
            on_invalid_token=removed_tokens.append,
        )

    assert result == {"sent": 0, "failed": 1}
    assert set(result) == {"sent", "failed"}
    assert token not in str(result)
    assert "provider rejected" not in str(result)
    assert token not in caplog.text
    assert "provider rejected" not in caplog.text
    assert "_ProviderFailure" in caplog.text
    assert "UNREGISTERED" in caplog.text
    assert removed_tokens == [token]


def test_broadcast_does_not_remove_token_for_transient_provider_failure(monkeypatch):
    class _TransientFailure(RuntimeError):
        code = "UNAVAILABLE"

    class _TransientMessaging(_FailingMessaging):
        @staticmethod
        def send(_message):
            raise _TransientFailure("temporary provider failure")

    removed_tokens: list[str] = []
    monkeypatch.setattr(fcm, "_initialize_admin", lambda: True)
    monkeypatch.setattr(fcm, "_messaging_module", _TransientMessaging)

    result = fcm.broadcast(
        tokens=["temporary-token"],
        title="검사 완료",
        body="일반 사용자용 알림",
        on_invalid_token=removed_tokens.append,
    )

    assert result == {"sent": 0, "failed": 1}
    assert removed_tokens == []


def test_public_delivery_summary_strips_untrusted_provider_fields():
    token_suffix = "private-token-tail"
    result = fcm.public_delivery_summary(
        {
            "ok": False,
            "mode": "firebase-admin",
            "sent": "2",
            "failed": 1,
            "pending": 3,
            "failures": [{"token": token_suffix, "error": "provider exception"}],
        }
    )

    assert result == {"sent": 2, "failed": 1}
    assert token_suffix not in str(result)
