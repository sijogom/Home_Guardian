import os
import sqlite3
import tempfile

import pytest

from app.services.device_presentation import apply_device_presentation
from app.storage.sqlite_repository import HOME, SQLiteRepository, normalize_observed_device


def _temp_repo() -> tuple[SQLiteRepository, str]:
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    return SQLiteRepository(path), path


def test_device_alias_without_verified_observation_stays_private():
    repo, path = _temp_repo()
    try:
        repo.set_device_alias("dev-x", "우리집 카메라")
        assert repo._device_alias_map() == {"dev-x": "우리집 카메라"}

        applied = repo._apply_aliases(
            [{"device_id": "dev-x", "name": "삼성 카메라 (SNV-5080)"}], HOME["home_id"]
        )
        assert applied[0]["name"] == "삼성 카메라 (SNV-5080)"
        assert "alias" not in applied[0]

        # 다른 기기는 영향 없음
        other = repo._apply_aliases([{"device_id": "dev-y", "name": "삼성 냉장고 (RF85C90)"}], HOME["home_id"])
        assert other[0]["name"] == "삼성 냉장고 (RF85C90)"
        assert "alias" not in other[0]
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_device_alias_clear_removes_override():
    repo, path = _temp_repo()
    try:
        repo.set_device_alias("dev-x", "우리집 냉장고")
        repo.set_device_alias("dev-x", None)
        assert repo._device_alias_map() == {}
        applied = repo._apply_aliases([{"device_id": "dev-x", "name": "삼성 냉장고 (RF85C90)"}], HOME["home_id"])
        assert applied[0]["name"] == "삼성 냉장고 (RF85C90)"
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_repository_connection_context_closes_the_sqlite_connection():
    repo, path = _temp_repo()
    try:
        with repo._connect() as connection:
            connection.execute("SELECT 1")

        with pytest.raises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_normalize_observed_device_keeps_weak_evidence_private_without_a_public_name():
    """OUI나 포트만 있는 신호는 내부 분석용으로 남기고 공개 이름을 저장하지 않는다."""
    samsung = normalize_observed_device(
        {
            "ip_address": "192.168.0.5",
            "mac_address": "64:1B:2F:FE:00:06",
            "device_type": "tv",
            "open_ports": [8001],
            "discovery_sources": ["mdns"],
        },
        "android-native",
    )
    assert samsung["name"] == ""
    assert samsung["is_unresolved"] is True
    assert apply_device_presentation(samsung) is None

    # native 가 "알 수 없는 기기 ..." 를 그대로 보내도 중립 표현으로 교체된다.
    unidentified = normalize_observed_device(
        {
            "ip_address": "192.168.0.9",
            "mac_address": "UNKNOWN-192.168.0.9",
            "name": "알 수 없는 기기 192.168.0.9",
            "open_ports": [80],
            "discovery_sources": ["tcp-port-probe"],
        },
        "android-native",
    )
    assert unidentified["name"] == ""
    assert unidentified["is_unresolved"] is True
    assert apply_device_presentation(unidentified) is None
