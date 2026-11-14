"""저장소 진입점.

- ``DATABASE_URL`` 환경변수가 PostgreSQL 또는 SQLAlchemy URL 이면 ``SqlAlchemyRepository`` 사용.
- 그 외에는 기본 SQLite 단일 파일 repository (``SQLiteRepository``).

운영 전환 가이드:
1. PostgreSQL 인스턴스 준비, ``psql $DATABASE_URL -f Home_Guardian/backend/app/storage/postgres_schema.sql`` 로 스키마 적용.
2. ``DATABASE_URL=postgresql+psycopg://user:pass@host:5432/dbname`` 환경변수 export.
3. 서버 재시작. ``SqlAlchemyRepository`` 가 자동 활성화된다.
"""

from __future__ import annotations

import os


def _make_repository():
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url.startswith(("postgresql://", "postgresql+psycopg://", "sqlite+pysqlite://", "sqlite+aiosqlite://")):
        from .sa_repository import SqlAlchemyRepository

        # PostgreSQL URL 은 SQLAlchemy 가 psycopg 드라이버를 직접 인식하지 못할 수 있어 보정.
        if database_url.startswith("postgresql://"):
            database_url = "postgresql+psycopg://" + database_url[len("postgresql://"):]
        return SqlAlchemyRepository(database_url)
    from .sqlite_repository import SQLiteRepository

    return SQLiteRepository()


repository = _make_repository()

__all__ = ["repository"]
