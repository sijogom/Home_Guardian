#!/usr/bin/env bash
# Home Guardian — 운영 SQLite DB 일일 백업 (온라인 백업 + 최근 14개 보관)
# systemd timer(home-guardian-db-backup.timer)가 매일 실행한다.
# SD카드 손상/파일 깨짐 시 사용자·보호자 연결 데이터를 복구할 수 있게 한다.
set -euo pipefail
umask 027

DB="${HOME_GUARDIAN_DB_PATH:-/srv/home-guardian/runtime/home_guardian.sqlite3}"
BACKUP_DIR="/srv/home-guardian/runtime/backups"
KEEP=14

mkdir -p "$BACKUP_DIR"
chmod 0750 "$BACKUP_DIR"
LOCK_FILE="/srv/home-guardian/.db-backup.lock"
if [ ! -f "$LOCK_FILE" ] || [ -L "$LOCK_FILE" ]; then
  echo "[db-backup] 안전한 배포 잠금 파일이 없습니다: $LOCK_FILE" >&2
  exit 1
fi
exec 9<"$LOCK_FILE"
if ! flock -w 30 9; then
  echo "[db-backup] 다른 백업/배포가 DB 백업 잠금을 사용 중입니다." >&2
  exit 1
fi
if [ ! -f "$DB" ]; then
  echo "[db-backup] DB 파일 없음(아직 데이터 없음): $DB"
  exit 0
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_ID="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
DEST="$BACKUP_DIR/home_guardian-${TS}-${BACKUP_ID}.sqlite3"
PARTIAL="${DEST}.partial"
GZIP_PARTIAL="${DEST}.gz.partial"
cleanup() { rm -f "$PARTIAL" "$GZIP_PARTIAL"; }
trap cleanup EXIT

# 온라인 백업(sqlite3 .backup): WAL/동시 쓰기 중에도 일관된 스냅샷을 만든다(잠금 안전).
python3 - "$DB" "$PARTIAL" <<'PYEOF'
import os
import sqlite3
import sys

source_path, backup_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
check = source.execute("PRAGMA quick_check").fetchall()
if check != [("ok",)]:
    raise SystemExit(f"source quick_check failed: {check!r}")
backup = sqlite3.connect(backup_path)
with backup:
    source.backup(backup)
check = backup.execute("PRAGMA integrity_check").fetchall()
backup.close()
source.close()
if check != [("ok",)]:
    raise SystemExit(f"backup integrity_check failed: {check!r}")
os.chmod(backup_path, 0o640)
PYEOF

gzip -c "$PARTIAL" > "$GZIP_PARTIAL"
chmod 0640 "$GZIP_PARTIAL"
mv -f "$GZIP_PARTIAL" "${DEST}.gz"
rm -f "$PARTIAL"
trap - EXIT
echo "[db-backup] $(date -Is) 백업 완료: ${DEST}.gz"

# 보관 정책: 최신 KEEP 개만 남기고 오래된 백업 삭제.
ls -1t "$BACKUP_DIR"/home_guardian-*.sqlite3.gz 2>/dev/null | tail -n +$((KEEP + 1)) | xargs -r rm -f
