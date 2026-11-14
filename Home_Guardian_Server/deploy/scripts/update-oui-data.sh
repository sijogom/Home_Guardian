#!/usr/bin/env bash
# IEEE registration database validator/updater. A valid existing database is
# never replaced in place: all three official sources are downloaded, strictly
# validated, merged and renamed on the target filesystem.

set -euo pipefail
umask 027

MA_L_URL="${HG_OUI_MA_L_URL:-https://standards-oui.ieee.org/oui/oui.csv}"
MA_M_URL="${HG_OUI_MA_M_URL:-https://standards-oui.ieee.org/oui28/mam.csv}"
MA_S_URL="${HG_OUI_MA_S_URL:-https://standards-oui.ieee.org/oui36/oui36.csv}"
TARGET="${HG_OUI_TARGET:-/srv/home-guardian/Home_Guardian/backend/app/data/oui.csv}"
SHA256_RECORD="${HG_OUI_SHA256_RECORD:-/srv/home-guardian/runtime/oui-data.sha256}"
SERVICE="${HG_OUI_SERVICE:-home-guardian-api}"
NO_RESTART=0
DEPLOY_LOCK_HELD=0

fail() {
  echo "[oui-update] ERROR: $*" >&2
  exit 1
}

validate_safe_absolute_file() {
  local value="$1" label="$2"
  case "${value}" in
    /*) ;;
    *) fail "${label} must be an absolute path: ${value}" ;;
  esac
  case "/${value#/}/" in
    *'/../'*|*'/./'*|*'//'*) fail "unsafe ${label}: ${value}" ;;
  esac
  [ "${value%/}" != '/' ] || fail "${label} is too broad"
}

validate_https_url() {
  case "$1" in
    https://standards-oui.ieee.org/*) ;;
    *) fail "IEEE registry URL must use the official HTTPS host: $1" ;;
  esac
}

# Accept either the prior valid MA-L-only file (carry-forward compatibility) or
# the new complete MA-L/MA-M/MA-S integrated file. New downloads are checked by
# validate_integrated_oui_file and can never regress to MA-L only.
validate_oui_file() {
  python3 - "$1" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_lengths = {"MA-L": 6, "MA-M": 7, "MA-S": 9}
minimum_rows = {"MA-L": 30_000, "MA-M": 4_000, "MA-S": 5_000}
try:
    if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("missing or oversized")
    counts = {key: 0 for key in expected_lengths}
    seen = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        if header[:4] != ["Registry", "Assignment", "Organization Name", "Organization Address"]:
            raise ValueError("header")
        for line_number, row in enumerate(reader, 2):
            if len(row) < 4:
                raise ValueError(f"short row {line_number}")
            registry = row[0].strip().upper()
            assignment = row[1].strip().upper().replace(":", "").replace("-", "")
            organization = row[2].strip()
            if registry not in expected_lengths:
                raise ValueError(f"registry {line_number}")
            if len(assignment) != expected_lengths[registry] or any(c not in "0123456789ABCDEF" for c in assignment):
                raise ValueError(f"assignment {line_number}")
            if not organization or "\x00" in organization:
                raise ValueError(f"organization {line_number}")
            key = (registry, assignment)
            if key in seen:
                # IEEE's official MA-L CSV contains a small number of historic
                # conflicting reassignments (for example 080030).  They are
                # valid source rows, but must not inflate the minimum-count
                # gate or become an arbitrary manufacturer decision.
                continue
            seen.add(key)
            counts[registry] += 1
    present = {registry for registry, count in counts.items() if count}
    if present == {"MA-L"}:
        if counts["MA-L"] < minimum_rows["MA-L"]:
            raise ValueError("legacy count")
    elif present == set(expected_lengths):
        if any(counts[key] < minimum_rows[key] for key in expected_lengths):
            raise ValueError("integrated counts")
    else:
        raise ValueError("incomplete registry set")
except (OSError, UnicodeError, csv.Error, ValueError, StopIteration):
    raise SystemExit(1)
PY
}

validate_integrated_oui_file() {
  python3 - "$1" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_lengths = {"MA-L": 6, "MA-M": 7, "MA-S": 9}
minimum_rows = {"MA-L": 30_000, "MA-M": 4_000, "MA-S": 5_000}
try:
    counts = {key: 0 for key in expected_lengths}
    seen = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        if next(reader)[:4] != ["Registry", "Assignment", "Organization Name", "Organization Address"]:
            raise ValueError("header")
        for line_number, row in enumerate(reader, 2):
            if len(row) < 4:
                raise ValueError(f"short row {line_number}")
            registry = row[0].strip().upper()
            assignment = row[1].strip().upper().replace(":", "").replace("-", "")
            if registry not in expected_lengths or len(assignment) != expected_lengths[registry]:
                raise ValueError(f"registry/length {line_number}")
            if any(c not in "0123456789ABCDEF" for c in assignment) or not row[2].strip():
                raise ValueError(f"content {line_number}")
            key = (registry, assignment)
            if key in seen:
                raise ValueError(f"duplicate {line_number}")
            seen.add(key)
            counts[registry] += 1
    if any(counts[key] < minimum_rows[key] for key in expected_lengths):
        raise ValueError("counts")
except (OSError, UnicodeError, csv.Error, ValueError, StopIteration):
    raise SystemExit(1)
PY
}

validate_registry_source() {
  local path="$1" expected_registry="$2" expected_length="$3" minimum_rows="$4"
  python3 - "${path}" "${expected_registry}" "${expected_length}" "${minimum_rows}" <<'PY'
import csv
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
expected_registry = sys.argv[2]
expected_length = int(sys.argv[3])
minimum_rows = int(sys.argv[4])
try:
    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("missing or oversized")
    count = 0
    seen = set()
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        if next(reader)[:4] != ["Registry", "Assignment", "Organization Name", "Organization Address"]:
            raise ValueError("header")
        for line_number, row in enumerate(reader, 2):
            if len(row) < 4 or row[0].strip().upper() != expected_registry:
                raise ValueError(f"registry {line_number}")
            assignment = row[1].strip().upper().replace(":", "").replace("-", "")
            if len(assignment) != expected_length or any(c not in "0123456789ABCDEF" for c in assignment):
                raise ValueError(f"assignment {line_number}")
            if not row[2].strip() or "\x00" in row[2]:
                raise ValueError(f"organization {line_number}")
            if assignment in seen:
                # Official IEEE source files may retain historic duplicate
                # assignments.  The merge step below omits conflicting keys.
                continue
            seen.add(assignment)
            count += 1
    if count < minimum_rows:
        raise ValueError("count")
except (OSError, UnicodeError, csv.Error, ValueError, StopIteration):
    raise SystemExit(1)
PY
}

if [ "${1:-}" = '--validate-file' ]; then
  [ "$#" -eq 2 ] || fail 'usage: update-oui-data.sh --validate-file <path>'
  validate_oui_file "$2" || fail "invalid OUI file: $2"
  exit 0
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-restart) NO_RESTART=1 ;;
    --deploy-lock-held) DEPLOY_LOCK_HELD=1 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift
done

validate_safe_absolute_file "${TARGET}" target
validate_safe_absolute_file "${SHA256_RECORD}" sha256_record
validate_https_url "${MA_L_URL}"
validate_https_url "${MA_M_URL}"
validate_https_url "${MA_S_URL}"
TARGET_DIR="$(dirname "${TARGET}")"
RECORD_DIR="$(dirname "${SHA256_RECORD}")"
mkdir -p "${TARGET_DIR}" "${RECORD_DIR}"
chmod 0750 "${TARGET_DIR}" "${RECORD_DIR}"

if [ "${DEPLOY_LOCK_HELD}" -eq 0 ]; then
  DEPLOY_LOCK_FILE="${HG_DEPLOY_LOCK_FILE:-/srv/home-guardian/.deploy.lock}"
  mkdir -p "$(dirname "${DEPLOY_LOCK_FILE}")"
  exec 8>"${DEPLOY_LOCK_FILE}"
  chmod 0640 "${DEPLOY_LOCK_FILE}"
  if ! flock -w 30 8; then
    fail "could not acquire deployment lock: ${DEPLOY_LOCK_FILE}"
  fi
fi

LOCK_FILE="${HG_OUI_LOCK_FILE:-/srv/home-guardian/.oui-update.lock}"
mkdir -p "$(dirname "${LOCK_FILE}")"
exec 9>"${LOCK_FILE}"
chmod 0640 "${LOCK_FILE}"
if ! flock -w 30 9; then
  fail "could not acquire OUI update lock: ${LOCK_FILE}"
fi

EXISTING_VALID=0
if validate_oui_file "${TARGET}"; then EXISTING_VALID=1; fi

TMP_DIR="$(mktemp -d "${TARGET_DIR}/.oui-download.XXXXXX")"
RECORD_TMP="$(mktemp "${RECORD_DIR}/.oui-data.sha256.XXXXXX")"
cleanup() { rm -rf "${TMP_DIR}"; rm -f "${RECORD_TMP}"; }
trap cleanup EXIT
chmod 0750 "${TMP_DIR}"
chmod 0640 "${RECORD_TMP}"

fallback_or_fail() {
  if [ "${EXISTING_VALID}" -eq 1 ]; then
    echo "[oui-update] $1 — 검증된 기존 OUI 유지"
    exit 0
  fi
  fail "$1 and no valid existing OUI is available"
}

download_registry() {
  local registry="$1" url="$2" output="$3" prefix_length="$4" minimum_rows="$5"
  echo "[oui-update] $(date -Is) IEEE ${registry} 다운로드"
  # Redirects are intentionally not followed: every byte must come directly
  # from the allowlisted IEEE host above, not an arbitrary HTTPS redirect.
  curl --proto '=https' --tlsv1.2 -fsS \
    --retry 2 --max-time 180 --max-filesize 33554432 "${url}" -o "${output}" || return 1
  validate_registry_source "${output}" "${registry}" "${prefix_length}" "${minimum_rows}"
}

MA_L_FILE="${TMP_DIR}/ma-l.csv"
MA_M_FILE="${TMP_DIR}/ma-m.csv"
MA_S_FILE="${TMP_DIR}/ma-s.csv"
if ! download_registry MA-L "${MA_L_URL}" "${MA_L_FILE}" 6 30000; then
  fallback_or_fail 'MA-L download or validation failed'
fi
if ! download_registry MA-M "${MA_M_URL}" "${MA_M_FILE}" 7 4000; then
  fallback_or_fail 'MA-M download or validation failed'
fi
if ! download_registry MA-S "${MA_S_URL}" "${MA_S_FILE}" 9 5000; then
  fallback_or_fail 'MA-S download or validation failed'
fi

MERGED="${TMP_DIR}/oui.csv"
python3 - "${MA_L_FILE}" "${MA_M_FILE}" "${MA_S_FILE}" "${MERGED}" <<'PY'
import csv
import pathlib
import sys

sources = [pathlib.Path(value) for value in sys.argv[1:4]]
target = pathlib.Path(sys.argv[4])
unique_rows = {}
ambiguous = set()
for source in sources:
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        next(reader)
        for row in reader:
            registry = row[0].strip().upper()
            assignment = row[1].strip().upper().replace(":", "").replace("-", "")
            organization = row[2].strip()
            key = (registry, assignment)
            if key in ambiguous:
                continue
            previous = unique_rows.get(key)
            if previous is None:
                unique_rows[key] = row
            elif previous[2].strip() != organization:
                # A historic prefix with more than one organization is not a
                # safe manufacturer fact.  Omit every conflicting row rather
                # than selecting whichever happens to occur last.
                unique_rows.pop(key, None)
                ambiguous.add(key)

with target.open("w", encoding="utf-8", newline="") as output:
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["Registry", "Assignment", "Organization Name", "Organization Address"])
    registry_order = {"MA-L": 0, "MA-M": 1, "MA-S": 2}
    # IEEE's generated CSV row order can differ between otherwise equivalent
    # downloads.  Stable ordering prevents a no-op refresh from restarting the
    # API solely because the source rows arrived in another order.
    writer.writerows(
        row[:3] + [""]  # 기기 식별에 불필요한 주소·연락처는 저장하지 않는다.
        for _, row in sorted(
            unique_rows.items(),
            key=lambda item: (registry_order[item[0][0]], item[0][1]),
        )
    )
print(f"[oui-update] ambiguous IEEE assignments omitted: {len(ambiguous)}")
PY
validate_integrated_oui_file "${MERGED}" || fallback_or_fail 'integrated OUI validation failed'

{
  printf '# Home Guardian local digest record; IEEE does not publish checksums for these CSV endpoints.\n'
  printf '# generated_at=%s\n' "$(date -Is)"
  printf '%s\tMA-L\t%s\n' "$(sha256sum "${MA_L_FILE}" | awk '{print $1}')" "${MA_L_URL}"
  printf '%s\tMA-M\t%s\n' "$(sha256sum "${MA_M_FILE}" | awk '{print $1}')" "${MA_M_URL}"
  printf '%s\tMA-S\t%s\n' "$(sha256sum "${MA_S_FILE}" | awk '{print $1}')" "${MA_S_URL}"
  printf '%s\tINTEGRATED\t%s\n' "$(sha256sum "${MERGED}" | awk '{print $1}')" "${TARGET}"
} > "${RECORD_TMP}"

if [ "${EXISTING_VALID}" -eq 1 ] && cmp -s "${MERGED}" "${TARGET}"; then
  mv -f "${RECORD_TMP}" "${SHA256_RECORD}"
  trap - EXIT
  rm -rf "${TMP_DIR}"
  echo '[oui-update] 변경 없음 — 기존 OUI 유지, SHA-256 기록 갱신'
  exit 0
fi

TARGET_UID="$(stat -c '%u' "${TARGET_DIR}")"
TARGET_GID="$(stat -c '%g' "${TARGET_DIR}")"
RECORD_UID="$(stat -c '%u' "${RECORD_DIR}")"
RECORD_GID="$(stat -c '%g' "${RECORD_DIR}")"
chown "${TARGET_UID}:${TARGET_GID}" "${MERGED}"
chown "${RECORD_UID}:${RECORD_GID}" "${RECORD_TMP}"
chmod 0640 "${MERGED}" "${RECORD_TMP}"
sync -f "${MERGED}" 2>/dev/null || true
mv -f "${MERGED}" "${TARGET}"
mv -f "${RECORD_TMP}" "${SHA256_RECORD}"
trap - EXIT
rm -rf "${TMP_DIR}"
chmod 0640 "${TARGET}" "${SHA256_RECORD}"
echo "[oui-update] atomic update 완료: $(wc -l < "${TARGET}" | tr -d '[:space:]') rows"

if [ "${NO_RESTART}" -eq 0 ] && systemctl is-active --quiet "${SERVICE}"; then
  systemctl restart "${SERVICE}"
  API_READY=0
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if systemctl is-active --quiet "${SERVICE}" && \
       curl -fsS --max-time 2 'http://127.0.0.1:8010/health' >/dev/null; then
      API_READY=1
      break
    fi
    sleep 1
  done
  [ "${API_READY}" -eq 1 ] || fail "${SERVICE} health did not recover after OUI update"
  echo "[oui-update] ${SERVICE} health 복구 완료"
fi
