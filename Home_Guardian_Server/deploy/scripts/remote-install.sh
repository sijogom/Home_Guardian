#!/usr/bin/env bash
# Home Guardian — Raspberry Pi production release installer

set -euo pipefail
umask 027
exec 2>&1

APP_DIR="${HG_APP_DIR:-/srv/home-guardian}"
SOURCE_DIR="${APP_DIR}/Home_Guardian"
RUNTIME_DIR="${APP_DIR}/runtime"
SERVER_ROOT="${HG_SERVER_ROOT:-/srv/home-guardian-server}"
SERVICE_NAME=home-guardian-api
IDENTITY_RESEARCH_SERVICE_NAME=home-guardian-identity-research
SERVICE_SRC="${SERVER_ROOT}/deploy/systemd/home-guardian-api.service"
SYSTEMD_TARGET=/etc/systemd/system/home-guardian-api.service
AUTH_ENV_FILE=/etc/home-guardian/auth.env
DB_PATH="${RUNTIME_DIR}/home_guardian.sqlite3"
SOURCE_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/source-runtime-files.txt"
SERVER_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/server-runtime-files.txt"
SOURCE_HASH_MANIFEST=.home-guardian-runtime-manifest.sha256
SERVER_HASH_MANIFEST=deploy/runtime-manifest.sha256
OUI_RELATIVE_PATH=backend/app/data/oui.csv

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

validate_safe_absolute_path() {
  local value="$1" label="$2"
  case "${value}" in
    /*) ;;
    *) fail "${label} must be an absolute path: ${value}" ;;
  esac
  case "/${value#/}/" in
    *'/../'*|*'/./'*|*'//'*) fail "${label} contains an unsafe path segment: ${value}" ;;
  esac
  case "${value%/}" in
    ''|'/'|'/srv'|'/home'|'/opt'|'/tmp'|'/var') fail "${label} is too broad: ${value}" ;;
  esac
}

validate_manifest_file() {
  local manifest="$1" label="$2" previous='' entry
  [ -f "${manifest}" ] || fail "${label} manifest is missing: ${manifest}"
  while IFS= read -r entry || [ -n "${entry}" ]; do
    entry="${entry%$'\r'}"
    [ -n "${entry}" ] || continue
    case "${entry}" in
      /*|*/../*|../*|*/..|*/./*|./*|*/.) fail "${label} manifest has an unsafe entry: ${entry}" ;;
    esac
    if ! printf '%s' "${entry}" | grep -Eq '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$'; then
      fail "${label} manifest has an invalid entry: ${entry}"
    fi
    if [ "${entry}" = "${previous}" ]; then
      fail "${label} manifest has a duplicate adjacent entry: ${entry}"
    fi
    previous="${entry}"
  done < <(LC_ALL=C sort "${manifest}")

  if [ "$(sed '/^[[:space:]]*$/d' "${manifest}" | LC_ALL=C sort -u | wc -l)" -ne \
       "$(sed '/^[[:space:]]*$/d' "${manifest}" | wc -l)" ]; then
    fail "${label} manifest contains duplicate entries"
  fi
}

reject_special_payload_nodes() {
  local root="$1" label="$2" special
  special="$(find "${root}" -mindepth 1 -type l -print -quit)"
  [ -z "${special}" ] || fail "${label} payload contains a symlink: ${special}"
  special="$(find "${root}" -mindepth 1 ! -type f ! -type d -print -quit)"
  [ -z "${special}" ] || fail "${label} payload contains a special node: ${special}"
}

compare_exact_file_set() {
  local root="$1" manifest="$2" label="$3" extra_one="${4:-}" extra_two="${5:-}"
  local actual expected
  actual="$(find "${root}" -type f -printf '%P\n' | LC_ALL=C sort)"
  expected="$({
    sed '/^[[:space:]]*$/d' "${manifest}"
    if [ -n "${extra_one}" ]; then printf '%s\n' "${extra_one}"; fi
    if [ -n "${extra_two}" ]; then printf '%s\n' "${extra_two}"; fi
    true
  } | LC_ALL=C sort)"
  if [ "${actual}" != "${expected}" ]; then
    echo "ERROR: ${label} exact runtime manifest mismatch" >&2
    diff -u <(printf '%s\n' "${expected}") <(printf '%s\n' "${actual}") >&2 || true
    exit 1
  fi
}

verify_hash_manifest() {
  local root="$1" manifest_relative="$2" label="$3"
  local manifest="${root}/${manifest_relative}"
  [ -f "${manifest}" ] || fail "${label} SHA256 manifest is missing: ${manifest_relative}"
  if grep -Ev '^[0-9a-f]{64}  [A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$' "${manifest}" | grep -q .; then
    fail "${label} SHA256 manifest has an invalid line"
  fi
  (
    cd "${root}"
    sha256sum --check --strict "${manifest_relative}" >/dev/null
  ) || fail "${label} SHA256 verification failed"
}

verify_oui_file() {
  local path="$1"
  "${SERVER_ROOT}/deploy/scripts/update-oui-data.sh" --validate-file "${path}" >/dev/null
}

verify_clean_source_tree() {
  local root="${1:-${SOURCE_DIR}}" optional_oui=''
  validate_safe_absolute_path "${root}" source_root
  [ -d "${root}" ] || fail "source directory is missing: ${root}"
  validate_manifest_file "${SOURCE_FILE_MANIFEST}" source
  reject_special_payload_nodes "${root}" source
  if [ -f "${root}/${OUI_RELATIVE_PATH}" ]; then
    verify_oui_file "${root}/${OUI_RELATIVE_PATH}" || fail "source OUI file is invalid"
    optional_oui="${OUI_RELATIVE_PATH}"
  fi
  compare_exact_file_set "${root}" "${SOURCE_FILE_MANIFEST}" source "${SOURCE_HASH_MANIFEST}" "${optional_oui}"
  verify_hash_manifest "${root}" "${SOURCE_HASH_MANIFEST}" source
}

verify_clean_server_tree() {
  local root="${1:-${SERVER_ROOT}}"
  validate_safe_absolute_path "${root}" server_root
  [ -d "${root}" ] || fail "server asset directory is missing: ${root}"
  local previous_server_root="${SERVER_ROOT}"
  SERVER_ROOT="${root}"
  SOURCE_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/source-runtime-files.txt"
  SERVER_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/server-runtime-files.txt"
  validate_manifest_file "${SERVER_FILE_MANIFEST}" server
  reject_special_payload_nodes "${root}" server
  compare_exact_file_set "${root}" "${SERVER_FILE_MANIFEST}" server "${SERVER_HASH_MANIFEST}"
  verify_hash_manifest "${root}" "${SERVER_HASH_MANIFEST}" server
  SERVER_ROOT="${previous_server_root}"
  SOURCE_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/source-runtime-files.txt"
  SERVER_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/server-runtime-files.txt"
}

normalize_payload_permissions() {
  local root="$1"
  find "${root}" -type d -exec chmod 0750 {} +
  find "${root}" -type f -exec chmod 0640 {} +
}

critical_env_value() {
  local key="$1" min_length="$2" count line value
  count="$(sudo awk -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { count += 1 }
    END { print count + 0 }
  ' "${AUTH_ENV_FILE}")"
  [ "${count}" -eq 1 ] || fail "${AUTH_ENV_FILE} must define ${key} exactly once (found ${count})"
  line="$(sudo awk -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      print $0
    }
  ' "${AUTH_ENV_FILE}")"
  if ! printf '%s\n' "${line}" | grep -Eq "^${key}=[A-Za-z0-9_./:@+,=~-]+$"; then
    fail "${key} must use one unquoted KEY=value line with no whitespace, comment, or shell escape"
  fi
  value="${line#*=}"
  [ "${#value}" -ge "${min_length}" ] || fail "${key} is missing or shorter than ${min_length} characters"
  printf '%s' "${value}"
}

env_key_count() {
  local key="$1"
  sudo awk -v key="${key}" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*=" { count += 1 }
    END { print count + 0 }
  ' "${AUTH_ENV_FILE}"
}

validate_auth_env_key_allowlist() {
  local invalid_line
  invalid_line="$(sudo awk '
    /^[[:space:]]*($|#)/ { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      key = line
      sub(/=.*/, "", key)
      if (line !~ /^[A-Za-z_][A-Za-z0-9_]*=/ ||
          !(key == "HG_AUTH_TOKEN_SECRET" || key == "GOOGLE_CLIENT_ID" ||
            key == "FIREBASE_CREDENTIALS" || key == "HG_IDENTITY_REVIEW_SECRET" ||
            key == "HG_IDENTITY_AI_RESEARCH_ENABLED" ||
            key == "HG_IDENTITY_RESEARCH_ENABLED" || key == "OPENAI_API_KEY" ||
            key == "HG_IDENTITY_RESEARCH_MODEL")) {
        print NR ":" $0
      }
    }
  ' "${AUTH_ENV_FILE}")"
  [ -z "${invalid_line}" ] || fail "${AUTH_ENV_FILE} contains a non-auth or invalid entry: ${invalid_line}"
}

validate_identity_research_auth() {
  local research_enabled ai_count legacy_count openai_count openai_key model_count research_model
  ai_count="$(env_key_count HG_IDENTITY_AI_RESEARCH_ENABLED)"
  legacy_count="$(env_key_count HG_IDENTITY_RESEARCH_ENABLED)"
  [ "${ai_count}" -le 1 ] || fail 'HG_IDENTITY_AI_RESEARCH_ENABLED must not be duplicated'
  [ "${legacy_count}" -le 1 ] || fail 'HG_IDENTITY_RESEARCH_ENABLED must not be duplicated'
  if [ "${ai_count}" -eq 1 ]; then
    research_enabled="$(critical_env_value HG_IDENTITY_AI_RESEARCH_ENABLED 1)"
    [[ "${research_enabled}" =~ ^(0|1)$ ]] || fail 'HG_IDENTITY_AI_RESEARCH_ENABLED must be 0 or 1'
  elif [ "${legacy_count}" -eq 1 ]; then
    research_enabled="$(critical_env_value HG_IDENTITY_RESEARCH_ENABLED 1)"
    [[ "${research_enabled}" =~ ^(0|1)$ ]] || fail 'HG_IDENTITY_RESEARCH_ENABLED must be 0 or 1'
  else
    # Omitting the optional flag is equivalent to the safe disabled mode.
    research_enabled='0'
  fi

  OPENAI_API_KEY_SHA256=''
  openai_count="$(env_key_count OPENAI_API_KEY)"
  model_count="$(env_key_count HG_IDENTITY_RESEARCH_MODEL)"
  [ "${openai_count}" -le 1 ] || fail 'OPENAI_API_KEY must not be duplicated'
  [ "${model_count}" -le 1 ] || fail 'HG_IDENTITY_RESEARCH_MODEL must not be duplicated'
  if [ "${openai_count}" -eq 1 ]; then
    openai_key="$(critical_env_value OPENAI_API_KEY 1)"
    OPENAI_API_KEY_SHA256="$(printf '%s' "${openai_key}" | sha256sum | awk '{print $1}')"
    unset openai_key
  fi
  if [ "${model_count}" -eq 1 ]; then
    research_model="$(critical_env_value HG_IDENTITY_RESEARCH_MODEL 1)"
  else
    research_model=''
  fi
  if [ "${research_enabled}" = '1' ]; then
    [ "${openai_count}" -eq 1 ] || fail 'enabled identity research requires OPENAI_API_KEY exactly once'
    openai_key="$(critical_env_value OPENAI_API_KEY 20)"
    [[ "${openai_key}" =~ ^sk-[A-Za-z0-9_-]{17,}$ ]] || fail 'OPENAI_API_KEY format is invalid'
    unset openai_key

    [ "${model_count}" -eq 1 ] || fail 'enabled identity research requires HG_IDENTITY_RESEARCH_MODEL exactly once'
    [[ "${research_model}" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$ ]] || fail 'HG_IDENTITY_RESEARCH_MODEL format is invalid'
  fi
  IDENTITY_RESEARCH_ENABLED_EFFECTIVE="${research_enabled}"
  IDENTITY_RESEARCH_MODEL_EFFECTIVE="${research_model}"
}

validate_production_auth() {
  local owner mode forbidden_key auth_secret google_client_id firebase_credentials optional_count
  sudo test -f "${AUTH_ENV_FILE}" || fail "${AUTH_ENV_FILE} is required"
  owner="$(sudo stat -c '%U:%G' "${AUTH_ENV_FILE}")"
  mode="$(sudo stat -c '%a' "${AUTH_ENV_FILE}")"
  [ "${owner}" = 'root:root' ] || fail "${AUTH_ENV_FILE} owner must be root:root"
  [ "${mode}" = '600' ] || fail "${AUTH_ENV_FILE} mode must be 0600"

  validate_auth_env_key_allowlist

  for forbidden_key in HG_ALLOW_TEST_LOGIN HG_ALLOW_TEST_SCOPE ALLOW_DEV_GOOGLE_OAUTH HG_ALLOW_EPHEMERAL_AUTH_SECRET; do
    if sudo grep -Eq "^[[:space:]]*${forbidden_key}[[:space:]]*=" "${AUTH_ENV_FILE}"; then
      fail "${AUTH_ENV_FILE} contains removed development option ${forbidden_key}"
    fi
  done
  if sudo grep -Eq '^[[:space:]]*export[[:space:]]+' "${AUTH_ENV_FILE}"; then
    fail "${AUTH_ENV_FILE} uses shell export syntax that systemd EnvironmentFile does not accept"
  fi

  auth_secret="$(critical_env_value HG_AUTH_TOKEN_SECRET 32)"
  google_client_id="$(critical_env_value GOOGLE_CLIENT_ID 20)"
  firebase_credentials="$(critical_env_value FIREBASE_CREDENTIALS 2)"
  if printf '%s' "${auth_secret}" | grep -Eq '[[:space:]]'; then
    fail 'HG_AUTH_TOKEN_SECRET must not contain whitespace'
  fi
  if printf '%s' "${google_client_id}" | grep -Eq '[[:space:]]'; then
    fail 'GOOGLE_CLIENT_ID must not contain whitespace'
  fi
  if printf '%s' "${firebase_credentials}" | grep -Eq '[[:space:]]'; then
    fail 'FIREBASE_CREDENTIALS must not contain whitespace'
  fi
  if ! printf '%s' "${google_client_id}" | grep -Eq '^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$'; then
    fail 'GOOGLE_CLIENT_ID is not a production Google OAuth client id'
  fi
  [ -n "${auth_secret}" ] || fail 'HG_AUTH_TOKEN_SECRET is empty'
  validate_safe_absolute_path "${firebase_credentials}" firebase_credentials
  case "${firebase_credentials}" in
    /etc/home-guardian/credentials/*.json) ;;
    *) fail 'FIREBASE_CREDENTIALS must be a JSON file in /etc/home-guardian/credentials' ;;
  esac
  [ "$(sudo readlink -f -- "${firebase_credentials}")" = "${firebase_credentials}" ] || \
    fail 'FIREBASE_CREDENTIALS or one of its parent paths is a symlink'
  [ ! -L "${firebase_credentials}" ] || fail 'FIREBASE_CREDENTIALS must not be a symlink'
  sudo test -f "${firebase_credentials}" || fail 'FIREBASE_CREDENTIALS file is missing'
  sudo python3 - "${firebase_credentials}" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
if payload.get("type") != "service_account":
    raise SystemExit("Firebase credential type is not service_account")
for key in ("project_id", "client_email", "private_key"):
    if not str(payload.get(key) or "").strip():
        raise SystemExit(f"Firebase credential is missing {key}")
if "BEGIN PRIVATE KEY" not in payload["private_key"]:
    raise SystemExit("Firebase credential private_key is invalid")
PY
  sudo install -d -o root -g "${SVC_USER}" -m 0750 /etc/home-guardian/credentials
  sudo chown "root:${SVC_USER}" "${firebase_credentials}"
  sudo chmod 0640 "${firebase_credentials}"
  sudo -u "${SVC_USER}" test -r "${firebase_credentials}" || fail 'service user cannot read FIREBASE_CREDENTIALS'

  optional_count="$(env_key_count HG_IDENTITY_REVIEW_SECRET)"
  [ "${optional_count}" -le 1 ] || fail 'HG_IDENTITY_REVIEW_SECRET must not be duplicated'
  if [ "${optional_count}" -eq 1 ]; then
    critical_env_value HG_IDENTITY_REVIEW_SECRET 32 >/dev/null
  fi

  validate_identity_research_auth

  GOOGLE_CLIENT_ID_EFFECTIVE="${google_client_id}"
  FIREBASE_CREDENTIALS_EFFECTIVE="${firebase_credentials}"
  AUTH_SECRET_SHA256="$(printf '%s' "${auth_secret}" | sha256sum | awk '{print $1}')"
}

validate_new_venv() {
  local venv_dir="$1" google_client_id="$2" svc_user="$3" firebase_credentials="$4"
  local validation_db="${RUNTIME_DIR}/.release-validation-${RELEASE_ID}.sqlite3"
  rm -f "${validation_db}" "${validation_db}-wal" "${validation_db}-shm"
  local validation_status=0
  (
    cd "${SOURCE_DIR}"
    sudo -u "${svc_user}" env \
      GOOGLE_CLIENT_ID="${google_client_id}" \
      FIREBASE_CREDENTIALS="${firebase_credentials}" \
      HOME_GUARDIAN_DB_PATH="${validation_db}" \
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH="${SOURCE_DIR}/backend:${SOURCE_DIR}/ml" \
      "${venv_dir}/bin/python" - <<'PY'
import os
import re
import math
import warnings

import fastapi
import firebase_admin
import google.auth.transport.requests
import google.oauth2.id_token
import joblib
import numpy as np
import sklearn
import uvicorn
from firebase_admin import credentials
from backend.app.identity_research_worker import run_identity_research_worker
from backend.app.main import app
from backend.app.services.official_product_lookup import lookup_claimed_official_products
from home_guardian_ml.ml_predictor import predict_attack_probability

client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
if not re.fullmatch(r"[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com", client_id):
    raise SystemExit("effective GOOGLE_CLIENT_ID validation failed")
if getattr(app, "version", None) != "1.0.0":
    raise SystemExit(f"expected app version 1.0.0, got {getattr(app, 'version', None)!r}")
if not callable(predict_attack_probability):
    raise SystemExit("ML inference import is not callable")
if not callable(run_identity_research_worker) or not callable(lookup_claimed_official_products):
    raise SystemExit("identity research worker imports are not callable")
credentials.Certificate(os.environ["FIREBASE_CREDENTIALS"])

if sklearn.__version__ != "1.8.0":
    raise SystemExit(f"unexpected scikit-learn version: {sklearn.__version__}")
warnings.simplefilter("error")
model_root = os.path.join("ml", "training", "output", "lightweight")
for model_name in ("random_forest", "stacking"):
    model = joblib.load(os.path.join(model_root, f"{model_name}.joblib"))
    feature_count = int(getattr(model, "n_features_in_", 0))
    if feature_count != 8:
        raise SystemExit(f"{model_name} feature count mismatch: {feature_count}")
    probability = float(model.predict_proba(np.zeros((1, feature_count), dtype=float))[0][1])
    if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
        raise SystemExit(f"{model_name} prediction is invalid")

selected = predict_attack_probability({"open_ports": [23], "services": ["telnet"], "risk_signals": ["telnet-open"]})
if selected is None or selected.model != "lightweight:stacking":
    raise SystemExit(f"expected stacking inference, got {getattr(selected, 'model', None)!r}")
if not math.isfinite(selected.attack_probability) or not 0.0 <= selected.attack_probability <= 1.0:
    raise SystemExit("stacking inference probability is invalid")
PY
  ) || validation_status=$?
  rm -f "${validation_db}" "${validation_db}-wal" "${validation_db}-shm"
  return "${validation_status}"
}

prepare_versioned_venv() {
  local venv_dir="$1" svc_user="$2"
  [ ! -e "${venv_dir}" ] || fail "versioned venv already exists: ${venv_dir}"
  sudo install -d -o root -g "${svc_user}" -m 0750 "$(dirname "${venv_dir}")"
  sudo install -d -o "${svc_user}" -g "${svc_user}" -m 0750 "${venv_dir}"
  sudo -u "${svc_user}" python3 -m venv "${venv_dir}"
  sudo -u "${svc_user}" "${venv_dir}/bin/python" -m pip install --upgrade pip wheel >/dev/null
  sudo -u "${svc_user}" "${venv_dir}/bin/python" -m pip install -r "${SOURCE_DIR}/requirements.txt"
  sudo -u "${svc_user}" "${venv_dir}/bin/python" -m pip check
  find "${venv_dir}" -type d -exec chmod 0750 {} +
  find "${venv_dir}" -type f -perm /111 -exec chmod 0750 {} +
  find "${venv_dir}" -type f ! -perm /111 -exec chmod 0640 {} +
  sudo chown -R "root:${svc_user}" "${venv_dir}"
  validate_new_venv "${venv_dir}" "${GOOGLE_CLIENT_ID_EFFECTIVE}" "${svc_user}" "${FIREBASE_CREDENTIALS_EFFECTIVE}"
  verify_clean_source_tree "${SOURCE_DIR}"
}

install_systemd_assets() {
  local svc_user="$1" venv_dir="$2" rendered unit
  for unit in home-guardian-api.service home-guardian-identity-research.service home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.service home-guardian-oui-update.timer home-guardian-db-backup.service home-guardian-db-backup.timer; do
    sudo rm -f "/etc/systemd/system/${unit}"
    sudo rm -rf "/etc/systemd/system/${unit}.d"
  done
  rendered="$(mktemp)"
  sed \
    -e "s|__HG_RPI_USER__|${svc_user}|g" \
    -e "s|__HG_VENV_DIR__|${venv_dir}|g" \
    "${SERVICE_SRC}" > "${rendered}"
  sudo install -o root -g root -m 0640 "${rendered}" "${SYSTEMD_TARGET}"
  rm -f "${rendered}"

  rendered="$(mktemp)"
  sed \
    -e "s|__HG_RPI_USER__|${svc_user}|g" \
    -e "s|__HG_VENV_DIR__|${venv_dir}|g" \
    "${SERVER_ROOT}/deploy/systemd/home-guardian-identity-research.service" > "${rendered}"
  sudo install -o root -g root -m 0640 "${rendered}" /etc/systemd/system/home-guardian-identity-research.service
  rm -f "${rendered}"
  sudo install -o root -g root -m 0640 "${SERVER_ROOT}/deploy/systemd/home-guardian-identity-research.path" /etc/systemd/system/home-guardian-identity-research.path
  sudo install -o root -g root -m 0640 "${SERVER_ROOT}/deploy/systemd/home-guardian-identity-research.timer" /etc/systemd/system/home-guardian-identity-research.timer

  sudo install -d -o "${svc_user}" -g "${svc_user}" -m 0750 "${RUNTIME_DIR}/identity-research"
  sudo -u "${svc_user}" touch "${RUNTIME_DIR}/identity-research/wake"
  sudo chmod 0640 "${RUNTIME_DIR}/identity-research/wake"

  sudo install -o root -g root -m 0640 "${SERVER_ROOT}/deploy/systemd/home-guardian-oui-update.service" /etc/systemd/system/home-guardian-oui-update.service
  sudo install -o root -g root -m 0640 "${SERVER_ROOT}/deploy/systemd/home-guardian-oui-update.timer" /etc/systemd/system/home-guardian-oui-update.timer
  rendered="$(mktemp)"
  sed -e "s|__HG_RPI_USER__|${svc_user}|g" \
    "${SERVER_ROOT}/deploy/systemd/home-guardian-db-backup.service" > "${rendered}"
  sudo install -o root -g root -m 0640 "${rendered}" /etc/systemd/system/home-guardian-db-backup.service
  rm -f "${rendered}"
  sudo install -o root -g root -m 0640 "${SERVER_ROOT}/deploy/systemd/home-guardian-db-backup.timer" /etc/systemd/system/home-guardian-db-backup.timer

  sudo install -d -o root -g root -m 0750 "/etc/systemd/system/${SERVICE_NAME}.service.d"
  rendered="$(mktemp)"
  printf '[Service]\nEnvironment="HG_NVD_LOOKUP=1"\n' > "${rendered}"
  sudo install -o root -g root -m 0640 "${rendered}" "/etc/systemd/system/${SERVICE_NAME}.service.d/nvd-lookup.conf"
  rm -f "${rendered}"

  sudo systemctl daemon-reload
  sudo systemd-analyze verify \
    "${SYSTEMD_TARGET}" \
    /etc/systemd/system/home-guardian-identity-research.service \
    /etc/systemd/system/home-guardian-identity-research.path \
    /etc/systemd/system/home-guardian-identity-research.timer \
    /etc/systemd/system/home-guardian-oui-update.service \
    /etc/systemd/system/home-guardian-oui-update.timer \
    /etc/systemd/system/home-guardian-db-backup.service \
    /etc/systemd/system/home-guardian-db-backup.timer
  sudo systemctl enable "${SERVICE_NAME}.service" home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.timer home-guardian-db-backup.timer
}

verify_exact_systemd_dropins() {
  local unit actual expected
  for unit in home-guardian-api.service home-guardian-identity-research.service home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.service home-guardian-oui-update.timer home-guardian-db-backup.service home-guardian-db-backup.timer; do
    actual="$(sudo systemctl show "${unit}" -p DropInPaths --value)"
    expected=''
    if [ "${unit}" = 'home-guardian-api.service' ]; then
      expected="/etc/systemd/system/${SERVICE_NAME}.service.d/nvd-lookup.conf"
    fi
    [ "${actual}" = "${expected}" ] || fail "${unit} has an unexpected effective systemd drop-in: ${actual}"
  done
}

verify_service_health() {
  local health_json='' last_health_json='' attempt
  # A production database can contain hundreds of retained scan observations.
  # The first v1.0.0 start normalizes those rows and warms the lightweight ML
  # model on a Raspberry Pi, so a fixed 20-second window can kill a healthy
  # candidate while it is still importing. Keep a bounded fail-closed check,
  # but allow a 90-second startup envelope.
  for attempt in $(seq 1 90); do
    if sudo systemctl is-active --quiet "${SERVICE_NAME}.service" && \
       health_json="$(curl -fsS --max-time 3 http://127.0.0.1:8010/health 2>/dev/null)"; then
      last_health_json="${health_json}"
      if printf '%s' "${health_json}" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
if payload.get("success") is not True:
    raise SystemExit("health status is not success")
data = payload.get("data") or {}
if data.get("status") != "healthy" or data.get("version") != "1.0.0":
    raise SystemExit(f"unexpected health payload: {data!r}")
' >/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "ERROR: ${SERVICE_NAME}.service did not become healthy after 90 attempts" >&2
  if [ -n "${last_health_json}" ]; then
    printf 'ERROR: last /health response: %.1000s\n' "${last_health_json}" >&2
  else
    echo 'ERROR: no HTTP /health response was received' >&2
  fi
  return 1
}

verify_running_auth_environment() {
  local expected_client_id="$1" expected_firebase="$2" expected_secret_sha256="$3" expected_db_path="$4"
  local expected_research_enabled="$5" expected_openai_sha256="$6" expected_research_model="$7" pid
  pid="$(sudo systemctl show "${SERVICE_NAME}.service" -p MainPID --value)"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || fail 'service MainPID is invalid'
  sudo python3 - "${pid}" "${expected_client_id}" "${expected_firebase}" "${expected_secret_sha256}" "${expected_db_path}" \
    "${expected_research_enabled}" "${expected_openai_sha256}" "${expected_research_model}" <<'PY'
import hashlib
import sys

(
    pid,
    expected_client_id,
    expected_firebase,
    expected_secret_sha256,
    expected_db_path,
    expected_research_enabled,
    expected_openai_sha256,
    expected_research_model,
) = sys.argv[1:]
raw = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
env = {}
for item in raw:
    if b"=" in item:
        key, value = item.split(b"=", 1)
        env[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
if env.get("GOOGLE_CLIENT_ID") != expected_client_id:
    raise SystemExit("running GOOGLE_CLIENT_ID differs from the validated auth.env value")
secret = env.get("HG_AUTH_TOKEN_SECRET", "")
if len(secret) < 32 or secret.strip() != secret or any(ch.isspace() for ch in secret):
    raise SystemExit("running HG_AUTH_TOKEN_SECRET is not a permanent effective value")
if hashlib.sha256(secret.encode("utf-8")).hexdigest() != expected_secret_sha256:
    raise SystemExit("running HG_AUTH_TOKEN_SECRET differs from the validated auth.env value")
if env.get("FIREBASE_CREDENTIALS") != expected_firebase:
    raise SystemExit("running FIREBASE_CREDENTIALS differs from the validated auth.env value")
if env.get("HG_RUNTIME_ENV") != "production":
    raise SystemExit("running HG_RUNTIME_ENV is not production")
if env.get("HOME_GUARDIAN_DB_PATH") != expected_db_path:
    raise SystemExit("running HOME_GUARDIAN_DB_PATH differs from the production runtime path")
if "DATABASE_URL" in env:
    raise SystemExit("running DATABASE_URL is forbidden for this SQLite production deployment")
if env.get("PYTHONDONTWRITEBYTECODE") != "1":
    raise SystemExit("running PYTHONDONTWRITEBYTECODE is not enabled")
if env.get("HG_ENABLE_DOCS", "0") != "0":
    raise SystemExit("runtime API documentation must remain disabled")
running_research_enabled = env.get(
    "HG_IDENTITY_AI_RESEARCH_ENABLED",
    env.get("HG_IDENTITY_RESEARCH_ENABLED", "0"),
)
if running_research_enabled != expected_research_enabled:
    raise SystemExit("running effective identity AI research flag differs from auth.env")
openai_key = env.get("OPENAI_API_KEY", "")
if expected_openai_sha256:
    if hashlib.sha256(openai_key.encode("utf-8")).hexdigest() != expected_openai_sha256:
        raise SystemExit("running OPENAI_API_KEY differs from auth.env")
elif openai_key:
    raise SystemExit("running OPENAI_API_KEY is unexpected")
if env.get("HG_IDENTITY_RESEARCH_MODEL", "") != expected_research_model:
    raise SystemExit("running HG_IDENTITY_RESEARCH_MODEL differs from auth.env")
for key in ("HG_ALLOW_TEST_LOGIN", "HG_ALLOW_TEST_SCOPE", "ALLOW_DEV_GOOGLE_OAUTH", "HG_ALLOW_EPHEMERAL_AUTH_SECRET"):
    if key in env:
        raise SystemExit(f"removed development option is active: {key}")
PY
}

case "${1:-}" in
  --verify-source-only)
    [ "$#" -eq 2 ] || fail 'usage: remote-install.sh --verify-source-only <source-directory>'
    verify_clean_source_tree "$2"
    echo 'CLEAN_REMOTE_SOURCE_VERIFIED=1'
    exit 0
    ;;
  --verify-server-only)
    [ "$#" -eq 2 ] || fail 'usage: remote-install.sh --verify-server-only <server-directory>'
    verify_clean_server_tree "$2"
    echo 'CLEAN_REMOTE_SERVER_VERIFIED=1'
    exit 0
    ;;
  --prepare-release)
    [ "$#" -eq 6 ] || fail 'usage: remote-install.sh --prepare-release <source-directory> <server-directory> <venv-directory> <release-id> <service-user>'
    [ "${EUID}" -eq 0 ] || fail 'release preparation must run as root'
    SOURCE_DIR="$2"
    SERVER_ROOT="$3"
    VENV_DIR="$4"
    RELEASE_ID="$5"
    SVC_USER="$6"
    SOURCE_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/source-runtime-files.txt"
    SERVER_FILE_MANIFEST="${SERVER_ROOT}/deploy/manifests/server-runtime-files.txt"
    SERVICE_SRC="${SERVER_ROOT}/deploy/systemd/home-guardian-api.service"
    [[ "${RELEASE_ID}" =~ ^[0-9a-f]{32}$ ]] || fail 'release id must be a 32-character lowercase GUID'
    [[ "${SVC_USER}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || fail 'service user has an unsafe format'
    validate_safe_absolute_path "${SOURCE_DIR}" source_dir
    validate_safe_absolute_path "${SERVER_ROOT}" server_root
    validate_safe_absolute_path "${VENV_DIR}" venv_dir
    case "${VENV_DIR}" in
      "${APP_DIR}/venvs/${RELEASE_ID}") ;;
      *) fail 'candidate venv is outside the versioned release path' ;;
    esac

    echo '[prepare 1/5] exact candidate manifests and SHA256'
    verify_clean_server_tree "${SERVER_ROOT}"
    verify_clean_source_tree "${SOURCE_DIR}"
    echo '[prepare 2/5] immutable production permissions'
    normalize_payload_permissions "${SOURCE_DIR}"
    normalize_payload_permissions "${SERVER_ROOT}"
    find "${SERVER_ROOT}/deploy/scripts" -type f -name '*.sh' -exec chmod 0750 {} +
    chown -R "root:${SVC_USER}" "${SOURCE_DIR}"
    chown -R "root:${SVC_USER}" "${SERVER_ROOT}"
    chown "root:${SVC_USER}" "${APP_DIR}"
    chmod 0750 "${APP_DIR}"
    install -d -o "${SVC_USER}" -g "${SVC_USER}" -m 0750 \
      "${RUNTIME_DIR}" "${RUNTIME_DIR}/backups"
    install -d -o root -g "${SVC_USER}" -m 0750 "${APP_DIR}/venvs"
    echo '[prepare 3/5] permanent auth, OAuth and Firebase readiness'
    validate_production_auth
    echo '[prepare 4/5] valid OUI prerequisite'
    verify_oui_file "${SOURCE_DIR}/${OUI_RELATIVE_PATH}" || fail 'a valid OUI database is required before release preparation'
    echo '[prepare 5/5] isolated versioned venv and import validation'
    prepare_versioned_venv "${VENV_DIR}" "${SVC_USER}"
    echo "RELEASE_PREPARED=${RELEASE_ID}"
    exit 0
    ;;
esac

RELEASE_ID="${HG_RELEASE_ID:-}"
VENV_DIR="${HG_VENV_DIR:-}"
SVC_USER="${HG_RPI_USER:-$(whoami)}"
[ "${EUID}" -eq 0 ] || fail 'normal installation must run as root'
[[ "${RELEASE_ID}" =~ ^[0-9a-f]{32}$ ]] || fail 'HG_RELEASE_ID must be a 32-character lowercase GUID'
[[ "${SVC_USER}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || fail 'HG_RPI_USER has an unsafe format'
validate_safe_absolute_path "${APP_DIR}" app_dir
validate_safe_absolute_path "${SERVER_ROOT}" server_root
validate_safe_absolute_path "${VENV_DIR}" venv_dir
case "${VENV_DIR}" in
  "${APP_DIR}/venvs/${RELEASE_ID}") ;;
  *) fail "HG_VENV_DIR must be the versioned release venv path" ;;
esac

echo '[1/9] exact runtime manifests and SHA256'
verify_clean_server_tree "${SERVER_ROOT}"
verify_clean_source_tree "${SOURCE_DIR}"

echo '[2/9] production permissions'
normalize_payload_permissions "${SOURCE_DIR}"
normalize_payload_permissions "${SERVER_ROOT}"
find "${SERVER_ROOT}/deploy/scripts" -type f -name '*.sh' -exec chmod 0750 {} +
sudo chown -R "root:${SVC_USER}" "${SOURCE_DIR}"
sudo chown -R "root:${SVC_USER}" "${SERVER_ROOT}"
sudo chown "root:${SVC_USER}" "${APP_DIR}"
sudo chmod 0750 "${APP_DIR}"
sudo install -d -o "${SVC_USER}" -g "${SVC_USER}" -m 0750 \
  "${RUNTIME_DIR}" "${RUNTIME_DIR}/backups"
sudo install -d -o root -g "${SVC_USER}" -m 0750 "${APP_DIR}/venvs"
for database_file in "${DB_PATH}" "${DB_PATH}-wal" "${DB_PATH}-shm"; do
  if [ -f "${database_file}" ]; then
    sudo chown "${SVC_USER}:${SVC_USER}" "${database_file}"
    sudo chmod 0640 "${database_file}"
  fi
done

echo '[3/9] permanent auth and effective OAuth readiness'
validate_production_auth

echo "[4/9] new versioned venv ${VENV_DIR}"
if [ "${HG_VENV_PREPARED:-0}" = '1' ]; then
  [ -x "${VENV_DIR}/bin/python" ] || fail "prepared versioned venv is missing: ${VENV_DIR}"
  sudo -u "${SVC_USER}" "${VENV_DIR}/bin/python" -m pip check
else
  prepare_versioned_venv "${VENV_DIR}" "${SVC_USER}"
fi

echo '[5/9] import, ML and OAuth library validation'
if [ "${HG_VENV_PREPARED:-0}" = '1' ]; then
  validate_new_venv "${VENV_DIR}" "${GOOGLE_CLIENT_ID_EFFECTIVE}" "${SVC_USER}" "${FIREBASE_CREDENTIALS_EFFECTIVE}"
  verify_clean_source_tree "${SOURCE_DIR}"
fi

echo '[6/9] systemd units and drop-in installation'
install_systemd_assets "${SVC_USER}" "${VENV_DIR}"
verify_exact_systemd_dropins
environment_files="$(sudo systemctl show "${SERVICE_NAME}.service" -p EnvironmentFiles --value)"
case "${environment_files}" in
  *"${AUTH_ENV_FILE}"*) ;;
  *) fail "systemd did not load ${AUTH_ENV_FILE} as EnvironmentFile" ;;
esac
identity_environment_files="$(sudo systemctl show "${IDENTITY_RESEARCH_SERVICE_NAME}.service" -p EnvironmentFiles --value)"
case "${identity_environment_files}" in
  *"${AUTH_ENV_FILE}"*) ;;
  *) fail "identity research worker did not load ${AUTH_ENV_FILE} as EnvironmentFile" ;;
esac

echo '[7/9] OUI and backup scripts'
verify_oui_file "${SOURCE_DIR}/${OUI_RELATIVE_PATH}" || fail 'a valid OUI database is required before service start'

echo '[8/9] API start before background triggers'
# Enable trigger units without starting them.  On a host whose boot delay has
# already elapsed, `enable --now` can immediately launch the oneshot worker;
# that must not race the new API process and its first DB migration.
sudo systemctl enable home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.timer home-guardian-db-backup.timer
sudo systemctl restart "${SERVICE_NAME}.service"

echo '[9/9] internal health check'
if ! verify_service_health; then
  sudo systemctl status "${SERVICE_NAME}.service" --no-pager || true
  fail 'new release failed internal health check'
fi
sudo systemctl start "${IDENTITY_RESEARCH_SERVICE_NAME}.service"
[ "$(sudo systemctl show "${IDENTITY_RESEARCH_SERVICE_NAME}.service" -p Result --value)" = 'success' ] || \
  fail 'identity research worker smoke run failed'
sudo systemctl start home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.timer home-guardian-db-backup.timer
sudo systemctl is-active --quiet home-guardian-identity-research.path || fail 'identity research path is not active'
sudo systemctl is-active --quiet home-guardian-identity-research.timer || fail 'identity research timer is not active'
verify_service_health || fail 'background trigger start disturbed API health'
verify_running_auth_environment \
  "${GOOGLE_CLIENT_ID_EFFECTIVE}" \
  "${FIREBASE_CREDENTIALS_EFFECTIVE}" \
  "${AUTH_SECRET_SHA256}" \
  "${DB_PATH}" \
  "${IDENTITY_RESEARCH_ENABLED_EFFECTIVE}" \
  "${OPENAI_API_KEY_SHA256}" \
  "${IDENTITY_RESEARCH_MODEL_EFFECTIVE}"

echo "DONE: ${SERVICE_NAME} v1.0.0 release ${RELEASE_ID} is healthy"
