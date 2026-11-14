# Home Guardian production deployment (Windows -> Raspberry Pi)

[CmdletBinding()]
param(
    [string] $RemoteUser = $env:HG_RPI_USER,
    [string] $RemoteHost = $env:HG_RPI_HOST,
    [string] $RemoteAppRoot = $(if ($env:HG_RPI_APP_ROOT) { $env:HG_RPI_APP_ROOT } else { '/srv/home-guardian' }),
    [string] $RemoteServerRoot = $(if ($env:HG_RPI_SERVER_ROOT) { $env:HG_RPI_SERVER_ROOT } else { '/srv/home-guardian-server' }),
    [switch] $PackageOnly,
    [string] $PackageOutputDirectory
)

$ErrorActionPreference = 'Stop'
$gateScript = Join-Path $PSScriptRoot 'payload-gates.ps1'
if (-not (Test-Path -LiteralPath $gateScript -PathType Leaf)) { throw "payload gate script가 없습니다: $gateScript" }
. $gateScript

function Assert-SafeRemotePath {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Label
    )
    if ($Path -notmatch '^/[A-Za-z0-9._/-]+$' -or $Path -match '//' -or $Path -match '(^|/)\.{1,2}(/|$)') {
        throw "$Label 경로는 안전한 Linux 절대경로여야 합니다: $Path"
    }
    $normalized = $Path.TrimEnd('/')
    if ($normalized -in @('', '/', '/srv', '/home', '/opt', '/tmp', '/var')) {
        throw "$Label 경로가 너무 넓습니다: $Path"
    }
    if (($normalized -split '/' | Where-Object { $_ }).Count -lt 2) {
        throw "$Label 경로 깊이가 부족합니다: $Path"
    }
}

function Remove-ValidatedDirectory {
    param(
        [Parameter(Mandatory = $true)][string] $Target,
        [Parameter(Mandatory = $true)][string] $Boundary
    )
    if (-not (Test-Path -LiteralPath $Target)) { return }
    $targetFull = [IO.Path]::GetFullPath($Target).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $boundaryFull = [IO.Path]::GetFullPath($Boundary).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not $targetFull.StartsWith($boundaryFull + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "정리 대상이 허용 경계를 벗어났습니다: $targetFull"
    }
    Remove-Item -LiteralPath $targetFull -Recurse -Force
}

function Copy-CheckedFile {
    param(
        [Parameter(Mandatory = $true)][string] $Source,
        [Parameter(Mandatory = $true)][string] $SourceBoundary,
        [Parameter(Mandatory = $true)][string] $Destination
    )
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "runtime 파일 누락: $Source" }
    Assert-PathHasNoReparsePoint -Path $Source -Boundary $SourceBoundary
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination
}

function Resolve-SourceRuntimeFile {
    param(
        [Parameter(Mandatory = $true)][string] $Relative,
        [Parameter(Mandatory = $true)][string] $SourceRoot,
        [Parameter(Mandatory = $true)][string] $ServerRoot
    )
    switch ($Relative) {
        'requirements.txt' { return (Join-Path $ServerRoot 'deploy\requirements-prod.txt') }
        'pyproject.toml' { return (Join-Path $ServerRoot 'deploy\pyproject-prod.toml') }
        default { return (Join-Path $SourceRoot ($Relative.Replace('/', [IO.Path]::DirectorySeparatorChar))) }
    }
}

$serverConfigRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$localEnvPath = Join-Path $serverConfigRoot '.env.local'
if ((-not $RemoteUser -or -not $RemoteHost) -and (Test-Path -LiteralPath $localEnvPath)) {
    foreach ($line in Get-Content -LiteralPath $localEnvPath) {
        if ($line -match '^\s*(HG_RPI_USER|HG_RPI_HOST)\s*=\s*(.*?)\s*$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim().Trim('"').Trim("'")
            if ($key -eq 'HG_RPI_USER' -and -not $RemoteUser) { $RemoteUser = $value }
            if ($key -eq 'HG_RPI_HOST' -and -not $RemoteHost) { $RemoteHost = $value }
        }
    }
}

if (-not $PackageOnly -and (-not $RemoteUser -or -not $RemoteHost)) {
    throw 'HG_RPI_USER/HG_RPI_HOST가 필요합니다.'
}
if (-not $PackageOnly) {
    if ($RemoteUser -notmatch '^[A-Za-z_][A-Za-z0-9_.-]*$') { throw "RemoteUser 형식이 안전하지 않습니다: $RemoteUser" }
    if ($RemoteHost -notmatch '^[A-Za-z0-9.-]+$') { throw "RemoteHost 형식이 안전하지 않습니다: $RemoteHost" }
}
Assert-SafeRemotePath -Path $RemoteAppRoot -Label 'RemoteAppRoot'
Assert-SafeRemotePath -Path $RemoteServerRoot -Label 'RemoteServerRoot'
if ($RemoteAppRoot.TrimEnd('/') -eq $RemoteServerRoot.TrimEnd('/')) { throw 'RemoteAppRoot와 RemoteServerRoot는 달라야 합니다.' }
if ($RemoteAppRoot.TrimEnd('/') -ne '/srv/home-guardian' -or $RemoteServerRoot.TrimEnd('/') -ne '/srv/home-guardian-server') {
    throw '현재 production systemd/backup/OUI 계약은 /srv/home-guardian 및 /srv/home-guardian-server만 허용합니다.'
}

$workspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$sourceRoot = Join-Path $workspaceRoot 'Home_Guardian'
$serverRoot = Join-Path $workspaceRoot 'Home_Guardian_Server'
$sourceManifestPath = Join-Path $serverRoot 'deploy\manifests\source-runtime-files.txt'
$serverManifestPath = Join-Path $serverRoot 'deploy\manifests\server-runtime-files.txt'
$sourceRuntimeFiles = @(Read-RuntimeFileManifest -ManifestPath $sourceManifestPath)
$serverRuntimeFiles = @(Read-RuntimeFileManifest -ManifestPath $serverManifestPath)

foreach ($required in @(
    'backend/app/identity_research_worker.py',
    'backend/app/main.py',
    'backend/app/services/identity_research.py',
    'backend/app/services/official_product_lookup.py',
    'backend/app/data/official_product_sources.json',
    'backend/app/storage/identity_history.py',
    'ml/home_guardian_ml/ml_predictor.py',
    'ml/training/output/lightweight/metrics.json',
    'ml/training/output/lightweight/random_forest.joblib',
    'ml/training/output/lightweight/stacking.joblib',
    'requirements.txt', 'pyproject.toml'
)) {
    if ($sourceRuntimeFiles -notcontains $required) { throw "source exact manifest 필수 항목 누락: $required" }
}
if (@($sourceRuntimeFiles | Where-Object { $_ -match '(^|/)(scanner|tests?|fixtures?|mocks?|demos?|samples?|seeds?)(/|$)' -or $_ -eq 'backend/app/data/oui.csv' }).Count -gt 0) {
    throw 'source exact manifest에 운영 비허용 경로가 있습니다.'
}

$deploymentId = [guid]::NewGuid().ToString('N')
if ($PackageOutputDirectory) {
    $workRoot = [IO.Path]::GetFullPath($PackageOutputDirectory)
    if (Test-Path -LiteralPath $workRoot) { throw "PackageOutputDirectory는 존재하지 않는 새 경로여야 합니다: $workRoot" }
} else {
    $workRoot = Join-Path ([IO.Path]::GetTempPath()) ("home-guardian-deploy-{0}-{1}" -f $PID, $deploymentId)
}

$workBoundary = Split-Path -Parent $workRoot
$sourceStage = Join-Path $workRoot 'source-stage'
$serverStageParent = Join-Path $workRoot 'server-stage'
$serverStage = Join-Path $serverStageParent 'Home_Guardian_Server'
$sourceTar = Join-Path $workRoot 'home-guardian-source.tar.gz'
$serverTar = Join-Path $workRoot 'home-guardian-server.tar.gz'
$sourceHashManifestRelative = '.home-guardian-runtime-manifest.sha256'
$serverHashManifestRelative = 'deploy/runtime-manifest.sha256'
$keepArtifacts = $false

try {
    New-Item -ItemType Directory -Path $sourceStage, $serverStage -Force | Out-Null

    Write-Host '[1/7] exact runtime manifest -> unique clean staging'
    foreach ($relative in $sourceRuntimeFiles) {
        $origin = Resolve-SourceRuntimeFile -Relative $relative -SourceRoot $sourceRoot -ServerRoot $serverRoot
        $originBoundary = if ($relative -in @('requirements.txt', 'pyproject.toml')) { $serverRoot } else { $sourceRoot }
        $destination = Join-Path $sourceStage ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        Copy-CheckedFile -Source $origin -SourceBoundary $originBoundary -Destination $destination
    }
    foreach ($relative in $serverRuntimeFiles) {
        $origin = Join-Path $serverRoot ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        $destination = Join-Path $serverStage ($relative.Replace('/', [IO.Path]::DirectorySeparatorChar))
        Copy-CheckedFile -Source $origin -SourceBoundary $serverRoot -Destination $destination
    }

    Assert-ExactFileSet -Actual @(Get-StageFilePaths -StageRoot $sourceStage) -Expected $sourceRuntimeFiles -Label 'source staging'
    Assert-ExactFileSet -Actual @(Get-StageFilePaths -StageRoot $serverStage) -Expected $serverRuntimeFiles -Label 'server staging'
    Assert-NoCredentialMaterial -StageRoot $sourceStage -RelativeFiles $sourceRuntimeFiles
    Assert-NoCredentialMaterial -StageRoot $serverStage -RelativeFiles $serverRuntimeFiles

    Write-RuntimeHashManifest -StageRoot $sourceStage -RelativeFiles $sourceRuntimeFiles -OutputRelativePath $sourceHashManifestRelative
    Write-RuntimeHashManifest -StageRoot $serverStage -RelativeFiles $serverRuntimeFiles -OutputRelativePath $serverHashManifestRelative
    Assert-RuntimeHashManifest -StageRoot $sourceStage -HashManifestRelativePath $sourceHashManifestRelative
    Assert-RuntimeHashManifest -StageRoot $serverStage -HashManifestRelativePath $serverHashManifestRelative

    $sourcePackagedFiles = @($sourceRuntimeFiles + $sourceHashManifestRelative)
    $serverPackagedFiles = @($serverRuntimeFiles + $serverHashManifestRelative)
    Assert-ExactFileSet -Actual @(Get-StageFilePaths -StageRoot $sourceStage) -Expected $sourcePackagedFiles -Label 'source hashed staging'
    Assert-ExactFileSet -Actual @(Get-StageFilePaths -StageRoot $serverStage) -Expected $serverPackagedFiles -Label 'server hashed staging'

    Write-Host '[2/7] tar creation'
    & tar -czf $sourceTar -C $sourceStage .
    if ($LASTEXITCODE -ne 0) { throw "source tar 생성 실패: $LASTEXITCODE" }
    & tar -czf $serverTar -C $serverStageParent 'Home_Guardian_Server'
    if ($LASTEXITCODE -ne 0) { throw "server tar 생성 실패: $LASTEXITCODE" }

    Write-Host '[3/7] tar type, traversal and exact entry gates'
    Assert-TarEntryTypes -ArchivePath $sourceTar -Label 'source'
    Assert-TarEntryTypes -ArchivePath $serverTar -Label 'server'
    $sourceArchiveEntries = @(Get-NormalizedArchiveEntries -ArchivePath $sourceTar)
    $serverArchiveEntries = @(Get-NormalizedArchiveEntries -ArchivePath $serverTar)
    $expectedSourceEntries = @(Get-ExpectedArchiveEntries -RelativeFiles $sourcePackagedFiles)
    $expectedServerEntries = @(Get-ExpectedArchiveEntries -RelativeFiles $serverPackagedFiles -Prefix 'Home_Guardian_Server')
    Assert-ArchiveExactEntries -Actual $sourceArchiveEntries -Expected $expectedSourceEntries -Label 'source'
    Assert-ArchiveExactEntries -Actual $serverArchiveEntries -Expected $expectedServerEntries -Label 'server'

    $sourceHash = (Get-FileHash -LiteralPath $sourceTar -Algorithm SHA256).Hash.ToLowerInvariant()
    $serverHash = (Get-FileHash -LiteralPath $serverTar -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ("  source files={0}, entries={1}, sha256={2}" -f $sourcePackagedFiles.Count, $sourceArchiveEntries.Count, $sourceHash)
    Write-Host ("  server files={0}, entries={1}, sha256={2}" -f $serverPackagedFiles.Count, $serverArchiveEntries.Count, $serverHash)

    if ($PackageOnly) {
        $keepArtifacts = $true
        Write-Host '[4/7] PackageOnly — network/service actions skipped'
        Write-Host "DEPLOYMENT_ID=$deploymentId"
        Write-Host "SOURCE_ARCHIVE=$sourceTar"
        Write-Host "SERVER_ARCHIVE=$serverTar"
        Write-Host 'CLEAN_PAYLOAD_VERIFIED=1'
        return
    }

    $remoteSourceTar = "/tmp/home-guardian-source-$deploymentId.tar.gz"
    $remoteServerTar = "/tmp/home-guardian-server-$deploymentId.tar.gz"
    $remoteStepPath = "/tmp/home-guardian-deploy-$deploymentId.sh"
    $remoteVenv = "$($RemoteAppRoot.TrimEnd('/'))/venvs/$deploymentId"

    Write-Host '[4/7] verified GUID archives -> SCP'
    scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new $sourceTar ("$RemoteUser@$RemoteHost`:$remoteSourceTar")
    if ($LASTEXITCODE -ne 0) { throw "source SCP 실패: $LASTEXITCODE" }
    scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new $serverTar ("$RemoteUser@$RemoteHost`:$remoteServerTar")
    if ($LASTEXITCODE -ne 0) { throw "server SCP 실패: $LASTEXITCODE" }

    Write-Host '[5/7] transactional remote release step'
    $remoteScriptTemplate = @'
set -euo pipefail
umask 027
deployment_id='__DEPLOYMENT_ID__'
app_root='__APP_ROOT__'
source_root='__APP_ROOT__/Home_Guardian'
server_root='__SERVER_ROOT__'
svc_user='__SVC_USER__'
svc_group='__SVC_USER__'
remote_source_tar='__REMOTE_SOURCE_TAR__'
remote_server_tar='__REMOTE_SERVER_TAR__'
expected_source_sha='__SOURCE_SHA__'
expected_server_sha='__SERVER_SHA__'
venv_next='__VENV_NEXT__'
source_next="${app_root}/.Home_Guardian.next.${deployment_id}"
source_previous="${app_root}/.Home_Guardian.previous.${deployment_id}"
server_next="${server_root}.next.${deployment_id}"
server_previous="${server_root}.previous.${deployment_id}"
rollback_dir="${app_root}/deploy-rollbacks/${deployment_id}"
db_path="${app_root}/runtime/home_guardian.sqlite3"
db_backup_dir="${app_root}/runtime/predeploy-backups"
db_backup="${db_backup_dir}/home_guardian-${deployment_id}.sqlite3"
db_lock="${app_root}/.db-backup.lock"
managed_units=(home-guardian-api.service home-guardian-identity-research.service home-guardian-identity-research.path home-guardian-identity-research.timer home-guardian-oui-update.service home-guardian-oui-update.timer home-guardian-db-backup.service home-guardian-db-backup.timer)
transaction_started=0

fail() { echo "ERROR: $*" >&2; exit 1; }
[[ "${deployment_id}" =~ ^[0-9a-f]{32}$ ]] || fail 'invalid deployment id'
[[ "${svc_user}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || fail 'invalid service user'

cleanup_unactivated_candidate() {
  local status=$?
  if [ "${status}" -ne 0 ] && [ "${transaction_started}" -eq 0 ]; then
    sudo rm -rf -- "${source_next}" "${server_next}" "${venv_next}"
  fi
  return "${status}"
}
trap cleanup_unactivated_candidate EXIT

sudo install -d -o root -g "${svc_group}" -m 0750 "${app_root}"
lock_file="${app_root}/.deploy.lock"
sudo touch "${lock_file}"
sudo chown "root:${svc_group}" "${lock_file}"
sudo chmod 0640 "${lock_file}"
exec 9<"${lock_file}"
flock -n 9 || fail 'another deployment holds the release lock'

check_sha() {
  local path="$1" expected="$2" label="$3" actual
  [ -f "${path}" ] || fail "${label} archive is missing: ${path}"
  actual="$(sha256sum "${path}" | awk '{print $1}')"
  [ "${actual}" = "${expected}" ] || fail "${label} archive SHA256 mismatch"
}

inspect_archive_nodes() {
  python3 - "$1" "$2" <<'PYTAR'
import pathlib
import sys
import tarfile

archive, label = sys.argv[1:]
seen = set()
with tarfile.open(archive, "r:gz") as bundle:
    for member in bundle.getmembers():
        name = member.name
        if "\\" in name or name.startswith("/"):
            raise SystemExit(f"{label} archive has an unsafe name: {name!r}")
        while name.startswith("./"):
            name = name[2:]
        if name in ("", "."):
            if not member.isdir():
                raise SystemExit(f"{label} archive root entry is not a directory")
            canonical = "."
        else:
            raw_parts = name.split("/")
            if any(part in ("", ".", "..") for part in raw_parts):
                raise SystemExit(f"{label} archive has an unsafe path: {name!r}")
            parts = pathlib.PurePosixPath(name).parts
            if not parts or any(part in ("", ".", "..") for part in parts):
                raise SystemExit(f"{label} archive has an unsafe path: {name!r}")
            canonical = "/".join(parts)
        if canonical in seen:
            raise SystemExit(f"{label} archive has a duplicate entry: {canonical}")
        seen.add(canonical)
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"{label} archive has a forbidden tar node: {canonical} type={member.type!r}")
PYTAR
}

check_sha "${remote_source_tar}" "${expected_source_sha}" source
check_sha "${remote_server_tar}" "${expected_server_sha}" server
inspect_archive_nodes "${remote_source_tar}" source
inspect_archive_nodes "${remote_server_tar}" server

for candidate in "${source_next}" "${source_previous}" "${server_next}" "${server_previous}" "${rollback_dir}" "${venv_next}"; do
  if [ -e "${candidate}" ] || [ -L "${candidate}" ]; then fail "release path already exists: ${candidate}"; fi
done

sudo install -d -o root -g "${svc_group}" -m 0750 "${source_next}"
sudo install -d -o root -g root -m 0750 "${server_next}"
sudo tar -xzf "${remote_source_tar}" -C "${source_next}" --no-same-owner --no-same-permissions
sudo tar -xzf "${remote_server_tar}" -C "${server_next}" --strip-components=1 --no-same-owner --no-same-permissions
sudo find "${source_next}" -type d -exec chmod 0750 {} +
sudo find "${source_next}" -type f -exec chmod 0640 {} +
sudo chown -R "root:${svc_group}" "${source_next}"
sudo find "${server_next}" -type d -exec chmod 0750 {} +
sudo find "${server_next}" -type f -exec chmod 0640 {} +
sudo find "${server_next}/deploy/scripts" -type f -name '*.sh' -exec chmod 0750 {} +
sudo chown -R "root:${svc_group}" "${server_next}"

sudo env HG_SERVER_ROOT="${server_next}" "${server_next}/deploy/scripts/remote-install.sh" --verify-server-only "${server_next}"
sudo env HG_SERVER_ROOT="${server_next}" "${server_next}/deploy/scripts/remote-install.sh" --verify-source-only "${source_next}"

old_oui="${source_root}/backend/app/data/oui.csv"
new_oui="${source_next}/backend/app/data/oui.csv"
if sudo test -f "${old_oui}" && sudo "${server_next}/deploy/scripts/update-oui-data.sh" --validate-file "${old_oui}"; then
  sudo install -o root -g "${svc_group}" -m 0640 "${old_oui}" "${new_oui}"
  echo 'valid existing OUI carried into next release'
fi
sudo env HG_OUI_TARGET="${new_oui}" "${server_next}/deploy/scripts/update-oui-data.sh" --no-restart --deploy-lock-held
sudo env HG_SERVER_ROOT="${server_next}" "${server_next}/deploy/scripts/remote-install.sh" --verify-source-only "${source_next}"

if ! sudo env \
  HG_APP_DIR="${app_root}" \
  HG_SERVER_ROOT="${server_next}" \
  "${server_next}/deploy/scripts/remote-install.sh" \
  --prepare-release "${source_next}" "${server_next}" "${venv_next}" "${deployment_id}" "${svc_user}"; then
  fail 'candidate release preparation failed before service quiesce'
fi

old_service_active=0
old_health_version=''
if sudo systemctl is-active --quiet home-guardian-api.service; then
  old_service_active=1
  old_health_payload=''
  for attempt in $(seq 1 10); do
    if old_health_payload="$(curl -fsS --max-time 3 http://127.0.0.1:8010/health 2>/dev/null)"; then break; fi
    sleep 1
  done
  [ -n "${old_health_payload}" ] || fail 'active previous API has no healthy baseline response'
  old_health_version="$(printf '%s' "${old_health_payload}" | python3 -c '
import json, sys
p = json.load(sys.stdin)
d = p.get("data") or {}
if p.get("success") is not True or d.get("status") != "healthy" or not str(d.get("version") or "").strip():
    raise SystemExit("previous API health baseline is not healthy")
print(d["version"])
')" || fail 'active previous API health baseline is invalid'
fi

declare -A old_enabled old_active
for unit in "${managed_units[@]}"; do
  old_enabled["${unit}"]="$(sudo systemctl is-enabled "${unit}" 2>/dev/null || true)"
  current_active="$(sudo systemctl is-active "${unit}" 2>/dev/null || true)"
  # The research worker is a scheduled oneshot.  A timer may have it in the
  # transient `activating` state while deployment starts.  Its stable baseline
  # is inactive; the activation transaction will quiesce triggers and wait for
  # the in-flight claim to finish instead of interrupting it after backoff was
  # persisted.  Path/timer enablement is preserved separately.
  if [ "${unit}" = 'home-guardian-identity-research.service' ] && [ "${current_active}" = 'activating' ]; then
    current_active='inactive'
  fi
  old_active["${unit}"]="${current_active}"
  case "${old_enabled[${unit}]}" in
    enabled|enabled-runtime|disabled|static|indirect|not-found) ;;
    *) fail "unit ${unit} has an unsupported enablement baseline: ${old_enabled[${unit}]}" ;;
  esac
  case "${old_active[${unit}]}" in
    active|inactive) ;;
    *) fail "unit ${unit} is not in a stable active/inactive baseline: ${old_active[${unit}]}" ;;
  esac
done

had_source=0
had_server=0
if [ -e "${source_root}" ] || [ -L "${source_root}" ]; then had_source=1; fi
if [ -e "${server_root}" ] || [ -L "${server_root}" ]; then had_server=1; fi
sudo install -d -o root -g "${svc_group}" -m 0750 "${app_root}/deploy-rollbacks"
sudo install -d -o root -g root -m 0750 "${rollback_dir}" "${rollback_dir}/units" "${rollback_dir}/dropins"
for unit in "${managed_units[@]}"; do
  unit_path="/etc/systemd/system/${unit}"
  if [ -e "${unit_path}" ] || [ -L "${unit_path}" ]; then
    sudo cp -a -- "${unit_path}" "${rollback_dir}/units/${unit}"
  fi
  dropin_path="/etc/systemd/system/${unit}.d"
  if [ -d "${dropin_path}" ] || [ -L "${dropin_path}" ]; then
    sudo cp -a -- "${dropin_path}" "${rollback_dir}/dropins/${unit}.d"
  fi
done

sudo install -d -o "${svc_user}" -g "${svc_group}" -m 0750 "${app_root}/runtime" "${db_backup_dir}"
sudo touch "${db_lock}"
sudo chown "root:${svc_group}" "${db_lock}"
sudo chmod 0640 "${db_lock}"

create_final_db_backup() {
  local partial="${db_backup}.partial"
  if [ -f "${db_path}" ]; then
    sudo touch "${rollback_dir}/had-db"
    sudo rm -f -- "${partial}"
    sudo -u "${svc_user}" python3 - "${db_path}" "${partial}" "${db_backup}" <<'PYDB'
import os
import sqlite3
import sys

source_path, partial_path, final_path = sys.argv[1:]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True)
check = source.execute("PRAGMA quick_check").fetchall()
if check != [("ok",)]:
    raise SystemExit(f"source quick_check failed: {check!r}")
backup = sqlite3.connect(partial_path)
with backup:
    source.backup(backup)
check = backup.execute("PRAGMA integrity_check").fetchall()
backup.close()
source.close()
if check != [("ok",)]:
    raise SystemExit(f"backup integrity_check failed: {check!r}")
os.chmod(partial_path, 0o640)
os.replace(partial_path, final_path)
PYDB
    sudo touch "${rollback_dir}/db-backup-ready"
    echo "quiesced predeploy SQLite backup verified: ${db_backup}"
  else
    sudo touch "${rollback_dir}/no-db"
  fi
}

activation_transaction() (
  set -euo pipefail
  exec 8<"${db_lock}"
  flock -w 30 8
  # Stop every trigger before the final SQLite backup.  Otherwise a path or
  # timer wake can start the old worker between the API quiesce and directory
  # swap, producing a backup that does not match the activated source.
  sudo systemctl stop home-guardian-identity-research.path home-guardian-identity-research.timer >/dev/null 2>&1 || true
  # A oneshot may already have claimed jobs and persisted their retry time.
  # Let it finish within its managed 60-second TimeoutStartSec; killing it here
  # could defer untouched jobs for hours without any external lookup attempt.
  for attempt in $(seq 1 65); do
    research_state="$(sudo systemctl is-active home-guardian-identity-research.service 2>/dev/null || true)"
    [ "${research_state}" != 'activating' ] && break
    sleep 1
  done
  [ "$(sudo systemctl is-active home-guardian-identity-research.service 2>/dev/null || true)" = 'inactive' ] || \
    fail 'identity research worker did not quiesce within its managed timeout'
  if [ "${old_service_active}" -eq 1 ]; then
    sudo systemctl stop home-guardian-api.service
    [ "$(sudo systemctl is-active home-guardian-api.service 2>/dev/null || true)" = 'inactive' ]
  fi
  sudo touch "${rollback_dir}/api-quiesced"
  create_final_db_backup
  sudo touch "${rollback_dir}/activation-started"

  if [ "${had_source}" -eq 1 ]; then sudo mv "${source_root}" "${source_previous}"; fi
  if [ "${had_server}" -eq 1 ]; then sudo mv "${server_root}" "${server_previous}"; fi
  sudo mv "${source_next}" "${source_root}"
  sudo touch "${rollback_dir}/source-candidate-active"
  sudo mv "${server_next}" "${server_root}"
  sudo touch "${rollback_dir}/server-candidate-active"
  sudo chown -R "root:${svc_group}" "${source_root}"
  sudo chown -R "root:${svc_group}" "${server_root}"

  sudo env \
    HG_RELEASE_ID="${deployment_id}" \
    HG_VENV_DIR="${venv_next}" \
    HG_VENV_PREPARED=1 \
    HG_RPI_USER="${svc_user}" \
    HG_APP_DIR="${app_root}" \
    HG_SERVER_ROOT="${server_root}" \
    "${server_root}/deploy/scripts/remote-install.sh"
)

restore_database() {
  if [ -f "${rollback_dir}/had-db" ]; then
    if [ -f "${rollback_dir}/db-backup-ready" ]; then
      sudo rm -f -- "${db_path}-wal" "${db_path}-shm"
      sudo python3 - "${db_backup}" "${db_path}" "${deployment_id}" "${svc_user}" "${svc_group}" <<'PYRESTORE'
import os
import pwd
import grp
import shutil
import sqlite3
import sys

backup_path, target_path, release_id, user, group = sys.argv[1:]
connection = sqlite3.connect(f"file:{backup_path}?mode=ro", uri=True)
check = connection.execute("PRAGMA integrity_check").fetchall()
connection.close()
if check != [("ok",)]:
    raise SystemExit(f"rollback backup invalid: {check!r}")
temp_path = f"{target_path}.rollback.{release_id}"
shutil.copyfile(backup_path, temp_path)
os.chmod(temp_path, 0o640)
os.chown(temp_path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
os.replace(temp_path, target_path)
PYRESTORE
      sudo rm -f -- "${db_path}-wal" "${db_path}-shm"
    elif [ -f "${rollback_dir}/activation-started" ]; then
      echo 'ERROR: candidate activation began without a verified database backup' >&2
      return 1
    fi
  elif [ -f "${rollback_dir}/no-db" ]; then
    sudo rm -f -- "${db_path}" "${db_path}-wal" "${db_path}-shm"
  fi
}

restore_release_paths() {
  local result=0
  if [ -e "${source_previous}" ] || [ -L "${source_previous}" ]; then
    sudo rm -rf -- "${source_root}" || result=1
    sudo mv "${source_previous}" "${source_root}" || result=1
  elif [ "${had_source}" -eq 0 ] && [ ! -e "${source_next}" ] && [ -e "${source_root}" ]; then
    sudo rm -rf -- "${source_root}" || result=1
  fi
  if [ -e "${server_previous}" ] || [ -L "${server_previous}" ]; then
    sudo rm -rf -- "${server_root}" || result=1
    sudo mv "${server_previous}" "${server_root}" || result=1
  elif [ "${had_server}" -eq 0 ] && [ ! -e "${server_next}" ] && [ -e "${server_root}" ]; then
    sudo rm -rf -- "${server_root}" || result=1
  fi
  sudo rm -rf -- "${source_next}" "${server_next}" || result=1
  return "${result}"
}

restore_enablement_state() {
  local unit="$1" state="$2"
  case "${state}" in
    enabled) sudo systemctl enable "${unit}" >/dev/null ;;
    enabled-runtime) sudo systemctl enable --runtime "${unit}" >/dev/null ;;
    masked) sudo systemctl mask "${unit}" >/dev/null ;;
    masked-runtime) sudo systemctl mask --runtime "${unit}" >/dev/null ;;
    disabled|static|indirect|linked|linked-runtime|alias|not-found) ;;
    *) return 1 ;;
  esac
}

restore_systemd() {
  local unit unit_path unit_backup dropin_path dropin_backup current result=0
  # Validate every required baseline asset before touching the candidate units.
  # A rollback must not remove a working unit and only then discover that its
  # backup is unavailable.
  for unit in "${managed_units[@]}"; do
    unit_backup="${rollback_dir}/units/${unit}"
    if [ "${old_enabled[${unit}]}" != 'not-found' ] && [ ! -f "${unit_backup}" ]; then
      echo "ERROR: required systemd rollback unit is missing: ${unit_backup}" >&2
      return 1
    fi
  done
  for unit in "${managed_units[@]}"; do
    sudo systemctl stop "${unit}" >/dev/null 2>&1 || true
    sudo systemctl disable "${unit}" >/dev/null 2>&1 || true
    sudo systemctl disable --runtime "${unit}" >/dev/null 2>&1 || true
    sudo systemctl unmask "${unit}" >/dev/null 2>&1 || true
    sudo systemctl unmask --runtime "${unit}" >/dev/null 2>&1 || true
  done
  for unit in "${managed_units[@]}"; do
    unit_path="/etc/systemd/system/${unit}"
    unit_backup="${rollback_dir}/units/${unit}"
    dropin_path="/etc/systemd/system/${unit}.d"
    dropin_backup="${rollback_dir}/dropins/${unit}.d"
    if [ -f "${unit_backup}" ]; then
      # install replaces a candidate file or symlink with explicit ownership
      # and permissions before the subsequent daemon-reload.
      sudo install -o root -g root -m 0644 "${unit_backup}" "${unit_path}" || result=1
      sudo cmp -s -- "${unit_backup}" "${unit_path}" || {
        echo "ERROR: restored systemd unit differs from backup: ${unit}" >&2
        result=1
      }
    else
      sudo rm -f -- "${unit_path}" || result=1
    fi
    sudo rm -rf -- "${dropin_path}" || result=1
    if [ -d "${dropin_backup}" ]; then
      sudo install -d -o root -g root -m 0755 "${dropin_path}" || result=1
      sudo cp -a -- "${dropin_backup}/." "${dropin_path}/" || result=1
      sudo diff -qr -- "${dropin_backup}" "${dropin_path}" >/dev/null || {
        echo "ERROR: restored systemd drop-in differs from backup: ${unit}" >&2
        result=1
      }
    fi
  done
  sudo systemctl daemon-reload || result=1
  for unit in "${managed_units[@]}"; do
    restore_enablement_state "${unit}" "${old_enabled[${unit}]}" || result=1
  done
  for unit in "${managed_units[@]}"; do
    if [ "${old_active[${unit}]}" = 'active' ]; then
      sudo systemctl start "${unit}" || result=1
    else
      sudo systemctl stop "${unit}" >/dev/null 2>&1 || true
    fi
  done
  for unit in "${managed_units[@]}"; do
    current="$(sudo systemctl is-enabled "${unit}" 2>/dev/null || true)"
    [ "${current}" = "${old_enabled[${unit}]}" ] || { echo "ERROR: ${unit} enablement restore mismatch: ${current} != ${old_enabled[${unit}]}" >&2; result=1; }
    current="$(sudo systemctl is-active "${unit}" 2>/dev/null || true)"
    [ "${current}" = "${old_active[${unit}]}" ] || { echo "ERROR: ${unit} active restore mismatch: ${current} != ${old_active[${unit}]}" >&2; result=1; }
  done
  return "${result}"
}

rollback_health() {
  local attempt payload
  for attempt in $(seq 1 90); do
    if payload="$(curl -fsS --max-time 3 http://127.0.0.1:8010/health 2>/dev/null)" && \
       printf '%s' "${payload}" | python3 -c '
import json, sys
expected = sys.argv[1]
p = json.load(sys.stdin)
d = p.get("data") or {}
raise SystemExit(0 if p.get("success") is True and d.get("status") == "healthy" and str(d.get("version")) == expected else 1)
' "${old_health_version}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

rollback_release() {
  local original_status="$1" rollback_errors=0 unit
  set +e
  echo "new release failed (status=${original_status}); rolling back" >&2
  for unit in "${managed_units[@]}"; do sudo systemctl stop "${unit}" >/dev/null 2>&1 || true; done
  restore_database || { echo 'ERROR: database rollback failed' >&2; rollback_errors=$((rollback_errors + 1)); }
  restore_release_paths || { echo 'ERROR: release path rollback failed' >&2; rollback_errors=$((rollback_errors + 1)); }
  restore_systemd || { echo 'ERROR: systemd state rollback failed' >&2; rollback_errors=$((rollback_errors + 1)); }
  sudo rm -rf -- "${venv_next}" || rollback_errors=$((rollback_errors + 1))
  if [ "${old_service_active}" -eq 1 ]; then
    if rollback_health; then
      echo "rollback health check passed for prior version ${old_health_version}" >&2
    else
      echo 'ERROR: rollback health check failed' >&2
      rollback_errors=$((rollback_errors + 1))
    fi
  fi
  if [ "${rollback_errors}" -ne 0 ]; then
    echo "ERROR: rollback completed with ${rollback_errors} fatal restoration error(s); assets kept at ${rollback_dir}" >&2
    exit 90
  fi
  echo "rollback completed; forensic state kept at ${rollback_dir}" >&2
  exit "${original_status}"
}

transaction_started=1
set +e
( set -e; activation_transaction )
install_status=$?
set -e
if [ "${install_status}" -eq 0 ]; then
  sudo rm -rf -- "${source_previous}" "${server_previous}" "${rollback_dir}"
  trap - EXIT
  echo "TRANSACTIONAL_DEPLOYMENT_COMPLETE=${deployment_id}"
else
  rollback_release "${install_status}"
fi
'@
    $remoteScript = $remoteScriptTemplate.
        Replace('__DEPLOYMENT_ID__', $deploymentId).
        Replace('__APP_ROOT__', $RemoteAppRoot.TrimEnd('/')).
        Replace('__SERVER_ROOT__', $RemoteServerRoot.TrimEnd('/')).
        Replace('__SVC_USER__', $RemoteUser).
        Replace('__REMOTE_SOURCE_TAR__', $remoteSourceTar).
        Replace('__REMOTE_SERVER_TAR__', $remoteServerTar).
        Replace('__SOURCE_SHA__', $sourceHash).
        Replace('__SERVER_SHA__', $serverHash).
        Replace('__VENV_NEXT__', $remoteVenv)

    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $localRemoteStep = Join-Path $workRoot "home-guardian-deploy-$deploymentId.sh"
    [IO.File]::WriteAllText($localRemoteStep, (($remoteScript -replace "`r`n", "`n") + "`n"), $utf8NoBom)
    $stepHash = (Get-FileHash -LiteralPath $localRemoteStep -Algorithm SHA256).Hash.ToLowerInvariant()
    scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new $localRemoteStep ("$RemoteUser@$RemoteHost`:$remoteStepPath")
    if ($LASTEXITCODE -ne 0) { throw "remote step SCP 실패: $LASTEXITCODE" }

    $launcherTemplate = @'
set +e
if ! sudo chown root:'__SVC_GROUP__' '__REMOTE_STEP__' '__REMOTE_SOURCE__' '__REMOTE_SERVER__' || \
   ! sudo chmod 0440 '__REMOTE_STEP__' '__REMOTE_SOURCE__' '__REMOTE_SERVER__'; then
  status=73
else
  actual="$(sha256sum '__REMOTE_STEP__' | awk '{print $1}')"
  if [ "${actual}" != '__STEP_SHA__' ]; then status=74; else bash '__REMOTE_STEP__'; status=$?; fi
fi
sudo rm -f '__REMOTE_STEP__' '__REMOTE_SOURCE__' '__REMOTE_SERVER__'
exit "${status}"
'@
    $launcher = $launcherTemplate.
        Replace('__REMOTE_STEP__', $remoteStepPath).
        Replace('__SVC_GROUP__', $RemoteUser).
        Replace('__STEP_SHA__', $stepHash).
        Replace('__REMOTE_SOURCE__', $remoteSourceTar).
        Replace('__REMOTE_SERVER__', $remoteServerTar)
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$RemoteUser@$RemoteHost" $launcher
    if ($LASTEXITCODE -ne 0) { throw "transactional remote install 실패: $LASTEXITCODE" }

    Write-Host '[6/7] external health check'
    $publicBaseUrl = if ($env:HG_PUBLIC_BASE_URL) { $env:HG_PUBLIC_BASE_URL } else { $env:HOME_GUARDIAN_PUBLIC_BASE_URL }
    if ($publicBaseUrl) {
        $response = Invoke-RestMethod -Uri "$publicBaseUrl/health" -TimeoutSec 8
        if ($response.success -ne $true -or $response.data.status -ne 'healthy' -or $response.data.version -ne '1.0.0') {
            throw '외부 health 응답이 v1.0.0 healthy가 아닙니다.'
        }
    } else {
        Write-Host '  HG_PUBLIC_BASE_URL not set - external health skipped'
    }
    Write-Host '[7/7] DONE'
} finally {
    if (-not $keepArtifacts -and (Test-Path -LiteralPath $workRoot)) {
        Remove-ValidatedDirectory -Target $workRoot -Boundary $workBoundary
    }
}
