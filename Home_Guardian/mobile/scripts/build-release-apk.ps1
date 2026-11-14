[CmdletBinding()]
param(
  # Deliberately opt-in: this script never installs on a connected Android device
  # unless the operator requests it explicitly.
  [switch]$InstallOnDevice
)

# v1 release artifact builder.  Despite the retained filename, it produces both
# the side-load verification APK and the Play-upload AAB.  It refuses to patch
# Android source files, generate credentials, or weaken release signing rules.
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$mobileDir = Join-Path $repoRoot "Home_Guardian\mobile"
$androidDir = Join-Path $mobileDir "android"
$envPath = Join-Path $mobileDir ".env.local"
$googleServicesPath = Join-Path $androidDir "app\google-services.json"
$packageName = "com.homeguardian.app"
$expectedVersion = "1.0.0"
$expectedVersionCode = "100"

function Import-ReleaseEnvironment {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path)) {
    return
  }

  Get-Content -LiteralPath $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line -eq "" -or $line.StartsWith("#")) { return }
    if ($line -match "^([A-Z_][A-Z0-9_]*)=(.+)$") {
      $name = $matches[1]
      $value = $matches[2].Trim('"').Trim("'")
      if (-not (Get-Item "env:$name" -ErrorAction SilentlyContinue)) {
        Set-Item "env:$name" $value
      }
    }
  }
}

function Resolve-AndroidTool {
  param([string]$Name)

  $command = Get-Command $Name -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }

  $sdkRoot = $env:ANDROID_HOME
  if (-not $sdkRoot) { $sdkRoot = $env:ANDROID_SDK_ROOT }
  if (-not $sdkRoot) { return $null }

  $candidates = @()
  if ($Name -eq "adb") {
    $candidates += Join-Path $sdkRoot "platform-tools\adb.exe"
  } elseif ($Name -in @("aapt", "apksigner")) {
    $buildToolsRoot = Join-Path $sdkRoot "build-tools"
    if (Test-Path -LiteralPath $buildToolsRoot) {
      $candidates += Get-ChildItem -LiteralPath $buildToolsRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "$Name.bat" }
      $candidates += Get-ChildItem -LiteralPath $buildToolsRoot -Directory |
        Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName "$Name.exe" }
    }
  }

  return $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}

function Resolve-Bundletool {
  if ($env:BUNDLETOOL_JAR -and (Test-Path -LiteralPath $env:BUNDLETOOL_JAR)) {
    return (Resolve-Path -LiteralPath $env:BUNDLETOOL_JAR).Path
  }

  $command = Get-Command bundletool -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  return $null
}

function Assert-FreshArtifact {
  param([string]$Path, [datetime]$BuildStartedAt, [string]$Label)

  if (-not (Test-Path -LiteralPath $Path)) {
    throw "$Label 가 생성되지 않았습니다: $Path"
  }
  $item = Get-Item -LiteralPath $Path
  if ($item.LastWriteTime -lt $BuildStartedAt) {
    throw "$Label 가 이번 빌드에서 새로 생성되지 않았습니다: $Path"
  }
  return $item
}

function Read-ZipTextEntry {
  param([string]$ArchivePath, [string]$EntryPath, [string]$Label)

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    $entry = $archive.Entries | Where-Object { $_.FullName -eq $EntryPath } | Select-Object -First 1
    if (-not $entry) {
      throw "$Label 에 필수 파일이 없습니다: $EntryPath"
    }
    $reader = [System.IO.StreamReader]::new($entry.Open())
    try {
      return $reader.ReadToEnd()
    } finally {
      $reader.Dispose()
    }
  } finally {
    $archive.Dispose()
  }
}

function Assert-NoApkTestPayload {
  param([string]$ArchivePath)

  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
  try {
    $forbiddenAsset = $archive.Entries | Where-Object {
      $_.FullName -match '(?i)^assets/(?:__tests__|__mocks__|tests?|mocks?|fixtures?|samples?|demos?|seeds?)(?:/|$)' -or
      $_.FullName -match '(?i)^assets/.*(?:junit|jest)(?:[./_-]|$)'
    } | Select-Object -First 1
    if ($forbiddenAsset) {
      throw "APK에 테스트 또는 가짜 데이터 자산이 포함됐습니다: $($forbiddenAsset.FullName)"
    }

    foreach ($dexEntry in ($archive.Entries | Where-Object { $_.FullName -match '^classes\d*\.dex$' })) {
      $stream = $dexEntry.Open()
      $memory = [System.IO.MemoryStream]::new()
      try {
        $stream.CopyTo($memory)
        $dexText = [System.Text.Encoding]::ASCII.GetString($memory.ToArray())
      } finally {
        $memory.Dispose()
        $stream.Dispose()
      }
      if ($dexText -match 'L(?:com/homeguardian/app|expo/modules/homeguardiannetworkscanner)/[A-Za-z0-9_$/-]*(?:Test|Tests|__tests__|__mocks__)[A-Za-z0-9_$/-]*;') {
        throw "APK DEX에 앱 소유 테스트 클래스가 포함됐습니다: $($dexEntry.FullName)"
      }
      if ($dexText -match 'L(?:org/junit|junit/framework)/[A-Za-z0-9_$/-]+;') {
        throw "APK DEX에 JUnit 테스트 프레임워크 클래스가 포함됐습니다: $($dexEntry.FullName)"
      }
    }
  } finally {
    $archive.Dispose()
  }
}

function Assert-EmbeddedReleaseConfig {
  param([string]$RawConfig, [string]$Label)

  try {
    $config = $RawConfig | ConvertFrom-Json
  } catch {
    throw "$Label 의 assets/app.config 가 유효한 JSON이 아닙니다."
  }
  if ($config.extra.releaseBuild -ne $true) {
    throw "$Label 에 production releaseBuild=true 설정이 포함되지 않았습니다."
  }
  if (-not $config.extra.apiBaseUrl -or $config.extra.apiBaseUrl -notmatch '^https://') {
    throw "$Label 에 HTTPS 운영 API 주소가 포함되지 않았습니다."
  }
  if (-not $config.extra.googleClientId) {
    throw "$Label 에 Google 로그인 client ID가 포함되지 않았습니다."
  }
}

Import-ReleaseEnvironment -Path $envPath
$env:NODE_ENV = "production"
$env:HG_RELEASE_BUILD = "1"

if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
  $defaultSdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
  if (Test-Path -LiteralPath $defaultSdk) {
    $env:ANDROID_HOME = $defaultSdk
    $env:ANDROID_SDK_ROOT = $defaultSdk
  }
}

if (-not $env:EXPO_PUBLIC_API_BASE_URL -or $env:EXPO_PUBLIC_API_BASE_URL -notmatch "^https://") {
  throw "운영 release 빌드는 HTTPS EXPO_PUBLIC_API_BASE_URL 이 필요합니다. HTTP 또는 빈 주소로는 빌드하지 않습니다."
}
if (-not (Test-Path -LiteralPath $googleServicesPath)) {
  throw "Firebase Android 설정 파일이 없습니다: $googleServicesPath"
}

Push-Location $mobileDir
try {
& node -e "const config=require('./app.config.js')(); const extra=config.extra ?? {}; if (extra.releaseBuild !== true || extra.allowCleartextDevelopment !== false || !/^https:\/\//i.test(extra.apiBaseUrl ?? '') || !(extra.googleClientId ?? '').trim()) process.exit(1);"
if ($LASTEXITCODE -ne 0) {
    throw "release app.config의 프로덕션 설정(릴리스 모드, HTTPS API, Google client ID)이 유효하지 않습니다."
}
} finally {
  Pop-Location
}

$releaseProperties = @(
  "HG_RELEASE_STORE_FILE",
  "HG_RELEASE_STORE_PASSWORD",
  "HG_RELEASE_KEY_ALIAS",
  "HG_RELEASE_KEY_PASSWORD"
)
$projectProperties = Join-Path $androidDir "gradle.properties"
$userProperties = Join-Path $env:USERPROFILE ".gradle\gradle.properties"
$propertyText = @($projectProperties, $userProperties) |
  Where-Object { Test-Path -LiteralPath $_ } |
  ForEach-Object { Get-Content -LiteralPath $_ -Raw }
$missingProperties = $releaseProperties | Where-Object {
  $propertyName = $_
  -not ($propertyText | Select-String -Pattern "(?m)^$([regex]::Escape($propertyName))=.+$" -Quiet)
}
if ($missingProperties) {
  throw "운영 release 서명 속성이 없습니다: $($missingProperties -join ', '). 값은 출력하지 않았습니다."
}

Push-Location $androidDir
try {
  Write-Output "[build] signed v$expectedVersion APK와 AAB 생성 시작"
  $buildStartedAt = Get-Date
  .\gradlew.bat clean :app:assembleRelease :app:bundleRelease --console=plain
  if ($LASTEXITCODE -ne 0) {
    throw "Gradle release 빌드가 실패했습니다. exit code: $LASTEXITCODE"
  }
} finally {
  Pop-Location
}

$apkPath = Join-Path $androidDir "app\build\outputs\apk\release\app-release.apk"
$aabPath = Join-Path $androidDir "app\build\outputs\bundle\release\app-release.aab"
$sourceMapPath = Join-Path $androidDir "app\build\intermediates\sourcemaps\react\release\index.android.bundle.packager.map"
$apkItem = Assert-FreshArtifact -Path $apkPath -BuildStartedAt $buildStartedAt -Label "release APK"
$aabItem = Assert-FreshArtifact -Path $aabPath -BuildStartedAt $buildStartedAt -Label "release AAB"
$sourceMapItem = Assert-FreshArtifact -Path $sourceMapPath -BuildStartedAt $buildStartedAt -Label "release source map"

Push-Location $mobileDir
try {
  & npm.cmd run verify -- --release-artifacts
  if ($LASTEXITCODE -ne 0) {
    throw "release source map 검증에 실패했습니다. exit code: $LASTEXITCODE"
  }
} finally {
  Pop-Location
}

$apksigner = Resolve-AndroidTool -Name "apksigner"
$aapt = Resolve-AndroidTool -Name "aapt"
$keytool = (Get-Command keytool -ErrorAction SilentlyContinue).Source
$jarsigner = (Get-Command jarsigner -ErrorAction SilentlyContinue).Source
$bundletool = Resolve-Bundletool
$java = (Get-Command java -ErrorAction SilentlyContinue).Source
if (-not $apksigner -or -not $aapt -or -not $keytool -or -not $jarsigner -or -not $bundletool) {
  throw "APK/AAB 서명·버전을 검증할 Android Build Tools, JDK 도구, bundletool이 필요합니다. BUNDLETOOL_JAR에 검증된 bundletool.jar 경로를 지정할 수 있습니다."
}
if ($bundletool -like "*.jar" -and -not $java) {
  throw "BUNDLETOOL_JAR를 사용할 때는 java 실행 도구가 필요합니다."
}

$apkSignature = & $apksigner verify --verbose --print-certs $apkPath
if ($LASTEXITCODE -ne 0) { throw "APK 서명 검증에 실패했습니다." }
if ($apkSignature -match 'Android Debug') {
  throw "APK가 Android debug 인증서로 서명되었습니다. 운영 keystore를 사용해야 합니다."
}
$apkSignature | Out-Host

$badging = & $aapt dump badging $apkPath
if ($LASTEXITCODE -ne 0) { throw "APK 패키지 정보 확인에 실패했습니다." }
$badgingText = $badging -join "`n"
if ($badgingText -notmatch "package: name='$([regex]::Escape($packageName))'.*versionCode='$expectedVersionCode'.*versionName='$([regex]::Escape($expectedVersion))'") {
  throw "APK 패키지 또는 버전이 $packageName / $expectedVersionCode / $expectedVersion 과 일치하지 않습니다."
}
if ($badgingText -match '(?m)^application-debuggable') {
  throw "APK가 debuggable=true 입니다. 개발용 앱은 배포하지 않습니다."
}

$apkEntries = & $aapt list $apkPath
if ($LASTEXITCODE -ne 0) { throw "APK 파일 목록 확인에 실패했습니다." }
foreach ($requiredEntry in @('assets/index.android.bundle', 'assets/app.config')) {
  if ($apkEntries -notcontains $requiredEntry) {
    throw "APK에 필수 production asset이 없습니다: $requiredEntry"
  }
}
$apkManifest = (& $aapt dump xmltree $apkPath AndroidManifest.xml) -join "`n"
if ($LASTEXITCODE -ne 0) { throw "APK 매니페스트 확인에 실패했습니다." }
if ($apkManifest -notmatch 'android:usesCleartextTraffic.*\(type 0x12\)0x0') {
  throw "APK가 cleartext 통신 차단 상태가 아닙니다."
}
if ($apkManifest -match '(?i)devlauncher|devmenu|devsettingsactivity|androidx\.compose\.ui\.tooling\.previewactivity|metro') {
  throw "APK 매니페스트에 개발 화면 또는 Metro 진입 컴포넌트가 포함됐습니다."
}
$apkConfig = Read-ZipTextEntry -ArchivePath $apkPath -EntryPath 'assets/app.config' -Label 'release APK'
Assert-EmbeddedReleaseConfig -RawConfig $apkConfig -Label 'release APK'
Assert-NoApkTestPayload -ArchivePath $apkPath

& $jarsigner -verify -certs $aabPath
if ($LASTEXITCODE -ne 0) { throw "AAB 서명 검증에 실패했습니다." }
$aabCertificate = & $keytool -printcert -jarfile $aabPath
if ($LASTEXITCODE -ne 0) { throw "AAB 서명자 확인에 실패했습니다." }
if ($aabCertificate -match "Android Debug") {
  throw "AAB가 Android debug 인증서로 서명되었습니다. 운영 keystore를 사용해야 합니다."
}
$aabCertificate | Out-Host

if ($bundletool -like "*.jar") {
  & $java -jar $bundletool validate --bundle=$aabPath
  if ($LASTEXITCODE -ne 0) { throw "AAB structure validation failed." }
  $aabManifest = & $java -jar $bundletool dump manifest --bundle=$aabPath
} else {
  & $bundletool validate --bundle=$aabPath
  if ($LASTEXITCODE -ne 0) { throw "AAB structure validation failed." }
  $aabManifest = & $bundletool dump manifest --bundle=$aabPath
}
if ($LASTEXITCODE -ne 0) { throw "AAB 매니페스트 확인에 실패했습니다." }
$aabManifestText = $aabManifest -join "`n"
$aabPackagePattern = 'package="' + [regex]::Escape($packageName) + '"'
$aabVersionCodePattern = 'versionCode="' + [regex]::Escape($expectedVersionCode) + '"'
$aabVersionNamePattern = 'versionName="' + [regex]::Escape($expectedVersion) + '"'
if ($aabManifestText -notmatch $aabPackagePattern -or
    $aabManifestText -notmatch $aabVersionCodePattern -or
    $aabManifestText -notmatch $aabVersionNamePattern) {
  throw "AAB 패키지 또는 버전이 $packageName / $expectedVersionCode / $expectedVersion 과 일치하지 않습니다."
}
if ($aabManifestText -match 'android:debuggable="true"') {
  throw "AAB가 debuggable=true 입니다. 개발용 앱은 배포하지 않습니다."
}
if ($aabManifestText -notmatch 'android:usesCleartextTraffic="false"') {
  throw "AAB가 cleartext 통신 차단 상태가 아닙니다."
}
if ($aabManifestText -match '(?i)devlauncher|devmenu|devsettingsactivity|androidx\.compose\.ui\.tooling\.previewactivity|metro') {
  throw "AAB 매니페스트에 개발 화면 또는 Metro 진입 컴포넌트가 포함됐습니다."
}
$aabConfig = Read-ZipTextEntry -ArchivePath $aabPath -EntryPath 'base/assets/app.config' -Label 'release AAB'
Assert-EmbeddedReleaseConfig -RawConfig $aabConfig -Label 'release AAB'

$apkCopy = Join-Path $repoRoot "HomeGuardian-v$expectedVersion.apk"
$aabCopy = Join-Path $repoRoot "HomeGuardian-v$expectedVersion.aab"
Copy-Item -LiteralPath $apkPath -Destination $apkCopy -Force
Copy-Item -LiteralPath $aabPath -Destination $aabCopy -Force

Write-Output "[build] release 검증 완료"
foreach ($artifact in @($apkCopy, $aabCopy)) {
  $item = Get-Item -LiteralPath $artifact
  $hash = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash
  Write-Output "  $($item.Name): $($item.Length) bytes, SHA256=$hash"
}

if ($InstallOnDevice) {
  $adb = Resolve-AndroidTool -Name "adb"
  if (-not $adb) { throw "설치 검증에는 adb가 필요합니다." }
  $devices = & $adb devices | Select-Object -Skip 1 | Where-Object { $_ -match "\sdevice$" }
  if ($devices.Count -ne 1) {
    throw "설치 검증에는 연결·승인된 Android 기기 한 대가 필요합니다."
  }
  & $adb install -r $apkCopy
  if ($LASTEXITCODE -ne 0) { throw "APK 설치에 실패했습니다." }
  $installed = & $adb shell dumpsys package $packageName
  if ($installed -notmatch "versionCode=$expectedVersionCode" -or $installed -notmatch "versionName=$expectedVersion") {
    throw "설치된 앱의 버전이 release 산출물과 일치하지 않습니다."
  }
  Write-Output "[install] $packageName v$expectedVersion ($expectedVersionCode) 설치 확인"
}
