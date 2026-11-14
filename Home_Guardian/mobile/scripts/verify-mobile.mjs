import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = process.cwd();
const sourceRoot = join(root, "src");
const requireReleaseArtifacts = process.argv.includes("--release-artifacts");
const targetVersion = "1.0.0";
const targetVersionCode = 100;

const read = (path) => readFileSync(path, "utf8");
const readOptional = (path) => (existsSync(path) ? read(path) : "");

function fail(message) {
  throw new Error(`[v1.0.0 static gate] ${message}`);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function listSourceFiles(directory, extensions = new Set([".ts", ".tsx"])) {
  if (!existsSync(directory)) return [];

  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) return listSourceFiles(path, extensions);
    return [...extensions].some((extension) => name.endsWith(extension)) ? [path] : [];
  });
}

function sourceEntries(directory) {
  return listSourceFiles(directory)
    .filter((path) => !/\.(test|spec)\.[cm]?[jt]sx?$/.test(path))
    .map((path) => ({ path, source: read(path) }));
}

function label(path) {
  return relative(root, path).replaceAll("\\", "/");
}

function findFunctionCalls(source, functionName) {
  const calls = [];
  const matcher = new RegExp(`\\b${functionName}\\s*\\(`, "g");
  let match;

  while ((match = matcher.exec(source))) {
    let cursor = matcher.lastIndex;
    let depth = 1;
    let quote = null;
    let escaped = false;

    for (; cursor < source.length && depth > 0; cursor += 1) {
      const character = source[cursor];
      if (quote) {
        if (escaped) {
          escaped = false;
        } else if (character === "\\") {
          escaped = true;
        } else if (character === quote) {
          quote = null;
        }
        continue;
      }
      if (character === "'" || character === '"' || character === "`") {
        quote = character;
      } else if (character === "(") {
        depth += 1;
      } else if (character === ")") {
        depth -= 1;
      }
    }

    if (depth === 0) {
      calls.push({ argumentsText: source.slice(matcher.lastIndex, cursor - 1), offset: match.index });
      matcher.lastIndex = cursor;
    }
  }

  return calls;
}

function splitTopLevelArguments(argumentsText) {
  const argumentsList = [];
  let start = 0;
  let depth = 0;
  let quote = null;
  let escaped = false;

  for (let index = 0; index < argumentsText.length; index += 1) {
    const character = argumentsText[index];
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character;
    } else if (character === "(" || character === "[" || character === "{") {
      depth += 1;
    } else if (character === ")" || character === "]" || character === "}") {
      depth -= 1;
    } else if (character === "," && depth === 0) {
      argumentsList.push(argumentsText.slice(start, index).trim());
      start = index + 1;
    }
  }

  argumentsList.push(argumentsText.slice(start).trim());
  return argumentsList;
}

function visibleLiteralText(source) {
  // This gate deliberately checks strings that can become user-facing UI copy,
  // rather than comments, imports, test fixtures, or scanner implementation
  // identifiers. Runtime payloads are covered by the central presentation
  // checks below.
  const withoutComments = source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:\\])\/\/[^\r\n]*/gm, "$1");
  const stringValues = [...withoutComments.matchAll(/(["'`])((?:\\.|(?!\1)[\s\S])*)\1/g)].map((match) => match[2]);
  const jsxText = [...withoutComments.matchAll(/>([^<>{}]+)</g)].map((match) => match[1]);
  return [...stringValues, ...jsxText].join("\n");
}

function findForbiddenVisibleDeviceText(source) {
  const visibleText = visibleLiteralText(source);
  const normalizedText = visibleText.toLocaleLowerCase("ko-KR");
  const literal = forbiddenPublicDeviceLabels.find((name) =>
    normalizedText.includes(name.toLocaleLowerCase("ko-KR")),
  );
  if (literal) return literal;
  return forbiddenPublicDevicePatterns.find(({ pattern }) => pattern.test(visibleText))?.label;
}

const packageJson = JSON.parse(read(join(root, "package.json")));
const packageLock = JSON.parse(read(join(root, "package-lock.json")));
const appConfig = JSON.parse(read(join(root, "app.json")));
const easConfig = JSON.parse(read(join(root, "eas.json")));
const gradleText = read(join(root, "android", "app", "build.gradle"));
const manifestText = read(join(root, "android", "app", "src", "main", "AndroidManifest.xml"));
const lightStylesText = read(join(root, "android", "app", "src", "main", "res", "values", "styles.xml"));
const nightStylesText = read(join(root, "android", "app", "src", "main", "res", "values-night", "styles.xml"));
const nightColorsText = read(join(root, "android", "app", "src", "main", "res", "values-night", "colors.xml"));
const dynamicAppConfigText = read(join(root, "app.config.js"));
const networkSecurityPluginPath = join(root, "plugins", "with-network-security.js");
const legacyCleartextPluginPath = join(root, "plugins", "with-cleartext-traffic.js");
const networkSecurityPluginText = readOptional(networkSecurityPluginPath);
const scannerModuleText = read(
  join(
    root,
    "modules",
    "home-guardian-network-scanner",
    "android",
    "src",
    "main",
    "java",
    "expo",
    "modules",
    "homeguardiannetworkscanner",
    "HomeGuardianNetworkScannerModule.kt",
  ),
);
const scannerArpTestText = read(
  join(
    root,
    "modules",
    "home-guardian-network-scanner",
    "android",
    "src",
    "test",
    "java",
    "expo",
    "modules",
    "homeguardiannetworkscanner",
    "ArpFreshnessTest.kt",
  ),
);
const scannerSocketBindingTestText = read(
  join(
    root,
    "modules",
    "home-guardian-network-scanner",
    "android",
    "src",
    "test",
    "java",
    "expo",
    "modules",
    "homeguardiannetworkscanner",
    "WifiBoundSocketFactoryTest.kt",
  ),
);
const scannerSubnetSourceTestText = read(
  join(
    root,
    "modules",
    "home-guardian-network-scanner",
    "android",
    "src",
    "test",
    "java",
    "expo",
    "modules",
    "homeguardiannetworkscanner",
    "NetworkSubnetSourceTest.kt",
  ),
);
const scannerObservationCapacityTestText = read(
  join(
    root,
    "modules",
    "home-guardian-network-scanner",
    "android",
    "src",
    "test",
    "java",
    "expo",
    "modules",
    "homeguardiannetworkscanner",
    "ObservationCapacityTest.kt",
  ),
);
const scannerManifestText = read(
  join(root, "modules", "home-guardian-network-scanner", "android", "src", "main", "AndroidManifest.xml"),
);
const scannerBridgeText = read(join(sourceRoot, "native", "homeGuardianNetworkScanner.ts"));
const releaseScriptText = read(join(root, "scripts", "build-release-apk.ps1"));
const themeText = read(join(sourceRoot, "theme.ts"));
const apiText = read(join(sourceRoot, "api", "homeGuardianApi.ts"));
const apiTypesText = read(join(sourceRoot, "api", "types.ts"));
const googleSignInText = read(join(sourceRoot, "hooks", "useGoogleSignIn.ts"));
const controllerText = read(join(sourceRoot, "state", "useHomeGuardianController.ts"));
const storageText = read(join(sourceRoot, "state", "storage.ts"));
const safeScreenText = read(join(sourceRoot, "components", "SafeScreen.tsx"));
const profileText = read(join(sourceRoot, "screens", "ProfileScreen.tsx"));
const guardianScreenText = read(join(sourceRoot, "screens", "GuardianScreen.tsx"));
const deviceDetailText = read(join(sourceRoot, "screens", "DeviceDetailScreen.tsx"));
const textFieldText = read(join(sourceRoot, "components", "TextField.tsx"));
const bigCTAButtonText = read(join(sourceRoot, "components", "BigCTAButton.tsx"));
const trafficLightBadgeText = read(join(sourceRoot, "components", "TrafficLightBadge.tsx"));
const bottomTabBarText = read(join(sourceRoot, "components", "BottomTabBar.tsx"));
const scoreRingText = read(join(sourceRoot, "components", "ScoreRing.tsx"));
const deviceCardPath = join(sourceRoot, "components", "DeviceCard.tsx");
const deviceCardText = read(deviceCardPath);
const devicesScreenText = read(join(sourceRoot, "screens", "DevicesScreen.tsx"));
const scanResultScreenText = read(join(sourceRoot, "screens", "ScanResultScreen.tsx"));
const notificationsScreenText = read(join(sourceRoot, "screens", "NotificationsScreen.tsx"));
const guardianModeScreenText = read(join(sourceRoot, "screens", "GuardianModeScreen.tsx"));
const studioText = read(join(sourceRoot, "components", "StudioPrimitives.tsx"));
const userLoginScreenText = read(join(sourceRoot, "screens", "UserLoginScreen.tsx"));
const screenHeaderText = read(join(sourceRoot, "components", "ScreenHeader.tsx"));
const devicePresentationText = readOptional(join(sourceRoot, "utils", "devicePresentation.ts"));
const scanCoverageText = read(join(sourceRoot, "utils", "scanCoverage.ts"));
const responsiveLayoutText = read(join(sourceRoot, "utils", "responsiveLayout.ts"));
const appPath = join(root, "App.tsx");
const appEntryText = read(appPath);
const runtimeSourceEntries = [{ path: appPath, source: appEntryText }, ...sourceEntries(sourceRoot)];
const uiEntries = [
  ...sourceEntries(join(sourceRoot, "screens")),
  ...sourceEntries(join(sourceRoot, "components")),
];
const screenEntries = sourceEntries(join(sourceRoot, "screens"));
const userUiEntries = [
  ...(existsSync(appPath) ? [{ path: appPath, source: read(appPath) }] : []),
  ...uiEntries,
];
const userCopyUtilityEntries = [
  "riskCopy.ts",
  "guardianInvite.ts",
  "guardianWardDisplay.ts",
]
  .map((name) => join(sourceRoot, "utils", name))
  .filter(existsSync)
  .map((path) => ({ path, source: read(path) }));
// devicePresentation.ts and deviceIcons.ts intentionally stay outside this
// literal-copy scan: they hold sanitizer deny-list values and internal device
// type keys. The public presentation boundary is asserted separately below.
const userVisibleCopyEntries = [...userUiEntries, ...userCopyUtilityEntries];
const uiText = userVisibleCopyEntries.map(({ source }) => source).join("\n");
const textScaleBlock = themeText.match(/export\s+const\s+text\s*=\s*\{([\s\S]*?)\};/);
const textScale = Object.fromEntries(
  [...(textScaleBlock?.[1].matchAll(/([A-Za-z_$][\w$]*)\s*:\s*(\d+(?:\.\d+)?)/g) ?? [])].map((match) => [match[1], Number(match[2])]),
);

// 1. 모든 공개 버전 표면은 1.0.0 / 100을 같은 기준으로 사용한다.
assert(packageJson.version === targetVersion, `package.json version must be ${targetVersion}`);
assert(packageLock.version === targetVersion, `package-lock.json root version must be ${targetVersion}`);
assert(
  packageLock.packages?.[""]?.version === targetVersion,
  `package-lock.json package version must be ${targetVersion}`,
);
assert(
  !packageJson.dependencies?.["expo-dev-client"] &&
    !Object.keys(packageLock.packages ?? {}).some((packagePath) =>
      /node_modules\/expo-dev-(?:client|launcher|menu)(?:\/|$)/.test(packagePath),
    ),
  "distribution dependency graph must not include Expo dev client, launcher, or menu",
);
assert(
  releaseScriptText.includes("Assert-NoApkTestPayload") &&
    releaseScriptText.includes("release source map") &&
    releaseScriptText.includes("--release-artifacts") &&
    releaseScriptText.includes("com/homeguardian/app") &&
    releaseScriptText.includes("expo/modules/homeguardiannetworkscanner") &&
    releaseScriptText.includes("org/junit") &&
    releaseScriptText.includes("junit/framework"),
  "release builder must reject app-owned test classes, JUnit payloads, test assets, and unaudited source maps",
);
assert(
  storageText.includes('import AsyncStorage from "@react-native-async-storage/async-storage"') &&
    !/\b(?:memoryStore|secureMemoryStore|memoryStorage|memoryFallbackIsAllowed|loadStorage)\b/.test(storageText) &&
    !/\bNODE_ENV\b|typeof\s+navigator/.test(storageText),
  "production storage must use native persistent stores directly without memory or test-environment fallbacks",
);
assert(
  safeScreenText.includes('import { SafeAreaView, useSafeAreaInsets } from "react-native-safe-area-context"') &&
    !/\b(?:loadSafeAreaModule|fallbackInsets|useSafeAreaInsetsResolved)\b/.test(safeScreenText) &&
    !/require[^\n]*react-native-safe-area-context/.test(safeScreenText),
  "SafeScreen must use the native safe-area dependency directly without a zero-inset or View fallback",
);
assert(
  appEntryText.includes('import { SafeAreaProvider } from "react-native-safe-area-context"') &&
    appEntryText.includes("<SafeAreaProvider>") &&
    !/\b(?:loadSafeAreaProvider|safeAreaProviderModule)\b/.test(appEntryText) &&
    !/require[^\n]*react-native-safe-area-context/.test(appEntryText),
  "App must always install the native SafeAreaProvider",
);
assert(
  guardianScreenText.includes('placeholder="보호자 이메일 주소"') &&
    !/placeholder=["'][^"']*@(?:example\.(?:com|org|net)|example\.test)["']/i.test(guardianScreenText),
  "GuardianScreen must not ship an example account as an input placeholder",
);
const runtimeTestImport = runtimeSourceEntries.find(({ source }) =>
  /(?:from\s+|require\s*\()["'][^"']*(?:__tests__|__mocks__|(?:^|\/)test(?:s|ing)?\/|fixtures?\/|samples?\/|demos?\/|seeds?\/)/i.test(source),
);
if (runtimeTestImport) {
  fail(`${label(runtimeTestImport.path)} imports test-only, mock, fixture, sample, demo, or seed code`);
}

const releaseSourceMapPath = join(
  root,
  "android",
  "app",
  "build",
  "intermediates",
  "sourcemaps",
  "react",
  "release",
  "index.android.bundle.packager.map",
);
if (requireReleaseArtifacts) {
  assert(existsSync(releaseSourceMapPath), "fresh release source map is missing");
}
if (existsSync(releaseSourceMapPath)) {
  const releaseSourceMap = JSON.parse(read(releaseSourceMapPath));
  const releaseSources = Array.isArray(releaseSourceMap.sources) ? releaseSourceMap.sources : [];
  const releaseContents = Array.isArray(releaseSourceMap.sourcesContent) ? releaseSourceMap.sourcesContent : [];
  const appDefinedReleaseSources = releaseSources
    .map((path, index) => ({ path, source: releaseContents[index] ?? "" }))
    .filter(
      ({ path }) =>
        !path.includes("node_modules") &&
        /(^|[\\/])(?:App\.tsx|src[\\/]|modules[\\/]home-guardian-network-scanner[\\/])/.test(path),
    );
  const bundledTestSource = appDefinedReleaseSources.find(({ path }) =>
    /(^|[\\/])(?:__tests__|__mocks__|tests?|mocks?|fixtures?|samples?|demos?|seeds?)(?:[\\/]|\.|$)/i.test(path),
  );
  if (bundledTestSource) {
    fail(`release source map includes app-owned test or fake-data source: ${bundledTestSource.path}`);
  }
  const bundledRuntimeFallback = appDefinedReleaseSources.find(({ source }) =>
    /\b(?:memoryStore|secureMemoryStore|memoryStorage|memoryFallbackIsAllowed|fallbackInsets|loadSafeAreaProvider)\b|guardian@example\.com/.test(
      source,
    ),
  );
  if (bundledRuntimeFallback) {
    fail(`release source map includes removed runtime fallback data: ${bundledRuntimeFallback.path}`);
  }
  assert(appDefinedReleaseSources.length > 0, "release source map does not expose app-owned sources for audit");
}
const startScanPayloadBlock = apiTypesText.match(/export\s+type\s+StartScanPayload\s*=\s*\{([\s\S]*?)\};/);
assert(startScanPayloadBlock, "StartScanPayload type is missing");
assert(
  /scan_source:\s*"android-native"\s*;/.test(startScanPayloadBlock[1]) &&
    !/windows-port-probe/.test(startScanPayloadBlock[1]) &&
    /network_context:\s*NetworkContext\s*;/.test(startScanPayloadBlock[1]) &&
    /devices:\s*DiscoveredDevicePayload\[\]\s*;/.test(startScanPayloadBlock[1]) &&
    !/network_context\?\s*:|devices\?\s*:/.test(startScanPayloadBlock[1]),
  "mobile StartScanPayload must require Android-native source, network context, and discovered devices",
);
assert(
  !controllerText.includes("windows-port-probe") && !controllerText.includes("컴퓨터로 연결 확인"),
  "mobile runtime must not retain the legacy Windows scan-source branch",
);
const startScanMethodStart = apiText.indexOf("startScan(payload: StartScanPayload)");
const startScanMethodEnd = apiText.indexOf("\n  getScanResult", startScanMethodStart);
const startScanMethodText = apiText.slice(startScanMethodStart, startScanMethodEnd);
assert(startScanMethodStart >= 0 && startScanMethodEnd > startScanMethodStart, "startScan API boundary is missing");
assert(
  startScanMethodText.includes("network_context: payload.network_context") &&
    startScanMethodText.includes("devices: payload.devices") &&
    !/payload\.network_context\s*\?\?|payload\.devices\s*\?\?/.test(startScanMethodText),
  "startScan must send the required native context and device list without synthesized fallbacks",
);
const blockedScanPayloadStart = scannerBridgeText.indexOf("function blockedScanPayload(");
const blockedScanPayloadEnd = scannerBridgeText.indexOf("\nfunction actualScanBlockCode", blockedScanPayloadStart);
const blockedScanPayloadText = scannerBridgeText.slice(blockedScanPayloadStart, blockedScanPayloadEnd);
assert(
  blockedScanPayloadStart >= 0 &&
    blockedScanPayloadEnd > blockedScanPayloadStart &&
    blockedScanPayloadText.includes('scan_source: "android-native"') &&
    blockedScanPayloadText.includes("network_context: {") &&
    blockedScanPayloadText.includes("devices: []") &&
    blockedScanPayloadText.includes("isActualScan: false"),
  "native scan failures must preserve the explicit Android context/list contract without a synthetic scan",
);
const failedScanStart = scannerModuleText.indexOf("private fun failedScan(");
const failedScanEnd = scannerModuleText.indexOf("\n  private fun numberOption", failedScanStart);
const failedScanText = scannerModuleText.slice(failedScanStart, failedScanEnd);
assert(
  failedScanStart >= 0 &&
    failedScanEnd > failedScanStart &&
    failedScanText.includes("safeScanFailure(code)") &&
    !failedScanText.includes("message: String") &&
    !scannerBridgeText.includes("result.error_message") &&
    scannerBridgeText.includes("safeNativeScanFailure(blockedCode ?? result.error_code)"),
  "native scan failures must expose only allowlisted codes and fixed resident-facing messages",
);
for (const forbiddenRuntimeCopy of [
  "Expo Go",
  "native module",
  "development/release build",
]) {
  assert(
    !visibleLiteralText(scannerBridgeText).includes(forbiddenRuntimeCopy),
    `native scanner user copy must not expose development terminology: ${forbiddenRuntimeCopy}`,
  );
}
assert(appConfig.expo?.version === targetVersion, `app.json expo.version must be ${targetVersion}`);
assert(appConfig.expo?.orientation === "default", "app.json must allow system rotation rather than locking the app to portrait");
assert(appConfig.expo?.android?.versionCode === targetVersionCode, `app.json android.versionCode must be ${targetVersionCode}`);
assert(
  new RegExp(`\\bversionCode\\s+${targetVersionCode}\\b`).test(gradleText),
  `android/app/build.gradle versionCode must be ${targetVersionCode}`,
);
assert(
  new RegExp(`\\bversionName\\s+["']${targetVersion.replaceAll(".", "\\.")}["']`).test(gradleText),
  `android/app/build.gradle versionName must be ${targetVersion}`,
);
assert(
  profileText.includes(targetVersion),
  "ProfileScreen must show the same app version as package.json",
);
assert(
  easConfig.build?.production?.autoIncrement === false,
  "EAS production autoIncrement must stay false so source versionCode 100 is the build contract",
);
assert(easConfig.cli?.appVersionSource === "local", "EAS must use the local source as the app-version source");
assert(
  gradleText.includes("hasReleaseSigning") && gradleText.includes("Release signing is required"),
  "release Gradle tasks must fail clearly when signing properties are missing",
);
assert(
  /signingConfig\s+signingConfigs\.release/.test(gradleText) &&
    !/signingConfig\s+project\.hasProperty\([^\n]+signingConfigs\.debug/.test(gradleText),
  "release artifacts must not fall back to the Android debug signing key",
);
assert(
  appConfig.expo?.plugins?.includes("./plugins/with-network-security") &&
    !appConfig.expo?.plugins?.includes("./plugins/with-cleartext-traffic"),
  "Expo config must use the release-safe network-security plugin",
);
assert(existsSync(networkSecurityPluginPath) && networkSecurityPluginText, "network-security plugin is missing");
assert(!existsSync(legacyCleartextPluginPath), "legacy app-wide cleartext plugin must be removed");
assert(
  /android:usesCleartextTraffic="false"/.test(manifestText),
  "native AndroidManifest production baseline must disable cleartext traffic",
);
assert(
  !/android:screenOrientation="portrait"/.test(manifestText),
  "native AndroidManifest must not reintroduce a portrait-only activity lock",
);
const upnpDescriptionStart = scannerModuleText.indexOf("private fun fetchUpnpDescription");
const upnpDescriptionEnd = scannerModuleText.indexOf("private fun extractXmlTag", upnpDescriptionStart);
const upnpDescriptionText = scannerModuleText.slice(upnpDescriptionStart, upnpDescriptionEnd);
assert(
  upnpDescriptionStart >= 0 &&
    upnpDescriptionEnd > upnpDescriptionStart &&
    upnpDescriptionText.includes("java.net.URI(location)") &&
    upnpDescriptionText.includes('endpoint.scheme.equals("http", ignoreCase = true)') &&
    upnpDescriptionText.includes("scannerHttpGetBody") &&
    upnpDescriptionText.includes("readTimeoutMillis = 1_500") &&
    !upnpDescriptionText.includes("HttpURLConnection"),
  "UPnP description probing must keep URL validation and use bounded raw-socket HTTP without weakening release cleartext policy",
);
assert(
  /module\.exports\s*=\s*\(\{\s*config\s*\}/.test(dynamicAppConfigText) &&
    dynamicAppConfigText.includes("const isReleaseBuild") &&
    dynamicAppConfigText.includes("const allowCleartextDevelopment") &&
    dynamicAppConfigText.includes("allowCleartextDevelopment,") &&
    networkSecurityPluginText.includes("config.extra?.allowCleartextDevelopment === true"),
  "app.config.js must inherit app.json and allow local HTTP only by explicit development opt-in through the network-security plugin",
);
assert(
  scannerManifestText.includes('android.permission.ACCESS_COARSE_LOCATION') &&
    scannerManifestText.includes('android.permission.ACCESS_FINE_LOCATION') &&
    scannerBridgeText.includes("ACCESS_COARSE_LOCATION") &&
    scannerBridgeText.includes("ACCESS_FINE_LOCATION"),
  "Android 12 and lower LAN scanning must declare and request the coarse/fine location permission pair",
);
assert(
  scannerModuleText.includes("buildCandidateHosts(") &&
    scannerModuleText.includes('contextMap["subnet_cidr"]') &&
    scannerModuleText.includes('"candidate_coverage_complete"') &&
    scannerModuleText.includes("readNeighborTable(networkSnapshot.wifiInterfaceName)") &&
    scannerModuleText.includes("discoverMdnsLegacyHints(") &&
    scannerModuleText.includes("confirmLegacyMdnsHintOnBoundWifi(") &&
    scannerModuleText.includes("socket.connect(InetSocketAddress(target, 5353))") &&
    scannerModuleText.includes("discoverSsdp(discoveries, subnetAllowlist, socketFactory)"),
  "native discovery must enumerate the connected private LAN and confirm Android 12 NSD hints through a Wi-Fi-bound mDNS response",
);
assert(
  scannerModuleText.includes("let(connectivity::getLinkProperties)") &&
    scannerModuleText.includes("linkProperties?.interfaceName") &&
    scannerModuleText.includes("parseArpTableForInterface") &&
    scannerModuleText.includes("selectFreshArpObservations") &&
    scannerModuleText.includes("TcpEndpointState.REFUSED") &&
    scannerModuleText.includes("currentEvidenceHosts = discoveries.keys.toSet()") &&
    scannerModuleText.includes("trustedCurrentEvidenceHosts = currentEvidenceHosts") &&
    scannerModuleText.includes("candidateStimulationComplete") &&
    scannerModuleText.includes("activelyStimulatedHosts = tcpScanOutcome.activelyStimulatedHosts") &&
    scannerModuleText.includes("tcpProbeConfirmsDevicePresence") &&
    scannerModuleText.includes("result.state == TcpEndpointState.OPEN") &&
    scannerModuleText.includes("freshNeighborStateHosts = neighborAfterProbe.freshStateHosts") &&
    scannerArpTestText.includes("same CIDR row from another interface is rejected") &&
    scannerArpTestText.includes("unchanged pre scan row without active evidence stays suppressed") &&
    scannerArpTestText.includes("current mDNS SSDP or ONVIF response preserves unchanged neighbor MAC") &&
    scannerArpTestText.includes("complete current candidate stimulation preserves unchanged physical MAC") &&
    scannerArpTestText.includes("partial TCP completion preserves completed neighbor without reviving unrelated stale row") &&
    scannerArpTestText.includes("fresh ip neigh state preserves unchanged physical MAC without product clues") &&
    scannerArpTestText.includes("only an open endpoint confirms TCP device presence") &&
    scannerArpTestText.includes("refused TCP response stays in transport metrics without creating ARP-less device"),
  "ARP observations must match active Wi-Fi and require current discovery, an OPEN endpoint, or fresh neighbour state",
);
assert(
  scannerModuleText.includes("verifiedArpTable") &&
    scannerModuleText.includes("if (verifiedMac != null) put(\"mac_address\", verifiedMac)") &&
    !scannerModuleText.includes("macFromFingerprints") &&
    scannerArpTestText.includes("spoofed fingerprint MAC is never promoted without fresh ARP") &&
    scannerArpTestText.includes("fresh ARP MAC wins when advertised fingerprint MAC disagrees"),
  "advertised fingerprint MAC text must never become physical identity without a fresh current-interface ARP mapping",
);
assert(
  scannerModuleText.includes("ActiveSubnetAllowlist.from(") &&
    scannerModuleText.includes("subnetAllowlist.acceptObservation(src)") &&
    scannerModuleText.includes("subnetAllowlist.acceptObservation(ip)") &&
    scannerModuleText.includes("resolveAllowedHttpHost") &&
    scannerModuleText.includes('"out_of_subnet_observations_dropped"') &&
    scannerBridgeText.includes('"out_of_subnet_observations_dropped"'),
  "every native multicast/neighbor observation and UPnP endpoint must remain inside the active connected subnet",
);
assert(
  scannerModuleText.includes("connectivity::getLinkProperties") &&
    scannerModuleText.includes("linkProperties") &&
    scannerModuleText.includes("linkAddress.prefixLength") &&
    scannerModuleText.includes('source = "link-properties"') &&
    scannerModuleText.includes("!hasUsableCapturedLinkAddress && isWifi") &&
    scannerModuleText.includes("validatedDhcpWifiSubnet(") &&
    !scannerModuleText.includes("ipv4RangeFromLocalAndNetmask") &&
    scannerSubnetSourceTestText.includes("LinkProperties IPv4 address and prefix are the authoritative subnet source") &&
    scannerSubnetSourceTestText.includes("usable ambiguous LinkProperties addresses must not authorize DHCP fallback") &&
    scannerSubnetSourceTestText.includes("slash24 DHCP netmask is safe in network or vendor little endian order") &&
    scannerSubnetSourceTestText.includes("DHCP fallback rejects gateway outside candidate subnet"),
  "the active Wi-Fi LinkProperties IPv4 prefix must be authoritative and any DHCP endian fallback must fail closed",
);
assert(
  scannerModuleText.includes("network.bindSocket(socket)") &&
    scannerModuleText.includes("WifiBoundSocketFactory") &&
    scannerModuleText.includes("wifiNetwork.getAllByName(host)") &&
    scannerModuleText.includes("nsdManager.discoverServices(") &&
    scannerModuleText.includes("wifiNetwork,") &&
    scannerModuleText.includes("serviceInfo.network != wifiNetwork") &&
    scannerModuleText.includes("Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU") &&
    !scannerModuleText.includes("bindProcessToNetwork") &&
    scannerModuleText.includes('"wifi_network_socket_bind_failures"') &&
    scannerModuleText.includes('"wifi_network_unbound_paths_skipped"') &&
    scannerModuleText.includes('"wifi_network_evidence_path_failures"') &&
    scannerSocketBindingTestText.includes("binding failure closes socket and returns no fallback socket") &&
    scannerSocketBindingTestText.includes("first binding failure suppresses every later socket instead of using default route"),
  "every native scanner socket and DNS/NSD path must be pinned to the captured active Wi-Fi Network and fail closed on binding loss",
);
assert(
  (scannerModuleText.match(/DatagramSocket\(/g) ?? []).length === 1 &&
    (scannerModuleText.match(/MulticastSocket\(/g) ?? []).length === 1 &&
    (scannerModuleText.match(/\bSocket\(\)/g) ?? []).length === 1 &&
    !scannerModuleText.includes("InetAddress.getAllByName"),
  "scanner protocols must not create unbound sockets or use process-default DNS outside WifiBoundSocketFactory",
);
assert(
  scannerModuleText.includes('"tcp_scan_timed_out"') &&
    scannerModuleText.includes('"tcp_transport_complete"') &&
    scannerModuleText.includes('"observation_limit_reached"') &&
    scannerModuleText.includes("NATIVE_SCAN_HOST_HARD_CAP = 512") &&
    scannerModuleText.includes("classifyTcpEndpointFailure") &&
    scannerModuleText.includes('"scan_partial"') &&
    scannerModuleText.includes('"neighbor_presence_confirmed"') &&
    scannerModuleText.includes('"neighbor_coverage_complete"') &&
    scannerModuleText.includes('"candidate_stimulation_complete"') &&
    scannerModuleText.includes('"arp_stale_entries_suppressed"') &&
    scannerModuleText.includes('"neighbor_unverified_hosts"') &&
    scannerModuleText.includes("buildFairTcpProbeTargets(hosts, ports)") &&
    scannerBridgeText.includes('"tcp_scan_timed_out"') &&
    scannerBridgeText.includes('"tcp_transport_complete"') &&
    scannerBridgeText.includes('"observation_limit_reached"') &&
    scannerBridgeText.includes('"observation_hosts_dropped"') &&
    scannerBridgeText.includes('"candidate_stimulation_complete"') &&
    scannerBridgeText.includes('"arp_observation_hosts"') &&
    scannerBridgeText.includes('"arp_stale_entries_suppressed"') &&
    scannerBridgeText.includes('"neighbor_unverified_hosts"') &&
    scannerBridgeText.includes('"scan_partial"') &&
    scannerArpTestText.includes("local TCP transport failures hold coverage while peer negatives do not") &&
    scannerArpTestText.includes("neighbor absence is diagnostic while real execution loss keeps coverage partial") &&
    scannerArpTestText.includes("port major probe order gives every host a first port before later ports") &&
    scannerArpTestText.includes("single MAC-less open port remains presence evidence without product identity") &&
    scannerSubnetSourceTestText.includes("large CIDR alternates local and gateway slash24 neighborhoods first") &&
    scannerObservationCapacityTestText.includes("requested observation limit can never exceed 512") &&
    scannerObservationCapacityTestText.includes("open TCP overflow stays aggregate transport evidence without growing observations"),
  "native TCP, socket binding, fair probe order, execution-loss coverage, and bounded observations must fail closed",
);
assert(
  !/\b(?:wifiManager\.)?(?:startScan|scanResults|getScanResults)\b/.test(scannerModuleText),
  "nearby Wi-Fi scan results must never be counted as household devices; only the connected LAN is in scope",
);
assert(
  scannerModuleText.includes('contextMap["interface_type"] != "wifi"') &&
    scannerModuleText.includes('contextMap["is_private_network"] != true') &&
    scannerModuleText.includes('"NETWORK_NOT_SCANNABLE"'),
  "native discovery must fail closed outside the connected private Wi-Fi network",
);
assert(
  easConfig.build?.production?.env?.HG_RELEASE_BUILD === "1",
  "EAS production must explicitly mark the build as release before resolving API URLs",
);
assert(
  apiText.includes("function isReleaseBuild") &&
    apiText.includes("releaseBuild = isReleaseBuild()") &&
    apiText.includes("if (releaseBuild && !/^https:\\/\\//i.test(trimmed))"),
  "release API client must reject non-HTTPS base URLs",
);
for (const evidence of [
  "bundleRelease",
  "bundletool",
  "usesCleartextTraffic",
  "HG_RELEASE_STORE_FILE",
  "InstallOnDevice",
  "assets/index.android.bundle",
  "application-debuggable",
  "devlauncher|devmenu|devsettingsactivity|androidx\\.compose\\.ui\\.tooling\\.previewactivity|metro",
  "Assert-EmbeddedReleaseConfig",
  "Android Debug",
]) {
  assert(releaseScriptText.includes(evidence), `release artifact script is missing required evidence: ${evidence}`);
}

// 2. 테마는 실행 중 선택되는 팔레트만 사용한다. 전역 고정 colors는 허용하지 않는다.
assert(themeText.includes("ThemeProvider") && themeText.includes("useAppTheme"), "theme.ts must provide ThemeProvider and useAppTheme");
assert(themeText.includes("useColorScheme") && themeText.includes('"system"'), "theme.ts must support light, dark, and system preferences");
assert(!/export\s+(?:const|let|var)\s+colors\b/.test(themeText), "theme.ts must not export a global static colors palette");
assert(/useState<ThemePreference>\("light"\)/.test(themeText), "theme.ts must start from the readable light preference");
assert(
  /storageGet<ThemePreference>\(StorageKeys\.themePreference\)/.test(themeText) &&
    /storageSet\(StorageKeys\.themePreference, nextPreference\)/.test(themeText),
  "theme preference must be restored and persisted through StorageKeys.themePreference",
);
assert(
  /preference === "system" \? \(systemScheme === "dark" \? "dark" : "light"\) : preference/.test(themeText),
  "system preference must resolve from the current device color scheme",
);
assert(
  /colors:\s*mode === "dark" \? darkColors : lightColors/.test(themeText),
  "ThemeProvider must provide the active palette, not a static UI palette",
);
assert(
  themeText.includes("Appearance.setColorScheme") &&
    themeText.includes("heroBg:") &&
    themeText.includes("heroText:") &&
    themeText.includes("ctaOverlay:") &&
    themeText.includes("ctaOutline:"),
  "theme changes must synchronize native uiMode and keep brand/CTA foreground tokens separate",
);
assert(
  studioText.includes("colors.heroBg") &&
    studioText.includes("colors.heroText") &&
    userLoginScreenText.includes('color={colors.heroText}') &&
    userLoginScreenText.includes("color: colors.heroText"),
  "navy hero content must use the dedicated readable hero foreground",
);
for (const entry of uiEntries) {
  assert(!entry.source.includes("#D9E3EE"), `${label(entry.path)} must use the active divider token, not a fixed light divider`);
}

const lightPaletteBlock = themeText.match(/const\s+lightColors\s*:\s*ThemeColors\s*=\s*\{([\s\S]*?)\n\};/);
assert(lightPaletteBlock, "theme.ts must define the light palette");
const lightPalette = Object.fromEntries(
  [...lightPaletteBlock[1].matchAll(/^\s*([A-Za-z_$][\w$]*)\s*:\s*"(#[0-9A-Fa-f]{6})",/gm)].map((match) => [match[1], match[2].toUpperCase()]),
);
for (const token of ["bg", "surface", "surfaceElevated", "paperWarm"]) {
  assert(
    lightPalette[token] === "#FFFFFF",
    `light-mode ordinary surface token ${token} must remain pure white (#FFFFFF)`,
  );
}
for (const token of ["surfaceSoft", "surfaceMuted", "careBg", "protectBg", "calmBg"]) {
  assert(
    /^#(?:E|F)[0-9A-F]{5}$/.test(lightPalette[token] ?? ""),
    `light-mode secondary plane ${token} must stay a restrained cool near-white`,
  );
}
assert(
  lightPalette.infoBg === lightPalette.unknownBg,
  "light-mode info/progress fill must use the neutral-gray state surface rather than a decorative blue tint",
);

function styleBody(source, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`(?:^|\\n)\\s{2,}${escapedName}:\\s*\\{`).exec(source);
  if (!match) return "";

  const start = source.indexOf("{", match.index);
  let depth = 0;
  for (let index = start; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(match.index, index + 1);
    }
  }
  return "";
}

// Product-style surfaces: the active v1.0.0 system uses the Studio Halo
// composition. Legacy primitive files are compatibility boundaries only.
const whiteSurfaceStyles = [
  [join(sourceRoot, "screens", "ScanProgressScreen.tsx"), "steps"],
  [join(sourceRoot, "screens", "ScanResultScreen.tsx"), "heroBox"],
  [join(sourceRoot, "screens", "ScanResultScreen.tsx"), "riskSection"],
  [join(sourceRoot, "screens", "GuardianScreen.tsx"), "body"],
  [deviceCardPath, "row"],
  [join(sourceRoot, "components", "RiskHighlightCard.tsx"), "card"],
  [join(sourceRoot, "components", "StudioPrimitives.tsx"), "heroLight"],
  [join(sourceRoot, "components", "StudioPrimitives.tsx"), "heroDark"],
  [join(sourceRoot, "components", "StudioPrimitives.tsx"), "ribbon"],
  [join(sourceRoot, "components", "StudioPrimitives.tsx"), "command"],
];
for (const [path, name] of whiteSurfaceStyles) {
  const block = styleBody(read(path), name);
  assert(block, `${label(path)} must retain the ${name} visual style block`);
  if (path.endsWith("DesignPrimitives.tsx") || path.endsWith("PremiumPrimitives.tsx") || path.endsWith("AtelierPrimitives.tsx") || path.endsWith("StudioPrimitives.tsx")) {
    assert(/backgroundColor:\s*colors\.(?:surface|surfaceSoft|cta)/.test(read(path)), `${label(path)} ${name} must be palette-driven`);
    continue;
  }
  assert(
    /backgroundColor:\s*colors\.(?:surface|bg)/.test(block) || /border(?:Top|Bottom)Color:\s*colors\.divider/.test(block),
    `${label(path)} ${name} must use the editorial surface/divider system`,
  );
}

const loginScreenText = read(join(sourceRoot, "screens", "LoginScreen.tsx"));
for (const entry of screenEntries) {
  assert(!entry.source.includes("components/PremiumPrimitives") && !entry.source.includes("components\\PremiumPrimitives"), `${label(entry.path)} must not import the retired PremiumPrimitives card system`);
}
assert(
  loginScreenText.includes("<StudioHero") &&
    loginScreenText.includes('variant="navy"') &&
    loginScreenText.includes("<StudioCommand") &&
    loginScreenText.includes("emphasis"),
  "LoginScreen must use the Studio Halo stage and clear primary/secondary command rows",
);

const primitiveText = read(join(sourceRoot, "components", "DesignPrimitives.tsx"));
assert(primitiveText.includes("Animated.timing") && primitiveText.includes("useReducedMotion") && primitiveText.includes("only retained primitive"), "DesignPrimitives must remain a reduced-motion-safe behavior helper, not a visual card system");
assert(
  primitiveText.includes("delay <= 96") &&
    primitiveText.includes("duration: motion.quick") &&
    !screenHeaderText.includes("<Reveal"),
  "screen headers must render immediately and list reveal effects must stay short and bounded",
);
for (const [path, required] of [
  [join(sourceRoot, "screens", "UserLoginScreen.tsx"), "<StudioHero"],
  [join(sourceRoot, "screens", "ScanConsentScreen.tsx"), "<StudioHero"],
  [join(sourceRoot, "screens", "ScanResultScreen.tsx"), "<StudioSignalRibbon"],
  [join(sourceRoot, "screens", "DevicesScreen.tsx"), "<StudioSignalRibbon"],
  [join(sourceRoot, "screens", "NotificationsScreen.tsx"), "<StudioSignalRibbon"],
  [join(sourceRoot, "screens", "ProfileScreen.tsx"), "<StudioSignalRibbon"],
  [join(sourceRoot, "screens", "GuardianModeScreen.tsx"), "<StudioSignalRibbon"],
]) {
  assert(read(path).includes(required) && read(path).includes("StudioPrimitives"), `${label(path)} must use the shared Studio Halo design primitives`);
}

const riskHighlightText = read(join(sourceRoot, "components", "RiskHighlightCard.tsx"));
const riskHighlightCard = styleBody(riskHighlightText, "card");
assert(
  /backgroundColor:\s*colors\.surface/.test(riskHighlightCard) &&
    /borderBottomColor:\s*colors\.divider/.test(riskHighlightCard) &&
    /borderTopColor:\s*colors\.divider/.test(riskHighlightCard) &&
    /borderLeftWidth:\s*4/.test(riskHighlightCard),
  "RiskHighlightCard must use the Studio divider band and reserve traffic-light color for its status rail",
);
const guardianSurfaceText = read(join(sourceRoot, "screens", "GuardianScreen.tsx"));
const guardianBodyStyle = styleBody(guardianSurfaceText, "body");
assert(
  guardianSurfaceText.includes("contentContainerStyle={styles.body}") && /backgroundColor:\s*colors\.(?:surface|bg)/.test(guardianBodyStyle),
  "GuardianScreen must keep its divider/list layout on the ordinary surface",
);
assert(
  guardianSurfaceText.includes("<StudioStatus") &&
    guardianSurfaceText.includes("<StudioSection") &&
    guardianSurfaceText.includes("<StudioSignalRibbon") &&
    guardianSurfaceText.includes("styles.inviteStage") &&
    guardianSurfaceText.includes("styles.readyStage"),
  "GuardianScreen must use the dedicated invite-to-management Studio flow",
);
assert(
  guardianModeScreenText.includes("<StudioStatus") &&
    guardianModeScreenText.includes("<StudioSignalRibbon") &&
    guardianModeScreenText.includes("styles.loginStage") &&
    guardianModeScreenText.includes("styles.heroScoreLine") &&
    guardianModeScreenText.includes("styles.wardCard"),
  "GuardianModeScreen must use the dedicated login, ward-selection, and read-only score stages",
);

const staticThemeImport = userUiEntries.find(({ source }) => {
  const themeImports = source.match(/import[\s\S]*?from\s+["'][^"']*theme["'];?/g) ?? [];
  return themeImports.some((statement) => /\b(?:colors|lightColors|darkColors)\b/.test(statement));
});
if (staticThemeImport) {
  fail(`${label(staticThemeImport.path)} imports a static theme palette; use useAppTheme or useThemedStyles instead`);
}

const warmBackground = userUiEntries.find(({ source }) => /#fed7aa/i.test(source));
if (warmBackground) {
  fail(`${label(warmBackground.path)} still contains the removed warm background color #FED7AA`);
}

for (const entry of uiEntries) {
  const invalidToneCall = findFunctionCalls(entry.source, "tone").find(({ argumentsText }) => {
    const argumentsList = splitTopLevelArguments(argumentsText);
    return argumentsList.length < 2 || !argumentsList.at(-1);
  });
  if (invalidToneCall) {
    fail(`${label(entry.path)} calls tone without the active theme palette`);
  }
}

// 3. 취약 사용자용 UI 텍스트와 주요 제목의 최소 크기를 정적으로 확인한다.
// These are the critical active controls in the user and guardian flows. The
// evidence keeps the 56dp interaction contract tied to the current palette
// instead of relying on a static global color object.
function assertInteractiveControlEvidence(path, control, evidence) {
  const source = readOptional(path);
  assert(source, `${control} source is missing`);
  for (const token of evidence) {
    assert(source.includes(token), `${control} is missing interactive/theme evidence: ${token}`);
  }
}

const criticalInteractiveControls = [
  {
    path: join(sourceRoot, "components", "ActionButton.tsx"),
    control: "ActionButton",
    evidence: ["useAppTheme", 'accessibilityRole="button"', "style={({ pressed", "minHeight: touchTargetMin", "palette.pressed"],
  },
  {
    path: join(sourceRoot, "components", "BigCTAButton.tsx"),
    control: "BigCTAButton",
    evidence: ["useThemedStyles(createStyles)", 'accessibilityRole="button"', "style={({ pressed", "minHeight: ctaHeight", "paddingVertical: spacing.sm", "palette.pressed"],
  },
  {
    path: join(sourceRoot, "components", "BottomTabBar.tsx"),
    control: "BottomTabBar",
    evidence: ["useThemedStyles(createStyles)", 'accessibilityRole="tab"', "accessibilityState={{ selected }}", "styles.tab", "backgroundColor: colors.surfaceSoft", "borderColor: colors.cta", "minHeight: 68"],
  },
  {
    path: deviceCardPath,
    control: "DeviceCard",
    evidence: ["useThemedStyles(createStyles)", 'accessibilityRole="button"', "${palette.label}", "style={({ pressed", "backgroundColor: colors.surface", "minHeight: 122"],
  },
  {
    path: join(sourceRoot, "components", "ScreenHeader.tsx"),
    control: "ScreenHeader back control",
    evidence: ["useThemedStyles(createStyles)", 'accessibilityRole="button"', "style={({ pressed", "height: touchTargetMin", "width: touchTargetMin"],
  },
  {
    path: join(sourceRoot, "screens", "ProfileScreen.tsx"),
    control: "Profile toggles and theme selector",
    evidence: ["useAppTheme", 'accessibilityRole="switch"', 'accessibilityRole="radio"', "setPreference(option.value)", "styles.toggleRow", "pressed ? styles.rowPressed", "minHeight: touchTargetMin"],
  },
  {
    path: join(sourceRoot, "screens", "GuardianModeScreen.tsx"),
    control: "Guardian ward list",
    evidence: ["useThemedStyles(createStyles)", "style={styles.wardCard}", 'accessibilityRole="button"', "backgroundColor: colors.bg", "minHeight: touchTargetMin"],
  },
];
for (const { path, control, evidence } of criticalInteractiveControls) {
  assertInteractiveControlEvidence(path, control, evidence);
}

assert(
  bigCTAButtonText.includes("minHeight: ctaHeight") &&
    bigCTAButtonText.includes("paddingVertical: spacing.sm") &&
    !bigCTAButtonText.includes("height: ctaHeight"),
  "BigCTAButton must use a padded minimum height so enlarged labels can expand the control",
);
assert(
  trafficLightBadgeText.includes("minHeight: sz.minHeight") &&
    trafficLightBadgeText.includes("paddingVertical: sz.paddingVertical") &&
    !trafficLightBadgeText.includes("height: sz.height"),
  "TrafficLightBadge must use a padded minimum height so enlarged status text is not clipped",
);
assert(
  deviceCardText.includes("${palette.label}"),
  "DeviceCard accessibility label must announce the visible traffic-light state",
);
assert(
  deviceCardText.includes("useWindowDimensions") &&
    deviceCardText.includes("shouldUseCompactDeviceCardLayout") &&
    deviceCardText.includes('testID="device-card-compact-header"') &&
    deviceCardText.includes("styles.identityCompact"),
  "DeviceCard must move identity copy to a full-width compact layout on narrow or enlarged-text screens",
);
assert(
  responsiveLayoutText.includes("safeWidth / safeFontScale < safeThreshold") &&
    riskHighlightText.includes("shouldUseStackedCardLayout") &&
    riskHighlightText.includes("risk-highlight-compact-layout") &&
    riskHighlightText.includes("styles.headCompact") &&
    scanResultScreenText.includes("shouldUseStackedCardLayout") &&
    scanResultScreenText.includes('testID="home-risk-compact-header"') &&
    scanResultScreenText.includes("styles.riskRowCopyCompact"),
  "risk summary cards must stack status controls above full-width copy on narrow or enlarged-text screens",
);
assert(
  bottomTabBarText.includes("accessibilityState={{ selected }}"),
  "BottomTabBar must expose the selected tab state",
);
assert(
  bottomTabBarText.includes('accessibilityRole="toolbar"') &&
    !bottomTabBarText.includes('accessibilityRole="tabbar"'),
  "BottomTabBar container must use an Android-supported accessibility role",
);
assert(
  lightStylesText.includes('name="android:statusBarColor">@color/app_window_background') &&
    lightStylesText.includes('name="android:navigationBarColor">@color/app_window_background') &&
    lightStylesText.includes('name="android:windowLightStatusBar">true') &&
    lightStylesText.includes('name="android:windowLightNavigationBar" tools:targetApi="27">true') &&
    nightStylesText.includes('name="android:windowLightStatusBar">false') &&
    nightStylesText.includes('name="android:windowLightNavigationBar" tools:targetApi="27">false') &&
    nightColorsText.includes('<color name="app_window_background">#101418</color>'),
  "Android status, navigation, and pre-React window colors must follow the light and dark resource themes",
);
assert(
  appEntryText.includes("actions.navigate(TAB_TO_SCREEN[tab])") &&
    !appEntryText.includes("actions.setScreen(TAB_TO_SCREEN[tab])") &&
    appEntryText.includes("[actions.goBack]") &&
    controllerText.includes('current.screen === "guardianMode"') &&
    controllerText.includes("[...current.history, current.screen]"),
  "bottom tabs and guardian entry must preserve prior screens for Android back navigation",
);
assert(
  googleSignInText.includes("shouldAutoExchangeCode: false"),
  "Google PKCE code exchange must have a single owner",
);
assert(
  devicesScreenText.includes("style={styles.emptyScroll}") &&
    devicesScreenText.includes("contentContainerStyle={styles.empty}") &&
    devicesScreenText.includes("emptyScroll: {") &&
    devicesScreenText.includes("flexGrow: 1"),
  "Devices empty state must remain scrollable when large text increases its height",
);
assert(
  notificationsScreenText.includes("style={styles.emptyScroll}") &&
    notificationsScreenText.includes("contentContainerStyle={styles.emptyWrap}") &&
    notificationsScreenText.includes("emptyScroll: {") &&
    notificationsScreenText.includes("flexGrow: 1"),
  "Notifications empty state must remain scrollable when large text increases its height",
);
assert(
  guardianModeScreenText.includes("<Modal") &&
    guardianModeScreenText.includes("contentContainerStyle={styles.modalContent}") &&
    guardianModeScreenText.includes('keyboardShouldPersistTaps="handled"') &&
    (guardianModeScreenText.includes('maxHeight: "100%"') || guardianModeScreenText.includes('maxHeight: "88%"')) &&
    !guardianModeScreenText.includes("NativeModal") &&
    !guardianModeScreenText.includes("ReactNative as any"),
  "Guardian name editor must use a keyboard-safe scrollable modal card",
);
assert(
  scoreRingText.includes("height: size") &&
    scoreRingText.includes("width: size") &&
    scoreRingText.includes("aspectRatio: 1") &&
    scoreRingText.includes("RING_MAX_FONT_SIZE_MULTIPLIER") &&
    scoreRingText.includes("maxFontSizeMultiplier={RING_MAX_FONT_SIZE_MULTIPLIER}") &&
    scoreRingText.includes('maxWidth: "76%"'),
  "ScoreRing must keep compact visual labels inside its fixed canvas while exposing the full accessible value",
);

// 4. Studio Halo 시각 계층이 단순 색상 교체로 회귀하지 않았는지 확인한다.
// 화면은 하나의 깊이 있는 stage와 signal ribbon/command list를 공유해야 한다.
assert(
  studioText.includes("heroArt") &&
    studioText.includes("heroGlyph") &&
    studioText.includes("ribbon") &&
    studioText.includes("commandStripe") &&
    studioText.includes("commandEmphasis") &&
    studioText.includes("<Svg"),
  "StudioPrimitives must retain the Halo stage, signal ribbon, command list, and static SVG artwork",
);
assert(
  bigCTAButtonText.includes("borderLeftWidth: 6") &&
    bigCTAButtonText.includes("borderBottomWidth: 1") &&
    !bigCTAButtonText.includes("elevation:"),
  "BigCTAButton must remain an editorial command row rather than a rounded elevated card",
);
assert(
  textFieldText.includes("borderBottomWidth: 2") && textFieldText.includes("inputFocus") && !textFieldText.includes("borderRadius:"),
  "TextField must retain the large ruled input treatment",
);

function directTextInputTags(source) {
  return source.match(/<TextInput\b[\s\S]*?\/>/g) ?? [];
}

for (const entry of uiEntries) {
  for (const input of directTextInputTags(entry.source)) {
    assert(/\baccessibilityLabel\s*=/.test(input), `${label(entry.path)} TextInput is missing an accessibilityLabel`);
    assert(/\baccessibilityHint\s*=/.test(input), `${label(entry.path)} TextInput is missing an accessibilityHint`);
  }
}

assert(
  textFieldText.includes("accessibilityLabel={accessibilityLabel ?? label}") &&
    textFieldText.includes('accessibilityHint={accessibilityHint ?? helper ?? "내용을 입력하세요."}'),
  "TextField must derive a non-empty programmatic label and hint",
);
assert(/\bminHeight\s*:\s*64\b/.test(textFieldText), "TextField input must retain a 64dp minimum height");
assert(!/\bheight\s*:\s*64\b/.test(textFieldText), "TextField input must not use a fixed 64dp height");

// 이 검사는 실제 기기의 글꼴 크기 조정을 대신하지 않는다. 다만 큰 글꼴에서
// 피할 수 있는 잘림을 만드는 고정 한 줄 제한과 입력 높이 회귀는 막는다.
for (const [source, screen] of [
  [profileText, "ProfileScreen"],
  [guardianScreenText, "GuardianScreen"],
]) {
  assert(!/\bnumberOfLines\s*=\s*\{\s*1\s*\}/.test(source), `${screen} must not clip visible text to one line`);
}
assert(
  /accessibilityLabel="기기 이름"/.test(deviceDetailText) &&
    /accessibilityHint="새 이름을 입력한 뒤 저장을 누르세요\."/.test(deviceDetailText),
  "DeviceDetailScreen rename input must expose a programmatic label and hint",
);

for (const entry of uiEntries) {
  const smallFont = [...entry.source.matchAll(/fontSize\s*:\s*(\d+(?:\.\d+)?)/g)].find((match) => Number(match[1]) < 20);
  if (smallFont) {
    fail(`${label(entry.path)} has a visible fontSize below 20sp: ${smallFont[0]}`);
  }
  const smallToken = [...entry.source.matchAll(/fontSize\s*:\s*text\.([A-Za-z_$][\w$]*)/g)].find(
    (match) => Number(textScale[match[1]]) < 20,
  );
  if (smallToken) {
    fail(`${label(entry.path)} uses a visible text scale below 20sp: ${smallToken[0]}`);
  }
}

function hasLargeTitleStyle(source) {
  if (/fontSize\s*:\s*(?:3[2-9]|[4-9]\d|\d{3,})(?:\.\d+)?\b/.test(source)) return true;
  return [...source.matchAll(/fontSize\s*:\s*text\.([A-Za-z_$][\w$]*)/g)].some(
    (match) => Number(textScale[match[1]]) >= 32,
  );
}

const titleTargets = [
  [join(sourceRoot, "components", "ScreenHeader.tsx"), "ScreenHeader"],
  [join(sourceRoot, "components", "StudioPrimitives.tsx"), "StudioPrimitives"],
  [join(sourceRoot, "screens", "UserLoginScreen.tsx"), "UserLoginScreen"],
  [join(sourceRoot, "screens", "DevicesScreen.tsx"), "DevicesScreen"],
  [join(sourceRoot, "screens", "DeviceDetailScreen.tsx"), "DeviceDetailScreen"],
  [join(sourceRoot, "screens", "GuardianModeScreen.tsx"), "GuardianModeScreen"],
];
for (const [path, title] of titleTargets) {
  const source = readOptional(path);
  assert(
    hasLargeTitleStyle(source),
    `${title} must contain a 32sp-or-larger primary title style`,
  );
}

assert(!/letterSpacing\s*:\s*-/.test(uiText), "visible UI must not use negative letter spacing");

// 4. access/refresh/session/logout 흐름이 앱 소스에 실제로 연결되어 있어야 한다.
for (const endpoint of ["/api/v1/auth/session", "/api/v1/auth/refresh", "/api/v1/auth/logout"]) {
  assert(apiText.includes(endpoint), `missing mobile API mapping: ${endpoint}`);
}
for (const evidence of [
  "refreshAuthSession",
  "logoutAuthSession",
  "setRefreshHandler",
  "SecureStorageKeys.authSession",
  "secureStorageSetRequired(SecureStorageKeys.authSession",
]) {
  assert(controllerText.includes(evidence), `session restore/refresh/logout evidence is missing: ${evidence}`);
}
assert(
  !/\bsecureStorageSet\(SecureStorageKeys\.(?:authSession|pendingAuthHandoff|pendingLogout)/.test(controllerText),
  "authentication secrets must not use the compatibility SecureStore writer; use secureStorageSetRequired",
);
assert(storageText.includes('authSession: "hg.authSession"'), "auth session must have a SecureStore key");
const asyncStorageKeys = storageText.match(/export\s+const\s+StorageKeys\s*=\s*\{([\s\S]*?)\}\s+as\s+const;/);
assert(
  asyncStorageKeys && !/\b[A-Za-z_]*(?:auth|refresh|session|token)[A-Za-z_]*\s*:/i.test(asyncStorageKeys[1]),
  "AsyncStorage keys must not contain access or refresh session data",
);
const storageClearStart = storageText.indexOf("export async function storageClear");
const secureStorageGetStart = storageText.indexOf("export async function secureStorageGet");
const storageClearSource = storageText.slice(storageClearStart, secureStorageGetStart);
assert(storageClearStart >= 0 && secureStorageGetStart > storageClearStart, "storageClear boundary must be defined");
assert(
  !/secureStorage(?:Clear|Remove|Set|Get)|SecureStorageKeys/.test(storageClearSource),
  "cache/schema cleanup must not globally delete the SecureStore auth session",
);
assert(
  /storageClear\(\{\s*preserveAppPreferences:\s*true\s*\}\)/.test(controllerText),
  "logout must preserve the saved theme preference while clearing app cache",
);
const hydrationStart = controllerText.indexOf("const hydratedRef = useRef(false);");
const logoutStart = controllerText.indexOf("const logout = useCallback", hydrationStart);
const hydrationSource = controllerText.slice(hydrationStart, logoutStart);
assert(hydrationStart >= 0 && logoutStart > hydrationStart, "session hydration boundary must be defined");
assert(
  hydrationSource.includes("storageGet<number>(StorageKeys.schemaVersion)") &&
    hydrationSource.includes("migrateLegacyProductDerivedCache()") &&
    hydrationSource.includes("storageSet(StorageKeys.schemaVersion, STORAGE_SCHEMA_VERSION)") &&
    storageText.includes("export const STORAGE_SCHEMA_VERSION = 7;") &&
    controllerText.includes("const LEGACY_PRODUCT_DERIVED_STORAGE_KEYS") &&
    controllerText.includes("StorageKeys.scanResult") &&
    controllerText.includes("StorageKeys.devices") &&
    controllerText.includes("StorageKeys.notifications") &&
    controllerText.includes("StorageKeys.lastScanAt") &&
    controllerText.includes("_legacyProductSummary"),
  "schema migration must evict legacy product-derived cache before advancing the marker",
);
assert(
  !hydrationSource.includes("secureStorageClear("),
  "schema migration must not globally clear a valid auth session",
);
assert(
  (controllerText.match(/normalizeGuardianInvites\(guardiansResult\.value\?\.items\)/g) ?? []).length >= 3 &&
    !controllerText.includes("guardiansResult.value.items"),
  "every fulfilled guardian refresh must normalize a missing or null items list before screen state is patched",
);
assert(!apiText.includes("/api/v1/auth/test-login"), "test-login API must not be bundled in the mobile app");
assert(!/(?:test\s*account\s*login|테스트\s*(?:계정|로그인))/i.test(uiText), "test-login text must not be bundled in the user UI");
const forbiddenTechnicalUiTerms = [
  { label: "technical read-only term", pattern: /\bread-only\b/i },
  { label: "technical protocol term", pattern: /\b(?:mDNS|SSDP|ONVIF|RTSP|UPnP|CVE)\b/i },
  { label: "developer authentication term", pattern: /\b(?:OAuth|PKCE)\b/i },
  { label: "developer environment term", pattern: /\b(?:MVP|mock|demo)\b/i },
];
for (const entry of userVisibleCopyEntries) {
  const visibleText = visibleLiteralText(entry.source);
  const forbiddenTechnicalTerm = forbiddenTechnicalUiTerms.find(({ pattern }) => pattern.test(visibleText));
  if (forbiddenTechnicalTerm) {
    fail(`${label(entry.path)} contains a forbidden user-visible ${forbiddenTechnicalTerm.label}`);
  }
}

const semanticPlaceholderCopyPatterns = [
  { label: "automatic product confirmation copy", pattern: /제품\s*정보\s*자동\s*확인/i },
  { label: "unfinished identification copy", pattern: /식별(?:이|을|은|을)?\s*(?:끝나지|처리|진행|중)/i },
  { label: "additional detected connection copy", pattern: /추가로\s*감지된\s*연결/i },
  { label: "identity pending copy", pattern: /식별\s*대기/i },
  { label: "score pending copy", pattern: /점수\s*보류/i },
  { label: "product confirmation required copy", pattern: /제품(?:\s*정보)?\s*확인(?:이)?\s*필요/i },
  {
    label: "product or connection candidate count copy",
    pattern: /(?:제품|연결)\s*후보[\s\S]{0,24}(?:\$\{[^}]+\}|\d+)\s*개/i,
  },
  {
    label: "automatic-identification pending count copy",
    pattern: /(?:자동\s*확인|식별)[\s\S]{0,48}(?:제품|연결|물건)[\s\S]{0,24}(?:\$\{[^}]+\}|\d+)\s*개/i,
  },
];
for (const entry of [
  ...userVisibleCopyEntries,
  { path: join(sourceRoot, "state", "useHomeGuardianController.ts"), source: controllerText },
]) {
  const visibleText = visibleLiteralText(entry.source);
  const forbiddenCopy = semanticPlaceholderCopyPatterns.find(({ pattern }) => pattern.test(visibleText));
  if (forbiddenCopy) {
    fail(`${label(entry.path)} contains forbidden semantic placeholder copy: ${forbiddenCopy.label}`);
  }
}

// 5. 공개 DeviceCard와 그 전용 fixture에는 금지된 임시 기기명이 남아 있으면 안 된다.
const forbiddenDeviceNames = [
  "웹 관리 기기",
  "제조사 미확인",
  "정체불명",
  "알 수 없는",
  "기기 후보",
  "미확인",
  "임시 기기",
  "후보 기기",
  "web-device",
  "web device",
  "unknown device",
  "unidentified device",
  "unverified device",
  "candidate device",
  "unresolved device",
  "temporary device",
  "generic device",
  "realtek",
  "espressif",
  "esp32",
  "chipset",
];

// Keep this list at the user-visible UI boundary. Scanner evidence and test
// fixtures are allowed to retain their internal values so the normalizer can
// be tested without reintroducing those values into the app UI.
const forbiddenPublicDeviceLabels = [
  "\uC6F9 \uAD00\uB9AC \uAE30\uAE30",
  "\uC81C\uC870\uC0AC \uBBF8\uD655\uC778",
  "\uC815\uCCB4\uBD88\uBA85 \uAE30\uAE30",
  "\uC54C \uC218 \uC5C6\uB294 \uAE30\uAE30",
  "\uAE30\uAE30 \uD6C4\uBCF4",
  "\uBBF8\uD655\uC778 \uAE30\uAE30",
  "\uC784\uC2DC \uAE30\uAE30",
  "\uD6C4\uBCF4 \uAE30\uAE30",
  "web-device",
  "web device",
  "unknown device",
  "unidentified device",
  "unverified device",
  "candidate device",
  "unresolved device",
  "temporary device",
  "generic device",
  "제품 정보 확인 필요",
  "제품 확인이 필요한 물건",
  "식별 처리 중인 네트워크 기기",
  "확인 필요 기기",
];

const forbiddenPublicDevicePatterns = [
  { label: "chipset label", pattern: /\b(?:realtek|espressif|mediatek|qualcomm|broadcom|atheros|chipset)\b/i },
  { label: "chip model label", pattern: /\b(?:rtl|esp|mt|qca|bcm)\s*[-_]?\d{2,}\b/i },
  { label: "OUI or IEEE registration label", pattern: /\b(?:OUI|IEEE|IANA|MA[-\s]?[LMS])\b/i },
  { label: "registration agency label", pattern: /\b(?:Wi-Fi Alliance|Bluetooth SIG|MAC Vendor|IEEE Registration Authority|IEEE Standards Association|Registration Authority)\b/i },
  { label: "registration agency label", pattern: /(?:OUI\s*\uB4F1\uB85D\s*\uAE30\uAD00|\uB4F1\uB85D\s*\uAE30\uAD00)/i },
  {
    label: "private OUI registration label",
    pattern: /\bprivate(?:[\s:/-]+(?:oui|registration(?:\s+authority)?|address(?:\s+block)?|mac|ieee|iana|ma[-\s]?[lms]|device)|\s+(?:\uB4F1\uB85D(?:\uAE30\uAD00)?|\uAE30\uAE30))\b/i,
  },
];

for (const entry of userVisibleCopyEntries) {
  const forbiddenName = findForbiddenVisibleDeviceText(entry.source);
  if (forbiddenName) {
    fail(`${label(entry.path)} contains a forbidden user-visible device or chipset label: ${forbiddenName}`);
  }
}
assert(devicePresentationText.includes("presentDevice"), "mobile cache/UI must have a central device presentation helper");
assert(deviceCardText.includes("presentDevice(device)") && !/\bdevice\.name\b/.test(deviceCardText), "DeviceCard must render the presented device name, not raw device.name");
for (const presentationCall of [
  "presentDevice",
  "presentDevices",
  "presentDashboard",
  "presentGuardianDashboard",
  "presentNotifications",
  "presentScanResult",
]) {
  assert(controllerText.includes(presentationCall), `user-visible payload normalization is missing: ${presentationCall}`);
}
assert(
  apiTypesText.includes('export type IdentityResearchStatus = "complete" | "review_required";') &&
    apiTypesText.includes("identity_research_status?: IdentityResearchStatus") &&
    (apiTypesText.match(/identity_findings\?: IdentityFinding\[\]/g) ?? []).length >= 4,
  "mobile API types must carry the two-state identity research contract",
);
assert(
  scanCoverageText.includes("identityResearchState") &&
    scanCoverageText.includes('reviewRequired ? "review_required" : "complete"') &&
    scanCoverageText.includes("source.coverage_complete === true") &&
    scanCoverageText.includes("partialStatus ||= source.status === \"partial\" && !sourceHasCompleteCoverage"),
  "identity research must remain distinct from physical scan coverage",
);
assert(
  (devicePresentationText.match(/identity_findings:\s*\[\]/g) ?? []).length >= 3 &&
    !devicePresentationText.includes("presentIdentityFinding"),
  "individual identity findings must be dropped at every mobile presentation boundary",
);
for (const entry of screenEntries) {
  assert(
    !entry.source.includes("identity_findings"),
    `${label(entry.path)} must show scan-level retry state instead of individual identity cards`,
  );
}
for (const screenName of ["DevicesScreen.tsx", "ScanResultScreen.tsx", "ScanProgressScreen.tsx", "GuardianModeScreen.tsx"]) {
  const screenSource = read(join(sourceRoot, "screens", screenName));
  assert(
    !screenSource.includes("identity_pending_count") && !screenSource.includes("identity_findings"),
    `${screenName} must use the scan-level identity state, not raw identity payload fields`,
  );
}
assert(
    controllerText.includes("const research = identityResearchState(result)") &&
    controllerText.includes("if (!coverage.isPartial)") &&
    !controllerText.includes("if (!coverage.isPartial && !research.isIncomplete)") &&
    controllerText.includes("devices: deviceCacheAfterScan(presentDevices(result.devices))") &&
    controllerText.includes("presentDeviceCollection(") &&
    devicePresentationText.includes("const devices = presentDeviceCollection(result.devices, result.detected_connections)") &&
    devicePresentationText.includes("...presentDetectedConnections(connections)") &&
    !devicePresentationText.includes("const hasVerifiedL2Neighbor =") &&
    devicePresentationText.includes("const hasVerifiedL2Presence = isVerifiedL2Presence(") &&
    devicePresentationText.includes("if (!hasVerifiedProductClue && !hasVerifiedObservedFamily && !hasVerifiedL2Presence) return null") &&
    devicePresentationText.includes('"현재 Wi-Fi 이웃 확인"') &&
    !devicePresentationText.includes('"neighbor-presence": "현재 Wi-Fi 이웃 확인"') &&
    devicePresentationText.includes('normalizedService === "tcp-service"') &&
    devicePresentationText.includes('normalizedService === "neighbor-presence"') &&
    devicePresentationText.includes('observedService.toLowerCase() !== "neighbor-presence"') &&
    devicePresentationText.includes('const PUBLIC_L2_FALLBACK_LABEL = "Wi-Fi 단말"') &&
    devicePresentationText.includes("PUBLIC_OBSERVATION_SUFFIX_PATTERN") &&
    devicePresentationText.includes("!sourceOnlyVerified") &&
    devicePresentationText.includes("observed_port_verified") &&
    devicePresentationText.includes("observation_suffix_verified") &&
    devicePresentationText.includes("observed_source_only_verified") &&
    devicePresentationText.includes("const hasProvisionalObservedScore =") &&
    devicePresentationText.includes('serverScoreStatus === "provisional"') &&
    devicePresentationText.includes("(coverage.isPartial && !hasProvisionalObservedScore)") &&
    devicePresentationText.includes('? "provisional"') &&
    controllerText.includes('rawResult.security_score.score_status === "provisional"') &&
    scanResultScreenText.includes("집 전체 최종 점수가 아니") &&
    scanCoverageText.includes('SCAN_INCOMPLETE_TITLE = "점검을 모두 마치지 못했어요"') &&
    scanCoverageText.includes('SCAN_SCORE_WITHHELD_COPY = "안전 점수를 확정하지 않았어요."') &&
    scanCoverageText.includes('SCAN_CONFIRMED_RISK_COPY = "확인된 위험 안내를 먼저 살펴보세요."'),
  "identity state must stay separate from completion, score, and visible detected connections",
);

// 기존 핵심 흐름의 삭제를 정적 확인한다. 세부 동작은 Jest와 실제 기기 검증에서 별도로 확인한다.
const requiredScreenFiles = [
  "LoginScreen.tsx",
  "UserLoginScreen.tsx",
  "DashboardScreen.tsx",
  "ScanConsentScreen.tsx",
  "ScanProgressScreen.tsx",
  "ScanResultScreen.tsx",
  "DevicesScreen.tsx",
  "DeviceDetailScreen.tsx",
  "GuardianScreen.tsx",
  "GuardianModeScreen.tsx",
  "NotificationsScreen.tsx",
  "SettingsScreen.tsx",
  "ProfileScreen.tsx",
];
for (const name of requiredScreenFiles) {
  assert(existsSync(join(sourceRoot, "screens", name)), `required existing screen is missing: ${name}`);
}
for (const method of ["loginWithGoogle", "loginAsGuardianWithGoogle", "startScan", "logout", "loadGuardianWards"]) {
  assert(controllerText.includes(method), `required existing controller flow is missing: ${method}`);
}
for (const endpoint of ["/api/v1/dashboard", "/api/v1/devices", "/api/v1/security/scan", "/api/v1/guardians"]) {
  assert(apiText.includes(endpoint), `required existing API mapping is missing: ${endpoint}`);
}

console.log("v1.0.0 mobile static verification passed");
