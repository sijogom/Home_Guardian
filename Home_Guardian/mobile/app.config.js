const fs = require("node:fs");
const path = require("node:path");

const appJson = require("./app.json");

// .env.local 을 직접 파싱한다.
// Expo CLI(`expo start` / `eas build`) 는 자동으로 .env.local 의 EXPO_PUBLIC_* 를 inject 하지만,
// `gradlew assembleRelease` 처럼 Expo CLI 를 거치지 않는 native build 에서는 inject 가 누락된다.
// 그래서 app.config.js 가 빌드 시점에 .env.local 을 직접 읽어 process.env 와 extra 양쪽에 채운다.
function loadDotEnv(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const text = fs.readFileSync(filePath, "utf8");
  const result = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    result[key] = value;
  }
  return result;
}

const envLocal = loadDotEnv(path.resolve(__dirname, ".env.local"));
// .env.local 값으로 process.env 에 없는 키만 보완 (셸 환경변수 우선).
for (const [key, value] of Object.entries(envLocal)) {
  if (process.env[key] === undefined || process.env[key] === "") {
    process.env[key] = value;
  }
}

// A production artifact carries user credentials and must only call an HTTPS
// API.  Development can still opt into a local HTTP backend explicitly, but
// no production/EAS release may inherit that exception from a developer shell.
const isReleaseBuild =
  process.env.HG_RELEASE_BUILD === "1" ||
  process.env.EAS_BUILD_PROFILE === "production" ||
  process.env.NODE_ENV === "production";
const allowCleartextDevelopment = !isReleaseBuild && process.env.HG_ALLOW_CLEARTEXT_DEV === "1";

module.exports = ({ config } = {}) => {
  // Expo가 app.json을 읽어 전달한 기준 설정을 우선한다. 기본값은 Expo 외부의
  // 정적 검사에서도 같은 기준 설정을 확인할 수 있게만 남겨 둔다.
  const expo = config ?? appJson.expo;
  return {
    ...expo,
    extra: {
      ...expo.extra,
      apiBaseUrl: process.env.EXPO_PUBLIC_API_BASE_URL ?? expo.extra?.apiBaseUrl ?? "",
      googleClientId: process.env.EXPO_PUBLIC_GOOGLE_CLIENT_ID ?? expo.extra?.googleClientId ?? "",
      releaseBuild: isReleaseBuild,
      // Expo의 Android 공개 스키마에는 없는 내부 플러그인 입력이다.
      // 네트워크 보안 플러그인만 이 값을 읽어 AndroidManifest 속성을 만든다.
      allowCleartextDevelopment,
    },
  };
};
