// Google 로그인 설정 유틸.
// client_id 는 두 경로로 얻는다:
//   1) process.env.EXPO_PUBLIC_GOOGLE_CLIENT_ID (Expo build 시 inline)
//   2) Constants.expoConfig.extra.googleClientId (app.config.js 에서 inject)
// 실제 OAuth 흐름과 hook 호출은 ../hooks/useGoogleSignIn.ts 에서 처리한다.
// 이 파일은 hook 외부 (예: 화면 로직, 상태 계산) 에서도 안전하게 호출 가능한 순수 함수만 노출한다.

declare const process: { env?: { EXPO_PUBLIC_GOOGLE_CLIENT_ID?: string } };
declare function require<T = unknown>(path: string): T;

function loadExpoExtraGoogleClientId(): string | undefined {
  try {
    const constantsModule = require<{
      default?: {
        expoConfig?: { extra?: { googleClientId?: string } };
        manifest?: { extra?: { googleClientId?: string } };
      };
    }>("expo-constants");
    const constants = constantsModule.default;
    return (
      constants?.expoConfig?.extra?.googleClientId ??
      constants?.manifest?.extra?.googleClientId
    );
  } catch {
    return undefined;
  }
}

export function getGoogleClientId(): string | undefined {
  const envValue = process.env?.EXPO_PUBLIC_GOOGLE_CLIENT_ID?.trim();
  if (envValue) return envValue;
  const extraValue = loadExpoExtraGoogleClientId()?.trim();
  return extraValue || undefined;
}
