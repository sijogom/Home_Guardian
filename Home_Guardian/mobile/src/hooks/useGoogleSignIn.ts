// Google 로그인 React hook.
// Google Cloud Console 에서 "Android" 타입으로 발급한 client_id 를 그대로 쓰기 위해
// expo-auth-session/providers/Google 헬퍼 (useIdTokenAuthRequest) 를 사용한다.
// 이 헬퍼가 platform (Android/iOS/Web) 을 감지해 알맞은 client_id 와 redirect_uri 형식
// (Android 의 경우 reverse-DNS scheme `com.googleusercontent.apps.<id>:/...`) 을 자동 처리한다.
// 우리는 백엔드 /api/v1/auth/google/callback 에 id_token 만 전달하면 되므로
// code grant 가 아닌 id_token 흐름 (useIdTokenAuthRequest) 을 선택했다.

import { useCallback, useMemo } from "react";
import * as Google from "expo-auth-session/providers/google";
import { AccessTokenRequest, type AuthSessionResult } from "expo-auth-session";

import { HomeGuardianApiError, homeGuardianApi } from "../api/homeGuardianApi";
import { getGoogleClientId } from "../services/googleAuth";
import type { LoginResult, User } from "../api/types";

export type GoogleSignInResult = {
  ok: boolean;
  error?: string;
  user?: User;
  accessToken?: string;
  session?: LoginResult;
};

export type GoogleSignInController = {
  promptSignIn: (role?: "user" | "guardian", previousRefreshToken?: string) => Promise<GoogleSignInResult>;
  isReady: boolean;
};

export function useGoogleSignIn(): GoogleSignInController {
  const clientId = getGoogleClientId();

  // Android 단일 플랫폼. iosClientId / webClientId 는 추후 필요해지면 추가.
  // clientId 가 비어도 hook 자체는 항상 같은 순서로 호출되어야 한다 (조건부 hook 금지).
  const [request, , promptAsync] = Google.useIdTokenAuthRequest({
    androidClientId: clientId ?? undefined,
    scopes: ["openid", "profile", "email"],
    // Android returns a one-time PKCE authorization code. This hook performs
    // the exchange below so the backend callback can be awaited in one flow.
    // Disable the provider hook's own effect-based exchange; otherwise both
    // paths race to consume the same code and the losing promise can become an
    // unhandled rejection after a successful login.
    shouldAutoExchangeCode: false,
  });

  const promptSignIn = useCallback(async (
    role: "user" | "guardian" = "user",
    previousRefreshToken?: string,
  ): Promise<GoogleSignInResult> => {
    if (!clientId) {
      return {
        ok: false,
        error: "로그인을 준비하지 못했어요. 잠시 후 다시 시도해 주세요.",
      };
    }
    if (!request) {
      return {
        ok: false,
        error: "Google 로그인 준비가 아직 끝나지 않았습니다. 잠시 후 다시 시도해 주세요.",
      };
    }

    let result: AuthSessionResult;
    try {
      result = await promptAsync();
    } catch {
      return {
        ok: false,
        error: "Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
      };
    }

    if (result.type !== "success") {
      return { ok: false, error: "Google 로그인이 취소되었거나 실패했습니다." };
    }

    // Android type Google OAuth client 는 Code grant flow 로 동작한다.
    // 자동 교환은 위에서 명시적으로 끈다. await promptAsync()가 반환한 raw redirect
    // 결과의 PKCE code는 이 단일 경로에서만 id_token으로 교환한다.
    const params = result.params ?? {};
    const redirectUri = request.redirectUri;
    const directIdToken = params.id_token ?? result.authentication?.idToken;
    if (directIdToken) {
      return await completeWithIdToken(directIdToken, redirectUri, role, previousRefreshToken);
    }

    const code = params.code;
    if (!code) {
      return { ok: false, error: "로그인 정보를 확인하지 못했어요. 다시 로그인해 주세요." };
    }
    if (!request.codeVerifier) {
      return { ok: false, error: "로그인 정보를 확인하지 못했어요. 잠시 후 다시 시도해 주세요." };
    }
    if (!redirectUri) {
      return { ok: false, error: "로그인 정보를 확인하지 못했어요. 잠시 후 다시 시도해 주세요." };
    }

    try {
      const exchange = new AccessTokenRequest({
        clientId,
        redirectUri,
        scopes: ["openid", "profile", "email"],
        code,
        extraParams: { code_verifier: request.codeVerifier },
      });
      const tokenResponse = await exchange.performAsync(Google.discovery);
      const exchangedIdToken = tokenResponse.idToken;
      if (!exchangedIdToken) {
        return { ok: false, error: "로그인 정보를 확인하지 못했어요. 다시 로그인해 주세요." };
      }
      return await completeWithIdToken(exchangedIdToken, redirectUri, role, previousRefreshToken);
    } catch {
      return {
        ok: false,
        error: "Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
      };
    }
  }, [clientId, request, promptAsync]);

  const isReady = useMemo(() => Boolean(clientId && request), [clientId, request]);

  return { promptSignIn, isReady };
}

async function completeWithIdToken(
  idToken: string,
  redirectUri: string | undefined,
  role: "user" | "guardian",
  previousRefreshToken?: string,
): Promise<GoogleSignInResult> {
  try {
    const apiResult = await homeGuardianApi.googleLogin({ idToken, redirectUri, role, previousRefreshToken });
    return { ok: true, user: apiResult.user, accessToken: apiResult.access_token, session: apiResult };
  } catch (error) {
    if (error instanceof HomeGuardianApiError && error.code === "SERVER_VERSION_MISMATCH") {
      return { ok: false, error: error.message };
    }
    return {
      ok: false,
      error: "로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
    };
  }
}
