import Constants from "expo-constants";

import type {
  AuthSessionResult,
  AuthHandoffCompletionResult,
  ApiResponse,
  DashboardData,
  Device,
  DeviceListResult,
  FcmTokenRegistration,
  GuardianAcceptResult,
  GuardianDashboard,
  GuardianWard,
  GuardianList,
  GuardianInvite,
  GuardianWardList,
  LoginResult,
  NotificationItem,
  NotificationList,
  ScanResult,
  ScanStatus,
  SessionTokens,
  StartScanPayload,
  User,
} from "./types";

// 기본값을 비워둔다. 운영 도메인은 빌드 시점 EXPO_PUBLIC_API_BASE_URL 환경변수로만 주입한다.
// (코드/APK 에 운영 서버 주소가 박혀 디컴파일로 공개되는 것을 방지)
const DEFAULT_API_BASE_URL = "";
const REQUEST_TIMEOUT_MS = 8000;
// Android 실기기 스캔 저장은 라즈베리파이가 같은 내부망의 ARP·TCP·SSDP·HTTP
// 응답을 보강한 뒤 결과를 저장한다. 일반 API의 8초 제한을 그대로 적용하면
// 실제 탐지는 끝났는데 저장 요청만 시간 초과되어 사용자에게 연결 오류로 보인다.
// 일반 요청의 빠른 실패 감각은 유지하고, 스캔 저장 요청에만 별도 상한을 둔다.
const SCAN_REQUEST_TIMEOUT_MS = 120000;
const REQUIRED_V1_PATHS = new Set([
  "/api/v1/auth/google/callback",
  "/api/v1/auth/session",
  "/api/v1/auth/refresh",
  "/api/v1/auth/logout",
  "/api/v1/auth/handoff/complete",
  "/api/v1/security/scan",
  "/api/v1/security/scan/status",
]);

declare const process: {
  env?: {
    EXPO_PUBLIC_API_BASE_URL?: string;
    HG_RELEASE_BUILD?: string;
  };
};

function resolveExpoConstants(): {
  expoConfig?: { extra?: { releaseBuild?: boolean; apiBaseUrl?: string } };
  manifest?: { extra?: { releaseBuild?: boolean; apiBaseUrl?: string } };
} | null {
  const toExtra = (value: unknown) => {
    const record = typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
    const extra =
      typeof record.extra === "object" && record.extra !== null
        ? (record.extra as Record<string, unknown>)
        : {};
    return {
      releaseBuild: extra?.releaseBuild === true,
      apiBaseUrl: typeof extra?.apiBaseUrl === "string" ? extra.apiBaseUrl : undefined,
    };
  };

  if (!Constants) return null;
  return {
    expoConfig: Constants.expoConfig ? { extra: toExtra(Constants.expoConfig) } : undefined,
    manifest: Constants.manifest ? { extra: toExtra(Constants.manifest) } : undefined,
  };
}

export class HomeGuardianApiError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
  }
}

export class HomeGuardianApi {
  private authToken: string | null = null;
  private refreshHandler: (() => Promise<string | null>) | null = null;
  private refreshInFlight: Promise<string | null> | null = null;

  constructor(private baseUrl = getApiBaseUrl()) {}

  setBaseUrl(baseUrl: string) {
    this.baseUrl = normalizeApiBaseUrl(baseUrl);
  }

  getBaseUrl() {
    return this.baseUrl;
  }

  setAuthToken(authToken: string | null | undefined) {
    this.authToken = authToken?.trim() || null;
  }

  clearAuthToken() {
    this.authToken = null;
  }

  setRefreshHandler(handler: (() => Promise<string | null>) | null) {
    this.refreshHandler = handler;
  }

  private refreshAccessToken(): Promise<string | null> {
    if (!this.refreshHandler) return Promise.resolve(null);
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.refreshHandler().finally(() => {
        this.refreshInFlight = null;
      });
    }
    return this.refreshInFlight;
  }

  // Android type Google OAuth client 흐름:
  // 클라이언트가 PKCE code → id_token 교환을 마치고 id_token 만 백엔드로 전달한다.
  // 백엔드 google_oauth.authenticate 는 GOOGLE_CLIENT_ID 환경변수와 id_token.aud 를 비교해 검증한다.
  // code 는 일부 흐름 (백엔드 측 교환) 에서만 의미가 있어 optional.
  // redirectUri 는 OAuth 첫 요청에 실제로 사용한 URI 를 그대로 전달 (감사/로깅 용도, 검증에는 사용 안 함).
  googleLogin(params: {
    idToken?: string;
    code?: string;
    redirectUri?: string;
    role?: "user" | "guardian";
    previousRefreshToken?: string;
  }) {
    const body: Record<string, unknown> = {};
    if (params.code) {
      body.code = params.code;
    }
    if (params.idToken) {
      body.id_token = params.idToken;
    }
    if (params.redirectUri) {
      body.redirect_uri = params.redirectUri;
    }
    if (params.role) {
      body.role = params.role;
    }
    // The server hashes this value and creates only a short-lived pending
    // successor. The current session remains usable until the app durably
    // stores the handoff and explicitly completes it with both refresh tokens.
    if (params.previousRefreshToken) {
      body.previous_refresh_token = params.previousRefreshToken;
    }
    return this.request<LoginResult>("/api/v1/auth/google/callback", {
      method: "POST",
      body,
    });
  }

  getAuthSession() {
    return this.request<AuthSessionResult>("/api/v1/auth/session");
  }

  refreshAuthSession(refreshToken: string, refreshAttemptId?: string) {
    const body: { refresh_token: string; refresh_attempt_id?: string } = { refresh_token: refreshToken };
    if (refreshAttemptId) {
      body.refresh_attempt_id = refreshAttemptId;
    }
    return this.request<SessionTokens & { user: User }>("/api/v1/auth/refresh", {
      method: "POST",
      body,
      skipAuthRefresh: true,
    });
  }

  completeAuthHandoff(params: {
    previousRefreshToken: string;
    successorRefreshToken: string;
    handoffId: string;
  }) {
    return this.request<AuthHandoffCompletionResult>("/api/v1/auth/handoff/complete", {
      method: "POST",
      body: {
        previous_refresh_token: params.previousRefreshToken,
        successor_refresh_token: params.successorRefreshToken,
        handoff_id: params.handoffId,
      },
      // The endpoint authenticates by possession of both refresh secrets, not
      // by the soon-to-be-revoked access token attached to normal API calls.
      skipAuthRefresh: true,
    });
  }

  logoutAuthSession(refreshToken: string) {
    return this.request<{ revoked: boolean }>("/api/v1/auth/logout", {
      method: "POST",
      body: { refresh_token: refreshToken },
      skipAuthRefresh: true,
    });
  }

  getDashboard() {
    return this.request<DashboardData>("/api/v1/dashboard");
  }

  getDevices() {
    return this.request<DeviceListResult>("/api/v1/devices");
  }

  getDevice(deviceId: string) {
    return this.request<Device>(`/api/v1/devices/${deviceId}`);
  }

  startScan(payload: StartScanPayload) {
    return this.request<ScanStatus>("/api/v1/security/scan", {
      method: "POST",
      timeoutMs: SCAN_REQUEST_TIMEOUT_MS,
      body: {
        scan_profile: payload.scan_profile ?? "quick",
        scan_source: payload.scan_source,
        network_context: payload.network_context,
        devices: payload.devices,
      },
    });
  }

  getScanResult(scanId: string) {
    return this.request<ScanResult>(`/api/v1/security/scans/${scanId}`);
  }

  inviteGuardian(email: string, relation = "보호자", wardName?: string | null) {
    return this.request<GuardianInvite>("/api/v1/guardians/invite", {
      method: "POST",
      body: { email, relation, ward_name: wardName },
    });
  }

  getGuardians() {
    return this.request<GuardianList>("/api/v1/guardians");
  }

  acceptGuardianInvite(invite: string) {
    return this.request<GuardianAcceptResult>("/api/v1/guardian-mode/links/accept", {
      method: "POST",
      // Guardian identity is derived server-side from the active Bearer session.
      body: { invite },
    });
  }

  getGuardianWards(guardianId: string) {
    return this.request<GuardianWardList>(`/api/v1/guardian-mode/wards?guardian_id=${encodeURIComponent(guardianId)}`);
  }

  getGuardianWardDashboard(guardianId: string, linkId: string) {
    return this.request<GuardianDashboard>(
      `/api/v1/guardian-mode/wards/${encodeURIComponent(linkId)}/dashboard?guardian_id=${encodeURIComponent(guardianId)}`,
    );
  }

  removeGuardianWard(guardianId: string, linkId: string) {
    return this.request<GuardianWard>(
      `/api/v1/guardian-mode/wards/${encodeURIComponent(linkId)}?guardian_id=${encodeURIComponent(guardianId)}`,
      {
        method: "DELETE",
      },
    );
  }

  updateGuardianWardAlias(guardianId: string, linkId: string, wardAlias: string | null) {
    return this.request<GuardianWard>(`/api/v1/guardian-mode/wards/${encodeURIComponent(linkId)}`, {
      method: "PATCH",
      body: {
        guardian_id: guardianId,
        ward_alias: wardAlias,
      },
    });
  }

  updateDeviceAlias(deviceId: string, alias: string | null) {
    return this.request<Device>(`/api/v1/devices/${encodeURIComponent(deviceId)}`, {
      method: "PATCH",
      body: { alias },
    });
  }

  revokeGuardianInvite(inviteId: string) {
    return this.request<GuardianInvite>(`/api/v1/guardians/${encodeURIComponent(inviteId)}/revoke`, {
      method: "PATCH",
    });
  }

  // 취소(revoke=상태 표시)와 달리 초대를 목록에서 실제로 삭제한다.
  deleteGuardianInvite(inviteId: string) {
    return this.request<GuardianInvite>(`/api/v1/guardians/${encodeURIComponent(inviteId)}`, {
      method: "DELETE",
    });
  }

  getNotifications() {
    return this.request<NotificationList>("/api/v1/notifications");
  }

  markNotificationRead(notificationId: string) {
    return this.request<NotificationItem>(`/api/v1/notifications/${notificationId}/read`, {
      method: "PATCH",
    });
  }

  registerFcmToken(fcmToken: string, platform: "android" | "ios") {
    return this.request<FcmTokenRegistration>("/api/v1/auth/fcm-token", {
      method: "POST",
      body: { fcm_token: fcmToken, platform },
    });
  }

  deleteFcmToken(fcmToken: string) {
    return this.request<void>("/api/v1/auth/fcm-token", {
      method: "DELETE",
      body: { fcm_token: fcmToken },
    });
  }

  private async request<T>(
    path: string,
    options: {
      method?: "GET" | "POST" | "PATCH" | "DELETE";
      body?: Record<string, unknown>;
      headers?: Record<string, string>;
      skipAuthRefresh?: boolean;
      timeoutMs?: number;
    } = {},
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutMs = Number.isFinite(options.timeoutMs) && (options.timeoutMs ?? 0) > 0
      ? Math.min(Math.trunc(options.timeoutMs as number), SCAN_REQUEST_TIMEOUT_MS)
      : REQUEST_TIMEOUT_MS;
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const requestUrl = `${this.baseUrl}${path}`;

    let response: Response;
    try {
      response = await fetch(requestUrl, {
        method: options.method ?? "GET",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          ...(this.authToken ? { Authorization: `Bearer ${this.authToken}` } : {}),
          ...(options.headers ?? {}),
        },
        body: options.body ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });
    } catch (error) {
      throw new HomeGuardianApiError(connectionErrorMessage(this.baseUrl, error), "NETWORK_UNREACHABLE");
    } finally {
      clearTimeout(timeoutId);
    }

    if (response.status === 401 && !options.skipAuthRefresh && this.refreshHandler) {
      const refreshedAccessToken = await this.refreshAccessToken();
      if (refreshedAccessToken) {
        this.authToken = refreshedAccessToken;
        return this.request<T>(path, { ...options, skipAuthRefresh: true });
      }
    }

    // 구버전 FastAPI는 존재하지 않는 경로에 JSON이 아닌 빈 404를 반환할 수 있다.
    // JSON 파싱을 먼저 시도하면 서버 버전 불일치가 일반 연결 오류로 오인되므로 계약 판별을 우선한다.
    if (response.status === 404 && REQUIRED_V1_PATHS.has(path)) {
      throw new HomeGuardianApiError(
        "서비스 연결이 아직 준비되지 않았어요. 관리자에게 앱과 서버를 함께 업데이트해 달라고 알려 주세요.",
        "SERVER_VERSION_MISMATCH",
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }

    let payload: ApiResponse<T>;
    try {
      payload = (await response.json()) as ApiResponse<T>;
    } catch {
      // HTTP 상태나 요청 주소는 일반 사용자 화면에 그대로 전달하지 않는다.
      // 상세 진단은 운영 로그에서 확인하고, 앱에는 다음 행동만 안내한다.
      throw new HomeGuardianApiError("연결 결과를 확인하지 못했어요. 잠시 후 다시 시도해 주세요.", "INVALID_RESPONSE");
    }

    if (!response.ok || !payload.success) {
      // 실기기 스캔 저장 실패를 서버·인증·입력 검증으로 구분할 수 있도록
      // 민감한 요청 값 없이 경로·HTTP 상태·공개 오류 코드만 남긴다.
      // 사용자 화면에는 이 내부 진단을 표시하지 않는다.
      if (path === "/api/v1/security/scan") {
        console.warn("HomeGuardian scan request failed", response.status, payload.error?.code ?? "UNKNOWN");
      }
      throw new HomeGuardianApiError(
        payload.error?.message ?? "요청 처리 중 문제가 생겼습니다.",
        payload.error?.code ?? "UNKNOWN",
      );
    }

    return payload.data;
  }
}

export function getApiBaseUrl() {
  return normalizeApiBaseUrl(process.env?.EXPO_PUBLIC_API_BASE_URL ?? getExpoExtraApiBaseUrl() ?? DEFAULT_API_BASE_URL);
}

export const homeGuardianApi = new HomeGuardianApi();

export function normalizeApiBaseUrl(baseUrl: string, releaseBuild = isReleaseBuild()) {
  const trimmed = baseUrl.trim();
  if (!trimmed) {
    return DEFAULT_API_BASE_URL;
  }
  // A production build must never recover a developer's old HTTP endpoint
  // from AsyncStorage. Authentication and refresh traffic needs TLS.
  if (releaseBuild && !/^https:\/\//i.test(trimmed)) {
    return DEFAULT_API_BASE_URL;
  }
  return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
}

function isReleaseBuild() {
  if (process.env?.HG_RELEASE_BUILD === "1") return true;
  const constants = resolveExpoConstants();
  return constants?.expoConfig?.extra?.releaseBuild === true || constants?.manifest?.extra?.releaseBuild === true;
}

function getExpoExtraApiBaseUrl() {
  const constants = resolveExpoConstants();
  return constants?.expoConfig?.extra?.apiBaseUrl ?? constants?.manifest?.extra?.apiBaseUrl;
}

function connectionErrorMessage(baseUrl: string, error: unknown) {
  if (!baseUrl) {
    // 빌드 연결 설정이 빠진 경우에도 사용자에게 내부 설정 이름을 노출하지 않는다.
    return "앱 연결을 준비하지 못했어요. 앱을 최신 버전으로 다시 설치한 뒤 다시 시도해 주세요.";
  }
  const isTimeout = error instanceof Error && error.name === "AbortError";
  const reason = isTimeout ? "연결 시간이 오래 걸리고 있어요." : "지금 연결할 수 없어요.";
  return `${reason} 와이파이를 확인한 뒤 잠시 후 다시 시도해 주세요.`;
}
