import { useCallback, useEffect, useRef, useState } from "react";

import { HomeGuardianApiError, getApiBaseUrl, homeGuardianApi } from "../api/homeGuardianApi";
import { scanHomeNetwork } from "../native/homeGuardianNetworkScanner";
import { registerAutoScan, unregisterAutoScan } from "../services/backgroundScan";
import {
  addDevicePushTokenListener,
  getDevicePushToken,
  notifyScanCompleted,
  requestNotificationsPermission,
} from "../services/notifications";
import { useGoogleSignIn } from "../hooks/useGoogleSignIn";
import {
  STORAGE_SCHEMA_VERSION,
  SecureStorageKeys,
  StorageKeys,
  discardRetiredGuardianSessionToken,
  secureStorageGet,
  secureStorageRemove,
  secureStorageRemoveRequired,
  secureStorageSetRequired,
  storageClear,
  storageGet,
  storageRemove,
  storageSet,
} from "./storage";
import { parseGuardianInviteInput } from "../utils/guardianInvite";
import { guardianWardTitle } from "../utils/guardianWardDisplay";
import {
  deviceCacheAfterScan,
  hasConfirmedRedRisk,
  identityResearchState,
  scanIncompleteMessage,
  scanCoverageState,
  SCAN_INCOMPLETE_TITLE,
} from "../utils/scanCoverage";
import {
  presentDashboard,
  presentDevice,
  presentDeviceCollection,
  presentDevices,
  presentGuardianDashboard,
  presentNotifications,
  presentScanResult,
  residentVisibleDevices,
} from "../utils/devicePresentation";
import type {
  AuthSessionResult,
  AuthHandoff,
  DashboardData,
  Device,
  GuardianDashboard,
  GuardianInvite,
  GuardianWard,
  NetworkContext,
  NotificationItem,
  ScanResult,
  SessionTokens,
  User,
} from "../api/types";

export type Screen =
  | "login"
  | "userLogin"
  | "scanResult"
  | "scanConsent"
  | "scanProgress"
  | "devices"
  | "detail"
  | "guardian"
  | "alerts"
  | "profile"
  | "guardianMode"
  // 이전 화면 ID. 사용자 코드가 참조하면 controller 가 login/scanResult 로 매핑.
  | "start"
  | "settings"
  | "dashboard";
export type StatusTone = "info" | "success" | "warning" | "danger";

export type ScanStepKey = "wifi" | "discovery" | "services" | "analysis" | "guardian";
export type ScanStepState = "pending" | "running" | "completed" | "failed";

export type ScanStep = {
  key: ScanStepKey;
  title: string;
  detail: string;
  state: ScanStepState;
};

export type ScanUiState = {
  progress: number;
  steps: ScanStep[];
  errorCode: string | null;
  errorMessage: string | null;
  nativeMessage: string | null;
  networkContext: NetworkContext | null;
  sourceLabel: string;
  coverageComplete: boolean | null;
  tcpScanTimedOut: boolean;
  identityResearchPending: boolean;
  confirmedRedRisk: boolean;
};

type StoredAuthSession = {
  accessToken: string;
  refreshToken: string;
  role: "user" | "guardian";
  userId: string;
  expiresAt: number;
  // Persisted before refresh so a relaunch retries the exact same server-side
  // idempotent rotation when its first response was lost.
  refreshAttemptId?: string;
};

type StoredAuthHandoff = {
  previousSession: StoredAuthSession;
  successorSession: StoredAuthSession;
  handoffId: string;
  expiresAt: string;
};

type PendingLogout = {
  refreshToken: string;
  createdAt: number;
};

export type HomeGuardianState = {
  screen: Screen;
  history: Screen[];
  user: User | null;
  authToken: string | null;
  authSession: StoredAuthSession | null;
  dashboard: DashboardData | null;
  devices: Device[];
  selectedDevice: Device | null;
  scanResult: ScanResult | null;
  guardians: GuardianInvite[];
  notifications: NotificationItem[];
  guardianEmail: string;
  apiBaseUrl: string;
  statusMessage: string;
  statusTone: StatusTone;
  isLoading: boolean;
  isHydrated: boolean;
  scanUi: ScanUiState;
  lastScanAt: string | null;
  notificationsEnabled: boolean;
  autoScanEnabled: boolean;
  autoScanIntervalHours: number;
  // 보호자 모드 (수행계획서 명시: 보호자 전용 원격 모니터링)
  guardianDashboard: GuardianDashboard | null;
  guardianModeInviteCode: string;
  guardianUser: User | null;
  guardianWards: GuardianWard[];
  selectedGuardianWardId: string | null;
};

export type HomeGuardianActions = {
  setScreen: (screen: Screen) => void;
  navigate: (screen: Screen) => void;
  goBack: () => boolean;
  setGuardianEmail: (guardianEmail: string) => void;
  setApiBaseUrl: (apiBaseUrl: string) => void;
  loginWithGoogle: () => void;
  logout: () => Promise<void>;
  startScan: () => void;
  beginNetworkScan: () => void;
  retryScan: () => void;
  shareScanWithGuardian: () => void;
  openDevice: (device: Device) => void;
  renameDevice: (deviceId: string, alias: string | null) => Promise<void>;
  inviteGuardian: () => void;
  revokeGuardianInvite: (inviteId: string) => Promise<void>;
  deleteGuardianInvite: (inviteId: string) => Promise<void>;
  markNotificationRead: (notificationId: string) => void;
  setNotificationsEnabled: (enabled: boolean) => Promise<void>;
  setAutoScanEnabled: (enabled: boolean) => Promise<void>;
  setAutoScanIntervalHours: (hours: number) => void;
  // 보호자 모드 액션
  enterGuardianMode: () => void;
  exitGuardianMode: () => void;
  loginAsGuardianWithGoogle: () => void;
  loadGuardianWards: () => Promise<void>;
  acceptGuardianInvite: (inviteInput: string) => Promise<void>;
  openGuardianWard: (linkId: string) => Promise<void>;
  updateGuardianWardAlias: (linkId: string, wardAlias: string) => Promise<void>;
  removeGuardianWard: (linkId: string) => Promise<void>;
  openGuardianInviteLink: (inviteInput: string) => void;
  clearGuardianDashboard: () => void;
};

const TAB_SCREENS: Screen[] = ["scanResult", "devices", "guardian", "alerts", "profile"];
const LOGIN_SCREEN: Screen = "login";

// These values belong to the authenticated person or guardian role, not to the
// phone. They must never be restored for a different person after a terminal
// session failure. Theme and endpoint preferences deliberately stay outside
// this list because they contain no household or account data.
const ACCOUNT_SCOPED_STORAGE_KEYS = [
  StorageKeys.user,
  StorageKeys.scanResult,
  StorageKeys.devices,
  StorageKeys.notifications,
  StorageKeys.guardians,
  StorageKeys.guardianEmail,
  StorageKeys.lastScanAt,
  StorageKeys.notificationsEnabled,
  StorageKeys.autoScanEnabled,
  StorageKeys.autoScanIntervalHours,
  StorageKeys.guardianUser,
  StorageKeys.guardianWards,
  StorageKeys.selectedGuardianWardId,
] as const;

// v1.0.0 제품 식별 계약 이전에 저장된 결과에는 서버 provenance 없이도
// 그럴듯한 제품명·제조사·모델이 들어갈 수 있다. 계정·로그인·환경설정은
// 유지하되, 화면에 제품 또는 안전 결과로 나타날 수 있는 캐시는 새 스키마
// 최초 실행에서 반드시 폐기한다.
const LEGACY_PRODUCT_DERIVED_STORAGE_KEYS = [
  StorageKeys.scanResult,
  StorageKeys.devices,
  StorageKeys.notifications,
  StorageKeys.lastScanAt,
] as const;

async function clearAccountScopedCache(): Promise<void> {
  await Promise.all(ACCOUNT_SCOPED_STORAGE_KEYS.map((key) => storageRemove(key)));
}

async function migrateLegacyProductDerivedCache(): Promise<void> {
  const guardianWards = await storageGet<GuardianWard[]>(StorageKeys.guardianWards);
  await Promise.all(LEGACY_PRODUCT_DERIVED_STORAGE_KEYS.map((key) => storageRemove(key)));

  if (!Array.isArray(guardianWards) || guardianWards.length === 0) {
    await storageRemove(StorageKeys.guardianWards);
    return;
  }

  // 보호자-피보호자 연결 자체는 계정 정보이므로 보존한다. 다만 ward summary는
  // 이전 제품/위험 집계에서 파생된 값이어서 서버에서 새로 받을 때까지 제거한다.
  const accountOnlyWards = guardianWards.map(({ summary: _legacyProductSummary, ...accountWard }) => accountWard);
  await storageSet(StorageKeys.guardianWards, accountOnlyWards);
}

function normalizeGuardianInvites(value: unknown): GuardianInvite[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is GuardianInvite => {
    if (!item || typeof item !== "object") return false;
    const invite = item as Partial<GuardianInvite>;
    return (
      typeof invite.invite_id === "string" &&
      invite.invite_id.length > 0 &&
      typeof invite.email === "string" &&
      typeof invite.relation === "string" &&
      typeof invite.status === "string" &&
      typeof invite.message === "string"
    );
  });
}

function normalizeScreen(screen: Screen): Screen {
  if (screen === "start") return "login";
  if (screen === "dashboard") return "scanResult";
  if (screen === "settings") return "profile";
  return screen;
}

export function useHomeGuardianController() {
  // Google OAuth 는 useAuthRequest / useAutoDiscovery hook 에 의존한다.
  // 이 controller 자체가 hook 이므로 그 안에서 useGoogleSignIn 을 호출하면 hook 규칙을 지킨다.
  const googleSignIn = useGoogleSignIn();

  const [state, setState] = useState<HomeGuardianState>({
    screen: LOGIN_SCREEN,
    history: [],
    user: null,
    authToken: null,
    authSession: null,
    dashboard: null,
    devices: [],
    selectedDevice: null,
    scanResult: null,
    guardians: [],
    notifications: [],
    guardianEmail: "",
    apiBaseUrl: getApiBaseUrl(),
    statusMessage: "",
    statusTone: "info",
    isLoading: false,
    isHydrated: false,
    scanUi: initialScanUi(),
    lastScanAt: null,
    notificationsEnabled: false,
    autoScanEnabled: false,
    autoScanIntervalHours: 24,
    guardianDashboard: null,
    guardianModeInviteCode: "",
    guardianUser: null,
    guardianWards: [],
    selectedGuardianWardId: null,
  });

  const stateRef = useRef(state);
  useEffect(() => {
    stateRef.current = state;
  }, [state]);

  const patchState = useCallback((patch: Partial<HomeGuardianState>) => {
    setState((current) => ({ ...current, ...patch }));
  }, []);

  const clearTerminalAuthSession = useCallback(
    async (message: string) => {
      homeGuardianApi.clearAuthToken();
      await Promise.all([
        secureStorageRemove(SecureStorageKeys.authSession),
        secureStorageRemove(SecureStorageKeys.authToken),
        clearAccountScopedCache(),
        unregisterAutoScan().catch(() => undefined),
      ]);
      patchState({
        user: null,
        guardianUser: null,
        authToken: null,
        authSession: null,
        dashboard: null,
        devices: [],
        selectedDevice: null,
        scanResult: null,
        guardians: [],
        notifications: [],
        guardianEmail: "",
        lastScanAt: null,
        notificationsEnabled: false,
        autoScanEnabled: false,
        autoScanIntervalHours: 24,
        guardianDashboard: null,
        guardianModeInviteCode: "",
        guardianWards: [],
        selectedGuardianWardId: null,
        screen: LOGIN_SCREEN,
        history: [],
        statusMessage: message,
        statusTone: "warning",
      });
    },
    [patchState],
  );

  const refreshSavedSession = useCallback(async (): Promise<string | null> => {
    const activeSession = stateRef.current.authSession;
    if (!activeSession) return null;
    try {
      const pendingSession = await persistRefreshAttempt(activeSession);
      if (pendingSession !== activeSession) {
        stateRef.current = { ...stateRef.current, authSession: pendingSession };
        patchState({ authSession: pendingSession });
      }
      const refreshed = await homeGuardianApi.refreshAuthSession(
        pendingSession.refreshToken,
        pendingSession.refreshAttemptId,
      );
      const nextSession = toStoredAuthSession(refreshed.user, refreshed);
      homeGuardianApi.setAuthToken(nextSession.accessToken);
      await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(nextSession));
      await secureStorageRemove(SecureStorageKeys.authToken);
      patchState({ authToken: nextSession.accessToken, authSession: nextSession });
      return nextSession.accessToken;
    } catch (error) {
      if (isTerminalAuthError(error)) {
        await clearTerminalAuthSession("로그인 시간이 끝났어요. 다시 로그인해 주세요.");
        return null;
      }
      throw error;
    }
  }, [clearTerminalAuthSession, patchState]);

  useEffect(() => {
    homeGuardianApi.setRefreshHandler(refreshSavedSession);
    return () => homeGuardianApi.setRefreshHandler(null);
  }, [refreshSavedSession]);

  const registerDevicePushToken = useCallback(async (token: string): Promise<boolean> => {
    const normalizedToken = token.trim();
    if (!normalizedToken) return false;
    const previousToken = await secureStorageGet(SecureStorageKeys.registeredFcmToken);
    await homeGuardianApi.registerFcmToken(normalizedToken, "android");
    await secureStorageSetRequired(SecureStorageKeys.registeredFcmToken, normalizedToken);
    if (previousToken && previousToken !== normalizedToken) {
      await homeGuardianApi.deleteFcmToken(previousToken).catch((error) => {
        if (!(error instanceof HomeGuardianApiError && error.code === "AUTH_083")) throw error;
      });
    }
    return true;
  }, []);

  const registerCurrentDevicePushToken = useCallback(async (): Promise<boolean> => {
    const token = await getDevicePushToken();
    if (!token) return false;
    return registerDevicePushToken(token);
  }, [registerDevicePushToken]);

  const deleteRegisteredDevicePushToken = useCallback(async (): Promise<void> => {
    const token = await secureStorageGet(SecureStorageKeys.registeredFcmToken);
    if (!token) return;
    try {
      await homeGuardianApi.deleteFcmToken(token);
    } catch (error) {
      if (!(error instanceof HomeGuardianApiError && error.code === "AUTH_083")) throw error;
    }
    await secureStorageRemoveRequired(SecureStorageKeys.registeredFcmToken);
  }, []);

  const refreshRestoredUserData = useCallback(async (): Promise<boolean> => {
    const [dashboardResult, devicesResult, notificationsResult, guardiansResult] = await Promise.allSettled([
      homeGuardianApi.getDashboard(),
      homeGuardianApi.getDevices(),
      homeGuardianApi.getNotifications(),
      homeGuardianApi.getGuardians(),
    ]);

    patchState({
      dashboard:
        dashboardResult.status === "fulfilled"
          ? presentDashboard(dashboardResult.value)
          : stateRef.current.dashboard,
      devices:
        devicesResult.status === "fulfilled"
          ? presentDeviceCollection(
              devicesResult.value?.items,
              devicesResult.value?.detected_connections,
            )
          : stateRef.current.devices,
      notifications:
        notificationsResult.status === "fulfilled"
          ? presentNotifications(notificationsResult.value?.items)
          : stateRef.current.notifications,
      guardians:
        guardiansResult.status === "fulfilled"
          ? normalizeGuardianInvites(guardiansResult.value?.items)
          : stateRef.current.guardians,
    });

    return [dashboardResult, devicesResult, notificationsResult, guardiansResult].some(
      (result) => result.status === "rejected",
    );
  }, []);

  // 영구 저장 복원. 한 번만 실행.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (hydratedRef.current) return;
    hydratedRef.current = true;
    (async () => {
      // 스키마 마이그레이션 — 저장된 schemaVersion 이 코드 상수와 다르면
      // 이전 빌드의 제품·점검 파생 캐시를 청소한 뒤 시작한다. 계정과 설정은 보존한다.
      const storedSchemaVersion = await storageGet<number>(StorageKeys.schemaVersion);
      if (storedSchemaVersion !== STORAGE_SCHEMA_VERSION) {
        await migrateLegacyProductDerivedCache();
        await storageSet(StorageKeys.schemaVersion, STORAGE_SCHEMA_VERSION);
      }
      await discardRetiredGuardianSessionToken();
      const [
        user,
        scanResult,
        devices,
        notifications,
        guardians,
        apiBaseUrl,
        guardianEmail,
        lastScanAt,
        notificationsEnabled,
        autoScanEnabled,
        autoScanIntervalHours,
        guardianUser,
        guardianWards,
        selectedGuardianWardId,
        authSessionRaw,
        legacyAuthToken,
        pendingAuthHandoffRaw,
        pendingLogoutRaw,
      ] =
        await Promise.all([
          storageGet<User>(StorageKeys.user),
          storageGet<ScanResult>(StorageKeys.scanResult),
          storageGet<Device[]>(StorageKeys.devices),
          storageGet<NotificationItem[]>(StorageKeys.notifications),
          storageGet<GuardianInvite[]>(StorageKeys.guardians),
          storageGet<string>(StorageKeys.apiBaseUrl),
          storageGet<string>(StorageKeys.guardianEmail),
          storageGet<string>(StorageKeys.lastScanAt),
          storageGet<boolean>(StorageKeys.notificationsEnabled),
          storageGet<boolean>(StorageKeys.autoScanEnabled),
          storageGet<number>(StorageKeys.autoScanIntervalHours),
          storageGet<User>(StorageKeys.guardianUser),
          storageGet<GuardianWard[]>(StorageKeys.guardianWards),
          storageGet<string>(StorageKeys.selectedGuardianWardId),
          secureStorageGet(SecureStorageKeys.authSession),
          secureStorageGet(SecureStorageKeys.authToken),
          secureStorageGet(SecureStorageKeys.pendingAuthHandoff),
          secureStorageGet(SecureStorageKeys.pendingLogout),
        ]);

      const restoredApi = apiBaseUrl ?? getApiBaseUrl();
      homeGuardianApi.setBaseUrl(restoredApi);
      let restoredSession = parseStoredAuthSession(authSessionRaw);
      let restoredAccessToken = restoredSession?.accessToken ?? legacyAuthToken ?? null;
      let verifiedSession: AuthSessionResult | null = null;
      let restoreMessage = "";
      let discardAccountCache = false;
      homeGuardianApi.setAuthToken(restoredAccessToken);
      // A durable logout marker is stronger than a stale saved session. It can
      // survive a response loss or SecureStore deletion failure, so do not
      // refresh or restore either role while one exists.
      const logoutIntentPending = Boolean(pendingLogoutRaw);
      let logoutRetrySettled = false;
      if (logoutIntentPending) {
        restoredSession = null;
        restoredAccessToken = null;
        homeGuardianApi.clearAuthToken();
      }
      const pendingLogout = parsePendingLogout(pendingLogoutRaw);
      if (pendingLogout) {
        try {
          // A logout response may have been lost after the server revoke. The
          // endpoint is idempotent, so launch can safely retry its cleanup.
          await homeGuardianApi.logoutAuthSession(pendingLogout.refreshToken);
          logoutRetrySettled = true;
        } catch (error) {
          if (isTerminalAuthError(error)) {
            // The server already treats the refresh session as unusable. Local
            // cleanup below can safely finish the logout intent.
            logoutRetrySettled = true;
          } else {
            restoreMessage = "로그아웃은 완료했지만 서버 정리를 다시 시도하고 있어요.";
          }
        }
      } else if (pendingLogoutRaw) {
        // A corrupt marker is handled conservatively: do not resurrect the
        // prior household, then remove it only after local session cleanup.
        logoutRetrySettled = true;
      }

      if (logoutIntentPending) {
        try {
          // The marker must outlive session deletion. If SecureStore cannot
          // confirm deletion, retaining it makes the next launch fail closed.
          await secureStorageRemoveRequired(SecureStorageKeys.authSession);
          await secureStorageRemoveRequired(SecureStorageKeys.authToken);
          await secureStorageRemoveRequired(SecureStorageKeys.pendingAuthHandoff);
          if (logoutRetrySettled) {
            await secureStorageRemoveRequired(SecureStorageKeys.pendingLogout);
          }
        } catch {
          restoreMessage = restoreMessage || "로그아웃 정보를 안전하게 정리하지 못했어요. 다시 열어 확인해 주세요.";
        }
        await unregisterAutoScan().catch(() => undefined);
        discardAccountCache = true;
      }

      const pendingHandoff = logoutIntentPending ? null : parseStoredAuthHandoff(pendingAuthHandoffRaw);
      let handoffCompletionPending = false;
      if (pendingHandoff) {
        try {
          // Do not refresh the predecessor before this call. Refresh rotation
          // would replace the exact predecessor proof bound to the staged
          // successor and make a safe retry impossible.
          const completedSession = await completeStoredAuthHandoff(pendingHandoff);
          await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(completedSession));
          await secureStorageRemoveRequired(SecureStorageKeys.pendingAuthHandoff);
          restoredSession = completedSession;
          restoredAccessToken = completedSession.accessToken;
          homeGuardianApi.setAuthToken(restoredAccessToken);
          restoreMessage = "로그인 전환을 안전하게 마쳤어요.";
        } catch (error) {
          if (isTerminalHandoffError(error)) {
            // Expired/forged candidate never changes the still-active prior
            // session. Drop only the unusable candidate and restore that role.
            await secureStorageRemove(SecureStorageKeys.pendingAuthHandoff);
          } else {
            handoffCompletionPending = true;
            restoreMessage = `${friendlyErrorMessage(error)} 로그인 전환을 마저 시도하고 있어요. 기존 로그인과 저장된 화면은 유지합니다.`;
          }
        }
      } else if (!logoutIntentPending && pendingAuthHandoffRaw) {
        await secureStorageRemove(SecureStorageKeys.pendingAuthHandoff);
      }

      if (restoredSession && !handoffCompletionPending) {
        try {
          restoredSession = await persistRefreshAttempt(restoredSession);
          const refreshed = await homeGuardianApi.refreshAuthSession(
            restoredSession.refreshToken,
            restoredSession.refreshAttemptId,
          );
          restoredSession = toStoredAuthSession(refreshed.user, refreshed);
          restoredAccessToken = restoredSession.accessToken;
          homeGuardianApi.setAuthToken(restoredAccessToken);
          await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(restoredSession));
          await secureStorageRemove(SecureStorageKeys.authToken);
          verifiedSession = await homeGuardianApi.getAuthSession();
          if (
            verifiedSession.role !== restoredSession.role ||
            verifiedSession.user.user_id !== restoredSession.userId
          ) {
            throw new HomeGuardianApiError("로그인 정보를 다시 확인해 주세요.", "AUTH_SESSION_INVALID");
          }
        } catch (error) {
          if (isTerminalAuthError(error)) {
            restoredSession = null;
            restoredAccessToken = null;
            homeGuardianApi.clearAuthToken();
            await Promise.all([
              secureStorageRemove(SecureStorageKeys.authSession),
              secureStorageRemove(SecureStorageKeys.authToken),
              clearAccountScopedCache(),
              unregisterAutoScan().catch(() => undefined),
            ]);
            discardAccountCache = true;
            restoreMessage = "로그인 시간이 끝났어요. 다시 로그인해 주세요.";
          } else {
            restoreMessage = `${friendlyErrorMessage(error)} 저장된 화면을 유지하고 있어요.`;
          }
        }
      }
      const activeUser = verifiedSession?.role === "user" ? verifiedSession.user : user ?? null;
      const activeGuardianUser = verifiedSession?.role === "guardian" ? verifiedSession.user : guardianUser ?? null;
      const restoredUser = restoredSession && restoredSession.role === "user" ? activeUser : null;
      const restoredGuardianUser = restoredSession && restoredSession.role === "guardian" ? activeGuardianUser : null;
      const cachedPrincipal = restoredSession?.role === "guardian" ? guardianUser : user;
      // Preserve an offline cache only when it explicitly belongs to the
      // verified principal. Earlier builds did not persist a cache owner for
      // every payload, so an absent or mismatched principal is treated as
      // untrusted rather than shown to the next person on this phone.
      const cacheBelongsToVerifiedSession = Boolean(
        restoredSession && cachedPrincipal?.user_id === restoredSession.userId,
      );
      // A cache without a verified role session has no proven owner. Do not
      // let it become the next person's home screen.
      if (!cacheBelongsToVerifiedSession) {
        discardAccountCache = true;
        await clearAccountScopedCache();
      }
      const sessionExpiredMessage =
        !restoredSession && (user || guardianUser) ? "저장된 로그인 정보를 다시 확인해 주세요." : "";

      setState((current) => ({
        ...current,
        user: restoredUser,
        authToken: restoredAccessToken,
        authSession: restoredSession,
        scanResult: discardAccountCache ? null : presentScanResult(scanResult),
        devices: discardAccountCache ? [] : presentDevices(devices),
        notifications: discardAccountCache ? [] : presentNotifications(notifications),
        guardians: discardAccountCache ? [] : normalizeGuardianInvites(guardians),
        apiBaseUrl: restoredApi,
        guardianEmail: discardAccountCache ? "" : guardianEmail ?? "",
        lastScanAt: discardAccountCache ? null : lastScanAt ?? null,
        notificationsEnabled: discardAccountCache ? false : notificationsEnabled ?? false,
        autoScanEnabled: discardAccountCache ? false : autoScanEnabled ?? false,
        autoScanIntervalHours: discardAccountCache ? 24 : autoScanIntervalHours ?? 24,
        guardianUser: restoredGuardianUser,
        guardianWards: discardAccountCache ? [] : guardianWards ?? [],
        selectedGuardianWardId: discardAccountCache ? null : selectedGuardianWardId ?? null,
        screen: restoredUser ? "scanResult" : restoredGuardianUser ? "guardianMode" : LOGIN_SCREEN,
        history: [],
        statusMessage: restoreMessage || sessionExpiredMessage || (!restoredUser && restoredGuardianUser ? "저장된 보호자 계정을 확인하고 있어요." : current.statusMessage),
        statusTone: restoreMessage || sessionExpiredMessage ? "warning" : !restoredUser && restoredGuardianUser ? "info" : current.statusTone,
        isHydrated: true,
      }));

      if (!restoredUser && restoredGuardianUser) {
        try {
          const wards = await homeGuardianApi.getGuardianWards(restoredGuardianUser.user_id);
          const selectedWard =
            (selectedGuardianWardId && wards.items.find((ward) => ward.link_id === selectedGuardianWardId)) ||
            wards.items[0] ||
            null;
          let dashboard: GuardianDashboard | null = null;
          if (selectedWard) {
            dashboard = await homeGuardianApi.getGuardianWardDashboard(restoredGuardianUser.user_id, selectedWard.link_id);
          }
          setState((current) => ({
            ...current,
            guardianWards: wards.items,
            selectedGuardianWardId: selectedWard?.link_id ?? null,
            guardianDashboard: presentGuardianDashboard(dashboard),
            statusMessage: selectedWard
              ? "보호자 계정으로 연결된 피보호자를 불러왔어요."
              : "보호자 계정으로 로그인되어 있어요. 피보호자를 추가해 주세요.",
            statusTone: selectedWard ? "success" : "info",
          }));
        } catch (error) {
          setState((current) => ({
            ...current,
            guardianDashboard: null,
            statusMessage: `${friendlyErrorMessage(error)} 보호자 목록은 유지했어요. 다시 시도해 주세요.`,
            statusTone: "warning",
          }));
        }
      } else if (restoredUser && verifiedSession) {
        const usedCachedFallback = await refreshRestoredUserData();
        if (usedCachedFallback) {
          patchState({
            statusMessage: "최신 집 정보를 모두 불러오지 못했어요. 저장된 화면을 유지하고 다시 시도해 주세요.",
            statusTone: "warning",
          });
        }
      }
    })();
  }, [patchState, refreshRestoredUserData]);

  useEffect(() => {
    if (!state.isHydrated || !state.user || !state.notificationsEnabled) return;

    let cancelled = false;
    (async () => {
      try {
        const registered = await registerCurrentDevicePushToken();
        if (!registered && !cancelled) {
          patchState({
            statusMessage: "휴대폰 알림은 켰지만 보호자 알림 연결은 아직 확인하지 못했습니다.",
            statusTone: "warning",
          });
        }
      } catch {
        if (!cancelled) {
          patchState({
            statusMessage: "휴대폰 알림은 켰지만 보호자 알림 연결은 아직 확인하지 못했습니다.",
            statusTone: "warning",
          });
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    state.isHydrated,
    state.user,
    state.notificationsEnabled,
    registerCurrentDevicePushToken,
    patchState,
  ]);

  useEffect(() => {
    if (!state.isHydrated || !state.user || !state.notificationsEnabled) return;
    return addDevicePushTokenListener((token) => {
      void registerDevicePushToken(token).catch(() => undefined);
    });
  }, [state.isHydrated, state.user, state.notificationsEnabled, registerDevicePushToken]);

  // user 변경 시 저장
  useEffect(() => {
    if (!state.isHydrated) return;
    if (state.user) {
      void storageSet(StorageKeys.user, state.user);
    } else {
      // 역할 전환/로그아웃 뒤에는 빈 null 기록도 남기지 않는다.
      void storageRemove(StorageKeys.user);
    }
  }, [state.user, state.isHydrated]);

  useEffect(() => {
    if (!state.isHydrated) return;
    if (state.authSession) {
      homeGuardianApi.setAuthToken(state.authSession.accessToken);
      // Auth session changes are persisted only by the explicit
      // secureStorageSetRequired calls immediately before each transition.
      // Do not silently retry them through the compatibility helper here:
      // a native SecureStore failure must fail the transition, not create a
      // memory-only login that looks durable to the person using the app.
      void secureStorageRemove(SecureStorageKeys.authToken);
    } else {
      homeGuardianApi.clearAuthToken();
      void Promise.all([
        secureStorageRemove(SecureStorageKeys.authSession),
        secureStorageRemove(SecureStorageKeys.authToken),
      ]);
    }
  }, [state.authSession, state.isHydrated]);

  // scanResult / devices / notifications / guardians 변경 시 저장
  useEffect(() => {
    if (!state.isHydrated) return;
    if (state.scanResult) {
      void storageSet(StorageKeys.scanResult, presentScanResult(state.scanResult));
    } else {
      void storageRemove(StorageKeys.scanResult);
    }
    if (state.devices.length) {
      void storageSet(StorageKeys.devices, presentDevices(state.devices));
    } else {
      void storageRemove(StorageKeys.devices);
    }
    if (state.notifications.length) {
      void storageSet(StorageKeys.notifications, presentNotifications(state.notifications));
    } else {
      void storageRemove(StorageKeys.notifications);
    }
    if (state.guardians.length) {
      void storageSet(StorageKeys.guardians, state.guardians);
    } else {
      void storageRemove(StorageKeys.guardians);
    }
    if (state.lastScanAt) {
      void storageSet(StorageKeys.lastScanAt, state.lastScanAt);
    } else {
      void storageRemove(StorageKeys.lastScanAt);
    }
  }, [state.scanResult, state.devices, state.notifications, state.guardians, state.lastScanAt, state.isHydrated]);

  useEffect(() => {
    if (!state.isHydrated) return;
    if (state.guardianUser) {
      void storageSet(StorageKeys.guardianUser, state.guardianUser);
    } else {
      void storageRemove(StorageKeys.guardianUser);
    }
    if (state.guardianWards.length) {
      void storageSet(StorageKeys.guardianWards, state.guardianWards);
    } else {
      void storageRemove(StorageKeys.guardianWards);
    }
    if (state.selectedGuardianWardId) {
      void storageSet(StorageKeys.selectedGuardianWardId, state.selectedGuardianWardId);
    } else {
      void storageRemove(StorageKeys.selectedGuardianWardId);
    }
  }, [state.guardianUser, state.guardianWards, state.selectedGuardianWardId, state.isHydrated]);

  const setScreen = useCallback(
    (screen: Screen) => {
      const target = normalizeScreen(screen);
      setState((current) => ({ ...current, screen: target, history: [] }));
    },
    [],
  );

  // 새 화면으로 이동 + history 에 현재 push (뒤로가기 대상)
  const navigate = useCallback((screen: Screen) => {
    const target = normalizeScreen(screen);
    setState((current) => {
      if (current.screen === target) return current;
      return { ...current, screen: target, history: [...current.history, current.screen] };
    });
  }, []);

  // 뒤로가기. history 가 있으면 pop, 아니면 false 반환(앱 종료 확인은 App.tsx 에서).
  const goBack = useCallback((): boolean => {
    const currentState = stateRef.current;
    if (currentState.screen === "guardianMode" && currentState.guardianDashboard) {
      const statusMessage = currentState.guardianUser
        ? "내가 보는 사람들 목록으로 돌아왔어요."
        : "보호자 연결 화면으로 돌아왔어요.";
      stateRef.current = {
        ...currentState,
        guardianDashboard: null,
        guardianModeInviteCode: currentState.guardianUser ? "" : currentState.guardianModeInviteCode,
        statusMessage,
        statusTone: "info",
      };
      setState((current) => ({
        ...current,
        guardianDashboard: null,
        guardianModeInviteCode: current.guardianUser ? "" : current.guardianModeInviteCode,
        statusMessage: current.guardianUser ? "내가 보는 사람들 목록으로 돌아왔어요." : "보호자 연결 화면으로 돌아왔어요.",
        statusTone: "info",
      }));
      return true;
    }
    if (currentState.history.length === 0) {
      return false;
    }
    const nextHistory = [...currentState.history];
    const previousScreen = nextHistory.pop() ?? LOGIN_SCREEN;
    stateRef.current = { ...currentState, screen: previousScreen, history: nextHistory };
    setState((current) => {
      if (current.history.length === 0) {
        return current;
      }
      const next = [...current.history];
      const prev = next.pop() ?? LOGIN_SCREEN;
      return { ...current, screen: prev, history: next };
    });
    return true;
  }, []);

  const setGuardianEmail = useCallback(
    (guardianEmail: string) => {
      patchState({ guardianEmail });
      if (state.isHydrated) {
        void storageSet(StorageKeys.guardianEmail, guardianEmail);
      }
    },
    [patchState, state.isHydrated],
  );

  const setApiBaseUrl = useCallback(
    (apiBaseUrl: string) => {
      homeGuardianApi.setBaseUrl(apiBaseUrl);
      patchState({ apiBaseUrl });
      void storageSet(StorageKeys.apiBaseUrl, apiBaseUrl);
    },
    [patchState],
  );

  // 같은 액션의 연타는 첫 Promise를 공유해 중복 실행을 막되, 서로 다른 액션까지
  // 전역 잠금으로 버리지 않는다. 예: 상세 최신화가 느려도 점검 시작이나 이름 저장은
  // 독립적으로 진행돼야 한다.
  const inFlightActionsRef = useRef(new Map<string, Promise<void>>());
  const runAction = useCallback(
    (key: string, action: () => Promise<void>): Promise<void> => {
      const existing = inFlightActionsRef.current.get(key);
      if (existing) return existing;
      patchState({ isLoading: true });
      const pending = (async () => {
        try {
          await action();
        } catch (error) {
          const message = friendlyErrorMessage(error);
          setState((current) => ({
            ...current,
            statusMessage: message,
            statusTone: "danger",
            scanUi: current.screen === "scanProgress" ? failedScanUi(current.scanUi, message) : current.scanUi,
          }));
        } finally {
          inFlightActionsRef.current.delete(key);
          patchState({ isLoading: inFlightActionsRef.current.size > 0 });
        }
      })();
      inFlightActionsRef.current.set(key, pending);
      return pending;
    },
    [patchState],
  );

  const loadHome = useCallback(async (options: { retainCachedOnFailure?: boolean } = {}) => {
    const retainCachedOnFailure = options.retainCachedOnFailure ?? true;
    const [dashboardResult, devicesResult, notificationsResult, guardiansResult] = await Promise.allSettled([
      homeGuardianApi.getDashboard(),
      homeGuardianApi.getDevices(),
      homeGuardianApi.getNotifications(),
      homeGuardianApi.getGuardians(),
    ]);

    // 실패한 호출은 가짜 데이터로 채우지 않는다. 화면에는 빈 배열/null 만 노출된다.
    patchState({
      dashboard: dashboardResult.status === "fulfilled" ? presentDashboard(dashboardResult.value) : retainCachedOnFailure ? stateRef.current.dashboard : null,
      devices:
        devicesResult.status === "fulfilled"
          ? presentDeviceCollection(
              devicesResult.value?.items,
              devicesResult.value?.detected_connections,
            )
          : retainCachedOnFailure
          ? stateRef.current.devices
          : [],
      notifications: notificationsResult.status === "fulfilled" ? presentNotifications(notificationsResult.value?.items) : retainCachedOnFailure ? stateRef.current.notifications : [],
      guardians: guardiansResult.status === "fulfilled" ? normalizeGuardianInvites(guardiansResult.value?.items) : retainCachedOnFailure ? stateRef.current.guardians : [],
    });

    return [dashboardResult, devicesResult, notificationsResult, guardiansResult].some(
      (result) => result.status === "rejected",
    );
  }, [patchState]);

  const loginWithGoogle = useCallback(
    () =>
      runAction("login:user", async () => {
        if (!stateRef.current.isHydrated) {
          patchState({
            statusMessage: "앱 준비가 끝난 뒤 다시 눌러 주세요.",
            statusTone: "info",
          });
          return;
        }
        const previousSession = stateRef.current.authSession;
        const oauth = await googleSignIn.promptSignIn("user", previousSession?.refreshToken);
        if (!oauth.ok || !oauth.user || !oauth.session) {
          patchState({
            // OAuth 라이브러리 원문에는 내부 설정·주소가 포함될 수 있다.
            statusMessage: "Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
            statusTone: "danger",
          });
          return;
        }
        try {
          const candidateSession = toStoredAuthSession(oauth.session.user, oauth.session);
          if (candidateSession.role !== "user") {
            throw new HomeGuardianApiError("로그인 정보를 다시 확인해 주세요.", "AUTH_SESSION_INVALID");
          }
          let nextSession = candidateSession;
          if (previousSession) {
            // Callback response loss leaves this old key untouched. Only after
            // the candidate+handoff have been durably written do we ask the
            // server to revoke the old role and activate the new one.
            const pendingHandoff = createStoredAuthHandoff(previousSession, candidateSession, oauth.session.handoff);
            await secureStorageSetRequired(SecureStorageKeys.pendingAuthHandoff, JSON.stringify(pendingHandoff));
            nextSession = await completeStoredAuthHandoff(pendingHandoff);
            await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(nextSession));
            await secureStorageRemoveRequired(SecureStorageKeys.pendingAuthHandoff);
          } else {
            await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(nextSession));
          }
          const accountChanged = Boolean(
            previousSession &&
              (previousSession.role !== nextSession.role || previousSession.userId !== nextSession.userId),
          );
          homeGuardianApi.setAuthToken(nextSession.accessToken);
          await secureStorageRemove(SecureStorageKeys.authToken);
          if (accountChanged) {
            await clearAccountScopedCache();
            // Account-scoped persistence is asynchronous. Clear the in-memory
            // copy before loadHome so a transient failure cannot write or show
            // the previous person's scan while the new account is active.
            patchState({
              dashboard: null,
              devices: [],
              selectedDevice: null,
              scanResult: null,
              guardians: [],
              notifications: [],
              guardianEmail: "",
              lastScanAt: null,
              notificationsEnabled: false,
              autoScanEnabled: false,
              autoScanIntervalHours: 24,
              guardianDashboard: null,
              guardianModeInviteCode: "",
              guardianUser: null,
              guardianWards: [],
              selectedGuardianWardId: null,
            });
          }
          const usedFallback = await loadHome({ retainCachedOnFailure: !accountChanged });
          await Promise.all([
            storageRemove(StorageKeys.guardianUser),
            storageRemove(StorageKeys.guardianWards),
            storageRemove(StorageKeys.selectedGuardianWardId),
          ]);
          patchState({
            user: oauth.session.user,
            authToken: nextSession.accessToken,
            authSession: nextSession,
            guardianDashboard: null,
            guardianModeInviteCode: "",
            guardianUser: null,
            guardianWards: [],
            selectedGuardianWardId: null,
            statusMessage: usedFallback
              ? "Google 로그인은 성공했지만 일부 데이터를 불러오지 못했습니다. 잠시 후 다시 시도해 주세요."
              : "Google 계정으로 들어왔습니다.",
            statusTone: usedFallback ? "warning" : "success",
            screen: "scanResult",
            history: [],
          });
        } catch (error) {
          homeGuardianApi.setAuthToken(previousSession?.accessToken ?? null);
          patchState({
            statusMessage: previousSession
              ? `${friendlyErrorMessage(error)} 기존 로그인과 저장된 화면은 유지합니다. 잠시 후 다시 로그인 전환을 시도해 주세요.`
              : `${friendlyErrorMessage(error)} 서버 연결을 확인하고 다시 시도해 주세요.`,
            statusTone: previousSession ? "warning" : "danger",
          });
        }
      }),
    [googleSignIn, loadHome, patchState, runAction],
  );

  const logout = useCallback(async () => {
    const activeSession = stateRef.current.authSession;
    let statusMessage = "로그아웃했습니다.";
    let statusTone: StatusTone = "info";
    if (activeSession) {
      try {
        await deleteRegisteredDevicePushToken().catch(() => undefined);
        // Wait for the server acknowledgement instead of fire-and-forget. A
        // response-loss error is handled below without retaining the local
        // session or any household cache.
        await homeGuardianApi.logoutAuthSession(activeSession.refreshToken);
        await secureStorageRemove(SecureStorageKeys.pendingLogout);
      } catch (error) {
        if (!isTerminalAuthError(error)) {
          try {
            await secureStorageSetRequired(
              SecureStorageKeys.pendingLogout,
              JSON.stringify({ refreshToken: activeSession.refreshToken, createdAt: Date.now() } satisfies PendingLogout),
            );
            statusMessage = "로그아웃했고 서버 정리를 다시 시도할게요.";
            statusTone = "warning";
          } catch {
            // Do not keep a raw refresh token in AsyncStorage or memory-only
            // native storage. Local logout still wins; explain that the server
            // retry record could not be saved instead of pretending otherwise.
            statusMessage = "로그아웃했지만 서버 정리 정보를 안전하게 저장하지 못했어요.";
            statusTone = "warning";
          }
        }
      }
    }
    homeGuardianApi.clearAuthToken();
    await Promise.all([
      storageClear({ preserveAppPreferences: true }),
      secureStorageRemove(SecureStorageKeys.authSession),
      secureStorageRemove(SecureStorageKeys.authToken),
      unregisterAutoScan().catch(() => undefined),
    ]);
    setState((current) => ({
      ...current,
      user: null,
      authToken: null,
      authSession: null,
      dashboard: null,
      devices: [],
      selectedDevice: null,
      scanResult: null,
      guardians: [],
      notifications: [],
      notificationsEnabled: false,
      autoScanEnabled: false,
      autoScanIntervalHours: 24,
      guardianEmail: "",
      lastScanAt: null,
      guardianDashboard: null,
      guardianModeInviteCode: "",
      guardianUser: null,
      guardianWards: [],
      selectedGuardianWardId: null,
      screen: LOGIN_SCREEN,
      history: [],
      statusMessage,
      statusTone,
    }));
  }, [deleteRegisteredDevicePushToken]);

  const startScan = useCallback(
    () =>
      setState((current) => ({
        ...current,
        screen: "scanConsent",
        history: TAB_SCREENS.includes(current.screen) ? [current.screen] : current.history,
        scanUi: initialScanUi(),
        statusMessage: "우리 집 Wi-Fi에 연결되어 있는지 확인한 뒤 점검을 시작해 주세요.",
        statusTone: "info",
      })),
    [],
  );

  const beginNetworkScan = useCallback(
    () =>
      runAction("network-scan", async () => {
        let scanUi = updateScanStep(initialScanUi(), "wifi", "running", 8, "휴대폰 Wi-Fi 정보를 확인하고 있습니다.");
        patchState({
          screen: "scanProgress",
          scanUi,
          statusMessage: "우리 집 내부망 점검을 시작했습니다.",
          statusTone: "info",
        });

        await wait(250);
        scanUi = updateScanStep(scanUi, "wifi", "completed", 20, "같은 공유기 Wi-Fi 여부를 확인했습니다.");
        patchState({ scanUi });

        scanUi = updateScanStep(
          scanUi,
          "discovery",
          "running",
          38,
          "집에 연결된 물건을 찾고 있습니다.",
        );
        patchState({ scanUi });

        const nativeScan = await scanHomeNetwork();
        if (!nativeScan.isActualScan) {
          // 네이티브 모듈의 원문 오류에는 Android/네트워크 구현 정보가 섞일 수 있다.
          // 앱 화면에는 원문을 전달하지 않고, 사용자가 바로 할 수 있는 행동만 안내한다.
          const message = friendlyScanFailureMessage(nativeScan.nativeErrorCode);
          patchState({
            scanUi: failedScanUi(
              {
                ...scanUi,
                networkContext: nativeScan.network_context ?? null,
                nativeMessage: nativeScan.nativeMessage ?? null,
                sourceLabel:
                  nativeScan.nativeErrorCode === "SCAN_ACTUAL_DEVICE_REQUIRED"
                    ? "실기기 필요"
                    : sourceLabel(nativeScan.scan_source),
              },
              message,
              nativeScan.nativeErrorCode ?? "SCAN_ACTUAL_DEVICE_REQUIRED",
            ),
            statusMessage: message,
            statusTone: "danger",
            screen: "scanProgress",
          });
          return;
        }

        const nativeCoverage = scanCoverageState(nativeScan);
        const afterDiscovery = completeStepsUntil(
          "discovery",
          nativeCoverage.isPartial
            ? "이번에는 일부 연결만 확인했어요. 확인한 내용은 보관하고 다시 점검할 수 있게 준비합니다."
            : nativeScan.devices?.length
            ? "연결 상태를 확인했습니다."
            : "확인된 물건이 없어 빈 결과로 기록합니다.",
        );
        patchState({
          scanUi: {
            ...afterDiscovery,
            progress: 62,
            networkContext: nativeScan.network_context ?? null,
            nativeMessage: nativeScan.nativeMessage ?? null,
            sourceLabel: sourceLabel(nativeScan.scan_source),
            coverageComplete: nativeCoverage.coverageComplete,
            tcpScanTimedOut: nativeCoverage.tcpScanTimedOut,
          },
        });

        await wait(250);
        patchState({
          scanUi: updateScanStep(
            {
              ...afterDiscovery,
              networkContext: nativeScan.network_context ?? null,
              nativeMessage: nativeScan.nativeMessage ?? null,
              sourceLabel: sourceLabel(nativeScan.scan_source),
              coverageComplete: nativeCoverage.coverageComplete,
              tcpScanTimedOut: nativeCoverage.tcpScanTimedOut,
            },
            "services",
            "completed",
            74,
            nativeCoverage.isPartial ? "확인된 연결만 안전하게 정리했습니다." : "연결 상태를 정리했습니다.",
          ),
        });

        // 백엔드 저장 + 결과 조회. 실패하면 가짜 데이터로 화면을 채우지 않고 실패 상태만 표시.
        let result: ScanResult;
        try {
          const scan = await homeGuardianApi.startScan(nativeScan);
          const serverStartResearch = identityResearchState(scan);
          const serverStartCoverage = scanCoverageState(nativeScan, scan);
          patchState({
            scanUi: {
              ...updateScanStep(
                completeStepsUntil(
                  "analysis",
                   serverStartCoverage.isPartial
                     ? serverStartResearch.isIncomplete
                       ? SCAN_INCOMPLETE_TITLE
                       : "확인된 범위 안에서만 안전 상태를 정리하고 있어요."
                     : "위험 신호를 점수와 조치 안내로 변환했습니다.",
                ),
                "guardian",
                "running",
                88,
                 serverStartCoverage.isPartial
                   ? serverStartResearch.isIncomplete
                     ? scanIncompleteMessage(hasConfirmedRedRisk(scan))
                     : "부분 점검임을 분명히 표시해 결과를 준비하고 있습니다."
                   : "보호자 알림에 필요한 요약을 준비하고 있습니다.",
              ),
              // completeStepsUntil 은 initialScanUi() 로 리셋하므로 네트워크 출처 정보를 다시 채운다
              // (이 중간 상태에서 sourceLabel 이 "대기 중" 으로 깜빡이는 회귀 방지).
              networkContext: nativeScan.network_context ?? null,
              nativeMessage: nativeScan.nativeMessage ?? null,
              sourceLabel: sourceLabel(nativeScan.scan_source),
              coverageComplete: serverStartCoverage.coverageComplete,
              tcpScanTimedOut: serverStartCoverage.tcpScanTimedOut,
              identityResearchPending: serverStartResearch.isIncomplete,
              confirmedRedRisk: hasConfirmedRedRisk(scan),
            },
          });

          const rawResult = await homeGuardianApi.getScanResult(scan.scan_id);
          const coverage = scanCoverageState(nativeScan, scan, rawResult);
          const partialScoreIsProvisional =
            coverage.isPartial &&
            rawResult.security_score.score_status === "provisional" &&
            typeof rawResult.security_score.score === "number" &&
            Number.isFinite(rawResult.security_score.score);
          const normalizedResult: ScanResult = {
            ...rawResult,
            status: coverage.isPartial ? "partial" : rawResult.status,
            scan_complete: coverage.isPartial ? false : rawResult.scan_complete ?? coverage.coverageComplete ?? undefined,
            coverage_complete: coverage.isPartial ? false : coverage.coverageComplete ?? rawResult.coverage_complete,
            tcp_scan_timed_out: coverage.tcpScanTimedOut,
            security_score: coverage.isPartial
              ? {
                  ...rawResult.security_score,
                  score: partialScoreIsProvisional ? rawResult.security_score.score : null,
                  score_status: partialScoreIsProvisional ? "provisional" : "held",
                  risk_level: hasConfirmedRedRisk(rawResult)
                    ? "red"
                    : partialScoreIsProvisional
                    ? rawResult.security_score.risk_level
                    : "yellow",
                }
              : rawResult.security_score,
          };
          const presentedResult = presentScanResult(normalizedResult);
          if (!presentedResult) {
            throw new HomeGuardianApiError("점검 결과를 안전하게 확인하지 못했어요. 다시 점검해 주세요.", "INVALID_SCAN_RESULT");
          }
          result = presentedResult;
          const [notificationsResult, guardiansResult, dashboardResult] = await Promise.allSettled([
            homeGuardianApi.getNotifications(),
            homeGuardianApi.getGuardians(),
            homeGuardianApi.getDashboard(),
          ]);
          patchState({
            dashboard:
              dashboardResult.status === "fulfilled"
                ? presentDashboard(dashboardResult.value)
                : stateRef.current.dashboard,
            // 공개 가능한 안정적 네트워크 범위 키가 없으므로 이전 Wi-Fi의 기기를
            // 재사용하지 않는다. 부분 점검이어도 이번 시도에서 확인한 공개 기기만
            // 현재 화면과 영구 캐시에 남기고, 불완전성은 별도 partial 상태로 알린다.
            devices: deviceCacheAfterScan(presentDevices(result.devices)),
            notifications:
              notificationsResult.status === "fulfilled"
                ? presentNotifications(notificationsResult.value.items)
                : stateRef.current.notifications,
            guardians:
              guardiansResult.status === "fulfilled"
                ? normalizeGuardianInvites(guardiansResult.value?.items)
                : stateRef.current.guardians,
          });
        } catch (error) {
          const scanFailureMessage = friendlyScanSaveFailureMessage(error);
          patchState({
            scanUi: failedScanUi(
              {
                ...scanUi,
                networkContext: nativeScan.network_context ?? null,
                nativeMessage: nativeScan.nativeMessage ?? null,
                sourceLabel: sourceLabel(nativeScan.scan_source),
                coverageComplete: nativeCoverage.coverageComplete,
                tcpScanTimedOut: nativeCoverage.tcpScanTimedOut,
              },
              scanFailureMessage,
              "SCAN_SAVE_FAILED",
            ),
            statusMessage: scanFailureMessage,
            statusTone: "danger",
          });
          return;
        }

        const nowIso = new Date().toISOString();
        // 위험(red)뿐 아니라 주의(yellow) 물건도 상태 배너에 반영(공유기 CVE 등 yellow 를 숨기지 않게).
        const coverage = scanCoverageState(result);
        const research = identityResearchState(result);
        const cautionCount = result.devices.filter((device) => device.risk_level === "yellow").length;
        const detectedCount = residentVisibleDevices(result.devices).length;
        const confirmedRedRisk = hasConfirmedRedRisk(result);
        const noTargets = result.security_score.score_status === "no_targets";
        patchState({
          scanResult: result,
          lastScanAt: nowIso,
          scanUi: {
            ...completeStepsUntil(
              "guardian",
              coverage.isPartial
                ? scanIncompleteMessage(confirmedRedRisk)
                : noTargets
                ? "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요."
                : "보호자에게 공유할 수 있는 결과가 준비됐습니다.",
            ),
            progress: 100,
            networkContext: result.network_context ?? nativeScan.network_context ?? null,
            nativeMessage: nativeScan.nativeMessage ?? null,
            sourceLabel: sourceLabel(result.scan_source),
            coverageComplete: coverage.coverageComplete,
            tcpScanTimedOut: coverage.tcpScanTimedOut,
            identityResearchPending: research.isIncomplete,
            confirmedRedRisk,
          },
          statusMessage:
            coverage.isPartial
              ? confirmedRedRisk
                ? `이번 점검은 일부 연결만 확인했지만, 확인한 범위에서 위험 신호가 있어요. 결과를 먼저 살펴보고 와이파이가 안정되면 다시 점검해 주세요.`
                : `이번 점검은 일부 연결만 확인했어요. 확인된 물건 ${detectedCount}개는 보관했고, 와이파이가 안정되면 다시 점검해 주세요.`
              : noTargets
              ? "점검 완료: 평가할 네트워크 기기는 확인되지 않았어요."
              : result.high_risk_devices > 0
              ? `점검 완료: 확인된 연결 ${detectedCount}대 · 위험 ${result.high_risk_devices}대${cautionCount > 0 ? ` · 주의 ${cautionCount}대` : ""}`
              : cautionCount > 0
              ? `점검 완료: 확인된 연결 ${detectedCount}대 · 주의가 필요한 물건 ${cautionCount}대`
              : `점검 완료: 확인된 연결 ${detectedCount}대 · 위험·주의 물건 없음`,
          statusTone: confirmedRedRisk
            ? "danger"
            : coverage.isPartial || cautionCount > 0
            ? "warning"
            : noTargets
            ? "info"
            : "success",
          screen: "scanResult",
          history: [],
        });

        // 제품명 보강은 점검 완료와 독립적이다. 실제 네트워크 범위를 끝까지
        // 확인했으면 제품명이 없는 연결도 보안 신호와 함께 완료 알림에 포함한다.
        if (!coverage.isPartial) {
          void notifyScanCompleted({
            score: result.security_score.score,
            highRisk: result.high_risk_devices,
            caution: result.devices.filter((device) => device.risk_level === "yellow").length,
            deviceCount: detectedCount,
          });
        }
      }),
    [patchState, runAction],
  );

  const retryScan = useCallback(() => {
    setState((current) => ({
      ...current,
      screen: "scanConsent",
      scanUi: initialScanUi(),
      statusMessage: "점검을 다시 시작할 준비가 됐습니다.",
      statusTone: "info",
      // 다시 점검하기는 새 화면으로 이동하는 동작이다. 기존 화면을
      // 히스토리에 남겨야 Android 하드웨어 뒤로가기가 앱 종료 대신
      // 직전 결과/목록으로 돌아간다.
      history:
        current.screen === "scanConsent"
          ? current.history
          : [...current.history, current.screen],
    }));
  }, []);

  const shareScanWithGuardian = useCallback(
    () => {
      const hasGuardian = state.guardians.some((guardian) => !guardian.invite_id.startsWith("local-invite-"));
      setState((current) => ({
        ...current,
        screen: "guardian",
        // 결과/상세 화면에서 보호자 화면으로 이동한 경우에도 원래
        // 화면을 보존한다. 이미 보호자 화면이면 중복 push를 만들지 않는다.
        history:
          current.screen === "guardian"
            ? current.history
            : [...current.history, current.screen],
        statusMessage: hasGuardian
          ? "연결된 보호자를 확인하고 필요하면 초대 코드를 다시 공유해 주세요."
          : "도움을 받을 보호자 이메일을 입력하고 초대 코드를 보내 주세요.",
        statusTone: "info",
      }));
    },
    [state.guardians],
  );

  const openDevice = useCallback(
    (device: Device) => {
      const presentedDevice = presentDevice(device);
      if (!presentedDevice) {
        patchState({
          statusMessage: "확인된 물건 정보만 열 수 있어요. 다음 검사 후 다시 확인해 주세요.",
          statusTone: "warning",
        });
        return;
      }

      // 목록에 이미 검증되어 표시된 정보로 상세 화면을 먼저 연다. 서버 상세
      // 요청(최대 8초)이 화면 이동을 막아 버튼이 안 눌린 것처럼 보이면 안 된다.
      setState((current) => ({
        ...current,
        selectedDevice: presentedDevice,
        screen: "detail",
        history: current.screen === "detail" ? current.history : [...current.history, current.screen],
        statusMessage: "저장된 정보로 먼저 열고 최신 상태를 확인하고 있어요.",
        statusTone: "info",
      }));

      void runAction(`device-detail:${presentedDevice.device_id}`, async () => {
        try {
          const detail = await homeGuardianApi.getDevice(presentedDevice.device_id);
          const presentedDetail = presentDevice(detail) ?? presentedDevice;
          setState((current) => {
            if (current.selectedDevice?.device_id !== presentedDevice.device_id) return current;
            return {
              ...current,
              selectedDevice: presentedDetail,
              statusMessage: "최신 물건 정보를 확인했습니다.",
              statusTone: "info",
            };
          });
        } catch (error) {
          setState((current) => {
            if (current.selectedDevice?.device_id !== presentedDevice.device_id) return current;
            return {
              ...current,
              selectedDevice: presentedDevice,
              statusMessage: `${friendlyErrorMessage(error)} 저장된 목록 정보로 상세 화면을 열었습니다.`,
              statusTone: "warning",
            };
          });
        }
      });
    },
    [patchState, runAction],
  );

  const renameDevice = useCallback(
    (deviceId: string, alias: string | null) =>
      runAction(`device-alias:${deviceId}`, async () => {
        const updated = await homeGuardianApi.updateDeviceAlias(deviceId, alias);
        const presentedUpdated = presentDevice(updated);
        setState((current) => ({
          ...current,
          devices: current.devices.map((item) => (item.device_id === deviceId ? presentedUpdated ?? item : item)),
          selectedDevice:
            current.selectedDevice?.device_id === deviceId ? presentedUpdated ?? current.selectedDevice : current.selectedDevice,
          statusMessage: alias ? "기기 이름을 저장했어요." : "기기 이름을 기본값으로 되돌렸어요.",
          statusTone: "success",
        }));
      }),
    [runAction],
  );

  const inviteGuardian = useCallback(
    () =>
      runAction("guardian-invite:create", async () => {
        try {
          const currentUser = stateRef.current.user;
          const wardAccountName =
            currentUser?.nickname?.trim() || currentUser?.email?.split("@", 1)[0]?.trim() || "사용자";
          const invite = await homeGuardianApi.inviteGuardian(state.guardianEmail, "보호자", wardAccountName);
          await loadHome();
          patchState({
            statusMessage: invite.short_code
              ? `초대가 준비됐어요. 짧은 코드 ${invite.short_code}를 보호자에게 보내 주세요.`
              : "보호자 초대를 준비했어요. 보호자에게 안내를 보내 주세요.",
            statusTone: "success",
          });
        } catch (error) {
          patchState({
            statusMessage: `${friendlyErrorMessage(error)} 서버 연결을 확인하고 다시 시도해 주세요.`,
            statusTone: "danger",
          });
        }
      }),
    [loadHome, patchState, runAction, state.guardianEmail],
  );

  const revokeGuardianInvite = useCallback(
    (inviteId: string) =>
      runAction(`guardian-invite:revoke:${inviteId}`, async () => {
        try {
          const invite = await homeGuardianApi.revokeGuardianInvite(inviteId);
          await loadHome();
          patchState({
            statusMessage: `${invite.email} 보호자 초대를 취소했어요.`,
            statusTone: "success",
          });
        } catch (error) {
          patchState({
            statusMessage: `${friendlyErrorMessage(error)} 초대 취소를 다시 시도해 주세요.`,
            statusTone: "danger",
          });
        }
      }),
    [loadHome, patchState, runAction],
  );

  const deleteGuardianInvite = useCallback(
    (inviteId: string) =>
      runAction(`guardian-invite:delete:${inviteId}`, async () => {
        try {
          const invite = await homeGuardianApi.deleteGuardianInvite(inviteId);
          await loadHome();
          patchState({
            statusMessage: `${invite.email} 보호자 초대를 목록에서 삭제했어요.`,
            statusTone: "success",
          });
        } catch (error) {
          patchState({
            statusMessage: `${friendlyErrorMessage(error)} 초대 삭제를 다시 시도해 주세요.`,
            statusTone: "danger",
          });
        }
      }),
    [loadHome, patchState, runAction],
  );

  const markNotificationRead = useCallback(
    (notificationId: string) =>
      runAction(`notification-read:${notificationId}`, async () => {
        try {
          await homeGuardianApi.markNotificationRead(notificationId);
          await loadHome();
          patchState({ statusMessage: "알림을 읽음 처리했습니다.", statusTone: "success" });
        } catch (error) {
          // 백엔드 연결 실패 시 화면에서만 읽음으로 표시. 다음 동기화 때 서버 상태와 맞춤.
          setState((current) => ({
            ...current,
            notifications: current.notifications.map((notification) =>
              notification.notification_id === notificationId ? { ...notification, read: true } : notification,
            ),
            statusMessage: `${friendlyErrorMessage(error)} 화면에서는 읽음으로 표시했습니다.`,
            statusTone: "warning",
          }));
        }
      }),
    [loadHome, patchState, runAction],
  );

  const setNotificationsEnabled = useCallback(
    async (enabled: boolean) => {
      if (!enabled) {
        patchState({
          notificationsEnabled: false,
          statusMessage: "알림을 껐습니다.",
          statusTone: "info",
        });
        await storageSet(StorageKeys.notificationsEnabled, false);
        await deleteRegisteredDevicePushToken().catch(() => undefined);
        return;
      }

      const granted = await requestNotificationsPermission();
      if (!granted) {
        patchState({
          notificationsEnabled: false,
          statusMessage: "알림 권한이 거부되어 알림을 받을 수 없습니다.",
          statusTone: "warning",
        });
        await storageSet(StorageKeys.notificationsEnabled, false);
        return;
      }

      patchState({
        notificationsEnabled: true,
        statusMessage: "휴대폰 알림을 켰습니다. 보호자 알림 연결을 확인하고 있어요.",
        statusTone: "info",
      });
      await storageSet(StorageKeys.notificationsEnabled, true);

      // 실제 device push token 을 받아 백엔드에 등록한다. 실패해도 로컬 알림은 유지하되,
      // 보호자 push 연결은 확인되지 않았다고 화면에 남긴다.
      try {
        const registered = await registerCurrentDevicePushToken();
        patchState(
          registered
            ? {
                statusMessage: "알림을 켰습니다. 검사 완료 시 보호자에게도 알려드릴게요.",
                statusTone: "success",
              }
            : {
                statusMessage: "휴대폰 알림은 켰지만 보호자 알림 연결은 아직 확인하지 못했습니다.",
                statusTone: "warning",
              },
        );
      } catch {
        patchState({
          statusMessage: "휴대폰 알림은 켰지만 보호자 알림 연결은 아직 확인하지 못했습니다.",
          statusTone: "warning",
        });
      }
    },
    [deleteRegisteredDevicePushToken, patchState, registerCurrentDevicePushToken],
  );

  const setAutoScanIntervalHours = useCallback(
    (hours: number) => {
      const normalized = Math.max(1, Math.min(168, Math.round(hours)));
      patchState({ autoScanIntervalHours: normalized });
      void storageSet(StorageKeys.autoScanIntervalHours, normalized);
      // 마스터 토글이 켜져 있을 때만 새 주기로 재등록. 꺼져 있으면 unregister 상태 유지.
      setState((current) => {
        if (current.autoScanEnabled) {
          void registerAutoScan(normalized);
        }
        return current;
      });
    },
    [patchState],
  );

  const loadGuardianWards = useCallback(async () => {
    const guardianUser = stateRef.current.guardianUser;
    if (!guardianUser) {
      patchState({
        statusMessage: "보호자 Google 로그인이 먼저 필요합니다.",
        statusTone: "warning",
      });
      return;
    }
    try {
      const wards = await homeGuardianApi.getGuardianWards(guardianUser.user_id);
      patchState({
        guardianWards: wards.items,
        selectedGuardianWardId:
          stateRef.current.selectedGuardianWardId &&
          wards.items.some((ward) => ward.link_id === stateRef.current.selectedGuardianWardId)
            ? stateRef.current.selectedGuardianWardId
            : wards.items[0]?.link_id ?? null,
        statusMessage: wards.items.length
          ? "보호자 계정에 연결된 피보호자를 불러왔어요."
          : "아직 추가된 피보호자가 없습니다. 초대 코드를 한 번 입력해 주세요.",
        statusTone: wards.items.length ? "success" : "info",
      });
    } catch (error) {
      patchState({
        statusMessage: `${friendlyErrorMessage(error)} 보호자 목록을 다시 불러오지 못했습니다.`,
        statusTone: "warning",
      });
    }
  }, [patchState]);

  const loginAsGuardianWithGoogle = useCallback(
    () =>
      runAction("login:guardian", async () => {
        if (!stateRef.current.isHydrated) {
          patchState({
            statusMessage: "앱 준비가 끝난 뒤 다시 눌러 주세요.",
            statusTone: "info",
          });
          return;
        }
        const previousSession = stateRef.current.authSession;
        const oauth = await googleSignIn.promptSignIn("guardian", previousSession?.refreshToken);
        if (!oauth.ok || !oauth.user || !oauth.session) {
          patchState({
            // 보호자 로그인도 같은 안전한 사용자 안내만 노출한다.
            statusMessage: "Google 보호자 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
            statusTone: "danger",
          });
          return;
        }
        let guardianUser: User;
        let nextSession: StoredAuthSession;
        let accountChanged = false;
        try {
          const candidateSession = toStoredAuthSession(oauth.session.user, oauth.session);
          if (candidateSession.role !== "guardian") {
            throw new HomeGuardianApiError("로그인 정보를 다시 확인해 주세요.", "AUTH_SESSION_INVALID");
          }
          nextSession = candidateSession;
          if (previousSession) {
            const pendingHandoff = createStoredAuthHandoff(previousSession, candidateSession, oauth.session.handoff);
            await secureStorageSetRequired(SecureStorageKeys.pendingAuthHandoff, JSON.stringify(pendingHandoff));
            nextSession = await completeStoredAuthHandoff(pendingHandoff);
            await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(nextSession));
            await secureStorageRemoveRequired(SecureStorageKeys.pendingAuthHandoff);
          } else {
            await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(nextSession));
          }
          accountChanged = Boolean(
            previousSession &&
              (previousSession.role !== nextSession.role || previousSession.userId !== nextSession.userId),
          );
          homeGuardianApi.setAuthToken(nextSession.accessToken);
          guardianUser = toGuardianUser(oauth.session.user);
          await secureStorageRemove(SecureStorageKeys.authToken);
        } catch (error) {
          homeGuardianApi.setAuthToken(previousSession?.accessToken ?? null);
          patchState({
            statusMessage: `${friendlyErrorMessage(error)} 기존 로그인과 저장된 화면은 유지합니다. 잠시 후 다시 로그인 전환을 시도해 주세요.`,
            statusTone: "warning",
          });
          return;
        }
        if (accountChanged) {
          await clearAccountScopedCache();
          // Never leave the former user's household visible while the new
          // guardian account is loading its own read-only list.
          patchState({
            user: null,
            dashboard: null,
            devices: [],
            selectedDevice: null,
            scanResult: null,
            guardians: [],
            notifications: [],
            guardianEmail: "",
            lastScanAt: null,
            notificationsEnabled: false,
            autoScanEnabled: false,
            autoScanIntervalHours: 24,
            guardianDashboard: null,
            guardianModeInviteCode: "",
            guardianUser: null,
            guardianWards: [],
            selectedGuardianWardId: null,
          });
        }
        let wards: GuardianWard[] = [];
        let wardLoadFailed = false;
        try {
          const response = await homeGuardianApi.getGuardianWards(guardianUser.user_id);
          wards = response.items;
        } catch {
          wardLoadFailed = true;
          wards = !accountChanged && previousSession?.role === "guardian" && previousSession.userId === guardianUser.user_id
            ? stateRef.current.guardianWards
            : [];
        }
        await Promise.all([
          storageRemove(StorageKeys.user),
          storageRemove(StorageKeys.scanResult),
          storageRemove(StorageKeys.devices),
          storageRemove(StorageKeys.notifications),
          storageRemove(StorageKeys.guardians),
          storageRemove(StorageKeys.guardianEmail),
          storageRemove(StorageKeys.lastScanAt),
        ]);
        patchState({
          user: null,
          authToken: nextSession.accessToken,
          authSession: nextSession,
          dashboard: null,
          devices: [],
          selectedDevice: null,
          scanResult: null,
          guardians: [],
          notifications: [],
          guardianEmail: "",
          lastScanAt: null,
          guardianUser,
          guardianWards: wards,
          selectedGuardianWardId: wards[0]?.link_id ?? null,
          guardianDashboard: wardLoadFailed && !accountChanged ? stateRef.current.guardianDashboard : null,
          guardianModeInviteCode: "",
          screen: "guardianMode",
          history: [],
          statusMessage: wardLoadFailed
            ? "보호할 분 목록을 불러오지 못했어요. 연결을 확인한 뒤 다시 시도해 주세요."
            : wards.length
            ? "Google 보호자 계정으로 들어왔습니다. 볼 사람을 선택해 주세요."
            : "Google 보호자 계정으로 들어왔습니다. 피보호자를 추가해 주세요.",
          statusTone: wardLoadFailed ? "warning" : "success",
        });
      }),
    [googleSignIn, patchState, runAction],
  );

  const acceptGuardianInvite = useCallback(
    (inviteInput: string) =>
      runAction("guardian-invite:accept", async () => {
        const guardianUser = stateRef.current.guardianUser;
        const inviteCode = parseGuardianInviteInput(inviteInput);
        if (!guardianUser) {
          patchState({
            guardianModeInviteCode: inviteCode,
            statusMessage: "초대 코드는 보호자 Google 로그인 후 피보호자 추가에 사용합니다.",
            statusTone: "warning",
          });
          return;
        }
        const result = await homeGuardianApi.acceptGuardianInvite(inviteCode);
        patchState({
          guardianWards: result.wards,
          selectedGuardianWardId: result.active_ward.link_id,
          guardianDashboard: presentGuardianDashboard(result.dashboard),
          guardianModeInviteCode: "",
          statusMessage: `${guardianWardTitle(
            result.active_ward,
            Math.max(
              0,
              result.wards.findIndex((ward) => ward.link_id === result.active_ward.link_id),
            ),
            result.wards,
          )} 연결을 추가했어요.`,
          statusTone: "success",
        });
      }),
    [patchState, runAction],
  );

  const openGuardianWard = useCallback(
    (linkId: string) => {
      const guardianUser = stateRef.current.guardianUser;
      if (!guardianUser) {
        patchState({
          statusMessage: "보호자 Google 로그인이 먼저 필요합니다.",
          statusTone: "warning",
        });
        return Promise.resolve();
      }

      const selectedWard = stateRef.current.guardianWards.find((ward) => ward.link_id === linkId);
      if (!selectedWard) {
        patchState({
          statusMessage: "선택한 피보호자 연결을 찾을 수 없습니다. 목록을 다시 불러와 주세요.",
          statusTone: "warning",
        });
        return Promise.resolve();
      }

      // 목록에 이미 표시된 피보호자 요약으로 읽기 전용 화면을 먼저 연다.
      // 서버 목록 응답의 개인정보 제거 기기 스냅샷도 함께 써서, 상세 요청이
      // 느리거나 일시 실패해도 등록 대수만 있고 기기 정보는 빈 화면이 되지 않게 한다.
      const previewDevices = presentDevices(selectedWard.devices ?? []);
      const previewDashboard: GuardianDashboard = {
        invite: {
          invite_id: selectedWard.invite_id,
          email: "",
          relation: "",
          ward_account_name: selectedWard.ward_account_name ?? null,
          status: selectedWard.status,
          accepted_at: selectedWard.accepted_at ?? null,
          last_viewed_at: selectedWard.last_viewed_at ?? null,
        },
        ward: selectedWard,
        ward_summary: selectedWard.summary ?? {
          score: null,
          risk_level: null,
          device_count: 0,
          high_risk_devices: 0,
          caution_devices: 0,
          unread_notifications: 0,
        },
        devices: previewDevices,
        high_risk_devices: previewDevices.filter((device) => device.risk_level === "red"),
        caution_devices: previewDevices.filter((device) => device.risk_level === "yellow"),
        recent_notifications: [],
        read_only: true,
        scope: "guardian-read-only-preview",
      };
      patchState({
        guardianDashboard: previewDashboard,
        selectedGuardianWardId: linkId,
        statusMessage: "선택한 피보호자의 기기 상태를 불러오고 있어요.",
        statusTone: "info",
      });

      return runAction(`guardian-ward:open:${linkId}`, async () => {
        const dashboard = await homeGuardianApi.getGuardianWardDashboard(guardianUser.user_id, linkId);
        const presentedDashboard = presentGuardianDashboard(dashboard);
        setState((current) => {
          if (current.selectedGuardianWardId !== linkId || !current.guardianDashboard) return current;
          return {
            ...current,
            guardianDashboard: presentedDashboard ?? current.guardianDashboard,
            statusMessage: presentedDashboard
              ? "선택한 피보호자의 보호자 진단을 열었어요."
              : "최신 기기 상태를 표시할 수 없어 목록의 요약 정보를 열었어요.",
            statusTone: presentedDashboard ? "success" : "warning",
          };
        });
      });
    },
    [patchState, runAction],
  );

  const removeGuardianWard = useCallback(
    (linkId: string) =>
      runAction(`guardian-ward:remove:${linkId}`, async () => {
        const guardianUser = stateRef.current.guardianUser;
        if (!guardianUser) {
          patchState({
            statusMessage: "보호자 Google 로그인이 먼저 필요합니다.",
            statusTone: "warning",
          });
          return;
        }
        const previousWards = stateRef.current.guardianWards;
        const previousWardIndex = previousWards.findIndex((ward) => ward.link_id === linkId);
        const previousWard = previousWards[previousWardIndex];
        await homeGuardianApi.removeGuardianWard(guardianUser.user_id, linkId);
        const wards = await homeGuardianApi.getGuardianWards(guardianUser.user_id);
        const selectedWasRemoved = stateRef.current.selectedGuardianWardId === linkId;
        const dashboardWasRemoved = stateRef.current.guardianDashboard?.ward?.link_id === linkId;
        patchState({
          guardianWards: wards.items,
          selectedGuardianWardId: selectedWasRemoved ? wards.items[0]?.link_id ?? null : stateRef.current.selectedGuardianWardId,
          guardianDashboard: dashboardWasRemoved ? null : stateRef.current.guardianDashboard,
          statusMessage: `${previousWard ? guardianWardTitle(previousWard, previousWardIndex, previousWards) : "피보호자"} 연결을 삭제했어요. 다시 보려면 사용자가 새 초대를 만들어야 합니다.`,
          statusTone: "success",
        });
      }),
    [patchState, runAction],
  );

  const updateGuardianWardAlias = useCallback(
    (linkId: string, wardAlias: string) =>
      runAction(`guardian-ward:alias:${linkId}`, async () => {
        const guardianUser = stateRef.current.guardianUser;
        if (!guardianUser) {
          patchState({
            statusMessage: "보호자 Google 로그인이 먼저 필요합니다.",
            statusTone: "warning",
          });
          return;
        }
        const normalizedAlias = wardAlias.trim();
        const updatedWard = await homeGuardianApi.updateGuardianWardAlias(
          guardianUser.user_id,
          linkId,
          normalizedAlias || null,
        );
        const previousWards = stateRef.current.guardianWards;
        const updatedWards = previousWards.map((ward) => (ward.link_id === updatedWard.link_id ? updatedWard : ward));
        const updatedIndex = Math.max(
          0,
          updatedWards.findIndex((ward) => ward.link_id === updatedWard.link_id),
        );
        patchState({
          guardianWards: updatedWards,
          guardianDashboard:
            stateRef.current.guardianDashboard?.ward?.link_id === updatedWard.link_id
              ? { ...stateRef.current.guardianDashboard, ward: updatedWard }
              : stateRef.current.guardianDashboard,
          statusMessage: normalizedAlias
            ? `${guardianWardTitle(updatedWard, updatedIndex, updatedWards)} 이름으로 표시합니다.`
            : "계정 이름으로 다시 표시합니다.",
          statusTone: "success",
        });
      }),
    [patchState, runAction],
  );

  const enterGuardianMode = useCallback(() => {
    const guardianUser = stateRef.current.guardianUser;
    setState((current) => ({
      ...current,
      screen: "guardianMode",
      history:
        current.screen === "guardianMode"
          ? current.history
          : [...current.history, current.screen],
      guardianDashboard: guardianUser ? current.guardianDashboard : null,
      statusMessage: guardianUser
        ? "보호자 계정으로 들어갑니다."
        : "보호자 Google 로그인을 먼저 진행해 주세요.",
      statusTone: "info",
    }));
    if (guardianUser) {
      void loadGuardianWards();
    }
  }, [loadGuardianWards]);

  const exitGuardianMode = useCallback(() => {
    setState((current) => ({
      ...current,
      screen: LOGIN_SCREEN,
      history: [],
      guardianDashboard: null,
      guardianModeInviteCode: "",
    }));
  }, []);

  const openGuardianInviteLink = useCallback((inviteInput: string) => {
    const inviteCode = parseGuardianInviteInput(inviteInput);
    if (!inviteCode) return;
    setState((current) => ({
      ...current,
      screen: "guardianMode",
      history: [],
      guardianDashboard: null,
      guardianModeInviteCode: inviteCode,
      statusMessage: "초대 링크에서 코드를 불러왔어요. 아래 버튼만 누르면 확인합니다.",
      statusTone: "success",
    }));
  }, []);

  const clearGuardianDashboard = useCallback(() => {
    if (stateRef.current.guardianUser) {
      patchState({
        guardianDashboard: null,
        selectedGuardianWardId: null,
        guardianModeInviteCode: "",
        statusMessage: "내가 보는 사람들 목록으로 돌아왔어요.",
        statusTone: "info",
      });
      return;
    }
    patchState({
      guardianDashboard: null,
      guardianModeInviteCode: "",
      statusMessage: "보호자 Google 로그인을 먼저 진행해 주세요.",
      statusTone: "info",
    });
  }, [patchState]);

  const setAutoScanEnabled = useCallback(
    async (enabled: boolean) => {
      if (enabled) {
        const granted = await requestNotificationsPermission();
        if (!granted) {
          patchState({
            autoScanEnabled: false,
            statusMessage: "알림 권한이 없어 정기 점검 알림을 켜지 못했습니다.",
            statusTone: "warning",
          });
          await storageSet(StorageKeys.autoScanEnabled, false);
          await unregisterAutoScan();
          return;
        }
      }

      patchState({
        autoScanEnabled: enabled,
        statusMessage: enabled
          ? "정해진 시간마다 점검하라고 알려드릴게요."
          : "정기 점검 알림을 껐어요. 필요할 때 직접 검사하면 돼요.",
        statusTone: enabled ? "success" : "info",
      });
      await storageSet(StorageKeys.autoScanEnabled, enabled);
      if (!enabled) {
        await unregisterAutoScan();
        return;
      }
      // 켜면 현재 저장된 주기로 등록 시도. 실패해도(미설치 등) 다음에 다시 시도.
      const hours = (await storageGet<number>(StorageKeys.autoScanIntervalHours)) ?? 24;
      await registerAutoScan(hours);
    },
    [patchState],
  );

  const actions: HomeGuardianActions = {
    setScreen,
    navigate,
    goBack,
    setGuardianEmail,
    setApiBaseUrl,
    loginWithGoogle,
    logout,
    startScan,
    beginNetworkScan,
    retryScan,
    shareScanWithGuardian,
    openDevice,
    renameDevice,
    inviteGuardian,
    revokeGuardianInvite,
    deleteGuardianInvite,
    markNotificationRead,
    setNotificationsEnabled,
    setAutoScanEnabled,
    setAutoScanIntervalHours,
    enterGuardianMode,
    exitGuardianMode,
    loginAsGuardianWithGoogle,
    loadGuardianWards,
    acceptGuardianInvite,
    openGuardianWard,
    updateGuardianWardAlias,
    removeGuardianWard,
    openGuardianInviteLink,
    clearGuardianDashboard,
  };

  return {
    state,
    actions,
  };
}

function toStoredAuthSession(user: User, tokens: SessionTokens): StoredAuthSession {
  const role = user.role === "guardian" ? "guardian" : "user";
  if (!tokens.access_token || !tokens.refresh_token || !user.user_id) {
    throw new HomeGuardianApiError("로그인 정보를 다시 확인해 주세요.", "AUTH_SESSION_INVALID");
  }
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    role,
    userId: user.user_id,
    expiresAt: Date.now() + Math.max(1, Number(tokens.expires_in) || 0) * 1000,
  };
}

async function persistRefreshAttempt(session: StoredAuthSession): Promise<StoredAuthSession> {
  if (session.refreshAttemptId) return session;
  const pendingSession: StoredAuthSession = {
    ...session,
    refreshAttemptId: createRefreshAttemptId(),
  };
  // This must complete before sending refresh: otherwise an app termination
  // after the server commit would lose the idempotency key needed to recover.
  await secureStorageSetRequired(SecureStorageKeys.authSession, JSON.stringify(pendingSession));
  return pendingSession;
}

function createRefreshAttemptId() {
  // This is an idempotency key, not authentication material. The refresh token
  // remains the secret and the server additionally binds the retry to its hash.
  return `refresh-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function parseStoredAuthSession(value: string | null): StoredAuthSession | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<StoredAuthSession>;
    if (
      (parsed.role !== "user" && parsed.role !== "guardian") ||
      typeof parsed.accessToken !== "string" ||
      typeof parsed.refreshToken !== "string" ||
      typeof parsed.userId !== "string" ||
      !parsed.accessToken ||
      !parsed.refreshToken ||
      !parsed.userId
    ) {
      return null;
    }
    return {
      accessToken: parsed.accessToken,
      refreshToken: parsed.refreshToken,
      role: parsed.role,
      userId: parsed.userId,
      // v0.x sessions are still refreshed before use and are upgraded atomically after
      // verification. They must not be treated as a valid unexpired access token on their own.
      expiresAt: typeof parsed.expiresAt === "number" && Number.isFinite(parsed.expiresAt) ? parsed.expiresAt : 0,
      refreshAttemptId:
        typeof parsed.refreshAttemptId === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(parsed.refreshAttemptId)
          ? parsed.refreshAttemptId
          : undefined,
    };
  } catch {
    return null;
  }
}

function createStoredAuthHandoff(
  previousSession: StoredAuthSession,
  successorSession: StoredAuthSession,
  handoff: AuthHandoff | undefined,
): StoredAuthHandoff {
  if (!handoff || !/^[A-Za-z0-9_-]{32,128}$/.test(handoff.id) || !handoff.expires_at) {
    throw new HomeGuardianApiError("로그인 전환 정보를 다시 확인해 주세요.", "AUTH_HANDOFF_INVALID");
  }
  return {
    previousSession,
    successorSession,
    handoffId: handoff.id,
    expiresAt: handoff.expires_at,
  };
}

function parseStoredAuthHandoff(value: string | null): StoredAuthHandoff | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<StoredAuthHandoff>;
    const previousSession = parseStoredAuthSession(JSON.stringify(parsed.previousSession));
    const successorSession = parseStoredAuthSession(JSON.stringify(parsed.successorSession));
    if (
      !previousSession ||
      !successorSession ||
      typeof parsed.handoffId !== "string" ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(parsed.handoffId) ||
      typeof parsed.expiresAt !== "string" ||
      !parsed.expiresAt
    ) {
      return null;
    }
    return {
      previousSession,
      successorSession,
      handoffId: parsed.handoffId,
      expiresAt: parsed.expiresAt,
    };
  } catch {
    return null;
  }
}

function parsePendingLogout(value: string | null): PendingLogout | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value) as Partial<PendingLogout>;
    // The backend rejects malformed values. Here we only reject an absent
    // record so a previously persisted logout retry is never silently dropped
    // by a future client that changes token length/encoding.
    if (typeof parsed.refreshToken !== "string" || !parsed.refreshToken) return null;
    return {
      refreshToken: parsed.refreshToken,
      createdAt: typeof parsed.createdAt === "number" && Number.isFinite(parsed.createdAt) ? parsed.createdAt : 0,
    };
  } catch {
    return null;
  }
}

async function completeStoredAuthHandoff(pending: StoredAuthHandoff): Promise<StoredAuthSession> {
  const completed = await homeGuardianApi.completeAuthHandoff({
    previousRefreshToken: pending.previousSession.refreshToken,
    successorRefreshToken: pending.successorSession.refreshToken,
    handoffId: pending.handoffId,
  });
  const nextSession = toStoredAuthSession(completed.user, completed);
  if (
    nextSession.role !== pending.successorSession.role ||
    nextSession.userId !== pending.successorSession.userId ||
    nextSession.refreshToken !== pending.successorSession.refreshToken
  ) {
    throw new HomeGuardianApiError("로그인 전환 정보를 다시 확인해 주세요.", "AUTH_HANDOFF_INVALID");
  }
  return nextSession;
}

function isTerminalHandoffError(error: unknown) {
  return error instanceof HomeGuardianApiError && ["AUTH_HANDOFF_INVALID", "AUTH_HANDOFF_PREDECESSOR_INVALID"].includes(error.code);
}

function isTerminalAuthError(error: unknown) {
  if (!(error instanceof HomeGuardianApiError)) return false;
  return ["AUTH_SESSION_INVALID", "AUTH_REQUIRED", "GUARDIAN_AUTH_REQUIRED"].includes(error.code);
}

function friendlyErrorMessage(error: unknown) {
  if (!(error instanceof HomeGuardianApiError)) {
    return "처리하지 못했어요. 잠시 후 다시 시도해 주세요.";
  }

  if (["AUTH_SESSION_INVALID", "AUTH_REQUIRED", "GUARDIAN_AUTH_REQUIRED"].includes(error.code)) {
    return "로그인 정보를 다시 확인해 주세요.";
  }
  if (error.code === "NETWORK_UNREACHABLE") {
    return "지금 연결할 수 없어요. 와이파이를 확인한 뒤 잠시 후 다시 시도해 주세요.";
  }
  if (["GUARDIAN_SESSION_INVALID", "GUARDIAN_INVITE_REVOKED", "GUARDIAN_INVITE_EXPIRED"].includes(error.code)) {
    return "보호자 연결을 더 이상 사용할 수 없어요.";
  }
  return "처리하지 못했어요. 잠시 후 다시 시도해 주세요.";
}

function friendlyScanSaveFailureMessage(error: unknown) {
  if (!(error instanceof HomeGuardianApiError)) {
    return "검사 결과를 저장하지 못했어요. 잠시 후 다시 시도해 주세요.";
  }
  if (error.code === "NETWORK_UNREACHABLE") {
    return "검사는 끝났지만 결과를 서버에 보내지 못했어요. 와이파이를 확인한 뒤 다시 시도해 주세요.";
  }
  if (error.code === "AUTH_SESSION_INVALID" || error.code === "AUTH_REQUIRED") {
    return "검사는 끝났지만 로그인 확인이 필요해요. 다시 로그인한 뒤 점검해 주세요.";
  }
  if (error.code === "SCAN_ACTUAL_DEVICE_REQUIRED") {
    return "실제 집 Wi-Fi에서 확인된 검사만 저장할 수 있어요. 휴대폰이 집 Wi-Fi에 연결되어 있는지 확인해 주세요.";
  }
  if (error.code === "INPUT_CHECK_REQUIRED") {
    return "검사 데이터 형식을 확인하지 못했어요. 앱과 서버를 함께 최신 버전으로 업데이트해 주세요.";
  }
  if (error.code === "SERVER_VERSION_MISMATCH") {
    return "앱과 검사 서버의 버전이 맞지 않아요. 관리자에게 서버를 최신 버전으로 업데이트해 달라고 알려 주세요.";
  }
  if (error.code === "INTERNAL_ERROR") {
    return "검사는 끝났지만 서버가 결과를 저장하지 못했어요. 잠시 후 다시 시도해 주세요.";
  }
  return "검사는 끝났지만 결과를 저장하지 못했어요. 잠시 후 다시 시도해 주세요.";
}

function toGuardianUser(user: User): User {
  const rawId = String(user.user_id || user.email || "guardian");
  return {
    ...user,
    user_id: rawId.startsWith("guardian-") ? rawId : `guardian-${rawId}`,
    role: "guardian",
    home_id: "",
  };
}

function initialScanUi(): ScanUiState {
  return {
    progress: 0,
    steps: [
      { key: "wifi", title: "와이파이 확인", detail: "같은 공유기 와이파이에 연결되어 있는지 확인합니다.", state: "pending" },
      { key: "discovery", title: "물건 확인", detail: "집에 연결된 물건을 찾습니다.", state: "pending" },
      { key: "services", title: "상태 확인", detail: "물건별 연결 상태를 확인합니다.", state: "pending" },
      { key: "analysis", title: "안전 확인", detail: "안전 상태를 점수와 쉬운 안내로 정리합니다.", state: "pending" },
      { key: "guardian", title: "결과 정리", detail: "보호자가 이해할 수 있는 요약을 준비합니다.", state: "pending" },
    ],
    errorCode: null,
    errorMessage: null,
    nativeMessage: null,
    networkContext: null,
    sourceLabel: "대기 중",
    coverageComplete: null,
    tcpScanTimedOut: false,
    identityResearchPending: false,
    confirmedRedRisk: false,
  };
}

function updateScanStep(scanUi: ScanUiState, key: ScanStepKey, state: ScanStepState, progress: number, detail: string): ScanUiState {
  return {
    ...scanUi,
    progress,
    steps: scanUi.steps.map((step) => (step.key === key ? { ...step, state, detail } : step)),
  };
}

function completeStepsUntil(key: ScanStepKey, detail: string): ScanUiState {
  const order: ScanStepKey[] = ["wifi", "discovery", "services", "analysis", "guardian"];
  const index = order.indexOf(key);
  const scanUi = initialScanUi();
  return {
    ...scanUi,
    progress: Math.max(20, (index + 1) * 18),
    steps: scanUi.steps.map((step) => {
      const stepIndex = order.indexOf(step.key);
      if (stepIndex < index) {
        return { ...step, state: "completed" };
      }
      if (stepIndex === index) {
        return { ...step, state: "completed", detail };
      }
      return step;
    }),
  };
}

function sourceLabel(scanSource?: string) {
  if (scanSource === "android-native") {
    return "휴대폰으로 검사";
  }
  return "연결 확인";
}

function friendlyScanFailureMessage(errorCode?: string) {
  if (errorCode === "SCAN_PERMISSION_DENIED") {
    return "검사에 필요한 권한을 허용해 주세요. 휴대폰 설정에서 와이파이 권한을 켠 뒤 다시 검사해 주세요.";
  }
  if (errorCode === "SCAN_ACTUAL_DEVICE_REQUIRED" || errorCode === "NATIVE_SCANNER_UNAVAILABLE") {
    return "이 휴대폰에서 검사를 준비하지 못했어요. 우리 집 와이파이에 연결한 뒤 다시 검사해 주세요.";
  }
  return "검사를 끝내지 못했어요. 우리 집 와이파이를 확인한 뒤 다시 검사해 주세요.";
}

function wait(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function failedScanUi(scanUi: ScanUiState, message: string, errorCode = "SCAN_FLOW_FAILED"): ScanUiState {
  return {
    ...scanUi,
    progress: Math.max(scanUi.progress, 40),
    errorCode,
    errorMessage: message,
    steps: scanUi.steps.map((step) => (step.state === "running" ? { ...step, state: "failed", detail: message } : step)),
  };
}
