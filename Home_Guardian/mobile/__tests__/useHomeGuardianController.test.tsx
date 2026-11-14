import { act, useEffect, type ReactElement } from "react";
import { Text } from "react-native";

type TestRenderer = { unmount: () => void };
const ReactTestRenderer = require("react-test-renderer") as {
  create: (element: ReactElement) => TestRenderer;
};

const mockAsyncValues = (
  globalThis as typeof globalThis & {
    __HOME_GUARDIAN_ASYNC_STORAGE_MOCK__: { values: Map<string, string> };
  }
).__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.values;
const mockSecureValues = new Map<string, string>();
const mockPromptSignIn = jest.fn();
const mockScanHomeNetwork = jest.fn();
const mockNotifyScanCompleted = jest.fn();
let mockSecureDeleteFailureKey: string | null = null;

jest.mock("expo-secure-store", () => ({
  getItemAsync: jest.fn(async (key: string) => mockSecureValues.get(key) ?? null),
  setItemAsync: jest.fn(async (key: string, value: string) => {
    mockSecureValues.set(key, value);
  }),
  deleteItemAsync: jest.fn(async (key: string) => {
    if (key === mockSecureDeleteFailureKey) {
      throw new Error("secure delete failed");
    }
    mockSecureValues.delete(key);
  }),
}));

jest.mock("../src/hooks/useGoogleSignIn", () => ({
  useGoogleSignIn: () => ({
    promptSignIn: mockPromptSignIn,
    isReady: true,
  }),
}));

jest.mock("../src/native/homeGuardianNetworkScanner", () => ({
  scanHomeNetwork: (...args: unknown[]) => mockScanHomeNetwork(...args),
}));

jest.mock("../src/services/notifications", () => ({
  addDevicePushTokenListener: jest.fn(() => () => undefined),
  getDevicePushToken: jest.fn(async () => null),
  notifyScanCompleted: (...args: unknown[]) => mockNotifyScanCompleted(...args),
  requestNotificationsPermission: jest.fn(async () => false),
}));

import { HomeGuardianApiError, homeGuardianApi } from "../src/api/homeGuardianApi";
import type { AuthSessionResult, Device, GuardianDashboard, GuardianWard, SessionTokens, User } from "../src/api/types";
import {
  STORAGE_SCHEMA_VERSION,
  SecureStorageKeys,
  StorageKeys,
  secureStorageClear,
  secureStorageGet,
  secureStorageSet,
  storageClear,
  storageSet,
} from "../src/state/storage";
import { useHomeGuardianController } from "../src/state/useHomeGuardianController";

type Controller = ReturnType<typeof useHomeGuardianController>;

const user: User = {
  user_id: "user-1",
  email: "user@example.test",
  nickname: "사용자",
  role: "user",
  email_verified: true,
  home_id: "home-1",
};

const guardian: User = {
  user_id: "guardian-1",
  email: "guardian@example.test",
  nickname: "보호자",
  role: "guardian",
  email_verified: true,
  home_id: "",
};

const ward: GuardianWard = {
  link_id: "ward-link-1",
  guardian_id: guardian.user_id,
  invite_id: "invite-1",
  home_id: "home-1",
  ward_display_name: "사용자",
  status: "active",
};

const guardianDashboard: GuardianDashboard = {
  invite: {
    invite_id: "invite-1",
    email: user.email,
    relation: "보호자",
    status: "accepted",
  },
  ward,
  ward_summary: {
    score: 90,
    risk_level: "green",
    device_count: 0,
    high_risk_devices: 0,
    caution_devices: 0,
    unread_notifications: 0,
  },
  high_risk_devices: [],
  caution_devices: [],
  recent_notifications: [],
  read_only: true,
  scope: "guardian",
};

function sessionTokens(prefix: string): SessionTokens {
  return {
    access_token: `${prefix}-access`,
    refresh_token: `${prefix}-refresh`,
    token_type: "Bearer",
    expires_in: 900,
  };
}

function stagedHandoff(prefix: string) {
  return {
    id: `handoff-${prefix}-id-abcdefghijklmnopqrstuvwxyz0123456789`,
    expires_at: "2099-01-01T00:10:00Z",
  };
}

function storedSession(role: "user" | "guardian", principal: User, prefix: string) {
  return JSON.stringify({
    accessToken: `${prefix}-old-access`,
    refreshToken: `${prefix}-old-refresh`,
    role,
    userId: principal.user_id,
    expiresAt: Date.now() + 60_000,
  });
}

function sessionResult(principal: User): AuthSessionResult {
  return { user: principal, role: principal.role as "user" | "guardian" };
}

function verifiedDevice(overrides: Partial<Device> = {}): Device {
  return {
    device_id: "verified-device",
    name: "ipTIME 공유기 (A3004NS-M)",
    canonical_name: "ipTIME 공유기 (A3004NS-M)",
    device_type: "router",
    manufacturer: "ipTIME",
    model: "A3004NS-M",
    ip_address: "",
    mac_address: "",
    online: true,
    last_seen: "2026-08-21T00:00:00Z",
    open_ports: [],
    services: [],
    default_credentials: false,
    encryption: "",
    firmware: "",
    vulnerabilities: [],
    discovery_sources: [],
    fingerprints: [],
    risk_signals: [],
    scan_source: "",
    confidence: 1,
    security_score: 90,
    risk_level: "green",
    risk_summary: "",
    recommended_actions: [],
    identity_status: "resolved",
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function ControllerProbe({ onUpdate }: { onUpdate: (controller: Controller) => void }) {
  const controller = useHomeGuardianController();
  useEffect(() => {
    onUpdate(controller);
  }, [controller, onUpdate]);
  return <Text testID="controller-screen">{controller.state.screen}</Text>;
}

async function seedSession(role: "user" | "guardian", principal: User, prefix: string) {
  await secureStorageSet(SecureStorageKeys.authSession, storedSession(role, principal, prefix));
}

function renderController() {
  let latest: Controller | null = null;
  let rendered: TestRenderer | null = null;
  act(() => {
    rendered = ReactTestRenderer.create(<ControllerProbe onUpdate={(controller) => (latest = controller)} />);
  });
  return { rendered: rendered!, latest: () => latest };
}

async function waitForHydration(getController: () => Controller | null) {
  await waitForState(() => getController()?.state.isHydrated === true);
}

async function waitForState(predicate: () => boolean) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (predicate()) return;
    await act(async () => {
      await Promise.resolve();
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    });
  }
  expect(predicate()).toBe(true);
}

async function waitForStorageRemoval(key: string) {
  await waitForState(() => !mockAsyncValues.has(key));
}

function unmountController(probe: { rendered: TestRenderer }) {
  act(() => {
    probe.rendered.unmount();
  });
}

describe("사용자와 보호자 세션 복원", () => {
  beforeEach(async () => {
    mockAsyncValues.clear();
    mockSecureValues.clear();
    mockPromptSignIn.mockReset();
    mockScanHomeNetwork.mockReset();
    mockNotifyScanCompleted.mockReset();
    mockSecureDeleteFailureKey = null;
    await storageClear();
    await secureStorageClear();
    await storageSet(StorageKeys.schemaVersion, STORAGE_SCHEMA_VERSION);
    jest.restoreAllMocks();

    jest.spyOn(homeGuardianApi, "setBaseUrl").mockImplementation(() => undefined);
    jest.spyOn(homeGuardianApi, "setAuthToken").mockImplementation(() => undefined);
    jest.spyOn(homeGuardianApi, "clearAuthToken").mockImplementation(() => undefined);
    jest.spyOn(homeGuardianApi, "setRefreshHandler").mockImplementation(() => undefined);
    jest.spyOn(homeGuardianApi, "getDashboard").mockResolvedValue({
      home: { home_id: user.home_id, name: "우리 집", mode: "home", security_score: null, device_count: 0 },
      summary: { score: null, risk_level: "unknown", online_devices: 0, high_risk_devices: 0, recent_event_count: 0 },
      top_risks: [],
    });
    jest.spyOn(homeGuardianApi, "getDevices").mockResolvedValue({ items: [], total: 0 });
    jest.spyOn(homeGuardianApi, "getNotifications").mockResolvedValue({ items: [], total: 0, unread: 0 });
    jest.spyOn(homeGuardianApi, "getGuardians").mockResolvedValue({ items: [], total: 0 });
    jest.spyOn(homeGuardianApi, "getGuardianWards").mockResolvedValue({ items: [ward], total: 1 });
    jest.spyOn(homeGuardianApi, "getGuardianWardDashboard").mockResolvedValue(guardianDashboard);
    jest.spyOn(homeGuardianApi, "logoutAuthSession").mockResolvedValue({ revoked: true });
    jest.spyOn(homeGuardianApi, "deleteFcmToken").mockResolvedValue(undefined);
    jest.spyOn(homeGuardianApi, "completeAuthHandoff").mockImplementation(async ({ successorRefreshToken }) => ({
      ...sessionTokens("completed"),
      refresh_token: successorRefreshToken,
      user: successorRefreshToken.includes("guardian") ? guardian : user,
    }));
  });

  afterEach(async () => {
    await storageClear();
    await secureStorageClear();
    jest.restoreAllMocks();
  });

  it("사용자 로그인은 앱 재실행 때 refresh와 서버 역할 확인 후 사용자 화면으로 복원한다", async () => {
    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));

    const probe = renderController();
    await waitForHydration(probe.latest);

    expect(probe.latest()?.state.screen).toBe("scanResult");
    expect(probe.latest()?.state.user).toEqual(user);
    expect(probe.latest()?.state.guardianUser).toBeNull();
    expect(homeGuardianApi.refreshAuthSession).toHaveBeenCalledWith(
      "user-old-refresh",
      expect.stringMatching(/^[A-Za-z0-9_-]{16,128}$/),
    );
    expect(homeGuardianApi.getAuthSession).toHaveBeenCalledTimes(1);
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("renewed-user-refresh");
    unmountController(probe);
  });

  it("서버 홈 갱신에서 확정 제품과 같은 ID의 관측 및 generic 연결을 중복 병합하지 않는다", async () => {
    const resolved = verifiedDevice({ device_id: "same-public-id" });
    const duplicateClue = {
      device_id: resolved.device_id,
      display_name: resolved.canonical_name,
      name: resolved.canonical_name,
      manufacturer: resolved.manufacturer,
      model: resolved.model,
      device_type: resolved.device_type,
      identity_status: "unresolved",
      identity_note: "서버가 제품 단서를 확인하고 있어요.",
      identity_candidates: [],
      identity_evidence: ["기기가 보낸 식별 정보"],
      product_clue_verified: true,
      online: true,
      last_seen: resolved.last_seen,
      risk_level: "yellow",
      risk_summary: "",
      detected: true,
      is_identity_finding: true,
    };
    const generic = {
      ...duplicateClue,
      device_id: "generic-connection",
      display_name: "연결된 장비",
      name: "연결된 장비",
      manufacturer: "",
      model: "",
      device_type: "network",
      product_clue_verified: false,
    };

    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    (homeGuardianApi.getDevices as jest.MockedFunction<typeof homeGuardianApi.getDevices>).mockResolvedValue({
      items: [resolved],
      detected_connections: [duplicateClue, generic],
      total: 3,
    } as never);

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(() => probe.latest()?.state.devices.length === 1);

    expect(probe.latest()?.state.devices).toEqual([
      expect.objectContaining({
        device_id: resolved.device_id,
        identity_status: "resolved",
        name: resolved.name,
      }),
    ]);
    expect(JSON.stringify(probe.latest()?.state.devices)).not.toContain("연결된 장비");
    unmountController(probe);
  });

  it("다시 점검하기 뒤 Android 뒤로가기는 앱 종료 대신 직전 결과 화면으로 돌아간다", async () => {
    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));

    const probe = renderController();
    await waitForHydration(probe.latest);
    expect(probe.latest()?.state.screen).toBe("scanResult");

    await act(async () => {
      probe.latest()?.actions.retryScan();
    });
    expect(probe.latest()?.state.screen).toBe("scanConsent");
    expect(probe.latest()?.state.history).toEqual(["scanResult"]);

    let handled = false;
    await act(async () => {
      handled = probe.latest()?.actions.goBack() ?? false;
    });
    expect(handled).toBe(true);
    expect(probe.latest()?.state.screen).toBe("scanResult");
    expect(probe.latest()?.state.history).toEqual([]);
    unmountController(probe);
  });

  it("하단 탭 이동도 이전 탭을 history에 남겨 뒤로가기로 복원한다", async () => {
    const probe = renderController();
    await waitForHydration(probe.latest);

    act(() => {
      probe.latest()?.actions.setScreen("scanResult");
      probe.latest()?.actions.navigate("devices");
    });
    expect(probe.latest()?.state.screen).toBe("devices");
    expect(probe.latest()?.state.history).toEqual(["scanResult"]);

    let handled = false;
    act(() => {
      handled = probe.latest()?.actions.goBack() ?? false;
    });
    expect(handled).toBe(true);
    expect(probe.latest()?.state.screen).toBe("scanResult");
    unmountController(probe);
  });

  it("로그인 화면에서 보호자 보기로 들어가도 하드웨어 뒤로가기는 로그인으로 돌아온다", async () => {
    const probe = renderController();
    await waitForHydration(probe.latest);
    expect(probe.latest()?.state.screen).toBe("login");

    act(() => {
      probe.latest()?.actions.enterGuardianMode();
    });
    expect(probe.latest()?.state.screen).toBe("guardianMode");
    expect(probe.latest()?.state.history).toEqual(["login"]);

    let handled = false;
    act(() => {
      handled = probe.latest()?.actions.goBack() ?? false;
    });
    expect(handled).toBe(true);
    expect(probe.latest()?.state.screen).toBe("login");
    unmountController(probe);
  });

  it("스키마가 바뀌면 provenance 없는 legacy 제품 캐시를 버리고 계정과 설정만 보존한다", async () => {
    const plausibleButUntrustedDevice = verifiedDevice({
      device_id: "legacy-plausible-fake",
      name: "가짜브랜드 공기청정기 (FAKE-1)",
      canonical_name: "가짜브랜드 공기청정기 (FAKE-1)",
      device_type: "air-purifier",
      manufacturer: "가짜브랜드",
      model: "FAKE-1",
      identity_status: "resolved",
    });

    await seedSession("user", user, "user");
    await Promise.all([
      storageSet(StorageKeys.schemaVersion, STORAGE_SCHEMA_VERSION - 1),
      storageSet(StorageKeys.user, user),
      storageSet(StorageKeys.devices, [plausibleButUntrustedDevice]),
      storageSet(StorageKeys.scanResult, {
        scan_id: "legacy-fake-scan",
        status: "completed",
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 1,
        high_risk_devices: 0,
        scan_profile: "standard",
        devices: [plausibleButUntrustedDevice],
        security_score: { score: 100, risk_level: "green" },
      }),
      storageSet(StorageKeys.notifications, [
        {
          notification_id: "legacy-product-notice",
          type: "security",
          title: plausibleButUntrustedDevice.name,
          message: "안전합니다.",
          read: false,
          created_at: "2026-08-20T00:00:00Z",
        },
      ]),
      storageSet(StorageKeys.lastScanAt, "2026-08-20T00:00:00Z"),
      storageSet(StorageKeys.themePreference, "dark"),
      storageSet(StorageKeys.autoScanEnabled, true),
      storageSet(StorageKeys.guardianWards, [
        {
          ...ward,
          summary: {
            score: 100,
            risk_level: "green",
            device_count: 1,
            high_risk_devices: 0,
            caution_devices: 0,
            unread_notifications: 0,
          },
        },
      ]),
    ]);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(
      () =>
        probe.latest()?.state.devices.length === 0 &&
        probe.latest()?.state.scanResult === null &&
        !mockAsyncValues.has(StorageKeys.devices) &&
        !mockAsyncValues.has(StorageKeys.scanResult),
    );

    expect(probe.latest()?.state.user).toEqual(user);
    expect(probe.latest()?.state.devices).toEqual([]);
    expect(probe.latest()?.state.notifications).toEqual([]);
    expect(probe.latest()?.state.lastScanAt).toBeNull();
    expect(mockAsyncValues.get(StorageKeys.user)).toContain(user.user_id);
    expect(mockAsyncValues.get(StorageKeys.themePreference)).toBe(JSON.stringify("dark"));
    expect(mockAsyncValues.get(StorageKeys.autoScanEnabled)).toBe(JSON.stringify(true));
    expect(mockAsyncValues.get(StorageKeys.notifications)).toBeUndefined();
    expect(mockAsyncValues.get(StorageKeys.lastScanAt)).toBeUndefined();
    expect(mockAsyncValues.get(StorageKeys.schemaVersion)).toBe(JSON.stringify(STORAGE_SCHEMA_VERSION));
    expect(JSON.parse(mockAsyncValues.get(StorageKeys.guardianWards) ?? "[]")[0]).not.toHaveProperty("summary");
    expect(JSON.stringify([...mockAsyncValues.values()])).not.toContain(plausibleButUntrustedDevice.name);
    unmountController(probe);
  });

  it("다른 Wi-Fi의 부분 점검은 이전 Wi-Fi 기기를 상태와 AsyncStorage에서 제거한다", async () => {
    const wifiADevice = verifiedDevice({
      device_id: "wifi-a-fridge",
      name: "삼성 냉장고 (RF85C90F1AP)",
      canonical_name: "삼성 냉장고 (RF85C90F1AP)",
      device_type: "refrigerator",
      manufacturer: "삼성",
      model: "RF85C90F1AP",
    });
    const wifiBDevice = verifiedDevice({ device_id: "wifi-b-router" });

    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    (homeGuardianApi.getDevices as jest.MockedFunction<typeof homeGuardianApi.getDevices>).mockResolvedValue({
      items: [wifiADevice],
      total: 1,
    });
    mockScanHomeNetwork.mockResolvedValue({
      scan_profile: "quick",
      scan_source: "android-native",
      network_context: {
        ssid: "wifi-b",
        bssid: "22:33:44:55:66:77",
        local_ip: "192.168.20.10",
        gateway_ip: "192.168.20.1",
        subnet_cidr: "192.168.20.0/24",
        is_private_network: true,
        interface_type: "wifi",
        scan_diagnostics: { coverage_complete: false, scan_partial: true },
      },
      devices: [
        {
          ip_address: "192.168.20.1",
          mac_address: "22:33:44:55:66:77",
          online: true,
        },
      ],
      nativeStatus: "completed",
      isActualScan: true,
    });
    jest.spyOn(homeGuardianApi, "startScan").mockResolvedValue({
      scan_id: "wifi-b-partial",
      status: "partial",
      progress: 100,
      scan_source: "android-native",
      current_step: "partial",
      devices_found: 1,
      high_risk_devices: 0,
      scan_complete: false,
      coverage_complete: false,
    });
    jest.spyOn(homeGuardianApi, "getScanResult").mockResolvedValue({
      scan_id: "wifi-b-partial",
      status: "partial",
      progress: 100,
      scan_source: "android-native",
      current_step: "partial",
      devices_found: 1,
      high_risk_devices: 0,
      scan_complete: false,
      coverage_complete: false,
      scan_profile: "quick",
      devices: [wifiBDevice],
      security_score: { score: 74, score_status: "provisional", risk_level: "yellow" },
    });
    jest.mocked(homeGuardianApi.getGuardians).mockResolvedValue({ items: null, total: 0 } as never);

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(() => probe.latest()?.state.devices[0]?.device_id === wifiADevice.device_id);

    act(() => {
      probe.latest()?.actions.beginNetworkScan();
    });
    await act(async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 600));
    });
    await waitForState(
      () => probe.latest()?.state.screen === "scanResult" && probe.latest()?.state.isLoading === false,
    );

    expect(probe.latest()?.state.devices.map((device) => device.device_id)).toEqual([wifiBDevice.device_id]);
    expect(probe.latest()?.state.guardians).toEqual([]);
    expect(probe.latest()?.state.scanResult).toMatchObject({
      status: "partial",
      scan_complete: false,
      coverage_complete: false,
      security_score: { score: 74, score_status: "provisional", risk_level: "yellow" },
    });
    await waitForState(() => {
      const storedDevices = mockAsyncValues.get(StorageKeys.devices) ?? "";
      return storedDevices.includes(wifiBDevice.device_id) && !storedDevices.includes(wifiADevice.device_id);
    });
    unmountController(probe);
  });

  it("generic 연결명은 제외하고 기기 탭에서 숨긴 Wi-Fi 단말은 표시·알림 개수에서 제외한다", async () => {
    const verifiedRouter = verifiedDevice({ device_id: "current-verified-router" });
    const unverifiedObservation = verifiedDevice({
      device_id: "current-unverified-observation",
      name: "가짜브랜드 공기청정기 (FAKE-1)",
      canonical_name: "가짜브랜드 공기청정기 (FAKE-1)",
      device_type: "air-purifier",
      manufacturer: "가짜브랜드",
      model: "FAKE-1",
      identity_status: "unresolved",
      risk_level: "red",
    });
    const detectedConnection = {
      device_id: "current-detected-connection",
      display_name: "컴퓨터 연결",
      name: "컴퓨터 연결",
      device_type: "computer",
      identity_status: "unresolved",
      identity_note: "제품명이 없어도 확인된 연결과 보안 신호를 점수에 반영했어요.",
      identity_evidence: ["컴퓨터 연결 특성"],
      identity_candidates: [],
      online: true,
      last_seen: "2026-08-22T00:00:00Z",
      risk_level: "red",
      risk_summary: "보안 위험 신호가 있어 먼저 확인이 필요해요.",
      detected: true,
      is_identity_finding: true,
    } as never;
    const wifiFallback = {
      device_id: "current-wifi-fallback",
      display_name: "Wi-Fi 단말 · A1B2C3",
      name: "Wi-Fi 단말 · A1B2C3",
      device_type: "network",
      identity_status: "unresolved",
      identity_note: "현재 연결을 확인했어요.",
      identity_evidence: ["기기가 보낸 네트워크 응답"],
      identity_candidates: [],
      presentation_kind: "observed_connection",
      observed_service: "neighbor-presence",
      observed_service_verified: true,
      observation_suffix: "A1B2C3",
      observation_suffix_verified: true,
      online: true,
      last_seen: "2026-08-22T00:00:00Z",
      risk_level: "green",
      risk_summary: "",
      detected: true,
      is_identity_finding: true,
    } as never;

    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    mockScanHomeNetwork.mockResolvedValue({
      scan_profile: "standard",
      scan_source: "android-native",
      network_context: {
        ssid: "current-wifi",
        bssid: "22:33:44:55:66:88",
        local_ip: "192.168.30.10",
        gateway_ip: "192.168.30.1",
        subnet_cidr: "192.168.30.0/24",
        is_private_network: true,
        interface_type: "wifi",
        scan_diagnostics: { coverage_complete: true, scan_partial: false },
      },
      devices: [{ ip_address: "192.168.30.1", mac_address: "22:33:44:55:66:88", online: true }],
      nativeStatus: "completed",
      isActualScan: true,
    });
    jest.spyOn(homeGuardianApi, "startScan").mockResolvedValue({
      scan_id: "identity-review-scan",
      status: "completed",
      progress: 100,
      scan_source: "android-native",
      current_step: "completed",
      devices_found: 2,
      high_risk_devices: 1,
      identified_count: 1,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
      scan_complete: true,
      coverage_complete: true,
    });
    jest.spyOn(homeGuardianApi, "getScanResult").mockResolvedValue({
      scan_id: "identity-review-scan",
      status: "completed",
      progress: 100,
      scan_source: "android-native",
      current_step: "completed",
      devices_found: 2,
      high_risk_devices: 1,
      identified_count: 1,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
      scan_complete: true,
      coverage_complete: true,
      scan_profile: "standard",
      devices: [verifiedRouter, unverifiedObservation],
      detected_connections: [detectedConnection, wifiFallback],
      security_score: { score: 18, risk_level: "red" },
    });

    const probe = renderController();
    await waitForHydration(probe.latest);

    act(() => {
      probe.latest()?.actions.beginNetworkScan();
    });
    await act(async () => {
      await new Promise<void>((resolve) => setTimeout(resolve, 600));
    });
    await waitForState(
      () => probe.latest()?.state.screen === "scanResult" && probe.latest()?.state.isLoading === false,
    );
    await waitForState(() => (mockAsyncValues.get(StorageKeys.scanResult) ?? "").includes("identity-review-scan"));

    expect(probe.latest()?.state.scanResult).toMatchObject({
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      high_risk_devices: 1,
      devices_found: 2,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
      security_score: { score: 18, risk_level: "red" },
    });
    expect(probe.latest()?.state.scanUi).toMatchObject({
      coverageComplete: true,
      identityResearchPending: true,
    });
    expect(probe.latest()?.state.devices.map((device) => device.device_id)).toEqual([
      verifiedRouter.device_id,
      "current-wifi-fallback",
    ]);
    expect(probe.latest()?.state.statusMessage).toBe(
      "점검 완료: 확인된 연결 1대 · 위험 1대",
    );
    expect(mockNotifyScanCompleted).toHaveBeenCalledWith({
      score: 18,
      highRisk: 1,
      caution: 0,
      deviceCount: 1,
    });

    const storedDevices = mockAsyncValues.get(StorageKeys.devices) ?? "";
    const storedScanResult = mockAsyncValues.get(StorageKeys.scanResult) ?? "";
    expect(storedDevices).toContain(verifiedRouter.device_id);
    expect(storedDevices).toContain("current-wifi-fallback");
    expect(storedDevices).not.toContain("current-detected-connection");
    expect(storedDevices).not.toContain(unverifiedObservation.device_id);
    expect(storedScanResult).toContain('"identity_findings":[]');
    expect(storedScanResult).not.toContain("current-detected-connection");
    expect(storedScanResult).not.toContain(unverifiedObservation.device_id);
    expect(storedScanResult).not.toContain(unverifiedObservation.name);
    unmountController(probe);
  });

  it("보호자 로그인은 앱 재실행 때 연결된 피보호자 목록과 읽기 전용 요약을 복원한다", async () => {
    await seedSession("guardian", guardian, "guardian");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-guardian"), user: guardian });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(guardian));

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(() => probe.latest()?.state.guardianDashboard?.ward_summary.score === 90);

    expect(probe.latest()?.state.screen).toBe("guardianMode");
    expect(probe.latest()?.state.user).toBeNull();
    expect(probe.latest()?.state.guardianWards).toEqual([ward]);
    expect(homeGuardianApi.getGuardianWards).toHaveBeenCalledWith(guardian.user_id);
    unmountController(probe);
  });

  it("피보호자 선택은 상세 API가 지연되거나 실패해도 목록 스냅샷의 전체 기기를 즉시 보존한다", async () => {
    const previewGreenDevice = verifiedDevice({
      device_id: "guardian-preview-green",
      name: "삼성 냉장고 (RF85C90F1AP)",
      canonical_name: "삼성 냉장고 (RF85C90F1AP)",
      device_type: "refrigerator",
      manufacturer: "삼성",
      model: "RF85C90F1AP",
      risk_level: "green",
      security_score: 96,
    });
    const previewRedDevice = verifiedDevice({
      device_id: "guardian-preview-red",
      name: "ipTIME 공유기 (AX6000M)",
      canonical_name: "ipTIME 공유기 (AX6000M)",
      device_type: "router",
      manufacturer: "ipTIME",
      model: "AX6000M",
      risk_level: "red",
      security_score: 22,
    });
    const wardWithDeviceSnapshot: GuardianWard = {
      ...ward,
      summary: {
        score: 59,
        risk_level: "red",
        device_count: 2,
        high_risk_devices: 1,
        caution_devices: 0,
        unread_notifications: 0,
      },
      devices: [previewGreenDevice, previewRedDevice],
    };

    await seedSession("guardian", guardian, "guardian");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-guardian"), user: guardian });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(guardian));
    jest.mocked(homeGuardianApi.getGuardianWards).mockResolvedValue({ items: [wardWithDeviceSnapshot], total: 1 });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(() => probe.latest()?.state.guardianDashboard?.ward?.link_id === ward.link_id);
    act(() => {
      probe.latest()?.actions.clearGuardianDashboard();
    });

    const pendingDashboard = deferred<GuardianDashboard>();
    jest.mocked(homeGuardianApi.getGuardianWardDashboard).mockReturnValueOnce(pendingDashboard.promise);
    let openPromise: Promise<void> | undefined;
    act(() => {
      openPromise = probe.latest()?.actions.openGuardianWard(ward.link_id);
    });

    expect(probe.latest()?.state.guardianDashboard?.ward?.link_id).toBe(ward.link_id);
    expect(probe.latest()?.state.guardianDashboard?.read_only).toBe(true);
    expect(probe.latest()?.state.guardianDashboard?.devices?.map((device) => device.device_id)).toEqual([
      previewGreenDevice.device_id,
      previewRedDevice.device_id,
    ]);
    expect(probe.latest()?.state.guardianDashboard?.high_risk_devices.map((device) => device.device_id)).toEqual([
      previewRedDevice.device_id,
    ]);
    expect(probe.latest()?.state.statusMessage).toBe("선택한 피보호자의 기기 상태를 불러오고 있어요.");
    expect(probe.latest()?.state.isLoading).toBe(true);

    await act(async () => {
      pendingDashboard.reject(new HomeGuardianApiError("보호자 진단 연결 실패", "NETWORK_ERROR"));
      await openPromise;
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);
    expect(probe.latest()?.state.guardianDashboard?.devices?.map((device) => device.device_id)).toEqual([
      previewGreenDevice.device_id,
      previewRedDevice.device_id,
    ]);
    expect(probe.latest()?.state.guardianDashboard?.ward_summary.score).toBe(59);
    unmountController(probe);
  });

  it("일시 연결 오류에서는 저장된 사용자 세션과 캐시를 지우지 않고 다시 시도 안내를 남긴다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    await storageSet(StorageKeys.devices, [
      {
        device_id: "device-1",
        name: "삼성 냉장고 (RF85)",
        canonical_name: "삼성 냉장고 (RF85)",
        device_type: "refrigerator",
        manufacturer: "삼성",
        model: "RF85",
        ip_address: "",
        mac_address: "",
        online: true,
        last_seen: "",
        open_ports: [],
        services: [],
        default_credentials: false,
        encryption: "",
        firmware: "",
        vulnerabilities: [],
        discovery_sources: [],
        fingerprints: [],
        risk_signals: [],
        scan_source: "",
        confidence: 1,
        identity_status: "resolved",
        security_score: 90,
        risk_level: "green",
        risk_summary: "",
        recommended_actions: [],
      },
    ]);
    jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockRejectedValue(new HomeGuardianApiError("연결할 수 없습니다.", "NETWORK_UNREACHABLE"));

    const probe = renderController();
    await waitForHydration(probe.latest);

    expect(probe.latest()?.state.screen).toBe("scanResult");
    expect(probe.latest()?.state.authSession?.role).toBe("user");
    expect(probe.latest()?.state.devices.map((device) => device.name)).toEqual(["삼성 냉장고 (RF85)"]);
    expect(probe.latest()?.state.statusMessage).toContain("저장된 화면을 유지");
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("user-old-refresh");
    unmountController(probe);
  });

  it("서버 5xx에서는 저장된 사용자 세션과 캐시를 지우지 않는다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    await storageSet(StorageKeys.guardianEmail, "family@example.test");
    jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockRejectedValue(new HomeGuardianApiError("temporary server error", "INTERNAL_ERROR"));

    const probe = renderController();
    await waitForHydration(probe.latest);

    expect(probe.latest()?.state.screen).toBe("scanResult");
    expect(probe.latest()?.state.authSession?.role).toBe("user");
    expect(probe.latest()?.state.user).toEqual(user);
    expect(probe.latest()?.state.guardianEmail).toBe("family@example.test");
    expect(probe.latest()?.state.statusMessage).toContain("저장된 화면을 유지");
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("user-old-refresh");
    unmountController(probe);
  });

  it("reuses the persisted refresh attempt after a response-loss relaunch", async () => {
    await seedSession("user", user, "user");
    const refresh = jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockRejectedValueOnce(new HomeGuardianApiError("connection lost", "NETWORK_UNREACHABLE"))
      .mockResolvedValueOnce({ ...sessionTokens("recovered-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));

    const firstLaunch = renderController();
    await waitForHydration(firstLaunch.latest);

    const firstAttemptId = refresh.mock.calls[0]?.[1];
    expect(firstAttemptId).toEqual(expect.stringMatching(/^[A-Za-z0-9_-]{16,128}$/));
    const persistedAfterLoss = JSON.parse((await secureStorageGet(SecureStorageKeys.authSession)) ?? "{}") as {
      refreshAttemptId?: string;
    };
    expect(persistedAfterLoss.refreshAttemptId).toBe(firstAttemptId);
    unmountController(firstLaunch);

    const relaunched = renderController();
    await waitForHydration(relaunched.latest);

    expect(refresh).toHaveBeenLastCalledWith("user-old-refresh", firstAttemptId);
    expect(relaunched.latest()?.state.authSession?.refreshToken).toBe("recovered-user-refresh");
    const persistedAfterRecovery = JSON.parse((await secureStorageGet(SecureStorageKeys.authSession)) ?? "{}") as {
      refreshAttemptId?: string;
    };
    expect(persistedAfterRecovery.refreshAttemptId).toBeUndefined();
    unmountController(relaunched);
  });

  it("폐기되었거나 위조된 세션만 로그인 화면으로 이동시키고 SecureStore에서 제거한다", async () => {
    await seedSession("user", user, "user");
    jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockRejectedValue(new HomeGuardianApiError("세션이 끝났습니다.", "AUTH_SESSION_INVALID"));

    const probe = renderController();
    await waitForHydration(probe.latest);

    expect(probe.latest()?.state.screen).toBe("login");
    expect(probe.latest()?.state.authSession).toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
    unmountController(probe);
  });

  it("로그인 라이브러리의 내부 오류 원문은 사용자 화면에 노출하지 않는다", async () => {
    mockPromptSignIn.mockResolvedValue({
      ok: false,
      error: "PKCE code_verifier와 https://internal.example.test를 확인하세요.",
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      probe.latest()?.actions.loginWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);

    expect(probe.latest()?.state.statusMessage).toBe("Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.");
    expect(probe.latest()?.state.statusMessage).not.toContain("PKCE");
    expect(probe.latest()?.state.statusMessage).not.toContain("https://");
    unmountController(probe);
  });

  it("첫 피보호자 로그인은 보호자 목록 응답이 비정상이어도 빈 목록으로 안전하게 홈에 진입한다", async () => {
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user,
      session: { ...sessionTokens("first-user"), user },
    });
    jest.mocked(homeGuardianApi.getGuardians).mockResolvedValueOnce({ items: null, total: 0 } as never);

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      probe.latest()?.actions.loginWithGoogle();
    });
    await waitForState(
      () =>
        probe.latest()?.state.screen === "scanResult" &&
        probe.latest()?.state.user?.user_id === user.user_id &&
        probe.latest()?.state.isLoading === false,
    );

    expect(probe.latest()?.state.guardians).toEqual([]);
    expect(probe.latest()?.state.authSession?.role).toBe("user");
    unmountController(probe);
  });

  it("보호자 전환 검증이 실패하면 기존 사용자 세션과 화면을 보존한다", async () => {
    await seedSession("user", user, "user");
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest
      .spyOn(homeGuardianApi, "getAuthSession")
      .mockResolvedValue(sessionResult(user));
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user,
      session: { ...sessionTokens("unexpected-user"), user },
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      probe.latest()?.actions.loginAsGuardianWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);

    expect(probe.latest()?.state.screen).toBe("scanResult");
    expect(probe.latest()?.state.user).toEqual(user);
    expect(probe.latest()?.state.authSession?.role).toBe("user");
    expect(probe.latest()?.state.statusMessage).toContain("기존 로그인과 저장된 화면은 유지");
    unmountController(probe);
  });

  it("검증된 보호자 전환은 성공 뒤에만 사용자 캐시를 정리하고 보호자 화면으로 바꾼다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest
      .spyOn(homeGuardianApi, "getAuthSession")
      .mockResolvedValueOnce(sessionResult(user))
      .mockResolvedValueOnce(sessionResult(guardian));
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user: guardian,
      session: { ...sessionTokens("guardian"), user: guardian, handoff: stagedHandoff("guardian") },
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      probe.latest()?.actions.loginAsGuardianWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.screen === "guardianMode");

    expect(mockPromptSignIn).toHaveBeenCalledWith("guardian", "renewed-user-refresh");
    expect(probe.latest()?.state.user).toBeNull();
    expect(probe.latest()?.state.guardianUser?.role).toBe("guardian");
    expect(probe.latest()?.state.authSession?.role).toBe("guardian");
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("guardian-refresh");
    await waitForStorageRemoval(StorageKeys.user);
    unmountController(probe);
  });

  it("검증된 사용자 전환은 성공 뒤에만 보호자 캐시를 정리하고 사용자 화면으로 바꾼다", async () => {
    await seedSession("guardian", guardian, "guardian");
    await storageSet(StorageKeys.guardianUser, guardian);
    await storageSet(StorageKeys.guardianWards, [ward]);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-guardian"), user: guardian });
    jest
      .spyOn(homeGuardianApi, "getAuthSession")
      .mockResolvedValueOnce(sessionResult(guardian))
      .mockResolvedValueOnce(sessionResult(user));
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user,
      session: { ...sessionTokens("user"), user, handoff: stagedHandoff("user") },
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await waitForState(() => probe.latest()?.state.guardianDashboard?.ward_summary.score === 90);
    await act(async () => {
      probe.latest()?.actions.loginWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.screen === "scanResult" && probe.latest()?.state.user?.user_id === user.user_id);

    expect(mockPromptSignIn).toHaveBeenCalledWith("user", "renewed-guardian-refresh");
    expect(probe.latest()?.state.guardianUser).toBeNull();
    expect(probe.latest()?.state.authSession?.role).toBe("user");
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("user-refresh");
    await waitForStorageRemoval(StorageKeys.guardianUser);
    await waitForStorageRemoval(StorageKeys.guardianWards);
    unmountController(probe);
  });

  it("Google callback 응답 유실은 기존 역할·세션·캐시를 그대로 보존한다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    // The OAuth helper reports a lost callback response as a failed sign-in;
    // the controller must not clear the local user while no candidate exists.
    mockPromptSignIn.mockResolvedValue({ ok: false, error: "connection lost" });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      await probe.latest()?.actions.loginAsGuardianWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);

    expect(probe.latest()?.state.authSession?.role).toBe("user");
    expect(probe.latest()?.state.user?.user_id).toBe(user.user_id);
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toContain("renewed-user-refresh");
    await expect(secureStorageGet(SecureStorageKeys.pendingAuthHandoff)).resolves.toBeNull();
    expect(homeGuardianApi.completeAuthHandoff).not.toHaveBeenCalled();
    unmountController(probe);
  });

  it("handoff 완료 연결 실패는 기존 세션·캐시를 보존하고 SecureStore 재시도 기록만 남긴다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    await storageSet(StorageKeys.devices, []);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    jest
      .spyOn(homeGuardianApi, "completeAuthHandoff")
      .mockRejectedValue(new HomeGuardianApiError("offline", "NETWORK_UNREACHABLE"));
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user: guardian,
      session: { ...sessionTokens("guardian"), user: guardian, handoff: stagedHandoff("guardian-network") },
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      await probe.latest()?.actions.loginAsGuardianWithGoogle();
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);

    expect(probe.latest()?.state.authSession?.role).toBe("user");
    expect(probe.latest()?.state.user?.user_id).toBe(user.user_id);
    expect(probe.latest()?.state.statusMessage).toContain("기존 로그인과 저장된 화면은 유지");
    const pending = await secureStorageGet(SecureStorageKeys.pendingAuthHandoff);
    expect(pending).toContain("renewed-user-refresh");
    expect(pending).toContain("guardian-refresh");
    expect([...mockAsyncValues.values()].join(" ")).not.toContain("guardian-refresh");
    unmountController(probe);
  });

  it("handoff 완료 응답 유실은 재실행 시 같은 요청으로 복구하고 새 역할만 활성화한다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    jest
      .spyOn(homeGuardianApi, "completeAuthHandoff")
      .mockRejectedValueOnce(new HomeGuardianApiError("response lost", "NETWORK_UNREACHABLE"))
      .mockResolvedValueOnce({ ...sessionTokens("completed-guardian"), refresh_token: "guardian-refresh", user: guardian });
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user: guardian,
      session: { ...sessionTokens("guardian"), user: guardian, handoff: stagedHandoff("guardian-response-loss") },
    });

    const firstLaunch = renderController();
    await waitForHydration(firstLaunch.latest);
    await act(async () => {
      await firstLaunch.latest()?.actions.loginAsGuardianWithGoogle();
    });
    await waitForState(() => firstLaunch.latest()?.state.isLoading === false);
    await expect(secureStorageGet(SecureStorageKeys.pendingAuthHandoff)).resolves.toContain("guardian-refresh");
    unmountController(firstLaunch);

    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-guardian"), user: guardian });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(guardian));
    const relaunched = renderController();
    await waitForHydration(relaunched.latest);
    await waitForState(() => relaunched.latest()?.state.screen === "guardianMode");

    expect(homeGuardianApi.completeAuthHandoff).toHaveBeenCalledTimes(2);
    expect(relaunched.latest()?.state.authSession?.role).toBe("guardian");
    await expect(secureStorageGet(SecureStorageKeys.pendingAuthHandoff)).resolves.toBeNull();
    await waitForStorageRemoval(StorageKeys.user);
    unmountController(relaunched);
  });

  it("로그아웃은 refresh session 폐기를 요청하고 다음 복원에 쓸 인증 정보를 지운다", async () => {
    await seedSession("user", user, "user");
    await Promise.all([
      secureStorageSet(SecureStorageKeys.registeredFcmToken, "registered-device-token"),
      storageSet(StorageKeys.notificationsEnabled, true),
      storageSet(StorageKeys.autoScanEnabled, true),
      storageSet(StorageKeys.autoScanIntervalHours, 12),
    ]);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));

    const probe = renderController();
    await waitForHydration(probe.latest);
    await act(async () => {
      probe.latest()?.actions.logout();
      await Promise.resolve();
    });

    expect(probe.latest()?.state.screen).toBe("login");
    expect(probe.latest()?.state.authSession).toBeNull();
    expect(probe.latest()?.state.notificationsEnabled).toBe(false);
    expect(probe.latest()?.state.autoScanEnabled).toBe(false);
    expect(probe.latest()?.state.autoScanIntervalHours).toBe(24);
    expect(homeGuardianApi.deleteFcmToken).toHaveBeenCalledWith("registered-device-token");
    expect(homeGuardianApi.logoutAuthSession).toHaveBeenCalledWith("renewed-user-refresh");
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
    unmountController(probe);
  });

  it("로그아웃 응답 유실은 로컬 데이터를 지우고 SecureStore 폐기 재시도 기록을 다음 시작에 처리한다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    jest
      .spyOn(homeGuardianApi, "logoutAuthSession")
      .mockRejectedValueOnce(new HomeGuardianApiError("response lost", "NETWORK_UNREACHABLE"))
      .mockResolvedValueOnce({ revoked: true });

    const firstLaunch = renderController();
    await waitForHydration(firstLaunch.latest);
    await act(async () => {
      await firstLaunch.latest()?.actions.logout();
    });
    await waitForState(() => firstLaunch.latest()?.state.screen === "login");

    expect(firstLaunch.latest()?.state.authSession).toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.pendingLogout)).resolves.toContain("renewed-user-refresh");
    expect([...mockAsyncValues.values()].join(" ")).not.toContain("renewed-user-refresh");
    unmountController(firstLaunch);

    const relaunched = renderController();
    await waitForHydration(relaunched.latest);
    expect(relaunched.latest()?.state.screen).toBe("login");
    expect(homeGuardianApi.logoutAuthSession).toHaveBeenCalledTimes(2);
    await expect(secureStorageGet(SecureStorageKeys.pendingLogout)).resolves.toBeNull();
    unmountController(relaunched);
  });

  it("로그아웃 재시도 네트워크 오류와 SecureStore 세션 삭제 실패 뒤에도 이전 세션을 복원하지 않는다", async () => {
    await seedSession("user", user, "user");
    await storageSet(StorageKeys.user, user);
    const refresh = jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    const verifySession = jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    const logoutRequest = jest
      .spyOn(homeGuardianApi, "logoutAuthSession")
      .mockRejectedValue(new HomeGuardianApiError("response lost", "NETWORK_UNREACHABLE"));

    const firstLaunch = renderController();
    await waitForHydration(firstLaunch.latest);
    mockSecureDeleteFailureKey = SecureStorageKeys.authSession;
    await act(async () => {
      await firstLaunch.latest()?.actions.logout();
    });
    await waitForState(() => firstLaunch.latest()?.state.screen === "login");

    expect(mockSecureValues.get(SecureStorageKeys.authSession)).toContain("renewed-user-refresh");
    expect(mockSecureValues.get(SecureStorageKeys.pendingLogout)).toContain("renewed-user-refresh");
    unmountController(firstLaunch);

    const relaunched = renderController();
    await waitForHydration(relaunched.latest);

    expect(relaunched.latest()?.state.screen).toBe("login");
    expect(relaunched.latest()?.state.authSession).toBeNull();
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(verifySession).toHaveBeenCalledTimes(1);
    expect(logoutRequest).toHaveBeenCalledTimes(2);
    unmountController(relaunched);
  });

  it("종료 인증 실패는 계정 캐시와 상태를 지우고 테마 설정은 보존한다", async () => {
    const staleDevice = {
      device_id: "stale-device",
      name: "삼성 카메라 (SCB-2000)",
      canonical_name: "삼성 카메라 (SCB-2000)",
      device_type: "camera",
      manufacturer: "삼성",
      model: "SCB-2000",
      ip_address: "",
      mac_address: "",
      online: true,
      last_seen: "",
      open_ports: [],
      services: [],
      default_credentials: false,
      encryption: "",
      firmware: "",
      vulnerabilities: [],
      discovery_sources: [],
      fingerprints: [],
      risk_signals: [],
      scan_source: "",
      confidence: 1,
      security_score: 50,
      risk_level: "yellow" as const,
      risk_summary: "",
      recommended_actions: [],
    };
    const staleNotification = {
      notification_id: "stale-notification",
      type: "security",
      title: "Old notification",
      message: "Old account notification",
      read: false,
      created_at: "2026-08-13T00:00:00Z",
    };
    const staleScanResult = {
      scan_id: "stale-scan",
      status: "completed" as const,
      progress: 100,
      scan_source: "android-native",
      current_step: "completed",
      devices_found: 1,
      high_risk_devices: 0,
      scan_profile: "quick",
      devices: [staleDevice],
      security_score: { score: 50, risk_level: "yellow" as const },
    };
    const staleGuardian = {
      invite_id: "stale-guardian",
      email: "guardian@example.test",
      relation: "family",
      status: "accepted",
      message: "Old account guardian",
    };
    const accountKeys = [
      StorageKeys.user,
      StorageKeys.devices,
      StorageKeys.notifications,
      StorageKeys.scanResult,
      StorageKeys.guardians,
      StorageKeys.guardianUser,
      StorageKeys.guardianWards,
    ];

    await seedSession("user", user, "expired");
    await Promise.all([
      storageSet(StorageKeys.user, user),
      storageSet(StorageKeys.devices, [staleDevice]),
      storageSet(StorageKeys.notifications, [staleNotification]),
      storageSet(StorageKeys.scanResult, staleScanResult),
      storageSet(StorageKeys.guardians, [staleGuardian]),
      storageSet(StorageKeys.guardianUser, guardian),
      storageSet(StorageKeys.guardianWards, [ward]),
      storageSet(StorageKeys.themePreference, "dark"),
    ]);
    jest
      .spyOn(homeGuardianApi, "refreshAuthSession")
      .mockRejectedValue(new HomeGuardianApiError("expired", "AUTH_SESSION_INVALID"));

    const probe = renderController();
    await waitForHydration(probe.latest);

    expect(probe.latest()?.state.screen).toBe("login");
    expect(probe.latest()?.state.user).toBeNull();
    expect(probe.latest()?.state.devices).toEqual([]);
    expect(probe.latest()?.state.notifications).toEqual([]);
    expect(probe.latest()?.state.scanResult).toBeNull();
    expect(probe.latest()?.state.guardians).toEqual([]);
    expect(probe.latest()?.state.guardianUser).toBeNull();
    expect(probe.latest()?.state.guardianWards).toEqual([]);
    await waitForState(() => accountKeys.every((key) => !mockAsyncValues.has(key)));
    expect(mockAsyncValues.get(StorageKeys.themePreference)).toBe(JSON.stringify("dark"));
    unmountController(probe);
  });

  it("다른 사용자 로그인 뒤 홈 API 실패가 이전 계정 캐시를 되살리지 않는다", async () => {
    const nextUser: User = {
      ...user,
      user_id: "user-2",
      email: "next-user@example.test",
      home_id: "home-2",
      nickname: "Next user",
    };
    const staleDevice = {
      device_id: "stale-device",
      name: "삼성 카메라 (SCB-2000)",
      canonical_name: "삼성 카메라 (SCB-2000)",
      device_type: "camera",
      manufacturer: "삼성",
      model: "SCB-2000",
      ip_address: "",
      mac_address: "",
      online: true,
      last_seen: "",
      open_ports: [],
      services: [],
      default_credentials: false,
      encryption: "",
      firmware: "",
      vulnerabilities: [],
      discovery_sources: [],
      fingerprints: [],
      risk_signals: [],
      scan_source: "",
      confidence: 1,
      security_score: 50,
      risk_level: "yellow" as const,
      risk_summary: "",
      recommended_actions: [],
    };
    const staleNotification = {
      notification_id: "stale-notification",
      type: "security",
      title: "Old notification",
      message: "Old account notification",
      read: false,
      created_at: "2026-08-13T00:00:00Z",
    };
    const staleScanResult = {
      scan_id: "stale-scan",
      status: "completed" as const,
      progress: 100,
      scan_source: "android-native",
      current_step: "completed",
      devices_found: 1,
      high_risk_devices: 0,
      scan_profile: "quick",
      devices: [staleDevice],
      security_score: { score: 50, risk_level: "yellow" as const },
    };
    const staleGuardian = {
      invite_id: "stale-guardian",
      email: "guardian@example.test",
      relation: "family",
      status: "accepted",
      message: "Old account guardian",
    };
    const staleCacheKeys = [
      StorageKeys.devices,
      StorageKeys.notifications,
      StorageKeys.scanResult,
      StorageKeys.guardians,
    ];

    await seedSession("user", user, "first-user");
    await Promise.all([
      storageSet(StorageKeys.user, user),
      storageSet(StorageKeys.devices, [staleDevice]),
      storageSet(StorageKeys.notifications, [staleNotification]),
      storageSet(StorageKeys.scanResult, staleScanResult),
      storageSet(StorageKeys.guardians, [staleGuardian]),
    ]);
    jest.spyOn(homeGuardianApi, "refreshAuthSession").mockResolvedValue({ ...sessionTokens("renewed-user"), user });
    jest.spyOn(homeGuardianApi, "getAuthSession").mockResolvedValue(sessionResult(user));
    mockPromptSignIn.mockResolvedValue({
      ok: true,
      user: nextUser,
      session: { ...sessionTokens("next-user"), user: nextUser, handoff: stagedHandoff("next-user") },
    });
    jest.spyOn(homeGuardianApi, "completeAuthHandoff").mockResolvedValue({
      ...sessionTokens("completed-next-user"),
      refresh_token: "next-user-refresh",
      user: nextUser,
    });

    const probe = renderController();
    await waitForHydration(probe.latest);
    // A verified relaunch refreshes the household from the server before the
    // role-switch attempt; an empty server response must replace old cache.
    expect(probe.latest()?.state.devices).toEqual([]);

    jest.spyOn(homeGuardianApi, "getDashboard").mockRejectedValue(new Error("offline"));
    jest.spyOn(homeGuardianApi, "getDevices").mockRejectedValue(new Error("offline"));
    jest.spyOn(homeGuardianApi, "getNotifications").mockRejectedValue(new Error("offline"));
    jest.spyOn(homeGuardianApi, "getGuardians").mockRejectedValue(new Error("offline"));

    await act(async () => {
      probe.latest()?.actions.loginWithGoogle();
    });
    await waitForState(
      () =>
        probe.latest()?.state.screen === "scanResult" &&
        probe.latest()?.state.user?.user_id === nextUser.user_id &&
        probe.latest()?.state.isLoading === false,
    );

    expect(mockPromptSignIn).toHaveBeenCalledWith("user", "renewed-user-refresh");
    expect(probe.latest()?.state.devices).toEqual([]);
    expect(probe.latest()?.state.notifications).toEqual([]);
    expect(probe.latest()?.state.guardians).toEqual([]);
    expect(probe.latest()?.state.scanResult).toBeNull();
    await waitForState(() => staleCacheKeys.every((key) => !mockAsyncValues.has(key)));
    await waitForState(() => mockAsyncValues.get(StorageKeys.user)?.includes(nextUser.user_id) === true);
    unmountController(probe);
  });

  it("기기 상세 API를 기다리지 않고 저장된 목록 정보로 즉시 화면을 연다", async () => {
    const cached = verifiedDevice({ security_score: 90 });
    const latest = verifiedDevice({ security_score: 72 });
    const pendingDetail = deferred<Device>();
    jest.spyOn(homeGuardianApi, "getDevice").mockReturnValue(pendingDetail.promise);

    const probe = renderController();
    await waitForHydration(probe.latest);
    act(() => {
      probe.latest()?.actions.setScreen("devices");
    });
    act(() => {
      probe.latest()?.actions.openDevice(cached);
    });

    expect(probe.latest()?.state.screen).toBe("detail");
    expect(probe.latest()?.state.selectedDevice?.security_score).toBe(90);
    expect(probe.latest()?.state.history).toEqual(["devices"]);
    expect(homeGuardianApi.getDevice).toHaveBeenCalledWith(cached.device_id);

    await act(async () => {
      pendingDetail.resolve(latest);
      await pendingDetail.promise;
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);
    expect(probe.latest()?.state.selectedDevice?.security_score).toBe(72);
    expect(probe.latest()?.state.history).toEqual(["devices"]);
    unmountController(probe);
  });

  it("느린 상세 최신화 중에도 다른 저장 액션을 조용히 버리지 않는다", async () => {
    const cached = verifiedDevice({ security_score: 90 });
    const renamed = verifiedDevice({ alias: "거실 공유기", security_score: 90 });
    const pendingDetail = deferred<Device>();
    jest.spyOn(homeGuardianApi, "getDevice").mockReturnValue(pendingDetail.promise);
    jest.spyOn(homeGuardianApi, "updateDeviceAlias").mockResolvedValue(renamed);

    const probe = renderController();
    await waitForHydration(probe.latest);
    act(() => {
      probe.latest()?.actions.openDevice(cached);
    });

    await act(async () => {
      await probe.latest()?.actions.renameDevice(cached.device_id, "거실 공유기");
    });

    expect(homeGuardianApi.updateDeviceAlias).toHaveBeenCalledWith(cached.device_id, "거실 공유기");
    expect(probe.latest()?.state.selectedDevice?.alias).toBe("거실 공유기");
    expect(probe.latest()?.state.isLoading).toBe(true);

    await act(async () => {
      pendingDetail.resolve(renamed);
      await pendingDetail.promise;
    });
    await waitForState(() => probe.latest()?.state.isLoading === false);
    unmountController(probe);
  });

});
