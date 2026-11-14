import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";

let storageWriteTail: Promise<void> = Promise.resolve();

/**
 * AsyncStorage writes are intentionally serialized.  Scan flow changes the
 * same key from "remove while starting" to "set on completion"; firing both
 * operations without ordering lets the older remove finish last and erase a
 * valid completed result.  The queue is process-local and does not alter the
 * storage contract, it only preserves call order.
 */
function enqueueStorageWrite(operation: () => Promise<void>): Promise<void> {
  const next = storageWriteTail.then(operation, operation);
  storageWriteTail = next.catch(() => undefined);
  return next;
}

export const StorageKeys = {
  schemaVersion: "hg.schemaVersion",
  user: "hg.user",
  scanResult: "hg.scanResult",
  devices: "hg.devices",
  notifications: "hg.notifications",
  guardians: "hg.guardians",
  apiBaseUrl: "hg.apiBaseUrl",
  guardianEmail: "hg.guardianEmail",
  lastScanAt: "hg.lastScanAt",
  autoScanIntervalHours: "hg.autoScanIntervalHours",
  autoScanEnabled: "hg.autoScanEnabled",
  notificationsEnabled: "hg.notificationsEnabled",
  themePreference: "hg.themePreference",
  guardianUser: "hg.guardianUser",
  guardianWards: "hg.guardianWards",
  selectedGuardianWardId: "hg.selectedGuardianWardId",
} as const;

export const SecureStorageKeys = {
  authSession: "hg.authSession",
  registeredFcmToken: "hg.registeredFcmToken",
  // v0.x에서 사용한 access token 키. 새 세션으로 옮길 수 없는 경우에도 캐시를 보존한 채 제거한다.
  authToken: "hg.authToken",
  // 활성 세션과 별개인 2단계 역할 전환 기록. 이전/후속 refresh token과
  // handoff id는 이 단일 SecureStore 항목에만 함께 저장한다.
  pendingAuthHandoff: "hg.pendingAuthHandoff",
  // 네트워크 응답 유실로 서버 폐기 확인을 받지 못한 로그아웃 재시도용 refresh token.
  pendingLogout: "hg.pendingLogout",
} as const;

// v0.x의 초대 코드 직접 조회 세션이다. v1은 Google 보호자 계정만 허용하므로,
// 앱을 처음 다시 열 때 SecureStore와 AsyncStorage 양쪽에서 폐기한다.
const RETIRED_GUARDIAN_SESSION_TOKEN_KEY = "hg.guardianSessionToken";

// 스키마 버전은 비민감 캐시의 호환성 기록용이다. 버전이 달라도 인증
// SecureStore와 계정·환경설정은 보존하고, provenance를 신뢰할 수 없는
// 제품·점검 파생 캐시는 controller hydrate에서 먼저 폐기한다.
export const STORAGE_SCHEMA_VERSION = 7;

export async function storageGet<T>(key: string): Promise<T | null> {
  try {
    const raw = await AsyncStorage.getItem(key);
    if (raw === null) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function storageSet<T>(key: string, value: T): Promise<void> {
  await enqueueStorageWrite(async () => {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  });
}

export async function storageRemove(key: string): Promise<void> {
  await enqueueStorageWrite(async () => {
    await AsyncStorage.removeItem(key);
  });
}

export async function storageClear(options: { preserveAppPreferences?: boolean } = {}): Promise<void> {
  const keys = [...Object.values(StorageKeys), RETIRED_GUARDIAN_SESSION_TOKEN_KEY].filter(
    (key) => !options.preserveAppPreferences || key !== StorageKeys.themePreference,
  );
  await enqueueStorageWrite(async () => {
    await AsyncStorage.multiRemove(keys as string[]);
  });
}

export async function secureStorageGet(key: string): Promise<string | null> {
  try {
    const value = await SecureStore.getItemAsync(key);
    return typeof value === "string" ? value : null;
  } catch {
    // 보안 저장소를 읽을 수 없으면 로그인 정보가 없는 것으로 처리한다.
    return null;
  }
}

export async function secureStorageSet(key: string, value: string | null): Promise<void> {
  if (!value) {
    await secureStorageRemove(key);
    return;
  }
  try {
    await SecureStore.setItemAsync(key, value);
  } catch {
    throw new SecureStoragePersistenceError();
  }
}

export async function secureStorageRemove(key: string): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(key);
  } catch {
    // 호환 정리 경로는 기존 세션 복구를 막는 영구 marker가 별도로 지킨다.
    // 삭제 성공이 필수인 전환은 secureStorageRemoveRequired를 사용한다.
  }
}

export async function secureStorageClear(): Promise<void> {
  await Promise.all([
    ...Object.values(SecureStorageKeys).map((key) => secureStorageRemove(key)),
    secureStorageRemove(RETIRED_GUARDIAN_SESSION_TOKEN_KEY),
    storageRemove(RETIRED_GUARDIAN_SESSION_TOKEN_KEY),
  ]);
}

export class SecureStoragePersistenceError extends Error {
  constructor() {
    super("보안 저장소에 로그인 정보를 저장하지 못했습니다.");
    this.name = "SecureStoragePersistenceError";
  }
}

/**
 * 인증 자료를 네이티브 보안 저장소에 실패 폐쇄 방식으로 기록한다.
 */
export async function secureStorageSetRequired(key: string, value: string): Promise<void> {
  if (!value) {
    throw new SecureStoragePersistenceError();
  }
  try {
    await SecureStore.setItemAsync(key, value);
  } catch {
    throw new SecureStoragePersistenceError();
  }
}

export async function secureStorageGetRequired(key: string): Promise<string | null> {
  try {
    const value = await SecureStore.getItemAsync(key);
    return typeof value === "string" ? value : null;
  } catch {
    throw new SecureStoragePersistenceError();
  }
}

export async function secureStorageRemoveRequired(key: string): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(key);
  } catch {
    throw new SecureStoragePersistenceError();
  }
}

export async function discardRetiredGuardianSessionToken(): Promise<void> {
  await Promise.all([
    secureStorageRemove(RETIRED_GUARDIAN_SESSION_TOKEN_KEY),
    storageRemove(RETIRED_GUARDIAN_SESSION_TOKEN_KEY),
  ]);
}
