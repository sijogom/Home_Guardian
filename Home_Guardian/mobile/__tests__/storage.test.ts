const { values: mockAsyncValues, module: mockAsyncStorage } = (
  globalThis as typeof globalThis & {
    __HOME_GUARDIAN_ASYNC_STORAGE_MOCK__: {
      values: Map<string, string>;
      module: {
        getItem: jest.Mock;
        setItem: jest.Mock;
        removeItem: jest.Mock;
        multiRemove: jest.Mock;
      };
    };
  }
).__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__;
const mockSecureValues = new Map<string, string>();

const mockSecureStore = {
  getItemAsync: jest.fn(async (key: string) => mockSecureValues.get(key) ?? null),
  setItemAsync: jest.fn(async (key: string, value: string) => {
    mockSecureValues.set(key, value);
  }),
  deleteItemAsync: jest.fn(async (key: string) => {
    mockSecureValues.delete(key);
  }),
};

jest.mock("expo-secure-store", () => ({
  __esModule: true,
  getItemAsync: (...args: Parameters<typeof mockSecureStore.getItemAsync>) => mockSecureStore.getItemAsync(...args),
  setItemAsync: (...args: Parameters<typeof mockSecureStore.setItemAsync>) => mockSecureStore.setItemAsync(...args),
  deleteItemAsync: (...args: Parameters<typeof mockSecureStore.deleteItemAsync>) => mockSecureStore.deleteItemAsync(...args),
}));

import {
  SecureStoragePersistenceError,
  SecureStorageKeys,
  StorageKeys,
  discardRetiredGuardianSessionToken,
  secureStorageClear,
  secureStorageGet,
  secureStorageGetRequired,
  secureStorageSet,
  secureStorageSetRequired,
  storageClear,
  storageGet,
  storageSet,
} from "../src/state/storage";

const LEGACY_GUARDIAN_SESSION_TOKEN_KEY = "hg.guardianSessionToken";

describe("저장소 보안 경계", () => {
  beforeEach(async () => {
    mockAsyncValues.clear();
    mockSecureValues.clear();
    await secureStorageClear();
    Object.values(mockAsyncStorage).forEach((value) => {
      if (typeof value === "function" && "mockClear" in value) value.mockClear();
    });
    Object.values(mockSecureStore).forEach((value) => {
      if (typeof value === "function" && "mockClear" in value) value.mockClear();
    });
  });

  it("v0.x 보호자 직접 조회 세션을 두 저장소에서 폐기하고 정식 인증과 테마는 보존한다", async () => {
    mockAsyncValues.set(LEGACY_GUARDIAN_SESSION_TOKEN_KEY, JSON.stringify("legacy-guardian-token"));
    await secureStorageSet(LEGACY_GUARDIAN_SESSION_TOKEN_KEY, "secure-guardian-token");
    await secureStorageSet(SecureStorageKeys.authSession, "stored-session-for-test");
    await storageSet(StorageKeys.themePreference, "system");

    await discardRetiredGuardianSessionToken();

    expect(mockAsyncValues.has(LEGACY_GUARDIAN_SESSION_TOKEN_KEY)).toBe(false);
    expect(mockAsyncStorage.removeItem).toHaveBeenCalledWith(LEGACY_GUARDIAN_SESSION_TOKEN_KEY);
    await expect(secureStorageGet(LEGACY_GUARDIAN_SESSION_TOKEN_KEY)).resolves.toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBe("stored-session-for-test");
    await expect(storageGet(StorageKeys.themePreference)).resolves.toBe("system");
  });

  it("폐기 마이그레이션은 이전 값이 없어도 정식 인증 정보를 지우지 않는다", async () => {
    await secureStorageSet(SecureStorageKeys.authSession, "stored-session-for-test");

    await expect(discardRetiredGuardianSessionToken()).resolves.toBeUndefined();

    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBe("stored-session-for-test");
    expect(StorageKeys).not.toHaveProperty("guardianSessionToken");
    expect(SecureStorageKeys).not.toHaveProperty("guardianSessionToken");
  });

  it("전체 보안 저장소 정리는 폐기 대상의 두 저장소 값을 함께 지운다", async () => {
    mockAsyncValues.set(LEGACY_GUARDIAN_SESSION_TOKEN_KEY, JSON.stringify("legacy-guardian-token"));
    await secureStorageSet(LEGACY_GUARDIAN_SESSION_TOKEN_KEY, "secure-guardian-token");
    await secureStorageSet(SecureStorageKeys.authSession, "stored-session-for-test");

    await secureStorageClear();

    expect(mockAsyncValues.has(LEGACY_GUARDIAN_SESSION_TOKEN_KEY)).toBe(false);
    await expect(secureStorageGet(LEGACY_GUARDIAN_SESSION_TOKEN_KEY)).resolves.toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
  });

  it("캐시와 스키마 정리는 정식 SecureStore 인증 세션을 전역 삭제하지 않는다", async () => {
    await storageSet(StorageKeys.schemaVersion, 4);
    await storageSet(StorageKeys.devices, [{ device_id: "cache-only-device" }]);
    await secureStorageSet(SecureStorageKeys.authSession, "stored-session-for-test");

    await storageClear();

    await expect(storageGet(StorageKeys.schemaVersion)).resolves.toBeNull();
    await expect(storageGet(StorageKeys.devices)).resolves.toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBe("stored-session-for-test");
  });

  it("로그아웃 캐시 정리는 저장된 라이트·다크·시스템 테마 설정을 보존한다", async () => {
    await storageSet(StorageKeys.themePreference, "system");
    await storageSet(StorageKeys.notifications, [{ notification_id: "cached-notification" }]);
    await secureStorageSet(SecureStorageKeys.authSession, "stored-session-for-test");

    await storageClear({ preserveAppPreferences: true });
    await secureStorageClear();

    await expect(storageGet(StorageKeys.themePreference)).resolves.toBe("system");
    await expect(storageGet(StorageKeys.notifications)).resolves.toBeNull();
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
  });

  it("SecureStore 쓰기 실패는 테스트 환경에서도 인증 정보를 메모리에 남기지 않는다", async () => {
    mockSecureStore.setItemAsync.mockRejectedValueOnce(new Error("native keystore unavailable"));

    await expect(secureStorageSetRequired(SecureStorageKeys.pendingAuthHandoff, "handoff-secret")).rejects.toBeInstanceOf(
      SecureStoragePersistenceError,
    );
    await expect(secureStorageGet(SecureStorageKeys.pendingAuthHandoff)).resolves.toBeNull();
  });

  it("일반 SecureStore 쓰기도 실패를 성공처럼 처리하지 않는다", async () => {
    mockSecureStore.setItemAsync.mockRejectedValueOnce(new Error("native keystore unavailable"));

    await expect(secureStorageSet(SecureStorageKeys.authSession, "session-secret")).rejects.toBeInstanceOf(
      SecureStoragePersistenceError,
    );
    await expect(secureStorageGet(SecureStorageKeys.authSession)).resolves.toBeNull();
  });

  it("필수 SecureStore 읽기 실패는 빈 값으로 위장하지 않고 오류를 반환한다", async () => {
    mockSecureStore.getItemAsync.mockRejectedValueOnce(new Error("native keystore unavailable"));

    await expect(secureStorageGetRequired(SecureStorageKeys.authSession)).rejects.toBeInstanceOf(
      SecureStoragePersistenceError,
    );
  });

  it("AsyncStorage 쓰기 실패는 메모리 저장 성공으로 위장하지 않는다", async () => {
    mockAsyncStorage.setItem.mockRejectedValueOnce(new Error("native storage unavailable"));

    await expect(storageSet(StorageKeys.devices, [{ device_id: "device-write-failure" }])).rejects.toThrow(
      "native storage unavailable",
    );
    await expect(storageGet(StorageKeys.devices)).resolves.toBeNull();
  });
});
