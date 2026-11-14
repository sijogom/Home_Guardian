const asyncStorageValues = new Map();
const asyncStorageMock = {
  getItem: jest.fn(async (key) => asyncStorageValues.get(key) ?? null),
  setItem: jest.fn(async (key, value) => {
    asyncStorageValues.set(key, value);
  }),
  removeItem: jest.fn(async (key) => {
    asyncStorageValues.delete(key);
  }),
  multiRemove: jest.fn(async (keys) => {
    keys.forEach((key) => asyncStorageValues.delete(key));
  }),
};

globalThis.__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__ = {
  values: asyncStorageValues,
  module: asyncStorageMock,
};

jest.mock("@react-native-async-storage/async-storage", () => ({
  __esModule: true,
  default: {
    getItem: (...args) => globalThis.__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.module.getItem(...args),
    setItem: (...args) => globalThis.__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.module.setItem(...args),
    removeItem: (...args) => globalThis.__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.module.removeItem(...args),
    multiRemove: (...args) => globalThis.__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.module.multiRemove(...args),
  },
}));

jest.mock("react-native-safe-area-context", () => {
  const safeAreaMock = jest.requireActual("react-native-safe-area-context/jest/mock");
  return safeAreaMock.default ?? safeAreaMock;
});
