import { shouldRunBackgroundScan } from "../src/services/backgroundScan";
import { StorageKeys, storageClear, storageSet } from "../src/state/storage";

describe("background scan preference boundary", () => {
  beforeEach(async () => {
    await storageClear();
  });

  afterEach(async () => {
    await storageClear();
  });

  it("정기 점검 알림이 꺼져 있으면 남은 native task가 실행돼도 알리지 않는다", async () => {
    await storageSet(StorageKeys.autoScanEnabled, false);
    await storageSet(StorageKeys.lastScanAt, "2000-01-01T00:00:00.000Z");

    await expect(shouldRunBackgroundScan()).resolves.toBe(false);
  });

  it("정기 점검 알림이 켜져 있고 주기가 지났을 때만 실행한다", async () => {
    await storageSet(StorageKeys.autoScanEnabled, true);
    await storageSet(StorageKeys.autoScanIntervalHours, 24);
    await storageSet(StorageKeys.lastScanAt, "2000-01-01T00:00:00.000Z");

    await expect(shouldRunBackgroundScan()).resolves.toBe(true);
  });
});
