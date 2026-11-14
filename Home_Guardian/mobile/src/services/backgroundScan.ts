// expo-background-fetch + expo-task-manager 기반 정기 점검 알림.
// 미설치 환경(웹/테스트)에서는 no-op. 모든 함수가 안전하게 false 를 반환.

import { StorageKeys, storageGet } from "../state/storage";

declare function require<T = unknown>(path: string): T;

type TaskManagerLike = {
  defineTask: (taskName: string, task: () => Promise<unknown>) => void;
  isTaskRegisteredAsync: (taskName: string) => Promise<boolean>;
};

type BackgroundFetchLike = {
  registerTaskAsync: (taskName: string, options: { minimumInterval: number; stopOnTerminate?: boolean; startOnBoot?: boolean }) => Promise<void>;
  unregisterTaskAsync: (taskName: string) => Promise<void>;
  BackgroundFetchResult?: { NewData: number; NoData: number; Failed: number };
  Result?: { NewData: number; NoData: number; Failed: number };
};

const TASK_NAME = "home-guardian-background-scan";

let taskManagerCached: TaskManagerLike | null | undefined;
let backgroundFetchCached: BackgroundFetchLike | null | undefined;
let taskDefined = false;

function loadTaskManager(): TaskManagerLike | null {
  if (taskManagerCached !== undefined) return taskManagerCached;
  try {
    const mod = require<TaskManagerLike | { default?: TaskManagerLike }>("expo-task-manager");
    taskManagerCached = (mod as { default?: TaskManagerLike }).default ?? (mod as TaskManagerLike);
  } catch {
    taskManagerCached = null;
  }
  return taskManagerCached;
}

function loadBackgroundFetch(): BackgroundFetchLike | null {
  if (backgroundFetchCached !== undefined) return backgroundFetchCached;
  try {
    const mod = require<BackgroundFetchLike | { default?: BackgroundFetchLike }>("expo-background-fetch");
    backgroundFetchCached = (mod as { default?: BackgroundFetchLike }).default ?? (mod as BackgroundFetchLike);
  } catch {
    backgroundFetchCached = null;
  }
  return backgroundFetchCached;
}

// 백그라운드 태스크 정의. App 부팅 시 1회 등록.
export function defineBackgroundScanTask(handler: () => Promise<void>): void {
  const taskManager = loadTaskManager();
  if (!taskManager || taskDefined) return;
  const backgroundFetch = loadBackgroundFetch();
  const noDataResult = backgroundFetch?.BackgroundFetchResult?.NoData ?? backgroundFetch?.Result?.NoData ?? 1;
  const failedResult = backgroundFetch?.BackgroundFetchResult?.Failed ?? backgroundFetch?.Result?.Failed ?? 2;
  try {
    taskManager.defineTask(TASK_NAME, async () => {
      try {
        await handler();
        return backgroundFetch?.BackgroundFetchResult?.NewData ?? backgroundFetch?.Result?.NewData ?? 0;
      } catch {
        return failedResult;
      } finally {
        // no-op: NoData fallback handled by handler success path
        void noDataResult;
      }
    });
    taskDefined = true;
  } catch {
    // 이미 정의된 경우 무시.
  }
}

// 사용자가 정기 점검 알림을 켰을 때만 호출. 미설치/권한 거부 시 false.
export async function registerAutoScan(intervalHours: number): Promise<boolean> {
  const taskManager = loadTaskManager();
  const backgroundFetch = loadBackgroundFetch();
  if (!taskManager || !backgroundFetch) return false;
  try {
    const registered = await taskManager.isTaskRegisteredAsync(TASK_NAME);
    if (registered) {
      await backgroundFetch.unregisterTaskAsync(TASK_NAME);
    }
    const minimumInterval = Math.max(15 * 60, Math.round(intervalHours * 60 * 60));
    await backgroundFetch.registerTaskAsync(TASK_NAME, {
      minimumInterval,
      stopOnTerminate: false,
      startOnBoot: true,
    });
    return true;
  } catch {
    return false;
  }
}

export async function unregisterAutoScan(): Promise<void> {
  const taskManager = loadTaskManager();
  const backgroundFetch = loadBackgroundFetch();
  if (!taskManager || !backgroundFetch) return;
  try {
    const registered = await taskManager.isTaskRegisteredAsync(TASK_NAME);
    if (registered) {
      await backgroundFetch.unregisterTaskAsync(TASK_NAME);
    }
  } catch {
    // ignore
  }
}

// 백그라운드 태스크가 실행될 때 마지막 검사 시각을 확인해 너무 자주 알리지 않게.
export async function shouldRunBackgroundScan(): Promise<boolean> {
  const enabled = (await storageGet<boolean>(StorageKeys.autoScanEnabled)) ?? false;
  if (!enabled) return false;
  const intervalHours = (await storageGet<number>(StorageKeys.autoScanIntervalHours)) ?? 24;
  const lastIso = await storageGet<string>(StorageKeys.lastScanAt);
  if (!lastIso) return true;
  const last = Date.parse(lastIso);
  if (Number.isNaN(last)) return true;
  const elapsed = Date.now() - last;
  return elapsed >= intervalHours * 60 * 60 * 1000;
}

export const BACKGROUND_SCAN_TASK = TASK_NAME;
