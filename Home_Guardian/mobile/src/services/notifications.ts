// 로컬 알림 wrapper. expo-notifications 가 미설치(웹/테스트 등) 환경에서는 no-op.

declare function require<T = unknown>(path: string): T;

type ExpoNotifications = {
  setNotificationHandler: (handler: { handleNotification: () => Promise<unknown> }) => void;
  requestPermissionsAsync: () => Promise<{ status: string; granted?: boolean }>;
  getPermissionsAsync: () => Promise<{ status: string; granted?: boolean }>;
  scheduleNotificationAsync: (input: {
    content: { title: string; body?: string; data?: Record<string, unknown> };
    trigger: null;
  }) => Promise<string>;
  setNotificationChannelAsync?: (
    channelId: string,
    channel: { name: string; importance: number; sound?: string | null },
  ) => Promise<unknown>;
  AndroidImportance?: { DEFAULT: number; HIGH: number; MAX: number };
  getDevicePushTokenAsync?: () => Promise<{ data: string; type: string }>;
  getExpoPushTokenAsync?: (options?: { projectId?: string }) => Promise<{ data: string }>;
  addPushTokenListener?: (
    listener: (token: { data: string; type?: string }) => void,
  ) => { remove: () => void };
};

let cached: ExpoNotifications | null | undefined;

function loadNotifications(): ExpoNotifications | null {
  if (cached !== undefined) return cached;
  try {
    const mod = require<ExpoNotifications | { default?: ExpoNotifications }>("expo-notifications");
    const candidate = (mod as { default?: ExpoNotifications }).default ?? (mod as ExpoNotifications);
    candidate.setNotificationHandler?.({
      handleNotification: async () => ({
        shouldShowAlert: true,
        shouldPlaySound: true,
        shouldSetBadge: false,
      }),
    });
    cached = candidate;
  } catch {
    cached = null;
  }
  return cached;
}

export async function requestNotificationsPermission(): Promise<boolean> {
  const notifications = loadNotifications();
  if (!notifications) return false;
  try {
    const current = await notifications.getPermissionsAsync();
    if (current.granted || current.status === "granted") {
      await ensureAndroidChannel(notifications);
      return true;
    }
    const result = await notifications.requestPermissionsAsync();
    const granted = result.granted ?? result.status === "granted";
    if (granted) {
      await ensureAndroidChannel(notifications);
    }
    return granted;
  } catch {
    return false;
  }
}

async function ensureAndroidChannel(notifications: ExpoNotifications) {
  if (!notifications.setNotificationChannelAsync) return;
  const importance =
    notifications.AndroidImportance?.HIGH ??
    notifications.AndroidImportance?.DEFAULT ??
    4;
  try {
    await notifications.setNotificationChannelAsync("home-guardian-default", {
      name: "홈 가디언 알림",
      importance,
      sound: "default",
    });
  } catch {
    // 채널 등록 실패는 알림 전송 자체를 막지 않는다.
  }
}

type ScanCompletedPayload = {
  score: number | null;
  highRisk: number;
  caution: number;
  deviceCount: number;
};

// expo-notifications + Firebase 가 정상 연결돼 있으면 실제 device push token 을 반환.
// Firebase google-services.json 미설정 등 실패 시 null. 토큰 등록 실패는 흐름을 막지 않는다.
export async function getDevicePushToken(): Promise<string | null> {
  const notifications = loadNotifications();
  if (!notifications) return null;
  try {
    if (notifications.getDevicePushTokenAsync) {
      const result = await notifications.getDevicePushTokenAsync();
      if (result?.data) return result.data;
    }
    if (notifications.getExpoPushTokenAsync) {
      const result = await notifications.getExpoPushTokenAsync();
      if (result?.data) return result.data;
    }
  } catch {
    return null;
  }
  return null;
}

export function addDevicePushTokenListener(listener: (token: string) => void): () => void {
  const notifications = loadNotifications();
  if (!notifications?.addPushTokenListener) return () => undefined;
  try {
    const subscription = notifications.addPushTokenListener((nextToken) => {
      if (typeof nextToken?.data === "string" && nextToken.data.trim()) {
        listener(nextToken.data.trim());
      }
    });
    return () => {
      try {
        subscription.remove();
      } catch {
        // 이미 해제된 native listener는 무시한다.
      }
    };
  } catch {
    return () => undefined;
  }
}

export async function notifyScanCompleted(payload: ScanCompletedPayload): Promise<void> {
  const notifications = loadNotifications();
  if (!notifications) return;
  try {
    const current = await notifications.getPermissionsAsync();
    if (!(current.granted || current.status === "granted")) return;
    // 위험(red)뿐 아니라 '주의(yellow)' 물건도 알린다. 그러지 않으면 알려진 취약점으로 yellow 가 된
    // 물건(예 공유기 CVE)이 있어도 "지금은 안심해도 돼요" 로만 떠 사용자가 놓친다(백엔드 알림과 동일 기준).
    const title =
      payload.score == null
        ? "안전 검사를 마쳤어요"
        : payload.highRisk > 0
        ? `위험한 물건 ${payload.highRisk}개를 봐 주세요`
        : payload.caution > 0
        ? `확인할 물건 ${payload.caution}개가 있어요`
        : "지금은 안심해도 돼요";
    const body =
      payload.score == null
        ? `우리 집 물건 ${payload.deviceCount}개를 확인했어요.`
        : `안전 점수 ${payload.score}점 · 물건 ${payload.deviceCount}개`;
    await notifications.scheduleNotificationAsync({
      content: {
        title,
        body,
        data: { type: "scan_completed", ...payload },
      },
      trigger: null,
    });
  } catch {
    // 알림 전송 실패는 사용자 흐름을 막지 않는다.
  }
}

export async function notifyScanReminder(): Promise<void> {
  const notifications = loadNotifications();
  if (!notifications) return;
  try {
    const current = await notifications.getPermissionsAsync();
    if (!(current.granted || current.status === "granted")) return;
    await notifications.scheduleNotificationAsync({
      content: {
        title: "안전 점검할 시간이에요",
        body: "앱을 열어 우리 집 와이파이에 연결된 물건을 확인해 주세요.",
        data: { type: "scan_reminder" },
      },
      trigger: null,
    });
  } catch {
    // 알림 전송 실패는 사용자 흐름을 막지 않는다.
  }
}
