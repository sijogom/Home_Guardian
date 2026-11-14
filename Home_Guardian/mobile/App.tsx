import { useEffect } from "react";
import { BackHandler, Linking, Platform, StatusBar, StyleSheet, ToastAndroid, View } from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import * as WebBrowser from "expo-web-browser";

// OAuth (Google 로그인) redirect 콜백을 받아 promptAsync 의 promise 를 resolve 시키려면
// 앱 진입 시점에 한 번 호출되어야 한다. 호출이 누락되면 redirect URI 가 시스템 브라우저에서
// 멈추고 앱은 "Google 로그인이 취소되었거나 실패했습니다" 로 판정한다.
WebBrowser.maybeCompleteAuthSession();

import { BottomTabBar, type TabKey } from "./src/components/BottomTabBar";
import { SafeScreen, useBottomInset } from "./src/components/SafeScreen";
import { DeviceDetailScreen } from "./src/screens/DeviceDetailScreen";
import { DevicesScreen } from "./src/screens/DevicesScreen";
import { GuardianModeScreen } from "./src/screens/GuardianModeScreen";
import { GuardianScreen } from "./src/screens/GuardianScreen";
import { LoginScreen } from "./src/screens/LoginScreen";
import { NotificationsScreen } from "./src/screens/NotificationsScreen";
import { ProfileScreen } from "./src/screens/ProfileScreen";
import { ScanConsentScreen } from "./src/screens/ScanConsentScreen";
import { ScanProgressScreen } from "./src/screens/ScanProgressScreen";
import { ScanResultScreen } from "./src/screens/ScanResultScreen";
import { UserLoginScreen } from "./src/screens/UserLoginScreen";
import { BACKGROUND_SCAN_TASK, defineBackgroundScanTask, registerAutoScan, shouldRunBackgroundScan, unregisterAutoScan } from "./src/services/backgroundScan";
import { notifyScanCompleted, notifyScanReminder } from "./src/services/notifications";
import { useHomeGuardianController, type Screen } from "./src/state/useHomeGuardianController";
import { ThemeProvider, useAppTheme } from "./src/theme";

const TAB_SCREENS: Screen[] = ["scanResult", "devices", "guardian", "alerts", "profile"];
const SCREEN_TO_TAB: Partial<Record<Screen, TabKey>> = {
  scanResult: "home",
  devices: "devices",
  guardian: "guardian",
  alerts: "alerts",
  profile: "profile",
};
const TAB_TO_SCREEN: Record<TabKey, Screen> = {
  home: "scanResult",
  devices: "devices",
  guardian: "guardian",
  alerts: "alerts",
  profile: "profile",
};

// 백그라운드 태스크는 앱 부팅 시 1회 정의되어야 한다.
// OS 백그라운드 실행에서는 권한/시간 제약이 크므로 실제 스캔 완료처럼 알리지 않고
// 사용자가 앱을 열어 점검을 시작하도록 정기 알림만 보낸다.
defineBackgroundScanTask(async () => {
  if (!(await shouldRunBackgroundScan())) return;
  await notifyScanReminder();
});
void BACKGROUND_SCAN_TASK;

function AppShell() {
  const { state, actions } = useHomeGuardianController();
  const { colors, mode } = useAppTheme();
  const bottomInset = useBottomInset();

  // 보호자 초대 링크(homeguardian://join?invite=...)는 Google OAuth redirect와 분리해서 처리한다.
  useEffect(() => {
    let mounted = true;
    const handleUrl = (url: string | null) => {
      if (!url || !url.toLowerCase().startsWith("homeguardian://join")) return;
      actions.openGuardianInviteLink(url);
    };

    void Linking.getInitialURL().then((url) => {
      if (mounted) handleUrl(url);
    });
    const subscription = Linking.addEventListener("url", (event) => handleUrl(event.url));
    return () => {
      mounted = false;
      subscription.remove();
    };
  }, [actions.openGuardianInviteLink]);

  // 정기 점검 알림 토글이 켜져 있을 때만 백그라운드 fetch 등록.
  useEffect(() => {
    if (!state.isHydrated) return;
    if (state.autoScanEnabled) {
      void registerAutoScan(state.autoScanIntervalHours);
    } else {
      void unregisterAutoScan();
    }
  }, [state.autoScanEnabled, state.autoScanIntervalHours, state.isHydrated]);

  // Android 뒤로가기: history pop, 비어 있으면 한 번 더 누르면 종료 안내.
  useEffect(() => {
    if (Platform.OS !== "android") return;
    let canExit = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const subscription = BackHandler.addEventListener("hardwareBackPress", () => {
      const handled = actions.goBack();
      if (handled) {
        canExit = false;
        if (timer) {
          clearTimeout(timer);
          timer = null;
        }
        return true;
      }
      // 메인 탭/로그인 화면에서 두 번 누르면 시스템 기본 동작(앱 종료)을 허용.
      if (canExit) return false;
      canExit = true;
      if (ToastAndroid?.show) {
        ToastAndroid.show("한 번 더 누르면 앱이 닫혀요.", ToastAndroid.SHORT);
      }
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        canExit = false;
        timer = null;
      }, 2000);
      return true;
    });
    return () => {
      subscription.remove();
      if (timer) clearTimeout(timer);
    };
  }, [actions.goBack]);

  const screen: Screen = state.screen;
  const showTabBar = TAB_SCREENS.includes(screen);
  const unread = state.notifications.filter((n) => !n.read).length;
  const activeTab = SCREEN_TO_TAB[screen] ?? "home";

  return (
    <SafeScreen
      edges={showTabBar ? ["top", "left", "right"] : ["top", "left", "right", "bottom"]}
    >
      <StatusBar barStyle={mode === "dark" ? "light-content" : "dark-content"} backgroundColor={colors.bg} />
      <View style={styles.content}>
        {screen === "login" ? <LoginScreen state={state} actions={actions} /> : null}
        {screen === "userLogin" ? <UserLoginScreen state={state} actions={actions} /> : null}
        {screen === "profile" ? <ProfileScreen state={state} actions={actions} /> : null}
        {screen === "scanConsent" ? <ScanConsentScreen actions={actions} /> : null}
        {screen === "scanProgress" ? <ScanProgressScreen state={state} actions={actions} /> : null}
        {screen === "scanResult" ? <ScanResultScreen state={state} actions={actions} /> : null}
        {screen === "devices" ? <DevicesScreen state={state} actions={actions} /> : null}
        {screen === "detail" ? <DeviceDetailScreen state={state} actions={actions} /> : null}
        {screen === "guardian" ? <GuardianScreen state={state} actions={actions} /> : null}
        {screen === "alerts" ? <NotificationsScreen state={state} actions={actions} /> : null}
        {screen === "guardianMode" ? <GuardianModeScreen state={state} actions={actions} /> : null}
      </View>
      {showTabBar ? (
        <BottomTabBar
          active={activeTab}
          onChange={(tab) => actions.navigate(TAB_TO_SCREEN[tab])}
          unreadAlerts={unread}
          bottomInset={bottomInset}
        />
      ) : null}
    </SafeScreen>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <ThemeProvider>
        <AppShell />
      </ThemeProvider>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  content: {
    flex: 1,
  },
});
