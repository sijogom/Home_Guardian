import {
  Bell,
  Check,
  Clock,
  LogOut,
  Moon,
  ShieldCheck,
  Smartphone,
  Sun,
  Users,
  User as UserIcon,
} from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import { useState } from "react";
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import { ScreenHeader } from "../components/ScreenHeader";
import { StudioHero, StudioSignalRibbon, StudioSection } from "../components/StudioPrimitives";
import { StatusBanner } from "../components/StatusBanner";
import {
  spacing,
  touchTargetMin,
  type ThemeColors,
  type ThemePreference,
  useAppTheme,
  useThemedStyles,
} from "../theme";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";

type ProfileScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

const SCAN_INTERVAL_OPTIONS: Array<{ value: number; label: string; caption: string }> = [
  { value: 6, label: "6시간마다", caption: "더 자주 확인" },
  { value: 12, label: "12시간마다", caption: "하루 두 번" },
  { value: 24, label: "하루에 한 번", caption: "기본 추천" },
  { value: 72, label: "3일마다", caption: "여유 있게" },
  { value: 168, label: "일주일마다", caption: "가끔 확인" },
];

const THEME_OPTIONS: Array<{
  value: ThemePreference;
  label: string;
  description: string;
  icon: LucideIcon;
}> = [
  { value: "light", label: "밝게 보기", description: "흰색 바탕으로 봐요.", icon: Sun },
  { value: "dark", label: "어둡게 보기", description: "어두운 곳에서도 편하게 봐요.", icon: Moon },
  { value: "system", label: "휴대전화 설정", description: "휴대전화 화면 설정을 따라가요.", icon: Smartphone },
];

export function ProfileScreen({ state, actions }: ProfileScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const { mode, preference, setPreference } = useAppTheme();
  const [logoutPending, setLogoutPending] = useState(false);
  const nickname = state.user?.nickname ?? "이름 없음";
  const email = state.user?.email ?? "";
  const guardianCount = state.dashboard?.guardian_status.connected_guardians ?? state.guardians.length;

  const beginLogout = () => {
    if (logoutPending) return;
    setLogoutPending(true);
    void actions.logout().finally(() => setLogoutPending(false));
  };

  return (
    <>
      <ScreenHeader title="설정" />
      <ScrollView contentContainerStyle={styles.body}>
        <View key={mode} style={styles.themeBoundary} testID="profile-theme-boundary">
          <StudioHero
          body={email || "계정 연결 상태와 화면 설정을 여기에서 관리해요."}
          eyebrow="내 계정"
          icon={UserIcon}
          title={nickname}
          variant="navy"
        />
        <StudioSignalRibbon
          items={[
            { icon: ShieldCheck, label: "현재 모드", value: "사용자" },
            { icon: Users, label: "연결된 보호자", value: `${guardianCount}명` },
          ]}
          testID="profile-metric-rail"
        />

        {state.statusMessage && state.statusTone !== "info" ? (
          <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
        ) : null}

        <View style={styles.section}>
          <StudioSection eyebrow="필요한 소식" title="알림" body="위험 신호가 생겼을 때 필요한 알림을 받을 수 있어요." />
          <View style={styles.controlCard}>
            <Pressable
              accessibilityRole="switch"
              accessibilityLabel="위험 알림 받기"
              accessibilityHint="위험한 상태가 생기면 알려드려요."
              accessibilityState={{ checked: state.notificationsEnabled }}
              android_ripple={{ color: colors.surfaceMuted, borderless: false }}
              onPress={() => actions.setNotificationsEnabled(!state.notificationsEnabled)}
              style={({ pressed }: { pressed: boolean }) => [styles.toggleRow, pressed ? styles.rowPressed : null]}
            >
              <View style={styles.toggleIcon}>
                <Bell color={state.notificationsEnabled ? colors.cta : colors.textMuted} size={22} strokeWidth={2.4} />
              </View>
              <View style={styles.toggleBody}>
                <Text style={styles.toggleTitle}>위험할 때 알림 받기</Text>
                <Text style={styles.toggleSub}>{state.notificationsEnabled ? "알림을 받고 있어요" : "알림이 꺼져 있어요"}</Text>
              </View>
              <ToggleVisual active={state.notificationsEnabled} />
            </Pressable>
          </View>
        </View>

        <View style={styles.section}>
          <StudioSection eyebrow="잊지 않도록" title="정기 점검 알림" body="집을 확인할 시간을 정하면, 잊지 않도록 알려드려요." />
          <View style={styles.controlCard}>
            <Pressable
              accessibilityRole="switch"
              accessibilityLabel="정기 점검 알림 켜기"
              accessibilityHint="정해진 시간마다 점검을 시작하라고 알려드려요."
              accessibilityState={{ checked: state.autoScanEnabled }}
              android_ripple={{ color: colors.surfaceMuted, borderless: false }}
              onPress={() => void actions.setAutoScanEnabled(!state.autoScanEnabled)}
              style={({ pressed }: { pressed: boolean }) => [styles.toggleRow, pressed ? styles.rowPressed : null]}
            >
              <View style={styles.toggleIcon}>
                <Clock color={state.autoScanEnabled ? colors.cta : colors.textMuted} size={22} strokeWidth={2.4} />
              </View>
              <View style={styles.toggleBody}>
                <Text style={styles.toggleTitle}>점검 시간 알려주기</Text>
                <Text style={styles.toggleSub}>{state.autoScanEnabled ? "정기 알림을 받고 있어요" : "정기 알림이 꺼져 있어요"}</Text>
              </View>
              <ToggleVisual active={state.autoScanEnabled} />
            </Pressable>

            <View accessibilityState={{ disabled: !state.autoScanEnabled }} style={styles.intervalPanel}>
              <View style={styles.intervalHeader}>
                <Text style={[styles.intervalTitle, !state.autoScanEnabled ? styles.optionLabelDisabled : null]}>알림 주기</Text>
                <Text style={[styles.intervalHelper, !state.autoScanEnabled ? styles.optionLabelDisabled : null]}>
                  {state.autoScanEnabled ? "나에게 맞는 간격을 고르세요." : "정기 알림을 켜면 주기를 고를 수 있어요."}
                </Text>
              </View>
              <View style={styles.optionList}>
                {SCAN_INTERVAL_OPTIONS.map((option) => {
                  const selected = state.autoScanIntervalHours === option.value;
                  const disabled = !state.autoScanEnabled;
                  return (
                    <Pressable
                      key={option.value}
                      accessibilityRole="radio"
                      accessibilityLabel={option.label + " 주기"}
                    accessibilityState={{ disabled, selected }}
                    disabled={disabled}
                    android_ripple={{ color: colors.surfaceMuted, borderless: false }}
                    onPress={() => actions.setAutoScanIntervalHours(option.value)}
                      style={({ pressed }: { pressed: boolean }) => [
                        styles.optionRow,
                        selected && !disabled ? styles.optionRowSelected : null,
                        disabled ? styles.optionRowDisabled : null,
                        pressed && !disabled ? styles.rowPressed : null,
                      ]}
                    >
                      <View style={styles.optionCopy}>
                        <Text style={[styles.optionLabel, disabled ? styles.optionLabelDisabled : null]}>{option.label}</Text>
                        <Text style={[styles.optionCaption, disabled ? styles.optionLabelDisabled : null]}>{option.caption}</Text>
                      </View>
                      {selected && !disabled ? (
                        <View style={styles.optionCheck}>
                          <Check color={colors.ctaText} size={20} strokeWidth={3} />
                        </View>
                      ) : null}
                    </Pressable>
                  );
                })}
              </View>
            </View>
          </View>
        </View>

        <View style={styles.section}>
          <StudioSection eyebrow="보기 설정" title="화면 모양" body="보기 편한 화면을 고르세요. 언제든 다시 바꿀 수 있어요." />
          <View style={styles.themeOptions}>
            {THEME_OPTIONS.map((option) => {
              const selected = preference === option.value;
              const Icon = option.icon;
              return (
                <Pressable
                  key={option.value}
                  accessibilityRole="radio"
                  accessibilityLabel={option.label + " 화면"}
                  accessibilityHint={option.description}
                  accessibilityState={{ selected }}
                  android_ripple={{ color: colors.surfaceMuted, borderless: false }}
                  onPress={() => setPreference(option.value)}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.themeOption,
                    selected ? styles.themeOptionSelected : null,
                    pressed ? styles.rowPressed : null,
                  ]}
                >
                  <View style={[styles.appearanceIcon, selected ? styles.appearanceIconSelected : null]}>
                    <Icon color={selected ? colors.cta : colors.textMuted} size={24} strokeWidth={2.3} />
                  </View>
                  <View style={styles.themeOptionBody}>
                    <Text style={styles.themeOptionTitle}>{option.label}</Text>
                    <Text style={styles.themeOptionDescription}>{option.description}</Text>
                  </View>
                  <View style={[styles.radioMark, selected ? styles.radioMarkSelected : null]}>
                    {selected ? <Check color={colors.cta} size={20} strokeWidth={3} /> : null}
                  </View>
                </Pressable>
              );
            })}
          </View>
        </View>

        <View style={styles.accountSection}>
          <Text style={styles.accountSectionTitle}>계정</Text>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel="로그아웃"
            accessibilityState={{ busy: logoutPending, disabled: logoutPending }}
            android_ripple={{ color: colors.dangerBg, borderless: false }}
            disabled={logoutPending}
            onPress={beginLogout}
            style={({ pressed }: { pressed: boolean }) => [
              styles.logoutButton,
              logoutPending ? styles.logoutDisabled : null,
              pressed ? styles.logoutPressed : null,
            ]}
          >
            <View style={styles.logoutIcon}>
              {logoutPending ? (
                <ActivityIndicator color={colors.dangerStrong} size="small" />
              ) : (
                <LogOut color={colors.dangerStrong} size={22} strokeWidth={2.4} />
              )}
            </View>
            <View style={styles.logoutCopy}>
              <Text style={styles.logoutLabel}>{logoutPending ? "로그아웃하는 중…" : "로그아웃"}</Text>
              <Text style={styles.logoutHelper}>
                {logoutPending ? "계정 정보를 안전하게 정리하고 있어요." : "이 기기에서 내 계정으로 다시 로그인할 수 있어요."}
              </Text>
            </View>
          </Pressable>
        </View>

          <Text style={styles.version}>앱 버전 1.0.0</Text>
        </View>
      </ScrollView>
    </>
  );
}

function ToggleVisual({ active }: { active: boolean }) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View style={[styles.switch, { backgroundColor: active ? colors.cta : colors.divider }]}>
      <View style={[styles.thumb, active ? styles.thumbOn : styles.thumbOff]} />
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      backgroundColor: colors.bg,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    // Android의 DayNight uiMode가 바뀌면 ScrollView 밖에 있던 native child가
    // 이전 drawable을 유지할 수 있다. mode별 경계로 전체 내용만 다시 mount해
    // 스크롤 컨테이너는 유지하면서 모든 카드·텍스트·아이콘을 현재 palette로 만든다.
    themeBoundary: {
      gap: spacing.xl,
    },
    profileHero: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.lg,
      paddingVertical: spacing.lg,
    },
    profileHeader: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
    },
    avatar: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 32,
      height: 64,
      justifyContent: "center",
      width: 64,
    },
    profileText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    profileEyebrow: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    profileName: {
      color: colors.text,
      flexShrink: 1,
      fontSize: 32,
      fontWeight: "900",
      lineHeight: 40,
    },
    profileEmail: {
      color: colors.textMuted,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    accountSummary: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderTopColor: colors.divider,
      borderBottomWidth: 1,
      borderTopWidth: 1,
      gap: 1,
      paddingVertical: spacing.sm,
    },
    accountMetric: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.xs,
      justifyContent: "flex-start",
      minHeight: touchTargetMin,
      minWidth: 0,
      paddingHorizontal: spacing.sm,
    },
    metricIcon: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    metricCopy: {
      flex: 1,
      minWidth: 0,
    },
    accountDivider: {
      backgroundColor: colors.divider,
      height: 1,
      width: "100%",
    },
    accountLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    accountValue: {
      color: colors.text,
      fontSize: 20,
      fontVariant: ["tabular-nums"],
      fontWeight: "900",
      lineHeight: 30,
    },
    section: {
      gap: spacing.md,
    },
    sectionHeader: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    sectionIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    sectionHeaderText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    sectionTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    helper: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    controlCard: {
      backgroundColor: colors.surface,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.md,
    },
    toggleRow: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: touchTargetMin,
      paddingVertical: spacing.xs,
    },
    rowPressed: {
      backgroundColor: colors.infoBg,
    },
    toggleIcon: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    toggleBody: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    toggleTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    toggleSub: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    switch: {
      alignItems: "center",
      borderRadius: 16,
      flexDirection: "row",
      height: 32,
      padding: 3,
      width: 56,
    },
    thumb: {
      backgroundColor: colors.surface,
      borderRadius: 13,
      height: 26,
      width: 26,
    },
    thumbOn: {
      transform: [{ translateX: 24 }],
    },
    thumbOff: {
      transform: [{ translateX: 0 }],
    },
    intervalPanel: {
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.sm,
      paddingTop: spacing.md,
    },
    intervalHeader: {
      gap: 2,
    },
    intervalTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    intervalHelper: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    optionList: {
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
    },
    optionRow: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      flexDirection: "row",
      flexGrow: 1,
      flexBasis: "46%",
      gap: spacing.xs,
      justifyContent: "space-between",
      minHeight: touchTargetMin,
      minWidth: 144,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    optionRowSelected: {
      backgroundColor: colors.infoBg,
      borderColor: colors.cta,
    },
    optionRowDisabled: {
      opacity: 0.48,
    },
    optionCopy: {
      flex: 1,
      gap: 0,
      minWidth: 0,
    },
    optionLabel: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    optionCaption: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    optionLabelDisabled: {
      color: colors.textMuted,
    },
    optionCheck: {
      alignItems: "center",
      backgroundColor: colors.cta,
      borderRadius: 14,
      height: 28,
      justifyContent: "center",
      width: 28,
    },
    themeOptions: {
      gap: spacing.sm,
    },
    themeOption: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderBottomColor: colors.divider,
      borderTopColor: colors.divider,
      borderBottomWidth: 1,
      borderTopWidth: 1,
      borderWidth: 1,
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.md,
    },
    themeOptionSelected: {
      backgroundColor: colors.infoBg,
      borderColor: colors.cta,
      borderWidth: 2,
    },
    appearanceIcon: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    appearanceIconSelected: {
      backgroundColor: colors.surface,
    },
    themeOptionBody: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    themeOptionTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    themeOptionDescription: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    radioMark: {
      alignItems: "center",
      borderColor: colors.textMuted,
      borderRadius: 16,
      borderWidth: 2,
      height: 32,
      justifyContent: "center",
      width: 32,
    },
    radioMarkSelected: {
      borderColor: colors.cta,
    },
    accountSection: {
      gap: spacing.sm,
    },
    accountSectionTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    logoutButton: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderColor: colors.dangerStrong,
      borderBottomColor: colors.dangerStrong,
      borderBottomWidth: 1,
      borderLeftColor: colors.dangerStrong,
      borderLeftWidth: 5,
      borderTopColor: colors.dangerStrong,
      borderTopWidth: 1,
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: touchTargetMin,
      padding: spacing.md,
    },
    logoutPressed: {
      opacity: 0.72,
    },
    logoutDisabled: {
      opacity: 0.72,
    },
    logoutIcon: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    logoutCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    logoutLabel: {
      color: colors.dangerStrong,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    logoutHelper: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    version: {
      alignSelf: "center",
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
      paddingBottom: spacing.md,
    },
  });
