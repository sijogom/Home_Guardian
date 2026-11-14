import { CheckCircle2, LogIn, ShieldCheck } from "lucide-react-native";
import { ScrollView, StyleSheet, Text, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { StudioHero, StudioSection, StudioStatus } from "../components/StudioPrimitives";
import { ScreenHeader } from "../components/ScreenHeader";
import { spacing, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions, HomeGuardianState, StatusTone } from "../state/useHomeGuardianController";

type UserLoginScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

/** Account connection stays separate from the scan so the first action remains easy to understand. */
export function UserLoginScreen({ state, actions }: UserLoginScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const isPreparing = !state.isHydrated;
  const isBusy = state.isLoading;
  const statusMessage = isPreparing
    ? "앱을 준비하고 있어요. 잠시만 기다려 주세요."
    : state.statusMessage || (isBusy ? "Google 계정으로 연결하고 있어요." : "");
  const statusTone: StatusTone = isPreparing || (isBusy && !state.statusMessage) ? "info" : state.statusTone;
  const loginLabel = isPreparing
    ? "앱을 준비하고 있어요"
    : isBusy
      ? "계정을 연결하고 있어요"
      : "계정 연결하기";
  const loginAccessibilityLabel = isPreparing || isBusy ? loginLabel : "Google 계정으로 계속하기";

  return (
    <>
      <ScreenHeader title="내 집 점검 시작" onBack={() => actions.goBack() || actions.setScreen("login")} />
      <ScrollView contentContainerStyle={styles.container} keyboardShouldPersistTaps="handled">
        <View style={styles.stepRow}>
          <View style={styles.stepNumber}>
            <Text style={styles.stepNumberText}>1</Text>
          </View>
          <View style={styles.stepCopy}>
            <Text style={styles.stepEyebrow}>시작 단계</Text>
            <Text style={styles.stepTitle}>계정을 연결해요</Text>
          </View>
        </View>

        <StudioHero
          body={"점검 결과를\n안전하게 봐요."}
          eyebrow="내 집을 위한 안전 확인"
          icon={ShieldCheck}
          title="차근차근 시작할게요"
          variant="paper"
        />

        <StudioHero body="연결 뒤에만 점검 결과를 불러와요." eyebrow="다음 단계" title="계정을 연결해 주세요" variant="navy">
          <BigCTAButton
            label={loginLabel}
            accessibilityLabel={loginAccessibilityLabel}
            icon={LogIn}
            tone="cta"
            disabled={isPreparing || isBusy}
            onPress={actions.loginWithGoogle}
          />
          {statusMessage ? (
            <StudioStatus level={statusTone === "danger" ? "red" : statusTone === "warning" ? "yellow" : statusTone === "success" ? "green" : "unknown"} title={statusMessage} body={isPreparing || isBusy ? "잠시만 기다려 주세요." : undefined} />
          ) : null}
          <View style={styles.actionTrust}>
            <CheckCircle2 testID="user-login-trust-icon" color={colors.heroText} size={22} strokeWidth={2.35} />
            <Text testID="user-login-trust-copy" style={styles.actionTrustText}>위험한 것부터 쉬운 말로 알려드려요.</Text>
          </View>
        </StudioHero>

        <StudioSection eyebrow="안전한 연결" title="내 정보는 필요한 곳에만 사용해요." body="계정 연결이 끝나면 바로 내 집 점검을 시작할 수 있어요." />
      </ScrollView>
    </>
  );
}

const createStyles = (colors: ThemeColors) => StyleSheet.create({
  container: {
    gap: spacing.lg,
    padding: spacing.lg,
    paddingBottom: spacing.xxl,
  },
  stepRow: {
    alignItems: "center",
    flexDirection: "row",
    gap: spacing.sm,
  },
    stepNumber: {
      alignItems: "center",
      backgroundColor: colors.cta,
      height: 44,
    justifyContent: "center",
    width: 44,
  },
  stepNumberText: {
    color: colors.ctaText,
    fontSize: 20,
    fontWeight: "900",
    lineHeight: 28,
  },
  stepCopy: {
    flex: 1,
    gap: 1,
    minWidth: 0,
  },
  stepEyebrow: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 28,
  },
  stepTitle: {
    color: colors.text,
    fontSize: 24,
    fontWeight: "900",
    lineHeight: 32,
  },
  heroCard: {
    alignItems: "flex-start",
    backgroundColor: colors.bg,
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    gap: spacing.sm,
    paddingBottom: spacing.xl,
    paddingTop: spacing.lg,
  },
    iconCircle: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderColor: colors.borderStrong,
      borderWidth: 1,
    height: 72,
    justifyContent: "center",
    width: 72,
  },
  eyebrow: {
    color: colors.cta,
    fontSize: 20,
    fontWeight: "900",
    lineHeight: 28,
    paddingTop: spacing.xs,
  },
  title: {
    color: colors.text,
    fontSize: 32,
    fontWeight: "900",
    letterSpacing: 0,
    lineHeight: 40,
  },
  body: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 31,
    maxWidth: 440,
  },
  actionPanel: {
    backgroundColor: colors.bg,
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    borderTopColor: colors.divider,
    borderTopWidth: 1,
    gap: spacing.sm,
    paddingVertical: spacing.lg,
  },
  actionEyebrow: {
    color: colors.cta,
    fontSize: 20,
    fontWeight: "900",
    lineHeight: 28,
  },
  actionTitle: {
    color: colors.text,
    fontSize: 32,
    fontWeight: "900",
    lineHeight: 40,
  },
  actionBody: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
    paddingBottom: spacing.xs,
  },
  actionTrust: {
    alignItems: "center",
    borderTopColor: colors.heroOutline,
    borderTopWidth: 1,
    flexDirection: "row",
    gap: spacing.xs,
    minHeight: 56,
    paddingTop: spacing.sm,
  },
  actionTrustText: {
    color: colors.heroText,
    flex: 1,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 30,
    minWidth: 0,
  },
  privacyNote: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
    textAlign: "center",
  },
});
