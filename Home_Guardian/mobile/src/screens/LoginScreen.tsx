import { CheckCircle2, ShieldCheck, Users } from "lucide-react-native";
import { ScrollView, StyleSheet, Text, View } from "react-native";

import { StudioCommand, StudioHero, StudioSection } from "../components/StudioPrimitives";
import { fontWeight, lineHeight, spacing, text, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";

type LoginScreenProps = { state: HomeGuardianState; actions: HomeGuardianActions };

/** Role entry keeps the existing navigation actions but uses the new Quiet Signal composition. */
export function LoginScreen({ state, actions }: LoginScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  void state;
  return (
    <ScrollView contentContainerStyle={styles.container} bounces={false}>
      <View style={styles.masthead}>
        <View style={styles.mark}><ShieldCheck color={colors.cta} size={27} strokeWidth={2.4} /></View>
        <Text style={styles.brand}>홈 가디언</Text>
        <View style={styles.versionPill}><View style={styles.liveDot} /><Text style={styles.version}>안전 시작</Text></View>
      </View>

      <StudioHero
        body="내 집이나 가족의 상태를 필요한 만큼만, 쉬운 말로 확인해요."
        eyebrow="안심을 시작하는 방법"
        icon={ShieldCheck}
        testID="login-focus-panel"
        title={"집의 상태를\n한눈에 봐요"}
        variant="navy"
      >
        <View style={styles.heroFooter}>
          <View style={styles.heroSignal}><View style={styles.heroSignalActive} /><View style={styles.heroSignalIdle} /><View style={styles.heroSignalIdle} /></View>
          <Text style={styles.heroFooterText}>필요한 것만 보여요.</Text>
        </View>
      </StudioHero>

      <StudioSection body="아래에서 하나를 골라 주세요." eyebrow="어떤 도움을 드릴까요?" title={"지금 필요한 화면을\n선택해요"} />

      <View style={styles.roleStack}>
        <StudioCommand
          accessibilityHint="내 집의 보안 점검을 시작하는 화면으로 이동합니다."
          accessibilityLabel="내 집 점검하기"
          body="집 상태와 다음 일을 알려드려요."
          emphasis
          icon={ShieldCheck}
          index="01"
          onPress={() => actions.navigate("userLogin")}
          testID="login-user-action"
          title="집 점검하기"
        />
        <StudioCommand
          accessibilityHint="보호자 로그인 화면으로 이동합니다."
          accessibilityLabel="보호자로 보기"
          body="가족 상태를 읽기 전용으로 봐요."
          icon={Users}
          index="02"
          onPress={actions.enterGuardianMode}
          testID="login-guardian-action"
          title="보호자 보기"
        />
      </View>

      <View style={styles.reassurance}>
        <CheckCircle2 color={colors.safeStrong} size={22} strokeWidth={2.35} />
        <View style={styles.reassuranceCopy}>
          <Text style={styles.reassuranceTitle}>처음이라도 괜찮아요.</Text>
          <Text style={styles.reassuranceText}>화면의 안내를 따라 천천히 시작하면 돼요.</Text>
        </View>
      </View>
    </ScrollView>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    container: { backgroundColor: colors.bg, flexGrow: 1, gap: spacing.xl, paddingBottom: spacing.xxl, paddingHorizontal: spacing.lg, paddingTop: spacing.md },
    masthead: { alignItems: "center", flexDirection: "row", gap: spacing.sm, minHeight: touchTargetMin, paddingVertical: spacing.xs },
    mark: { alignItems: "center", backgroundColor: colors.surfaceMuted, borderColor: colors.cta, borderWidth: 2, height: 52, justifyContent: "center", width: 52 },
    brand: { color: colors.text, flex: 1, fontSize: 28, fontWeight: fontWeight.title, letterSpacing: 0, lineHeight: 36 },
    versionPill: { alignItems: "center", backgroundColor: colors.surface, borderBottomColor: colors.divider, borderBottomWidth: 1, borderTopColor: colors.divider, borderTopWidth: 1, flexDirection: "row", gap: spacing.xs, minHeight: 44, justifyContent: "center", paddingHorizontal: spacing.sm },
    liveDot: { backgroundColor: colors.safeStrong, borderRadius: 999, height: 10, width: 10 },
    version: { color: colors.textMuted, fontSize: text.caption, fontWeight: fontWeight.label, lineHeight: lineHeight.caption },
    roleStack: { gap: spacing.md },
    heroFooter: { alignItems: "center", flexDirection: "row", gap: spacing.sm, marginTop: spacing.xs },
    heroSignal: { alignItems: "center", flexDirection: "row", gap: spacing.xs },
    heroSignalActive: { backgroundColor: colors.heroText, borderRadius: 999, height: 8, width: 56 },
    heroSignalIdle: { backgroundColor: colors.heroOutline, borderRadius: 999, height: 8, width: 28 },
    heroFooterText: { color: colors.heroText, fontSize: 20, fontWeight: "700", lineHeight: 28, opacity: 0.88 },
    reassurance: { alignItems: "flex-start", backgroundColor: colors.surfaceSoft, borderLeftColor: colors.safeStrong, borderLeftWidth: 4, borderTopColor: colors.divider, borderTopWidth: 1, flexDirection: "row", gap: spacing.sm, padding: spacing.md },
    reassuranceCopy: { flex: 1, gap: 2, minWidth: 0 },
    reassuranceTitle: { color: colors.text, fontSize: 20, fontWeight: "900", lineHeight: 30 },
    reassuranceText: { color: colors.textMuted, fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body, minWidth: 0 },
  });
