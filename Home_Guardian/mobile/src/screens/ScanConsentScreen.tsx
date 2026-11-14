import { ArrowRight, Info, Wifi, CheckCircle2 } from "lucide-react-native";
import { ScrollView, StyleSheet, Text, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { StudioCommand, StudioHero, StudioSection } from "../components/StudioPrimitives";
import { ScreenHeader } from "../components/ScreenHeader";
import { radius, spacing, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions } from "../state/useHomeGuardianController";

type ScanConsentScreenProps = {
  actions: HomeGuardianActions;
};

/**
 * 실제 점검 전에 위험을 미리 표시하지 않는다.
 * 사용자가 준비할 것과 한 번의 시작 행동만 보여 준다.
 */
export function ScanConsentScreen({ actions }: ScanConsentScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);

  return (
    <>
      <ScreenHeader title="안전 점검" onBack={() => actions.goBack() || actions.setScreen("scanResult")} />
      <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
        <StudioHero
          body="우리 집 와이파이에 연결된 물건을 살펴보는 데 1분 정도 걸려요."
          eyebrow="점검 전 확인"
          icon={Info}
          title="아직 점검하지 않았어요"
          variant="paper"
        >
          <View style={styles.durationPill}><View style={styles.durationDot} /><Text style={styles.duration}>약 1분이면 충분해요</Text></View>
        </StudioHero>

        <StudioSection body="시작하기 전에 두 가지만 확인해 주세요." eyebrow="준비 안내" title="준비가 되었나요?" />
        <View style={styles.preparationList}>
          <StudioCommand icon={Wifi} index="01" title="와이파이 연결" body="휴대폰을 우리 집 와이파이에 연결해 주세요." />
          <StudioCommand icon={CheckCircle2} index="02" title="잠시 기다리기" body="권한을 물으면 허용하고 그대로 기다려 주세요." />
        </View>

        <View style={styles.actionArea}>
          <Text style={styles.actionHint}>준비가 되면 아래 버튼을 눌러 주세요.</Text>
          <BigCTAButton
            label="내 집 점검하기"
            icon={ArrowRight}
            tone="cta"
            onPress={actions.beginNetworkScan}
          />
        </View>
      </ScrollView>
    </>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      flexGrow: 1,
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    durationPill: { alignItems: "center", alignSelf: "flex-start", backgroundColor: colors.infoBg, borderColor: colors.borderSubtle, borderRadius: radius.pill, borderWidth: 1, flexDirection: "row", gap: spacing.xs, minHeight: 56, justifyContent: "center", paddingHorizontal: spacing.md },
    durationDot: { backgroundColor: colors.cta, borderRadius: radius.pill, height: 10, width: 10 },
    duration: { color: colors.unknownStrong, fontSize: 20, fontWeight: "800", lineHeight: 28 },
    preparationList: { gap: spacing.md },
    actionArea: {
      gap: spacing.sm,
    },
    actionHint: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
      textAlign: "center",
    },
  });
