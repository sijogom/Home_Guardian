import { AlertTriangle, CheckCircle2, HelpCircle, ShieldCheck } from "lucide-react-native";
import { ScrollView, StyleSheet, Text, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { StudioHero, StudioSignalRibbon, StudioSection } from "../components/StudioPrimitives";
import { DeviceCard } from "../components/DeviceCard";
import { EmptyState } from "../components/EmptyState";
import { ScreenHeader } from "../components/ScreenHeader";
import { spacing, type ThemeColors, useThemedStyles } from "../theme";
import type { Device, RiskLevel } from "../api/types";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import { residentVisibleDevices } from "../utils/devicePresentation";

type DevicesScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

const ORDER: Record<RiskLevel, number> = { red: 0, yellow: 1, green: 2, unknown: 3 };

// 기기 목록은 위험한 순서로 정렬한다. 상단은 필요한 안내만 요약하고,
// 각 상태와 전체 목록은 그 아래에서 차분히 확인하도록 분리한다.
export function DevicesScreen({ state, actions }: DevicesScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const visibleDevices = residentVisibleDevices(state.devices);
  if (visibleDevices.length === 0) {
    return (
      <>
        <ScreenHeader title="우리 집 물건" />
        <ScrollView style={styles.emptyScroll} contentContainerStyle={styles.empty}>
          <EmptyState
            icon={ShieldCheck}
            title={state.scanResult ? "연결된 물건을 찾지 못했어요" : "아직 점검하지 않았어요"}
            body={state.scanResult ? "이번 점검에서는 공유기에 연결된 물건의 응답을 받지 못했어요." : "내 집을 한 번 점검하면 확인할 물건을 여기에서 차분히 정리해 드려요."}
            action={<BigCTAButton label="내 집 점검하기" icon={ShieldCheck} tone="cta" onPress={actions.startScan} />}
          />
        </ScrollView>
      </>
    );
  }

  const sorted: Device[] = [...visibleDevices].sort(
    (a, b) => ORDER[a.risk_level] - ORDER[b.risk_level],
  );
  const redCount = visibleDevices.filter((device) => device.risk_level === "red").length;
  const yellowCount = visibleDevices.filter((device) => device.risk_level === "yellow").length;
  const greenCount = visibleDevices.filter((device) => device.risk_level === "green").length;
  const detectedCount = visibleDevices.length;
  const pendingCount = visibleDevices.filter((device) => device.is_identity_finding === true).length;
  const identifiedCount = detectedCount - pendingCount;
  const title = redCount > 0
      ? "먼저 확인할 물건이 있어요"
      : yellowCount > 0
      ? "확인하면 좋은 물건이 있어요"
      : "우리 집 물건을 확인했어요";
  const body = redCount > 0
      ? "위험한 물건부터 차례로 보고, 혼자 해결하기 어렵다면 보호자에게 보여 주세요."
      : yellowCount > 0
      ? "주의가 필요한 물건을 쉬운 순서대로 확인해 보세요."
      : "새 물건을 연결하거나 설정을 바꾼 뒤에는 다시 점검해 주세요.";

  return (
    <>
      <ScreenHeader title="우리 집 물건" />
      <ScrollView contentContainerStyle={styles.body}>
        <View testID="devices-hero-card" style={styles.heroFrame}>
          <StudioHero
            body={body}
            eyebrow={`감지된 연결 ${detectedCount}개 · 제품명 확인 ${identifiedCount}개`}
            icon={redCount > 0 ? AlertTriangle : ShieldCheck}
            title={title}
            variant="navy"
          >
            {redCount > 0 ? (
              <View
                accessible
                accessibilityLabel={`위험 기기 ${redCount}개를 먼저 이어서 확인하세요.`}
                testID="high-risk-warning"
                style={styles.priorityRow}
              >
                <View testID="high-risk-status-icon" style={[styles.priorityIcon, { backgroundColor: colors.dangerBg }]}>
                  <AlertTriangle color={colors.dangerStrong} size={24} strokeWidth={2.7} />
                </View>
                <View style={styles.priorityText}>
                  <Text style={styles.priorityTitle}>위험한 물건 {redCount}개</Text>
                  <Text style={styles.priorityBody}>보호자에게도 함께 보여 주세요.</Text>
                </View>
              </View>
            ) : null}
          </StudioHero>
        </View>

        <StudioSection body="어디부터 살펴볼지 한눈에 알려 드려요." eyebrow="상태별 보기" title="확인 순서" />
        <StudioSignalRibbon
          items={[
            { icon: AlertTriangle, label: "먼저 볼 것", value: `${redCount}개`, level: "red" },
            { icon: HelpCircle, label: "확인할 것", value: `${yellowCount}개`, level: "yellow" },
            { icon: CheckCircle2, label: "안전한 것", value: `${greenCount}개`, level: "green" },
          ]}
          testID="devices-metric-rail"
        />

        <StudioSection
          body={pendingCount > 0 ? "제품 이름을 보내지 않은 연결은 확인된 종류와 보안 상태로 함께 표시했어요." : "필요한 순서대로 정리했어요."}
          eyebrow="전체 목록"
          title="우리 집 물건"
        />
        <View style={styles.list}>
          {sorted.map((device, index) => (
            <DeviceCard
              index={index}
              key={device.device_id}
              device={device}
              onPress={() => actions.openDevice(device)}
            />
          ))}
        </View>
      </ScrollView>
    </>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    heroFrame: { backgroundColor: colors.bg, borderBottomColor: colors.divider, borderBottomWidth: 1, borderTopColor: colors.divider, borderTopWidth: 1 },
    hero: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      gap: spacing.sm,
      paddingBottom: spacing.xl,
      paddingTop: spacing.lg,
    },
    heroTopline: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
      justifyContent: "space-between",
    },
    eyebrow: {
      color: colors.cta,
      flex: 1,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    totalCount: {
      color: colors.textMuted,
      fontSize: 20,
      fontVariant: ["tabular-nums"],
      fontWeight: "800",
      lineHeight: 28,
      textAlign: "right",
    },
    heroTitle: {
      color: colors.text,
      fontSize: 40,
      fontWeight: "900",
      lineHeight: 50,
    },
    intro: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
      maxWidth: 440,
    },
    priorityRow: {
      alignItems: "center",
      backgroundColor: colors.dangerBg,
      borderLeftColor: colors.dangerStrong,
      borderLeftWidth: 5,
      flexDirection: "row",
      gap: spacing.sm,
      marginTop: spacing.sm,
      minHeight: 88,
      padding: spacing.md,
    },
    priorityIcon: {
      alignItems: "center",
      borderRadius: 0,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    priorityText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    priorityTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    priorityBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    summaryCard: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
    },
    summaryHeading: {
      gap: spacing.xs,
      paddingVertical: spacing.lg,
      paddingBottom: spacing.md,
    },
    summaryEyebrow: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    summaryTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    summaryList: {
      paddingHorizontal: spacing.sm,
    },
    summaryItem: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: 72,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.sm,
    },
    summaryItemDivider: {
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
    },
    summaryIcon: {
      alignItems: "center",
      borderRadius: 0,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    summaryLabel: {
      color: colors.text,
      flex: 1,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    summaryValueWrap: {
      alignItems: "flex-end",
      minWidth: 56,
    },
    summaryValue: {
      color: colors.text,
      fontSize: 20,
      fontVariant: ["tabular-nums"],
      fontWeight: "900",
      lineHeight: 30,
    },
    listHeading: {
      gap: spacing.xs,
    },
    listEyebrow: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    sectionTitle: {
      color: colors.text,
      fontSize: 32,
      fontWeight: "900",
      lineHeight: 40,
    },
    listHint: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    list: {
      backgroundColor: colors.surface,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
    },
    empty: {
      flexGrow: 1,
      justifyContent: "center",
      padding: spacing.lg,
    },
    emptyScroll: {
      flex: 1,
    },
    researchNotice: {
      backgroundColor: colors.warnBg,
      borderLeftColor: colors.warnStrong,
      borderLeftWidth: 5,
      gap: spacing.md,
      padding: spacing.lg,
    },
    researchNoticeTitle: {
      color: colors.warnStrong,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    researchNoticeBody: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
  });
