import { AlertTriangle, ArrowRight, CheckCircle2, HelpCircle, Info, RefreshCw, ShieldCheck, Users } from "lucide-react-native";
import { useState } from "react";
import { Pressable, ScrollView, StyleSheet, Text, useWindowDimensions, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { Reveal } from "../components/DesignPrimitives";
import { StudioHero, StudioSignalRibbon, StudioSection } from "../components/StudioPrimitives";
import { ScoreRing } from "../components/ScoreRing";
import { ScreenHeader } from "../components/ScreenHeader";
import { StatusBanner } from "../components/StatusBanner";
import { TrafficLightBadge } from "../components/TrafficLightBadge";
import { spacing, tone, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import type { Device, RiskLevel } from "../api/types";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import { presentDevice, residentVisibleDevices } from "../utils/devicePresentation";
import { audienceRiskCopy, userHomeCopy } from "../utils/riskCopy";
import { shouldUseStackedCardLayout } from "../utils/responsiveLayout";
import {
  hasConfirmedRedRisk,
  scanCoverageState,
} from "../utils/scanCoverage";

type ScanResultScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

type LayoutEvent = {
  nativeEvent: {
    layout: {
      width: number;
    };
  };
};

/**
 * 점검의 첫 화면은 결과와 다음 행동을 한눈에 보여 주되, 불안감을 키우지 않는다.
 * 실제 상태를 먼저 설명하고, 사용자가 지금 할 수 있는 한 가지 행동을 바로 아래에 둔다.
 */
export function ScanResultScreen({ state, actions }: ScanResultScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const [scoreSummaryWidth, setScoreSummaryWidth] = useState<number | null>(null);
  const result = state.scanResult;
  const coverage = scanCoverageState(result);
  const isPartial = Boolean(result) && coverage.isPartial;
  const isNoTargets =
    Boolean(result) &&
    coverage.coverageComplete === true &&
    result?.security_score?.score_status === "no_targets";
  const provisionalScore =
    isPartial &&
    result?.security_score?.score_status === "provisional" &&
    typeof result.security_score.score === "number" &&
    Number.isFinite(result.security_score.score)
      ? result.security_score.score
      : null;
  const hasProvisionalScore = provisionalScore !== null;
  const score = isNoTargets ? null : isPartial ? provisionalScore : result?.security_score?.score ?? null;
  const confirmedRedRisk = hasConfirmedRedRisk(result);
  const scoreExplanation =
    isPartial
      ? hasProvisionalScore
        ? "이번에 확인한 연결 기준 점수예요. 집 전체 최종 점수가 아니며, 다시 점검하면 달라질 수 있어요."
        : "공유기에 연결된 물건을 모두 살펴보지 못해 점수를 확정하지 않았어요. 확인한 결과는 그대로 보관했어요."
      : isNoTargets
      ? "점검은 끝났지만 평가할 네트워크 기기가 없어 점수를 만들지 않았어요. 이 상태를 안전으로 표시하지 않아요."
      : score == null
      ? "점검 점수 정보가 없어 확인된 위험 상태를 먼저 보여 드려요."
      : "점수와 상태를 함께 보고 다음 행동을 고르세요.";
  const hasScan = Boolean(result);
  const level: RiskLevel = !hasScan || isNoTargets
    ? "unknown"
    : confirmedRedRisk
    ? "red"
    : score == null
    ? "yellow"
    : score >= 90
    ? "green"
    : score >= 60
    ? "yellow"
    : "red";
  const palette = tone(level, colors);
  const deviceCount = residentVisibleDevices(state.devices).length;
  const guardianCount = state.dashboard?.guardian_status.connected_guardians ?? state.guardians.length;
  const highRiskCount = result?.high_risk_devices ?? state.devices.filter((device) => device.risk_level === "red").length;
  const homeCopy = isPartial
    ? hasProvisionalScore
      ? {
          title: "점검을 일부만 마쳤어요",
          body: "확인한 물건의 점수는 계산했지만 놓친 연결이 있을 수 있어요. 집 전체 최종 점수로 보지 않아요.",
          actionTitle: "다음 할 일",
          actionBody: "와이파이가 안정되면 다시 점검해 집 전체 상태를 확인해 주세요.",
        }
      : {
         title: "점검을 일부만 마쳤어요",
         body: "확인한 물건은 보여 드리지만, 놓친 연결이 있을 수 있어요. 지금 결과만으로 집 전체가 안전하다고 판단하지 않아요.",
         actionTitle: "다음 할 일",
         actionBody: "와이파이가 안정되면 다시 점검하기 버튼을 눌러 주세요.",
        }
    : isNoTargets
    ? {
        title: "점검을 마쳤어요",
        body: "평가할 네트워크 기기는 확인되지 않았어요. 이 결과만으로 집이 안전하다고 판단하지 않아요.",
        actionTitle: "확인할 내용",
        actionBody: "공유기 앱이나 관리 화면에서 현재 연결된 기기가 있는지 확인해 주세요.",
      }
    : userHomeCopy(level, hasScan, highRiskCount);
  const statusLabel = isPartial
    ? confirmedRedRisk
      ? "부분 점검 · 위험"
      : hasProvisionalScore
      ? "부분 점검 · 확인분 점수"
      : "부분 점검"
    : isNoTargets
    ? "점검 완료 · 대상 없음"
    : level === "red"
    ? "위험"
    : level === "yellow"
    ? "주의"
    : level === "green"
    ? "안전"
    : "검사 전";
  const GuidanceIcon = level === "red" ? AlertTriangle : level === "yellow" ? HelpCircle : level === "green" ? CheckCircle2 : Info;
  const risks = !result
    ? []
    : [...result.devices]
        .filter((device) => device.risk_level === "red" || device.risk_level === "yellow")
        .sort((a, b) => (a.risk_level === "red" ? 0 : 1) - (b.risk_level === "red" ? 0 : 1))
        .slice(0, 3);
  const primaryActionLabel = hasScan ? "다시 점검하기" : "내 집 점검하기";
  const primaryActionIcon = hasScan ? RefreshCw : ShieldCheck;
  const runPrimaryAction = hasScan ? actions.retryScan : actions.startScan;
  // Before the first layout pass, prefer the safe stacked layout. Once measured,
  // keep the ring and its 220dp readable copy on one row only when both fit.
  const useCompactScoreLayout = scoreSummaryWidth == null || scoreSummaryWidth < 376;
  const updateScoreSummaryWidth = (width: number) => {
    setScoreSummaryWidth((previousWidth) =>
      previousWidth != null && Math.abs(previousWidth - width) < 1 ? previousWidth : width,
    );
  };

  return (
    <>
      <ScreenHeader
        title="오늘의 안전"
        right={
          hasScan ? (
            <Pressable
              accessibilityLabel="보호자 추가하기"
              accessibilityRole="button"
              android_ripple={{ color: colors.surfaceMuted, borderless: false }}
              onPress={() => actions.navigate("guardian")}
              style={({ pressed }: { pressed: boolean }) => [styles.iconButton, pressed ? styles.iconButtonPressed : null]}
            >
              <Users color={colors.textMuted} size={24} strokeWidth={2.4} />
            </Pressable>
          ) : null
        }
      />
      <ScrollView contentContainerStyle={styles.body}>
        <Reveal>
          <View testID="home-hero-card" style={styles.heroBox}>
            <StudioHero
              body={homeCopy.body}
              eyebrow={`오늘의 점검 · ${statusLabel}`}
              icon={GuidanceIcon}
              statusAccessibilityLabel={`오늘의 점검 상태: ${statusLabel}`}
              title={homeCopy.title}
              variant={hasScan ? "navy" : "paper"}
            >
            {hasScan ? (
              <>
                <TrafficLightBadge level={level} size="md" />
                <View
                  onLayout={(event: LayoutEvent) => updateScoreSummaryWidth(event.nativeEvent.layout.width)}
                  style={[styles.scoreSummary, useCompactScoreLayout ? styles.scoreSummaryCompact : null]}
                  testID="home-score-summary"
                >
                  <View style={[styles.scoreRingWrap, useCompactScoreLayout ? styles.scoreRingWrapCompact : null]}>
                    <ScoreRing
                      score={score}
                      size={132}
                      stroke={12}
                      emptyLabel={isPartial ? "범위 확인" : isNoTargets ? "대상 없음" : "점수 없음"}
                      emptyAccessibilityLabel={
                        isPartial
                          ? hasProvisionalScore
                            ? "이번에 확인한 연결 기준 점수입니다. 집 전체 최종 점수는 아니며 다시 점검하면 달라질 수 있습니다."
                            : "일부 연결만 확인되어 보안 점수를 확정하지 않았습니다. 와이파이가 안정되면 다시 점검해 주세요."
                          : isNoTargets
                          ? "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았습니다. 이 상태는 안전 점수가 아닙니다."
                          : "점검 점수 정보가 없습니다. 확인된 위험 상태를 먼저 살펴보세요."
                      }
                    />
                  </View>
                  <View style={[styles.scoreCopy, useCompactScoreLayout ? styles.scoreCopyCompact : null]}>
                    <Text style={[styles.scoreNote, hasScan ? styles.scoreNoteOnNavy : null]}>{scoreExplanation}</Text>
                  </View>
                </View>
              </>
            ) : (
              <View style={styles.preScanBadge}><Info color={colors.unknownStrong} size={22} strokeWidth={2.4} /><Text style={styles.preScanBadgeText}>첫 점검을 준비했어요</Text></View>
            )}
            </StudioHero>
          </View>
        </Reveal>

        {isPartial ? (
          <StatusBanner
            message={
              confirmedRedRisk
                ? "이번에는 일부 연결만 확인했지만 위험 신호를 찾았어요. 결과를 먼저 살펴보고 다시 점검해 주세요."
                : hasProvisionalScore
                ? `이번에 확인한 물건 ${deviceCount}개 기준 점수예요. 집 전체 점수는 아니므로 다시 점검해 주세요.`
                : `이번에는 일부 연결만 확인했어요. 확인된 물건 ${deviceCount}개는 보관했고, 다시 점검해 주세요.`
            }
            loading={false}
            tone={confirmedRedRisk ? "danger" : "warning"}
          />
        ) : state.statusMessage ? (
          <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
        ) : null}

        <View
          accessible
          accessibilityLabel={statusLabel + ". " + homeCopy.actionBody}
          testID="home-status-guidance"
          style={[styles.guidanceLine, { borderLeftColor: palette.fg }]}
        >
          <View style={[styles.guidanceIcon, { backgroundColor: palette.bg }]}>
            <GuidanceIcon color={palette.fg} size={28} strokeWidth={2.4} />
          </View>
          <View style={styles.guidanceText}>
            <Text style={[styles.guidanceTitle, { color: palette.fg }]}>{homeCopy.actionTitle}</Text>
            <Text style={styles.guidanceBody}>{homeCopy.actionBody}</Text>
          </View>
        </View>

        {/* 점검이 미완료여도 핵심 재시도 행동이 화면 아래로 밀리지 않는다. */}
        <View style={styles.primaryActionArea} testID="home-primary-scan-action-top">
          <BigCTAButton icon={primaryActionIcon} label={primaryActionLabel} tone="cta" onPress={runPrimaryAction} />
        </View>

        <StudioSection eyebrow="한눈에 보기" title="우리 집 요약" />
        <StudioSignalRibbon
          items={[
            { icon: ShieldCheck, label: isPartial ? "이번에 확인한 물건" : "확인한 물건", value: `${deviceCount}개` },
            {
              icon: AlertTriangle,
              label: "먼저 볼 것",
              value: `${highRiskCount}개`,
              level: highRiskCount > 0 ? "red" : isNoTargets ? "unknown" : "green",
            },
            { icon: Users, label: "연결된 보호자", value: `${guardianCount}명` },
          ]}
          testID="home-metric-rail"
        />

        {risks.length ? (
          <View style={styles.riskSection}>
            <View style={styles.riskSectionHeading}>
              <Text style={styles.riskSectionEyebrow}>확인할 순서</Text>
              <Text style={styles.riskSectionTitle}>먼저 확인할 물건</Text>
              <Text style={styles.riskSectionHint}>위험하거나 주의가 필요한 물건이에요.</Text>
            </View>
            <View style={styles.riskRows}>
              {risks.map((device, index) => (
                <Reveal key={device.device_id} delay={Math.min(index, 6) * 45}>
                  <RiskRow
                    colors={colors}
                    device={device}
                    onPress={() => actions.openDevice(device)}
                    styles={styles}
                  />
                </Reveal>
              ))}
            </View>
          </View>
        ) : null}

        {hasScan ? (
          <View style={styles.meta}>
            <Text style={styles.metaEyebrow}>이번 점검</Text>
            <Text style={styles.metaTitle}>
              {isPartial
                ? hasProvisionalScore
                  ? "이번에 확인한 연결 기준 점수예요"
                  : "이번에는 일부 연결만 확인했어요"
                : "우리 집 상태를 다시 확인했어요"}
            </Text>
            <Text style={styles.metaBody}>
              {isPartial ? "이번에 확인한 물건" : "우리 집 물건"} {String(deviceCount)}개 · 보호자 {String(guardianCount)}명 · 최근 점검 {formatLastScan(state.lastScanAt)}
            </Text>
          </View>
        ) : null}
      </ScrollView>
    </>
  );
}

function PreScanHero({
  colors,
  homeCopy,
  styles,
}: {
  colors: ThemeColors;
  homeCopy: ReturnType<typeof userHomeCopy>;
  styles: ReturnType<typeof createStyles>;
}) {
  return (
    <>
      <View style={styles.heroTopline}>
        <Text style={styles.heroEyebrow}>오늘의 점검</Text>
        <Text style={styles.heroState}>점검 전</Text>
      </View>
      <View style={styles.preScanLead}>
        <View style={[styles.preScanIcon, { backgroundColor: colors.unknownBg }]}>
          <Info color={colors.unknownStrong} size={38} strokeWidth={2.2} />
        </View>
        <View style={styles.preScanCopy}>
          <Text style={styles.title}>{homeCopy.title}</Text>
          <Text style={styles.heroBody}>{homeCopy.body}</Text>
        </View>
      </View>
    </>
  );
}

function ResultHero({
  homeCopy,
  level,
  paletteForeground,
  score,
  styles,
  useCompactLayout,
  onScoreSummaryLayout,
}: {
  homeCopy: ReturnType<typeof userHomeCopy>;
  level: RiskLevel;
  paletteForeground: string;
  score: number | null;
  styles: ReturnType<typeof createStyles>;
  useCompactLayout: boolean;
  onScoreSummaryLayout: (width: number) => void;
}) {
  return (
    <>
      <View style={styles.heroTopline}>
        <Text style={styles.heroEyebrow}>오늘의 점검</Text>
        <TrafficLightBadge level={level} size="md" />
      </View>
      <View
        onLayout={(event: LayoutEvent) => onScoreSummaryLayout(event.nativeEvent.layout.width)}
        style={[styles.scoreSummary, useCompactLayout ? styles.scoreSummaryCompact : null]}
        testID="home-score-summary"
      >
        <View style={[styles.scoreRingWrap, useCompactLayout ? styles.scoreRingWrapCompact : null]}>
          <ScoreRing score={score} size={132} stroke={12} />
        </View>
        <View style={[styles.scoreCopy, useCompactLayout ? styles.scoreCopyCompact : null]}>
          <Text style={[styles.title, { color: paletteForeground }]}>{homeCopy.title}</Text>
          <Text style={styles.heroBody}>{homeCopy.body}</Text>
          <Text style={styles.scoreNote}>점수와 상태를 함께 보고 다음 행동을 고르세요.</Text>
        </View>
      </View>
    </>
  );
}

function RiskRow({
  colors,
  device,
  onPress,
  styles,
}: {
  colors: ThemeColors;
  device: Device;
  onPress: () => void;
  styles: ReturnType<typeof createStyles>;
}) {
  const { width, fontScale } = useWindowDimensions();
  const compact = shouldUseStackedCardLayout(width, fontScale);
  const presented = presentDevice(device);
  if (!presented) return null;

  const copy = audienceRiskCopy(presented, "user");
  const palette = tone(presented.risk_level, colors);
  const copyBlock = (
    <View testID="home-risk-copy" style={[styles.riskRowCopy, compact ? styles.riskRowCopyCompact : null]}>
      <Text style={styles.riskName}>{presented.name}</Text>
      <Text style={styles.riskBody}>{copy.body}</Text>
    </View>
  );
  const badgeBlock = (
    <View style={[styles.riskBadgeWrap, { backgroundColor: palette.bg }]}>
      <TrafficLightBadge level={presented.risk_level} size="sm" />
    </View>
  );
  const arrowBlock = <ArrowRight color={palette.fg} size={28} strokeWidth={2.35} />;

  return (
    <Pressable
      accessibilityLabel={presented.name + ". " + copy.title + ". " + copy.actionLabel}
      accessibilityRole="button"
      android_ripple={{ color: colors.surfaceMuted, borderless: false }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [styles.riskRow, compact ? styles.riskRowCompact : null, pressed ? styles.riskRowPressed : null]}
      testID={"home-risk-" + presented.device_id}
    >
      {compact ? (
        <>
          <View testID="home-risk-compact-header" style={styles.riskRowHeader}>{badgeBlock}{arrowBlock}</View>
          {copyBlock}
        </>
      ) : (
        <><View style={styles.riskRowLead}>{badgeBlock}{copyBlock}</View>{arrowBlock}</>
      )}
    </Pressable>
  );
}

function formatLastScan(lastScanAt: string | null) {
  if (!lastScanAt) return "아직 없음";
  const date = new Date(lastScanAt);
  if (Number.isNaN(date.getTime())) return "확인 중";
  return String(date.getMonth() + 1) + "월 " + String(date.getDate()) + "일";
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    heroBox: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      gap: spacing.lg,
      paddingBottom: spacing.xl,
      paddingTop: spacing.lg,
    },
    heroTopline: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
      justifyContent: "space-between",
    },
    heroEyebrow: {
      color: colors.textMuted,
      flex: 1,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    heroState: {
      color: colors.unknownStrong,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    preScanLead: {
      alignItems: "flex-start",
      flexDirection: "column",
      gap: spacing.md,
    },
    preScanIcon: {
      alignItems: "center",
      borderRadius: 0,
      height: 88,
      justifyContent: "center",
      width: 88,
    },
    preScanCopy: {
      flex: 0,
      gap: spacing.sm,
      minWidth: 0,
      width: "100%",
    },
    title: {
      color: colors.text,
      fontSize: 40,
      fontWeight: "900",
      lineHeight: 50,
    },
    heroBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 31,
      maxWidth: 360,
    },
    scoreSummary: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.lg,
      width: "100%",
    },
    scoreSummaryCompact: {
      alignItems: "stretch",
      flexDirection: "column",
      gap: spacing.md,
    },
    scoreRingWrap: {
      alignItems: "center",
      justifyContent: "center",
      minWidth: 132,
    },
    scoreRingWrapCompact: {
      width: "100%",
    },
    scoreCopy: {
      flex: 1,
      gap: spacing.sm,
      minWidth: 220,
    },
    scoreCopyCompact: {
      flex: 0,
      minWidth: 0,
      width: "100%",
    },
    scoreNote: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    scoreNoteOnNavy: {
      color: colors.ctaText,
      opacity: 0.88,
    },
    preScanBadge: {
      alignItems: "center",
      alignSelf: "flex-start",
      backgroundColor: colors.unknownBg,
      borderColor: colors.borderSubtle,
      borderRadius: 0,
      borderWidth: 1,
      flexDirection: "row",
      gap: spacing.xs,
      minHeight: 56,
      paddingHorizontal: spacing.md,
    },
    preScanBadgeText: {
      color: colors.unknownStrong,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    guidanceLine: {
      alignItems: "center",
      borderLeftWidth: 5,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      flexDirection: "row",
      gap: spacing.md,
      minHeight: 104,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.md,
    },
    guidanceIcon: {
      alignItems: "center",
      borderRadius: 0,
      height: 56,
      justifyContent: "center",
      width: 56,
    },
    guidanceText: {
      flex: 1,
      gap: 4,
      minWidth: 0,
    },
    guidanceTitle: {
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    guidanceBody: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    riskSection: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
    },
    riskSectionHeading: {
      gap: spacing.xs,
      paddingVertical: spacing.lg,
      paddingBottom: spacing.md,
    },
    riskSectionEyebrow: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    riskSectionTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    riskSectionHint: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    riskRows: {
      paddingHorizontal: spacing.sm,
    },
    riskRow: {
      alignItems: "center",
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      flexDirection: "row",
      gap: spacing.sm,
      justifyContent: "space-between",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.md,
    },
    riskRowPressed: {
      backgroundColor: colors.surfaceMuted,
    },
    riskRowCompact: {
      alignItems: "stretch",
      flexDirection: "column",
    },
    riskRowHeader: {
      alignItems: "center",
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.sm,
      justifyContent: "space-between",
      width: "100%",
    },
    riskRowLead: {
      alignItems: "flex-start",
      flex: 1,
      flexDirection: "row",
      gap: spacing.sm,
      minWidth: 0,
    },
    riskBadgeWrap: {
      borderRadius: 0,
      padding: spacing.xs,
    },
    riskRowCopy: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    riskRowCopyCompact: {
      flex: 0,
      width: "100%",
    },
    riskName: {
      color: colors.text,
      fontSize: 22,
      fontWeight: "800",
      lineHeight: 30,
    },
    riskBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    primaryActionArea: {
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      paddingTop: spacing.lg,
    },
    iconButton: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 0,
      borderWidth: 1,
      height: touchTargetMin,
      justifyContent: "center",
      width: touchTargetMin,
    },
    iconButtonPressed: {
      backgroundColor: colors.surfaceMuted,
      opacity: 0.9,
      transform: [{ scale: 0.985 }],
    },
    meta: {
      backgroundColor: colors.bg,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.xs,
      paddingTop: spacing.lg,
    },
    metaEyebrow: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    metaTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    metaBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
  });
