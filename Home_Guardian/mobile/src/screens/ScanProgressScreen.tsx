import { AlertTriangle } from "lucide-react-native";
import { useState } from "react";
import { ScrollView, StyleSheet, Text, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { StudioStageRail, StudioHero, StudioSection } from "../components/StudioPrimitives";
import { ProgressRing } from "../components/ProgressRing";
import { ScanStepRow } from "../components/ScanStepRow";
import { ScreenHeader } from "../components/ScreenHeader";
import { StatusBanner } from "../components/StatusBanner";
import { radius, spacing, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions, HomeGuardianState, ScanStep } from "../state/useHomeGuardianController";

type ScanProgressScreenProps = {
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
 * 진행 화면은 검사 엔진의 내부 용어를 노출하지 않는다.
 * 현재 단계, 쉬운 설명, 진행 정도를 하나의 영역에서 함께 전달한다.
 */
export function ScanProgressScreen({ state, actions }: ScanProgressScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const [heroWidth, setHeroWidth] = useState<number | null>(null);
  const visibleSteps = state.scanUi.steps.filter((step) => step.key !== "guardian");
  const current = visibleSteps.find((step) => step.state === "running") ?? visibleSteps[visibleSteps.length - 1];
  const hasError = state.scanUi.errorCode !== null;
  const isPartial = !hasError && (state.scanUi.coverageComplete === false || state.scanUi.tcpScanTimedOut);
  const stepTotal = Math.max(1, visibleSteps.length);
  const completedCount = visibleSteps.filter((step) => step.state === "completed").length;
  const currentStepNumber = hasError ? Math.max(1, completedCount) : Math.min(stepTotal, completedCount + 1);
  const headline = headlineFor(current);
  const useCompactHero = heroWidth == null || heroWidth < 340;
  const updateHeroWidth = (width: number) => {
    setHeroWidth((previousWidth) =>
      previousWidth != null && Math.abs(previousWidth - width) < 1 ? previousWidth : width,
    );
  };
  const supportingMessage = hasError
    ? state.scanUi.errorMessage || state.statusMessage || "점검을 끝내지 못했어요. 다시 확인해 주세요."
    : isPartial
    ? "이번에는 공유기에 연결된 물건을 모두 살펴보지 못했어요. 확인한 내용은 지우지 않고 안전하게 보관하고 있어요."
    : current?.detail || headline;
  const rawAdditionalStatusMessage =
    state.statusMessage && state.statusMessage !== supportingMessage
      ? state.statusMessage
      : "";
  const additionalStatusMessage = /식별\s*대기|점수\s*보류|제품(?:\s*정보)?\s*확인(?:이)?\s*필요/.test(
    rawAdditionalStatusMessage,
  )
    ? ""
    : rawAdditionalStatusMessage;
  const progressLabel = hasError
    ? "점검을 다시 준비해요"
    : isPartial
    ? "부분 점검 · 결과 정리 중"
    : String(currentStepNumber) + " / " + String(stepTotal) + " 단계";

  return (
    <>
      <ScreenHeader title="안전 점검" />
      <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
        <StudioHero
          body={supportingMessage}
          eyebrow={progressLabel}
          statusAccessibilityLabel={hasError ? "점검 상태: 확인 필요" : isPartial ? "점검 상태: 부분 점검" : "점검 상태: 진행 중"}
          title={hasError ? "잠시 멈췄어요" : isPartial ? "일부 연결만 확인했어요" : headline}
          titleAccessibilityLiveRegion="polite"
          variant={hasError || isPartial ? "paper" : "navy"}
        >
          <View
            onLayout={(event: LayoutEvent) => updateHeroWidth(event.nativeEvent.layout.width)}
            style={[styles.heroTop, useCompactHero ? styles.heroTopCompact : null]}
            testID="scan-progress-hero-top"
          >
            <View
              style={[
                styles.progressVisual,
                hasError ? styles.progressVisualError : null,
                useCompactHero ? styles.progressVisualCompact : null,
              ]}
            >
              {hasError ? (
                <View style={[styles.errorIcon, { backgroundColor: colors.dangerBg }]}>
                  <AlertTriangle color={colors.dangerStrong} size={42} strokeWidth={2.3} />
                </View>
              ) : (
                <ProgressRing size={116} stroke={10} />
              )}
            </View>
          </View>
        </StudioHero>

        {isPartial ? (
          <View accessible accessibilityLabel="부분 점검. 확인한 결과는 보관 중이며 다시 점검할 수 있습니다." style={styles.partialNotice} testID="scan-partial-notice">
            <Text style={styles.partialNoticeTitle}>확인한 결과는 그대로 보관해요</Text>
            <Text style={styles.partialNoticeBody}>점수를 확정하지 않고, 와이파이가 안정되면 다시 점검할 수 있게 준비하고 있어요.</Text>
          </View>
        ) : (
          <StudioStageRail
            stages={visibleSteps.map((step) => ({ label: step.title, state: step.state }))}
            testID="scan-stage-rail"
          />
        )}

        {hasError ? (
          additionalStatusMessage ? <StatusBanner message={additionalStatusMessage} loading={false} tone="danger" /> : null
        ) : additionalStatusMessage ? (
          <StatusBanner message={additionalStatusMessage} loading={state.isLoading} tone={state.statusTone} />
        ) : null}

        {!isPartial ? <View style={styles.stepsCard}>
          <View style={styles.stepsHeading}>
            <View style={styles.stepsHeadingCopy}>
              <StudioSection body="한 단계씩 차분하게 진행하고 있어요." eyebrow="점검 순서" title="지금 어디까지 왔는지 보여 드려요" />
            </View>
            <Text style={styles.stepsCount}>{String(completedCount)}개 완료</Text>
          </View>
          <View style={styles.steps}>
            {visibleSteps.map((step) => (
              <ScanStepRow key={step.key} step={step} />
            ))}
          </View>
        </View> : null}

        {hasError || (isPartial && !state.isLoading) ? (
          <View style={styles.errorActions}>
            <Text style={styles.errorActionHint}>{hasError ? "와이파이를 확인한 뒤 다시 시도해 주세요." : "잠시 후 다시 점검해 주세요."}</Text>
            <BigCTAButton label="다시 점검하기" tone="cta" onPress={actions.retryScan} />
          </View>
        ) : null}
      </ScrollView>
    </>
  );
}

function headlineFor(step?: ScanStep) {
  if (!step) return "결과를 정리하고 있어요";
  switch (step.key) {
    case "wifi":
      return "와이파이를 확인하고 있어요";
    case "discovery":
      return "집에 있는 물건을 찾고 있어요";
    case "services":
      return "물건의 상태를 확인하고 있어요";
    case "analysis":
      return "안전 상태를 살펴보고 있어요";
    case "guardian":
      return "결과를 정리하고 있어요";
    default:
      return "결과를 정리하고 있어요";
  }
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      flexGrow: 1,
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
    heroTop: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.lg,
    },
    heroTopCompact: {
      alignItems: "stretch",
      flexDirection: "column",
    },
    progressVisual: {
      alignItems: "center",
      justifyContent: "center",
      minHeight: 116,
      minWidth: 116,
    },
    progressVisualCompact: {
      alignSelf: "center",
    },
    progressVisualError: {
      backgroundColor: colors.dangerBg,
      borderRadius: 58,
    },
    errorIcon: {
      alignItems: "center",
      borderRadius: 58,
      height: 116,
      justifyContent: "center",
      width: 116,
    },
    heroCopy: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 200,
    },
    heroCopyCompact: {
      flex: 0,
      minWidth: 0,
      width: "100%",
    },
    stepLabel: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    stepLabelError: {
      color: colors.dangerStrong,
    },
    title: {
      color: colors.text,
      fontSize: 32,
      fontWeight: "900",
      lineHeight: 40,
    },
    supportingCard: {
      backgroundColor: colors.surfaceMuted,
      borderLeftColor: colors.cta,
      borderLeftWidth: 4,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.sm,
    },
    supportingCardError: {
      backgroundColor: colors.dangerBg,
    },
    note: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    stepsCard: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
    },
    stepsHeading: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.md,
      justifyContent: "space-between",
      paddingVertical: spacing.lg,
      paddingBottom: spacing.md,
    },
    stepsHeadingCopy: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    stepsEyebrow: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    stepsTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    stepsCount: {
      color: colors.calmStrong,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
      textAlign: "right",
    },
    steps: {
      backgroundColor: colors.bg,
      gap: 4,
      paddingHorizontal: spacing.sm,
    },
    errorActions: {
      backgroundColor: colors.bg,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingTop: spacing.lg,
    },
    partialNotice: {
      backgroundColor: colors.warnBg,
      borderLeftColor: colors.warnStrong,
      borderLeftWidth: 5,
      gap: spacing.xs,
      padding: spacing.lg,
    },
    partialNoticeTitle: {
      color: colors.warnStrong,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    partialNoticeBody: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    errorActionHint: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
      textAlign: "center",
    },
  });
