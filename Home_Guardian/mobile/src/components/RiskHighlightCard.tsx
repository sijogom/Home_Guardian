import { ArrowRight } from "lucide-react-native";
import { Pressable, StyleSheet, Text, useWindowDimensions, View } from "react-native";

import type { Device } from "../api/types";
import {
  fontWeight,
  lineHeight,
  motion,
  radius,
  spacing,
  text,
  touchTargetMin,
  tone,
  type ThemeColors,
  useThemedStyles,
} from "../theme";
import { deviceIcon } from "../utils/deviceIcons";
import { canonicalDeviceName, presentDevice, residentDeviceAccessibilityLabel } from "../utils/devicePresentation";
import { audienceRiskCopy, type RiskAudience } from "../utils/riskCopy";
import { shouldUseStackedCardLayout } from "../utils/responsiveLayout";
import { Reveal } from "./DesignPrimitives";
import { TrafficLightBadge } from "./TrafficLightBadge";

type RiskHighlightCardProps = {
  device: Device;
  onFix: () => void;
  audience?: RiskAudience;
};

/** Keeps one important risk calm: identify it, explain it, then surface the single next step. */
export function RiskHighlightCard({ device, onFix, audience = "user" }: RiskHighlightCardProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const { width, fontScale } = useWindowDimensions();
  const compact = shouldUseStackedCardLayout(width, fontScale);
  const presentedDevice = presentDevice(device);
  if (!presentedDevice) return null;

  const palette = tone(presentedDevice.risk_level, colors);
  const Glyph = deviceIcon(presentedDevice.device_type);
  const copy = audienceRiskCopy(presentedDevice, audience);
  const guardian = audience === "guardian";
  const canonicalName = canonicalDeviceName(presentedDevice);
  const canonicalLabel = presentedDevice.model ? "확인된 제품 이름과 품번" : "확인된 제품군";
  const accessibilityName = residentDeviceAccessibilityLabel(presentedDevice);
  const iconBlock = (
    <View style={[styles.iconBox, { backgroundColor: palette.bg }]}>
      <Glyph color={palette.fg} size={32} strokeWidth={2} />
    </View>
  );
  const identityBlock = (
    <View testID="risk-highlight-identity" style={[styles.head, compact ? styles.headCompact : null]}>
      <Text style={styles.name} accessibilityLabel={accessibilityName}>
        {presentedDevice.name}
      </Text>
      {canonicalName ? (
        <View style={styles.canonicalInfo}>
          <Text style={styles.canonicalLabel}>{canonicalLabel}</Text>
          <Text style={styles.canonicalName} accessibilityLabel={`${canonicalLabel}: ${canonicalName}`}>
            {canonicalName}
          </Text>
        </View>
      ) : null}
    </View>
  );
  const statusBlock = <TrafficLightBadge level={presentedDevice.risk_level} size="sm" />;

  return (
    <Reveal>
      <View style={[styles.card, { borderLeftColor: palette.fg }]}>
        <View pointerEvents="none" style={styles.cardGlow} />
        <View
          testID={compact ? "risk-highlight-compact-layout" : "risk-highlight-wide-layout"}
          style={[styles.top, compact ? styles.topCompact : null]}
        >
          {compact ? (
            <>
              <View style={styles.compactHeader}>{iconBlock}{statusBlock}</View>
              {identityBlock}
            </>
          ) : (
            <>{iconBlock}{identityBlock}{statusBlock}</>
          )}
        </View>

        <View style={styles.divider} />
        <Text style={styles.alertTitle}>{copy.title}</Text>
        <Text style={styles.summary}>{copy.body}</Text>
        {guardian ? (
          <View style={styles.diagnosisBox}>
            <Text style={styles.diagnosisLabel}>확인 근거</Text>
            <Text style={styles.diagnosisText}>{copy.reason}</Text>
            <Text style={styles.diagnosisLabel}>권장 조치</Text>
            <Text style={styles.diagnosisText}>{copy.fix}</Text>
          </View>
        ) : null}
        <Pressable
          accessibilityLabel={`${accessibilityName}. ${copy.actionLabel}`}
          accessibilityRole="button"
          android_ripple={{ color: colors.surfaceMuted, borderless: false }}
          onPress={onFix}
          style={({ pressed }: { pressed: boolean }) => [styles.fixButton, pressed ? styles.fixPressed : null]}
        >
          <Text style={styles.fixLabel}>{copy.actionLabel}</Text>
          <ArrowRight color={colors.cta} size={24} strokeWidth={2.35} />
        </Pressable>
      </View>
    </Reveal>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    card: {
      backgroundColor: colors.surface,
      borderBottomColor: colors.divider,
      borderLeftColor: colors.dangerStrong,
      borderLeftWidth: 4,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      marginBottom: spacing.sm,
      overflow: "hidden",
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.lg,
      position: "relative",
    },
    cardGlow: {
      backgroundColor: colors.surfaceSoft,
      height: 220,
      opacity: 0.5,
      position: "absolute",
      right: -108,
      top: -136,
      width: 220,
    },
    top: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    topCompact: {
      flexDirection: "column",
      width: "100%",
    },
    compactHeader: {
      alignItems: "center",
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.sm,
      justifyContent: "space-between",
      width: "100%",
    },
    iconBox: {
      alignItems: "center",
      borderRadius: radius.sm,
      height: 64,
      justifyContent: "center",
      width: 64,
    },
    head: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    headCompact: {
      flex: 0,
      width: "100%",
    },
    name: {
      color: colors.text,
      flexShrink: 1,
      fontSize: text.section,
      fontWeight: fontWeight.section,
      lineHeight: lineHeight.section,
    },
    canonicalInfo: {
      gap: 2,
    },
    canonicalLabel: {
      color: colors.textMuted,
      fontSize: text.caption,
      fontWeight: fontWeight.label,
      lineHeight: lineHeight.caption,
    },
    canonicalName: {
      color: colors.text,
      flexShrink: 1,
      fontSize: text.body,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.body,
    },
    divider: {
      backgroundColor: colors.divider,
      height: 1,
      width: "100%",
    },
    alertTitle: {
      color: colors.text,
      fontSize: text.title,
      fontWeight: fontWeight.metric,
      lineHeight: lineHeight.title,
    },
    summary: {
      color: colors.text,
      fontSize: text.body,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.body,
    },
    diagnosisBox: {
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.xs,
      paddingTop: spacing.md,
    },
    diagnosisLabel: {
      color: colors.text,
      fontSize: text.caption,
      fontWeight: fontWeight.metric,
      lineHeight: lineHeight.caption,
      marginTop: spacing.xs,
    },
    diagnosisText: {
      color: colors.text,
      fontSize: text.body,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.body,
    },
    fixButton: {
      alignItems: "center",
      alignSelf: "stretch",
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      flexDirection: "row",
      justifyContent: "space-between",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
    },
    fixPressed: {
      backgroundColor: colors.surfaceMuted,
      opacity: motion.pressOpacity,
      transform: [{ scale: motion.pressScale }],
    },
    fixLabel: {
      color: colors.cta,
      fontSize: text.bodyStrong,
      fontWeight: fontWeight.bodyStrong,
      lineHeight: lineHeight.bodyStrong,
    },
  });
