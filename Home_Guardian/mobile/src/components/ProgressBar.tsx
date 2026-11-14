import { StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, type ThemeColors, useThemedStyles } from "../theme";

type ProgressBarTone = "info" | "success" | "warning" | "danger";

type ProgressBarProps = {
  value: number;
  label?: string;
  tone?: ProgressBarTone;
};

export function ProgressBar({ value, label, tone = "info" }: ProgressBarProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const clamped = Math.max(0, Math.min(100, value));
  const visibleLabel = label ?? "진행률";
  return (
    <View
      accessible
      accessibilityLabel={`${visibleLabel} ${Math.round(clamped)}%`}
      accessibilityRole="progressbar"
      accessibilityValue={{ min: 0, max: 100, now: clamped, text: `${Math.round(clamped)}%` }}
      style={styles.wrap}
    >
      <View style={styles.row}>
        <Text style={styles.label}>{visibleLabel}</Text>
        <Text style={styles.value}>{Math.round(clamped)}%</Text>
      </View>
      <View style={styles.track}>
        <View style={[styles.fill, { width: `${clamped}%`, backgroundColor: toneColor(tone, colors) }]} />
      </View>
    </View>
  );
}

function toneColor(tone: ProgressBarTone, colors: ThemeColors) {
  if (tone === "success") return colors.safeStrong;
  if (tone === "warning") return colors.warnStrong;
  if (tone === "danger") return colors.dangerStrong;
  return colors.cta;
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    wrap: {
      gap: spacing.xs,
    },
    row: {
      alignItems: "center",
      flexDirection: "row",
      justifyContent: "space-between",
    },
    label: {
      color: colors.textMuted,
      fontSize: text.body,
      fontWeight: fontWeight.bodyStrong,
      lineHeight: lineHeight.body,
    },
    value: {
      color: colors.text,
      fontSize: text.bodyStrong,
      fontVariant: ["tabular-nums"],
      fontWeight: fontWeight.bodyStrong,
      lineHeight: lineHeight.bodyStrong,
    },
    track: {
      backgroundColor: colors.surfaceMuted,
      height: 8,
      overflow: "hidden",
    },
    fill: {
      height: 8,
    },
  });
