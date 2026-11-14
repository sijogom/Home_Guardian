import { AlertTriangle, CheckCircle2, Clock4, ShieldAlert } from "lucide-react-native";
import { StyleSheet, Text, View } from "react-native";

import type { RiskLevel } from "../api/types";
import { fontWeight, lineHeight, spacing, text, tone, useAppTheme } from "../theme";

export type TrafficLightSize = "sm" | "md" | "lg";

type TrafficLightBadgeProps = {
  level: RiskLevel;
  size?: TrafficLightSize;
};

const sizes: Record<
  TrafficLightSize,
  { minHeight: number; fontSize: number; lineHeight: number; paddingHorizontal: number; paddingVertical: number; icon: number }
> = {
  sm: { minHeight: 40, fontSize: text.caption, lineHeight: lineHeight.caption, paddingHorizontal: spacing.sm, paddingVertical: spacing.xs, icon: 20 },
  md: { minHeight: 48, fontSize: text.caption, lineHeight: lineHeight.caption, paddingHorizontal: spacing.md, paddingVertical: spacing.xs, icon: 22 },
  lg: { minHeight: 56, fontSize: text.section, lineHeight: lineHeight.section, paddingHorizontal: spacing.lg, paddingVertical: spacing.sm, icon: 26 },
};

/** Display-only status: color is always paired with an icon and visible label. */
export function TrafficLightBadge({ level, size = "md" }: TrafficLightBadgeProps) {
  const { colors } = useAppTheme();
  const palette = tone(level, colors);
  const sz = sizes[size];
  const Glyph =
    level === "green" ? CheckCircle2 : level === "yellow" ? AlertTriangle : level === "red" ? ShieldAlert : Clock4;

  return (
    <View
      accessible
      accessibilityLabel={`${palette.label} 상태`}
      accessibilityRole="text"
      style={[
        styles.badge,
        {
          backgroundColor: palette.bg,
          borderColor: palette.fg,
          borderRadius: 4,
          borderWidth: 1,
          minHeight: sz.minHeight,
          paddingHorizontal: sz.paddingHorizontal,
          paddingVertical: sz.paddingVertical,
        },
      ]}
    >
      <Glyph color={palette.fg} size={sz.icon} strokeWidth={2.35} />
      <Text style={[styles.label, { color: palette.fg, fontSize: sz.fontSize, lineHeight: sz.lineHeight }]}>{palette.label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  badge: {
    alignItems: "center",
    alignSelf: "flex-start",
    flexDirection: "row",
    gap: spacing.xs,
  },
  label: {
    flexShrink: 1,
    fontWeight: fontWeight.label,
    letterSpacing: 0,
  },
});
