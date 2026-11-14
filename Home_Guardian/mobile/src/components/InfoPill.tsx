import type { LucideIcon } from "lucide-react-native";
import { StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, type ThemeColors, useAppTheme } from "../theme";

type InfoPillTone = "success" | "warning" | "danger" | "info" | "slate";

type InfoPillProps = {
  label: string;
  icon?: LucideIcon;
  tone?: InfoPillTone;
};

/** Compact display-only metadata. Do not use it as an interactive control. */
export function InfoPill({ label, icon: Icon, tone = "slate" }: InfoPillProps) {
  const { colors } = useAppTheme();
  const palette = tonePalette(tone, colors);
  return (
    <View accessible accessibilityLabel={label} accessibilityRole="text" style={[styles.pill, { backgroundColor: palette.bg, borderColor: colors.divider }]}>
      {Icon ? <Icon color={palette.fg} size={20} strokeWidth={2.2} /> : null}
      <Text style={[styles.label, { color: palette.fg }]}>{label}</Text>
    </View>
  );
}

function tonePalette(tone: InfoPillTone, colors: ThemeColors): { bg: string; fg: string } {
  if (tone === "success") return { bg: colors.safeBg, fg: colors.safeStrong };
  if (tone === "warning") return { bg: colors.warnBg, fg: colors.warnStrong };
  if (tone === "danger") return { bg: colors.dangerBg, fg: colors.dangerStrong };
  if (tone === "info") return { bg: colors.infoBg, fg: colors.textMuted };
  return { bg: colors.surfaceMuted, fg: colors.textMuted };
}

const styles = StyleSheet.create({
  pill: {
    alignItems: "center",
    alignSelf: "flex-start",
    borderWidth: 1,
    borderRadius: 4,
    flexDirection: "row",
    gap: spacing.xs,
    minHeight: 40,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
  },
  label: {
    fontSize: text.caption,
    fontWeight: fontWeight.label,
    lineHeight: lineHeight.caption,
  },
});
