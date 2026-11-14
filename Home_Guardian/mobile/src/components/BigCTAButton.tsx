import { ArrowRight } from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import { Pressable, StyleSheet, Text, View } from "react-native";

import { ctaHeight, fontWeight, lineHeight, motion, spacing, text, type ThemeColors, useThemedStyles } from "../theme";

export type BigCTATone = "cta" | "safe" | "danger";

type BigCTAButtonProps = {
  label: string;
  accessibilityLabel?: string;
  onPress: () => void;
  icon?: LucideIcon;
  tone?: BigCTATone;
  disabled?: boolean;
};

/** The single decisive action on a screen: solid, calm, and easy to scan. */
export function BigCTAButton({ label, accessibilityLabel, onPress, icon: Icon, tone = "cta", disabled = false }: BigCTAButtonProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const palette = tonePalette(tone, colors);
  const foreground = disabled ? colors.textMuted : palette.fg;
  return (
    <Pressable
      accessibilityLabel={accessibilityLabel ?? label}
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      android_ripple={{ color: colors.ctaOverlay, borderless: false }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.button,
        { backgroundColor: disabled ? colors.surfaceMuted : pressed ? palette.pressed : palette.bg },
        pressed && !disabled ? styles.pressed : null,
      ]}
    >
      <View pointerEvents="none" style={styles.sheen} />
      <View style={styles.row}>
        <View style={styles.labelGroup}>
          {Icon ? <View style={styles.icon}><Icon color={foreground} size={25} strokeWidth={2.3} /></View> : null}
          <Text style={[styles.label, { color: foreground }]}>{label}</Text>
        </View>
        <View style={styles.arrow}><ArrowRight color={foreground} size={25} strokeWidth={2.4} /></View>
      </View>
    </Pressable>
  );
}

function tonePalette(tone: BigCTATone, colors: ThemeColors) {
  if (tone === "safe") return { bg: colors.safeStrong, fg: colors.ctaText, pressed: colors.safePressed };
  if (tone === "danger") return { bg: colors.dangerStrong, fg: colors.ctaText, pressed: colors.dangerPressed };
  return { bg: colors.cta, fg: colors.ctaText, pressed: colors.ctaPressed };
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    button: {
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderLeftColor: colors.cta,
      borderLeftWidth: 6,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      justifyContent: "center",
      minHeight: ctaHeight,
      overflow: "hidden",
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.sm,
      position: "relative",
      width: "100%",
    },
    pressed: { opacity: motion.pressOpacity, transform: [{ scale: motion.pressScale }] },
    sheen: { backgroundColor: colors.ctaOverlay, height: 18, left: -24, position: "absolute", top: 14, transform: [{ rotate: "-16deg" }], width: 180 },
    row: { alignItems: "center", flexDirection: "row", gap: spacing.sm, justifyContent: "space-between", width: "100%" },
    labelGroup: { alignItems: "center", flex: 1, flexDirection: "row", gap: spacing.sm, minWidth: 0 },
    icon: { alignItems: "center", borderColor: colors.ctaOutline, borderWidth: 1, height: 48, justifyContent: "center", width: 48 },
    label: { flex: 1, flexShrink: 1, fontSize: text.section, fontWeight: fontWeight.section, lineHeight: lineHeight.section },
    arrow: { alignItems: "center", borderLeftColor: colors.ctaOutline, borderLeftWidth: 1, height: 48, justifyContent: "center", width: 54 },
  });
