import type { LucideIcon } from "lucide-react-native";
import { Pressable, StyleSheet, Text, View } from "react-native";

import {
  fontWeight,
  lineHeight,
  motion,
  spacing,
  text,
  touchTargetMin,
  type ThemeColors,
  useAppTheme,
} from "../theme";

type ActionButtonVariant = "primary" | "secondary" | "danger" | "ghost";

type ActionButtonProps = {
  label: string;
  onPress: () => void;
  icon?: LucideIcon;
  variant?: ActionButtonVariant;
  disabled?: boolean;
};

export function ActionButton({
  label,
  onPress,
  icon: Icon,
  variant = "primary",
  disabled = false,
}: ActionButtonProps) {
  const { colors } = useAppTheme();
  const palette = variantPalette(variant, colors);
  const foreground = disabled ? colors.textMuted : palette.fg;
  return (
    <Pressable
      accessibilityLabel={label}
      accessibilityRole="button"
      accessibilityState={{ disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.base,
        {
          backgroundColor: disabled ? colors.surfaceMuted : pressed ? palette.pressed : palette.bg,
          borderColor: disabled ? colors.borderSubtle : palette.border,
          borderLeftColor: disabled ? colors.borderSubtle : palette.border,
        },
        variant === "primary" && !disabled ? styles.primaryRail : null,
        pressed && !disabled ? styles.pressed : null,
      ]}
    >
      <View style={styles.content}>
        {Icon ? <Icon color={foreground} size={22} strokeWidth={2.25} /> : null}
        <Text style={[styles.label, { color: foreground }]}>{label}</Text>
      </View>
    </Pressable>
  );
}

function variantPalette(
  variant: ActionButtonVariant,
  colors: ThemeColors,
): { bg: string; fg: string; pressed: string; border: string } {
  if (variant === "secondary") {
    return { bg: colors.surface, fg: colors.text, pressed: colors.surfaceMuted, border: colors.borderSubtle };
  }
  if (variant === "danger") {
    return { bg: colors.surface, fg: colors.dangerStrong, pressed: colors.dangerBg, border: colors.dangerStrong };
  }
  if (variant === "ghost") {
    return { bg: "transparent", fg: colors.cta, pressed: colors.surfaceMuted, border: "transparent" };
  }
  return { bg: colors.cta, fg: colors.ctaText, pressed: colors.ctaPressed, border: colors.cta };
}

const styles = StyleSheet.create({
  base: {
    alignItems: "center",
    borderRadius: 0,
    borderLeftWidth: 5,
    borderWidth: 1,
    justifyContent: "center",
    minHeight: touchTargetMin,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.sm,
  },
  primaryRail: {
    borderLeftWidth: 7,
  },
  pressed: {
    opacity: motion.pressOpacity,
    transform: [{ scale: motion.pressScale }],
  },
  content: {
    alignItems: "center",
    flexDirection: "row",
    gap: spacing.xs,
    justifyContent: "center",
  },
  label: {
    fontSize: text.bodyStrong,
    fontWeight: fontWeight.bodyStrong,
    lineHeight: lineHeight.bodyStrong,
    textAlign: "center",
  },
});
