import { ArrowLeft } from "lucide-react-native";
import type { ReactNode } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, motion, spacing, text, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";

type ScreenHeaderProps = {
  title: string;
  onBack?: () => void;
  right?: ReactNode;
};

/** A quiet editorial masthead shared by every flow. SafeScreen owns the inset. */
export function ScreenHeader({ title, onBack, right }: ScreenHeaderProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View style={styles.header}>
      <View pointerEvents="none" style={styles.headerAccent} />
      <View style={styles.row}>
        {onBack ? (
          <Pressable
            accessibilityHint="이전 화면으로 돌아갑니다."
            accessibilityLabel="뒤로 가기"
            accessibilityRole="button"
            android_ripple={{ color: colors.surfaceMuted, borderless: false }}
            onPress={onBack}
            style={({ pressed }: { pressed: boolean }) => [styles.back, pressed ? styles.pressed : null]}
          >
            <ArrowLeft color={colors.text} size={25} strokeWidth={2.2} />
          </Pressable>
        ) : null}
        <Text accessibilityRole="header" style={styles.title}>{title}</Text>
        <View style={[styles.right, right ? null : styles.rightEmpty]}>{right}</View>
      </View>
      <View style={styles.rule} />
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    header: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      paddingHorizontal: spacing.lg,
      paddingTop: spacing.sm,
    },
    headerAccent: { backgroundColor: colors.cta, borderRadius: 999, height: 5, marginBottom: spacing.xs, width: 56 },
    row: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: 84,
    },
    back: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 18,
      borderWidth: 1,
      height: touchTargetMin,
      justifyContent: "center",
      width: touchTargetMin,
    },
    pressed: {
      backgroundColor: colors.surfaceMuted,
      opacity: motion.pressOpacity,
      transform: [{ scale: motion.pressScale }],
    },
    title: {
      color: colors.text,
      flex: 1,
      flexShrink: 1,
      fontSize: 32,
      fontWeight: fontWeight.title,
      letterSpacing: 0,
      lineHeight: 40,
      minWidth: 0,
    },
    right: {
      alignItems: "flex-end",
      justifyContent: "center",
      minHeight: touchTargetMin,
      minWidth: touchTargetMin,
    },
    rightEmpty: {
      minWidth: 0,
      width: 0,
    },
    rule: {
      backgroundColor: colors.divider,
      height: 1,
      width: "100%",
    },
  });
