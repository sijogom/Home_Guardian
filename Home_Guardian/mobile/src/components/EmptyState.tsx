import type { LucideIcon } from "lucide-react-native";
import type { ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, tone, type ThemeColors, useThemedStyles } from "../theme";

type EmptyStateTone = "neutral" | "success" | "warning";

type EmptyStateProps = {
  icon: LucideIcon;
  title: string;
  body: string;
  tone?: EmptyStateTone;
  action?: ReactNode;
};

const TONE_TO_LEVEL: Record<EmptyStateTone, "green" | "yellow" | "unknown"> = {
  neutral: "unknown",
  success: "green",
  warning: "yellow",
};

export function EmptyState({ icon: Icon, title, body, tone: stateTone = "neutral", action }: EmptyStateProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const palette = tone(TONE_TO_LEVEL[stateTone], colors);
  return (
    <View style={styles.container}>
      <View style={[styles.iconWrap, { backgroundColor: palette.bg }]}>
        <Icon color={palette.fg} size={48} strokeWidth={1.8} />
      </View>
      <Text accessibilityRole="header" style={styles.title}>{title}</Text>
      <Text style={styles.body}>{body}</Text>
      {action ? <View style={styles.action}>{action}</View> : null}
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    container: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderBottomWidth: 1,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingHorizontal: spacing.lg,
      paddingVertical: spacing.xl,
      width: "100%",
    },
    iconWrap: {
      alignItems: "center",
      borderColor: colors.borderSubtle,
      borderWidth: 1,
      height: 88,
      justifyContent: "center",
      width: 88,
    },
    title: {
      color: colors.text,
      fontSize: text.title,
      fontWeight: fontWeight.title,
      lineHeight: lineHeight.title,
      textAlign: "center",
    },
    body: {
      color: colors.text,
      fontSize: text.body,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.body,
      maxWidth: 360,
      textAlign: "center",
    },
    action: {
      marginTop: spacing.md,
      width: "100%",
    },
  });
