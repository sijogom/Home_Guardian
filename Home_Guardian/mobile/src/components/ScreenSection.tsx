import type { ReactNode } from "react";
import { StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, type ThemeColors, useThemedStyles } from "../theme";

type ScreenSectionProps = {
  title?: string;
  children: ReactNode;
};

export function ScreenSection({ title, children }: ScreenSectionProps) {
  const { styles } = useThemedStyles(createStyles);
  return (
    <View style={styles.section}>
      {title ? <Text accessibilityRole="header" style={styles.title}>{title}</Text> : null}
      {children}
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    section: {
      gap: spacing.md,
    },
    title: {
      color: colors.text,
      fontSize: text.section,
      fontWeight: fontWeight.section,
      lineHeight: lineHeight.section,
    },
  });
