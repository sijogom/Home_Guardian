import { useState } from "react";
import { StyleSheet, Text, TextInput, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, type ThemeColors, useThemedStyles } from "../theme";

type TextFieldProps = {
  label: string;
  value: string;
  onChangeText: (value: string) => void;
  placeholder?: string;
  helper?: string;
  accessibilityLabel?: string;
  accessibilityHint?: string;
  keyboardType?: "default" | "email-address" | "url";
  autoCapitalize?: "none" | "sentences" | "words" | "characters";
};

export function TextField({
  label,
  value,
  onChangeText,
  placeholder,
  helper,
  accessibilityLabel,
  accessibilityHint,
  keyboardType = "default",
  autoCapitalize = "none",
}: TextFieldProps) {
  const [focused, setFocused] = useState(false);
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View style={styles.wrap}>
      <Text style={styles.label}>{label}</Text>
      <TextInput
        accessibilityHint={accessibilityHint ?? helper ?? "내용을 입력하세요."}
        accessibilityLabel={accessibilityLabel ?? label}
        autoCapitalize={autoCapitalize}
        autoCorrect={false}
        keyboardType={keyboardType}
        onBlur={() => setFocused(false)}
        onChangeText={onChangeText}
        onFocus={() => setFocused(true)}
        placeholder={placeholder}
        placeholderTextColor={colors.textMuted}
        selectionColor={colors.focus}
        style={[styles.input, focused ? styles.inputFocus : null]}
        value={value}
      />
      {helper ? <Text style={styles.helper}>{helper}</Text> : null}
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    wrap: {
      gap: spacing.xs,
      width: "100%",
    },
    label: {
      color: colors.text,
      fontSize: text.bodyStrong,
      fontWeight: fontWeight.bodyStrong,
      lineHeight: lineHeight.bodyStrong,
    },
    input: {
      backgroundColor: colors.surface,
      borderBottomColor: colors.borderStrong,
      borderBottomWidth: 2,
      color: colors.text,
      fontSize: text.body,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.body,
      minHeight: 64,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.sm,
    },
    inputFocus: {
      borderBottomColor: colors.focus,
      borderBottomWidth: 4,
    },
    helper: {
      color: colors.textMuted,
      fontSize: text.caption,
      fontWeight: fontWeight.body,
      lineHeight: lineHeight.caption,
    },
  });
