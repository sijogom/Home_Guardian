import type { ReactNode } from "react";
import { KeyboardAvoidingView, Platform, StyleSheet } from "react-native";
import { SafeAreaView, useSafeAreaInsets } from "react-native-safe-area-context";

import { useAppTheme } from "../theme";

type SafeScreenProps = {
  children: ReactNode;
  edges?: Array<"top" | "right" | "bottom" | "left">;
  backgroundColor?: string;
};

// 모든 화면 루트에 사용. Android status bar(시간/와이파이/배터리),
// navigation bar(홈/뒤로/최근), 가로 노치까지 자동으로 피한다.
export function SafeScreen({ children, edges = ["top", "left", "right"], backgroundColor }: SafeScreenProps) {
  const { colors } = useAppTheme();
  const resolvedBackgroundColor = backgroundColor ?? colors.bg;
  const wrappedChildren = (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      keyboardVerticalOffset={0}
      style={styles.root}
    >
      {children}
    </KeyboardAvoidingView>
  );
  return (
    <SafeAreaView style={[styles.root, { backgroundColor: resolvedBackgroundColor }]} edges={edges}>
      {wrappedChildren}
    </SafeAreaView>
  );
}

export function useBottomInset(): number {
  return useSafeAreaInsets().bottom;
}

export function useTopInset(): number {
  return useSafeAreaInsets().top;
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
});
