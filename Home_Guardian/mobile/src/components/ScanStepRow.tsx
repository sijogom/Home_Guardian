import { Check, Clock4, X } from "lucide-react-native";
import { useEffect, useRef } from "react";
import { Animated, Easing, StyleSheet, Text, View } from "react-native";

import type { ScanStep } from "../state/useHomeGuardianController";
import { fontWeight, lineHeight, spacing, text, useAppTheme, useReducedMotion } from "../theme";

type ScanStepRowProps = {
  step: ScanStep;
};

export function ScanStepRow({ step }: ScanStepRowProps) {
  const { colors } = useAppTheme();
  const reducedMotion = useReducedMotion();
  const isDone = step.state === "completed";
  const isRun = step.state === "running";
  const isFail = step.state === "failed";
  const foreground = isFail ? colors.dangerStrong : isDone ? colors.safeStrong : isRun ? colors.cta : colors.textMuted;
  const background = isFail ? colors.dangerBg : isDone ? colors.safeBg : isRun ? colors.infoBg : colors.unknownBg;
  const pulse = useRef(new Animated.Value(1)).current;

  useEffect(() => {
    pulse.setValue(1);
    if (!isRun || reducedMotion) return;

    const loop = Animated.loop(
      Animated.sequence([
        Animated.timing(pulse, {
          toValue: 0.82,
          duration: 800,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(pulse, {
          toValue: 1,
          duration: 800,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [isRun, pulse, reducedMotion]);

  return (
    <Animated.View
      accessible
      accessibilityLabel={`${step.title}. ${stateLabel(step.state)}`}
      accessibilityRole="summary"
      style={[styles.row, { backgroundColor: isRun ? colors.surfaceMuted : "transparent", borderBottomColor: colors.divider, opacity: pulse }]}
    >
      <View style={[styles.iconBox, { backgroundColor: background }]}>
        {isDone ? (
          <Check color={foreground} size={24} strokeWidth={2.7} />
        ) : isFail ? (
          <X color={foreground} size={24} strokeWidth={2.7} />
        ) : isRun ? (
          <RunningDot color={foreground} reducedMotion={reducedMotion} />
        ) : (
          <Clock4 color={foreground} size={24} strokeWidth={2.2} />
        )}
      </View>
      <Text style={[styles.title, { color: isRun || isDone ? colors.text : colors.textMuted }]}>{step.title}</Text>
    </Animated.View>
  );
}

function stateLabel(state: ScanStep["state"]): string {
  if (state === "completed") return "완료";
  if (state === "running") return "진행 중";
  if (state === "failed") return "다시 확인 필요";
  return "대기 중";
}

function RunningDot({ color, reducedMotion }: { color: string; reducedMotion: boolean }) {
  const rotation = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    rotation.setValue(0);
    if (reducedMotion) return;

    const loop = Animated.loop(
      Animated.timing(rotation, {
        toValue: 1,
        duration: 900,
        easing: Easing.linear,
        useNativeDriver: true,
      }),
    );
    loop.start();
    return () => loop.stop();
  }, [reducedMotion, rotation]);

  const spin = rotation.interpolate({ inputRange: [0, 1], outputRange: ["0deg", "360deg"] });
  return (
    <Animated.View
      style={{
        borderColor: color,
        borderRadius: 11,
        borderRightColor: "transparent",
        borderWidth: 2,
        height: 22,
        transform: [{ rotate: spin }],
        width: 22,
      }}
    />
  );
}

const styles = StyleSheet.create({
  row: {
    alignItems: "center",
    borderBottomWidth: 1,
    flexDirection: "row",
    gap: spacing.md,
    padding: spacing.md,
  },
  iconBox: {
    alignItems: "center",
    height: 48,
    justifyContent: "center",
    width: 48,
  },
  title: {
    flex: 1,
    fontSize: text.bodyStrong,
    fontWeight: fontWeight.bodyStrong,
    lineHeight: lineHeight.bodyStrong,
  },
});
