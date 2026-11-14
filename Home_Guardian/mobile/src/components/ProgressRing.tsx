import { useEffect, useRef } from "react";
import { Animated, Easing, StyleSheet, View } from "react-native";

import { motion, useAppTheme, useReducedMotion } from "../theme";

type ProgressRingProps = {
  size?: number;
  stroke?: number;
};

/** Indeterminate scan feedback that becomes a static partial ring with reduced motion enabled. */
export function ProgressRing({ size = 220, stroke = 16 }: ProgressRingProps) {
  const { colors } = useAppTheme();
  const reducedMotion = useReducedMotion();
  const rotation = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    rotation.setValue(0);
    if (reducedMotion) return;

    const loop = Animated.loop(
      Animated.timing(rotation, {
        toValue: 1,
        duration: 1400,
        easing: Easing.linear,
        useNativeDriver: true,
      }),
    );
    loop.start();
    return () => loop.stop();
  }, [reducedMotion, rotation]);

  const spin = rotation.interpolate({
    inputRange: [0, 1],
    outputRange: ["0deg", "360deg"],
  });

  return (
    <View
      accessible
      accessibilityLabel="검사 진행 중"
      accessibilityRole="progressbar"
      accessibilityValue={{ text: "검사 진행 중" }}
      style={[styles.wrapper, { borderRadius: size / 2, height: size, width: size }]}
    >
      <View
        style={[
          styles.track,
          {
            borderColor: colors.surfaceMuted,
            borderRadius: size / 2,
            borderWidth: stroke,
            height: size,
            width: size,
          },
        ]}
      />
      <Animated.View
        style={[
          styles.arc,
          {
            borderColor: "transparent",
            borderTopColor: colors.cta,
            borderRadius: size / 2,
            borderWidth: stroke,
            height: size,
            transform: [{ rotate: spin }],
            width: size,
          },
        ]}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  wrapper: {
    alignItems: "center",
    justifyContent: "center",
    overflow: "hidden",
  },
  track: {
    position: "absolute",
  },
  arc: {
    position: "absolute",
  },
});
