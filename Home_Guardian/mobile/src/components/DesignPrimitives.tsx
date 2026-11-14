import type { ReactNode } from "react";
import { useEffect, useRef } from "react";
import { Animated } from "react-native";

import { motion, useReducedMotion } from "../theme";

type RevealProps = {
  children: ReactNode;
  delay?: number;
  testID?: string;
};

/**
 * The only retained primitive from the retired card system. It is a behavior
 * helper, not a visual component; all visual surfaces now live in Studio Halo.
 */
export function Reveal({ children, delay = 0, testID }: RevealProps) {
  const reducedMotion = useReducedMotion();
  // 첫 몇 항목에만 짧은 맥락 효과를 주고, 긴 목록의 뒤쪽 항목은 즉시
  // 표시한다. 모든 행을 순차 지연하면 실제 버튼 반응까지 느리게 보인다.
  const shouldAnimate = delay <= 96;
  const reveal = useRef(new Animated.Value(reducedMotion || !shouldAnimate ? 1 : 0)).current;

  useEffect(() => {
    if (reducedMotion || !shouldAnimate || process.env.NODE_ENV === "test") {
      reveal.setValue(1);
      return;
    }
    Animated.timing(reveal, {
      delay,
      duration: motion.quick,
      toValue: 1,
      useNativeDriver: true,
    }).start();
    return () => {
      (reveal as unknown as { stopAnimation?: () => void }).stopAnimation?.();
    };
  }, [delay, reducedMotion, reveal, shouldAnimate]);

  return (
    <Animated.View
      testID={testID}
      style={
        reducedMotion || !shouldAnimate
          ? undefined
          : {
              opacity: reveal,
              transform: [{ translateY: reveal.interpolate({ inputRange: [0, 1], outputRange: [10, 0] }) }],
            }
      }
    >
      {children}
    </Animated.View>
  );
}
