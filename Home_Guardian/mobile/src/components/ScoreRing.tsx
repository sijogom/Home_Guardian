import { Clock4 } from "lucide-react-native";
import { StyleSheet, Text, View } from "react-native";
import Svg, { Circle } from "react-native-svg";

import { fontWeight, lineHeight, spacing, text, tone, type ToneKey, type ThemeColors, useThemedStyles } from "../theme";

type ScoreRingProps = {
  score: number | null;
  size?: number;
  stroke?: number;
  emptyLabel?: string;
  emptyAccessibilityLabel?: string;
};

// The score ring is a compact graphic, not the only textual explanation of the
// result.  Keep its two visual lines inside the SVG canvas while the surrounding
// result copy continues to follow the user's full system font scale.  The root
// accessibility label exposes the complete value without this visual cap.
const RING_MAX_FONT_SIZE_MULTIPLIER = 1.15;

/**
 * A static SVG metric ring deliberately avoids looping or entrance motion, so
 * the score remains readable when motion is reduced and when a scan refreshes.
 */
export function ScoreRing({
  score,
  size = 240,
  stroke = 18,
  emptyLabel = "검사 전",
  emptyAccessibilityLabel,
}: ScoreRingProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const level: ToneKey = score == null ? "unknown" : score >= 90 ? "green" : score >= 60 ? "yellow" : "red";
  const palette = tone(level, colors);
  const normalizedScore = score == null ? 0 : Math.max(0, Math.min(100, score));
  const circleRadius = Math.max(0, (size - stroke) / 2);
  const circumference = 2 * Math.PI * circleRadius;
  const dashOffset = circumference * (1 - normalizedScore / 100);
  const metricSize = Math.max(40, Math.round(size * 0.34));
  const subSize = Math.max(text.caption, Math.round(metricSize * 0.38));
  const accessibilityLabel =
    score == null
      ? emptyAccessibilityLabel ?? `${emptyLabel}. 검사를 시작하면 보안 점수를 들려드려요.`
      : `보안 점수 ${score}점, 100점 만점`;

  return (
    <View
      accessible
      accessibilityLabel={accessibilityLabel}
      accessibilityRole="summary"
      accessibilityValue={score == null ? { text: emptyLabel } : { min: 0, max: 100, now: normalizedScore, text: `${score}점` }}
      style={[
        styles.ring,
        {
          backgroundColor: colors.surface,
          borderColor: colors.borderSubtle,
          borderRadius: size / 2,
          height: size,
          width: size,
        },
      ]}
    >
      <Svg accessible={false} height={size} style={styles.svg} viewBox={`0 0 ${size} ${size}`} width={size}>
        <Circle cx={size / 2} cy={size / 2} fill="none" r={circleRadius} stroke={colors.surfaceMuted} strokeWidth={stroke} />
        {score == null ? null : (
          <Circle
            cx={size / 2}
            cy={size / 2}
            fill="none"
            r={circleRadius}
            rotation="-90"
            stroke={palette.fg}
            strokeDasharray={`${circumference} ${circumference}`}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            strokeWidth={stroke}
            origin={`${size / 2}, ${size / 2}`}
          />
        )}
      </Svg>
      <View pointerEvents="none" style={styles.content}>
        {score == null ? (
          <>
            <Clock4 color={palette.fg} size={Math.max(32, Math.round(size * 0.2))} strokeWidth={2.2} />
            <Text
              maxFontSizeMultiplier={RING_MAX_FONT_SIZE_MULTIPLIER}
              numberOfLines={1}
              style={[styles.preLabel, { color: palette.fg }]}
            >
              {emptyLabel}
            </Text>
          </>
        ) : (
          <>
            <Text
              maxFontSizeMultiplier={RING_MAX_FONT_SIZE_MULTIPLIER}
              numberOfLines={1}
              style={[styles.number, { color: palette.fg, fontSize: metricSize, lineHeight: metricSize }]}
            >
              {score}
            </Text>
            <Text
              maxFontSizeMultiplier={RING_MAX_FONT_SIZE_MULTIPLIER}
              numberOfLines={1}
              style={[styles.over, { color: colors.textMuted, fontSize: subSize, lineHeight: subSize }]}
            >
              100점 만점
            </Text>
          </>
        )}
      </View>
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    ring: {
      alignItems: "center",
      alignSelf: "center",
      aspectRatio: 1,
      borderWidth: 1,
      elevation: 1,
      justifyContent: "center",
      overflow: "hidden",
      shadowColor: colors.shadow,
      shadowOffset: { width: 0, height: 2 },
      shadowOpacity: 0.1,
      shadowRadius: 4,
    },
    svg: {
      position: "absolute",
    },
    content: {
      alignItems: "center",
      gap: spacing.xs,
      justifyContent: "center",
      maxWidth: "76%",
    },
    number: {
      fontVariant: ["tabular-nums"],
      fontWeight: fontWeight.metric,
      letterSpacing: 0,
    },
    over: {
      fontWeight: fontWeight.bodyStrong,
      textAlign: "center",
    },
    preLabel: {
      fontSize: text.section,
      fontWeight: fontWeight.section,
      lineHeight: lineHeight.section,
      textAlign: "center",
    },
  });
