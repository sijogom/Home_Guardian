import { AlertTriangle, CheckCircle2, Info, WifiOff } from "lucide-react-native";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, spacing, text, type ThemeColors, useReducedMotion, useThemedStyles } from "../theme";
import type { StatusTone } from "../state/useHomeGuardianController";
import { Reveal } from "./DesignPrimitives";

type StatusBannerProps = { message: string; loading: boolean; tone?: StatusTone };

export function StatusBanner({ message, loading, tone = "info" }: StatusBannerProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const reducedMotion = useReducedMotion();
  if (!message) return null;
  const Icon = tone === "success" ? CheckCircle2 : tone === "warning" ? AlertTriangle : tone === "danger" ? WifiOff : Info;
  const foreground = tone === "success" ? colors.safeStrong : tone === "warning" ? colors.warnStrong : tone === "danger" ? colors.dangerStrong : colors.textMuted;
  return (
    <Reveal>
      <View accessibilityLiveRegion="polite" style={[styles.banner, { borderLeftColor: foreground }]}>
        <View style={styles.icon}>{loading && !reducedMotion ? <ActivityIndicator color={foreground} /> : <Icon color={foreground} size={23} strokeWidth={2.3} />}</View>
        <Text style={styles.message}>{message}</Text>
      </View>
    </Reveal>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    banner: { alignItems: "center", backgroundColor: colors.surface, borderBottomColor: colors.divider, borderBottomWidth: 1, borderLeftWidth: 4, borderTopColor: colors.divider, borderTopWidth: 1, flexDirection: "row", gap: spacing.sm, minHeight: 72, paddingHorizontal: spacing.md, paddingVertical: spacing.sm },
    icon: { alignItems: "center", height: 44, justifyContent: "center", width: 44 },
    message: { color: colors.text, flex: 1, fontSize: text.body, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.body },
  });
