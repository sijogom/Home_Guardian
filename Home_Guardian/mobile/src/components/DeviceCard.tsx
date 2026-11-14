import { ChevronRight } from "lucide-react-native";
import { Pressable, StyleSheet, Text, useWindowDimensions, View } from "react-native";

import type { Device } from "../api/types";
import { fontWeight, lineHeight, motion, spacing, text, tone, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import { deviceIcon } from "../utils/deviceIcons";
import { canonicalDeviceName, presentDevice, residentDeviceAccessibilityLabel } from "../utils/devicePresentation";
import { audienceRiskCopy, type RiskAudience } from "../utils/riskCopy";
import { shouldUseStackedCardLayout } from "../utils/responsiveLayout";
import { Reveal } from "./DesignPrimitives";
import { TrafficLightBadge } from "./TrafficLightBadge";

type DeviceCardProps = { device: Device; onPress: () => void; index?: number; audience?: RiskAudience };

export function shouldUseCompactDeviceCardLayout(width: number, fontScale: number): boolean {
  return shouldUseStackedCardLayout(width, fontScale);
}

/** A flat, divider-led row. The status rail carries the signal; identity stays primary. */
export function DeviceCard({ device, onPress, index = 0, audience = "user" }: DeviceCardProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const { width, fontScale } = useWindowDimensions();
  const compact = shouldUseCompactDeviceCardLayout(width, fontScale);
  const presented = presentDevice(device);
  if (!presented) return null;
  const palette = tone(presented.risk_level, colors);
  const Glyph = deviceIcon(presented.device_type);
  const copy = audienceRiskCopy(presented, audience);
  const canonicalName = canonicalDeviceName(presented);
  const canonicalLabel = presented.model ? "확인된 제품 이름과 품번" : "확인된 제품군";
  const accessibilityName = residentDeviceAccessibilityLabel(presented);
  const isFinding = presented.is_identity_finding === true;
  const indexBlock = (
    <View pointerEvents="none" style={styles.indexColumn}>
      <Text style={[styles.index, { color: palette.fg }]}>{String(index + 1).padStart(2, "0")}</Text>
      <View style={[styles.indexRule, { backgroundColor: palette.fg }]} />
    </View>
  );
  const iconBlock = (
    <View style={[styles.icon, { backgroundColor: palette.bg }]}>
      <Glyph color={palette.fg} size={28} strokeWidth={2.1} />
    </View>
  );
  const identityBlock = (
    <View testID="device-card-identity" style={[styles.identity, compact ? styles.identityCompact : null]}>
      <Text style={styles.name} accessibilityLabel={accessibilityName}>{presented.name}</Text>
      {canonicalName ? (
        <View style={styles.canonicalBlock}>
          <Text style={styles.canonicalLabel}>{canonicalLabel}</Text>
          <Text style={styles.canonical} accessibilityLabel={`${canonicalLabel}: ${canonicalName}`}>{canonicalName}</Text>
        </View>
      ) : null}
      {isFinding ? <Text style={styles.identityNote}>{presented.identity_note || "연결은 감지됐지만 제품명·품번 근거가 부족해요."}</Text> : null}
      <Text style={styles.summary}>{copy.body}</Text>
      {presented.online === false ? <Text style={styles.offline}>최근 검사에선 안 보였어요</Text> : null}
    </View>
  );
  const trailingBlock = (
    <View style={[styles.trailing, compact ? styles.trailingCompact : null]}>
      <TrafficLightBadge level={presented.risk_level} size="sm" />
      <ChevronRight color={colors.textMuted} size={25} strokeWidth={2.2} />
    </View>
  );
  return (
    <Reveal delay={Math.min(index, 6) * 45}>
      <Pressable
        accessibilityHint="두 번 누르면 물건 정보를 자세히 봅니다."
        accessibilityLabel={`${accessibilityName}. ${palette.label}. 자세히 보기`}
        accessibilityRole="button"
        android_ripple={{ color: colors.surfaceMuted, borderless: false }}
        onPress={onPress}
        style={({ pressed }: { pressed: boolean }) => [styles.row, { borderLeftColor: palette.fg }, pressed ? styles.pressed : null]}
      >
        <View pointerEvents="none" style={styles.cardGlow} />
        <View testID={compact ? "device-card-compact-layout" : "device-card-wide-layout"} style={[styles.main, compact ? styles.mainCompact : null]}>
          {compact ? (
            <>
              <View testID="device-card-compact-header" style={styles.compactHeader}>
                <View style={styles.compactLead}>{indexBlock}{iconBlock}</View>
                {trailingBlock}
              </View>
              {identityBlock}
            </>
          ) : (
            <>{indexBlock}{iconBlock}{identityBlock}{trailingBlock}</>
          )}
        </View>
      </Pressable>
    </Reveal>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    row: { backgroundColor: colors.surface, borderColor: colors.borderSubtle, borderLeftColor: colors.cta, borderLeftWidth: 5, borderRadius: 22, borderWidth: 1, elevation: 2, marginBottom: spacing.sm, minHeight: 122, overflow: "hidden", paddingHorizontal: spacing.md, paddingVertical: spacing.md, position: "relative", shadowColor: colors.shadow, shadowOffset: { height: 4, width: 0 }, shadowOpacity: 0.06, shadowRadius: 12 },
    cardGlow: { backgroundColor: colors.surfaceSoft, borderRadius: 120, height: 180, opacity: 0.56, position: "absolute", right: -90, top: -118, width: 180 },
    pressed: { backgroundColor: colors.surfaceMuted, opacity: motion.pressOpacity },
    main: { alignItems: "flex-start", flexDirection: "row", gap: spacing.sm, minWidth: 0 },
    mainCompact: { flexDirection: "column", width: "100%" },
    compactHeader: { alignItems: "center", flexDirection: "row", flexWrap: "wrap", gap: spacing.sm, justifyContent: "space-between", minWidth: 0, width: "100%" },
    compactLead: { alignItems: "center", flexDirection: "row", gap: spacing.sm },
    indexColumn: { alignItems: "center", gap: spacing.xs, justifyContent: "center", minHeight: touchTargetMin, minWidth: 36, paddingHorizontal: 2, paddingTop: 2 },
    index: { fontSize: 20, fontVariant: ["tabular-nums"], fontWeight: fontWeight.metric, lineHeight: 28 },
    indexRule: { height: 3, width: 22 },
    icon: { alignItems: "center", borderRadius: 14, height: 56, justifyContent: "center", width: 56 },
    identity: { flex: 1, gap: 2, minWidth: 0, paddingTop: 1 },
    identityCompact: { flex: 0, paddingTop: spacing.xs, width: "100%" },
    name: { color: colors.text, flexShrink: 1, fontSize: text.section, fontWeight: fontWeight.section, lineHeight: lineHeight.section },
    canonical: { color: colors.cta, flexShrink: 1, fontSize: text.body, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.body },
    canonicalBlock: { gap: 1, minWidth: 0 },
    canonicalLabel: { color: colors.textMuted, fontSize: text.caption, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.caption },
    summary: { color: colors.textMuted, flexShrink: 1, fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body },
    identityNote: { color: colors.cta, flexShrink: 1, fontSize: text.caption, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.caption },
    offline: { color: colors.textMuted, flexShrink: 1, fontSize: text.caption, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.caption },
    trailing: { alignItems: "flex-end", gap: spacing.sm, justifyContent: "space-between", minHeight: touchTargetMin, paddingTop: 1 },
    trailingCompact: { alignItems: "center", flexDirection: "row", justifyContent: "flex-end", marginLeft: "auto", paddingTop: 0 },
  });
