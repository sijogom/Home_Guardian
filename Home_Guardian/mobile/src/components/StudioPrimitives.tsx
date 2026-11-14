import { AlertTriangle, ArrowRight, Check, CheckCircle2, Circle, Info } from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import type { ReactNode } from "react";
import { Pressable, StyleSheet, Text, View } from "react-native";
import Svg, { Circle as SvgCircle, Path, Rect } from "react-native-svg";

import { fontWeight, lineHeight, motion, radius, spacing, text, tone, type ThemeColors, useThemedStyles } from "../theme";
import type { RiskLevel } from "../api/types";

type HeroProps = {
  eyebrow?: string;
  title: string;
  body?: string;
  icon?: LucideIcon;
  children?: ReactNode;
  variant?: "navy" | "paper";
  testID?: string;
  statusAccessibilityLabel?: string;
  titleAccessibilityLabel?: string;
  titleAccessibilityLiveRegion?: "none" | "polite" | "assertive";
};

/**
 * Studio Halo is a fresh composition system. It keeps a single visual stage,
 * but gives it depth through SVG light, restrained surface elevation, and a
 * clear message-to-action rhythm. It intentionally does not mimic the old
 * repeated hero/card stack.
 */
export function StudioHero({
  eyebrow,
  title,
  body,
  icon: Icon,
  children,
  variant = "paper",
  testID,
  statusAccessibilityLabel = "상태 안내",
  titleAccessibilityLabel,
  titleAccessibilityLiveRegion,
}: HeroProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const dark = variant === "navy";
  return (
    <View testID={testID} style={[styles.hero, dark ? styles.heroDark : styles.heroLight]}>
      <View pointerEvents="none" style={styles.heroArt}>
        <Svg height="100%" preserveAspectRatio="none" viewBox="0 0 420 360" width="100%">
          <Rect fill={dark ? colors.heroBg : colors.surfaceSoft} height="360" width="420" x="0" y="0" />
          <Rect fill={dark ? colors.heroPressed : colors.surfaceMuted} height="360" opacity={dark ? 0.35 : 0.46} width="420" x="0" y="0" />
          <SvgCircle cx="350" cy="38" fill={dark ? colors.heroText : colors.cta} opacity={dark ? 0.18 : 0.1} r="154" />
          <SvgCircle
            cx="315"
            cy="295"
            fill="none"
            opacity={dark ? 0.2 : 0.32}
            r="126"
            stroke={dark ? colors.heroText : colors.focus}
            strokeWidth="1.5"
          />
          <SvgCircle
            cx="315"
            cy="295"
            fill="none"
            opacity={dark ? 0.14 : 0.18}
            r="90"
            stroke={dark ? colors.heroText : colors.focus}
            strokeWidth="1"
          />
          <Path d="M-30 230 L260 140" opacity={dark ? 0.2 : 0.08} stroke={dark ? colors.heroText : colors.cta} strokeWidth="24" />
          <Path d="M286 0 V360 M0 188 H420" opacity={dark ? 0.18 : 0.1} stroke={dark ? colors.heroText : colors.focus} strokeWidth="1" />
          <SvgCircle cx="365" cy="82" fill={dark ? colors.heroText : colors.cta} opacity={dark ? 0.75 : 0.55} r="5" />
          <SvgCircle cx="388" cy="104" fill={dark ? colors.heroText : colors.cta} opacity={dark ? 0.3 : 0.18} r="3" />
        </Svg>
      </View>

      <View style={styles.heroContent}>
        <View style={styles.heroTopline}>
          {Icon ? (
            <View style={[styles.heroGlyph, dark ? styles.heroGlyphDark : null]}>
              <Icon color={dark ? colors.heroText : colors.cta} size={28} strokeWidth={2.2} />
            </View>
          ) : null}
          <View style={styles.heroToplineCopy}>
            {eyebrow ? <Text style={[styles.heroEyebrow, dark ? styles.heroInk : null]}>{eyebrow}</Text> : null}
            <View style={[styles.heroRule, dark ? styles.heroRuleDark : null]} />
          </View>
          <View accessibilityLabel={statusAccessibilityLabel} accessible style={[styles.heroStatus, dark ? styles.heroStatusDark : null]}>
            <View style={[styles.heroStatusDot, dark ? styles.heroStatusDotDark : null]} />
          </View>
        </View>

        <View style={styles.heroMain}>
          <View style={styles.heroCopy}>
            <Text
              accessibilityLabel={titleAccessibilityLabel}
              accessibilityLiveRegion={titleAccessibilityLiveRegion}
              style={[styles.heroTitle, dark ? styles.heroInk : null]}
            >
              {title}
            </Text>
            {body ? <Text style={[styles.heroBody, dark ? styles.heroBodyDark : null]}>{body}</Text> : null}
          </View>
        </View>

        {children ? <View style={styles.heroFooter}>{children}</View> : null}
      </View>
    </View>
  );
}

export type StudioMetric = {
  label: string;
  value: string;
  hint?: string;
  icon?: LucideIcon;
  level?: RiskLevel;
};

export function StudioSignalRibbon({ items, testID }: { items: StudioMetric[]; testID?: string }) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View testID={testID} style={styles.ribbon}>
      {items.map((item, index) => {
        const palette = item.level ? tone(item.level, colors) : null;
        const Icon = item.icon;
        return (
          <View key={`${item.label}-${index}`} style={[styles.ribbonItem, index > 0 ? styles.ribbonDivider : null]}>
            <View style={styles.ribbonTopline}>
              {Icon ? (
                <View style={[styles.ribbonIcon, palette ? { backgroundColor: palette.bg } : null]}>
                  <Icon color={palette?.fg ?? colors.cta} size={18} strokeWidth={2.4} />
                </View>
              ) : null}
              <Text style={styles.ribbonLabel}>{item.label}</Text>
            </View>
            <Text style={[styles.ribbonValue, palette ? { color: palette.fg } : null]}>{item.value}</Text>
            {item.hint ? <Text style={styles.ribbonHint}>{item.hint}</Text> : null}
          </View>
        );
      })}
    </View>
  );
}

type CommandProps = {
  icon: LucideIcon;
  title: string;
  body?: string;
  index?: string;
  onPress?: () => void;
  testID?: string;
  accessibilityLabel?: string;
  accessibilityHint?: string;
  level?: RiskLevel;
  emphasis?: boolean;
};

export function StudioCommand({
  icon: Icon,
  title,
  body,
  index,
  onPress,
  testID,
  accessibilityLabel,
  accessibilityHint,
  level,
  emphasis = false,
}: CommandProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const palette = level ? tone(level, colors) : null;
  const content = (
    <>
      <View style={[styles.commandStripe, emphasis ? styles.commandStripeEmphasis : null, palette ? { backgroundColor: palette.fg } : null]} />
      <View style={[styles.commandIcon, emphasis ? styles.commandIconEmphasis : null, palette ? { backgroundColor: palette.bg } : null]}>
        <Icon color={emphasis ? colors.ctaText : palette?.fg ?? colors.cta} size={26} strokeWidth={2.2} />
      </View>
      <View style={styles.commandCopy}>
        <View style={styles.commandHeading}>
          {index ? <Text style={[styles.commandIndex, emphasis ? styles.commandInk : null]}>{index}</Text> : null}
          <Text style={[styles.commandTitle, emphasis ? styles.commandInk : null]}>{title}</Text>
        </View>
        {body ? <Text style={[styles.commandBody, emphasis ? styles.commandBodyInk : null]}>{body}</Text> : null}
      </View>
      <View style={[styles.commandArrow, emphasis ? styles.commandArrowEmphasis : null]}>
        <ArrowRight color={emphasis ? colors.ctaText : colors.cta} size={24} strokeWidth={2.45} />
      </View>
    </>
  );

  if (!onPress) return <View testID={testID} style={[styles.command, emphasis ? styles.commandEmphasis : null]}>{content}</View>;
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={accessibilityLabel ?? title}
      accessibilityHint={accessibilityHint}
      android_ripple={{ color: colors.surfaceMuted, borderless: false }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [styles.command, emphasis ? styles.commandEmphasis : null, pressed ? styles.commandPressed : null]}
    >
      {content}
    </Pressable>
  );
}

export function StudioStatus({ level, title, body }: { level: RiskLevel; title: string; body?: string }) {
  const { colors, styles } = useThemedStyles(createStyles);
  const palette = tone(level, colors);
  const Icon = level === "red" ? AlertTriangle : level === "green" ? CheckCircle2 : Info;
  return (
    <View accessible accessibilityLabel={`${title}${body ? `. ${body}` : ""}`} style={[styles.status, { backgroundColor: palette.bg, borderLeftColor: palette.fg }]}>
      <View style={[styles.statusIcon, { backgroundColor: colors.surface }]}><Icon color={palette.fg} size={24} strokeWidth={2.4} /></View>
      <View style={styles.statusCopy}><Text style={[styles.statusTitle, { color: palette.fg }]}>{title}</Text>{body ? <Text style={styles.statusBody}>{body}</Text> : null}</View>
    </View>
  );
}

export function StudioSection({ eyebrow, title, body }: { eyebrow?: string; title: string; body?: string }) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View style={styles.section}>
      {eyebrow ? <View style={styles.sectionEyebrow}><View style={styles.sectionDot} /><Text style={styles.sectionEyebrowText}>{eyebrow}</Text></View> : null}
      <Text style={styles.sectionTitle}>{title}</Text>
      {body ? <Text style={[styles.sectionBody, { color: colors.textMuted }]}>{body}</Text> : null}
    </View>
  );
}

export type StudioStage = { label: string; state: "completed" | "running" | "failed" | "pending" };

export function StudioStageRail({ stages, testID }: { stages: StudioStage[]; testID?: string }) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View accessible accessibilityLabel={stages.map((stage) => `${stage.label}, ${stageLabel(stage.state)}`).join(". ")} testID={testID} style={styles.stageRail}>
      <View pointerEvents="none" style={styles.stageTrack} />
      {stages.map((stage, index) => {
        const active = stage.state === "running";
        const failed = stage.state === "failed";
        const accent = failed ? colors.dangerStrong : active ? colors.cta : stage.state === "completed" ? colors.safeStrong : colors.borderStrong;
        return (
          <View key={`${stage.label}-${index}`} style={styles.stageItem}>
            <View style={[styles.stageMarker, { borderColor: accent, backgroundColor: active ? colors.cta : colors.surface }]}>
              {stage.state === "completed" ? <Check color={accent} size={20} strokeWidth={2.8} /> : failed ? <AlertTriangle color={accent} size={19} strokeWidth={2.4} /> : active ? <View style={[styles.stageMarkerCore, { backgroundColor: colors.ctaText }]} /> : <Circle color={accent} size={12} strokeWidth={2.2} />}
            </View>
            <Text style={[styles.stageLabel, { color: active || failed ? colors.text : colors.textMuted }]}>{stage.label}</Text>
          </View>
        );
      })}
    </View>
  );
}

function stageLabel(state: StudioStage["state"]): string {
  if (state === "completed") return "완료";
  if (state === "running") return "진행 중";
  if (state === "failed") return "확인 필요";
  return "대기 중";
}

const createStyles = (colors: ThemeColors) => StyleSheet.create({
  hero: {
    borderColor: colors.borderSubtle,
    borderRadius: 30,
    borderWidth: 1,
    elevation: 5,
    minHeight: 252,
    overflow: "hidden",
    position: "relative",
    shadowColor: colors.shadow,
    shadowOffset: { height: 10, width: 0 },
    shadowOpacity: 0.13,
    shadowRadius: 22,
  },
  heroLight: { backgroundColor: colors.surface },
  heroDark: { backgroundColor: colors.heroBg },
  heroArt: { bottom: 0, left: 0, position: "absolute", right: 0, top: 0 },
  heroContent: { gap: spacing.sm, padding: spacing.md, position: "relative" },
  heroTopline: { alignItems: "center", flexDirection: "row", gap: spacing.sm, minHeight: 46 },
  heroToplineCopy: { flex: 1, gap: spacing.xs, minWidth: 0 },
  heroEyebrow: { color: colors.cta, fontSize: text.body, fontWeight: fontWeight.label, lineHeight: lineHeight.body },
  heroRule: { backgroundColor: colors.cta, height: 3, width: 56 },
  heroRuleDark: { backgroundColor: colors.heroText },
  heroStatus: { alignItems: "center", height: 42, justifyContent: "center", width: 30 },
  heroStatusDark: { backgroundColor: "transparent" },
  heroStatusDot: { backgroundColor: colors.safeStrong, borderRadius: radius.pill, height: 12, width: 12 },
  heroStatusDotDark: { backgroundColor: colors.heroText },
  heroInk: { color: colors.heroText },
  heroGlyph: { alignItems: "center", backgroundColor: colors.surfaceMuted, borderColor: colors.borderSubtle, borderRadius: 18, borderWidth: 1, flexShrink: 0, height: 56, justifyContent: "center", width: 56 },
  heroGlyphDark: { backgroundColor: colors.heroOverlay, borderColor: colors.heroOutline },
  heroMain: { gap: spacing.md },
  heroCopy: { gap: spacing.sm, minWidth: 0 },
  heroTitle: { color: colors.text, flexShrink: 1, fontSize: 34, fontWeight: fontWeight.hero, lineHeight: 42 },
  heroBody: { color: colors.textMuted, fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body },
  heroBodyDark: { color: colors.heroText, opacity: 0.88 },
  heroFooter: { borderTopColor: colors.heroOutline, borderTopWidth: 1, paddingTop: spacing.md },
  ribbon: { backgroundColor: colors.surface, borderColor: colors.borderSubtle, borderRadius: 24, borderWidth: 1, elevation: 2, flexDirection: "row", flexWrap: "wrap", overflow: "hidden", shadowColor: colors.shadow, shadowOffset: { height: 4, width: 0 }, shadowOpacity: 0.06, shadowRadius: 12 },
  ribbonItem: { flexBasis: 0, flexGrow: 1, minHeight: 120, minWidth: 112, paddingHorizontal: spacing.md, paddingVertical: spacing.md },
  ribbonDivider: { borderLeftColor: colors.divider, borderLeftWidth: 1 },
  ribbonTopline: { alignItems: "center", flexDirection: "row", gap: spacing.xs, minHeight: 40 },
  ribbonIcon: { alignItems: "center", borderRadius: radius.sm, height: 36, justifyContent: "center", width: 36 },
  ribbonLabel: { color: colors.textMuted, flex: 1, fontSize: 20, fontWeight: fontWeight.label, lineHeight: 28, minWidth: 0 },
  ribbonValue: { color: colors.text, fontSize: 38, fontWeight: fontWeight.metric, lineHeight: 46, marginTop: spacing.xs },
  ribbonHint: { color: colors.textMuted, fontSize: 20, lineHeight: 28 },
  command: { alignItems: "center", backgroundColor: colors.surface, borderColor: colors.borderSubtle, borderRadius: 22, borderWidth: 1, elevation: 2, flexDirection: "row", gap: spacing.sm, minHeight: 96, overflow: "hidden", paddingHorizontal: spacing.md, shadowColor: colors.shadow, shadowOffset: { height: 4, width: 0 }, shadowOpacity: 0.06, shadowRadius: 12 },
  commandEmphasis: { backgroundColor: colors.cta, borderColor: colors.cta },
  commandPressed: { opacity: motion.pressOpacity, transform: [{ scale: motion.pressScale }] },
  commandStripe: { alignSelf: "stretch", backgroundColor: colors.borderStrong, width: 5 },
  commandStripeEmphasis: { backgroundColor: colors.ctaText },
  commandIcon: { alignItems: "center", backgroundColor: colors.surfaceMuted, borderRadius: radius.md, height: 62, justifyContent: "center", width: 62 },
  commandIconEmphasis: { backgroundColor: colors.ctaOverlay },
  commandCopy: { flex: 1, gap: 3, minWidth: 0 },
  commandHeading: { alignItems: "center", flexDirection: "row", gap: spacing.xs, minWidth: 0 },
  commandIndex: { color: colors.cta, fontSize: 20, fontWeight: fontWeight.metric, lineHeight: 28, minWidth: 34 },
  commandTitle: { color: colors.text, flex: 1, flexShrink: 1, fontSize: 25, fontWeight: fontWeight.label, lineHeight: 33, minWidth: 0 },
  commandBody: { color: colors.textMuted, fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body },
  commandInk: { color: colors.ctaText },
  commandBodyInk: { color: colors.ctaText, opacity: 0.86 },
  commandArrow: { alignItems: "center", backgroundColor: colors.surfaceMuted, borderRadius: radius.pill, height: 52, justifyContent: "center", width: 52 },
  commandArrowEmphasis: { backgroundColor: colors.ctaOverlay },
  status: { alignItems: "center", borderColor: colors.borderSubtle, borderLeftWidth: 6, borderRadius: 18, borderWidth: 1, flexDirection: "row", gap: spacing.sm, minHeight: 86, padding: spacing.md },
  statusIcon: { alignItems: "center", borderRadius: radius.sm, height: 48, justifyContent: "center", width: 48 },
  statusCopy: { flex: 1, gap: 2, minWidth: 0 },
  statusTitle: { fontSize: 22, fontWeight: fontWeight.label, lineHeight: 30 },
  statusBody: { color: colors.text, fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body },
  section: { gap: spacing.xs, paddingTop: spacing.sm },
  sectionEyebrow: { alignItems: "center", flexDirection: "row", gap: spacing.xs },
  sectionDot: { backgroundColor: colors.cta, borderRadius: radius.pill, height: 10, width: 10 },
  sectionEyebrowText: { color: colors.cta, fontSize: 20, fontWeight: fontWeight.label, lineHeight: 28 },
  sectionTitle: { color: colors.text, fontSize: 32, fontWeight: fontWeight.section, lineHeight: 40 },
  sectionBody: { fontSize: text.body, fontWeight: fontWeight.body, lineHeight: lineHeight.body },
  stageRail: { backgroundColor: colors.surface, borderColor: colors.borderSubtle, borderRadius: 22, borderWidth: 1, flexDirection: "row", justifyContent: "space-between", minHeight: 110, paddingHorizontal: spacing.sm, paddingVertical: spacing.md, position: "relative" },
  stageTrack: { backgroundColor: colors.divider, height: 2, left: 32, position: "absolute", right: 32, top: 36 },
  stageItem: { alignItems: "center", flex: 1, gap: spacing.xs, minWidth: 64 },
  stageMarker: { alignItems: "center", borderWidth: 2, height: 42, justifyContent: "center", width: 42, zIndex: 1 },
  stageMarkerCore: { height: 12, width: 12 },
  stageLabel: { fontSize: 20, fontWeight: fontWeight.bodyStrong, lineHeight: 28, textAlign: "center" },
});
