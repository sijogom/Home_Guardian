import { Bell, MoreHorizontal, Router, ShieldCheck, Users } from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import { useEffect, useRef } from "react";
import { Animated, Pressable, StyleSheet, Text, View } from "react-native";

import { fontWeight, lineHeight, motion, spacing, text, type ThemeColors, useReducedMotion, useThemedStyles } from "../theme";

export type TabKey = "home" | "devices" | "guardian" | "alerts" | "profile";
type BottomTabBarProps = { active: TabKey; onChange: (tab: TabKey) => void; unreadAlerts?: number; bottomInset?: number };
const tabs: Array<{ id: TabKey; label: string; accessibilityLabel: string; icon: LucideIcon }> = [
  { id: "home", label: "홈", accessibilityLabel: "홈", icon: ShieldCheck },
  { id: "devices", label: "기기", accessibilityLabel: "기기", icon: Router },
  { id: "guardian", label: "보호", accessibilityLabel: "보호자", icon: Users },
  { id: "alerts", label: "알림", accessibilityLabel: "알림", icon: Bell },
  { id: "profile", label: "더", accessibilityLabel: "더보기", icon: MoreHorizontal },
];

export function BottomTabBar({ active, onChange, unreadAlerts = 0, bottomInset = 0 }: BottomTabBarProps) {
  const { styles } = useThemedStyles(createStyles);
  // React Native has no `tabbar` accessibility role. Android rejects that
  // value while mounting the native view; the items retain their `tab` role.
  return (
    <View accessibilityRole="toolbar" style={[styles.bar, { paddingBottom: spacing.xs + bottomInset }]}>
      {tabs.map((tab) => {
        const selected = tab.id === active;
        const Icon = tab.icon;
        const badge = tab.id === "alerts" && unreadAlerts > 0 ? unreadAlerts : null;
        const label = badge ? `${tab.accessibilityLabel}, 읽지 않은 알림 ${badge}개` : tab.accessibilityLabel;
        return (
          <AnimatedTab
            key={tab.id}
            badge={badge}
            label={label}
            onPress={() => onChange(tab.id)}
            selected={selected}
            tab={tab}
          />
        );
      })}
    </View>
  );
}

function AnimatedTab({
  badge,
  label,
  onPress,
  selected,
  tab,
}: {
  badge: number | null;
  label: string;
  onPress: () => void;
  selected: boolean;
  tab: (typeof tabs)[number];
}) {
  const { colors, styles } = useThemedStyles(createStyles);
  const reducedMotion = useReducedMotion();
  const progress = useRef(new Animated.Value(selected ? 1 : 0)).current;
  const Icon = tab.icon;

  useEffect(() => {
    if (reducedMotion || process.env.NODE_ENV === "test") {
      progress.setValue(selected ? 1 : 0);
      return;
    }
    Animated.timing(progress, { duration: motion.standard, toValue: selected ? 1 : 0, useNativeDriver: true }).start();
    return () => {
      (progress as unknown as { stopAnimation?: () => void }).stopAnimation?.();
    };
  }, [progress, reducedMotion, selected]);

  return (
    <Pressable
      accessibilityLabel={label}
      accessibilityRole="tab"
      accessibilityState={{ selected }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [styles.tab, pressed ? styles.pressed : null]}
    >
      <Animated.View
        style={[
          styles.iconSlot,
          selected ? styles.iconSlotSelected : null,
          reducedMotion ? null : { transform: [{ scale: progress.interpolate({ inputRange: [0, 1], outputRange: [0.94, 1] }) }] },
        ]}
      >
        {selected ? <View pointerEvents="none" style={styles.selectedHalo} /> : null}
        <Icon color={selected ? colors.ctaText : colors.textMuted} size={25} strokeWidth={selected ? 2.5 : 2} />
        {badge ? <View accessibilityElementsHidden importantForAccessibility="no-hide-descendants" style={styles.dot} /> : null}
      </Animated.View>
      <Text style={[styles.label, selected ? styles.labelSelected : null]}>{tab.label}</Text>
    </Pressable>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    bar: { backgroundColor: colors.surfaceSoft, borderColor: colors.borderSubtle, borderTopLeftRadius: 26, borderTopRightRadius: 26, borderWidth: 1, elevation: 6, flexDirection: "row", marginTop: spacing.xs, paddingHorizontal: spacing.xs, paddingTop: spacing.sm, shadowColor: colors.shadow, shadowOffset: { height: -4, width: 0 }, shadowOpacity: 0.08, shadowRadius: 14 },
    tab: { alignItems: "center", borderTopColor: "transparent", borderTopWidth: 0, flex: 1, gap: 3, justifyContent: "center", minHeight: 68, paddingHorizontal: 2 },
    pressed: { opacity: motion.pressOpacity, transform: [{ scale: motion.pressScale }] },
    iconSlot: { alignItems: "center", height: 44, justifyContent: "center", position: "relative", width: 56 },
    iconSlotSelected: { backgroundColor: colors.cta, borderRadius: 16, elevation: 2 },
    selectedHalo: { borderColor: colors.cta, borderBottomWidth: 0, bottom: -4, left: 6, opacity: 0, position: "absolute", right: 6 },
    dot: { backgroundColor: colors.dangerStrong, borderColor: colors.surface, borderRadius: 5, borderWidth: 2, height: 10, position: "absolute", right: 7, top: 1, width: 10 },
    label: { color: colors.textMuted, fontSize: text.caption, fontWeight: fontWeight.bodyStrong, lineHeight: lineHeight.caption, textAlign: "center" },
    labelSelected: { color: colors.cta, fontWeight: fontWeight.label },
  });
