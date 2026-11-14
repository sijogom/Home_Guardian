import { Bell, CheckCircle2, ChevronRight, ShieldAlert, ShieldCheck, Users } from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import { EmptyState } from "../components/EmptyState";
import { Reveal } from "../components/DesignPrimitives";
import { StudioHero, StudioSignalRibbon, StudioSection } from "../components/StudioPrimitives";
import { ScreenHeader } from "../components/ScreenHeader";
import { radius, spacing, tone, type ThemeColors, useThemedStyles } from "../theme";
import type { NotificationItem, RiskLevel } from "../api/types";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import { residentNotificationTime } from "../utils/devicePresentation";

type NotificationsScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

// 받은 소식은 한 줄씩의 맥락과 목록만 보여 준다. 읽지 않은 소식은 작은 표시로
// 구분하고, 실제 보안 상태만 신호등 계열 아이콘과 색을 사용한다.
export function NotificationsScreen({ state, actions }: NotificationsScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  if (state.notifications.length === 0) {
    return (
      <>
        <ScreenHeader title="받은 소식" />
        <ScrollView style={styles.emptyScroll} contentContainerStyle={styles.emptyWrap}>
          <EmptyState
            icon={Bell}
            title="새로운 소식이 없어요"
            body="점검 결과와 보호자 연결 소식이 생기면 여기에서 차분히 알려 드릴게요."
          />
        </ScrollView>
      </>
    );
  }

  const unreadCount = state.notifications.filter((item) => !item.read).length;
  return (
    <>
      <ScreenHeader title="받은 소식" />
      <ScrollView contentContainerStyle={styles.body}>
        <StudioHero
          body={unreadCount > 0 ? "새 소식부터 눌러 읽어 보세요." : "필요한 소식은 언제든 다시 이어서 볼 수 있어요."}
          eyebrow="알림 한눈에 보기"
          icon={Bell}
          title={unreadCount > 0 ? `새로 확인할 소식 ${unreadCount}개` : "모든 소식을 확인했어요"}
          variant="paper"
        />
        <StudioSignalRibbon
          items={[{ icon: Bell, label: "읽지 않은 소식", value: `${unreadCount}개`, level: unreadCount > 0 ? "yellow" : "green" }]}
          testID="notifications-metric-rail"
        />
        <View style={styles.list}>
          <StudioSection body="점검 결과와 보호자 연결 소식을 시간순으로 보여 드려요." eyebrow="모든 알림" title="받은 소식" />
          <View style={styles.listRows}>
            {state.notifications.map((item, index) => (
              <Reveal key={item.notification_id} delay={Math.min(index, 6) * 45}>
                <NotificationCard
                  item={item}
                  onPress={() => actions.markNotificationRead(item.notification_id)}
                />
              </Reveal>
            ))}
          </View>
        </View>
      </ScrollView>
    </>
  );
}

function NotificationCard({ item, onPress }: { item: NotificationItem; onPress: () => void }) {
  const { colors, styles } = useThemedStyles(createStyles);
  const level: RiskLevel =
    item.type === "security_scan" || item.type === "scan"
      ? "green"
      : item.type === "guardian"
      ? "unknown"
      : "red";
  const palette = tone(level, colors);
  const Icon: LucideIcon =
    item.type === "security_scan" || item.type === "scan"
      ? ShieldCheck
      : item.type === "guardian"
      ? Users
      : ShieldAlert;
  const message = item.message || "누르면 자세한 내용을 볼 수 있어요.";
  const createdAt = residentNotificationTime(item.created_at);
  const accessibilityLabel = [
    item.read ? "읽은 소식" : "읽지 않은 소식",
    item.title,
    message,
    createdAt,
  ].join(". ");

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityHint="누르면 이 소식을 읽음으로 표시합니다."
      accessibilityLabel={accessibilityLabel}
      android_ripple={{ color: colors.surfaceMuted, borderless: false }}
      onPress={onPress}
      style={({ pressed }: { pressed: boolean }) => [
        styles.card,
        !item.read ? styles.cardUnread : null,
        pressed ? styles.pressed : null,
      ]}
    >
      <View style={styles.statusColumn}>
        <View
          accessibilityElementsHidden
          importantForAccessibility="no"
          style={[styles.unreadDot, { backgroundColor: item.read ? "transparent" : colors.cta }]}
        />
        <View style={[styles.iconBox, { backgroundColor: palette.bg }]}>
          <Icon color={palette.fg} size={26} strokeWidth={2.4} />
        </View>
      </View>
      <View style={styles.text}>
        <Text style={styles.title}>{item.title}</Text>
        <Text style={styles.message}>{message}</Text>
        <Text style={styles.created}>{createdAt}</Text>
      </View>
      <View style={styles.trailing}>
        {item.read ? (
          <CheckCircle2 color={colors.textMuted} size={22} strokeWidth={2.2} />
        ) : (
          <ChevronRight color={colors.textMuted} size={24} strokeWidth={2.2} />
        )}
      </View>
    </Pressable>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    summary: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingVertical: spacing.lg,
    },
    summaryLead: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
    },
    summaryIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: radius.lg,
      height: 56,
      justifyContent: "center",
      width: 56,
    },
    summaryText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    summaryEyebrow: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    summaryTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    summaryBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    emptyWrap: {
      flexGrow: 1,
      justifyContent: "center",
      padding: spacing.lg,
    },
    emptyScroll: {
      flex: 1,
    },
    list: {
      backgroundColor: colors.surface,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
    },
    listHeading: {
      gap: spacing.xs,
      paddingVertical: spacing.lg,
      paddingBottom: spacing.md,
    },
    listEyebrow: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    listTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "800",
      lineHeight: 32,
    },
    listRows: {
      paddingHorizontal: spacing.sm,
    },
    card: {
      alignItems: "center",
      backgroundColor: colors.surface,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderLeftColor: "transparent",
      borderLeftWidth: 4,
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: 112,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.md,
    },
    cardUnread: {
      backgroundColor: colors.infoBg,
      borderLeftColor: colors.cta,
    },
    pressed: {
      backgroundColor: colors.surfaceMuted,
    },
    statusColumn: {
      alignItems: "center",
      gap: 4,
      width: 48,
    },
    unreadDot: {
      borderRadius: 5,
      height: 10,
      width: 10,
    },
    iconBox: {
      alignItems: "center",
      borderRadius: 20,
      height: 40,
      justifyContent: "center",
      width: 40,
    },
    text: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    title: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    message: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    created: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    trailing: {
      alignItems: "center",
      justifyContent: "center",
      minHeight: 56,
      width: 28,
    },
  });
