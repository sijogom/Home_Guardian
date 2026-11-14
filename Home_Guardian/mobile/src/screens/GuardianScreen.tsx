import {
  CheckCircle2,
  Clock3,
  Mail,
  Search,
  Send,
  Share2,
  ShieldCheck,
  Trash2,
  User as UserIcon,
  XCircle,
} from "lucide-react-native";
import { useMemo, useState } from "react";
import { Alert, Pressable, ScrollView, Share, StyleSheet, Text, View } from "react-native";

import type { GuardianInvite } from "../api/types";
import { BigCTAButton } from "../components/BigCTAButton";
import { Reveal } from "../components/DesignPrimitives";
import { StudioHero, StudioSection, StudioSignalRibbon, StudioStatus } from "../components/StudioPrimitives";
import { ScreenHeader } from "../components/ScreenHeader";
import { StatusBanner } from "../components/StatusBanner";
import { TextField } from "../components/TextField";
import { spacing, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import {
  guardianInviteCode,
  guardianInviteLink,
  guardianInviteMatches,
  guardianStatus,
  guardianStatusLabel,
  isGuardianInviteRevokable,
  isGuardianInviteShareable,
} from "../utils/guardianInvite";

type GuardianScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

type GroupConfig = {
  key: string;
  title: string;
  helper: string;
  items: GuardianInvite[];
};

export function GuardianScreen({ state, actions }: GuardianScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const [guardianSearch, setGuardianSearch] = useState("");
  const valid = state.guardianEmail.includes("@");

  const visibleGuardians = useMemo(
    () =>
      state.guardians
        .filter((guardian) => !guardian.invite_id.startsWith("local-invite-"))
        .sort((a, b) => newestFirst(a.created_at, b.created_at)),
    [state.guardians],
  );
  const filteredGuardians = useMemo(
    () => visibleGuardians.filter((guardian) => guardianInviteMatches(guardian, guardianSearch)),
    [guardianSearch, visibleGuardians],
  );
  const pendingGuardians = filteredGuardians.filter((guardian) => guardianStatus(guardian) === "pending");
  const acceptedGuardians = filteredGuardians.filter((guardian) => guardianStatus(guardian) === "accepted");
  const inactiveGuardians = filteredGuardians.filter((guardian) =>
    ["expired", "revoked", "unknown"].includes(guardianStatus(guardian)),
  );
  const guardianSummary = {
    accepted: visibleGuardians.filter((guardian) => guardianStatus(guardian) === "accepted").length,
    inactive: visibleGuardians.filter((guardian) =>
      ["expired", "revoked", "unknown"].includes(guardianStatus(guardian)),
    ).length,
    pending: visibleGuardians.filter((guardian) => guardianStatus(guardian) === "pending").length,
  };
  const latestInvite =
    visibleGuardians.find((guardian) => guardianStatus(guardian) === "pending" && guardianInviteCode(guardian)) ??
    visibleGuardians.find((guardian) => guardianStatus(guardian) === "pending") ??
    visibleGuardians.find(isGuardianInviteShareable);
  const groups: GroupConfig[] = [
    {
      key: "pending",
      title: "초대 대기",
      helper: "아직 링크를 열지 않은 초대예요.",
      items: pendingGuardians,
    },
    {
      key: "accepted",
      title: "연결됨",
      helper: "보호자가 읽기 전용 진단을 확인할 수 있어요.",
      items: acceptedGuardians,
    },
    {
      key: "inactive",
      title: "지난 초대",
      helper: "다시 연결하려면 새 초대를 만들면 돼요.",
      items: inactiveGuardians,
    },
  ];

  const shareInvite = async (invite: GuardianInvite) => {
    const code = guardianInviteCode(invite);
    const link = guardianInviteLink(invite);
    const fallbackLine = code
      ? "링크가 열리지 않으면 아래 초대 코드를 입력해 주세요.\n초대 코드: " + code
      : "링크가 열리지 않으면 사용자에게 새 초대를 만들어 달라고 요청해 주세요.";
    const message =
      "[홈 가디언 보호자 초대]\n\n" +
      invite.email +
      " 님을 보안 결과 확인 보호자로 초대했어요.\n\n" +
      "아래 링크를 열면 보호자 진단으로 바로 들어갈 수 있어요.\n" +
      link +
      "\n\n" +
      fallbackLine;
    try {
      await Share.share({ message });
    } catch {
      // 공유 창을 닫은 경우에는 별도 실패 상태를 만들지 않는다.
    }
  };

  const confirmRevoke = (invite: GuardianInvite) => {
    Alert.alert("초대 취소", invite.email + " 보호자 초대를 취소할까요?", [
      { text: "아니요", style: "cancel" },
      {
        text: "초대 취소",
        style: "destructive",
        onPress: () => void actions.revokeGuardianInvite(invite.invite_id),
      },
    ]);
  };
  const confirmDelete = (invite: GuardianInvite) => {
    Alert.alert("초대 삭제", invite.email + " 보호자 초대를 목록에서 완전히 삭제할까요?", [
      { text: "아니요", style: "cancel" },
      {
        text: "삭제",
        style: "destructive",
        onPress: () => void actions.deleteGuardianInvite(invite.invite_id),
      },
    ]);
  };

  return (
    <>
      <ScreenHeader title="보호자" />
      <ScrollView contentContainerStyle={styles.body} keyboardShouldPersistTaps="handled">
        <StudioHero
          body="보호자는 위험 신호와 최근 알림을 읽기 전용으로 확인해요. 설정 변경과 점검 실행은 내 계정에서만 할 수 있어요."
          eyebrow="함께 보는 집 보안"
          icon={ShieldCheck}
          title="필요할 때만 안심을 나눠요"
          variant="navy"
        />

        <StudioStatus
          body="필요한 보안 결과만 공유하고, 기기 설정과 점검 실행 권한은 공유하지 않아요."
          level="unknown"
          title="읽기 전용 연결"
        />

        <StudioSection
          body="안심을 함께 볼 사람의 이메일을 입력하면 안전한 초대 링크와 코드가 만들어져요."
          eyebrow="01 · 연결 만들기"
          title="보호자를 초대해요"
        />
        <View style={styles.inviteStage}>
          <View style={styles.stageHeader}>
            <View style={styles.stageIcon}>
              <Mail color={colors.cta} size={24} strokeWidth={2.3} />
            </View>
            <View style={styles.stageHeaderCopy}>
              <Text style={styles.stageTitle}>보호자 이메일</Text>
              <Text style={styles.stageBody}>초대받은 사람은 본인 계정으로만 진단을 볼 수 있어요.</Text>
            </View>
          </View>
          <TextField
            accessibilityHint="초대 링크를 보낼 보호자의 이메일 주소를 입력하세요."
            keyboardType="email-address"
            label="보호자 이메일"
            onChangeText={actions.setGuardianEmail}
            placeholder="보호자 이메일 주소"
            value={state.guardianEmail}
          />
          <BigCTAButton
            label="초대 링크 만들기"
            icon={Send}
            tone="cta"
            disabled={!valid}
            onPress={actions.inviteGuardian}
          />
          {state.statusMessage && state.statusTone !== "info" ? (
            <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
          ) : null}
        </View>

        {latestInvite ? (
          <Reveal>
            <View style={styles.readyStage}>
              <View style={styles.readyHeader}>
                <View style={styles.readyHeading}>
                  <View style={styles.readyIcon}>
                    <Share2 color={colors.cta} size={22} strokeWidth={2.4} />
                  </View>
                  <View style={styles.readyHeaderCopy}>
                    <Text style={styles.readyEyebrow}>초대가 준비됐어요</Text>
                    <Text style={styles.readyTitle}>링크 또는 코드를 보내세요</Text>
                  </View>
                </View>
                <Text style={styles.readyEmail}>{latestInvite.email}</Text>
              </View>
              <InviteCodeDisplay invite={latestInvite} />
              <Pressable
                accessibilityRole="button"
                accessibilityLabel="링크와 코드 보내기"
                onPress={() => void shareInvite(latestInvite)}
                style={({ pressed }: { pressed: boolean }) => [
                  styles.shareAction,
                  pressed ? styles.actionButtonPressed : null,
                ]}
              >
                <Share2 color={colors.cta} size={22} strokeWidth={2.4} />
                <Text style={styles.shareActionLabel}>링크와 코드 보내기</Text>
              </Pressable>
            </View>
          </Reveal>
        ) : null}

        <StudioSection
          body="연결 상태를 한눈에 보고, 필요할 때만 초대를 관리해요."
          eyebrow="02 · 연결 관리"
          title="보호자 연결"
        />
        <StudioSignalRibbon
          items={[
            { icon: CheckCircle2, label: "연결됨", value: String(guardianSummary.accepted), level: "green" },
            { icon: Clock3, label: "초대 대기", value: String(guardianSummary.pending), level: "yellow" },
            { icon: XCircle, label: "지난 초대", value: String(guardianSummary.inactive), level: "unknown" },
          ]}
          testID="guardian-metric-rail"
        />
        <Text style={styles.managementSummaryText}>
          연결됨 {guardianSummary.accepted}명 · 초대 대기 {guardianSummary.pending}명 · 지난 초대 {guardianSummary.inactive}건
        </Text>

        <View style={styles.managementSection}>
          {visibleGuardians.length > 0 ? (
            <View style={styles.searchBlock}>
              <View style={styles.searchHeading}>
                <Search color={colors.textMuted} size={22} strokeWidth={2.3} />
                <Text style={styles.searchTitle}>목록에서 찾기</Text>
              </View>
              <TextField
                accessibilityHint="이메일, 초대 코드 또는 상태로 보호자를 찾아요."
                label="보호자 찾기"
                onChangeText={setGuardianSearch}
                placeholder="이메일 또는 상태 검색"
                value={guardianSearch}
              />
            </View>
          ) : null}

          {visibleGuardians.length === 0 ? (
            <View style={styles.emptyCard}>
              <View style={styles.emptyIcon}>
                <ShieldCheck color={colors.safeStrong} size={30} strokeWidth={2.3} />
              </View>
              <View style={styles.emptyCopy}>
                <Text style={styles.emptyTitle}>아직 연결된 보호자가 없어요</Text>
                <Text style={styles.emptyBody}>위에서 이메일을 입력해 초대를 만들면, 여기에서 연결 상태를 확인할 수 있어요.</Text>
              </View>
            </View>
          ) : filteredGuardians.length === 0 ? (
            <View style={styles.emptyCard}>
              <View style={styles.emptyIcon}>
                <Search color={colors.textMuted} size={30} strokeWidth={2.3} />
              </View>
              <View style={styles.emptyCopy}>
                <Text style={styles.emptyTitle}>찾는 보호자가 없어요</Text>
                <Text style={styles.emptyBody}>이메일, 초대 코드 또는 상태를 바꿔서 다시 찾아보세요.</Text>
              </View>
            </View>
          ) : (
            <View style={styles.groupList}>
              {groups.map((group) => (
                <GuardianGroup
                  key={group.key}
                  group={group}
                  onDelete={confirmDelete}
                  onRevoke={confirmRevoke}
                  onShare={shareInvite}
                />
              ))}
            </View>
          )}
        </View>
      </ScrollView>
    </>
  );
}

function GuardianGroup({
  group,
  onShare,
  onRevoke,
  onDelete,
}: {
  group: GroupConfig;
  onShare: (invite: GuardianInvite) => Promise<void>;
  onRevoke: (invite: GuardianInvite) => void;
  onDelete: (invite: GuardianInvite) => void;
}) {
  const { styles } = useThemedStyles(createStyles);
  if (group.items.length === 0) return null;

  return (
    <View style={styles.group}>
      <View style={styles.groupHeader}>
        <Text style={styles.groupTitle}>{group.title}</Text>
        <Text style={styles.groupCount}>{group.items.length}</Text>
      </View>
      <Text style={styles.groupHelper}>{group.helper}</Text>
      <View style={styles.cardList}>
                {group.items.map((guardian, index) => (
                  <GuardianCard
                    index={index}
            key={guardian.invite_id}
            guardian={guardian}
            onDelete={onDelete}
            onRevoke={onRevoke}
            onShare={onShare}
          />
        ))}
      </View>
    </View>
  );
}

function GuardianCard({
  guardian,
  onShare,
  onRevoke,
  onDelete,
  index = 0,
}: {
  guardian: GuardianInvite;
  onShare: (invite: GuardianInvite) => Promise<void>;
  onRevoke: (invite: GuardianInvite) => void;
  onDelete: (invite: GuardianInvite) => void;
  index?: number;
}) {
  const { colors, styles } = useThemedStyles(createStyles);
  const status = guardianStatus(guardian);
  const StatusIcon = status === "accepted" ? CheckCircle2 : status === "pending" ? Clock3 : XCircle;
  const statusPalette =
    status === "accepted"
      ? { bg: colors.safeBg, fg: colors.safeStrong }
      : status === "pending"
        ? { bg: colors.warnBg, fg: colors.warnStrong }
        : { bg: colors.unknownBg, fg: colors.unknownStrong };

  return (
    <Reveal delay={Math.min(index, 6) * 45}>
      <View style={styles.guardianCard}>
      <View style={styles.guardianTop}>
        <View pointerEvents="none" style={styles.guardianIndex}>
          <Text style={[styles.guardianIndexText, { color: statusPalette.fg }]}>{String(index + 1).padStart(2, "0")}</Text>
          <View style={[styles.guardianIndexRule, { backgroundColor: statusPalette.fg }]} />
        </View>
        <View style={[styles.avatar, { backgroundColor: statusPalette.bg }]}>
          <UserIcon color={statusPalette.fg} size={26} strokeWidth={2.1} />
        </View>
        <View style={styles.guardianCopy}>
          <Text style={styles.guardianName}>{guardian.display_name || guardian.relation || "보호자"}</Text>
          <Text style={styles.guardianEmail}>{guardian.email}</Text>
        </View>
      </View>
      <View style={styles.guardianStatusRow}>
        <View style={[styles.statusBadge, { backgroundColor: statusPalette.bg }]}>
          <StatusIcon color={statusPalette.fg} size={18} strokeWidth={2.5} />
          <Text style={[styles.statusLabel, { color: statusPalette.fg }]}>{guardianStatusLabel(guardian)}</Text>
        </View>
      </View>
      {guardianInviteCode(guardian) ? (
        <View style={styles.inviteCodeNote}>
          <Text style={styles.inviteCodeValue}>초대 코드 {guardianInviteCode(guardian)}</Text>
        </View>
      ) : null}
      <View style={styles.actionRow}>
        {isGuardianInviteShareable(guardian) ? (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={guardian.email + " 보호자 초대 다시 보내기"}
            onPress={() => void onShare(guardian)}
            style={({ pressed }: { pressed: boolean }) => [
              styles.actionButton,
              pressed ? styles.actionButtonPressed : null,
            ]}
          >
            <Share2 color={colors.cta} size={20} strokeWidth={2.4} />
            <Text style={styles.actionLabel}>다시 보내기</Text>
          </Pressable>
        ) : null}
        {isGuardianInviteRevokable(guardian) ? (
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={guardian.email + " 보호자 초대 취소"}
            onPress={() => onRevoke(guardian)}
            style={({ pressed }: { pressed: boolean }) => [
              styles.actionButton,
              pressed ? styles.actionButtonPressed : null,
            ]}
          >
            <XCircle color={colors.textMuted} size={20} strokeWidth={2.4} />
            <Text style={styles.secondaryActionLabel}>초대 취소</Text>
          </Pressable>
        ) : null}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={guardian.email + " 보호자 초대 삭제"}
          onPress={() => onDelete(guardian)}
          style={({ pressed }: { pressed: boolean }) => [
            styles.deleteButton,
            pressed ? styles.deleteButtonPressed : null,
          ]}
        >
          <Trash2 color={colors.dangerStrong} size={20} strokeWidth={2.4} />
          <Text style={styles.deleteLabel}>삭제</Text>
        </Pressable>
      </View>
      </View>
    </Reveal>
  );
}

function InviteCodeDisplay({ invite }: { invite: GuardianInvite }) {
  const { colors, styles } = useThemedStyles(createStyles);
  const code = guardianInviteCode(invite);
  if (!code) {
    return <Text style={styles.codeMissing}>짧은 코드가 없어요. 새 초대 링크를 만들어 보내 주세요.</Text>;
  }
  return (
    <View accessible accessibilityLabel={"현재 초대 코드 " + code} style={styles.codeDisplay}>
      <Text style={[styles.codeLabel, { color: colors.ctaText }]}>현재 초대 코드</Text>
      <Text style={styles.code}>{code}</Text>
    </View>
  );
}

function newestFirst(a?: string, b?: string) {
  return (Date.parse(b || "") || 0) - (Date.parse(a || "") || 0);
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    body: {
      backgroundColor: colors.bg,
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    hero: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.md,
      paddingTop: spacing.sm,
    },
    heroIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 0,
      height: 56,
      justifyContent: "center",
      width: 56,
    },
    heroCopy: {
      flex: 1,
      gap: 4,
      minWidth: 0,
    },
    eyebrow: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    title: {
      color: colors.text,
      fontSize: 32,
      fontWeight: "900",
      lineHeight: 40,
    },
    intro: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    inviteStage: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 28,
      borderWidth: 1,
      elevation: 3,
      gap: spacing.md,
      padding: spacing.lg,
      shadowColor: colors.shadow,
      shadowOffset: { height: 8, width: 0 },
      shadowOpacity: 0.08,
      shadowRadius: 18,
    },
    stageHeader: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    stageIcon: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 18,
      borderWidth: 1,
      flexShrink: 0,
      height: 52,
      justifyContent: "center",
      width: 52,
    },
    stageHeaderCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    stageTitle: {
      color: colors.text,
      flexShrink: 1,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    stageBody: {
      color: colors.textMuted,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    sectionTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    sectionBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    readyStage: {
      backgroundColor: colors.cta,
      borderRadius: 28,
      elevation: 4,
      gap: spacing.md,
      padding: spacing.lg,
      shadowColor: colors.shadow,
      shadowOffset: { height: 8, width: 0 },
      shadowOpacity: 0.12,
      shadowRadius: 18,
    },
    readyHeader: {
      gap: 2,
    },
    readyHeading: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    readyIcon: {
      alignItems: "center",
      backgroundColor: colors.ctaOverlay,
      borderColor: colors.ctaOutline,
      borderRadius: 16,
      borderWidth: 1,
      flexShrink: 0,
      height: 50,
      justifyContent: "center",
      width: 50,
    },
    readyHeaderCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    readyEyebrow: {
      color: colors.ctaText,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
    },
    readyTitle: {
      color: colors.ctaText,
      flexShrink: 1,
      fontSize: 25,
      fontWeight: "900",
      lineHeight: 32,
    },
    readyEmail: {
      color: colors.ctaText,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
      marginLeft: 62,
      opacity: 0.84,
    },
    codeDisplay: {
      backgroundColor: colors.ctaOverlay,
      borderColor: colors.ctaOutline,
      borderRadius: 18,
      borderWidth: 1,
      gap: 2,
      minHeight: touchTargetMin,
      padding: spacing.md,
    },
    codeLabel: {
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    code: {
      color: colors.ctaText,
      fontFamily: "monospace",
      fontSize: 30,
      fontWeight: "900",
      letterSpacing: 1,
      lineHeight: 40,
    },
    codeMissing: {
      color: colors.ctaText,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    shareAction: {
      alignItems: "center",
      alignSelf: "stretch",
      backgroundColor: colors.ctaText,
      borderRadius: 18,
      flexDirection: "row",
      gap: spacing.xs,
      justifyContent: "center",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.xs,
    },
    shareActionLabel: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    managementSection: {
      gap: spacing.md,
    },
    managementSummaryText: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    searchBlock: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 24,
      borderWidth: 1,
      elevation: 2,
      gap: spacing.sm,
      padding: spacing.md,
      shadowColor: colors.shadow,
      shadowOffset: { height: 5, width: 0 },
      shadowOpacity: 0.06,
      shadowRadius: 12,
    },
    searchHeading: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.xs,
    },
    searchTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    emptyCard: {
      alignItems: "flex-start",
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 24,
      borderWidth: 1,
      elevation: 2,
      flexDirection: "row",
      gap: spacing.sm,
      padding: spacing.lg,
      shadowColor: colors.shadow,
      shadowOffset: { height: 5, width: 0 },
      shadowOpacity: 0.06,
      shadowRadius: 12,
    },
    emptyIcon: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderRadius: 18,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    emptyCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    emptyTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    emptyBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    groupList: {
      gap: spacing.lg,
    },
    group: {
      gap: spacing.sm,
    },
    groupHeader: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.sm,
      justifyContent: "space-between",
    },
    groupTitle: {
      color: colors.text,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    groupCount: {
      color: colors.textMuted,
      fontSize: 20,
      fontVariant: ["tabular-nums"],
      fontWeight: "800",
      lineHeight: 30,
    },
    groupHelper: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    cardList: {
      gap: spacing.sm,
    },
    guardianCard: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 24,
      borderWidth: 1,
      elevation: 3,
      gap: spacing.md,
      overflow: "hidden",
      padding: spacing.md,
      shadowColor: colors.shadow,
      shadowOffset: { height: 7, width: 0 },
      shadowOpacity: 0.07,
      shadowRadius: 15,
    },
    guardianTop: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    guardianIndex: {
      alignItems: "center",
      gap: spacing.xs,
      justifyContent: "center",
      minHeight: touchTargetMin,
      width: 28,
    },
    guardianIndexText: {
      fontSize: 20,
      fontVariant: ["tabular-nums"],
      fontWeight: "900",
      lineHeight: 28,
    },
    guardianIndexRule: {
      height: 3,
      width: 22,
    },
    avatar: {
      alignItems: "center",
      borderRadius: 24,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    guardianCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    guardianName: {
      color: colors.text,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    guardianEmail: {
      color: colors.textMuted,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    guardianStatusRow: {
      alignItems: "flex-start",
      flexDirection: "row",
    },
    statusBadge: {
      alignItems: "center",
      borderRadius: 999,
      flexDirection: "row",
      gap: 4,
      minHeight: 44,
      paddingHorizontal: spacing.xs,
      paddingVertical: 4,
    },
    statusLabel: {
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    inviteCodeNote: {
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 16,
      borderWidth: 1,
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    inviteCodeLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    inviteCodeValue: {
      color: colors.text,
      fontFamily: "monospace",
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    actionRow: {
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
    },
    actionButton: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 16,
      borderWidth: 1,
      flexDirection: "row",
      gap: 4,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    deleteButton: {
      alignItems: "center",
      backgroundColor: colors.dangerBg,
      borderColor: colors.dangerStrong,
      borderRadius: 16,
      borderWidth: 1,
      flexDirection: "row",
      gap: 4,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    actionButtonPressed: {
      backgroundColor: colors.infoBg,
    },
    deleteButtonPressed: {
      backgroundColor: colors.dangerBg,
      opacity: 0.72,
    },
    actionLabel: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    secondaryActionLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    deleteLabel: {
      color: colors.dangerStrong,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
  });
