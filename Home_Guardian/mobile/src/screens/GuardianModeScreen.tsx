import {
  AlertTriangle,
  Bell,
  Check,
  CheckCircle2,
  ChevronRight,
  Eye,
  PencilLine,
  RefreshCw,
  ShieldHalf,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";
import { useEffect, useState } from "react";
import {
  Alert,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { DeviceCard } from "../components/DeviceCard";
import { Reveal } from "../components/DesignPrimitives";
import { StudioHero, StudioSection, StudioSignalRibbon, StudioStatus } from "../components/StudioPrimitives";
import { ScoreRing } from "../components/ScoreRing";
import { ScreenHeader } from "../components/ScreenHeader";
import { StatusBanner } from "../components/StatusBanner";
import { TextField } from "../components/TextField";
import { spacing, tone, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import { parseGuardianInviteInput } from "../utils/guardianInvite";
import {
  guardianWardAccountName,
  guardianWardRiskLabel,
  guardianWardSubtitle,
  guardianWardSummaryText,
  guardianWardTitle,
  guardianWardUnreadLabel,
} from "../utils/guardianWardDisplay";
import { guardianDashboardLead } from "../utils/riskCopy";

type GuardianModeScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

const guardianDeviceRiskOrder = { red: 0, yellow: 1, green: 2, unknown: 3 } as const;

export function GuardianModeScreen({ state, actions }: GuardianModeScreenProps) {
  const { colors, styles } = useThemedStyles(createStyles);
  const [inviteCode, setInviteCode] = useState(state.guardianModeInviteCode ?? "");
  const [editingWardId, setEditingWardId] = useState<string | null>(null);
  const [wardAliasDraft, setWardAliasDraft] = useState("");

  useEffect(() => {
    setInviteCode(state.guardianModeInviteCode ?? "");
  }, [state.guardianModeInviteCode]);

  useEffect(() => {
    if (editingWardId && !state.guardianWards.some((ward) => ward.link_id === editingWardId)) {
      setEditingWardId(null);
      setWardAliasDraft("");
    }
  }, [editingWardId, state.guardianWards]);

  const data = state.guardianDashboard;
  const wards = state.guardianWards;
  const guardianScreenMode = data ? "guardian-dashboard" : state.guardianUser ? "guardian-list" : "guardian-login";
  const wardScore = data?.ward_summary?.score ?? null;
  const wardNoTargets = data?.ward_summary?.score_status === "no_targets";
  const wardRisk = data?.ward_summary?.risk_level ?? "unknown";
  const wardStatusLabel = wardNoTargets
    ? "점검 완료 · 대상 없음"
    : wardRisk === "red"
    ? "위험"
    : wardRisk === "yellow"
    ? "주의"
    : wardRisk === "green" && wardScore != null
    ? "안전"
    : wardScore == null
    ? "검사 전"
    : "상태 확인 필요";
  const guardianRiskDevices = [
    ...(data?.high_risk_devices ?? []),
    ...(data?.caution_devices ?? []),
  ];
  const guardianDevices = Array.from(
    new Map([...(data?.devices ?? []), ...guardianRiskDevices].map((device) => [device.device_id, device])).values(),
  ).sort((left, right) => guardianDeviceRiskOrder[left.risk_level] - guardianDeviceRiskOrder[right.risk_level]);
  const guardianLead = wardNoTargets
    ? {
        title: "평가할 네트워크 기기가 없어요",
        body: "점검은 끝났지만 확인된 대상이 없어 안전 점수를 만들지 않았어요. 이 상태를 안전으로 판단하지 않아요.",
      }
    : guardianRiskDevices.length > 0
    ? guardianDashboardLead(guardianRiskDevices)
    : wardRisk === "red"
    ? {
        title: "먼저 확인할 위험 신호가 있어요",
        body: "사용자 앱의 연결 목록에서 빨간 상태를 먼저 확인하고 필요한 조치를 함께 진행해 주세요.",
      }
    : wardRisk === "yellow"
    ? {
        title: "확인하면 좋은 신호가 있어요",
        body: "사용자 앱의 연결 목록에서 노란 상태를 확인하고 가능한 조치부터 함께 진행해 주세요.",
      }
    : guardianDashboardLead([]);
  const activeWard = data?.ward ?? wards.find((ward) => ward.link_id === state.selectedGuardianWardId) ?? null;
  const activeWardIndex = activeWard ? Math.max(0, wards.findIndex((ward) => ward.link_id === activeWard.link_id)) : 0;
  const activeWardTitle = activeWard
    ? guardianWardTitle(activeWard, activeWardIndex, wards.length ? wards : [activeWard])
    : "";
  const editingWard = editingWardId ? wards.find((ward) => ward.link_id === editingWardId) ?? null : null;
  const editingWardIndex = editingWard ? Math.max(0, wards.findIndex((ward) => ward.link_id === editingWard.link_id)) : 0;
  const editingWardTitle = editingWard ? guardianWardTitle(editingWard, editingWardIndex, wards) : "";

  const confirmRemoveWard = (linkId: string, label: string) => {
    Alert.alert("피보호자 삭제", label + " 연결을 보호자 계정에서 삭제할까요? 다시 보려면 사용자가 새 초대를 만들어야 해요.", [
      { text: "취소", style: "cancel" },
      { text: "삭제", style: "destructive", onPress: () => void actions.removeGuardianWard(linkId) },
    ]);
  };
  const beginEditWardName = (ward: (typeof wards)[number]) => {
    setEditingWardId(ward.link_id);
    setWardAliasDraft(ward.ward_alias ?? "");
  };
  const closeWardNameEditor = () => {
    setEditingWardId(null);
    setWardAliasDraft("");
  };
  const saveWardName = (linkId: string) => {
    void actions.updateGuardianWardAlias(linkId, wardAliasDraft).then(closeWardNameEditor);
  };
  const clearWardName = (linkId: string) => {
    void actions.updateGuardianWardAlias(linkId, "").then(closeWardNameEditor);
  };

  return (
    <>
      <ScreenHeader
        title={data ? "보호자 진단" : state.guardianUser ? "내가 보는 사람들" : "보호자 로그인"}
        onBack={() => actions.goBack() || actions.exitGuardianMode()}
      />
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.keyboardAvoider}>
        <ScrollView
          key={guardianScreenMode}
          contentContainerStyle={styles.body}
          keyboardDismissMode="on-drag"
          keyboardShouldPersistTaps="handled"
        >
          {!state.guardianUser ? (
            <View style={styles.loginFlow}>
              <StudioHero
                body="보호자는 위험한 기기와 최근 알림을 확인할 수 있어요. 점검을 시작하거나 설정을 바꾸는 일은 할 수 없어요."
                eyebrow="홈 가디언 보호자"
                icon={ShieldHalf}
                title="필요한 안전 신호만 함께 살펴봐요"
                variant="navy"
              >
                <View style={styles.loginStage}>
                  <View style={styles.loginStageHeading}>
                    <View style={styles.loginStageIcon}>
                      <Eye color={colors.heroText} size={24} strokeWidth={2.4} />
                    </View>
                    <View style={styles.loginStageCopy}>
                      <Text style={styles.loginStageEyebrow}>보호자 계정</Text>
                      <Text style={styles.loginStageTitle}>초대받은 계정으로 확인해요</Text>
                      <Text style={styles.loginStageBody}>연결된 사람의 진단을 읽기 전용으로 볼 수 있어요.</Text>
                    </View>
                  </View>
                {inviteCode ? (
                  <View style={styles.inviteNotice}>
                    <UserPlus color={colors.cta} size={22} strokeWidth={2.4} />
                    <Text style={styles.inviteNoticeText}>로그인 뒤 초대 코드 {inviteCode}를 이어서 추가할 수 있어요.</Text>
                  </View>
                ) : null}
                <BigCTAButton
                  label="Google로 보호자 로그인"
                  icon={ShieldHalf}
                  tone="cta"
                  onPress={() => actions.loginAsGuardianWithGoogle()}
                />
                </View>
              </StudioHero>
              {state.statusMessage ? (
                <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
              ) : null}
            </View>
          ) : !data ? (
            <>
              <StudioHero
                body="카드를 누르면 그 사람의 현재 안전 상태와 필요한 조치를 읽기 전용으로 확인할 수 있어요."
                eyebrow={`보호자 계정 · ${wards.length}명`}
                icon={Users}
                title="내가 보는 사람들"
                variant="navy"
              />

              <StudioStatus
                body="별칭은 내 목록에만 보이는 이름이에요. 연결된 사람의 계정 이름이나 설정은 바뀌지 않아요."
                level="unknown"
                title="보호자 보기 전용"
              />
              <StudioSection
                body="사람을 선택하면 현재 안전 상태와 필요한 확인만 열립니다."
                eyebrow="01 · 연결된 사람"
                title="안전 상태를 골라요"
              />
              <StudioSignalRibbon
                items={[
                  { icon: Users, label: "연결된 사람", value: String(wards.length) },
                  {
                    icon: AlertTriangle,
                    label: "위험 신호",
                    value: String(wards.filter((ward) => ward.summary?.risk_level === "red").length),
                    level: wards.some((ward) => ward.summary?.risk_level === "red") ? "red" : "green",
                  },
                  {
                    icon: Bell,
                    label: "새 알림",
                    value: String(wards.reduce((total, ward) => total + (ward.summary?.unread_notifications ?? 0), 0)),
                    level: wards.some((ward) => (ward.summary?.unread_notifications ?? 0) > 0) ? "yellow" : "green",
                  },
                ]}
                testID="guardian-ward-metric-rail"
              />

              {wards.length > 0 ? (
                <View style={styles.wardList}>
                  {wards.map((ward, index) => {
                    const title = guardianWardTitle(ward, index, wards);
                    const riskTone = tone(ward.summary?.risk_level ?? "unknown", colors);
                    return (
                      <Reveal key={ward.link_id} delay={Math.min(index, 6) * 45}>
                        <View style={styles.wardCard}>
                          <View pointerEvents="none" style={styles.wardGlow} />
                        <Pressable
                          accessibilityRole="button"
                          accessibilityLabel={title + " 보호자 진단 열기"}
                          accessibilityHint="누르면 읽기 전용 진단을 확인합니다."
                          android_ripple={{ color: colors.surfaceMuted, borderless: false }}
                          onPress={() => void actions.openGuardianWard(ward.link_id)}
                          style={({ pressed }: { pressed: boolean }) => [
                            styles.wardOpenArea,
                            pressed ? styles.rowPressed : null,
                          ]}
                        >
                          <View style={[styles.wardAvatar, { backgroundColor: riskTone.bg }]}>
                            <Text style={[styles.wardAvatarText, { color: riskTone.fg }]}>{index + 1}</Text>
                          </View>
                          <View style={styles.wardText}>
                            <Text style={styles.wardName}>{title}</Text>
                            <Text style={styles.wardMeta}>{guardianWardSubtitle(ward, index, wards)}</Text>
                          </View>
                          <ChevronRight color={colors.textMuted} size={24} strokeWidth={2.2} />
                        </Pressable>
                        <View style={styles.wardSummaryRow}>
                          <View style={[styles.riskBadge, { backgroundColor: riskTone.bg }]}>
                            <Text style={[styles.wardRisk, { color: riskTone.fg }]}>{guardianWardRiskLabel(ward.summary)}</Text>
                          </View>
                          <Text style={styles.wardSummary}>{guardianWardSummaryText(ward.summary)}</Text>
                        </View>
                        <View style={styles.wardFooter}>
                          <Text style={styles.wardUnread}>{guardianWardUnreadLabel(ward.summary)}</Text>
                          <View style={styles.wardActions}>
                            <Pressable
                              accessibilityRole="button"
                              accessibilityLabel={title + " 이름 편집"}
                              android_ripple={{ color: colors.surfaceMuted, borderless: false }}
                              onPress={() => beginEditWardName(ward)}
                              style={({ pressed }: { pressed: boolean }) => [
                                styles.textButton,
                                pressed ? styles.rowPressed : null,
                              ]}
                            >
                              <PencilLine color={colors.cta} size={20} strokeWidth={2.4} />
                              <Text style={styles.textButtonLabel}>이름 편집</Text>
                            </Pressable>
                            <Pressable
                              accessibilityRole="button"
                              accessibilityLabel={title + " 연결 삭제"}
                              android_ripple={{ color: colors.dangerBg, borderless: false }}
                              onPress={() => confirmRemoveWard(ward.link_id, title)}
                              style={({ pressed }: { pressed: boolean }) => [
                                styles.removeButton,
                                pressed ? styles.removeButtonPressed : null,
                              ]}
                            >
                              <Trash2 color={colors.dangerStrong} size={20} strokeWidth={2.4} />
                              <Text style={styles.removeButtonLabel}>연결 삭제</Text>
                            </Pressable>
                          </View>
                        </View>
                        </View>
                      </Reveal>
                    );
                  })}
                </View>
              ) : (
                <View style={styles.emptyCard}>
                  <View style={styles.emptyIcon}>
                    <Users color={colors.textMuted} size={30} strokeWidth={2.3} />
                  </View>
                  <View style={styles.emptyCopy}>
                    <Text style={styles.emptyTitle}>아직 추가한 사람이 없어요</Text>
                    <Text style={styles.emptyBody}>사용자 계정에서 만든 초대 코드를 아래에 입력하면, 이 목록에서 안전 상태를 확인할 수 있어요.</Text>
                  </View>
                </View>
              )}

              <Pressable
                accessibilityRole="button"
                accessibilityLabel="보호자 목록 새로고침"
                android_ripple={{ color: colors.surfaceMuted, borderless: false }}
                onPress={() => void actions.loadGuardianWards()}
                style={({ pressed }: { pressed: boolean }) => [
                  styles.refreshAction,
                  pressed ? styles.rowPressed : null,
                ]}
              >
                <RefreshCw color={colors.textMuted} size={20} strokeWidth={2.3} />
                <Text style={styles.secondaryTextButtonLabel}>목록 새로고침</Text>
              </Pressable>

              <StudioSection
                body="사용자 계정에서 받은 초대 코드를 한 번만 입력하면 목록에 연결돼요."
                eyebrow="02 · 새 연결"
                title="피보호자를 추가해요"
              />
              <View style={styles.addCard}>
                <View style={styles.addHeading}>
                  <View style={styles.sectionIcon}>
                    <UserPlus color={colors.cta} size={24} strokeWidth={2.4} />
                  </View>
                  <View style={styles.sectionHeaderText}>
                    <Text style={styles.sectionTitle}>피보호자 추가</Text>
                    <Text style={styles.sectionBody}>처음 연결할 때만 초대 코드를 입력하면 돼요.</Text>
                  </View>
                </View>
                <TextField
                  autoCapitalize="characters"
                  helper="링크를 붙여 넣어도 코드만 읽어와요."
                  label="초대 코드"
                  onChangeText={(value) => setInviteCode(parseGuardianInviteInput(value))}
                  placeholder="예: ABCD-1234"
                  value={inviteCode}
                />
                <BigCTAButton
                  label="피보호자 추가"
                  icon={UserPlus}
                  tone="cta"
                  disabled={inviteCode.trim().length < 6}
                  onPress={() => void actions.acceptGuardianInvite(inviteCode.trim())}
                />
                {state.statusMessage ? (
                  <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
                ) : null}
              </View>
            </>
          ) : (
            <>
              <StudioHero
                body="지금은 필요한 안전 상태와 조치만 살펴볼 수 있어요. 점검 실행과 설정 변경은 사용자 계정에서만 가능해요."
                eyebrow={`선택한 피보호자 · ${wardStatusLabel} · 읽기 전용`}
                icon={ShieldHalf}
                statusAccessibilityLabel={`선택한 피보호자 상태: ${wardStatusLabel}`}
                title={activeWardTitle}
                variant="navy"
              >
                <View style={styles.heroScoreLine}>
                  <ScoreRing
                    score={wardScore}
                    size={112}
                    stroke={10}
                    emptyLabel={wardNoTargets ? "대상 없음" : "검사 전"}
                    emptyAccessibilityLabel={
                      wardNoTargets
                        ? "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았습니다. 이 상태는 안전 점수가 아닙니다."
                        : "아직 안전 점검 결과가 없습니다."
                    }
                  />
                  <View style={styles.heroScoreCopy}>
                    <Text style={styles.heroScoreEyebrow}>현재 안전 점수</Text>
                    <Text style={styles.heroScoreTitle}>{wardNoTargets ? "평가 대상 없음" : wardScore == null ? "검사 전" : "차분히 확인해요"}</Text>
                    <Text style={styles.heroScoreBody}>연결된 사람은 결과를 보기만 할 수 있어요.</Text>
                  </View>
                </View>
              </StudioHero>

              <StudioStatus
                body={`보호자는 보기만 할 수 있어요. ${guardianLead.body}`}
                level={wardNoTargets ? "unknown" : wardRisk}
                title={guardianLead.title}
              />

              <StudioSection eyebrow="현재 상태" title="한눈에 보는 요약" />
              <StudioSignalRibbon
                items={[
                  { icon: Users, label: "등록된 기기", value: String(data.ward_summary.device_count) },
                  {
                    icon: AlertTriangle,
                    label: "위험 신호",
                    value: String(data.ward_summary.high_risk_devices),
                    level: data.ward_summary.high_risk_devices > 0 ? "red" : wardNoTargets ? "unknown" : "green",
                  },
                  { icon: Bell, label: "새 알림", value: String(data.ward_summary.unread_notifications), level: data.ward_summary.unread_notifications > 0 ? "yellow" : "green" },
                ]}
                testID="guardian-metric-rail"
              />

              {guardianDevices.length > 0 ? (
                <View testID="guardian-device-list" style={styles.riskSection}>
                  <StudioSection
                    body="피보호자의 연결 목록을 위험한 순서대로 보여 드려요. 카드를 누르면 개인정보 없이 보안 상태와 조치를 확인할 수 있어요."
                    eyebrow="읽기 전용 기기 목록"
                    title="피보호자의 기기"
                  />
                  {guardianDevices.map((device, index) => (
                    <DeviceCard
                      audience="guardian"
                      device={device}
                      index={index}
                      key={device.device_id}
                      onPress={() => actions.openDevice(device)}
                    />
                  ))}
                </View>
              ) : (
                <View style={styles.calmCard}>
                  <View style={styles.emptyIcon}>
                    {data.ward_summary.device_count > 0 ? (
                      <RefreshCw color={colors.cta} size={30} strokeWidth={2.4} />
                    ) : (
                      <CheckCircle2 color={colors.safeStrong} size={30} strokeWidth={2.4} />
                    )}
                  </View>
                  <View style={styles.emptyCopy}>
                    <Text style={styles.emptyTitle}>
                      {data.ward_summary.device_count > 0
                        ? state.isLoading
                          ? "기기 정보를 불러오고 있어요"
                          : "기기 정보를 다시 불러와 주세요"
                        : "표시할 기기가 없어요"}
                    </Text>
                    <Text style={styles.emptyBody}>
                      {data.ward_summary.device_count > 0
                        ? `요약에는 ${data.ward_summary.device_count}대가 있어요. 개별 정보가 도착하면 바로 목록에 표시할게요.`
                        : "새 점검에서 기기가 확인되면 이곳에 목록을 보여 드릴게요."}
                    </Text>
                  </View>
                </View>
              )}

              <View style={styles.notificationsSection}>
                <View style={styles.sectionLabelRow}>
                  <Bell color={colors.cta} size={22} strokeWidth={2.4} />
                  <Text style={styles.sectionTitle}>최근 알림</Text>
                </View>
                {data.recent_notifications.length > 0 ? (
                  <View style={styles.notificationList}>
                    {data.recent_notifications.slice(0, 3).map((item) => (
                      <View key={item.notification_id} style={styles.notificationCard}>
                        <Text style={styles.notificationTitle}>{item.title}</Text>
                        <Text style={styles.notificationMessage}>{item.message}</Text>
                      </View>
                    ))}
                  </View>
                ) : (
                  <View style={styles.noNotification}>
                    <Text style={styles.sectionBody}>새 알림이 없어요.</Text>
                  </View>
                )}
              </View>

              <View style={styles.dashboardActions}>
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="피보호자 추가하기"
                  onPress={() => actions.clearGuardianDashboard()}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.dashboardAction,
                    pressed ? styles.rowPressed : null,
                  ]}
                >
                  <Users color={colors.cta} size={20} strokeWidth={2.3} />
                  <Text style={styles.textButtonLabel}>피보호자 추가</Text>
                </Pressable>
                {activeWard ? (
                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel={activeWardTitle + " 연결 삭제"}
                    onPress={() => confirmRemoveWard(activeWard.link_id, activeWardTitle)}
                    style={({ pressed }: { pressed: boolean }) => [
                      styles.dashboardRemoveAction,
                      pressed ? styles.removeButtonPressed : null,
                    ]}
                  >
                    <Trash2 color={colors.dangerStrong} size={20} strokeWidth={2.3} />
                    <Text style={styles.removeButtonLabel}>이 사람 연결 삭제</Text>
                  </Pressable>
                ) : null}
              </View>
              {state.statusMessage ? (
                <StatusBanner message={state.statusMessage} loading={state.isLoading} tone={state.statusTone} />
              ) : null}
            </>
          )}
        </ScrollView>
      </KeyboardAvoidingView>

      <Modal animationType="fade" onRequestClose={closeWardNameEditor} transparent visible={Boolean(editingWard)}>
        <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : "height"} style={styles.modalAvoider}>
          <View style={styles.modalBackdrop}>
            {editingWard ? (
              <ScrollView
                contentContainerStyle={styles.modalContent}
                keyboardDismissMode="on-drag"
                keyboardShouldPersistTaps="handled"
                style={styles.modal}
              >
                <View style={styles.modalHeader}>
                  <View style={styles.modalIcon}>
                    <PencilLine color={colors.cta} size={24} strokeWidth={2.4} />
                  </View>
                  <View style={styles.modalHeaderCopy}>
                    <Text style={styles.eyebrow}>표시 이름 편집</Text>
                    <Text style={styles.modalTitle}>{editingWardTitle}</Text>
                  </View>
                </View>
                <View style={styles.accountName}>
                  <Text style={styles.accountNameLabel}>기본 계정 이름</Text>
                  <Text style={styles.accountNameValue}>{guardianWardAccountName(editingWard)}</Text>
                </View>
                <TextField
                  autoCapitalize="words"
                  helper="비워두면 기본 계정 이름으로 표시해요."
                  label="목록 이름"
                  onChangeText={setWardAliasDraft}
                  placeholder={guardianWardAccountName(editingWard)}
                  value={wardAliasDraft}
                />
                <View style={styles.modalActions}>
                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel="이름 편집 취소"
                    onPress={closeWardNameEditor}
                    style={({ pressed }: { pressed: boolean }) => [
                      styles.modalSecondaryAction,
                      pressed ? styles.rowPressed : null,
                    ]}
                  >
                    <Text style={styles.secondaryTextButtonLabel}>취소</Text>
                  </Pressable>
                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel={editingWardTitle + " 기본 이름으로 표시"}
                    onPress={() => clearWardName(editingWard.link_id)}
                    style={({ pressed }: { pressed: boolean }) => [
                      styles.modalSecondaryAction,
                      pressed ? styles.rowPressed : null,
                    ]}
                  >
                    <Text style={styles.secondaryTextButtonLabel}>기본 이름</Text>
                  </Pressable>
                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel={editingWardTitle + " 이름 저장"}
                    onPress={() => saveWardName(editingWard.link_id)}
                    style={({ pressed }: { pressed: boolean }) => [
                      styles.modalPrimaryAction,
                      pressed ? styles.modalPrimaryActionPressed : null,
                    ]}
                  >
                    <Check color={colors.ctaText} size={20} strokeWidth={3} />
                    <Text style={styles.modalPrimaryActionLabel}>저장</Text>
                  </Pressable>
                </View>
              </ScrollView>
            ) : null}
          </View>
        </KeyboardAvoidingView>
      </Modal>
    </>
  );
}

function SummaryTile({
  icon: Icon,
  label,
  value,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
}) {
  const { colors, styles } = useThemedStyles(createStyles);
  return (
    <View style={styles.summaryTile}>
      <Icon color={colors.cta} size={22} strokeWidth={2.4} />
      <Text style={styles.summaryValue}>{value}</Text>
      <Text style={styles.summaryLabel}>{label}</Text>
    </View>
  );
}

const createStyles = (colors: ThemeColors) =>
  StyleSheet.create({
    keyboardAvoider: {
      flex: 1,
    },
    body: {
      backgroundColor: colors.bg,
      gap: spacing.xl,
      padding: spacing.lg,
      paddingBottom: spacing.xxl,
    },
    loginFlow: {
      gap: spacing.lg,
      paddingTop: spacing.xl,
    },
    loginStage: {
      backgroundColor: colors.heroOverlay,
      borderColor: colors.heroOutline,
      borderRadius: 22,
      borderWidth: 1,
      gap: spacing.md,
      padding: spacing.md,
    },
    loginStageHeading: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    loginStageIcon: {
      alignItems: "center",
      backgroundColor: colors.heroOverlay,
      borderColor: colors.heroOutline,
      borderRadius: 16,
      borderWidth: 1,
      flexShrink: 0,
      height: 50,
      justifyContent: "center",
      width: 50,
    },
    loginStageCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    loginStageEyebrow: {
      color: colors.heroText,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
      opacity: 0.84,
    },
    loginStageTitle: {
      color: colors.heroText,
      flexShrink: 1,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    loginStageBody: {
      color: colors.heroText,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
      opacity: 0.86,
    },
    loginHero: {
      alignItems: "center",
      gap: spacing.sm,
    },
    heroIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 0,
      height: 80,
      justifyContent: "center",
      width: 80,
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
    bodyText: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    loginCard: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingVertical: spacing.lg,
    },
    loginCardHeading: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.xs,
    },
    loginCardTitle: {
      color: colors.text,
      flex: 1,
      flexShrink: 1,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
      minWidth: 0,
    },
    loginCardBody: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    inviteNotice: {
      alignItems: "flex-start",
      backgroundColor: colors.surface,
      borderRadius: 18,
      flexDirection: "row",
      gap: spacing.xs,
      padding: spacing.md,
    },
    inviteNoticeText: {
      color: colors.text,
      flex: 1,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    listHero: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.md,
      paddingTop: spacing.sm,
    },
    listHeroCopy: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    wardCountBadge: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 0,
      minHeight: 72,
      justifyContent: "center",
      minWidth: 72,
      paddingHorizontal: spacing.sm,
    },
    wardCountValue: {
      color: colors.cta,
      fontSize: 32,
      fontVariant: ["tabular-nums"],
      fontWeight: "900",
      lineHeight: 40,
    },
    wardCountLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    listGuidance: {
      alignItems: "flex-start",
      backgroundColor: colors.careBg,
      borderLeftColor: colors.careStrong,
      borderLeftWidth: 4,
      flexDirection: "row",
      gap: spacing.sm,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.md,
    },
    listGuidanceText: {
      color: colors.text,
      flex: 1,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    wardList: {
      gap: spacing.sm,
    },
    wardCard: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 24,
      borderWidth: 1,
      elevation: 3,
      borderLeftColor: colors.cta,
      borderLeftWidth: 4,
      gap: spacing.sm,
      overflow: "hidden",
      padding: spacing.md,
      position: "relative",
      shadowColor: colors.shadow,
      shadowOffset: { height: 7, width: 0 },
      shadowOpacity: 0.07,
      shadowRadius: 15,
    },
    wardGlow: { backgroundColor: colors.surfaceSoft, borderRadius: 120, height: 170, opacity: 0.5, position: "absolute", right: -92, top: -110, width: 170 },
    wardOpenArea: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.sm,
      minHeight: touchTargetMin,
    },
    rowPressed: {
      backgroundColor: colors.infoBg,
    },
    wardAvatar: {
      alignItems: "center",
      borderRadius: 18,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    wardAvatarText: {
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    wardText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    wardName: {
      color: colors.text,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    wardMeta: {
      color: colors.textMuted,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    wardSummaryRow: {
      alignItems: "flex-start",
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
    },
    riskBadge: {
      borderRadius: 999,
      minHeight: 44,
      paddingHorizontal: spacing.xs,
      paddingVertical: 4,
    },
    wardRisk: {
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    wardSummary: {
      color: colors.text,
      flex: 1,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
      minWidth: 160,
    },
    wardFooter: {
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.sm,
      paddingTop: spacing.sm,
    },
    wardUnread: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    wardActions: {
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
    },
    textButton: {
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
    removeButton: {
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
    textButtonLabel: {
      color: colors.cta,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    secondaryTextButtonLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    removeButtonLabel: {
      color: colors.dangerStrong,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    removeButtonPressed: {
      opacity: 0.72,
    },
    refreshAction: {
      alignItems: "center",
      alignSelf: "center",
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 16,
      borderWidth: 1,
      flexDirection: "row",
      gap: spacing.xs,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.xs,
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
      borderRadius: 24,
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
    addCard: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 28,
      borderWidth: 1,
      elevation: 3,
      gap: spacing.md,
      padding: spacing.lg,
      shadowColor: colors.shadow,
      shadowOffset: { height: 7, width: 0 },
      shadowOpacity: 0.07,
      shadowRadius: 15,
    },
    addHeading: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    sectionIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 24,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    sectionHeaderText: {
      flex: 1,
      gap: 2,
      minWidth: 0,
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
    heroScoreLine: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
    },
    heroScoreCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    heroScoreEyebrow: {
      color: colors.ctaText,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 28,
      opacity: 0.86,
    },
    heroScoreTitle: {
      color: colors.ctaText,
      flexShrink: 1,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    heroScoreBody: {
      color: colors.ctaText,
      flexShrink: 1,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
      opacity: 0.84,
    },
    dashboardHeroCard: {
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      gap: spacing.md,
      paddingVertical: spacing.lg,
    },
    dashboardHeader: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.md,
    },
    dashboardHeaderText: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    modeNotice: {
      alignItems: "flex-start",
      backgroundColor: colors.careBg,
      borderRadius: 0,
      flexDirection: "row",
      gap: spacing.xs,
      padding: spacing.md,
    },
    modeNoticeText: {
      color: colors.text,
      flex: 1,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    leadCard: {
      alignItems: "flex-start",
      backgroundColor: colors.bg,
      borderBottomColor: colors.divider,
      borderBottomWidth: 1,
      borderLeftColor: colors.cta,
      borderLeftWidth: 4,
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      flexDirection: "row",
      gap: spacing.sm,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.md,
    },
    leadIcon: {
      alignItems: "center",
      borderRadius: 24,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    leadCopy: {
      flex: 1,
      gap: 4,
      minWidth: 0,
    },
    leadEyebrow: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    leadTitle: {
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    leadBody: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    summaryGrid: {
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.sm,
    },
    summaryTile: {
      alignItems: "flex-start",
      backgroundColor: colors.surfaceMuted,
      borderRadius: 20,
      flexBasis: "46%",
      flexGrow: 1,
      gap: 2,
      minHeight: 128,
      justifyContent: "center",
      minWidth: 140,
      padding: spacing.md,
    },
    summaryValue: {
      color: colors.text,
      fontSize: 32,
      fontVariant: ["tabular-nums"],
      fontWeight: "900",
      lineHeight: 40,
    },
    summaryLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    riskSection: {
      gap: spacing.sm,
    },
    researchNotice: {
      alignItems: "flex-start",
      backgroundColor: colors.warnBg,
      borderLeftColor: colors.warnStrong,
      borderLeftWidth: 5,
      flexDirection: "row",
      gap: spacing.md,
      padding: spacing.lg,
    },
    researchNoticeCopy: {
      flex: 1,
      gap: spacing.xs,
      minWidth: 0,
    },
    researchNoticeTitle: {
      color: colors.warnStrong,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    researchNoticeBody: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "600",
      lineHeight: 30,
    },
    sectionLabelRow: {
      alignItems: "center",
      flexDirection: "row",
      gap: spacing.xs,
    },
    calmCard: {
      alignItems: "flex-start",
      backgroundColor: colors.safeBg,
      borderLeftColor: colors.safeStrong,
      borderLeftWidth: 4,
      borderColor: colors.borderSubtle,
      borderRadius: 22,
      borderWidth: 1,
      elevation: 2,
      flexDirection: "row",
      gap: spacing.sm,
      padding: spacing.lg,
    },
    notificationsSection: {
      gap: spacing.sm,
    },
    notificationList: {
      gap: spacing.sm,
    },
    notificationCard: {
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 20,
      borderWidth: 1,
      elevation: 2,
      gap: 2,
      padding: spacing.md,
      shadowColor: colors.shadow,
      shadowOffset: { height: 5, width: 0 },
      shadowOpacity: 0.05,
      shadowRadius: 11,
    },
    notificationTitle: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "900",
      lineHeight: 30,
    },
    notificationMessage: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "500",
      lineHeight: 30,
    },
    noNotification: {
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 20,
      borderWidth: 1,
      minHeight: touchTargetMin,
      justifyContent: "center",
      padding: spacing.md,
    },
    dashboardActions: {
      borderTopColor: colors.divider,
      borderTopWidth: 1,
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.sm,
      paddingTop: spacing.sm,
    },
    dashboardAction: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 18,
      borderWidth: 1,
      flexDirection: "row",
      flexGrow: 1,
      gap: spacing.xs,
      justifyContent: "center",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.xs,
    },
    dashboardRemoveAction: {
      alignItems: "center",
      backgroundColor: colors.dangerBg,
      borderColor: colors.dangerStrong,
      borderRadius: 18,
      borderWidth: 1,
      flexDirection: "row",
      flexGrow: 1,
      gap: spacing.xs,
      justifyContent: "center",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.md,
      paddingVertical: spacing.xs,
    },
    modalAvoider: {
      flex: 1,
    },
    modalBackdrop: {
      backgroundColor: "rgba(15,23,42,0.52)",
      flex: 1,
      justifyContent: "flex-end",
    },
    modal: {
      alignSelf: "stretch",
      backgroundColor: colors.surface,
      borderColor: colors.borderSubtle,
      borderRadius: 30,
      borderWidth: 1,
      maxHeight: "88%",
      width: "100%",
    },
    modalContent: {
      gap: spacing.md,
      padding: spacing.lg,
    },
    modalHeader: {
      alignItems: "flex-start",
      flexDirection: "row",
      gap: spacing.sm,
    },
    modalIcon: {
      alignItems: "center",
      backgroundColor: colors.infoBg,
      borderRadius: 18,
      height: 48,
      justifyContent: "center",
      width: 48,
    },
    modalHeaderCopy: {
      flex: 1,
      gap: 2,
      minWidth: 0,
    },
    modalTitle: {
      color: colors.text,
      flexShrink: 1,
      fontSize: 24,
      fontWeight: "900",
      lineHeight: 32,
    },
    accountName: {
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 18,
      borderWidth: 1,
      gap: 2,
      padding: spacing.md,
    },
    accountNameLabel: {
      color: colors.textMuted,
      fontSize: 20,
      fontWeight: "700",
      lineHeight: 30,
    },
    accountNameValue: {
      color: colors.text,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
    modalActions: {
      flexDirection: "row",
      flexWrap: "wrap",
      gap: spacing.xs,
    },
    modalSecondaryAction: {
      alignItems: "center",
      backgroundColor: colors.surfaceMuted,
      borderColor: colors.borderSubtle,
      borderRadius: 16,
      borderWidth: 1,
      flexDirection: "row",
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    modalPrimaryAction: {
      alignItems: "center",
      backgroundColor: colors.cta,
      borderRadius: 16,
      flexDirection: "row",
      gap: 4,
      minHeight: touchTargetMin,
      paddingHorizontal: spacing.sm,
      paddingVertical: spacing.xs,
    },
    modalPrimaryActionPressed: {
      backgroundColor: colors.ctaPressed,
    },
    modalPrimaryActionLabel: {
      color: colors.ctaText,
      fontSize: 20,
      fontWeight: "800",
      lineHeight: 30,
    },
  });
