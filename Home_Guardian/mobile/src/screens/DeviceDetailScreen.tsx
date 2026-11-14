import {
  AlertTriangle,
  Check,
  ClipboardCheck,
  Eye,
  HelpCircle,
  HelpingHand,
  Info,
  Pencil,
  RefreshCw,
  ShieldOff,
  X,
} from "lucide-react-native";
import { useEffect, useState } from "react";
import { Keyboard, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";

import { BigCTAButton } from "../components/BigCTAButton";
import { Reveal } from "../components/DesignPrimitives";
import { StudioHero } from "../components/StudioPrimitives";
import { ScreenHeader } from "../components/ScreenHeader";
import { TrafficLightBadge } from "../components/TrafficLightBadge";
import { radius, spacing, tone, touchTargetMin, type ThemeColors, useThemedStyles } from "../theme";
import type { Device } from "../api/types";
import type { HomeGuardianActions, HomeGuardianState } from "../state/useHomeGuardianController";
import { deviceIcon } from "../utils/deviceIcons";
import {
  canonicalDeviceName,
  presentDevice,
  residentDeviceAccessibilityLabel,
} from "../utils/devicePresentation";
import { audienceRiskCopy, confirmedVulnerabilities } from "../utils/riskCopy";

type DeviceDetailScreenProps = {
  state: HomeGuardianState;
  actions: HomeGuardianActions;
};

// 일반 사용자는 다음 행동을 먼저 보고, 보호자는 근거와 조치를 읽는다.
// 탐색 주소·포트·서비스 이름 등 판단에 쓰기 어려운 내부 단서는 표시하지 않는다.
export function DeviceDetailScreen({ state, actions }: DeviceDetailScreenProps) {
  const { styles } = useThemedStyles(createStyles);
  const device = state.selectedDevice ?? state.devices[0];
  const readOnly =
    state.history.includes("guardianMode") ||
    (state.screen === "detail" && Boolean(state.guardianDashboard));
  const presentedDevice = presentDevice(device);
  if (!presentedDevice) {
    return (
      <>
        <ScreenHeader title="기기 정보" onBack={() => actions.goBack() || actions.setScreen("devices")} />
        <View style={styles.empty}>
          <Text style={styles.emptyText}>선택된 기기가 없어요.</Text>
        </View>
      </>
    );
  }

  return <DeviceDetailBody device={presentedDevice} actions={actions} readOnly={readOnly} />;
}

function DeviceDetailBody({
  device,
  actions,
  readOnly,
}: {
  device: Device;
  actions: HomeGuardianActions;
  readOnly: boolean;
}) {
  const { colors, styles } = useThemedStyles(createStyles);
  const palette = tone(device.risk_level, colors);
  const Glyph = deviceIcon(device.device_type);
  const hasServerSuggestion = (device.recommended_actions ?? []).length > 0;
  const checklist = safeChecklistFor(readOnly, device.risk_level, hasServerSuggestion);
  const [checks, setChecks] = useState<boolean[]>(() => checklist.map(() => false));
  const [editingName, setEditingName] = useState(false);
  const [nameInput, setNameInput] = useState(device.name);
  const userCopy = audienceRiskCopy(device, "user");
  const guardianCopy = audienceRiskCopy(device, "guardian");
  const vulnerabilities = confirmedVulnerabilities(device);
  const canonicalName = canonicalDeviceName(device);
  const canonicalLabel = device.model ? "확인된 제품 이름과 품번" : "확인된 제품군";
  const accessibilityName = residentDeviceAccessibilityLabel(device);
  const isActionableRisk = device.risk_level === "red" || device.risk_level === "yellow";
  const isIdentityFinding = device.is_identity_finding === true;

  useEffect(() => {
    setChecks(safeChecklistFor(readOnly, device.risk_level, hasServerSuggestion).map(() => false));
    setNameInput(device.name);
    setEditingName(false);
    Keyboard.dismiss();
  }, [device.device_id, device.name, device.risk_level, hasServerSuggestion, readOnly]);

  return (
    <>
      <ScreenHeader
        title={readOnly ? "보호자 진단" : "기기 정보"}
        onBack={() => actions.goBack() || actions.setScreen("devices")}
      />
      <ScrollView contentContainerStyle={styles.body}>
        {readOnly ? (
          <View style={styles.modeNotice}>
            <View style={styles.modeIcon}>
              <Eye color={colors.cta} size={24} strokeWidth={2.4} />
            </View>
            <View style={styles.modeText}>
              <Text style={styles.modeTitle}>보기만 가능해요</Text>
              <Text style={styles.modeBody}>보호자는 상태를 확인하고 사용자에게 연락할 수 있어요.</Text>
            </View>
          </View>
        ) : null}

        <StudioHero
          eyebrow={readOnly ? "선택한 피보호자 물건" : "우리 집 물건"}
          icon={Glyph}
          title={device.name}
          titleAccessibilityLabel={accessibilityName}
          variant="paper"
        >
          {canonicalName ? (
            <View style={styles.canonicalInfo}>
              <Text style={styles.canonicalLabel}>{canonicalLabel}</Text>
              <Text style={styles.canonicalName} accessibilityLabel={canonicalLabel + ": " + canonicalName}>
                {canonicalName}
              </Text>
            </View>
          ) : null}
        </StudioHero>
        <TrafficLightBadge level={device.risk_level} size="lg" />

        {isIdentityFinding ? (
          <View style={styles.identityFindingNotice}>
            <Info color={colors.cta} size={24} strokeWidth={2.4} />
            <Text style={styles.identityFindingText}>
              {device.identity_note || "연결은 감지됐지만 제품명·품번 근거가 부족해요."}
            </Text>
          </View>
        ) : !readOnly ? (
          editingName ? (
            <View style={styles.renameEditor}>
              <TextInput
                accessibilityHint="새 이름을 입력한 뒤 저장을 누르세요."
                accessibilityLabel="기기 이름"
                autoFocus
                maxLength={40}
                onChangeText={setNameInput}
                placeholder="예: 우리 집 냉장고"
                placeholderTextColor={colors.textMuted}
                style={styles.renameInput}
                value={nameInput}
              />
              <View style={styles.renameActions}>
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="기기 이름 저장"
                  onPress={() => {
                    void actions.renameDevice(device.device_id, nameInput.trim() || null);
                    setEditingName(false);
                  }}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.textButton,
                    pressed ? styles.textButtonPressed : null,
                  ]}
                >
                  <Check color={colors.cta} size={20} strokeWidth={3} />
                  <Text style={styles.textButtonLabel}>저장</Text>
                </Pressable>
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="이름 바꾸기 취소"
                  onPress={() => {
                    setNameInput(device.name);
                    setEditingName(false);
                  }}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.textButton,
                    pressed ? styles.textButtonPressed : null,
                  ]}
                >
                  <X color={colors.textMuted} size={20} strokeWidth={3} />
                  <Text style={styles.secondaryTextButtonLabel}>취소</Text>
                </Pressable>
              </View>
            </View>
          ) : (
            <View style={styles.renameActions}>
              <Pressable
                accessibilityRole="button"
                accessibilityLabel="기기 이름 바꾸기"
                onPress={() => setEditingName(true)}
                style={({ pressed }: { pressed: boolean }) => [
                  styles.textButton,
                  pressed ? styles.textButtonPressed : null,
                ]}
              >
                <Pencil color={colors.cta} size={18} strokeWidth={2.4} />
                <Text style={styles.textButtonLabel}>이름 바꾸기</Text>
              </Pressable>
              {device.alias ? (
                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel="기본 이름으로 되돌리기"
                  onPress={() => void actions.renameDevice(device.device_id, null)}
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.textButton,
                    pressed ? styles.textButtonPressed : null,
                  ]}
                >
                  <RefreshCw color={colors.textMuted} size={18} strokeWidth={2.4} />
                  <Text style={styles.secondaryTextButtonLabel}>기본 이름</Text>
                </Pressable>
              ) : null}
            </View>
          )
        ) : null}

        <Reveal>
          <View style={styles.nextStep}>
          <View style={[styles.nextStepIcon, { backgroundColor: palette.bg }]}>
            {readOnly ? (
              <ClipboardCheck color={palette.fg} size={26} strokeWidth={2.5} />
            ) : (
              <AlertTriangle color={palette.fg} size={26} strokeWidth={2.5} />
            )}
          </View>
          <View style={styles.nextStepText}>
            <Text style={styles.nextStepEyebrow}>{readOnly ? "가장 먼저 확인할 진단" : "지금 할 수 있는 일"}</Text>
            <Text style={[styles.nextStepTitle, { color: palette.fg }]}>
              {readOnly ? guardianCopy.title : userCopy.title}
            </Text>
            <Text style={styles.nextStepBody}>{readOnly ? guardianCopy.body : userCopy.body}</Text>
            {readOnly ? (
              <>
                <Text style={styles.detailLabel}>근거</Text>
                <Text style={styles.nextStepBody}>{guardianCopy.reason}</Text>
                <Text style={styles.detailLabel}>조치</Text>
                <Text style={styles.nextStepBody}>{guardianCopy.fix}</Text>
              </>
            ) : (
              <Text style={styles.nextStepAction}>{userCopy.fix}</Text>
            )}
          </View>
          </View>
        </Reveal>

        {device.identity_note ? (
          <View style={styles.inlineNote}>
            <HelpCircle color={colors.textMuted} size={22} strokeWidth={2.3} />
            <Text style={styles.inlineNoteText}>{device.identity_note}</Text>
          </View>
        ) : null}

        {vulnerabilities.length > 0 ? (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>알려진 보안 문제</Text>
            <View style={styles.rowList}>
              {vulnerabilities.slice(0, 4).map((vuln, index) => {
                const severe = vuln.severity === "critical" || vuln.severity === "high";
                return (
                  <View key={`${vuln.cve_id ?? "vuln"}-${index}`} style={styles.vulnerabilityRow}>
                    <View style={styles.vulnerabilityText}>
                      <Text style={styles.vulnerabilitySummary}>
                        {readOnly ? guardianVulnerabilityCopy(vuln.severity) : userVulnerabilityCopy(vuln.severity)}
                      </Text>
                      <Text style={styles.vulnerabilityFix}>
                        {readOnly
                          ? "제조사 앱에서 업데이트 여부와 비밀번호를 확인해 주세요."
                          : "보호자와 함께 제조사 앱에서 업데이트가 있는지 확인해 주세요."}
                      </Text>
                    </View>
                    <Text style={[styles.vulnerabilityLabel, { color: severe ? colors.dangerStrong : colors.warnStrong }]}>
                      {severityLabel(vuln.severity)}
                    </Text>
                  </View>
                );
              })}
            </View>
          </View>
        ) : null}

        {checklist.length > 0 ? (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>차례대로 해 보세요</Text>
            <View style={styles.rowList}>
              {checklist.map((step, index) => (
                <Pressable
                  key={step}
                  accessibilityRole="checkbox"
                  accessibilityLabel={step}
                  accessibilityHint="누르면 이 안내를 마친 것으로 표시해요."
                  accessibilityState={{ checked: checks[index] }}
                  onPress={() =>
                    setChecks((previous) =>
                      previous.map((value, itemIndex) => (itemIndex === index ? !value : value)),
                    )
                  }
                  style={({ pressed }: { pressed: boolean }) => [
                    styles.checkItem,
                    pressed ? styles.checkItemPressed : null,
                  ]}
                >
                  <View style={[styles.checkBox, checks[index] ? styles.checkBoxDone : null]}>
                    {checks[index] ? <Check color={colors.ctaText} size={18} strokeWidth={3.5} /> : null}
                  </View>
                  <Text style={[styles.checkText, checks[index] ? styles.checkTextDone : null]}>{step}</Text>
                </Pressable>
              ))}
            </View>
          </View>
        ) : null}

        {!readOnly && device.risk_level === "red" ? (
          <View style={styles.section}>
            <View style={styles.blockHeading}>
              <View style={[styles.blockIcon, { backgroundColor: colors.dangerBg }]}>
                <ShieldOff color={colors.dangerStrong} size={24} strokeWidth={2.5} />
              </View>
              <Text style={[styles.sectionTitle, styles.blockHeadingTitle]}>이 기기를 차단하려면</Text>
            </View>
            <Text style={styles.blockBody}>
              위험이 계속되면 공유기에서 이 기기의 인터넷 연결을 막을 수 있어요. 잘 모르겠으면 보호자에게 도움을 요청해 주세요.
            </Text>
            <Text style={styles.blockStep}>1. 공유기 앱이나 관리 화면을 열어요.</Text>
            <Text style={styles.blockStep}>
              2. 연결된 기기 목록에서 이 기기({device.name})를 찾아 차단 또는 연결 거부로 설정해요.
            </Text>
            <Text style={styles.blockStep}>3. 잘 모르겠으면 아래 보호자에게 도움 요청을 눌러 주세요.</Text>
          </View>
        ) : null}

        {!readOnly && isActionableRisk ? (
          <>
            <BigCTAButton
              label="보호자에게 도움 요청"
              icon={HelpingHand}
              tone="cta"
              onPress={actions.shareScanWithGuardian}
            />
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="다시 점검하기"
              onPress={actions.retryScan}
              style={({ pressed }: { pressed: boolean }) => [
                styles.secondaryAction,
                pressed ? styles.secondaryActionPressed : null,
              ]}
            >
              <RefreshCw color={colors.textMuted} size={22} strokeWidth={2.4} />
              <Text style={styles.secondaryActionLabel}>다시 점검하기</Text>
            </Pressable>
          </>
        ) : null}
        {!readOnly && !isActionableRisk ? (
          <BigCTAButton
            label="다시 점검하기"
            icon={RefreshCw}
            tone="cta"
            onPress={actions.retryScan}
          />
        ) : null}
      </ScrollView>
    </>
  );
}

function severityLabel(severity: string | undefined) {
  if (severity === "critical" || severity === "high") return "높은 위험";
  if (severity === "medium") return "주의 필요";
  if (severity === "low") return "낮은 위험";
  return "보안 문제";
}

function userVulnerabilityCopy(severity: string | undefined) {
  if (severity === "critical" || severity === "high") return "제조사에서 알린 보안 문제가 있어요. 바로 확인해 주세요.";
  if (severity === "medium") return "제조사에서 알린 보안 문제가 있어요. 보호자와 함께 확인해 주세요.";
  return "제조사에서 알린 보안 문제가 있어요. 업데이트가 있는지 확인해 주세요.";
}

function guardianVulnerabilityCopy(severity: string | undefined) {
  if (severity === "critical" || severity === "high") return "제조사에서 알린 보안 문제가 있어 바로 확인이 필요합니다.";
  if (severity === "medium") return "제조사에서 알린 보안 문제가 있어 확인이 필요합니다.";
  return "제조사에서 알린 보안 문제가 있어 업데이트 여부를 확인해 주세요.";
}

function safeChecklistFor(
  readOnly: boolean,
  riskLevel: Device["risk_level"],
  hasServerSuggestion: boolean,
): string[] {
  return readOnly
    ? guardianSafeChecklist(riskLevel, hasServerSuggestion)
    : userSafeChecklist(riskLevel, hasServerSuggestion);
}

function userSafeChecklist(riskLevel: Device["risk_level"], hasServerSuggestion: boolean): string[] {
  if (riskLevel === "red") {
    return [
      "보호자에게 이 화면을 보여 주세요.",
      "기기 앱에서 비밀번호와 업데이트를 함께 확인해 주세요.",
      "모르면 기기를 잠시 인터넷에서 분리하고 도움을 받아 주세요.",
    ];
  }
  if (riskLevel === "yellow") {
    return [
      "보호자와 함께 기기 앱에서 비밀번호와 업데이트를 확인해 주세요.",
      "확인이 끝나면 다시 점검해 주세요.",
    ];
  }
  return hasServerSuggestion ? ["새 물건을 연결했거나 설정을 바꾼 뒤 다시 점검해 주세요."] : [];
}

function guardianSafeChecklist(riskLevel: Device["risk_level"], hasServerSuggestion: boolean): string[] {
  if (riskLevel === "red") {
    return [
      "사용자에게 이 화면을 보여 주고 함께 확인해 주세요.",
      "제조사 앱에서 비밀번호와 업데이트 상태를 확인해 주세요.",
      "도움이 필요하면 기기를 잠시 인터넷에서 분리하도록 안내해 주세요.",
    ];
  }
  if (riskLevel === "yellow") {
    return [
      "사용자와 함께 제조사 앱에서 비밀번호와 업데이트를 확인해 주세요.",
      "확인이 끝나면 다시 점검하도록 안내해 주세요.",
    ];
  }
  return hasServerSuggestion ? ["새 물건을 연결했거나 설정을 바꾼 뒤 다시 점검하도록 안내해 주세요."] : [];
}

const createStyles = (colors: ThemeColors) => StyleSheet.create({
  body: {
    gap: spacing.xl,
    padding: spacing.lg,
  },
  empty: {
    flex: 1,
    justifyContent: "center",
    padding: spacing.lg,
  },
  emptyText: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  modeNotice: {
    alignItems: "center",
    backgroundColor: colors.careBg,
    borderLeftColor: colors.careStrong,
    borderLeftWidth: 4,
    flexDirection: "row",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.md,
  },
  identityFindingNotice: {
    alignItems: "center",
    backgroundColor: colors.infoBg,
    borderLeftColor: colors.cta,
    borderLeftWidth: 4,
    flexDirection: "row",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.md,
  },
  identityFindingText: {
    color: colors.text,
    flex: 1,
    // Keep the resolver guidance readable for the ward-facing large-text
    // contract enforced by the release static gate.
    fontSize: 20,
    fontWeight: "600",
    lineHeight: 30,
  },
  modeIcon: {
    alignItems: "center",
    backgroundColor: colors.infoBg,
    borderRadius: 22,
    height: 44,
    justifyContent: "center",
    width: 44,
  },
  modeText: {
    flex: 1,
    gap: 2,
    minWidth: 0,
  },
  modeTitle: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "800",
    lineHeight: 30,
  },
  modeBody: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  hero: {
    alignItems: "flex-start",
    backgroundColor: colors.bg,
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    flexDirection: "row",
    gap: spacing.md,
    paddingBottom: spacing.xl,
    paddingTop: spacing.lg,
  },
  iconCircle: {
    alignItems: "center",
    borderColor: colors.borderSubtle,
    borderRadius: 40,
    borderWidth: 1,
    height: 80,
    justifyContent: "center",
    width: 80,
  },
  heroText: {
    flex: 1,
    gap: 4,
    minWidth: 0,
  },
  eyebrow: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 30,
  },
  title: {
    color: colors.text,
    flexShrink: 1,
    fontSize: 32,
    fontWeight: "900",
    lineHeight: 40,
  },
  canonicalInfo: {
    gap: 2,
  },
  canonicalLabel: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 28,
  },
  canonicalName: {
    color: colors.text,
    flexShrink: 1,
    fontSize: 20,
    fontWeight: "600",
    lineHeight: 30,
  },
  renameEditor: {
    backgroundColor: colors.surfaceMuted,
    borderLeftColor: colors.cta,
    borderLeftWidth: 4,
    gap: spacing.sm,
    padding: spacing.md,
  },
  renameInput: {
    backgroundColor: colors.surface,
    borderBottomColor: colors.borderStrong,
    borderBottomWidth: 2,
    color: colors.text,
    fontSize: 20,
    fontWeight: "600",
    minHeight: touchTargetMin,
    paddingHorizontal: spacing.md,
  },
  renameActions: {
    alignItems: "center",
    flexDirection: "row",
    flexWrap: "wrap",
    gap: spacing.sm,
  },
  textButton: {
    alignItems: "center",
    flexDirection: "row",
    gap: 6,
    minHeight: touchTargetMin,
    paddingHorizontal: spacing.sm,
  },
  textButtonPressed: {
    backgroundColor: colors.infoBg,
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
  nextStep: {
    alignItems: "flex-start",
    backgroundColor: colors.bg,
    borderLeftColor: colors.cta,
    borderLeftWidth: 5,
    borderTopColor: colors.divider,
    borderTopWidth: 1,
    flexDirection: "row",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.lg,
  },
  nextStepIcon: {
    alignItems: "center",
    borderRadius: 24,
    height: 48,
    justifyContent: "center",
    width: 48,
  },
  nextStepText: {
    flex: 1,
    gap: 4,
    minWidth: 0,
  },
  nextStepEyebrow: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 30,
  },
  nextStepTitle: {
    fontSize: 24,
    fontWeight: "900",
    lineHeight: 32,
  },
  nextStepBody: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  nextStepAction: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "800",
    lineHeight: 30,
  },
  detailLabel: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "800",
    lineHeight: 30,
    marginTop: spacing.xs,
  },
  inlineNote: {
    alignItems: "flex-start",
    backgroundColor: colors.surfaceMuted,
    borderLeftColor: colors.borderStrong,
    borderLeftWidth: 4,
    flexDirection: "row",
    gap: spacing.xs,
    padding: spacing.md,
  },
  inlineNoteText: {
    color: colors.textMuted,
    flex: 1,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  section: {
    backgroundColor: colors.bg,
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    borderTopColor: colors.divider,
    borderTopWidth: 1,
    gap: spacing.sm,
    paddingVertical: spacing.lg,
  },
  sectionTitle: {
    color: colors.text,
    fontSize: 24,
    fontWeight: "800",
    lineHeight: 32,
  },
  rowList: {
    borderTopColor: colors.divider,
    borderTopWidth: 1,
    overflow: "hidden",
  },
  vulnerabilityRow: {
    alignItems: "flex-start",
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    flexDirection: "row",
    gap: spacing.sm,
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.md,
  },
  vulnerabilityText: {
    flex: 1,
    gap: 4,
    minWidth: 0,
  },
  vulnerabilitySummary: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 30,
  },
  vulnerabilityFix: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  vulnerabilityLabel: {
    fontSize: 20,
    fontWeight: "800",
    lineHeight: 30,
    textAlign: "right",
  },
  checkItem: {
    alignItems: "flex-start",
    borderBottomColor: colors.divider,
    borderBottomWidth: 1,
    flexDirection: "row",
    gap: spacing.sm,
    minHeight: touchTargetMin,
    paddingHorizontal: spacing.md,
    paddingVertical: spacing.md,
  },
  checkItemPressed: {
    backgroundColor: colors.infoBg,
  },
  checkBox: {
    alignItems: "center",
    borderColor: colors.textMuted,
    borderRadius: 14,
    borderWidth: 2,
    height: 28,
    justifyContent: "center",
    marginTop: 2,
    width: 28,
  },
  checkBoxDone: {
    backgroundColor: colors.cta,
    borderColor: colors.cta,
  },
  checkText: {
    color: colors.text,
    flex: 1,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  checkTextDone: {
    color: colors.textMuted,
    textDecorationLine: "line-through",
  },
  blockHeading: {
    alignItems: "center",
    flexDirection: "row",
    gap: spacing.sm,
  },
  blockHeadingTitle: {
    flex: 1,
    flexShrink: 1,
    minWidth: 0,
  },
  blockIcon: {
    alignItems: "center",
    borderRadius: 24,
    height: 48,
    justifyContent: "center",
    width: 48,
  },
  blockBody: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "500",
    lineHeight: 30,
  },
  blockStep: {
    color: colors.text,
    fontSize: 20,
    fontWeight: "600",
    lineHeight: 30,
  },
  secondaryAction: {
    alignItems: "center",
    alignSelf: "center",
    flexDirection: "row",
    gap: spacing.xs,
    minHeight: touchTargetMin,
    paddingHorizontal: spacing.md,
  },
  secondaryActionPressed: {
    backgroundColor: colors.infoBg,
  },
  secondaryActionLabel: {
    color: colors.textMuted,
    fontSize: 20,
    fontWeight: "700",
    lineHeight: 30,
  },
});
