import type { GuardianWard, GuardianWardSummary } from "../api/types";

const GENERIC_WARD_NAMES = new Set(["", "보호자", "가족", "이웃", "친구", "도우미", "보호 대상"]);

function cleanName(value: string | null | undefined) {
  return String(value ?? "").trim();
}

export function isGenericGuardianWardName(value: string | null | undefined) {
  return GENERIC_WARD_NAMES.has(cleanName(value));
}

export function guardianWardTitle(ward: GuardianWard, index: number, wards: GuardianWard[]) {
  const rawName = guardianWardBaseTitle(ward);
  const sameNameCount = wards.filter((item) => guardianWardBaseTitle(item) === rawName).length;
  if (!rawName) return "이름 미설정";
  if (sameNameCount > 1) {
    const sameBefore = wards.slice(0, index).filter((item) => guardianWardBaseTitle(item) === rawName).length;
    return `${rawName} ${sameBefore + 1}`;
  }
  return rawName;
}

export function guardianWardSubtitle(ward: GuardianWard, index: number, wards: GuardianWard[]) {
  void index;
  void wards;
  const rawName = cleanName(ward.ward_display_name);
  const accountName = cleanName(ward.ward_account_name);
  const alias = cleanName(ward.ward_alias);
  const parts: string[] = [];
  if (alias && accountName) {
    parts.push(`계정 이름 ${accountName}`);
  } else if (accountName && rawName && rawName !== accountName && !isGenericGuardianWardName(rawName)) {
    parts.push(`계정 이름 ${accountName}`);
  } else if (!accountName && rawName && isGenericGuardianWardName(rawName)) {
    parts.push(`초대명 ${rawName}`);
  }
  parts.push(formatShortDate(ward.last_viewed_at || ward.accepted_at));
  return parts.join(" · ");
}

export function guardianWardAccountName(ward: GuardianWard) {
  return cleanName(ward.ward_account_name) || cleanName(ward.ward_display_name) || "계정 이름 없음";
}

export function guardianWardSummaryText(summary: GuardianWardSummary | undefined) {
  if (!summary) return "진단 요약 대기";
  const score = summary.score_status === "no_targets"
    ? "점검 완료 · 대상 없음"
    : summary.score === null || summary.score === undefined
    ? "점검 전"
    : `점수 ${summary.score}`;
  const caution = summary.caution_devices > 0 ? ` · 주의 ${summary.caution_devices}개` : "";
  return `${score} · 물건 ${summary.device_count}개 · 위험 ${summary.high_risk_devices}개${caution}`;
}

export function guardianWardRiskLabel(summary: GuardianWardSummary | undefined) {
  if (!summary) return "점검 전";
  if (summary.score_status === "no_targets") return "평가 대상 없음";
  if (summary.high_risk_devices > 0) return `조치 필요 ${summary.high_risk_devices}개`;
  if (summary.risk_level === "green") return "위험 없음";
  if (summary.risk_level === "yellow") return "주의";
  if (summary.risk_level === "red") return "조치 필요";
  return "점검 필요";
}

export function guardianWardUnreadLabel(summary: GuardianWardSummary | undefined) {
  if (!summary) return "새 소식 0개";
  return `새 소식 ${summary.unread_notifications}개`;
}

function formatShortDate(value: string | null | undefined) {
  if (!value) return "연결 날짜 미확인";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "연결 날짜 미확인";
  return `${date.getMonth() + 1}/${date.getDate()} 확인`;
}

function guardianWardBaseTitle(ward: GuardianWard) {
  const alias = cleanName(ward.ward_alias);
  const accountName = cleanName(ward.ward_account_name);
  const displayName = cleanName(ward.ward_display_name);
  if (alias) return alias;
  if (accountName) return accountName;
  if (displayName && !isGenericGuardianWardName(displayName)) return displayName;
  return "";
}
