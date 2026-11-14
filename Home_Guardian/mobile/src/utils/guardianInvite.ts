import type { GuardianInvite } from "../api/types";

export type GuardianStatus = "pending" | "accepted" | "expired" | "revoked" | "unknown";

const STATUS_LABELS: Record<GuardianStatus, string> = {
  pending: "초대 대기",
  accepted: "연결됨",
  expired: "만료",
  revoked: "초대 취소",
  unknown: "확인 필요",
};

export function parseGuardianInviteInput(value: string) {
  const trimmed = value.trim();
  const match = trimmed.match(/[?&](?:invite|code|invite_id)=([^&#]+)/i);
  const raw = match ? decodeURIComponent(match[1]) : trimmed;
  const compact = raw.replace(/\s/g, "").toUpperCase();
  const codeOnly = compact.replace(/-/g, "");
  if (/^[A-Z0-9]{8}$/.test(codeOnly)) {
    return `${codeOnly.slice(0, 4)}-${codeOnly.slice(4)}`;
  }
  return raw.trim();
}

function normalizedShortCode(value?: string | null) {
  if (!value) return "";
  const parsed = parseGuardianInviteInput(value);
  return /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(parsed) ? parsed : "";
}

export function guardianInviteCode(invite: GuardianInvite) {
  return normalizedShortCode(invite.short_code) || normalizedShortCode(invite.deep_link);
}

export function guardianInviteLink(invite: GuardianInvite) {
  const code = guardianInviteCode(invite);
  return invite.deep_link || `homeguardian://join?invite=${encodeURIComponent(code || invite.invite_id)}`;
}

export function guardianStatus(invite: GuardianInvite): GuardianStatus {
  const status = (invite.status || "").toLowerCase();
  if (status === "sent" || status === "pending") return "pending";
  if (status === "accepted") return "accepted";
  if (status === "expired") return "expired";
  if (status === "revoked") return "revoked";
  return "unknown";
}

export function guardianStatusLabel(invite: GuardianInvite) {
  return invite.status_label || STATUS_LABELS[guardianStatus(invite)];
}

export function isGuardianInviteShareable(invite: GuardianInvite) {
  return guardianStatus(invite) === "pending" || guardianStatus(invite) === "accepted";
}

export function isGuardianInviteRevokable(invite: GuardianInvite) {
  const status = guardianStatus(invite);
  return status === "pending" || status === "accepted";
}

export function guardianInviteMatches(invite: GuardianInvite, query: string) {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return [
    invite.email,
    invite.relation,
    invite.display_name,
    invite.short_code,
    invite.invite_id,
    guardianStatusLabel(invite),
  ]
    .filter(Boolean)
    .some((value) => String(value).toLowerCase().includes(needle));
}
