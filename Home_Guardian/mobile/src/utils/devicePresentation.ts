import type {
  DashboardData,
  Device,
  DetectedConnection,
  GuardianDashboard,
  NotificationItem,
  RiskLevel,
  ScanResult,
} from "../api/types";
import {
  hasConfirmedRedRisk,
  identityResearchState,
  normalizedScanStatus,
  scanCoverageState,
} from "./scanCoverage";

// The server is the source of truth. This second boundary prevents an old local cache,
// an interrupted update, or a malformed response from putting an internal discovery label
// back onto a resident-facing screen.
const FORBIDDEN_TERMS = [
  "웹 관리 기기",
  "제조사 미확인",
  "정체불명 기기",
  "알 수 없는 기기",
  "기기 후보",
  "확인 필요 기기",
  "임시 인터넷 신호",
  "확인되지 않은 신호",
  "현재 Wi-Fi 이웃 확인",
  "TCP 서비스 응답",
  "기기 정보 방송 응답",
  "연결된 장비",
  "서비스 응답",
  "제조사 없음",
  "제조사 알 수 없음",
  "미확인",
  "정체불명",
  "알 수 없는",
  "확인되지 않은",
  "임시 기기",
  "후보 기기",
  "unknown device",
  "unidentified device",
  "unverified device",
  "candidate device",
  "unresolved device",
  "temporary device",
  "generic device",
  "web-device",
  "web device",
  "iot device",
  "espressif",
  "realtek",
  "seongji",
  "intel",
  "mediatek",
  "qualcomm",
  "broadcom",
  "microsoft",
  "librespot",
  "spotify",
  "atheros",
  "esp32",
  "esp8266",
  "chipset",
  "칩셋",
];

// A resident must never receive an address, MAC/OUI, or registration-authority trace
// through a legacy cache field or a newly added backend field. Address detection is
// intentionally separate from the other discovery patterns: compressed IPv6 has too
// many valid spellings for a single loose regex, and timestamps such as 00:00:00 must
// not be mistaken for an address while cache values are being normalized.
const IPV4_ADDRESS_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/u;
const MAC_ADDRESS_PATTERNS = [
  /\b(?:[0-9A-F]{2}:){5}[0-9A-F]{2}\b/iu,
  /\b(?:[0-9A-F]{2}-){5}[0-9A-F]{2}\b/iu,
  /\b(?:[0-9A-F]{4}\.){2}[0-9A-F]{4}\b/iu,
] as const;
const LEGACY_DASHED_DEVICE_ID_PATTERN = /(?:^|[^A-Za-z0-9])(?:dev|device)-(?:25[0-5]|2[0-4]\d|1?\d{1,2})-(?:25[0-5]|2[0-4]\d|1?\d{1,2})-(?:25[0-5]|2[0-4]\d|1?\d{1,2})-(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?![A-Za-z0-9])/iu;
const FULL_IPV6_ADDRESS_PATTERN = /(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])/u;
// Require the IPv6 compression marker (`::`).  A looser "one or more colons"
// expression would accidentally suppress ordinary times such as 00:00:00.
const COMPRESSED_IPV6_ADDRESS_PATTERN = /(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){1,7}:[0-9A-Fa-f]{0,4}|::[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:])/u;

function containsPrivateNetworkIdentifier(value: string): boolean {
  return (
    IPV4_ADDRESS_PATTERN.test(value) ||
    MAC_ADDRESS_PATTERNS.some((pattern) => pattern.test(value)) ||
    LEGACY_DASHED_DEVICE_ID_PATTERN.test(value) ||
    FULL_IPV6_ADDRESS_PATTERN.test(value) ||
    COMPRESSED_IPV6_ADDRESS_PATTERN.test(value)
  );
}

// These checks apply to every string before the explicit public object is built.
const PRIVATE_DISCOVERY_PATTERNS = [
  /\b(?:rtl\d+[a-z0-9-]*|mt\d{3,}[a-z0-9-]*|qca\d+[a-z0-9-]*|bcm\d+[a-z0-9-]*)\b/iu,
  /\b(?:oui|ieee|iana|ma-[lms]|organizationally unique identifier|registration authority|private registration authority|registered (?:organization|owner))\b/iu,
  /\bmac(?:\s*(?:address|vendor|prefix))?\b/iu,
  /(?:등록\s*(?:기관|정보|소유자|회사)|(?:private|사설)\s*등록\s*기관|칩\s*제조사)/iu,
];

const PRIVATE_DISCOVERY_KEY = /(?:^|[_-])(?:ip|mac|bssid|oui|ieee|iana|ma[_-]?[lms]|registr(?:ation|ar|y)?|registry|authority|allocation|chip(?:set)?|fingerprint|discovery|service|port)(?:$|[_-])/iu;
const MAX_SANITIZER_DEPTH = 8;

// Resident aliases are location or purpose names, never technical discovery evidence.
// Unsafe aliases fall back to the verified product name before they reach visible copy.

const RESIDENT_ALIAS_TECHNICAL_PATTERNS = [
  /\b(?:mdns|ssdp|onvif|rtsp|upnp|spotify(?:-connect)?|cve(?:[-_]?\d+)?|api|oauth|pkce|https?)\b/iu,
  /(?:\uD3EC\uD2B8|\uD504\uB85C\uD1A0\uCF5C|\uD38C\uC6E8\uC5B4|\uC11C\uBC84\s*\uC8FC\uC18C|ip\s*\uC8FC\uC18C|mac\s*\uC8FC\uC18C)/iu,
];

const UNKNOWN_NOTIFICATION_TIME_LABEL = "\uC2DC\uAC04\uC744 \uD655\uC778\uD560 \uC218 \uC5C6\uC5B4\uC694.";
const ISO_NOTIFICATION_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-](?:[01]\d|2[0-3]):?[0-5]\d)$/u;

// The cache can predate the server-side presentation boundary. A raw label may
// be reused only if it contains independently stored product evidence: a verified
// manufacturer and model code that are both present in the visible legacy label.
// Scanner placeholders are never treated as a category or as product evidence.
const PUBLIC_DEVICE_TYPES = new Set([
  "camera",
  "router",
  "fridge",
  "refrigerator",
  "tv",
  "speaker",
  "lock",
  "plug",
  "hub",
  "phone",
  "tablet",
  "computer",
  "nas",
  "printer",
  "light",
  "robot",
  "thermostat",
  "air_conditioner",
]);

const PUBLIC_DEVICE_TYPE_LABELS: Record<string, string> = {
  camera: "카메라",
  router: "공유기",
  fridge: "냉장고",
  refrigerator: "냉장고",
  tv: "TV",
  speaker: "스피커",
  lock: "도어록",
  plug: "스마트 플러그",
  hub: "스마트 허브",
  phone: "휴대폰",
  tablet: "태블릿",
  computer: "컴퓨터",
  nas: "NAS/저장장치",
  printer: "프린터",
  light: "스마트 조명",
  robot: "로봇청소기",
  thermostat: "온도조절기",
  air_conditioner: "에어컨",
};

// The server may append a verified computer's resident-recognizable NetBIOS
// or mDNS host token (for example, "제조사 컴퓨터 - desktop-home").  It is a
// display suffix, never a model or a network identifier, so keep the mobile
// boundary as narrow as the backend parser.
const PUBLIC_COMPUTER_HOSTNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/u;

type SanitizedPayload = string | number | boolean | null | SanitizedPayload[] | SanitizedRecord;
type SanitizedRecord = { [key: string]: SanitizedPayload };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSanitizedRecord(value: SanitizedPayload | undefined): value is SanitizedRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeText(value: unknown): value is string {
  if (typeof value !== "string" || !value.trim()) return false;
  const trimmed = value.trim();
  const normalized = trimmed.toLowerCase();
  return (
    !FORBIDDEN_TERMS.some((term) => normalized.includes(term.toLowerCase())) &&
    !containsPrivateNetworkIdentifier(trimmed) &&
    !PRIVATE_DISCOVERY_PATTERNS.some((pattern) => pattern.test(trimmed))
  );
}

function safeText(value: unknown): string {
  return isSafeText(value) ? value.trim() : "";
}

function residentAlias(value: unknown): string {
  if (!isSafeText(value)) return "";
  const alias = value.trim();
  return RESIDENT_ALIAS_TECHNICAL_PATTERNS.some((pattern) => pattern.test(alias)) ? "" : alias;
}

function isSafePayloadKey(key: string): boolean {
  // The server emits a bounded service enum plus a verification bit for
  // evidence-backed observation labels. These two exact keys are safe; raw
  // `services`, ports and discovery records remain blocked below.
  if (
    key === "observed_service" ||
    key === "observed_service_verified" ||
    key === "observed_port" ||
    key === "observed_port_verified"
  ) {
    return true;
  }
  return isSafeText(key) && !PRIVATE_DISCOVERY_KEY.test(key);
}

// Sanitizing an unsafe field away is not enough for device identity. A stale cache
// could otherwise combine a non-product manufacturer/model with a safe-looking
// canonical name and bypass the server's product-identification boundary.
function hasUnsafeRawDeviceIdentity(device: Pick<Device, "name" | "canonical_name" | "manufacturer" | "model">): boolean {
  return [device.name, device.canonical_name, device.manufacturer, device.model].some(
    (value) => typeof value === "string" && value.trim() !== "" && !isSafeText(value),
  );
}

// Sanitize unknown nested response/cache objects first, then selectively copy only
// fields that have a resident-facing contract. The allowlists below intentionally do
// not preserve arbitrary extra keys, even when their values happen to be safe.
function sanitizeNestedPayload(
  value: unknown,
  seen: WeakSet<object> = new WeakSet<object>(),
  depth = 0,
): SanitizedPayload | undefined {
  if (typeof value === "string") return safeText(value) || undefined;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "boolean" || value === null) return value;
  if (depth >= MAX_SANITIZER_DEPTH) return undefined;

  if (Array.isArray(value)) {
    return value.flatMap((item) => {
      const sanitized = sanitizeNestedPayload(item, seen, depth + 1);
      return sanitized === undefined ? [] : [sanitized];
    });
  }

  if (!isRecord(value) || seen.has(value)) return undefined;
  seen.add(value);

  const sanitized: SanitizedRecord = {};
  for (const [key, item] of Object.entries(value)) {
    if (!isSafePayloadKey(key)) continue;
    const child = sanitizeNestedPayload(item, seen, depth + 1);
    if (child !== undefined) sanitized[key] = child;
  }
  return sanitized;
}

function sanitizedRecord(value: unknown): SanitizedRecord | null {
  const sanitized = sanitizeNestedPayload(value);
  return isSanitizedRecord(sanitized) ? sanitized : null;
}

function textField(record: SanitizedRecord, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value : "";
}

function optionalTextField(record: SanitizedRecord, key: string): string | undefined {
  const value = textField(record, key);
  return value || undefined;
}

function booleanField(record: SanitizedRecord, key: string, fallback = false): boolean {
  return typeof record[key] === "boolean" ? record[key] : fallback;
}

function numberField(record: SanitizedRecord, key: string, fallback = 0): number {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function nullableNumberField(record: SanitizedRecord, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function recordField(record: SanitizedRecord, key: string): SanitizedRecord {
  const value = record[key];
  return isSanitizedRecord(value) ? value : {};
}

function riskLevelField(record: SanitizedRecord, key: string, fallback: RiskLevel = "unknown"): RiskLevel {
  const value = record[key];
  return value === "green" || value === "yellow" || value === "red" || value === "unknown" ? value : fallback;
}

function scanStatusField(record: SanitizedRecord): ScanResult["status"] {
  const status = record.status;
  return status === "completed" || status === "partial" || status === "running" || status === "failed" ? status : "failed";
}

function residentNotificationCopy(type: string): Pick<NotificationItem, "title" | "message"> {
  const normalizedType = type.toLowerCase();

  if (/(?:guardian|invite|care)/u.test(normalizedType)) {
    return {
      title: "보호자 연결 상태를 확인해 주세요.",
      message: "앱에서 보호자 연결 상태를 확인할 수 있어요.",
    };
  }

  if (/(?:scan|complete|finished|done)/u.test(normalizedType)) {
    return {
      title: "검사가 끝났어요.",
      message: "확인된 기기와 보안 상태를 앱에서 살펴보세요.",
    };
  }

  if (/(?:risk|security|alert|danger|critical|high|vulnerab)/u.test(normalizedType)) {
    return {
      title: "바로 확인이 필요해요.",
      message: "보호자와 함께 기기 설정과 업데이트를 확인해 주세요.",
    };
  }

  return {
    title: "새 소식이 있어요.",
    message: "앱에서 현재 보안 상태를 확인해 주세요.",
  };
}

export function residentNotificationTime(createdAt: unknown): string {
  if (typeof createdAt !== "string" || !createdAt.trim()) return UNKNOWN_NOTIFICATION_TIME_LABEL;

  const normalized = createdAt.trim();
  const timestampMatch = ISO_NOTIFICATION_TIMESTAMP.exec(normalized);
  if (!timestampMatch) return UNKNOWN_NOTIFICATION_TIME_LABEL;

  const year = Number(timestampMatch[1]);
  const month = Number(timestampMatch[2]);
  const day = Number(timestampMatch[3]);
  const calendarDate = new Date(Date.UTC(year, month - 1, day));
  if (
    calendarDate.getUTCFullYear() !== year ||
    calendarDate.getUTCMonth() !== month - 1 ||
    calendarDate.getUTCDate() !== day
  ) {
    return UNKNOWN_NOTIFICATION_TIME_LABEL;
  }

  const date = new Date(normalized);
  if (!Number.isFinite(date.getTime())) return UNKNOWN_NOTIFICATION_TIME_LABEL;

  const hour = date.getHours();
  const period = hour < 12 ? "\uC624\uC804" : "\uC624\uD6C4";
  const twelveHour = hour % 12 || 12;
  const minute = String(date.getMinutes()).padStart(2, "0");
  return (
    String(date.getFullYear()) +
    "\uB144 " +
    String(date.getMonth() + 1) +
    "\uC6D4 " +
    String(date.getDate()) +
    "\uC77C " +
    period +
    " " +
    String(twelveHour) +
    "\uC2DC " +
    minute +
    "\uBD84"
  );
}

function isCanonicalProductName(
  canonicalName: string,
  deviceType: string,
  manufacturer: string,
  model: string,
  identityStatus: string,
  familyVerified: boolean,
  identityEvidence: string[],
): boolean {
  const typeLabel = PUBLIC_DEVICE_TYPE_LABELS[deviceType];
  if (!typeLabel || !canonicalName || !manufacturer || (identityStatus !== "resolved" && identityStatus !== "manual_resolved")) {
    return false;
  }

  const base = manufacturer + " " + typeLabel;
  if (!model) {
    // Computers often do not publish a board model.  The backend may expose a
    // model-less family only when its resolver independently checked the MAC
    // OUI and SMB response; preserve that narrow contract on the mobile side.
    const hostSuffix = canonicalName.startsWith(`${base} - `)
      ? canonicalName.slice(`${base} - `.length).trim()
      : "";
    const hasSafeHostSuffix =
      Boolean(hostSuffix) &&
      PUBLIC_COMPUTER_HOSTNAME_PATTERN.test(hostSuffix) &&
      !["workstation", "services", "local", "unknown"].includes(hostSuffix.toLowerCase());
    return (
      deviceType === "computer" &&
      familyVerified &&
      identityEvidence.some((item) =>
        [
          "네트워크 제조사 조회 단서",
          "제품 제조사 광고",
          "서버 호스트 하드웨어 등록",
          "서버에 이전에 확인된 제품 정보",
        ].includes(item),
      ) &&
      (canonicalName === base || hasSafeHostSuffix)
    );
  }
  const expected = base + " (" + model + ")";
  return canonicalName === expected;
}

function isVerifiedProductClue(
  displayName: string,
  deviceType: string,
  manufacturer: string,
  model: string,
  verified: boolean,
): boolean {
  const typeLabel = PUBLIC_DEVICE_TYPE_LABELS[deviceType];
  if (!verified || !typeLabel || !manufacturer || !model) return false;
  return displayName === `${manufacturer} ${typeLabel} (${model})`;
}

const PUBLIC_OBSERVATION_EVIDENCE = new Set([
  "기기가 보낸 네트워크 정보",
  "기기가 보낸 네트워크 응답",
  "공유기가 알려준 연결 정보",
  "기기가 보낸 식별 정보",
  "서버에 저장된 식별 정보",
  "네트워크 등록 정보 단서",
  "기기가 응답한 네트워크 서비스",
  "서버에 등록된 하드웨어 정보",
]);

const PUBLIC_OBSERVED_SERVICES = new Set([
  "googlecast", "airplay", "onvif", "ws-discovery", "ipp", "smb",
  "netbios", "spotify-connect", "mdns", "upnp", "ssdp", "mqtt",
  "https", "http", "ssh", "telnet", "rtsp", "tcp-service",
  "neighbor-presence",
]);

const PUBLIC_OBSERVATION_SUFFIX_PATTERN = /^[0-9A-F]{6}$/u;
const PUBLIC_HOSTNAME_HEX_IDENTIFIER_PATTERN = /^[0-9A-F]{12}$/iu;
const PUBLIC_L2_FALLBACK_LABEL = "Wi-Fi 단말";

export function residentVisibleDevices(devices: Device[] | null | undefined): Device[] {
  if (!Array.isArray(devices)) return [];
  return devices.filter((device) => !device.name.trim().startsWith(PUBLIC_L2_FALLBACK_LABEL));
}

function isVerifiedObservedFamily(
  displayName: string,
  alias: string,
  deviceType: string,
  manufacturer: string,
  observedHostName: string,
  presentationKind: string,
  observedTypeVerified: boolean,
  hostNameVerified: boolean,
  observationSuffix: string,
  suffixVerified: boolean,
  identityEvidence: string[],
): boolean {
  const typeLabel = PUBLIC_DEVICE_TYPE_LABELS[deviceType];
  if (
    presentationKind !== "observed_connection" ||
    !observedTypeVerified ||
    !typeLabel ||
    !identityEvidence.some((item) => PUBLIC_OBSERVATION_EVIDENCE.has(item))
  ) {
    return false;
  }

  const base = manufacturer ? `${manufacturer} ${typeLabel}` : typeLabel;
  if (alias && displayName === alias) return true;
  if (
    hostNameVerified &&
    observedHostName &&
    displayName === (manufacturer ? `${base} - ${observedHostName}` : observedHostName)
  ) return true;
  if (manufacturer && displayName === base) return true;
  return Boolean(
    suffixVerified &&
    PUBLIC_OBSERVATION_SUFFIX_PATTERN.test(observationSuffix) &&
    displayName === `${typeLabel} · ${observationSuffix}`
  );
}

function safeObservedHostName(value: string, verified: boolean): string {
  if (
    !verified ||
    !isSafeText(value) ||
    !PUBLIC_COMPUTER_HOSTNAME_PATTERN.test(value) ||
    PUBLIC_HOSTNAME_HEX_IDENTIFIER_PATTERN.test(value) ||
    ["workstation", "services", "local", "unknown"].includes(value.toLowerCase())
  ) return "";
  return value;
}

function isVerifiedL2Presence(
  displayName: string,
  alias: string,
  observedHostName: string,
  deviceType: string,
  manufacturer: string,
  presentationKind: string,
  observedService: string,
  serviceVerified: boolean,
  observationSuffix: string,
  suffixVerified: boolean,
): boolean {
  if (
    presentationKind !== "observed_connection" ||
    observedService.toLowerCase() !== "neighbor-presence" ||
    !serviceVerified ||
    !suffixVerified ||
    !PUBLIC_OBSERVATION_SUFFIX_PATTERN.test(observationSuffix)
  ) return false;
  if (alias && displayName === alias) return true;
  const typeLabel = PUBLIC_DEVICE_TYPE_LABELS[deviceType];
  if (
    observedHostName &&
    displayName === (manufacturer && typeLabel
      ? `${manufacturer} ${typeLabel} - ${observedHostName}`
      : observedHostName)
  ) return true;
  if (manufacturer && typeLabel && displayName === `${manufacturer} ${typeLabel}`) return true;
  if (typeLabel && displayName === `${typeLabel} · ${observationSuffix}`) return true;
  return displayName === `${PUBLIC_L2_FALLBACK_LABEL} · ${observationSuffix}`;
}

function isVerifiedObservedService(
  presentationKind: string,
  observedService: string,
  serviceVerified: boolean,
  observedPort: number | null,
  portVerified: boolean,
  observationSuffix: string,
  suffixVerified: boolean,
  sourceOnly: boolean,
  sourceOnlyVerified: boolean,
  identityEvidence: string[],
): boolean {
  const normalizedService = observedService.toLowerCase();
  if (!PUBLIC_OBSERVED_SERVICES.has(normalizedService)) return false;
  const hasSafeSuffix =
    suffixVerified && PUBLIC_OBSERVATION_SUFFIX_PATTERN.test(observationSuffix);
  if (normalizedService === "neighbor-presence") {
    if (
      observedPort !== null ||
      portVerified ||
      !hasSafeSuffix ||
      sourceOnly ||
      sourceOnlyVerified
    ) return false;
    return presentationKind === "observed_connection" && serviceVerified;
  } else if (normalizedService === "tcp-service") {
    if (
      !portVerified ||
      observedPort === null ||
      !Number.isInteger(observedPort) ||
      observedPort < 1 ||
      observedPort > 65535 ||
      !hasSafeSuffix ||
      sourceOnly ||
      sourceOnlyVerified
    ) {
      return false;
    }
  } else if (observationSuffix || suffixVerified) {
    if (
      !hasSafeSuffix ||
      observedPort !== null ||
      portVerified ||
      !sourceOnly ||
      !sourceOnlyVerified
    ) return false;
  } else if (observedPort !== null || portVerified || sourceOnly || sourceOnlyVerified) {
    return false;
  }
  return (
    presentationKind === "observed_connection" &&
    serviceVerified &&
    identityEvidence.some((item) => PUBLIC_OBSERVATION_EVIDENCE.has(item))
  );
}

function presentVulnerabilities(value: SanitizedPayload | undefined): Device["vulnerabilities"] {
  if (!Array.isArray(value)) return [];

  return value.flatMap((item) => {
    if (!isSanitizedRecord(item)) return [];
    const cveId = optionalTextField(item, "cve_id");
    const summary = optionalTextField(item, "summary_ko");
    const remediation = optionalTextField(item, "remediation_ko");
    if (!cveId && !summary && !remediation) return [];

    return [
      {
        cve_id: cveId,
        severity: optionalTextField(item, "severity"),
        cvss: nullableNumberField(item, "cvss") ?? undefined,
        summary_ko: summary,
        remediation_ko: remediation,
        matched_on: optionalTextField(item, "matched_on"),
        confidence: optionalTextField(item, "confidence"),
      },
    ];
  });
}

function presentRiskExplanations(value: SanitizedPayload | undefined): Device["risk_explanations"] {
  if (!Array.isArray(value)) return [];

  return value.flatMap((item) => {
    if (!isSanitizedRecord(item)) return [];
    const signal = optionalTextField(item, "signal");
    const summary = optionalTextField(item, "summary_ko");
    const remediation = optionalTextField(item, "remediation_ko");
    if (!signal && !summary && !remediation) return [];
    return [{ signal, summary_ko: summary, remediation_ko: remediation }];
  });
}

function highestRiskLevel(items: Array<{ risk_level: RiskLevel }>): RiskLevel {
  if (items.some((item) => item.risk_level === "red")) return "red";
  if (items.some((item) => item.risk_level === "yellow")) return "yellow";
  if (items.some((item) => item.risk_level === "green")) return "green";
  return "unknown";
}

function uniqueDeviceCount(devices: Device[]): number {
  return new Set(devices.map((device) => device.device_id)).size;
}

export function canonicalDeviceName(device: Pick<Device, "name" | "canonical_name">): string | null {
  const displayName = residentAlias(device.name);
  const canonicalName = safeText(device.canonical_name);
  return canonicalName && canonicalName !== displayName ? canonicalName : null;
}

export function residentDeviceAccessibilityLabel(device: Pick<Device, "name" | "canonical_name">): string {
  const displayName = residentAlias(device.name) || safeText(device.canonical_name);
  const canonicalName = canonicalDeviceName(device);
  if (canonicalName === displayName) return displayName;
  return canonicalName ? `${displayName}. 확인된 제품 이름과 품번: ${canonicalName}` : displayName;
}

export function presentDevice(device: Device | null | undefined): Device | null {
  if (!device) return null;
  if (hasUnsafeRawDeviceIdentity(device)) return null;
  const record = sanitizedRecord(device);
  if (!record) return null;
  const isIdentityFinding = booleanField(record, "is_identity_finding") || booleanField(record, "detected");
  if (isIdentityFinding) {
    const deviceId = textField(record, "device_id");
    const displayName = safeText(textField(record, "display_name") || textField(record, "name"));
    const rawDeviceType = safeText(textField(record, "device_type")) || "network";
    const identityStatus = textField(record, "identity_status") || "unresolved";
    if (!deviceId || !displayName || identityStatus === "resolved" || identityStatus === "manual_resolved") {
      return null;
    }
    const clueManufacturer = safeText(textField(record, "manufacturer"));
    const clueModel = safeText(textField(record, "model"));
    const evidence = Array.isArray(record.identity_evidence)
      ? record.identity_evidence.filter((item): item is string => typeof item === "string" && isSafeText(item))
      : [];
    const observedAlias = residentAlias(textField(record, "alias"));
    const observedHostName = safeObservedHostName(
      textField(record, "observed_host_name"),
      booleanField(record, "host_name_verified"),
    );
    const hasVerifiedProductClue = isVerifiedProductClue(
      displayName,
      rawDeviceType,
      clueManufacturer,
      clueModel,
      booleanField(record, "product_clue_verified"),
    );
    const presentationKind = textField(record, "presentation_kind");
    const hasVerifiedObservedFamily = isVerifiedObservedFamily(
      displayName,
      observedAlias,
      rawDeviceType,
      clueManufacturer,
      observedHostName,
      presentationKind,
      booleanField(record, "observed_type_verified"),
      booleanField(record, "host_name_verified"),
      textField(record, "observation_suffix"),
      booleanField(record, "observation_suffix_verified"),
      evidence,
    );
    const observedService = textField(record, "observed_service");
    const observedPort = nullableNumberField(record, "observed_port");
    const observationSuffix = textField(record, "observation_suffix");
    const hasVerifiedObservedService = isVerifiedObservedService(
      presentationKind,
      observedService,
      booleanField(record, "observed_service_verified"),
      observedPort,
      booleanField(record, "observed_port_verified"),
      observationSuffix,
      booleanField(record, "observation_suffix_verified"),
      booleanField(record, "observed_source_only"),
      booleanField(record, "observed_source_only_verified"),
      evidence,
    );
    const hasVerifiedL2Presence = isVerifiedL2Presence(
      displayName,
      observedAlias,
      observedHostName,
      rawDeviceType,
      clueManufacturer,
      presentationKind,
      observedService,
      booleanField(record, "observed_service_verified"),
      observationSuffix,
      booleanField(record, "observation_suffix_verified"),
    );
    // Bare TCP/mDNS/HTTP responses remain research evidence only. A verified
    // current L2 endpoint is retained with a safe alias/hostname/type or opaque
    // suffix, without turning its protocol into a product name.
    if (!hasVerifiedProductClue && !hasVerifiedObservedFamily && !hasVerifiedL2Presence) return null;
    const deviceType = rawDeviceType;
    return {
      device_id: deviceId,
      name: displayName,
      canonical_name: displayName,
      device_type: deviceType,
      manufacturer: clueManufacturer,
      model: hasVerifiedProductClue ? clueModel : "",
      ip_address: "",
      mac_address: "",
      online: booleanField(record, "online", true),
      last_seen: textField(record, "last_seen"),
      open_ports: [],
      services: [],
      default_credentials: false,
      encryption: "",
      firmware: "",
      vulnerabilities: [],
      risk_explanations: [],
      discovery_sources: [],
      fingerprints: [],
      risk_signals: [],
      scan_source: "",
      confidence: numberField(record, "confidence"),
      security_score: 0,
      risk_level: riskLevelField(record, "risk_level", "yellow"),
      risk_summary: "",
      recommended_actions: [],
      alias: observedAlias || undefined,
      identity_note: textField(record, "identity_note"),
      identity_status: identityStatus,
      identity_evidence: evidence,
      identity_candidates: [],
      identity_family_verified: hasVerifiedObservedFamily,
      product_clue_verified: hasVerifiedProductClue,
      presentation_kind: presentationKind || undefined,
      observed_type_verified:
        (hasVerifiedObservedFamily || hasVerifiedL2Presence) &&
        booleanField(record, "observed_type_verified"),
      observed_service: hasVerifiedObservedService ? observedService.toLowerCase() : undefined,
      observed_service_verified: hasVerifiedObservedService,
      observed_port: hasVerifiedObservedService && observedPort !== null ? observedPort : undefined,
      observed_port_verified:
        hasVerifiedObservedService && booleanField(record, "observed_port_verified"),
      observation_suffix: hasVerifiedObservedService && observationSuffix ? observationSuffix : undefined,
      observation_suffix_verified:
        hasVerifiedObservedService && booleanField(record, "observation_suffix_verified"),
      observed_source_only:
        hasVerifiedObservedService && booleanField(record, "observed_source_only"),
      observed_source_only_verified:
        hasVerifiedObservedService && booleanField(record, "observed_source_only_verified"),
      host_name_verified:
        (hasVerifiedObservedFamily || hasVerifiedL2Presence) && Boolean(observedHostName),
      is_unresolved: true,
      is_identity_finding: true,
    };
  }
  if (booleanField(record, "is_phantom") || booleanField(record, "is_unresolved") || booleanField(record, "is_uncertain")) {
    return null;
  }

  const deviceId = textField(record, "device_id");
  const alias = residentAlias(textField(record, "alias"));
  const canonicalName = textField(record, "canonical_name");
  const deviceType = textField(record, "device_type").toLowerCase();
  const manufacturer = textField(record, "manufacturer");
  const model = textField(record, "model");
  const identityStatus = textField(record, "identity_status");
  const familyVerified = booleanField(record, "identity_family_verified");
  const identityEvidence = Array.isArray(record.identity_evidence)
    ? record.identity_evidence.filter((item): item is string => typeof item === "string")
    : [];
  // AirPlay/RAOP/Spotify 같은 프로토콜은 오디오 제품의 증거가 아니다.
  // 제조사와 품번이 서버에서 검증된 경우에만 실제 제품 유형으로 표시한다.
  if (deviceType === "audio") return null;
  // Old caches did not include a server-produced canonical_name.  Never infer
  // verification from a self-consistent raw name/manufacturer/model triplet:
  // an arbitrary stale or altered cache could otherwise look like a real
  // product. A fresh server response supplies the canonical value after its
  // evidence boundary has checked advertisements and the bounded catalog.
  if (!canonicalName || !isCanonicalProductName(canonicalName, deviceType, manufacturer, model, identityStatus, familyVerified, identityEvidence)) return null;
  const verifiedCanonicalName = canonicalName;

  // A public household type is necessary but never sufficient: a legacy name is
  // accepted only when it carries manufacturer + model evidence, while new data
  // must carry canonical_name from the server-side identification boundary.
  if (!deviceId || !PUBLIC_DEVICE_TYPES.has(deviceType) || !verifiedCanonicalName) return null;

  const vulnerabilities = presentVulnerabilities(record.vulnerabilities);

  return {
    device_id: deviceId,
    name: alias || verifiedCanonicalName,
    canonical_name: verifiedCanonicalName,
    device_type: deviceType,
    manufacturer,
    model,
    ip_address: "",
    mac_address: "",
    online: booleanField(record, "online"),
    last_seen: textField(record, "last_seen"),
    open_ports: [],
    services: [],
    default_credentials: booleanField(record, "default_credentials"),
    encryption: "",
    firmware: "",
    vulnerabilities,
    risk_explanations: presentRiskExplanations(record.risk_explanations),
    discovery_sources: [],
    fingerprints: [],
    risk_signals: [],
    scan_source: "",
    confidence: numberField(record, "confidence"),
    security_score: numberField(record, "security_score"),
    risk_level: riskLevelField(record, "risk_level"),
    // The resident-facing UI builds its own fixed easy-Korean guidance from
    // risk level. Do not cache free-form server summaries/actions, which can
    // contain legacy device labels or technical wording outside this contract.
    risk_summary: "",
    recommended_actions: [],
    alias: alias || undefined,
    identity_note: "",
    identity_status: identityStatus,
    // DeviceCard revalidates the normalized object before rendering. Keep the
    // server's safe evidence labels so model-less, independently verified
    // computer families remain visible on that second boundary.
    identity_evidence: identityEvidence,
    identity_family_verified: familyVerified,
  };
}

export function presentDevices(devices: Device[] | null | undefined): Device[] {
  if (!Array.isArray(devices)) return [];
  return devices.flatMap((device) => {
    const presented = presentDevice(device);
    return presented ? [presented] : [];
  });
}

export function presentDetectedConnections(
  connections: DetectedConnection[] | null | undefined,
): Device[] {
  if (!Array.isArray(connections)) return [];
  return connections.flatMap((connection) => {
    const presented = presentDevice(connection as unknown as Device);
    return presented ? [presented] : [];
  });
}

/**
 * Normalize both API collections and deduplicate them by the server's opaque
 * public device id. Confirmed `devices/items` are intentionally processed
 * first, so a legacy detected-product clue can never replace a resolved card.
 */
export function presentDeviceCollection(
  devices: Device[] | null | undefined,
  connections: DetectedConnection[] | null | undefined,
): Device[] {
  return dedupePresentedDevices([
    ...presentDevices(devices),
    ...presentDetectedConnections(connections),
  ]);
}

export function presentScanResult(result: ScanResult | null | undefined): ScanResult | null {
  if (!result) return null;
  const record = sanitizedRecord(result);
  if (!record) return null;

  const devices = presentDeviceCollection(result.devices, result.detected_connections);
  const rawDeviceCount = Array.isArray(result.devices) ? result.devices.length : 0;
  const rawDetectedCount = Array.isArray(result.detected_connections) ? result.detected_connections.length : 0;
  // v1.0.0 공개 계약은 원시 identity_findings를 전달하지 않는다. 새 상태·개수
  // 계약이 없는 구형 결과는 내용 일부를 재해석하지 않고 통째로 폐기한다.
  // evidence-backed detected_connections만 위의 별도 검증 경계를 통과할 수 있다.
  const legacyPendingCount = Array.isArray(result.identity_findings) ? result.identity_findings.length : 0;
  const declaredResearch = identityResearchState(result);
  if (legacyPendingCount > 0 && !declaredResearch.hasExplicitContract) return null;
  const identityPendingCount = declaredResearch.pendingCount;
  const visiblePendingCount = devices.filter((device) => device.is_identity_finding === true).length;
  const identityResearchStatus = declaredResearch.status;
  const identityResearchIncomplete = identityResearchStatus === "review_required";
  const removedUnverifiedDevice = rawDeviceCount + rawDetectedCount !== devices.length;
  const highRiskDevices = devices.filter((device) => device.risk_level === "red").length;
  const serverHighRiskCount = numberField(record, "high_risk_devices");
  // review_required 응답의 개별 관측은 비공개지만 서버가 검증한 red 집계는
  // 실제 위험 근거다. 반대로 새 계약이 없는 구형 캐시에서 제거된 기기는
  // 집계를 오염시킬 수 있으므로 검증된 공개 기기로 다시 계산한다.
  const trustServerRiskAggregate =
    identityResearchIncomplete && declaredResearch.hasExplicitContract
      ? true
      : !removedUnverifiedDevice && legacyPendingCount === 0;
  const aggregateHighRiskCount = trustServerRiskAggregate
    ? Math.max(highRiskDevices, serverHighRiskCount)
    : highRiskDevices;
  const securityScore = recordField(record, "security_score");
  const coverage = scanCoverageState(result, {
    identity_pending_count: identityPendingCount,
    identity_research_status: identityResearchStatus,
  });
  // Evidence-backed observations stay distinguishable through
  // is_identity_finding while contributing their verified security signals to
  // the server score. Only an old response without the explicit contract is
  // failed closed here.
  const trustedIdentityProjection = declaredResearch.hasExplicitContract && declaredResearch.isIncomplete;
  const serverScore = nullableNumberField(securityScore, "score");
  const serverScoreStatus = textField(securityScore, "score_status");
  const hasProvisionalObservedScore =
    coverage.isPartial && serverScoreStatus === "provisional" && serverScore !== null;
  const scoreWithheld =
    (coverage.isPartial && !hasProvisionalObservedScore) ||
    (removedUnverifiedDevice && !trustedIdentityProjection);
  const confirmedRedRisk = hasConfirmedRedRisk({
    high_risk_devices: aggregateHighRiskCount,
    security_score: {
      risk_level: !trustServerRiskAggregate
        ? highestRiskLevel(devices)
        : riskLevelField(securityScore, "risk_level"),
    },
    devices,
  });

  return {
    scan_id: textField(record, "scan_id"),
    status: normalizedScanStatus(scanStatusField(record), coverage),
    progress: Math.min(100, Math.max(0, numberField(record, "progress"))),
    scan_source: "",
    current_step: "",
    devices_found: uniqueDeviceCount(devices),
    high_risk_devices: aggregateHighRiskCount,
    identified_count: devices.filter((device) => device.is_identity_finding !== true).length,
    identity_pending_count: visiblePendingCount,
    identity_research_status: identityResearchStatus,
    scan_complete: coverage.isPartial
      ? false
      : coverage.coverageComplete ?? undefined,
    coverage_complete: coverage.isPartial ? false : coverage.coverageComplete ?? undefined,
    tcp_scan_timed_out: coverage.tcpScanTimedOut,
    scan_profile: "",
    devices,
    identity_findings: [],
    detected_connections: [],
    security_score: {
      score: scoreWithheld ? null : serverScore,
      risk_level: scoreWithheld
        ? confirmedRedRisk
          ? "red"
          : coverage.isPartial
          ? "yellow"
          : highestRiskLevel(devices)
        : coverage.isPartial && confirmedRedRisk
        ? "red"
        : riskLevelField(securityScore, "risk_level"),
      score_status: scoreWithheld
        ? "held"
        : coverage.isPartial
        ? "provisional"
        : serverScoreStatus || "final",
      identity_incomplete: identityResearchIncomplete,
      identity_pending_count: visiblePendingCount,
    },
  };
}

function dedupePresentedDevices(devices: Device[]): Device[] {
  const byId = new Map<string, Device>();
  for (const device of devices) {
    const current = byId.get(device.device_id);
    if (!current || (current.is_identity_finding === true && device.is_identity_finding !== true)) {
      byId.set(device.device_id, device);
    }
  }
  return [...byId.values()];
}

export function presentNotification(notification: NotificationItem | null | undefined): NotificationItem | null {
  if (!notification) return null;
  const record = sanitizedRecord(notification);
  if (!record) return null;

  const notificationId = textField(record, "notification_id");
  const type = textField(record, "type");
  const title = textField(record, "title");
  const message = textField(record, "message");
  if (!notificationId || !title || !message) return null;
  const residentCopy = residentNotificationCopy(type);

  return {
    notification_id: notificationId,
    type,
    title: residentCopy.title,
    message: residentCopy.message,
    read: booleanField(record, "read"),
    created_at: textField(record, "created_at"),
  };
}

export function presentNotifications(items: NotificationItem[] | null | undefined): NotificationItem[] {
  if (!Array.isArray(items)) return [];
  return items.flatMap((item) => {
    const presented = presentNotification(item);
    return presented ? [presented] : [];
  });
}

export function presentDashboard(dashboard: DashboardData | null | undefined): DashboardData | null {
  if (!dashboard) return null;
  const record = sanitizedRecord(dashboard);
  if (!record) return null;

  const home = recordField(record, "home");
  const summary = recordField(record, "summary");
  const guardianStatus = recordField(record, "guardian_status");
  const legacyPendingCount = Array.isArray(dashboard.identity_findings) ? dashboard.identity_findings.length : 0;
  const declaredResearch = identityResearchState(dashboard, dashboard.summary);
  if (legacyPendingCount > 0 && !declaredResearch.hasExplicitContract) return null;
  const identityPendingCount = declaredResearch.pendingCount;
  const identityResearchStatus = declaredResearch.status;
  const identityResearchIncomplete = identityResearchStatus === "review_required";
  const summaryHighRiskCount = numberField(summary, "high_risk_devices");
  const summaryRiskLevel = riskLevelField(summary, "risk_level");
  // Dashboard top-risk entries are only a compact server summary and do not
  // carry the product evidence that presentDevice() requires. They are not
  // rendered by the resident flow (scan results carry the verified devices),
  // so never persist their free-form device names or messages in mobile cache.
  // If the response contains an unsafe or address-derived item, fail closed
  // for the complete aggregate because its score cannot be recomputed here.
  const rawTopRiskCount = Array.isArray(dashboard.top_risks) ? dashboard.top_risks.length : 0;
  if (rawTopRiskCount > 0) {
    const topRiskEntries = Array.isArray(record.top_risks) ? record.top_risks : [];
    if (
      topRiskEntries.length !== rawTopRiskCount ||
      topRiskEntries.some((item) => {
        if (!isSanitizedRecord(item)) return true;
        return !textField(item, "device_id") || !textField(item, "device_name") || !textField(item, "message");
      })
    ) {
      return null;
    }
  }

  return {
    home: {
      home_id: textField(home, "home_id"),
      name: textField(home, "name"),
      mode: textField(home, "mode"),
      security_score: nullableNumberField(home, "security_score"),
      device_count: numberField(home, "device_count", 0),
      identified_device_count: numberField(home, "identified_device_count", numberField(home, "device_count", 0)),
      identity_pending_count: identityPendingCount,
    },
    summary: {
      score: nullableNumberField(summary, "score"),
      score_status: textField(summary, "score_status") || "final",
      risk_level: summaryRiskLevel,
      online_devices: numberField(summary, "online_devices"),
      high_risk_devices: summaryHighRiskCount,
      recent_event_count: numberField(summary, "recent_event_count"),
      identity_pending_count: identityPendingCount,
      identity_research_status: identityResearchStatus,
    },
    top_risks: [],
    guardian_status: {
      connected_guardians: numberField(guardianStatus, "connected_guardians"),
      last_alert_status: textField(guardianStatus, "last_alert_status"),
    },
    identity_pending_count: identityPendingCount,
    identity_research_status: identityResearchStatus,
    identity_findings: [],
  };
}

export function presentGuardianDashboard(dashboard: GuardianDashboard | null | undefined): GuardianDashboard | null {
  if (!dashboard) return null;
  const record = sanitizedRecord(dashboard);
  if (!record) return null;

  const rawDevices = Array.from(
    new Map(
      [
        ...(Array.isArray(dashboard.devices) ? dashboard.devices : []),
        ...(dashboard.high_risk_devices ?? []),
        ...(dashboard.caution_devices ?? []),
      ].map((device) => [device.device_id, device]),
    ).values(),
  );
  const visibleDevices = presentDevices(rawDevices);
  const highRiskDevices = visibleDevices.filter((device) => device.risk_level === "red");
  const cautionDevices = visibleDevices.filter((device) => device.risk_level === "yellow");
  const legacyPendingCount = Array.isArray(dashboard.identity_findings) ? dashboard.identity_findings.length : 0;
  const declaredResearch = identityResearchState(dashboard, dashboard.ward_summary);
  if (legacyPendingCount > 0 && !declaredResearch.hasExplicitContract) return null;
  const identityPendingCount = declaredResearch.pendingCount;
  const identityResearchStatus = declaredResearch.status;
  const identityResearchIncomplete = identityResearchStatus === "review_required";
  const notifications = presentNotifications(dashboard.recent_notifications);
  const rawDeviceCount = rawDevices.length;
  const removedUnverifiedDevice = rawDeviceCount !== visibleDevices.length;
  const invite = recordField(record, "invite");
  const wardSummary = recordField(record, "ward_summary");
  const ward = recordField(record, "ward");
  const serverWardRiskLevel = riskLevelField(wardSummary, "risk_level");
  const serverHighRiskCount = numberField(wardSummary, "high_risk_devices");
  const trustServerRiskAggregate =
    identityResearchIncomplete && declaredResearch.hasExplicitContract ? true : !removedUnverifiedDevice && legacyPendingCount === 0;
  const guardianHighRiskCount = trustServerRiskAggregate
    ? Math.max(highRiskDevices.length, serverHighRiskCount)
    : highRiskDevices.length;

  return {
    invite: {
      invite_id: textField(invite, "invite_id"),
      email: textField(invite, "email"),
      relation: textField(invite, "relation"),
      display_name: optionalTextField(invite, "display_name"),
      ward_account_name: optionalTextField(invite, "ward_account_name") ?? null,
      short_code: optionalTextField(invite, "short_code"),
      status: textField(invite, "status"),
      status_label: optionalTextField(invite, "status_label"),
      expires_at: optionalTextField(invite, "expires_at"),
      accepted_at: optionalTextField(invite, "accepted_at") ?? null,
      last_viewed_at: optionalTextField(invite, "last_viewed_at") ?? null,
    },
    ward: Object.keys(ward).length
      ? {
          link_id: textField(ward, "link_id"),
          guardian_id: textField(ward, "guardian_id"),
          invite_id: textField(ward, "invite_id"),
          home_id: textField(ward, "home_id"),
          ward_account_name: optionalTextField(ward, "ward_account_name") ?? null,
          ward_alias: optionalTextField(ward, "ward_alias") ?? null,
          ward_display_name: textField(ward, "ward_display_name"),
          status: textField(ward, "status"),
          accepted_at: optionalTextField(ward, "accepted_at"),
          revoked_at: optionalTextField(ward, "revoked_at") ?? null,
          last_viewed_at: optionalTextField(ward, "last_viewed_at"),
          summary: undefined,
          devices: Array.isArray(dashboard.ward?.devices) ? presentDevices(dashboard.ward.devices) : undefined,
        }
      : null,
    ward_summary: {
      score: removedUnverifiedDevice ? null : nullableNumberField(wardSummary, "score"),
      score_status: textField(wardSummary, "score_status") || "final",
      risk_level: !trustServerRiskAggregate
        ? highestRiskLevel(visibleDevices)
        : serverWardRiskLevel,
      device_count: removedUnverifiedDevice && !declaredResearch.hasExplicitContract
        ? uniqueDeviceCount(visibleDevices)
        : numberField(wardSummary, "device_count", visibleDevices.length),
      high_risk_devices: guardianHighRiskCount,
      caution_devices: cautionDevices.length,
      unread_notifications: notifications.filter((item) => !item.read).length,
      identity_pending_count: identityPendingCount,
      identity_research_status: identityResearchStatus,
    },
    devices: visibleDevices,
    high_risk_devices: highRiskDevices,
    caution_devices: cautionDevices,
    identity_pending_count: identityPendingCount,
    identity_research_status: identityResearchStatus,
    identity_findings: [],
    recent_notifications: notifications,
    read_only: booleanField(record, "read_only"),
    scope: textField(record, "scope"),
  };
}
