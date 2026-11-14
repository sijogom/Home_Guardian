import type {
  IdentityResearchStatus,
  NetworkContext,
  RiskLevel,
  ScanDiagnostics,
  ScanStatus,
} from "../api/types";

type ScanCoverageSource = {
  status?: string;
  scan_complete?: boolean;
  coverage_complete?: boolean;
  tcp_scan_timed_out?: boolean;
  identity_pending_count?: number | null;
  identity_research_status?: IdentityResearchStatus | string | null;
  network_context?: NetworkContext | null;
  scan_diagnostics?: ScanDiagnostics | null;
};

export type ScanCoverageState = {
  coverageComplete: boolean | null;
  tcpScanTimedOut: boolean;
  isPartial: boolean;
};

export type IdentityResearchState = {
  status: IdentityResearchStatus;
  pendingCount: number;
  isIncomplete: boolean;
  hasExplicitContract: boolean;
};

export const SCAN_INCOMPLETE_TITLE = "점검을 모두 마치지 못했어요";
export const SCAN_SCORE_WITHHELD_COPY = "안전 점수를 확정하지 않았어요.";
export const SCAN_CONFIRMED_RISK_COPY = "확인된 위험 안내를 먼저 살펴보세요.";
export const SCAN_RETRY_COPY = "잠시 후 다시 점검해 주세요.";

export function scanIncompleteBody(confirmedRedRisk: boolean): string {
  return [
    SCAN_SCORE_WITHHELD_COPY,
    confirmedRedRisk ? SCAN_CONFIRMED_RISK_COPY : "",
    SCAN_RETRY_COPY,
  ]
    .filter(Boolean)
    .join(" ");
}

export function scanIncompleteMessage(confirmedRedRisk: boolean): string {
  return `${SCAN_INCOMPLETE_TITLE}. ${scanIncompleteBody(confirmedRedRisk)}`;
}

type ScanRiskEvidenceSource = {
  high_risk_devices?: number | null;
  security_score?: { risk_level?: RiskLevel | null } | null;
  devices?: Array<{ risk_level?: RiskLevel | null }> | null;
};

/**
 * 개별 미식별 관측은 공개 응답이나 모바일 캐시에 싣지 않는다. 서버가 계산한
 * 개수와 두 상태값만 읽어 점검 전체가 끝났는지 판단한다. 순차 배포 중 값이
 * 어긋나면 더 보수적인 review_required가 항상 우선한다.
 */
export function identityResearchState(
  ...sources: Array<ScanCoverageSource | null | undefined>
): IdentityResearchState {
  let pendingCount = 0;
  let reviewRequired = false;
  let hasExplicitContract = false;

  for (const source of sources) {
    if (!source) continue;
    if (
      source.identity_research_status === "complete" ||
      source.identity_research_status === "review_required"
    ) {
      hasExplicitContract = true;
      reviewRequired ||= source.identity_research_status === "review_required";
    }
    if (
      typeof source.identity_pending_count === "number" &&
      Number.isFinite(source.identity_pending_count) &&
      source.identity_pending_count >= 0
    ) {
      hasExplicitContract = true;
      pendingCount = Math.max(pendingCount, Math.trunc(source.identity_pending_count));
    }
  }

  reviewRequired ||= pendingCount > 0;
  return {
    status: reviewRequired ? "review_required" : "complete",
    pendingCount,
    isIncomplete: reviewRequired,
    hasExplicitContract,
  };
}

/**
 * 앱과 서버가 순차 배포되는 동안에도 부분 탐색을 완전한 점검으로 오인하지 않는다.
 * 새 공개 필드와 기존 네이티브 진단 필드를 모두 읽되, 한 경로라도 불완전하면
 * 완전 탐색 신호보다 우선한다.
 */
export function scanCoverageState(...sources: Array<ScanCoverageSource | null | undefined>): ScanCoverageState {
  const completionSignals: boolean[] = [];
  let tcpScanTimedOut = false;
  let partialStatus = false;

  for (const source of sources) {
    if (!source) continue;
    // `scan_complete=false` also represents identity research pending.  When
    // the same response explicitly says physical coverage is complete, do not
    // reinterpret that research state as a transport gap.
    if (!(source.scan_complete === false && source.coverage_complete === true)) {
      pushBoolean(completionSignals, source.scan_complete);
    }
    pushBoolean(completionSignals, source.coverage_complete);
    // A scan may stay `partial` while product identity research is pending.
    // Treat that status as transport-partial only when the response does not
    // explicitly confirm physical coverage; the backend owns this distinction.
    const sourceHasCompleteCoverage = source.coverage_complete === true;
    partialStatus ||= source.status === "partial" && !sourceHasCompleteCoverage;
    tcpScanTimedOut ||= source.tcp_scan_timed_out === true;

    const diagnostics = source.network_context?.scan_diagnostics ?? source.scan_diagnostics;
    if (!diagnostics) continue;
    pushBoolean(completionSignals, diagnostics.coverage_complete);
    pushBoolean(completionSignals, diagnostics.candidate_coverage_complete);
    pushNegativeBoolean(completionSignals, diagnostics.candidate_stimulation_complete);
    // Android 10+ may hide both /proc/net/arp and `ip neigh` from an ordinary
    // app even after the bounded probe sweep succeeds.  Neighbour-source,
    // probe, presence and neighbour-coverage fields are therefore diagnostics,
    // not independent proof that the physical scan was partial.  The native
    // scanner owns candidate coverage and reports actual execution loss via
    // the explicit fields retained below.
    pushNegativeBoolean(completionSignals, diagnostics.tcp_transport_complete);
    pushNegativeBoolean(completionSignals, diagnostics.wifi_network_socket_binding_complete);
    tcpScanTimedOut ||= diagnostics.tcp_scan_timed_out === true;
    if (diagnostics.scan_partial === true) {
      completionSignals.push(false);
      partialStatus = true;
    }
    const observationCapacityLoss =
      diagnostics.observation_limit_reached === true ||
      boundedPositiveCount(diagnostics.observation_overflow_events) ||
      boundedPositiveCount(diagnostics.observation_hosts_dropped) ||
      boundedPositiveCount(diagnostics.observation_hosts_evicted) ||
      boundedPositiveCount(diagnostics.observation_receive_buffer_dropped);
    if (observationCapacityLoss) {
      completionSignals.push(false);
      partialStatus = true;
    }
  }

  const coverageComplete = completionSignals.includes(false)
    ? false
    : completionSignals.includes(true)
    ? true
    : null;
  return {
    coverageComplete,
    tcpScanTimedOut,
    isPartial: partialStatus || coverageComplete === false || tcpScanTimedOut,
  };
}

export function normalizedScanStatus(
  status: ScanStatus["status"],
  coverage: ScanCoverageState,
): ScanStatus["status"] {
  return coverage.isPartial ? "partial" : status;
}

/**
 * Keep only the verified public devices observed by the current scan attempt.
 *
 * The v1 public API intentionally does not expose a stable privacy-safe network
 * scope key.  Without one, preserving an older complete list during a partial
 * attempt can leak Wi-Fi A devices into the current Wi-Fi B screen and cache.
 * Fail closed until such a scope key exists: partial status and score withholding
 * remain visible, but stale devices are never merged back into the current list.
 */
export function deviceCacheAfterScan<T>(latest: T[]): T[] {
  return latest;
}

/**
 * 점수를 확정할 수 없는 점검에서도 이미 확인한 위험까지 주의(yellow)로
 * 낮추지 않는다. 개별 미식별 관측은 공개하지 않으므로 서버의 안전한 red
 * 집계, 점수 요약, 검증된 공개 기기 중 하나라도 red이면 그대로 유지한다.
 */
export function hasConfirmedRedRisk(
  ...sources: Array<ScanRiskEvidenceSource | null | undefined>
): boolean {
  return sources.some((source) => {
    if (!source) return false;
    const highRiskCount = source.high_risk_devices;
    return (
      source.security_score?.risk_level === "red" ||
      (typeof highRiskCount === "number" && Number.isFinite(highRiskCount) && highRiskCount > 0) ||
      source.devices?.some((device) => device.risk_level === "red") === true
    );
  });
}

function pushBoolean(target: boolean[], value: unknown) {
  if (value === true || value === false) target.push(value);
}

function pushNegativeBoolean(target: boolean[], value: unknown) {
  if (value === false) target.push(false);
}

function boundedPositiveCount(value: unknown): boolean {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}
