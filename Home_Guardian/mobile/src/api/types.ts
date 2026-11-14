export type ApiResponse<T> = {
  success: boolean;
  data: T;
  error: null | {
    code: string;
    message: string;
    details: Record<string, unknown>;
  };
  timestamp: string;
};

export type User = {
  user_id: string;
  email: string;
  nickname: string;
  role: string;
  email_verified: boolean;
  home_id: string;
};

export type SessionTokens = {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
};

export type AuthHandoff = {
  // One-time opaque id. It is stored only with the two refresh tokens in
  // SecureStore until the server atomically activates the new role.
  id: string;
  expires_at: string;
};

export type LoginResult = SessionTokens & {
  user: User;
  auth_mode?: string;
  provider?: string;
  handoff?: AuthHandoff;
};

export type AuthHandoffCompletionResult = SessionTokens & {
  user: User;
};

export type AuthSessionResult = {
  user: User;
  role: "user" | "guardian";
};

export type GuardianAccount = {
  guardian_id: string;
  email: string;
  display_name?: string;
  provider: string;
  created_at?: string;
  last_login_at?: string;
};

export type RiskLevel = "green" | "yellow" | "red" | "unknown";

export type IdentityResearchStatus = "complete" | "review_required";

export type GuardianWardSummary = {
  score: number | null;
  score_status?: "held" | "provisional" | "final" | "no_targets" | string;
  risk_level: RiskLevel | null;
  device_count: number;
  high_risk_devices: number;
  caution_devices: number;
  unread_notifications: number;
  identity_pending_count?: number;
  identity_research_status?: IdentityResearchStatus;
};

export type Device = {
  device_id: string;
  name: string;
  canonical_name?: string;
  device_type: string;
  manufacturer: string;
  model: string;
  // Public device DTOs intentionally omit network addresses. Legacy cache
  // entries may still carry empty values while the presentation boundary
  // migrates them away.
  ip_address?: string;
  mac_address?: string;
  online: boolean;
  last_seen: string;
  open_ports: number[];
  services: string[];
  default_credentials: boolean;
  encryption: string;
  firmware: string;
  vulnerabilities: CveMatch[];
  risk_explanations?: Array<{
    signal?: string;
    summary_ko?: string;
    remediation_ko?: string;
  }>;
  discovery_sources: string[];
  fingerprints: string[];
  risk_signals: string[];
  scan_source: string;
  confidence: number;
  security_score: number;
  risk_level: RiskLevel;
  risk_summary: string;
  recommended_actions: string[];
  // 보호자가 직접 지정한 별칭(있으면 name 이 별칭으로 표시됨).
  alias?: string;
  // 서버 제품 카탈로그 대조 결과와 재검사 안내.
  is_uncertain?: boolean;
  is_phantom?: boolean;
  is_unresolved?: boolean;
  is_identity_finding?: boolean;
  identity_note?: string;
  identity_status?: "resolved" | "enriching" | "unresolved" | "manual_resolved" | string;
  identity_evidence?: string[];
  identity_candidates?: Array<{ label: string; kind?: string; catalog_id?: string; confidence?: number }>;
  identity_family_verified?: boolean;
  /** Server-revalidated structured manufacturer + concrete model + product type clue. */
  product_clue_verified?: boolean;
  /** Explicitly marks a bounded, evidence-backed observation rather than a resolved product. */
  presentation_kind?: "observed_connection" | string;
  observed_type_verified?: boolean;
  observed_service?: string;
  observed_service_verified?: boolean;
  observed_port?: number;
  observed_port_verified?: boolean;
  observation_suffix?: string;
  observation_suffix_verified?: boolean;
  observed_source_only?: boolean;
  observed_source_only_verified?: boolean;
  host_name_verified?: boolean;
};

export type IdentityFinding = {
  device_id: string;
  identity_status: "enriching" | "unresolved" | "manual_resolved" | string;
  display_name: string;
  identity_note: string;
  identity_candidates: Array<{ label: string; kind?: string; catalog_id?: string; confidence?: number }>;
  identity_evidence: string[];
  manufacturer?: string;
  model?: string;
  device_type?: string;
  online: boolean;
  last_seen: string;
  risk_level: RiskLevel;
  risk_summary: string;
  detected: boolean;
  retry_after_scan?: boolean;
  is_identity_finding?: boolean;
  product_clue_verified?: boolean;
};

/**
 * A bounded observation DTO. It is not a confirmed product card. The mobile
 * presentation boundary may surface it only when the server supplies a
 * non-generic manufacturer + verified type/hostname label or a bounded,
 * verified service-response label with provenance.
 *
 * `product_clue_verified` exists only for compatibility with servers that
 * returned a revalidated manufacturer + concrete model + product type clue in
 * this collection before promoting it to `devices/items`.
 */
export type DetectedConnection = IdentityFinding & {
  name?: string;
  device_type?: string;
  is_identity_finding: true;
  presentation_kind?: "observed_connection" | string;
  observed_type?: string;
  observed_type_verified?: boolean;
  observed_service?: string;
  observed_service_verified?: boolean;
  observed_port?: number;
  observed_port_verified?: boolean;
  observation_suffix?: string;
  observation_suffix_verified?: boolean;
  observed_source_only?: boolean;
  observed_source_only_verified?: boolean;
  observed_manufacturer?: string;
  observed_manufacturer_verified?: boolean;
  observed_host_name?: string;
  host_name_verified?: boolean;
};

// 보호자 모드 read-only 대시보드 응답.
export type GuardianDashboard = {
  invite: {
    invite_id: string;
    email: string;
    relation: string;
    display_name?: string;
    ward_account_name?: string | null;
    short_code?: string;
    deep_link?: string;
    status: string;
    status_label?: string;
    expires_at?: string;
    accepted_at?: string | null;
    last_viewed_at?: string | null;
  };
  ward?: GuardianWard | null;
  ward_summary: GuardianWardSummary;
  /** 선택한 피보호자 집에서 확인된 전체 기기의 개인정보 제거 read-only 목록. */
  devices?: Device[];
  high_risk_devices: Device[];
  caution_devices: Device[];
  identity_findings?: IdentityFinding[];
  identity_pending_count?: number;
  identity_research_status?: IdentityResearchStatus;
  recent_notifications: NotificationItem[];
  read_only: boolean;
  scope: string;
};

export type GuardianWard = {
  link_id: string;
  guardian_id: string;
  invite_id: string;
  home_id: string;
  ward_account_name?: string | null;
  ward_alias?: string | null;
  ward_display_name: string;
  status: string;
  accepted_at?: string;
  revoked_at?: string | null;
  last_viewed_at?: string | null;
  summary?: GuardianWardSummary;
  /** 상세 요청이 지연돼도 즉시 보여 줄 수 있는 개인정보 제거 기기 스냅샷. */
  devices?: Device[];
};

export type GuardianWardList = {
  items: GuardianWard[];
  total: number;
};

export type GuardianAcceptResult = {
  guardian: GuardianAccount;
  wards: GuardianWard[];
  total: number;
  active_ward: GuardianWard;
  dashboard: GuardianDashboard;
};

// 백엔드 cve_matcher 가 채우는 CVE 매칭 결과.
// catalog/nvd-api 소스 모두 같은 shape, 한국어 설명은 summary_ko/remediation_ko 가 핵심.
export type CveMatch = {
  cve_id?: string;
  severity?: "critical" | "high" | "medium" | "low" | string;
  cvss?: number;
  summary_ko?: string;
  remediation_ko?: string;
  source?: "catalog" | "nvd-api" | "generic_signal" | string;
  vendor?: string;
  product?: string;
  matched_on?: string;
  confidence?: string;
};

export type DashboardData = {
  home: {
    home_id: string;
    name: string;
    mode: string;
    security_score: number | null;
    device_count: number;
    identified_device_count?: number;
    identity_pending_count?: number;
  };
  summary: {
    score: number | null;
    score_status?: "held" | "provisional" | "final" | "no_targets" | string;
    risk_level: RiskLevel;
    online_devices: number;
    high_risk_devices: number;
    recent_event_count: number;
    identity_pending_count?: number;
    identity_research_status?: IdentityResearchStatus;
  };
  top_risks: Array<{
    device_id: string;
    device_name: string;
    risk_level: RiskLevel;
    message: string;
  }>;
  guardian_status: {
    connected_guardians: number;
    last_alert_status: string;
  };
  identity_findings?: IdentityFinding[];
  identity_pending_count?: number;
  identity_research_status?: IdentityResearchStatus;
};

export type GuardianList = {
  items: GuardianInvite[];
  total: number;
  summary?: GuardianInviteSummary;
};

export type GuardianInviteSummary = {
  total: number;
  pending: number;
  accepted: number;
  expired: number;
  revoked: number;
};

export type DeviceListResult = {
  items: Device[];
  total: number;
  identified_count?: number;
  identity_pending_count?: number;
  identity_findings?: IdentityFinding[];
  detected_connections?: DetectedConnection[];
  identity_research_status?: IdentityResearchStatus;
};

export type ScanStatus = {
  scan_id: string;
  status: "completed" | "partial" | "running" | "failed";
  progress: number;
  scan_source: string;
  current_step: string;
  devices_found: number;
  high_risk_devices: number;
  identified_count?: number;
  identity_pending_count?: number;
  identity_research_status?: IdentityResearchStatus;
  identity_findings?: IdentityFinding[];
  detected_connections?: DetectedConnection[];
  /** False means findings were kept, but the whole current LAN was not covered. */
  scan_complete?: boolean;
  /** Compatibility field used by scanner/server versions that report coverage directly. */
  coverage_complete?: boolean;
  tcp_scan_timed_out?: boolean;
  /** The initial POST response may already include safe collection counters. */
  network_context?: NetworkContext;
};

export type ScanResult = ScanStatus & {
  scan_profile: string;
  network_context?: NetworkContext;
  devices: Device[];
  identity_findings?: IdentityFinding[];
  detected_connections?: DetectedConnection[];
  identified_count?: number;
  identity_pending_count?: number;
  security_score: {
    home_id?: string;
    score: number | null;
    score_status?: "held" | "provisional" | "final" | "no_targets" | string;
    risk_level: RiskLevel;
    summary?: string;
    identity_incomplete?: boolean;
    identity_pending_count?: number;
  };
};

export type NetworkContext = {
  ssid?: string | null;
  bssid?: string | null;
  local_ip?: string | null;
  gateway_ip?: string | null;
  subnet_cidr?: string | null;
  is_private_network?: boolean;
  interface_type?: "wifi" | "unknown";
  is_emulator?: boolean;
  is_virtual_network?: boolean;
  virtual_network_reason?: string | null;
  /** Safe aggregate counters used to distinguish discovery gaps from identity gaps. */
  scan_diagnostics?: ScanDiagnostics;
};

export type ScanDiagnostics = {
  subnet_host_count?: number;
  candidate_host_count?: number;
  /** Newer scanners may use this direct name; older builds use candidate_coverage_complete. */
  coverage_complete?: boolean;
  candidate_coverage_complete?: boolean;
  active_subnet_filter_enabled?: boolean;
  /** Whether Android exposed an interface-scoped neighbour source before/after probing. */
  neighbor_proc_source_available_before?: boolean;
  neighbor_ip_source_available_before?: boolean;
  neighbor_source_available_before?: boolean;
  neighbor_proc_source_available_after?: boolean;
  neighbor_ip_source_available_after?: boolean;
  neighbor_source_available_after?: boolean;
  /** Presence/coverage facts derived from the two neighbour snapshots. */
  neighbor_probe_complete?: boolean;
  neighbor_presence_confirmed?: boolean;
  neighbor_coverage_complete?: boolean;
  /** Whether every candidate received the bounded current-scan probe sweep. */
  candidate_stimulation_complete?: boolean;
  tcp_transport_complete?: boolean;
  wifi_network_socket_binding_required?: boolean;
  wifi_network_socket_binding_complete?: boolean;
  out_of_subnet_observations_dropped?: number;
  /** Server-side local-hostname endpoint evidence removed before any network fetch. */
  endpoint_evidence_quarantined?: number;
  requested_host_limit?: number;
  requested_port_count?: number;
  arp_entries_before_probe?: number;
  mdns_hosts?: number;
  mdns_raw_hosts?: number;
  ssdp_hosts?: number;
  onvif_hosts?: number;
  tcp_hosts?: number;
  tcp_responsive_hosts?: number;
  tcp_probe_completed_hosts?: number;
  tcp_scan_timed_out?: boolean;
  /** The scanner reached its hard per-scan observation bound. */
  observation_limit_reached?: boolean;
  scan_partial?: boolean;
  arp_entries_after_probe?: number;
  arp_observation_hosts?: number;
  arp_stale_entries_suppressed?: number;
  neighbor_fresh_state_hosts?: number;
  neighbor_unverified_hosts?: number;
  wifi_network_socket_bind_attempts?: number;
  wifi_network_socket_bind_failures?: number;
  wifi_network_socket_bind_suppressed?: number;
  wifi_network_unbound_paths_skipped?: number;
  wifi_network_evidence_path_failures?: number;
  /** Privacy-safe stage counts; the corresponding values never leave the private payload. */
  physical_mac_hosts?: number;
  manufacturer_hint_hosts?: number;
  model_hint_hosts?: number;
  raw_observation_count?: number;
  observation_host_limit?: number;
  observation_overflow_events?: number;
  observation_hosts_dropped?: number;
  observation_hosts_evicted?: number;
  observation_receive_buffer_dropped?: number;
};

export type DiscoveredDevicePayload = {
  device_id?: string;
  name?: string;
  device_type?: string;
  manufacturer?: string;
  model?: string;
  ip_address: string;
  mac_address?: string;
  online?: boolean;
  last_seen?: string;
  open_ports?: number[];
  services?: string[];
  default_credentials?: boolean;
  encryption?: string;
  firmware?: string;
  vulnerabilities?: Array<Record<string, unknown>>;
  discovery_sources?: string[];
  fingerprints?: string[];
  risk_signals?: string[];
  confidence?: number;
};

export type StartScanPayload = {
  scan_profile?: "quick" | "standard";
  scan_source: "android-native";
  network_context: NetworkContext;
  devices: DiscoveredDevicePayload[];
};

export type GuardianInvite = {
  invite_id: string;
  email: string;
  relation: string;
  display_name?: string;
  ward_account_name?: string | null;
  short_code?: string;
  deep_link?: string;
  status: string;
  status_label?: string;
  message: string;
  created_at?: string;
  expires_at?: string;
  accepted_at?: string | null;
  revoked_at?: string | null;
  last_viewed_at?: string | null;
};

export type NotificationItem = {
  notification_id: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  created_at: string;
};

export type NotificationList = {
  items: NotificationItem[];
  unread_count: number;
};

export type FcmTokenRegistration = {
  registered: boolean;
  platform: "android" | "ios";
  updated_at: string;
};
