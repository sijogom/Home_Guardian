import type {
  NativeScanOptions,
  NativeScanPayload,
} from "../../modules/home-guardian-network-scanner/src/HomeGuardianNetworkScanner.types";
import type { ScanDiagnostics, StartScanPayload } from "../api/types";

declare function require<T = unknown>(path: string): T;

type NativeScannerModule = {
  scanNetworkAsync: (options: NativeScanOptions) => Promise<NativeScanPayload>;
};

type AndroidPermissionsModule = {
  PERMISSIONS: Record<string, string>;
  RESULTS: { GRANTED: string };
  requestMultiple: (permissions: string[]) => Promise<Record<string, string>>;
};

type PlatformModule = {
  OS: string;
  Version: number | string;
};

export type HomeNetworkScanResult = StartScanPayload & {
  nativeStatus: NativeScanPayload["status"];
  nativeMessage?: string;
  nativeErrorCode?: string;
  isActualScan: boolean;
  blockedReason?: string;
};

const DEFAULT_SCAN_OPTIONS: NativeScanOptions = {
  // The native scanner derives the actual subnet from DHCP/netmask.  Keep a
  // generous cap for larger home networks while adding ARP-observed hosts
  // outside the sequential sample so known devices are not silently skipped.
  maxHosts: 4096,
  timeoutMillis: 350,
  // 공유기 LISTEN 포트 + 흔한 가정용 서비스 포트.
  // 21 FTP, 22 SSH, 23 Telnet, 53 DNS, 80 HTTP, 443 HTTPS, 139/445 SMB,
  // 554 RTSP, 1400/1443 Sonos 설명, 1900 SSDP/UPnP, 3702 ONVIF,
  // 5000 일반 admin, 5001 미디어, 7000/7001 미디어, 7676/8001/8002 스마트홈,
  // 7547 TR-069(공유기 원격관리), 8060 Roku, 8080/8443 alt HTTP/HTTPS, 8888 admin alt,
  // 8899 IP 카메라 알리바바, 9000 Portainer/일반, 17654 Samsung Family Hub/Spotify
  // ZeroConf getInfo, 25565 Minecraft, 32400 Plex.
  ports: [
    21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1400, 1443, 1900, 3702,
    5000, 5001, 7000, 7001, 7547, 7676, 8001, 8002, 8008, 8009, 8060,
    8080, 8081, 8443, 8888, 8899, 9000, 9001, 17654,
    9100, 25565, 32400, 49152, 49153, 49154, 49155, 49156, 49157,
  ],
};

let cachedNativeModule: NativeScannerModule | null | undefined;

type SafeNativeScanErrorCode =
  | "NATIVE_SCANNER_UNAVAILABLE"
  | "SCAN_PERMISSION_REQUIRED"
  | "SCAN_ACTUAL_DEVICE_REQUIRED"
  | "NETWORK_NOT_SCANNABLE"
  | "ACTIVE_WIFI_NETWORK_MISSING"
  | "LOCAL_IP_MISSING"
  | "LOCAL_SUBNET_MISSING"
  | "SCAN_FAILED";

const SAFE_NATIVE_SCAN_MESSAGES: Record<SafeNativeScanErrorCode, string> = {
  NATIVE_SCANNER_UNAVAILABLE:
    "기기 점검 기능을 준비하지 못했습니다. 앱을 다시 실행한 뒤 다시 시도해 주세요.",
  SCAN_PERMISSION_REQUIRED:
    "기기 탐색 권한이 필요합니다. 설정에서 근처 기기 또는 위치 권한을 허용한 뒤 다시 시도해 주세요.",
  SCAN_ACTUAL_DEVICE_REQUIRED:
    "현재 휴대전화에서는 공유기 점검을 실행할 수 없습니다. Wi-Fi에 연결된 휴대전화에서 다시 시도해 주세요.",
  NETWORK_NOT_SCANNABLE: "가정용 Wi-Fi 연결을 확인한 뒤 다시 점검해 주세요.",
  ACTIVE_WIFI_NETWORK_MISSING:
    "현재 Wi-Fi 연결을 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
  LOCAL_IP_MISSING:
    "현재 Wi-Fi 정보를 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
  LOCAL_SUBNET_MISSING:
    "현재 Wi-Fi 정보를 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
  SCAN_FAILED:
    "공유기 점검을 마치지 못했습니다. Wi-Fi 연결을 확인한 뒤 다시 시도해 주세요.",
};

export function safeNativeScanFailure(errorCode?: string | null): {
  code: SafeNativeScanErrorCode;
  message: string;
} {
  const candidate = typeof errorCode === "string" ? errorCode : "";
  const code = Object.prototype.hasOwnProperty.call(SAFE_NATIVE_SCAN_MESSAGES, candidate)
    ? (candidate as SafeNativeScanErrorCode)
    : "SCAN_FAILED";
  return { code, message: SAFE_NATIVE_SCAN_MESSAGES[code] };
}

export async function scanHomeNetwork(): Promise<HomeNetworkScanResult> {
  const nativeModule = loadNativeModule();
  if (!nativeModule) {
    return blockedScanPayload("NATIVE_SCANNER_UNAVAILABLE");
  }

  let result: NativeScanPayload;
  try {
    if (!(await ensureAndroidScanPermissions())) {
      return blockedScanPayload("SCAN_PERMISSION_REQUIRED");
    }
    result = await nativeModule.scanNetworkAsync(DEFAULT_SCAN_OPTIONS);
  } catch {
    return blockedScanPayload("SCAN_FAILED");
  }
  const blockedCode = actualScanBlockCode(result);
  const blockedReason = blockedCode
    ? safeNativeScanFailure(blockedCode).message
    : undefined;
  if (result.status === "failed" || blockedReason) {
    const failure = safeNativeScanFailure(blockedCode ?? result.error_code);
    return {
      scan_profile: "quick",
      scan_source: "android-native",
      network_context: withScanDiagnostics(result.network_context, result.scan_diagnostics),
      devices: [],
      nativeStatus: "failed",
      nativeErrorCode: failure.code,
      nativeMessage: failure.message,
      isActualScan: false,
      blockedReason,
    };
  }

  return {
    scan_profile: "quick",
    scan_source: "android-native",
    network_context: withScanDiagnostics(result.network_context, result.scan_diagnostics),
    devices: result.devices,
    nativeStatus: "completed",
    isActualScan: true,
  };
}

function withScanDiagnostics(
  networkContext: StartScanPayload["network_context"],
  diagnostics: NativeScanPayload["scan_diagnostics"],
): StartScanPayload["network_context"] {
  if (!diagnostics || typeof diagnostics !== "object") {
    return networkContext;
  }
  const safe: ScanDiagnostics = {};
  const booleanKeys: Array<keyof ScanDiagnostics> = [
    "coverage_complete",
    "candidate_coverage_complete",
    "active_subnet_filter_enabled",
    "neighbor_proc_source_available_before",
    "neighbor_ip_source_available_before",
    "neighbor_source_available_before",
    "neighbor_proc_source_available_after",
    "neighbor_ip_source_available_after",
    "neighbor_source_available_after",
    "neighbor_probe_complete",
    "neighbor_presence_confirmed",
    "neighbor_coverage_complete",
    "candidate_stimulation_complete",
    "tcp_transport_complete",
    "wifi_network_socket_binding_required",
    "wifi_network_socket_binding_complete",
    "tcp_scan_timed_out",
    "observation_limit_reached",
    "scan_partial",
  ];
  for (const key of booleanKeys) {
    const value = diagnostics[key];
    if (value === true || value === false) {
      Object.assign(safe, { [key]: value });
    }
  }
  const keys: Array<keyof ScanDiagnostics> = [
    "subnet_host_count",
    "candidate_host_count",
    "out_of_subnet_observations_dropped",
    "requested_host_limit",
    "requested_port_count",
    "arp_entries_before_probe",
    "mdns_hosts",
    "mdns_raw_hosts",
    "ssdp_hosts",
    "onvif_hosts",
    "tcp_hosts",
    "tcp_responsive_hosts",
    "tcp_probe_completed_hosts",
    "arp_entries_after_probe",
    "arp_observation_hosts",
    "arp_stale_entries_suppressed",
    "neighbor_fresh_state_hosts",
    "neighbor_unverified_hosts",
    "wifi_network_socket_bind_attempts",
    "wifi_network_socket_bind_failures",
    "wifi_network_socket_bind_suppressed",
    "wifi_network_unbound_paths_skipped",
    "wifi_network_evidence_path_failures",
    "physical_mac_hosts",
    "manufacturer_hint_hosts",
    "model_hint_hosts",
    "raw_observation_count",
    "observation_host_limit",
    "observation_overflow_events",
    "observation_hosts_dropped",
    "observation_hosts_evicted",
    "observation_receive_buffer_dropped",
  ];
  for (const key of keys) {
    const value = diagnostics[key];
    if (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1_000_000) {
      Object.assign(safe, { [key]: Math.trunc(value) });
    }
  }
  return Object.keys(safe).length ? { ...networkContext, scan_diagnostics: safe } : networkContext;
}

async function ensureAndroidScanPermissions() {
  const platform = loadPlatformModule();
  const permissionsAndroid = loadPermissionsModule();
  if (!platform || !permissionsAndroid) {
    return true;
  }

  if (platform.OS !== "android") {
    return true;
  }

  const version = typeof platform.Version === "number" ? platform.Version : Number.parseInt(String(platform.Version), 10);
  const permissionNames = permissionsAndroid.PERMISSIONS;
  const permissions =
    version >= 33
      ? [
          permissionNames.NEARBY_WIFI_DEVICES ?? "android.permission.NEARBY_WIFI_DEVICES",
          // WifiInfo.ssid/bssid are location-sensitive fields even on Android
          // 13+.  The backend immediately converts BSSID into an opaque HMAC
          // scope and never stores or returns the raw value, but without this
          // permission Android redacts it to 02:00:00:00:00:00.  A subnet-only
          // scope can collide when one account scans two different locations.
          permissionNames.ACCESS_FINE_LOCATION ?? "android.permission.ACCESS_FINE_LOCATION",
        ]
      : [
          permissionNames.ACCESS_COARSE_LOCATION ?? "android.permission.ACCESS_COARSE_LOCATION",
          permissionNames.ACCESS_FINE_LOCATION ?? "android.permission.ACCESS_FINE_LOCATION",
        ];
  const results = await permissionsAndroid.requestMultiple(permissions);
  const denied = permissions.some((permission) => results[permission] !== permissionsAndroid.RESULTS.GRANTED);
  return !denied;
}

function loadNativeModule(): NativeScannerModule | null {
  if (cachedNativeModule !== undefined) {
    return cachedNativeModule;
  }

  try {
    cachedNativeModule = require<{ default?: NativeScannerModule }>("../../modules/home-guardian-network-scanner").default ?? null;
  } catch {
    cachedNativeModule = null;
  }
  return cachedNativeModule;
}

function loadPermissionsModule(): AndroidPermissionsModule | null {
  try {
    return require<{ default?: AndroidPermissionsModule }>("react-native/Libraries/PermissionsAndroid/PermissionsAndroid").default ?? null;
  } catch {
    return null;
  }
}

function loadPlatformModule(): PlatformModule | null {
  try {
    return require<{ default?: PlatformModule }>("react-native/Libraries/Utilities/Platform").default ?? null;
  } catch {
    return null;
  }
}

function blockedScanPayload(
  errorCode: string,
): HomeNetworkScanResult {
  const failure = safeNativeScanFailure(errorCode);
  return {
    scan_profile: "quick",
    scan_source: "android-native",
    network_context: {
      ssid: null,
      bssid: null,
      local_ip: null,
      gateway_ip: null,
      subnet_cidr: null,
      is_private_network: false,
      interface_type: "unknown",
    },
    devices: [],
    nativeStatus: "failed",
    nativeErrorCode: failure.code,
    nativeMessage: failure.message,
    isActualScan: false,
    blockedReason: failure.message,
  };
}

function actualScanBlockCode(result: NativeScanPayload): SafeNativeScanErrorCode | undefined {
  const context = result.network_context;
  if (context.is_emulator || context.is_virtual_network) {
    return "SCAN_ACTUAL_DEVICE_REQUIRED";
  }
  if (isAndroidVirtualIpv4(context.local_ip) || isAndroidVirtualIpv4(context.gateway_ip) || isAndroidVirtualSubnet(context.subnet_cidr)) {
    return "SCAN_ACTUAL_DEVICE_REQUIRED";
  }
  if (result.devices.some((device) => isAndroidVirtualIpv4(device.ip_address) || isDocumentationIpv4(device.ip_address))) {
    return "SCAN_ACTUAL_DEVICE_REQUIRED";
  }
  return undefined;
}

function isAndroidVirtualSubnet(subnet?: string | null) {
  return subnet === "10.0.2.0/24" || subnet === "10.0.3.0/24";
}

function isAndroidVirtualIpv4(ip?: string | null) {
  return Boolean(ip?.startsWith("10.0.2.") || ip?.startsWith("10.0.3."));
}

function isDocumentationIpv4(ip?: string | null) {
  return Boolean(ip?.startsWith("192.0.2.") || ip?.startsWith("198.51.100.") || ip?.startsWith("203.0.113."));
}
