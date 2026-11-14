export type HomeGuardianNetworkScannerModuleEvents = Record<string, never>;

export type NativeScanOptions = {
  maxHosts?: number;
  timeoutMillis?: number;
  ports?: number[];
};

export type NativeNetworkContext = {
  ssid: string | null;
  bssid: string | null;
  local_ip: string | null;
  gateway_ip: string | null;
  subnet_cidr: string | null;
  is_private_network: boolean;
  interface_type: "wifi" | "unknown";
  is_emulator?: boolean;
  is_virtual_network?: boolean;
  virtual_network_reason?: string | null;
};

export type NativeDiscoveredDevice = {
  device_id: string;
  name: string;
  device_type: string;
  manufacturer: string;
  model: string;
  ip_address: string;
  mac_address?: string;
  online: boolean;
  last_seen: string;
  open_ports: number[];
  services: string[];
  default_credentials: boolean;
  encryption: string;
  vulnerabilities: Array<Record<string, unknown>>;
  discovery_sources: string[];
  fingerprints: string[];
  risk_signals: string[];
  confidence: number;
};

export type NativeScanPayload = {
  scan_id: string;
  scan_source: "android-native";
  status: "completed" | "failed";
  duration_ms: number;
  network_context: NativeNetworkContext;
  devices_found: number;
  devices: NativeDiscoveredDevice[];
  /** Counters only; no IP, MAC, hostname, or banner text is allowed here. */
  scan_diagnostics?: Record<string, number | string | boolean | null>;
  error_code?: string;
  error_message?: string;
};
