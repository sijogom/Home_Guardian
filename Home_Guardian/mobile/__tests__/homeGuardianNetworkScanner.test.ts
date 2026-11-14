describe("Android native scanner payload contract", () => {
  afterEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  function mockRuntime(nativeModule: unknown) {
    jest.doMock("../modules/home-guardian-network-scanner", () => ({
      __esModule: true,
      default: nativeModule,
    }));
    jest.doMock("react-native/Libraries/Utilities/Platform", () => ({
      __esModule: true,
      default: { OS: "web", Version: 1 },
    }));
    jest.doMock(
      "react-native/Libraries/PermissionsAndroid/PermissionsAndroid",
      () => ({
        __esModule: true,
        default: {
          PERMISSIONS: {},
          RESULTS: { GRANTED: "granted" },
          requestMultiple: jest.fn(),
        },
      }),
    );
  }

  function failedNativePayload(errorCode: string, errorMessage: string) {
    return {
      scan_id: "android-test",
      scan_source: "android-native" as const,
      status: "failed" as const,
      duration_ms: 1,
      network_context: {
        ssid: null,
        bssid: null,
        local_ip: "192.168.0.9",
        gateway_ip: "192.168.0.1",
        subnet_cidr: "192.168.0.0/24",
        is_private_network: true,
        interface_type: "wifi" as const,
      },
      devices_found: 0,
      devices: [],
      error_code: errorCode,
      error_message: errorMessage,
    };
  }

  it("returns an explicit context and empty device list when the native scanner is unavailable", async () => {
    mockRuntime(null);
    const { scanHomeNetwork } = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");

    await expect(scanHomeNetwork()).resolves.toMatchObject({
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
      nativeErrorCode: "NATIVE_SCANNER_UNAVAILABLE",
      nativeMessage:
        "기기 점검 기능을 준비하지 못했습니다. 앱을 다시 실행한 뒤 다시 시도해 주세요.",
      isActualScan: false,
    });
  });

  it("ignores native exception text and projects a fixed message by allowlisted code", async () => {
    const raw = "socket EADDRNOTAVAIL at 192.168.0.44 token=secret /data/user/0/app";
    mockRuntime({
      scanNetworkAsync: jest
        .fn()
        .mockResolvedValue(failedNativePayload("LOCAL_SUBNET_MISSING", raw)),
    });
    const { scanHomeNetwork } = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");

    const result = await scanHomeNetwork();

    expect(result.nativeErrorCode).toBe("LOCAL_SUBNET_MISSING");
    expect(result.nativeMessage).toBe(
      "현재 Wi-Fi 정보를 확인하지 못했습니다. Wi-Fi를 다시 연결한 뒤 점검해 주세요.",
    );
    expect(result.nativeMessage).not.toContain(raw);
    expect(JSON.stringify(result)).not.toContain("token=secret");
    expect(JSON.stringify(result)).not.toContain("/data/user/0/app");
  });

  it("maps unknown native codes and thrown bridge errors to one generic safe failure", async () => {
    const raw = "ENETDOWN 192.168.0.44 secret-token";
    mockRuntime({
      scanNetworkAsync: jest.fn().mockResolvedValue(failedNativePayload(raw, raw)),
    });
    let scanner = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");
    let result = await scanner.scanHomeNetwork();
    expect(result.nativeErrorCode).toBe("SCAN_FAILED");
    expect(JSON.stringify(result)).not.toContain(raw);

    jest.resetModules();
    mockRuntime({
      scanNetworkAsync: jest.fn().mockRejectedValue(new Error(raw)),
    });
    scanner = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");
    result = await scanner.scanHomeNetwork();
    expect(result.nativeErrorCode).toBe("SCAN_FAILED");
    expect(JSON.stringify(result)).not.toContain(raw);
  });

  it("keeps development terminology out of every resident-facing fixed message", async () => {
    mockRuntime(null);
    const { safeNativeScanFailure } = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");
    const forbidden = ["Expo Go", "native module", "development", "release"];
    const codes = [
      "NATIVE_SCANNER_UNAVAILABLE",
      "SCAN_PERMISSION_REQUIRED",
      "SCAN_ACTUAL_DEVICE_REQUIRED",
      "NETWORK_NOT_SCANNABLE",
      "ACTIVE_WIFI_NETWORK_MISSING",
      "LOCAL_IP_MISSING",
      "LOCAL_SUBNET_MISSING",
      "SCAN_FAILED",
    ];

    for (const code of codes) {
      const failure = safeNativeScanFailure(code);
      expect(failure.message).not.toBe("");
      forbidden.forEach((word) =>
        expect(failure.message.toLowerCase()).not.toContain(word.toLowerCase()),
      );
    }
  });

  it("preserves allowlisted neighbour coverage diagnostics without exposing arbitrary native fields", async () => {
    mockRuntime({
      scanNetworkAsync: jest.fn().mockResolvedValue({
        ...failedNativePayload("", ""),
        status: "completed" as const,
        scan_diagnostics: {
          coverage_complete: false,
          scan_partial: true,
          neighbor_proc_source_available_before: true,
          neighbor_ip_source_available_before: false,
          neighbor_source_available_before: true,
          neighbor_proc_source_available_after: true,
          neighbor_ip_source_available_after: true,
          neighbor_source_available_after: true,
          neighbor_probe_complete: true,
          neighbor_presence_confirmed: false,
          neighbor_coverage_complete: false,
          candidate_stimulation_complete: false,
          tcp_transport_complete: false,
          observation_limit_reached: true,
          tcp_probe_completed_hosts: 18,
          arp_observation_hosts: 5,
          arp_stale_entries_suppressed: 2,
          neighbor_fresh_state_hosts: 1,
          neighbor_unverified_hosts: 2,
          wifi_network_socket_binding_required: true,
          wifi_network_socket_binding_complete: false,
          wifi_network_socket_bind_attempts: 42,
          wifi_network_socket_bind_failures: 1,
          physical_mac_hosts: 5,
          manufacturer_hint_hosts: 3,
          model_hint_hosts: 2,
          observation_host_limit: 512,
          observation_overflow_events: 4,
          observation_hosts_dropped: 1,
          observation_hosts_evicted: 3,
          observation_receive_buffer_dropped: 2,
          private_native_detail: "must-not-cross",
        },
      }),
    });
    const { scanHomeNetwork } = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");

    const result = await scanHomeNetwork();

    expect(result.network_context.scan_diagnostics).toMatchObject({
      coverage_complete: false,
      scan_partial: true,
      neighbor_proc_source_available_before: true,
      neighbor_ip_source_available_before: false,
      neighbor_source_available_before: true,
      neighbor_proc_source_available_after: true,
      neighbor_ip_source_available_after: true,
      neighbor_source_available_after: true,
      neighbor_probe_complete: true,
      neighbor_presence_confirmed: false,
      neighbor_coverage_complete: false,
      candidate_stimulation_complete: false,
      tcp_transport_complete: false,
      observation_limit_reached: true,
      tcp_probe_completed_hosts: 18,
      arp_observation_hosts: 5,
      arp_stale_entries_suppressed: 2,
      neighbor_fresh_state_hosts: 1,
      neighbor_unverified_hosts: 2,
      wifi_network_socket_binding_required: true,
      wifi_network_socket_binding_complete: false,
      wifi_network_socket_bind_attempts: 42,
      wifi_network_socket_bind_failures: 1,
      physical_mac_hosts: 5,
      manufacturer_hint_hosts: 3,
      model_hint_hosts: 2,
      observation_host_limit: 512,
      observation_overflow_events: 4,
      observation_hosts_dropped: 1,
      observation_hosts_evicted: 3,
      observation_receive_buffer_dropped: 2,
    });
    expect(JSON.stringify(result)).not.toContain("private_native_detail");
    expect(JSON.stringify(result)).not.toContain("must-not-cross");
  });

  it("requests nearby Wi-Fi and precise location together on Android 13+ so BSSID is not redacted", async () => {
    const requestMultiple = jest.fn().mockResolvedValue({
      "android.permission.NEARBY_WIFI_DEVICES": "granted",
      "android.permission.ACCESS_FINE_LOCATION": "granted",
    });
    jest.doMock("../modules/home-guardian-network-scanner", () => ({
      __esModule: true,
      default: {
        scanNetworkAsync: jest.fn().mockResolvedValue({
          ...failedNativePayload("", ""),
          status: "completed" as const,
        }),
      },
    }));
    jest.doMock("react-native/Libraries/Utilities/Platform", () => ({
      __esModule: true,
      default: { OS: "android", Version: 35 },
    }));
    jest.doMock(
      "react-native/Libraries/PermissionsAndroid/PermissionsAndroid",
      () => ({
        __esModule: true,
        default: {
          PERMISSIONS: {
            NEARBY_WIFI_DEVICES: "android.permission.NEARBY_WIFI_DEVICES",
            ACCESS_FINE_LOCATION: "android.permission.ACCESS_FINE_LOCATION",
          },
          RESULTS: { GRANTED: "granted" },
          requestMultiple,
        },
      }),
    );

    const { scanHomeNetwork } = require("../src/native/homeGuardianNetworkScanner") as typeof import("../src/native/homeGuardianNetworkScanner");
    await expect(scanHomeNetwork()).resolves.toMatchObject({ isActualScan: true });
    expect(requestMultiple).toHaveBeenCalledWith([
      "android.permission.NEARBY_WIFI_DEVICES",
      "android.permission.ACCESS_FINE_LOCATION",
    ]);
  });
});
