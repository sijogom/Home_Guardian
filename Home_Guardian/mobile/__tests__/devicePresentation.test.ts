import type { DashboardData, DetectedConnection, Device, GuardianDashboard, NotificationItem, ScanResult } from "../src/api/types";
import {
  canonicalDeviceName,
  presentDashboard,
  presentDevice,
  presentDeviceCollection,
  presentDetectedConnections,
  presentDevices,
  presentGuardianDashboard,
  presentNotification,
  presentScanResult,
  residentNotificationTime,
  residentDeviceAccessibilityLabel,
} from "../src/utils/devicePresentation";

function makeDevice(overrides: Partial<Device> = {}): Device {
  return {
    device_id: "device-1",
    name: "삼성 냉장고 (RF85C90F1AP)",
    canonical_name: "삼성 냉장고 (RF85C90F1AP)",
    device_type: "refrigerator",
    manufacturer: "삼성",
    model: "RF85C90F1AP",
    ip_address: "192.168.0.10",
    mac_address: "AA:BB:CC:DD:EE:FF",
    online: true,
    last_seen: "2026-08-13T00:00:00Z",
    open_ports: [],
    services: [],
    default_credentials: false,
    encryption: "WPA3",
    firmware: "1.0.0",
    vulnerabilities: [],
    discovery_sources: ["mdns"],
    fingerprints: [],
    risk_signals: [],
    scan_source: "android-native",
    confidence: 0.99,
    identity_status: "resolved",
    security_score: 100,
    risk_level: "green",
    risk_summary: "안전하게 확인되었습니다.",
    recommended_actions: ["정기적으로 확인해 주세요."],
    ...overrides,
  };
}

function makeScanResult(devices: Device[]): ScanResult {
  return {
    scan_id: "scan-1",
    status: "completed",
    progress: 100,
    scan_source: "android-native",
    current_step: "completed",
    devices_found: devices.length,
    high_risk_devices: devices.filter((device) => device.risk_level === "red").length,
    identity_pending_count: 0,
    identity_research_status: "complete",
    identity_findings: [],
    scan_profile: "standard",
    devices,
    security_score: {
      score: 90,
      risk_level: "green",
    },
  };
}

function makeDetectedConnection(overrides: Partial<DetectedConnection> = {}): DetectedConnection {
  return {
    device_id: "detected-connection-1",
    identity_status: "unresolved",
    display_name: "연결된 장비",
    name: "연결된 장비",
    identity_note: "제품명이 없어도 확인된 연결과 보안 신호를 점수에 반영했어요.",
    identity_candidates: [],
    identity_evidence: ["기기가 응답한 네트워크 서비스"],
    device_type: "network",
    online: true,
    last_seen: "2026-08-24T00:00:00Z",
    risk_level: "yellow",
    risk_summary: "확인된 보안 신호를 기준으로 현재 상태를 계산했어요.",
    detected: true,
    is_identity_finding: true,
    ...overrides,
  };
}

function makeDashboard(overrides: Partial<DashboardData> = {}): DashboardData {
  return {
    home: {
      home_id: "home-1",
      name: "우리 집",
      mode: "home",
      security_score: 90,
      device_count: 1,
    },
    summary: {
      score: 90,
      risk_level: "green",
      online_devices: 1,
      high_risk_devices: 0,
      recent_event_count: 0,
    },
    top_risks: [],
    guardian_status: {
      connected_guardians: 0,
      last_alert_status: "",
    },
    ...overrides,
  };
}

function makeNotification(overrides: Partial<NotificationItem> = {}): NotificationItem {
  return {
    notification_id: "notification-1",
    type: "security",
    title: "검사 결과를 알려드립니다",
    message: "확인된 기기만 목록에 표시합니다.",
    read: false,
    created_at: "2026-08-13T00:00:00Z",
    ...overrides,
  };
}

describe("모바일 캐시 기기 표시 정규화", () => {
  it("제품 근거가 없는 오디오 프로토콜은 제품으로 표시하지 않는다", () => {
    expect(
      presentDevice(
        makeDevice({
          device_id: "audio-1",
          name: "오디오 기기",
          canonical_name: "오디오 기기",
          device_type: "audio",
          manufacturer: "",
          model: "",
        }),
      ),
    ).toBeNull();
  });

  it("확인된 제조사, 물품 종류, 모델명 조합은 그대로 표시한다", () => {
    const refrigerator = presentDevice(makeDevice());
    const router = presentDevice(
      makeDevice({
        device_id: "device-2",
        name: "ipTIME 공유기 (A3004NS-M)",
        canonical_name: "ipTIME 공유기 (A3004NS-M)",
        device_type: "router",
        manufacturer: "ipTIME",
        model: "A3004NS-M",
      }),
    );

    expect(refrigerator).toMatchObject({
      name: "삼성 냉장고 (RF85C90F1AP)",
      canonical_name: "삼성 냉장고 (RF85C90F1AP)",
      manufacturer: "삼성",
      model: "RF85C90F1AP",
    });
    expect(router).toMatchObject({
      name: "ipTIME 공유기 (A3004NS-M)",
      canonical_name: "ipTIME 공유기 (A3004NS-M)",
      manufacturer: "ipTIME",
      model: "A3004NS-M",
    });
  });

  it("별칭이 있어도 확인된 제품 이름과 품번은 따로 보존한다", () => {
    const presented = presentDevice(makeDevice({ alias: "주방 냉장고" }));

    expect(presented).toMatchObject({
      name: "주방 냉장고",
      canonical_name: "삼성 냉장고 (RF85C90F1AP)",
    });
    expect(canonicalDeviceName(presented!)).toBe("삼성 냉장고 (RF85C90F1AP)");
    expect(residentDeviceAccessibilityLabel(presented!)).toContain("확인된 제품 이름과 품번: 삼성 냉장고 (RF85C90F1AP)");
  });

  it("모델이 없어도 서버가 검증한 컴퓨터 제조사군은 표시하고 일반 종류명은 숨긴다", () => {
    const asrock = presentDevice(
      makeDevice({
        name: "ASRock 컴퓨터",
        canonical_name: "ASRock 컴퓨터",
        device_type: "computer",
        manufacturer: "ASRock",
        model: "",
        identity_status: "resolved",
        identity_family_verified: true,
        identity_evidence: ["네트워크 제조사 조회 단서"],
      }),
    );
    const msi = presentDevice(
      makeDevice({
        device_id: "computer-msi",
        name: "MSI 컴퓨터",
        canonical_name: "MSI 컴퓨터",
        device_type: "computer",
        manufacturer: "MSI",
        model: "",
        identity_status: "resolved",
        identity_family_verified: true,
        identity_evidence: ["네트워크 제조사 조회 단서"],
      }),
    );
    const computer = presentDevice(
      makeDevice({
        name: "컴퓨터",
        canonical_name: "컴퓨터",
        device_type: "computer",
        manufacturer: "",
        model: "",
        identity_status: "resolved",
        identity_family_verified: true,
        identity_evidence: ["열려 있는 네트워크 서비스"],
      }),
    );

    expect(asrock).toMatchObject({
      name: "ASRock 컴퓨터",
      canonical_name: "ASRock 컴퓨터",
      manufacturer: "ASRock",
      model: "",
    });
    expect(msi).toMatchObject({
      name: "MSI 컴퓨터",
      canonical_name: "MSI 컴퓨터",
      manufacturer: "MSI",
      model: "",
    });
    expect(computer).toBeNull();
  });

  it("서버가 검증한 컴퓨터 호스트명을 품목명 뒤에 안전하게 표시한다", () => {
    const presented = presentDevice(
      makeDevice({
        name: "ASRock 컴퓨터 - testpc",
        canonical_name: "ASRock 컴퓨터 - testpc",
        device_type: "computer",
        manufacturer: "ASRock",
        model: "",
        identity_status: "resolved",
        identity_family_verified: true,
        identity_evidence: ["서버에 이전에 확인된 제품 정보"],
      }),
    );
    expect(presented).toMatchObject({
      name: "ASRock 컴퓨터 - testpc",
      canonical_name: "ASRock 컴퓨터 - testpc",
    });

    expect(
      presentDevice(
        makeDevice({
          name: "ASRock 컴퓨터 - 192.168.0.2",
          canonical_name: "ASRock 컴퓨터 - 192.168.0.2",
          device_type: "computer",
          manufacturer: "ASRock",
          model: "",
          identity_status: "resolved",
          identity_family_verified: true,
          identity_evidence: ["서버에 이전에 확인된 제품 정보"],
        }),
      ),
    ).toBeNull();
  });

  it("가족 검증 플래그만 위조한 모델 없는 컴퓨터는 표시하지 않는다", () => {
    expect(
      presentDevice(
        makeDevice({
          name: "ASRock 컴퓨터",
          canonical_name: "ASRock 컴퓨터",
          device_type: "computer",
          manufacturer: "ASRock",
          model: "",
          identity_status: "resolved",
          identity_family_verified: true,
          identity_evidence: [],
        }),
      ),
    ).toBeNull();
  });

  it("서버가 만든 canonical_name 없는 기존 캐시는 그럴듯해도 숨긴다", () => {
    const selfConsistentLegacyDevice = makeDevice({
      canonical_name: undefined,
      name: "삼성 냉장고 (RF85C90F1AP)",
    });
    const forgedLegacyDevice = makeDevice({
      device_id: "forged-legacy",
      canonical_name: undefined,
      name: "가짜브랜드 냉장고 (FAKE-1)",
      manufacturer: "가짜브랜드",
      model: "FAKE-1",
    });

    expect(presentDevice(selfConsistentLegacyDevice)).toBeNull();
    expect(presentDevice(forgedLegacyDevice)).toBeNull();
  });

  it("falls back to the verified product name when an alias has technical terms", () => {
    const canonicalName = "삼성 냉장고 (RF85C90F1AP)";

    for (const alias of ["mDNS 기기", "SSDP 기기", "ONVIF 카메라", "RTSP 카메라", "UPnP 기기", "CVE-2026-0001", "CVE20260001", "API 설정", "OAuth 연결", "PKCE 연결", "HTTP 기기"]) {
      const presented = presentDevice(makeDevice({ alias }));

      expect(presented).toMatchObject({ name: canonicalName, canonical_name: canonicalName });
      expect(presented?.alias).toBeUndefined();
      expect(JSON.stringify(presented)).not.toContain(alias);
      expect(residentDeviceAccessibilityLabel(presented!)).not.toContain(alias);
      expect(
        residentDeviceAccessibilityLabel({
          name: alias,
          canonical_name: canonicalName,
        } as Pick<Device, "name" | "canonical_name">),
      ).toBe(canonicalName);
    }
  });

  it("rejects a structurally noncanonical but safe-looking cached identity", () => {
    expect(
      presentDevice(
        makeDevice({
          canonical_name: "거실 장치",
        }),
      ),
    ).toBeNull();

    expect(
      presentDevice(
        makeDevice({
          canonical_name: "삼성 냉장고 (다른 모델)",
        }),
      ),
    ).toBeNull();

    expect(
      presentDevice(
        makeDevice({
          manufacturer: "",
          model: "RF85C90F1AP",
          canonical_name: "냉장고 (RF85C90F1AP)",
        }),
      ),
    ).toBeNull();

    expect(
      presentDevice(
        makeDevice({
          identity_status: "unresolved",
        }),
      ),
    ).toBeNull();
  });

  it("금지된 임시 이름, 미확인 이름, 칩셋 이름을 가진 캐시 기기는 숨긴다", () => {
    const hidden = presentDevices([
      makeDevice({ name: "웹 관리 기기", canonical_name: "웹 관리 기기" }),
      makeDevice({ name: "제조사 미확인", canonical_name: "제조사 미확인" }),
      makeDevice({ name: "정체불명 기기", canonical_name: "정체불명 기기" }),
      makeDevice({ name: "Realtek RTL8197F", canonical_name: "Realtek RTL8197F" }),
      makeDevice({ name: "ESP32 기기", canonical_name: "ESP32 기기" }),
    ]);

    expect(hidden).toEqual([]);
  });

  it("IEEE, OUI, IANA, MA 등록정보와 등록기관 이름이 제품명에 있으면 숨긴다", () => {
    const forbiddenIdentityLabels = [
      "IEEE",
      "OUI",
      "IANA",
      "MA-L",
      "MA-M",
      "MA-S",
      "Registration Authority",
      "등록기관",
      "Private 등록기관",
    ];

    for (const identityLabel of forbiddenIdentityLabels) {
      expect(
        presentDevice(
          makeDevice({
            name: `삼성 냉장고 (${identityLabel})`,
            canonical_name: `삼성 냉장고 (${identityLabel})`,
          }),
        ),
      ).toBeNull();
    }
  });

  it("안전해 보이는 별칭이 있어도 확인되지 않은 원본 신호는 다시 표시하지 않는다", () => {
    expect(
      presentDevice(
        makeDevice({
          name: "제조사 미확인",
          canonical_name: "Realtek RTL8197F",
          alias: "우리 집 기기",
        }),
      ),
    ).toBeNull();
  });

  it("칩셋 제조사나 탐색용 종류가 남은 캐시 기기는 복원하지 않는다", () => {
    const presented = presentDevice(
      makeDevice({
        manufacturer: "Espressif Systems",
        model: "ESP32-WROOM-32",
        firmware: "Realtek SDK 2.0",
        device_type: "web-device",
        fingerprints: ["Realtek SDK"],
        risk_signals: ["Espressif discovery"],
      }),
    );

    expect(presented).toBeNull();
  });

  it("의미상 미확인·후보 이름과 공개하지 않는 종류도 캐시에서 숨긴다", () => {
    const hidden = presentDevices([
      makeDevice({ name: "임시 기기", canonical_name: "임시 기기" }),
      makeDevice({ name: "candidate device", canonical_name: "candidate device" }),
      makeDevice({ device_type: "iot" }),
      makeDevice({ device_type: "web-device" }),
    ]);

    expect(hidden).toEqual([]);
  });

  it("안전한 기기를 복원할 때 내부 탐색 주소와 서비스 값은 제거한다", () => {
    const presented = presentDevice(
      makeDevice({
        ip_address: "192.168.0.10",
        mac_address: "AA:BB:CC:DD:EE:FF",
        open_ports: [80, 443],
        services: ["web-device"],
        firmware: "internal-build",
        discovery_sources: ["mdns"],
        encryption: "WPA3",
        identity_note: "scanner note",
      }),
    );

    expect(presented).toMatchObject({
      ip_address: "",
      mac_address: "",
      open_ports: [],
      services: [],
      firmware: "",
      discovery_sources: [],
      encryption: "",
      identity_note: "",
    });
  });

  it("generic 연결명은 기기 수에서 제외하되 완료 상태와 서버 점수 계약은 유지한다", () => {
    const result = presentScanResult({
      scan_id: "scan-identity",
      status: "completed",
      progress: 100,
      scan_source: "android-native",
      current_step: "점검 완료",
      devices_found: 1,
      high_risk_devices: 1,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      scan_complete: true,
      coverage_complete: true,
      scan_profile: "quick",
      devices: [],
      detected_connections: [makeDetectedConnection()],
      identity_findings: [],
      security_score: { score: 90, risk_level: "red" },
    });

    expect(result?.devices_found).toBe(0);
    expect(result?.identity_pending_count).toBe(0);
    expect(result?.identity_research_status).toBe("review_required");
    expect(result?.status).toBe("completed");
    expect(result?.scan_complete).toBe(true);
    expect(result?.coverage_complete).toBe(true);
    expect(result?.security_score.score).toBe(90);
    expect(result?.security_score.risk_level).toBe("red");
    expect(result?.identity_findings).toEqual([]);
    expect(result?.devices).toHaveLength(0);

    const noTargetResult = presentScanResult({
      scan_id: "scan-no-targets",
      status: "completed",
      progress: 100,
      scan_source: "android-native",
      current_step: "점검 완료",
      devices_found: 0,
      high_risk_devices: 0,
      identified_count: 0,
      identity_pending_count: 0,
      identity_research_status: "complete",
      scan_complete: true,
      coverage_complete: true,
      scan_profile: "quick",
      devices: [],
      identity_findings: [],
      security_score: {
        score: null,
        score_status: "no_targets",
        risk_level: "unknown",
        summary: "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요.",
      },
    });

    expect(noTargetResult).toMatchObject({
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      devices_found: 0,
      security_score: {
        score: null,
        score_status: "no_targets",
        risk_level: "unknown",
      },
    });
  });

  it("구조화된 제조사·품번·종류 단서는 미확정 연결에서도 지우지 않는다", () => {
    const result = presentScanResult({
      ...makeScanResult([]),
      devices_found: 1,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      detected_connections: [
        makeDetectedConnection({
          display_name: "삼성 냉장고 (RF85C90)",
          name: "삼성 냉장고 (RF85C90)",
          manufacturer: "삼성",
          model: "RF85C90",
          device_type: "fridge",
          product_clue_verified: true,
          presentation_kind: "observed_connection",
          observed_service: "mdns",
          observed_service_verified: true,
        }),
      ],
    });

    expect(result).toMatchObject({
      devices_found: 1,
      identified_count: 0,
      identity_pending_count: 1,
      devices: [
        {
          name: "삼성 냉장고 (RF85C90)",
          canonical_name: "삼성 냉장고 (RF85C90)",
          manufacturer: "삼성",
          model: "RF85C90",
          device_type: "fridge",
          product_clue_verified: true,
          observed_service: "mdns",
          observed_service_verified: true,
          is_identity_finding: true,
        },
      ],
    });
  });

  it("근거가 검증된 제조사·종류와 안전한 컴퓨터 호스트명은 관측 카드로 보존한다", () => {
    const connections = presentDetectedConnections([
      makeDetectedConnection({
        device_id: "observed-google-tv",
        presentation_kind: "observed_connection",
        display_name: "Google TV",
        name: "Google TV",
        manufacturer: "Google",
        model: "",
        device_type: "tv",
        observed_type_verified: true,
        identity_evidence: ["기기가 보낸 식별 정보"],
      }),
      makeDetectedConnection({
        device_id: "observed-asrock-computer",
        presentation_kind: "observed_connection",
        display_name: "ASRock 컴퓨터 - testpc",
        name: "ASRock 컴퓨터 - testpc",
        manufacturer: "ASRock",
        model: "",
        device_type: "computer",
        observed_type_verified: true,
        observed_host_name: "testpc",
        host_name_verified: true,
        identity_evidence: ["서버에 저장된 식별 정보"],
      }),
      makeDetectedConnection({
        device_id: "observed-host-only-computer",
        presentation_kind: "observed_connection",
        display_name: "desktop-home",
        name: "desktop-home",
        manufacturer: "",
        model: "",
        device_type: "computer",
        observed_type_verified: true,
        observed_host_name: "desktop-home",
        host_name_verified: true,
        identity_evidence: ["기기가 응답한 네트워크 서비스"],
      }),
      makeDetectedConnection({
        device_id: "observed-onvif-service",
        presentation_kind: "observed_connection",
        display_name: "카메라 · C0FFEE",
        name: "카메라 · C0FFEE",
        manufacturer: "",
        model: "",
        device_type: "camera",
        observed_type_verified: true,
        observed_service: "onvif",
        observed_service_verified: true,
        observation_suffix: "C0FFEE",
        observation_suffix_verified: true,
        identity_evidence: ["기기가 보낸 네트워크 응답"],
      }),
    ]);

    expect(connections).toMatchObject([
      {
        name: "Google TV",
        canonical_name: "Google TV",
        manufacturer: "Google",
        device_type: "tv",
        is_identity_finding: true,
      },
      {
        name: "ASRock 컴퓨터 - testpc",
        canonical_name: "ASRock 컴퓨터 - testpc",
        manufacturer: "ASRock",
        device_type: "computer",
        is_identity_finding: true,
      },
      {
        name: "desktop-home",
        canonical_name: "desktop-home",
        manufacturer: "",
        device_type: "computer",
        is_identity_finding: true,
      },
      {
        name: "카메라 · C0FFEE",
        canonical_name: "카메라 · C0FFEE",
        manufacturer: "",
        device_type: "camera",
        observed_service: undefined,
        observed_service_verified: false,
        is_identity_finding: true,
      },
    ]);
  });

  it("서버 플래그가 있어도 generic·ordinal 연결명과 안전하지 않은 호스트명은 숨긴다", () => {
    const base = {
      presentation_kind: "observed_connection",
      observed_type_verified: true,
      identity_evidence: ["기기가 보낸 식별 정보"],
    } as const;

    expect(
      presentDetectedConnections([
        makeDetectedConnection({ ...base }),
        makeDetectedConnection({
          ...base,
          device_id: "generic-computer",
          display_name: "컴퓨터 연결",
          name: "컴퓨터 연결",
          manufacturer: "ASRock",
          device_type: "computer",
        }),
        makeDetectedConnection({
          ...base,
          device_id: "ordinal-device",
          display_name: "연결된 장비 02",
          name: "연결된 장비 02",
          manufacturer: "Google",
          device_type: "tv",
        }),
        makeDetectedConnection({
          ...base,
          device_id: "unsafe-computer-host",
          display_name: "ASRock 컴퓨터 - 192.168.0.2",
          name: "ASRock 컴퓨터 - 192.168.0.2",
          manufacturer: "ASRock",
          device_type: "computer",
          host_name_verified: true,
        }),
        makeDetectedConnection({
          ...base,
          device_id: "forged-service-label",
          display_name: "카메라 표준 서비스 응답",
          name: "카메라 표준 서비스 응답",
          manufacturer: "",
          device_type: "camera",
          observed_service: "onvif",
          observed_service_verified: true,
        }),
      ]),
    ).toEqual([]);
  });

  it("TCP OPEN만은 숨기고 L2 neighbor는 불투명 식별자 카드로 보존한다", () => {
    const connections = presentDetectedConnections([
      makeDetectedConnection({
        device_id: "tcp-open-device-a",
        presentation_kind: "observed_connection",
        display_name: "TCP 서비스 응답 (포트 8443) · A1B2C3",
        name: "TCP 서비스 응답 (포트 8443) · A1B2C3",
        device_type: "",
        observed_service: "tcp-service",
        observed_service_verified: true,
        observed_port: 8443,
        observed_port_verified: true,
        observation_suffix: "A1B2C3",
        observation_suffix_verified: true,
        identity_evidence: ["기기가 응답한 네트워크 서비스"],
      }),
      makeDetectedConnection({
        device_id: "fresh-neighbor-device-a",
        presentation_kind: "observed_connection",
        display_name: "Wi-Fi 단말 · D4E5F6",
        name: "Wi-Fi 단말 · D4E5F6",
        device_type: "",
        observed_service: "neighbor-presence",
        observed_service_verified: true,
        observation_suffix: "D4E5F6",
        observation_suffix_verified: true,
        identity_evidence: ["기기가 보낸 네트워크 응답"],
      }),
    ]);

    expect(connections).toMatchObject([
      {
        device_id: "fresh-neighbor-device-a",
        name: "Wi-Fi 단말 · D4E5F6",
        canonical_name: "Wi-Fi 단말 · D4E5F6",
        device_type: "network",
        is_identity_finding: true,
      },
    ]);
    expect(JSON.stringify(connections)).not.toContain("TCP 서비스 응답");
    expect(JSON.stringify(connections)).not.toContain("현재 Wi-Fi 이웃 확인");
  });

  it("미식별 L2 단말도 카드·점수·위험 집계와 접근성 이름에 남긴다", () => {
    const l2 = makeDetectedConnection({
      device_id: "red-l2-device",
      presentation_kind: "observed_connection",
      display_name: "Wi-Fi 단말 · A1B2C3",
      name: "Wi-Fi 단말 · A1B2C3",
      device_type: "network",
      observed_service: "neighbor-presence",
      observed_service_verified: true,
      observation_suffix: "A1B2C3",
      observation_suffix_verified: true,
      risk_level: "red",
      identity_note: "현재 관측 근거를 보안 점수에 반영했어요.",
    });
    const result = presentScanResult({
      ...makeScanResult([]),
      devices_found: 1,
      high_risk_devices: 1,
      identity_pending_count: 1,
      identity_research_status: "review_required",
      detected_connections: [l2],
      security_score: { score: 42, score_status: "final", risk_level: "red" },
    });

    expect(result).toMatchObject({
      devices_found: 1,
      high_risk_devices: 1,
      identity_pending_count: 1,
      security_score: { score: 42, risk_level: "red" },
      devices: [{ device_id: "red-l2-device", name: "Wi-Fi 단말 · A1B2C3", risk_level: "red" }],
    });
    expect(residentDeviceAccessibilityLabel(result!.devices[0])).toBe("Wi-Fi 단말 · A1B2C3");
  });

  it("source-only mDNS·SSDP 관측은 검증 접미사가 있어도 별도 카드로 만들지 않는다", () => {
    const connections = presentDetectedConnections([
      makeDetectedConnection({
        device_id: "mdns-source-a",
        presentation_kind: "observed_connection",
        display_name: "기기 정보 방송 응답 · 11AA22",
        name: "기기 정보 방송 응답 · 11AA22",
        device_type: "",
        observed_service: "mdns",
        observed_service_verified: true,
        observation_suffix: "11AA22",
        observation_suffix_verified: true,
        observed_source_only: true,
        observed_source_only_verified: true,
        identity_evidence: ["기기가 보낸 네트워크 정보"],
      }),
      makeDetectedConnection({
        device_id: "ssdp-source-a",
        presentation_kind: "observed_connection",
        display_name: "기기 검색 서비스 응답 · 33BB44",
        name: "기기 검색 서비스 응답 · 33BB44",
        device_type: "",
        observed_service: "ssdp",
        observed_service_verified: true,
        observation_suffix: "33BB44",
        observation_suffix_verified: true,
        observed_source_only: true,
        observed_source_only_verified: true,
        identity_evidence: ["기기가 보낸 네트워크 정보"],
      }),
    ]);

    expect(connections).toEqual([]);
  });

  it("Spotify Connect 응답도 제품이나 종류 근거가 없으면 별도 카드로 만들지 않는다", () => {
    const verified = makeDetectedConnection({
      device_id: "observation-service-a",
      presentation_kind: "observed_connection",
      display_name: "Spotify Connect 서비스 응답",
      name: "Spotify Connect 서비스 응답",
      device_type: "",
      observed_service: "spotify-connect",
      observed_service_verified: true,
      identity_evidence: ["기기가 응답한 네트워크 서비스"],
    });
    const probeAttemptOnly = makeDetectedConnection({
      device_id: "observation-probe-a",
      presentation_kind: "observed_connection",
      display_name: "Spotify Connect 서비스 응답",
      name: "Spotify Connect 서비스 응답",
      device_type: "",
      observed_service: "spotify-connect",
      observed_service_verified: false,
      identity_evidence: ["기기가 응답한 네트워크 서비스"],
    });
    const forgedLabel = makeDetectedConnection({
      ...verified,
      device_id: "observation-forged-a",
      display_name: "Sonos 오디오 기기",
      name: "Sonos 오디오 기기",
    });

    expect(presentDetectedConnections([verified, probeAttemptOnly, forgedLabel])).toEqual([]);
  });

  it("OPEN·이웃 관측의 플래그, 포트, 접미사 또는 문구가 위조되면 표시하지 않는다", () => {
    const tcpBase = {
      presentation_kind: "observed_connection",
      device_type: "",
      observed_service: "tcp-service",
      observed_service_verified: true,
      observed_port: 443,
      observed_port_verified: true,
      observation_suffix: "ABC123",
      observation_suffix_verified: true,
      identity_evidence: ["기기가 응답한 네트워크 서비스"],
    } as const;
    const neighborBase = {
      presentation_kind: "observed_connection",
      device_type: "",
      observed_service: "neighbor-presence",
      observed_service_verified: true,
      observation_suffix: "DEF456",
      observation_suffix_verified: true,
      identity_evidence: ["기기가 보낸 네트워크 응답"],
    } as const;

    expect(
      presentDetectedConnections([
        makeDetectedConnection({
          ...tcpBase,
          device_id: "tcp-port-mismatch",
          display_name: "TCP 서비스 응답 (포트 80) · ABC123",
          name: "TCP 서비스 응답 (포트 80) · ABC123",
        }),
        makeDetectedConnection({
          ...tcpBase,
          device_id: "tcp-invalid-port",
          display_name: "TCP 서비스 응답 (포트 70000) · ABC123",
          name: "TCP 서비스 응답 (포트 70000) · ABC123",
          observed_port: 70000,
        }),
        makeDetectedConnection({
          ...tcpBase,
          device_id: "tcp-unverified-suffix",
          display_name: "TCP 서비스 응답 (포트 443) · ABC123",
          name: "TCP 서비스 응답 (포트 443) · ABC123",
          observation_suffix_verified: false,
        }),
        makeDetectedConnection({
          ...neighborBase,
          device_id: "neighbor-arbitrary-suffix",
          display_name: "현재 Wi-Fi 이웃 확인 · classroom",
          name: "현재 Wi-Fi 이웃 확인 · classroom",
          observation_suffix: "classroom",
        }),
        makeDetectedConnection({
          ...neighborBase,
          device_id: "neighbor-generic",
          display_name: "연결된 장비",
          name: "연결된 장비",
        }),
        makeDetectedConnection({
          presentation_kind: "observed_connection",
          device_id: "mdns-source-without-source-proof",
          display_name: "기기 정보 방송 응답 · 11AA22",
          name: "기기 정보 방송 응답 · 11AA22",
          device_type: "",
          observed_service: "mdns",
          observed_service_verified: true,
          observation_suffix: "11AA22",
          observation_suffix_verified: true,
          identity_evidence: ["기기가 보낸 네트워크 정보"],
        }),
      ]),
    ).toEqual([]);
  });

  it("같은 제조사·호스트명이라도 공개 ID가 다른 실제 연결은 모두 유지한다", () => {
    const observation = {
      presentation_kind: "observed_connection",
      display_name: "ASRock 컴퓨터 - testpc",
      name: "ASRock 컴퓨터 - testpc",
      manufacturer: "ASRock",
      device_type: "computer",
      observed_type_verified: true,
      observed_host_name: "testpc",
      host_name_verified: true,
      observed_service: "smb",
      observed_service_verified: true,
      identity_evidence: ["서버에 저장된 식별 정보"],
    } as const;

    expect(
      presentDetectedConnections([
        makeDetectedConnection({ ...observation, device_id: "same-label-a" }),
        makeDetectedConnection({ ...observation, device_id: "same-label-b" }),
      ]).map((item) => item.device_id),
    ).toEqual(["same-label-a", "same-label-b"]);
  });

  it("같은 공개 ID의 확정 제품과 관측 단서가 겹치면 확정 제품 한 건만 남긴다", () => {
    const resolved = makeDevice({ device_id: "same-public-id" });
    const detected = makeDetectedConnection({
      device_id: "same-public-id",
      display_name: resolved.canonical_name!,
      name: resolved.canonical_name!,
      manufacturer: resolved.manufacturer,
      model: resolved.model,
      device_type: resolved.device_type,
      product_clue_verified: true,
    });

    const merged = presentDeviceCollection([resolved], [detected]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({
      device_id: "same-public-id",
      identity_status: "resolved",
    });
    expect(merged[0]?.is_identity_finding).toBeUndefined();
  });

  it("표시명과 모델이 같아도 공개 ID가 다른 실기기는 각각 유지한다", () => {
    const first = makeDevice({ device_id: "classroom-tv-1" });
    const second = makeDevice({ device_id: "classroom-tv-2" });

    expect(presentDeviceCollection([first, second], [])).toMatchObject([
      { device_id: "classroom-tv-1", name: first.name, model: first.model },
      { device_id: "classroom-tv-2", name: second.name, model: second.model },
    ]);
  });

  it("서버 선언 개수보다 generic을 제거한 실제 공개 카드 수를 결과 개수로 사용한다", () => {
    const result = presentScanResult({
      ...makeScanResult([]),
      devices_found: 20,
      identity_pending_count: 20,
      identity_research_status: "review_required",
      detected_connections: [makeDetectedConnection()],
    });

    expect(result?.devices_found).toBe(0);
    expect(result?.identity_pending_count).toBe(0);
    expect(result?.devices).toHaveLength(0);
  });

  it("구형 개별 항목 캐시는 제품 카드로 변환하지 않고 폐기한다", () => {
    const legacyResult = {
      scan_id: "scan-neutral-finding",
      status: "completed",
      progress: 100,
      scan_source: "android-native",
      current_step: "점검 완료",
      devices_found: 1,
      high_risk_devices: 0,
      scan_profile: "standard",
      devices: [],
      identity_findings: [
        {
          device_id: "dev-pending-iot",
          identity_status: "enriching",
          display_name: "제품 정보 확인 필요",
          identity_note: "서버가 수집한 단서를 제품 카탈로그와 대조하고 있어요.",
          identity_candidates: [],
          identity_evidence: ["열려 있는 네트워크 서비스"],
          online: true,
          last_seen: "2026-08-16T00:00:00Z",
          risk_level: "yellow",
          risk_summary: "제품 확인 전까지 안전하다고 단정하지 않아요.",
          detected: true,
        },
      ],
      security_score: { score: 90, risk_level: "green" },
    } as ScanResult;

    expect(presentScanResult(legacyResult)).toBeNull();
  });

  it("압축 IPv6와 주소 기반 legacy ID가 들어간 캐시는 기기 자체를 숨긴다", () => {
    for (const deviceId of ["dev-192-168-77-2", "device-fe80::1", "device-2001:db8::1", "device-::1"]) {
      expect(presentDevice(makeDevice({ device_id: deviceId }))).toBeNull();
    }
    // ISO 시간은 IPv6처럼 보일 수 있는 콜론을 포함하지만 주소가 아니므로
    // 확인된 기기의 시간 정보까지 버리면 안 된다.
    expect(presentDevice(makeDevice({ last_seen: "2026-08-13T00:00:00Z" }))?.last_seen).toBe("2026-08-13T00:00:00Z");
  });

  it("알 수 없는 중첩 캐시 payload의 칩셋, OUI, 등록기관, IP, MAC 흔적을 넘기지 않는다", () => {
    const rawDevice = {
      ...makeDevice({
        vulnerabilities: [
          {
            cve_id: "CVE-2026-0001",
            severity: "high",
            summary_ko: "제조사에서 알린 보안 문제입니다.",
            remediation_ko: "제조사 앱에서 업데이트해 주세요.",
            cache_evidence: {
              chipset_name: "RTL8197F",
              oui_owner: "IEEE Registration Authority",
              network: { gateway_ip: "192.168.0.1", mac_address: "AA:BB:CC:DD:EE:FF" },
            },
          },
        ],
      }),
      cache_snapshot: {
        raw_device_name: "Realtek RTL8197F",
        registration_authority: "IEEE Registration Authority",
        ieee_registry: "IEEE",
        oui_prefix: "OUI",
        iana_allocation: "IANA",
        ma_l: "MA-L",
        ma_m: "MA-M",
        ma_s: "MA-S",
        private_registration_authority: "Private 등록기관",
        등록기관: "등록기관",
        source_ip: "192.168.0.10",
        source_mac: "AA:BB:CC:DD:EE:FF",
      },
    } as Device;

    const presented = presentDevice(rawDevice);
    const serialized = JSON.stringify(presented);

    expect(presented).not.toHaveProperty("cache_snapshot");
    expect(presented?.vulnerabilities[0]).not.toHaveProperty("cache_evidence");
    expect(serialized).not.toContain("RTL8197F");
    expect(serialized).not.toContain("IEEE Registration Authority");
    expect(serialized).not.toContain("IEEE");
    expect(serialized).not.toContain("OUI");
    expect(serialized).not.toContain("IANA");
    expect(serialized).not.toContain("MA-L");
    expect(serialized).not.toContain("MA-M");
    expect(serialized).not.toContain("MA-S");
    expect(serialized).not.toContain("등록기관");
    expect(serialized).not.toContain("192.168.0.10");
    expect(serialized).not.toContain("AA:BB:CC:DD:EE:FF");
  });

  it("숨긴 기기는 검사 결과의 기기 수와 위험 기기 수에도 포함하지 않는다", () => {
    const result = presentScanResult(
      makeScanResult([
        makeDevice({ risk_level: "green" }),
        makeDevice({
          device_id: "hidden-red-device",
          name: "알 수 없는 기기",
          canonical_name: "알 수 없는 기기",
          risk_level: "red",
        }),
      ]),
    );

    expect(result).toMatchObject({ devices_found: 1, high_risk_devices: 0 });
    expect(result?.devices).toHaveLength(1);
    expect(result?.devices[0].name).toBe("삼성 냉장고 (RF85C90F1AP)");
    expect(result?.security_score).toMatchObject({ score: null, risk_level: "green" });
    expect(result?.security_score.summary).toBeUndefined();
  });

  it("비제품 신원 근거는 안전한 canonical_name과 함께 남아 있어도 백엔드 기준으로 차단한다", () => {
    const invalidIdentityVariants: Partial<Device>[] = [
      { manufacturer: "Intel Corporation" },
      { model: "Microsoft Surface Hub" },
      { canonical_name: "librespot speaker (P100)" },
      { name: "Spotify speaker (P100)" },
    ];

    for (const [index, invalidIdentity] of invalidIdentityVariants.entries()) {
      expect(presentDevice(makeDevice({ device_id: `non-product-${index}`, ...invalidIdentity }))).toBeNull();
    }
  });

  it("dashboard top-risk의 원시 기기 이름은 모바일 캐시에 남기지 않는다", () => {
    const safeDashboard = makeDashboard({
      home: { home_id: "home-1", name: "우리 집", mode: "home", security_score: 42, device_count: 2 },
      summary: { score: 42, risk_level: "red", online_devices: 2, high_risk_devices: 1, recent_event_count: 3 },
      top_risks: [
        {
          device_id: "safe-risk",
          device_name: "삼성 냉장고 (RF85C90F1AP)",
          risk_level: "red",
          message: "보안 설정을 확인해 주세요.",
        },
      ],
    });
    const cachedDashboard = {
      ...safeDashboard,
      top_risks: [
        ...safeDashboard.top_risks,
        {
          device_id: "unsafe-risk",
          device_name: "Intel Corporation",
          risk_level: "red" as const,
          message: "보안 설정을 확인해 주세요.",
        },
      ],
    };

    expect(presentDashboard(safeDashboard)).toMatchObject({
      home: { security_score: 42, device_count: 2 },
      summary: { score: 42, high_risk_devices: 1 },
      top_risks: [],
    });
    expect(presentDashboard(cachedDashboard)).toBeNull();
  });

  it("dashboard 자동 조사 미완료는 점수만 보류하고 확정된 red 집계는 보존한다", () => {
    const presented = presentDashboard(
      makeDashboard({
        home: { home_id: "home-1", name: "우리 집", mode: "home", security_score: 18, device_count: 3 },
        summary: {
          score: 18,
          risk_level: "red",
          online_devices: 3,
          high_risk_devices: 2,
          recent_event_count: 1,
          identity_pending_count: 1,
          identity_research_status: "review_required",
        },
        identity_pending_count: 1,
        identity_research_status: "review_required",
        identity_findings: [],
      }),
    );

    expect(presented).toMatchObject({
      home: { security_score: 18, identity_pending_count: 1 },
      summary: {
        score: 18,
        risk_level: "red",
        high_risk_devices: 2,
        identity_pending_count: 1,
        identity_research_status: "review_required",
      },
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
    });
  });
});

describe("모바일 캐시 알림 정규화", () => {
  it("금지 기기명이나 칩셋명이 포함된 알림은 표시하지 않는다", () => {
    expect(presentNotification(makeNotification({ message: "웹 관리 기기가 발견되었습니다." }))).toBeNull();
    expect(presentNotification(makeNotification({ title: "Realtek 장치 알림" }))).toBeNull();
    for (const address of ["fe80::1", "2001:db8::1", "::1"]) {
      expect(presentNotification(makeNotification({ message: `주소 ${address}를 확인하세요.` }))).toBeNull();
    }
  });

  it("알림 원문 대신 쉬운 고정 안내만 공개한다", () => {
    const rawTitle = "CVE-2026-9999와 RTSP 설정을 확인하세요.";
    const rawMessage = "HTTP API 포트 8443의 취약점 조치가 필요합니다.";

    expect(
      presentNotification(makeNotification({ title: rawTitle, message: rawMessage, type: "security-alert" })),
    ).toMatchObject({
      title: "바로 확인이 필요해요.",
      message: "보호자와 함께 기기 설정과 업데이트를 확인해 주세요.",
    });
    expect(JSON.stringify(presentNotification(makeNotification({ title: rawTitle, message: rawMessage })))).not.toContain(
      rawTitle,
    );
  });

  it("알림의 알려지지 않은 중첩 cache payload도 공개 객체에 남기지 않는다", () => {
    const notification = presentNotification({
      ...makeNotification(),
      cache_debug: {
        network: { ip_address: "10.0.0.7", mac_address: "AA:BB:CC:DD:EE:FF" },
        chipset: "ESP32",
      },
    } as NotificationItem);

    expect(notification).not.toHaveProperty("cache_debug");
    expect(JSON.stringify(notification)).not.toContain("10.0.0.7");
    expect(JSON.stringify(notification)).not.toContain("ESP32");
  });
});

describe("보호자 공개 데이터 정규화", () => {
  it("보호자 전체 기기 목록은 위험 기기뿐 아니라 green 기기도 유지한다", () => {
    const greenDevice = makeDevice({
      device_id: "guardian-green-device",
      risk_level: "green",
      security_score: 96,
    });
    const redDevice = makeDevice({
      device_id: "guardian-red-device",
      name: "ipTIME 공유기 (AX6000M)",
      canonical_name: "ipTIME 공유기 (AX6000M)",
      device_type: "router",
      manufacturer: "ipTIME",
      model: "AX6000M",
      risk_level: "red",
      security_score: 22,
    });
    const dashboard: GuardianDashboard = {
      invite: { invite_id: "invite-all", email: "guardian@example.com", relation: "보호자", status: "accepted" },
      ward_summary: {
        score: 59,
        risk_level: "red",
        device_count: 2,
        high_risk_devices: 1,
        caution_devices: 0,
        unread_notifications: 0,
      },
      devices: [greenDevice, redDevice],
      high_risk_devices: [redDevice],
      caution_devices: [],
      recent_notifications: [],
      read_only: true,
      scope: "guardian-read-only",
    };

    const presented = presentGuardianDashboard(dashboard);

    expect(presented?.devices?.map((device) => device.device_id)).toEqual([
      greenDevice.device_id,
      redDevice.device_id,
    ]);
    expect(presented?.high_risk_devices.map((device) => device.device_id)).toEqual([redDevice.device_id]);
    expect(presented?.caution_devices).toEqual([]);
    expect(presented?.ward_summary).toMatchObject({ device_count: 2, high_risk_devices: 1 });
  });

  it("보호자 위험 목록에서도 현재 L2 단말을 숨기지 않는다", () => {
    const l2 = makeDetectedConnection({
      device_id: "guardian-l2-device",
      presentation_kind: "observed_connection",
      display_name: "Wi-Fi 단말 · 1A2B3C",
      name: "Wi-Fi 단말 · 1A2B3C",
      device_type: "network",
      observed_service: "neighbor-presence",
      observed_service_verified: true,
      observation_suffix: "1A2B3C",
      observation_suffix_verified: true,
      risk_level: "red",
    }) as unknown as Device;
    const dashboard: GuardianDashboard = {
      invite: { invite_id: "invite-l2", email: "guardian@example.com", relation: "보호자", status: "accepted" },
      ward_summary: {
        score: 42,
        risk_level: "red",
        device_count: 1,
        high_risk_devices: 1,
        caution_devices: 0,
        unread_notifications: 0,
      },
      high_risk_devices: [l2],
      caution_devices: [],
      recent_notifications: [],
      read_only: true,
      scope: "guardian-read-only",
    };

    expect(presentGuardianDashboard(dashboard)).toMatchObject({
      ward_summary: { device_count: 1, high_risk_devices: 1, risk_level: "red" },
      high_risk_devices: [
        { device_id: "guardian-l2-device", name: "Wi-Fi 단말 · 1A2B3C", risk_level: "red" },
      ],
    });
  });

  it("보호자 요약의 기기·알림과 집계에서도 숨긴 신호를 제외한다", () => {
    const dashboard: GuardianDashboard = {
      invite: { invite_id: "invite-1", email: "guardian@example.com", relation: "보호자", status: "accepted" },
      ward_summary: {
        score: 80,
        risk_level: "red",
        device_count: 2,
        high_risk_devices: 2,
        caution_devices: 0,
        unread_notifications: 2,
      },
      high_risk_devices: [
        makeDevice({ risk_level: "red" }),
        makeDevice({ device_id: "hidden", name: "정체불명 기기", canonical_name: "정체불명 기기", risk_level: "red" }),
      ],
      caution_devices: [],
      recent_notifications: [
        makeNotification(),
        makeNotification({ notification_id: "hidden-notice", message: "제조사 미확인 기기 안내" }),
      ],
    read_only: true,
    scope: "guardian-read-only",
  };

    const presented = presentGuardianDashboard(dashboard);

    expect(presented?.high_risk_devices).toHaveLength(1);
    expect(presented?.recent_notifications).toHaveLength(1);
    expect(presented?.ward_summary.high_risk_devices).toBe(1);
    expect(presented?.ward_summary.device_count).toBe(1);
    expect(presented?.ward_summary.score).toBeNull();
    expect(presented?.ward_summary.unread_notifications).toBe(1);
  });

  it("보호자 자동 조사 미완료도 개별 항목 없이 확정된 red 집계를 보존한다", () => {
    const dashboard: GuardianDashboard = {
      invite: { invite_id: "invite-1", email: "guardian@example.com", relation: "보호자", status: "accepted" },
      ward_summary: {
        score: 18,
        risk_level: "red",
        device_count: 3,
        high_risk_devices: 2,
        caution_devices: 0,
        unread_notifications: 0,
        identity_pending_count: 1,
        identity_research_status: "review_required",
      },
      high_risk_devices: [],
      caution_devices: [],
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
      recent_notifications: [],
      read_only: true,
      scope: "guardian-read-only",
    };

    const presented = presentGuardianDashboard(dashboard);

    expect(presented).toMatchObject({
      ward_summary: {
        score: 18,
        risk_level: "red",
        high_risk_devices: 2,
        identity_pending_count: 1,
        identity_research_status: "review_required",
      },
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
    });
    expect(presented?.high_risk_devices).toEqual([]);
  });
});

describe("confirmation-needed cache labels", () => {
  it("excludes the label from device, score, alias, and notification projections", () => {
    const label = "\uD655\uC778 \uD544\uC694 \uAE30\uAE30";
    const canonical = presentDevice(makeDevice());
    const hiddenDevice = presentDevice(makeDevice({ name: label, canonical_name: label }));
    const unsafeAlias = presentDevice(makeDevice({ alias: label }));
    const scan = presentScanResult(
      makeScanResult([
        makeDevice(),
        makeDevice({ device_id: "confirmation-needed", name: label, canonical_name: label, risk_level: "red" }),
      ]),
    );

    expect(canonical).not.toBeNull();
    expect(hiddenDevice).toBeNull();
    expect(unsafeAlias).toMatchObject({
      name: canonical!.canonical_name,
      canonical_name: canonical!.canonical_name,
    });
    expect(unsafeAlias?.alias).toBeUndefined();
    expect(scan).toMatchObject({ devices_found: 1, high_risk_devices: 0 });
    expect(scan?.security_score).toMatchObject({ score: null, risk_level: "green" });
    expect(presentNotification(makeNotification({ message: `${label} needs another check.` }))).toBeNull();
  });

  it.each([
    "TCP 서비스 응답",
    "기기 정보 방송 응답",
    "연결된 장비",
    "현재 Wi-Fi 이웃 확인",
    "알 수 없는 기기",
    "제조사 미확인",
  ])("%s를 카드·별칭·설명·알림·접근성에서 모두 차단한다", (label) => {
    const canonical = presentDevice(makeDevice())!;
    const unsafeAlias = presentDevice(makeDevice({ alias: label }));
    const unsafeCard = presentDevice(
      makeDetectedConnection({ display_name: label, name: label }),
    );
    const safeL2WithUnsafeNote = presentDevice(
      makeDetectedConnection({
        device_id: `safe-l2-${label.length}`,
        display_name: "Wi-Fi 단말 · F0E1D2",
        name: "Wi-Fi 단말 · F0E1D2",
        device_type: "network",
        presentation_kind: "observed_connection",
        observed_service: "neighbor-presence",
        observed_service_verified: true,
        observation_suffix: "F0E1D2",
        observation_suffix_verified: true,
        identity_note: `${label} 상태`,
      }),
    );

    expect(unsafeAlias?.name).toBe(canonical.canonical_name);
    expect(unsafeAlias?.alias).toBeUndefined();
    expect(unsafeCard).toBeNull();
    expect(safeL2WithUnsafeNote?.identity_note).toBe("");
    expect(JSON.stringify(safeL2WithUnsafeNote)).not.toContain(label);
    expect(
      residentDeviceAccessibilityLabel({ name: label, canonical_name: canonical.canonical_name }),
    ).toBe(canonical.canonical_name);
    expect(presentNotification(makeNotification({ message: `${label} 상태` }))).toBeNull();
  });
});
