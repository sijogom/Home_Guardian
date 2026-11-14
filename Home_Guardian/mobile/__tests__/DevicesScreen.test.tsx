import React from "react";
import { StyleSheet } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

import type { Device } from "../src/api/types";
import { DevicesScreen } from "../src/screens/DevicesScreen";

const highRiskDevice: Device = {
  device_id: "device-1",
  name: "공유기(A3004NS-M)",
  canonical_name: "공유기(A3004NS-M)",
  device_type: "router",
  manufacturer: "ipTIME",
  model: "A3004NS-M",
  ip_address: "192.168.0.1",
  mac_address: "00:11:22:33:44:55",
  online: true,
  last_seen: "",
  open_ports: [],
  services: [],
  default_credentials: false,
  encryption: "unknown",
  firmware: "unknown",
  vulnerabilities: [],
  discovery_sources: [],
  fingerprints: [],
  risk_signals: [],
  scan_source: "android-native",
  confidence: 1,
  security_score: 30,
  risk_level: "red",
  risk_summary: "위험",
  recommended_actions: [],
};

const detectedConnection: Device = {
  ...highRiskDevice,
  device_id: "detected-connection-1",
  name: "ASRock 컴퓨터 - testpc",
  canonical_name: "ASRock 컴퓨터 - testpc",
  device_type: "computer",
  manufacturer: "ASRock",
  model: "",
  ip_address: "",
  mac_address: "",
  risk_level: "yellow",
  risk_summary: "",
  identity_status: "unresolved",
  identity_evidence: ["서버에 저장된 식별 정보"],
  identity_family_verified: true,
  presentation_kind: "observed_connection",
  observed_type_verified: true,
  observed_host_name: "testpc",
  host_name_verified: true,
  is_identity_finding: true,
};

function render(stateOverrides: Record<string, unknown> = {}): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <DevicesScreen
        state={{ devices: [highRiskDevice], ...stateOverrides } as never}
        actions={{ startScan: jest.fn(), openDevice: jest.fn() } as never}
      />,
    );
  });
  return renderer;
}

describe("DevicesScreen traffic-light presentation", () => {
  it("presents a high-risk count with a restrained red status marker", () => {
    const renderer = render();
    const warning = renderer.root.findByProps({ testID: "high-risk-warning" });
    const statusIcon = renderer.root.findByProps({ testID: "high-risk-status-icon" });
    const statusIconStyle = StyleSheet.flatten(statusIcon.props.style);

    expect(String(warning.props.accessibilityLabel)).toContain("위험 기기 1개");
    expect(statusIconStyle.backgroundColor).toBe("#FFF1F1");
  });

  it("keeps the ordinary device-list hero card white in the default light theme", () => {
    const renderer = render();
    const hero = renderer.root.findByProps({ testID: "devices-hero-card" });

    expect(StyleSheet.flatten(hero.props.style).backgroundColor).toBe("#FFFFFF");
  });

  it("shows an evidence-backed observed computer without turning it into a retry notice", () => {
    const renderer = render({
      devices: [highRiskDevice, detectedConnection],
      scanResult: {
        identity_pending_count: 2,
        identity_research_status: "review_required",
        identity_findings: [],
      },
    });
    const serialized = JSON.stringify(renderer.toJSON());

    expect(serialized).not.toContain("devices-research-retry");
    expect(serialized).toContain("감지된 연결 2개 · 제품명 확인 1개");
    expect(serialized).toContain("ASRock 컴퓨터 - testpc");
    expect(serialized).not.toContain("식별 대기");
    expect(serialized).not.toContain("점수 보류");
    expect(serialized).not.toContain("제품 정보 자동 확인");
    expect(serialized).not.toContain("추가로 감지된 연결");
  });

  it("counts only the devices that the device tab actually lists", () => {
    const renderer = render({
      devices: [
        highRiskDevice,
        {
          ...detectedConnection,
          device_id: "wifi-fallback-1",
          name: "Wi-Fi 단말 · A1B2C3",
          canonical_name: "Wi-Fi 단말 · A1B2C3",
        },
      ],
    });
    const serialized = JSON.stringify(renderer.toJSON());

    expect(serialized).toContain("감지된 연결 1개 · 제품명 확인 1개");
    expect(serialized).not.toContain("Wi-Fi 단말 · A1B2C3");
  });
});
