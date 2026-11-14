import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { DeviceDetailScreen } from "../src/screens/DeviceDetailScreen";

function render(): TestRenderer.ReactTestRenderer {
  const device = {
    device_id: "device-1",
    name: "ipTIME 공유기 (A3004NS-M)",
    canonical_name: "ipTIME 공유기 (A3004NS-M)",
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
    identity_status: "resolved",
    security_score: 30,
    risk_level: "red",
    risk_summary: "위험",
    recommended_actions: ["관리자 비밀번호를 바꿔 주세요"],
  };
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <DeviceDetailScreen
        state={{ selectedDevice: device, history: [], screen: "detail", guardianDashboard: null } as never}
        actions={{ goBack: jest.fn(), setScreen: jest.fn(), renameDevice: jest.fn() } as never}
      />,
    );
  });
  return renderer;
}

describe("DeviceDetailScreen checklist accessibility", () => {
  it("labels every checklist control and explains its action", () => {
    const renderer = render();
    const checkboxes = renderer.root.findAllByProps({ accessibilityRole: "checkbox" });

    expect(checkboxes.length).toBeGreaterThan(0);
    checkboxes.forEach((checkbox) => {
      expect(typeof checkbox.props.accessibilityLabel).toBe("string");
      expect(String(checkbox.props.accessibilityLabel).length).toBeGreaterThan(0);
      expect(typeof checkbox.props.accessibilityHint).toBe("string");
      expect(String(checkbox.props.accessibilityHint).length).toBeGreaterThan(0);
    });
  });
});
