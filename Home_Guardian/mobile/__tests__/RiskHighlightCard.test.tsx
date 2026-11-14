import React from "react";
import { StyleSheet } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

let mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1.3 };

jest.mock("react-native/Libraries/Utilities/useWindowDimensions", () => ({
  __esModule: true,
  default: () => mockWindowDimensions,
}));

import type { Device } from "../src/api/types";
import { RiskHighlightCard } from "../src/components/RiskHighlightCard";

function makeDevice(): Device {
  return {
    device_id: "router-1",
    name: "ipTIME 공유기 (A3004NS-M)",
    canonical_name: "ipTIME 공유기 (A3004NS-M)",
    device_type: "router",
    manufacturer: "ipTIME",
    model: "A3004NS-M",
    ip_address: "192.168.0.1",
    mac_address: "00:11:22:33:44:55",
    online: true,
    last_seen: "2026-08-28T00:00:00Z",
    open_ports: [],
    services: [],
    default_credentials: false,
    encryption: "WPA3",
    firmware: "1.0.0",
    vulnerabilities: [],
    discovery_sources: ["android-native"],
    fingerprints: [],
    risk_signals: [],
    scan_source: "android-native",
    confidence: 0.99,
    identity_status: "resolved",
    security_score: 72,
    risk_level: "yellow",
    risk_summary: "한 번 확인하면 더 안전해져요.",
    recommended_actions: [],
  } as Device;
}

function render(): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<RiskHighlightCard device={makeDevice()} onFix={() => {}} />);
  });
  return renderer;
}

describe("RiskHighlightCard 반응형 배치", () => {
  afterEach(() => {
    mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1.3 };
  });

  it("작은 화면에서는 상태와 제품 설명을 분리해 설명에 전체 폭을 준다", () => {
    const renderer = render();
    const identity = renderer.root.findByProps({ testID: "risk-highlight-identity" });

    expect(renderer.root.findByProps({ testID: "risk-highlight-compact-layout" })).toBeTruthy();
    expect(StyleSheet.flatten(identity.props.style)).toMatchObject({ flex: 0, width: "100%" });
  });

  it("태블릿에서는 기존 가로 배치를 유지한다", () => {
    mockWindowDimensions = { width: 800, height: 1280, scale: 2, fontScale: 1.3 };
    const renderer = render();

    expect(renderer.root.findByProps({ testID: "risk-highlight-wide-layout" })).toBeTruthy();
    expect(() => renderer.root.findByProps({ testID: "risk-highlight-compact-layout" })).toThrow();
  });
});
