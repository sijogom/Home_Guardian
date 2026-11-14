import React from "react";
import { StyleSheet } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

let mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1.3 };

jest.mock("react-native/Libraries/Utilities/useWindowDimensions", () => ({
  __esModule: true,
  default: () => mockWindowDimensions,
}));

import { DashboardScreen } from "../src/screens/DashboardScreen";
import { ScanResultScreen } from "../src/screens/ScanResultScreen";

type ScreenActions = {
  navigate: jest.Mock;
  retryScan: jest.Mock;
  startScan: jest.Mock;
  openDevice: jest.Mock;
};

function render(stateOverrides: Record<string, unknown> = {}): { renderer: TestRenderer.ReactTestRenderer; actions: ScreenActions } {
  const actions = {
    navigate: jest.fn(),
    retryScan: jest.fn(),
    startScan: jest.fn(),
    openDevice: jest.fn(),
  };
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <ScanResultScreen
        state={{
          scanResult: null,
          dashboard: null,
          guardians: [],
          devices: [],
          lastScanAt: null,
          statusMessage: "",
          statusTone: "info",
          isLoading: false,
          ...stateOverrides,
        } as never}
        actions={actions as never}
      />,
    );
  });
  return { renderer, actions };
}

function visibleText(renderer: TestRenderer.ReactTestRenderer): string {
  const collect = (node: unknown): string[] => {
    if (typeof node === "string") return [node];
    if (Array.isArray(node)) return node.flatMap(collect);
    if (!node || typeof node !== "object") return [];
    return ((node as { children?: unknown[] }).children ?? []).flatMap(collect);
  };
  return collect(renderer.toJSON()).join(" ");
}

describe("ScanResultScreen pre-scan state", () => {
  it("uses the neutral guidance state before the first scan", () => {
    const { renderer } = render();
    const guidance = renderer.root.findByProps({ testID: "home-status-guidance" });
    const hero = renderer.root.findByProps({ testID: "home-hero-card" });

    expect(String(guidance.props.accessibilityLabel)).toContain("검사 전");
    expect(String(guidance.props.accessibilityLabel)).toContain("검사 시작하기 버튼을 누르세요.");
    expect(renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 검사 전" }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "안심 모드" })).toHaveLength(0);
    expect(StyleSheet.flatten(hero.props.style).backgroundColor).toBe("#FFFFFF");
  });

  it.each([
    [95, "안전"],
    [75, "주의"],
    [45, "위험"],
  ] as const)("announces score %i as %s instead of a fixed safe state", (score, label) => {
    const { renderer } = render({
      scanResult: {
        scan_id: `scan-${label}`,
        status: "completed",
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 0,
        high_risk_devices: label === "위험" ? 1 : 0,
        scan_profile: "standard",
        devices: [],
        security_score: { score, risk_level: label === "안전" ? "green" : label === "주의" ? "yellow" : "red" },
      },
    });

    expect(renderer.root.findAllByProps({ accessibilityLabel: `오늘의 점검 상태: ${label}` }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "안심 모드" })).toHaveLength(0);
  });

  it("starts the existing scan flow from the single primary action", () => {
    const { renderer, actions } = render();
    const action = renderer.root.findByProps({ accessibilityLabel: "내 집 점검하기" });

    act(() => {
      action.props.onPress();
    });

    expect(actions.startScan).toHaveBeenCalledTimes(1);
  });

  it("stacks the score ring and readable copy until the measured summary is wide enough", () => {
    const { renderer } = render({
      scanResult: {
        scan_id: "scan-layout",
        status: "completed",
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 0,
        high_risk_devices: 0,
        scan_profile: "standard",
        devices: [],
        security_score: { score: 92, risk_level: "green" },
      },
    });

    const narrowSummary = renderer.root.findByProps({ testID: "home-score-summary" });
    expect(narrowSummary.props.style).toEqual(
      expect.arrayContaining([expect.objectContaining({ flexDirection: "column" })]),
    );

    act(() => {
      narrowSummary.props.onLayout({ nativeEvent: { layout: { width: 400 } } });
    });

    const wideSummary = renderer.root.findByProps({ testID: "home-score-summary" });
    expect(wideSummary.props.style).toEqual(
      expect.arrayContaining([expect.objectContaining({ flexDirection: "row" })]),
    );
  });

  it("keeps DashboardScreen as the compatible result-screen alias", () => {
    expect(DashboardScreen).toBe(ScanResultScreen);
  });

  it("uses the device-tab list count instead of the larger observed count", () => {
    const listedDevice = {
      device_id: "listed-device",
      name: "ipTIME 공유기 (A3004NS-M)",
      risk_level: "green",
    };
    const wifiFallback = {
      device_id: "wifi-fallback",
      name: "Wi-Fi 단말 · A1B2C3",
      risk_level: "green",
    };
    const { renderer } = render({
      scanResult: {
        scan_id: "scan-visible-count",
        status: "completed",
        progress: 100,
        devices_found: 2,
        high_risk_devices: 0,
        devices: [listedDevice, wifiFallback],
        security_score: { score: 95, score_status: "final", risk_level: "green" },
      },
      devices: [listedDevice, wifiFallback],
    });
    const text = visibleText(renderer);

    expect(text).toContain("확인한 물건 1개");
    expect(text).toMatch(/우리 집 물건\s+1\s*개/u);
    expect(text).not.toContain("확인한 물건 2개");
  });

  it("keeps result, guardian, and verified-risk actions connected", () => {
    const device = {
      device_id: "router-1",
      name: "ipTIME 공유기 (A3004NS-M)",
      canonical_name: "ipTIME 공유기 (A3004NS-M)",
      device_type: "router",
      manufacturer: "ipTIME",
      model: "A3004NS-M",
      online: true,
      last_seen: "2026-08-13T00:00:00Z",
      open_ports: [],
      services: [],
      default_credentials: false,
      encryption: "WPA3",
      firmware: "1.0.0",
      vulnerabilities: [],
      discovery_sources: [],
      fingerprints: [],
      risk_signals: [],
      scan_source: "android-native",
      confidence: 0.99,
      identity_status: "resolved",
      security_score: 48,
      risk_level: "red",
      risk_summary: "",
      recommended_actions: [],
    };
    const { renderer, actions } = render({
      scanResult: {
        scan_id: "scan-1",
        status: "completed",
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 1,
        high_risk_devices: 1,
        scan_profile: "standard",
        devices: [device],
        security_score: { score: 48, risk_level: "red" },
      },
      statusMessage: "점검을 마쳤어요. 먼저 확인할 물건이 있어요.",
      statusTone: "warning",
    });
    const compactRiskCopy = renderer.root.findByProps({ testID: "home-risk-copy" });

    expect(renderer.root.findByProps({ testID: "home-risk-compact-header" })).toBeTruthy();
    expect(StyleSheet.flatten(compactRiskCopy.props.style)).toMatchObject({ flex: 0, width: "100%" });

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "보호자 추가하기" }).props.onPress();
      renderer.root.findByProps({ accessibilityLabel: "다시 점검하기" }).props.onPress();
      renderer.root.findByProps({ testID: "home-risk-router-1" }).props.onPress();
    });

    expect(actions.navigate).toHaveBeenCalledWith("guardian");
    expect(actions.retryScan).toHaveBeenCalledTimes(1);
    expect(actions.openDevice).toHaveBeenCalledWith(device);
  });

  it("labels an incomplete coverage result as partial and withholds a stale score", () => {
    const { renderer, actions } = render({
      scanResult: {
        scan_id: "scan-partial",
        status: "partial",
        scan_complete: false,
        coverage_complete: false,
        tcp_scan_timed_out: true,
        progress: 100,
        scan_source: "android-native",
        current_step: "일부 연결을 다시 확인해 주세요.",
        devices_found: 1,
        identified_count: 1,
        high_risk_devices: 0,
        scan_profile: "quick",
        devices: [],
        security_score: { score: 99, risk_level: "green" },
      },
      statusMessage: "점검 완료: 안전합니다.",
      statusTone: "success",
    });

    const text = visibleText(renderer);
    expect(text).toContain("점검을 일부만 마쳤어요");
    expect(text).toContain("점수를 확정하지 않았어요");
    expect(text).toContain("다시 점검");
    expect(text).not.toContain("점검 완료: 안전합니다.");
    expect(text).not.toContain("99");
    expect(renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 부분 점검" }).length).toBeGreaterThan(0);

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "다시 점검하기" }).props.onPress();
    });
    expect(actions.retryScan).toHaveBeenCalledTimes(1);
  });

  it("keeps a confirmed danger signal red while a partial score remains withheld", () => {
    const { renderer } = render({
      scanResult: {
        scan_id: "scan-partial-red",
        status: "partial",
        scan_complete: false,
        coverage_complete: false,
        tcp_scan_timed_out: true,
        progress: 100,
        scan_source: "android-native",
        current_step: "일부 연결을 다시 확인해 주세요.",
        devices_found: 1,
        identified_count: 1,
        high_risk_devices: 1,
        scan_profile: "quick",
        devices: [],
        security_score: { score: 42, risk_level: "red" },
      },
    });

    const text = visibleText(renderer);
    const guidance = renderer.root.findByProps({ testID: "home-status-guidance" });
    expect(text).toContain("부분 점검 · 위험");
    expect(text).toContain("위험 신호를 찾았어요");
    expect(text).toContain("다시 점검");
    expect(text).not.toContain("42");
    expect(String(guidance.props.accessibilityLabel)).toContain("부분 점검 · 위험");
    expect(renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 부분 점검 · 위험" }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "위험 상태" }).length).toBeGreaterThan(0);
  });

  it("shows a provisional observed score while clearly separating it from the whole-home score", () => {
    const { renderer } = render({
      scanResult: {
        scan_id: "scan-partial-provisional",
        status: "partial",
        scan_complete: false,
        coverage_complete: false,
        progress: 100,
        scan_source: "android-native",
        current_step: "일부 연결을 다시 확인해 주세요.",
        devices_found: 2,
        identified_count: 2,
        high_risk_devices: 0,
        scan_profile: "quick",
        devices: [],
        security_score: { score: 74, score_status: "provisional", risk_level: "yellow" },
      },
    });

    const text = visibleText(renderer);
    expect(text).toContain("74");
    expect(text).toContain("이번에 확인한 연결 기준 점수");
    expect(text).toContain("집 전체 최종 점수가 아니");
    expect(text).toContain("집 전체 점수는 아니므로 다시 점검");
    expect(text).not.toContain("점수를 확정하지 않았어요");
    expect(
      renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 부분 점검 · 확인분 점수" }).length,
    ).toBeGreaterThan(0);
  });

  it("keeps the completed score visible while product-name research continues", () => {
    const { renderer } = render({
      scanResult: {
        scan_id: "scan-research-review",
        status: "completed",
        scan_complete: true,
        coverage_complete: true,
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 1,
        identified_count: 0,
        high_risk_devices: 1,
        identity_pending_count: 1,
        identity_research_status: "review_required",
        identity_findings: [],
        scan_profile: "quick",
        devices: [],
        security_score: { score: 42, risk_level: "red" },
      },
    });

    const text = visibleText(renderer);
    expect(text).toContain("오늘의 점검 · 위험");
    expect(text).toContain("점수와 상태를 함께 보고 다음 행동을 고르세요");
    expect(text).not.toContain("식별 대기");
    expect(text).not.toContain("점수 보류");
    expect(text).not.toContain("제품 정보 자동 확인");
    expect(text).toContain("42");
    expect(renderer.root.findAllByProps({ testID: "identity-findings-section" })).toHaveLength(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 위험" }).length).toBeGreaterThan(0);

    const { renderer: noTargetsRenderer } = render({
      scanResult: {
        scan_id: "scan-no-targets",
        status: "completed",
        scan_complete: true,
        coverage_complete: true,
        progress: 100,
        scan_source: "android-native",
        current_step: "completed",
        devices_found: 0,
        identified_count: 0,
        high_risk_devices: 0,
        scan_profile: "quick",
        devices: [],
        security_score: {
          score: null,
          score_status: "no_targets",
          risk_level: "unknown",
          summary: "점검은 완료됐고, 평가할 네트워크 기기는 확인되지 않았어요.",
        },
      },
      statusMessage: "점검 완료: 평가할 네트워크 기기는 확인되지 않았어요.",
      statusTone: "info",
    });

    const noTargetsText = visibleText(noTargetsRenderer);
    expect(noTargetsText).toContain("점검 완료 · 대상 없음");
    expect(noTargetsText).toContain("이 상태를 안전으로 표시하지 않아요");
    expect(noTargetsText).not.toContain("점검을 일부만 마쳤어요");
    expect(noTargetsText).not.toContain("오늘의 점검 · 안전");
    expect(noTargetsRenderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 점검 완료 · 대상 없음" }).length).toBeGreaterThan(0);
  });
});
