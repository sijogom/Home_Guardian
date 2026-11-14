import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import type { Device } from "../src/api/types";
import { GuardianModeScreen } from "../src/screens/GuardianModeScreen";

function makeDevice(overrides: Partial<Device> = {}): Device {
  return {
    device_id: "guardian-device",
    name: "삼성 냉장고 (RF85C90F1AP)",
    canonical_name: "삼성 냉장고 (RF85C90F1AP)",
    device_type: "refrigerator",
    manufacturer: "삼성",
    model: "RF85C90F1AP",
    online: true,
    last_seen: "2026-08-29T00:00:00Z",
    open_ports: [],
    services: [],
    default_credentials: false,
    encryption: "",
    firmware: "",
    vulnerabilities: [],
    discovery_sources: [],
    fingerprints: [],
    risk_signals: [],
    scan_source: "android-native",
    confidence: 1,
    security_score: 90,
    risk_level: "green",
    risk_summary: "현재 확인된 위험 신호가 없어요.",
    recommended_actions: [],
    identity_status: "resolved",
    ...overrides,
  };
}

const ward = {
  link_id: "ward-1",
  guardian_id: "guardian-1",
  invite_id: "invite-1",
  home_id: "home-1",
  ward_account_name: "어머니",
  ward_alias: null,
  ward_display_name: "어머니",
  status: "accepted",
  accepted_at: "2026-08-13T00:00:00Z",
  summary: {
    score: 72,
    risk_level: "yellow",
    device_count: 3,
    high_risk_devices: 0,
    caution_devices: 1,
    unread_notifications: 2,
  },
};

function makeActions() {
  return {
    acceptGuardianInvite: jest.fn(() => Promise.resolve()),
    clearGuardianDashboard: jest.fn(),
    exitGuardianMode: jest.fn(),
    goBack: jest.fn(() => false),
    loadGuardianWards: jest.fn(() => Promise.resolve()),
    loginAsGuardianWithGoogle: jest.fn(),
    openDevice: jest.fn(),
    openGuardianWard: jest.fn(() => Promise.resolve()),
    removeGuardianWard: jest.fn(() => Promise.resolve()),
    updateGuardianWardAlias: jest.fn(() => Promise.resolve()),
  };
}

function render(
  actions: ReturnType<typeof makeActions>,
  guardianDashboard: Record<string, unknown> | null,
): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <GuardianModeScreen
        state={{
          guardianDashboard,
          guardianModeInviteCode: "",
          guardianUser: { user_id: "guardian-1" },
          guardianWards: [ward],
          isLoading: false,
          selectedGuardianWardId: ward.link_id,
          statusMessage: "",
          statusTone: "info",
        } as never}
        actions={actions as never}
      />,
    );
  });
  return renderer;
}

describe("GuardianModeScreen read-only and ward flows", () => {
  it("renders every ward device including safe devices and opens the selected card", () => {
    const actions = makeActions();
    const redDevice = makeDevice({
      device_id: "guardian-red-device",
      name: "ipTIME 공유기 (AX6000M)",
      canonical_name: "ipTIME 공유기 (AX6000M)",
      device_type: "router",
      manufacturer: "ipTIME",
      model: "AX6000M",
      risk_level: "red",
      security_score: 22,
      risk_summary: "바로 확인할 보안 신호가 있어요.",
    });
    const greenDevice = makeDevice({
      device_id: "guardian-green-device",
      name: "삼성 냉장고 (RF85C90F1AP)",
      risk_level: "green",
      security_score: 96,
    });
    const renderer = render(actions, {
      devices: [greenDevice, redDevice],
      high_risk_devices: [redDevice],
      caution_devices: [],
      invite: {
        invite_id: "invite-1",
        email: "guardian@example.com",
        relation: "가족",
        status: "accepted",
      },
      read_only: true,
      recent_notifications: [],
      scope: "read_only",
      ward,
      ward_summary: {
        ...ward.summary,
        score: 59,
        risk_level: "red",
        device_count: 2,
        high_risk_devices: 1,
        caution_devices: 0,
      },
    });

    const serialized = JSON.stringify(renderer.toJSON());
    expect(serialized).toContain(redDevice.name);
    expect(serialized).toContain(greenDevice.name);
    expect(renderer.root.findAllByProps({ testID: "guardian-device-list" }).length).toBeGreaterThan(0);

    const greenCard = renderer.root.findAll(
      (node) =>
        node.props.accessibilityRole === "button" &&
        String(node.props.accessibilityLabel ?? "").includes(greenDevice.name),
    )[0];
    expect(greenCard).toBeDefined();
    act(() => {
      greenCard.props.onPress();
    });
    expect(actions.openDevice).toHaveBeenCalledWith(greenDevice);
  });

  it("keeps the dashboard read-only notice and the direct add-person route", () => {
    const actions = makeActions();
    const renderer = render(actions, {
      high_risk_devices: [],
      caution_devices: [],
      invite: {
        invite_id: "invite-1",
        email: "guardian@example.com",
        relation: "가족",
        status: "accepted",
      },
      read_only: true,
      recent_notifications: [],
      scope: "read_only",
      ward,
      ward_summary: ward.summary,
    });

    expect(JSON.stringify(renderer.toJSON())).toContain("보호자는 보기만 할 수 있어요.");
    expect(JSON.stringify(renderer.toJSON())).toContain("선택한 피보호자 · 주의 · 읽기 전용");
    expect(renderer.root.findAllByProps({ accessibilityLabel: "선택한 피보호자 상태: 주의" }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "안심 모드" })).toHaveLength(0);
    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "피보호자 추가하기" }).props.onPress();
    });
    expect(actions.clearGuardianDashboard).toHaveBeenCalledTimes(1);
  });

  it("keeps opening a ward and accepting a normalized invite code", () => {
    const actions = makeActions();
    const renderer = render(actions, null);

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "어머니 보호자 진단 열기" }).props.onPress();
      renderer.root.findByProps({ accessibilityLabel: "초대 코드" }).props.onChangeText("abcd1234");
    });
    expect(actions.openGuardianWard).toHaveBeenCalledWith("ward-1");

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "피보호자 추가" }).props.onPress();
    });
    expect(actions.acceptGuardianInvite).toHaveBeenCalledWith("ABCD-1234");
  });

  it("keeps the ward score and risk visible without an identity retry request", () => {
    const actions = makeActions();
    const renderer = render(actions, {
      high_risk_devices: [],
      caution_devices: [],
      identity_pending_count: 1,
      identity_research_status: "review_required",
      identity_findings: [],
      invite: {
        invite_id: "invite-1",
        email: "guardian@example.com",
        relation: "가족",
        status: "accepted",
      },
      read_only: true,
      recent_notifications: [],
      scope: "read_only",
      ward,
      ward_summary: {
        ...ward.summary,
        score: 18,
        risk_level: "red",
        high_risk_devices: 1,
        identity_pending_count: 1,
        identity_research_status: "review_required",
      },
    });
    const serialized = JSON.stringify(renderer.toJSON());

    expect(serialized).not.toContain("guardian-research-retry");
    expect(serialized).toContain("선택한 피보호자 · 위험 · 읽기 전용");
    expect(serialized).toContain("먼저 확인할 위험 신호가 있어요");
    expect(serialized).toContain("18");
    expect(serialized).not.toContain("식별 대기");
    expect(serialized).not.toContain("점수 보류");
    expect(serialized).not.toContain("제품 정보 자동 확인");
    expect(serialized).not.toContain("추가로 감지된 연결");
    expect(serialized).not.toContain("바로 볼 위험은 없어요");

    const noTargetsRenderer = render(actions, {
      high_risk_devices: [],
      caution_devices: [],
      invite: {
        invite_id: "invite-1",
        email: "guardian@example.com",
        relation: "가족",
        status: "accepted",
      },
      read_only: true,
      recent_notifications: [],
      scope: "read_only",
      ward,
      ward_summary: {
        ...ward.summary,
        score: null,
        score_status: "no_targets",
        risk_level: "unknown",
        device_count: 0,
        high_risk_devices: 0,
        caution_devices: 0,
      },
    });
    const noTargetsSerialized = JSON.stringify(noTargetsRenderer.toJSON());

    expect(noTargetsSerialized).toContain("선택한 피보호자 · 점검 완료 · 대상 없음 · 읽기 전용");
    expect(noTargetsSerialized).toContain("평가할 네트워크 기기가 없어요");
    expect(noTargetsSerialized).toContain("이 상태를 안전으로 판단하지 않아요");
    expect(noTargetsSerialized).not.toContain("선택한 피보호자 · 검사 전 · 읽기 전용");
    expect(noTargetsSerialized).not.toContain("선택한 피보호자 · 안전 · 읽기 전용");
  });
});
