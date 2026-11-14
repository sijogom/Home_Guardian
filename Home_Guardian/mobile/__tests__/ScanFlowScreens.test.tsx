import React from "react";
import { StyleSheet } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

import { ScanConsentScreen } from "../src/screens/ScanConsentScreen";
import { ScanProgressScreen } from "../src/screens/ScanProgressScreen";
import { UserLoginScreen } from "../src/screens/UserLoginScreen";

const liveRenderers: TestRenderer.ReactTestRenderer[] = [];

function renderScreen(screen: React.ReactElement): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(screen);
  });
  liveRenderers.push(renderer);
  return renderer;
}

afterEach(() => {
  act(() => {
    liveRenderers.splice(0).forEach((renderer) => renderer.unmount());
  });
});

function visibleText(renderer: TestRenderer.ReactTestRenderer): string[] {
  const collect = (node: unknown): string[] => {
    if (typeof node === "string") return [node];
    if (Array.isArray(node)) return node.flatMap(collect);
    if (!node || typeof node !== "object") return [];
    const children = (node as { children?: unknown[] }).children ?? [];
    return children.flatMap(collect);
  };

  return collect(renderer.toJSON());
}

describe("UserLoginScreen", () => {
  it("makes account preparation visible and prevents an early OAuth action", () => {
    const actions = { goBack: jest.fn(), setScreen: jest.fn(), loginWithGoogle: jest.fn() };
    const renderer = renderScreen(
      <UserLoginScreen
        state={{
          isHydrated: false,
          isLoading: false,
          statusMessage: "",
          statusTone: "info",
        } as never}
        actions={actions as never}
      />,
    );

    const connect = renderer.root.findByProps({ accessibilityLabel: "앱을 준비하고 있어요" });
    expect(connect.props.disabled).toBe(true);
    expect(visibleText(renderer)).toContain("앱을 준비하고 있어요. 잠시만 기다려 주세요.");
  });

  it("keeps the Google login action and exposes its error message", () => {
    const actions = { goBack: jest.fn(), setScreen: jest.fn(), loginWithGoogle: jest.fn() };
    const renderer = renderScreen(
      <UserLoginScreen
        state={{
          isHydrated: true,
          isLoading: false,
          statusMessage: "Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.",
          statusTone: "danger",
        } as never}
        actions={actions as never}
      />,
    );

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "Google 계정으로 계속하기" }).props.onPress();
    });

    expect(actions.loginWithGoogle).toHaveBeenCalledTimes(1);
    expect(visibleText(renderer)).toContain("Google 로그인을 완료하지 못했어요. 잠시 후 다시 시도해 주세요.");
  });

  it("uses the navy hero foreground for the protected-user trust message", () => {
    const renderer = renderScreen(
      <UserLoginScreen
        state={{
          isHydrated: true,
          isLoading: false,
          statusMessage: "",
          statusTone: "info",
        } as never}
        actions={{ goBack: jest.fn(), setScreen: jest.fn(), loginWithGoogle: jest.fn() } as never}
      />,
    );

    const trustCopy = renderer.root.findByProps({ testID: "user-login-trust-copy" });
    expect(StyleSheet.flatten(trustCopy.props.style)?.color).toBe("#FFFFFF");
    expect(renderer.root.findByProps({ testID: "user-login-trust-icon" }).props.color).toBe("#FFFFFF");
  });
});

describe("ScanConsentScreen", () => {
  it("shows preparation before a single scan-start action", () => {
    const actions = { goBack: jest.fn(), setScreen: jest.fn(), beginNetworkScan: jest.fn() };
    const renderer = renderScreen(<ScanConsentScreen actions={actions as never} />);

    const text = visibleText(renderer).join(" ");
    expect(text).toContain("아직 점검하지");
    expect(text).not.toContain("위험해요!");

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "내 집 점검하기" }).props.onPress();
    });
    expect(actions.beginNetworkScan).toHaveBeenCalledTimes(1);
  });
});

describe("ScanProgressScreen", () => {
  const scanUi = {
    progress: 42,
    errorCode: null,
    errorMessage: null,
    nativeMessage: null,
    networkContext: null,
    sourceLabel: "휴대폰으로 검사",
    steps: [
      { key: "wifi", title: "와이파이 확인", detail: "같은 공유기 와이파이를 확인했습니다.", state: "completed" },
      { key: "discovery", title: "물건 확인", detail: "집에 연결된 물건을 찾고 있습니다.", state: "running" },
      { key: "services", title: "상태 확인", detail: "물건별 연결 상태를 확인합니다.", state: "pending" },
      { key: "analysis", title: "안전 확인", detail: "안전 상태를 정리합니다.", state: "pending" },
      { key: "guardian", title: "결과 정리", detail: "결과를 준비합니다.", state: "pending" },
    ],
  };

  it("announces the current simple-language stage and the existing status update", () => {
    const renderer = renderScreen(
      <ScanProgressScreen
        state={{
          scanUi,
          statusMessage: "우리 집 점검을 계속하고 있어요.",
          statusTone: "info",
          isLoading: true,
        } as never}
        actions={{ retryScan: jest.fn() } as never}
      />,
    );

    const text = visibleText(renderer).join(" ");
    expect(text).toContain("2 / 4 단계");
    expect(text).toContain("집에 있는 물건을 찾고 있어요");
    expect(text).toContain("우리 집 점검을 계속하고 있어요.");
    expect(text).not.toContain("mDNS");
  });

  it("stacks the progress ring and copy until the measured hero has enough width", () => {
    const renderer = renderScreen(
      <ScanProgressScreen
        state={{ scanUi, statusMessage: "", statusTone: "info", isLoading: true } as never}
        actions={{ retryScan: jest.fn() } as never}
      />,
    );

    const narrowHero = renderer.root.findByProps({ testID: "scan-progress-hero-top" });
    expect(narrowHero.props.style).toEqual(
      expect.arrayContaining([expect.objectContaining({ flexDirection: "column" })]),
    );

    act(() => {
      narrowHero.props.onLayout({ nativeEvent: { layout: { width: 400 } } });
    });

    const wideHero = renderer.root.findByProps({ testID: "scan-progress-hero-top" });
    expect(wideHero.props.style).toEqual(expect.arrayContaining([expect.objectContaining({ flexDirection: "row" })]));
  });

  it("shows one actionable retry state when the scan fails", () => {
    const actions = { retryScan: jest.fn() };
    const renderer = renderScreen(
      <ScanProgressScreen
        state={{
          scanUi: {
            ...scanUi,
            errorCode: "SCAN_SAVE_FAILED",
            errorMessage: "저장하지 못했어요. 와이파이를 확인한 뒤 다시 시도해 주세요.",
            steps: scanUi.steps.map((step) => (step.key === "discovery" ? { ...step, state: "failed" } : step)),
          },
          statusMessage: "저장하지 못했어요. 와이파이를 확인한 뒤 다시 시도해 주세요.",
          statusTone: "danger",
          isLoading: false,
        } as never}
        actions={actions as never}
      />,
    );

    expect(renderer.root.findAllByProps({ testID: "scan-progress-meter" })).toHaveLength(0);
    expect(visibleText(renderer)).toContain("잠시 멈췄어요");

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "다시 점검하기" }).props.onPress();
    });
    expect(actions.retryScan).toHaveBeenCalledTimes(1);
  });

  it("shows a partial-check state without completion labels when coverage is incomplete", () => {
    const renderer = renderScreen(
      <ScanProgressScreen
        state={{
          scanUi: {
            ...scanUi,
            coverageComplete: false,
            tcpScanTimedOut: true,
          },
          statusMessage: "확인한 결과를 정리하고 있어요.",
          statusTone: "warning",
          isLoading: true,
        } as never}
        actions={{ retryScan: jest.fn() } as never}
      />,
    );

    const text = visibleText(renderer).join(" ");
    expect(text).toContain("일부 연결만 확인했어요");
    expect(text).toContain("확인한 결과는 그대로 보관해요");
    expect(text).not.toContain("개 완료");
    expect(renderer.root.findAllByProps({ testID: "scan-stage-rail" })).toHaveLength(0);
    expect(renderer.root.findAllByProps({ testID: "scan-partial-notice" }).length).toBeGreaterThan(0);
  });

  it("does not turn product-name research into a scan failure or retry state", () => {
    const actions = { retryScan: jest.fn() };
    const renderer = renderScreen(
      <ScanProgressScreen
        state={{
          scanUi: {
            ...scanUi,
            coverageComplete: true,
            identityResearchPending: true,
            confirmedRedRisk: true,
          },
          statusMessage: "식별 대기 중인 연결이 있어요.",
          statusTone: "warning",
          isLoading: false,
        } as never}
        actions={actions as never}
      />,
    );

    const text = visibleText(renderer).join(" ");
    expect(text).toContain("집에 있는 물건을 찾고 있어요");
    expect(text).not.toContain("식별 대기");
    expect(text).not.toContain("점수 보류");
    expect(text).not.toContain("제품 정보 자동 확인");
    expect(text).not.toContain("제품 정보 확인 필요");
    expect(renderer.root.findAllByProps({ testID: "scan-stage-rail" }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ testID: "scan-partial-notice" })).toHaveLength(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "다시 점검하기" })).toHaveLength(0);
    expect(actions.retryScan).not.toHaveBeenCalled();
  });
});
