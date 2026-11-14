import React from "react";
import { StyleSheet, Text } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

import { ProfileScreen } from "../src/screens/ProfileScreen";
import { ThemeProvider } from "../src/theme";

const profileState = {
  user: null,
  dashboard: null,
  guardians: [],
  statusMessage: "",
  statusTone: "info",
  isLoading: false,
  notificationsEnabled: false,
  autoScanEnabled: false,
  autoScanIntervalHours: 24,
} as never;

const profileActions = (logout: jest.Mock = jest.fn()) =>
  ({
    setNotificationsEnabled: jest.fn(),
    setAutoScanEnabled: jest.fn(),
    setAutoScanIntervalHours: jest.fn(),
    logout,
  }) as never;

function render(logout: jest.Mock = jest.fn()): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <ProfileScreen
        state={profileState}
        actions={profileActions(logout)}
      />,
    );
  });
  return renderer;
}

describe("ProfileScreen switch accessibility", () => {
  it("gives every notification switch an understandable label and hint", () => {
    const renderer = render();
    const switches = renderer.root.findAllByProps({ accessibilityRole: "switch" });

    expect(switches.length).toBeGreaterThanOrEqual(2);
    switches.forEach((toggle) => {
      expect(typeof toggle.props.accessibilityLabel).toBe("string");
      expect(String(toggle.props.accessibilityLabel).length).toBeGreaterThan(0);
      expect(typeof toggle.props.accessibilityHint).toBe("string");
      expect(String(toggle.props.accessibilityHint).length).toBeGreaterThan(0);
    });
    expect(new Set(switches.map((toggle) => String(toggle.props.accessibilityLabel)))).toEqual(
      new Set(["위험 알림 받기", "정기 점검 알림 켜기"]),
    );
  });

  it("shows immediate progress and blocks duplicate presses while logout is running", async () => {
    let resolveLogout!: () => void;
    const logout = jest.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveLogout = resolve;
        }),
    );
    const renderer = render(logout);
    const logoutButton = renderer.root.findByProps({ accessibilityLabel: "로그아웃" });

    await act(async () => {
      logoutButton.props.onPress();
    });

    expect(logout).toHaveBeenCalledTimes(1);
    expect(renderer.root.findByProps({ accessibilityLabel: "로그아웃" }).props.accessibilityState).toEqual({
      busy: true,
      disabled: true,
    });
    expect(renderer.root.findAllByProps({ children: "로그아웃하는 중…" }).length).toBeGreaterThan(0);

    await act(async () => {
      resolveLogout();
      await Promise.resolve();
    });

    expect(renderer.root.findByProps({ accessibilityLabel: "로그아웃" }).props.accessibilityState).toEqual({
      busy: false,
      disabled: false,
    });
  });

  it("remounts off-screen settings content and refreshes every palette value after light-dark-light", async () => {
    let renderer!: TestRenderer.ReactTestRenderer;
    await act(async () => {
      renderer = TestRenderer.create(
        <ThemeProvider>
          <ProfileScreen state={profileState} actions={profileActions()} />
        </ThemeProvider>,
      );
      await Promise.resolve();
      await Promise.resolve();
    });

    const readPalette = () => {
      const systemOption = renderer.root.findByProps({ accessibilityLabel: "휴대전화 설정 화면" });
      const logout = renderer.root.findByProps({ accessibilityLabel: "로그아웃" });
      const systemTitle = systemOption.findAll(
        (node) => node.type === Text && node.props.children === "휴대전화 설정",
      )[0];
      const systemDescription = systemOption.findAll(
        (node) => node.type === Text && node.props.children === "휴대전화 화면 설정을 따라가요.",
      )[0];
      const logoutTitle = logout.findAll((node) => node.type === Text && node.props.children === "로그아웃")[0];
      const logoutHelper = logout.findAll(
        (node) => node.type === Text && node.props.children === "이 기기에서 내 계정으로 다시 로그인할 수 있어요.",
      )[0];
      const iconColors = [
        ...systemOption.findAll((node) => typeof node.props.color === "string").map((node) => node.props.color),
        ...logout.findAll((node) => typeof node.props.color === "string").map((node) => node.props.color),
      ];
      return {
        systemBackground: StyleSheet.flatten(systemOption.props.style({ pressed: false })).backgroundColor,
        systemTitle: StyleSheet.flatten(systemTitle.props.style).color,
        systemDescription: StyleSheet.flatten(systemDescription.props.style).color,
        logoutBackground: StyleSheet.flatten(logout.props.style({ pressed: false })).backgroundColor,
        logoutTitle: StyleSheet.flatten(logoutTitle.props.style).color,
        logoutHelper: StyleSheet.flatten(logoutHelper.props.style).color,
        iconColors,
      };
    };

    const initialBoundary = renderer.root.findByProps({ testID: "profile-theme-boundary" });
    const initialLight = readPalette();
    expect(initialLight).toMatchObject({
      systemBackground: "#FFFFFF",
      systemTitle: "#101828",
      systemDescription: "#526277",
      logoutBackground: "#FFFFFF",
      logoutTitle: "#AB2E34",
      logoutHelper: "#101828",
    });
    expect(initialLight.iconColors).toEqual(expect.arrayContaining(["#526277", "#AB2E34"]));

    await act(async () => {
      renderer.root.findByProps({ accessibilityLabel: "어둡게 보기 화면" }).props.onPress();
      await Promise.resolve();
    });
    const darkBoundary = renderer.root.findByProps({ testID: "profile-theme-boundary" });
    expect(darkBoundary).not.toBe(initialBoundary);
    expect(renderer.root.findByProps({ accessibilityLabel: "어둡게 보기 화면" }).props.accessibilityState).toEqual({
      selected: true,
    });
    expect(readPalette()).toMatchObject({
      systemBackground: "#151E2A",
      systemTitle: "#F4F7FB",
      systemDescription: "#C5D0DD",
      logoutBackground: "#151E2A",
      logoutTitle: "#F3ADB1",
      logoutHelper: "#F4F7FB",
    });

    await act(async () => {
      renderer.root.findByProps({ accessibilityLabel: "밝게 보기 화면" }).props.onPress();
      await Promise.resolve();
    });
    expect(renderer.root.findByProps({ testID: "profile-theme-boundary" })).not.toBe(darkBoundary);
    expect(renderer.root.findByProps({ accessibilityLabel: "밝게 보기 화면" }).props.accessibilityState).toEqual({
      selected: true,
    });
    expect(readPalette()).toEqual(initialLight);
  });
});
