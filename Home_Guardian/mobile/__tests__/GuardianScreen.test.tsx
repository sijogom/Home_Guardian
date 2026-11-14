import React from "react";
import { StyleSheet, Text } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

jest.mock("@react-native-async-storage/async-storage", () => ({
  __esModule: true,
  default: require("@react-native-async-storage/async-storage/jest/async-storage-mock"),
}));

jest.mock("expo-secure-store", () => ({
  __esModule: true,
  getItemAsync: jest.fn(async () => null),
  setItemAsync: jest.fn(async () => undefined),
  deleteItemAsync: jest.fn(async () => undefined),
}));

import { GuardianScreen } from "../src/screens/GuardianScreen";

const pendingGuardian = {
  invite_id: "invite-1",
  email: "guardian@example.com",
  relation: "가족",
  display_name: "딸",
  short_code: "ABCD-1234",
  deep_link: "homeguardian://join?invite=ABCD-1234",
  status: "pending",
  created_at: "2026-08-13T00:00:00Z",
};

function textInTree(node: unknown): string {
  if (node == null) return "";
  if (typeof node === "string") return node;
  if (Array.isArray(node)) return node.map(textInTree).join("");
  if (typeof node === "object") return textInTree((node as { children?: unknown }).children);
  return "";
}

function render(actions: Record<string, jest.Mock>): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <GuardianScreen
        state={{
          guardianEmail: "new-guardian@example.com",
          guardians: [pendingGuardian],
          isLoading: false,
          statusMessage: "",
          statusTone: "info",
        } as never}
        actions={actions as never}
      />,
    );
  });
  return renderer;
}

describe("GuardianScreen invitation flow", () => {
  it("keeps the invite input, primary creation action, and existing invite status visible", () => {
    const actions = {
      deleteGuardianInvite: jest.fn(),
      inviteGuardian: jest.fn(),
      revokeGuardianInvite: jest.fn(),
      setGuardianEmail: jest.fn(),
    };
    const renderer = render(actions);

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "보호자 이메일" }).props.onChangeText("helper@example.com");
      renderer.root.findByProps({ accessibilityLabel: "초대 링크 만들기" }).props.onPress();
    });

    expect(actions.setGuardianEmail).toHaveBeenCalledWith("helper@example.com");
    expect(actions.inviteGuardian).toHaveBeenCalledTimes(1);
    const screenText = textInTree(renderer.toJSON());
    expect(screenText).toContain("연결됨 0명 · 초대 대기 1명 · 지난 초대 0건");
    expect(screenText).toContain("초대 코드 ABCD-1234");

    const currentInviteCodeLabel = renderer.root
      .findAllByType(Text)
      .find((node) => textInTree(node.props.children) === "현재 초대 코드");
    expect(currentInviteCodeLabel).toBeDefined();
    expect(StyleSheet.flatten(currentInviteCodeLabel?.props.style).color).toBe("#FFFFFF");
  });
});
