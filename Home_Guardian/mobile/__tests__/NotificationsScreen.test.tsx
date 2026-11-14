import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import type { HomeGuardianActions, HomeGuardianState } from "../src/state/useHomeGuardianController";
import { NotificationsScreen } from "../src/screens/NotificationsScreen";
import { residentNotificationTime } from "../src/utils/devicePresentation";

function textInTree(node: unknown, expected: string): boolean {
  if (node == null) return false;
  if (typeof node === "string") return node.includes(expected);
  if (Array.isArray(node)) return node.some((child) => textInTree(child, expected));
  if (typeof node === "object") {
    return textInTree((node as { children?: unknown }).children, expected);
  }
  return false;
}

function stateWithNotification(createdAt: string): HomeGuardianState {
  return {
    notifications: [
      {
        notification_id: "notice-1",
        type: "security",
        title: "바로 확인이 필요해요.",
        message: "기기 설정을 확인해 주세요.",
        read: false,
        created_at: createdAt,
      },
    ],
  } as unknown as HomeGuardianState;
}

const actions = {
  markNotificationRead: jest.fn(),
} as unknown as HomeGuardianActions;

function render(createdAt: string): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<NotificationsScreen state={stateWithNotification(createdAt)} actions={actions} />);
  });
  return renderer;
}

describe("NotificationsScreen notification time presentation", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders the central Korean timestamp and never the raw ISO string", () => {
    const rawTimestamp = "2026-08-13T00:05:00Z";
    const tree = render(rawTimestamp).toJSON();

    expect(textInTree(tree, residentNotificationTime(rawTimestamp))).toBe(true);
    expect(textInTree(tree, rawTimestamp)).toBe(false);
  });

  it("renders the friendly fallback for an invalid timestamp", () => {
    const tree = render("not-a-date").toJSON();

    expect(textInTree(tree, "시간을 확인할 수 없어요.")).toBe(true);
    expect(textInTree(tree, "not-a-date")).toBe(false);
  });
});
