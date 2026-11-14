import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { BottomTabBar } from "../src/components/BottomTabBar";

function render(): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<BottomTabBar active="devices" onChange={() => {}} />);
  });
  return renderer;
}

describe("BottomTabBar accessibility", () => {
  it("uses an Android-supported role for the tab container", () => {
    const root = render().root;

    expect(root.findAll((node) => node.props.accessibilityRole === "toolbar").length).toBeGreaterThanOrEqual(1);
    expect(root.findAll((node) => node.props.accessibilityRole === "tabbar")).toHaveLength(0);
  });

  it("marks exactly the active tab as selected", () => {
    const tabs = render().root.findAll((node) => node.props.accessibilityRole === "tab");
    const selected = tabs.filter((tab) => tab.props.accessibilityState?.selected === true);
    const selectedLabels = [...new Set(selected.map((button) => button.props.accessibilityLabel))];

    expect(selectedLabels).toEqual(["기기"]);
  });

  it("announces unread alerts without enlarging the visual tab badge", () => {
    let renderer!: TestRenderer.ReactTestRenderer;
    act(() => {
      renderer = TestRenderer.create(<BottomTabBar active="home" onChange={() => {}} unreadAlerts={12} />);
    });

    const alertsTab = renderer.root.findAll((node) => node.props.accessibilityRole === "tab").find(
      (tab) => tab.props.accessibilityLabel === "알림, 읽지 않은 알림 12개",
    );
    expect(alertsTab).toBeDefined();
  });
});
