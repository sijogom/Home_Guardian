import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { LoginScreen } from "../src/screens/LoginScreen";

function render() {
  const actions = {
    navigate: jest.fn(),
    enterGuardianMode: jest.fn(),
  };
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <LoginScreen
        state={{ isHydrated: true } as never}
        actions={actions as never}
      />,
    );
  });
  return { renderer, actions };
}

function renderedText(renderer: TestRenderer.ReactTestRenderer): string {
  return JSON.stringify(renderer.toJSON());
}

describe("LoginScreen visual role hierarchy", () => {
  it("sends the user role to account connection before scan", () => {
    const { renderer, actions } = render();

    act(() => {
      renderer.root.findByProps({ accessibilityLabel: "내 집 점검하기" }).props.onPress();
    });

    expect(actions.navigate).toHaveBeenCalledWith("userLogin");
    expect(renderedText(renderer)).toContain("내 집 점검");
  });

  it("keeps role choice neutral instead of showing a false pre-scan danger state", () => {
    const { renderer } = render();
    const text = renderedText(renderer);

    expect(text).not.toContain("위험해요!");
    expect(text).toContain("어떤 도움을");
  });
});
