import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { StudioHero } from "../src/components/StudioPrimitives";

function renderHero(props: Partial<React.ComponentProps<typeof StudioHero>> = {}) {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<StudioHero title="상태 요약" {...props} />);
  });
  return renderer;
}

describe("StudioHero accessibility status", () => {
  it("uses a neutral fallback instead of announcing every hero as safe", () => {
    const renderer = renderHero();

    expect(renderer.root.findAllByProps({ accessibilityLabel: "상태 안내" }).length).toBeGreaterThan(0);
    expect(renderer.root.findAllByProps({ accessibilityLabel: "안심 모드" })).toHaveLength(0);
  });

  it("announces the caller-provided state while preserving the visible eyebrow", () => {
    const renderer = renderHero({
      eyebrow: "오늘의 점검 · 위험",
      statusAccessibilityLabel: "오늘의 점검 상태: 위험",
    });

    expect(renderer.root.findAllByProps({ accessibilityLabel: "오늘의 점검 상태: 위험" }).length).toBeGreaterThan(0);
    expect(JSON.stringify(renderer.toJSON())).toContain("오늘의 점검 · 위험");
  });
});
