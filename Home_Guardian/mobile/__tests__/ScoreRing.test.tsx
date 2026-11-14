import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { ScoreRing } from "../src/components/ScoreRing";

function render(score: number | null): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<ScoreRing score={score} size={150} stroke={14} />);
  });
  return renderer;
}

describe("ScoreRing accessibility", () => {
  it("announces the pre-scan guidance instead of a score when no scan exists", () => {
    const renderer = render(null);
    const rings = renderer.root.findAll(
      (node) => typeof node.props.accessibilityLabel === "string" && node.props.accessibilityLabel.includes("검사 전"),
    );

    expect(rings.length).toBeGreaterThan(0);
    expect(rings.every((ring) => String(ring.props.accessibilityLabel).includes("검사를 시작하면"))).toBe(true);
    expect(JSON.stringify(renderer.toJSON())).toContain("검사 전");
  });

  it("announces an actual security score after a scan", () => {
    const renderer = render(76);
    const rings = renderer.root.findAll(
      (node) => typeof node.props.accessibilityLabel === "string" && node.props.accessibilityLabel.includes("76"),
    );

    expect(rings.length).toBeGreaterThan(0);
    expect(rings.every((ring) => String(ring.props.accessibilityLabel).includes("보안 점수"))).toBe(true);
  });

  it("draws a score-proportional SVG progress arc instead of a categorical border", () => {
    const arc = render(76).root.findAll((node) => typeof node.props.strokeDasharray === "string")[0];

    expect(arc).toBeDefined();
    const circumference = Number(String(arc.props.strokeDasharray).split(" ")[0]);
    expect(Number(arc.props.strokeDashoffset)).toBeCloseTo(circumference * 0.24, 4);
  });

  it("keeps compact visual labels inside the fixed ring canvas at large system text sizes", () => {
    const renderer = render(76);
    const visualLabels = renderer.root.findAll(
      (node) => node.type === "Text" && (node.props.children === 76 || node.props.children === "100점 만점"),
    );
    const fixedCanvas = renderer.root.find(
      (node) => Array.isArray(node.props.style) && JSON.stringify(node.props.style).includes('"height":150'),
    );

    expect(visualLabels).toHaveLength(2);
    expect(visualLabels.every((label) => label.props.numberOfLines === 1)).toBe(true);
    expect(visualLabels.every((label) => label.props.maxFontSizeMultiplier === 1.15)).toBe(true);
    expect(JSON.stringify(fixedCanvas.props.style)).toContain('"width":150');
  });
});
