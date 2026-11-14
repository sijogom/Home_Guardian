import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { TextField } from "../src/components/TextField";

type JsonNode = {
  type?: string;
  props?: Record<string, unknown>;
  children?: unknown;
};

function findTextInput(json: unknown): JsonNode | null {
  if (json == null || typeof json !== "object") return null;
  if (Array.isArray(json)) {
    for (const item of json) {
      const found = findTextInput(item);
      if (found) return found;
    }
    return null;
  }

  const node = json as JsonNode;
  if (node.type === "TextInput") return node;
  return findTextInput(node.children);
}

function renderTextField(
  props: Pick<React.ComponentProps<typeof TextField>, "label" | "helper" | "accessibilityLabel" | "accessibilityHint">,
): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(
      <TextField
        label={props.label}
        value=""
        onChangeText={() => {}}
        helper={props.helper}
        accessibilityLabel={props.accessibilityLabel}
        accessibilityHint={props.accessibilityHint}
      />,
    );
  });
  return renderer;
}

describe("TextField accessibility", () => {
  it("uses its visible label and helper as programmatic input context", () => {
    const input = findTextInput(
      renderTextField({
        label: "보호자 이메일",
        helper: "초대할 보호자의 이메일 주소를 입력하세요.",
      }).toJSON(),
    );

    expect(input?.props?.accessibilityLabel).toBe("보호자 이메일");
    expect(input?.props?.accessibilityHint).toBe("초대할 보호자의 이메일 주소를 입력하세요.");
  });

  it("allows a specific label and hint while retaining a non-empty fallback hint", () => {
    const overrideInput = findTextInput(
      renderTextField({
        label: "검색",
        accessibilityLabel: "보호자 검색",
        accessibilityHint: "이메일 또는 초대 코드로 보호자를 찾으세요.",
      }).toJSON(),
    );
    const fallbackInput = findTextInput(renderTextField({ label: "목록 이름" }).toJSON());

    expect(overrideInput?.props?.accessibilityLabel).toBe("보호자 검색");
    expect(overrideInput?.props?.accessibilityHint).toBe("이메일 또는 초대 코드로 보호자를 찾으세요.");
    expect(fallbackInput?.props?.accessibilityHint).toBe("내용을 입력하세요.");
  });
});
