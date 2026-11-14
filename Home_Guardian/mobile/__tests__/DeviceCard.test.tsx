import React from "react";
import TestRenderer, { act } from "react-test-renderer";

let mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1 };

jest.mock("react-native/Libraries/Utilities/useWindowDimensions", () => ({
  __esModule: true,
  default: () => mockWindowDimensions,
}));

import { DeviceCard, shouldUseCompactDeviceCardLayout } from "../src/components/DeviceCard";
import type { Device } from "../src/api/types";
import { presentDevice } from "../src/utils/devicePresentation";

function makeDevice(overrides: Partial<Device> = {}): Device {
  return {
    device_id: "dev-1",
    name: "ipTIME 공유기 (A3004NS-M)",
    canonical_name: "ipTIME 공유기 (A3004NS-M)",
    device_type: "router",
    manufacturer: "ipTIME",
    model: "A3004NS-M",
    ip_address: "192.168.0.65",
    mac_address: "UNKNOWN-192.168.0.65",
    online: true,
    last_seen: "",
    open_ports: [445],
    services: ["smb"],
    default_credentials: false,
    encryption: "none",
    firmware: "unknown",
    vulnerabilities: [],
    discovery_sources: ["tcp-port-probe"],
    fingerprints: [],
    risk_signals: [],
    scan_source: "android-native",
    confidence: 0.5,
    identity_status: "resolved",
    security_score: 83,
    risk_level: "yellow",
    risk_summary: "주의",
    recommended_actions: [],
    ...overrides,
  } as Device;
}

function textInTree(json: unknown, text: string): boolean {
  if (json == null) return false;
  if (typeof json === "string") return json.includes(text);
  if (Array.isArray(json)) return json.some((j) => textInTree(j, text));
  if (typeof json === "object") {
    const children = (json as { children?: unknown }).children;
    return textInTree(children, text);
  }
  return false;
}

type JsonNode = {
  type?: string;
  props?: Record<string, unknown>;
  children?: unknown;
};

function findTextNode(json: unknown, text: string): JsonNode | null {
  if (json == null || typeof json !== "object") return null;
  if (Array.isArray(json)) {
    for (const item of json) {
      const found = findTextNode(item, text);
      if (found) return found;
    }
    return null;
  }

  const node = json as JsonNode;
  if (node.type === "Text" && textInTree(node.children, text)) return node;
  return findTextNode(node.children, text);
}

function findButtonNode(json: unknown): JsonNode | null {
  if (json == null || typeof json !== "object") return null;
  if (Array.isArray(json)) {
    for (const item of json) {
      const found = findButtonNode(item);
      if (found) return found;
    }
    return null;
  }

  const node = json as JsonNode;
  if (node.props?.accessibilityRole === "button") return node;
  return findButtonNode(node.children);
}

function flattenStyle(style: unknown): Record<string, unknown> {
  if (!style) return {};
  if (Array.isArray(style)) {
    return style.reduce<Record<string, unknown>>(
      (merged, item) => ({ ...merged, ...flattenStyle(item) }),
      {},
    );
  }
  return typeof style === "object" ? (style as Record<string, unknown>) : {};
}

function render(device: Device): TestRenderer.ReactTestRenderer {
  let renderer!: TestRenderer.ReactTestRenderer;
  act(() => {
    renderer = TestRenderer.create(<DeviceCard device={device} onPress={() => {}} />);
  });
  return renderer;
}

describe("DeviceCard 소형 화면·큰 글자 배치", () => {
  afterEach(() => {
    mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1 };
  });

  it("일반 휴대전화 폭에서는 본문을 전체 폭으로 내리는 compact 배치를 사용한다", () => {
    expect(shouldUseCompactDeviceCardLayout(360, 1)).toBe(true);
    expect(shouldUseCompactDeviceCardLayout(412, 1.3)).toBe(true);
  });

  it("충분히 넓은 태블릿에서는 기존 가로 배치를 유지한다", () => {
    expect(shouldUseCompactDeviceCardLayout(800, 1.3)).toBe(false);
    expect(shouldUseCompactDeviceCardLayout(1024, 1)).toBe(false);
  });

  it("잘못된 화면 배율 입력에도 안전한 기본 배치를 선택한다", () => {
    expect(shouldUseCompactDeviceCardLayout(Number.NaN, Number.NaN)).toBe(false);
    expect(shouldUseCompactDeviceCardLayout(360, 0)).toBe(true);
  });

  it("360dp·130% 글자에서는 실제 본문을 카드 전체 폭의 compact 트리에 둔다", () => {
    mockWindowDimensions = { width: 360, height: 800, scale: 3, fontScale: 1.3 };
    const canonicalName = "ipTIME 공유기 (A3004NS-M)";
    const renderer = render(makeDevice());
    const tree = renderer.toJSON();
    const identity = renderer.root.findByProps({ testID: "device-card-identity" });

    expect(renderer.root.findByProps({ testID: "device-card-compact-layout" })).toBeTruthy();
    expect(() => renderer.root.findByProps({ testID: "device-card-wide-layout" })).toThrow();
    expect(flattenStyle(identity.props.style)).toMatchObject({ flex: 0, width: "100%" });
    expect(findTextNode(tree, canonicalName)?.props?.numberOfLines).toBeUndefined();
  });

  it("800dp·130% 글자에서는 태블릿용 wide 트리를 유지한다", () => {
    mockWindowDimensions = { width: 800, height: 1280, scale: 2, fontScale: 1.3 };
    const device = makeDevice();
    expect(presentDevice(device)).not.toBeNull();
    const renderer = render(device);

    expect(renderer.root.findByProps({ testID: "device-card-wide-layout" })).toBeTruthy();
    expect(() => renderer.root.findByProps({ testID: "device-card-compact-layout" })).toThrow();
  });
});

describe("DeviceCard 오프라인(병합 유지) 표시", () => {
  const OFFLINE_NOTE = "최근 검사에선 안 보였어요";

  it("online=false 면 '최근 검사에선 안 보였어요'를 표시한다(왜 목록에 있는지 설명)", () => {
    const tree = render(makeDevice({ online: false })).toJSON();
    expect(textInTree(tree, OFFLINE_NOTE)).toBe(true);
  });

  it("online=true 면 안내를 표시하지 않는다(현재 검사에서 관측됨)", () => {
    const tree = render(makeDevice({ online: true })).toJSON();
    expect(textInTree(tree, OFFLINE_NOTE)).toBe(false);
  });

  it("기기 이름은 항상 표시한다", () => {
    const tree = render(makeDevice({ name: "ipTIME 공유기 (A3004NS-M)", canonical_name: "ipTIME 공유기 (A3004NS-M)" })).toJSON();
    expect(textInTree(tree, "ipTIME")).toBe(true);
  });

  it("별칭이 있어도 확인된 제품 이름과 긴 품번을 별도로 모두 표시하고 읽어 준다", () => {
    const canonicalName = "삼성 냉장고 (RF85C90F1AP-ABCDEFGHIJKLMN)";
    const device = makeDevice({
        name: canonicalName,
        canonical_name: canonicalName,
        device_type: "refrigerator",
        manufacturer: "삼성",
        model: "RF85C90F1AP-ABCDEFGHIJKLMN",
        alias: "주방 냉장고",
      });
    // Temporary diagnostic for the strict presentation boundary is intentionally
    // kept as an assertion: a verified product must remain displayable.
    expect(presentDevice(device)).not.toBeNull();
    const tree = render(device).toJSON();

    expect(textInTree(tree, "주방 냉장고")).toBe(true);
    expect(textInTree(tree, "확인된 제품 이름과 품번")).toBe(true);
    expect(textInTree(tree, canonicalName)).toBe(true);
    expect(findTextNode(tree, "주방 냉장고")?.props?.numberOfLines).toBeUndefined();
    expect(findTextNode(tree, canonicalName)?.props?.numberOfLines).toBeUndefined();
    expect(String(findButtonNode(tree)?.props?.accessibilityLabel)).toContain(canonicalName);
    expect(String(findButtonNode(tree)?.props?.accessibilityLabel)).toContain("주의");
  });
});

describe("DeviceCard 부분/null 필드 견고성(흰 화면 방지)", () => {
  it("백엔드가 open_ports/services/recommended_actions 를 누락(undefined)해도 크래시하지 않는다", () => {
    // enrich 방어래퍼가 실패 시 필드 없는 기기를 반환할 수 있다 → 모바일이 null-safe 해야 흰 화면 안 남.
    const partial = makeDevice();
    delete (partial as Record<string, unknown>).open_ports;
    delete (partial as Record<string, unknown>).services;
    delete (partial as Record<string, unknown>).recommended_actions;
    const tree = render(partial as Device).toJSON();  // 크래시하면 테스트 실패
    expect(textInTree(tree, partial.name)).toBe(true);  // 기기는 여전히 표시
  });
});

