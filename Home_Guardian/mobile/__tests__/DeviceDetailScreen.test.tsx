import React from "react";
import TestRenderer, { act } from "react-test-renderer";

import { DeviceDetailScreen } from "../src/screens/DeviceDetailScreen";

function makeDevice(overrides: Record<string, unknown> = {}) {
  return {
    device_id: "dev-1",
    name: "삼성 냉장고 (RF85N9003SL)",
    canonical_name: "삼성 냉장고 (RF85N9003SL)",
    device_type: "fridge",
    manufacturer: "삼성",
    model: "RF85N9003SL",
    ip_address: "192.168.0.5",
    mac_address: "64:1B:2F:FE:00:06",
    online: true,
    last_seen: "",
    open_ports: [8080],
    services: ["http-alt"],
    default_credentials: true,
    encryption: "none",
    firmware: "unknown",
    vulnerabilities: [],
    discovery_sources: ["mdns"],
    fingerprints: [],
    risk_signals: [],
    scan_source: "android-native",
    confidence: 0.8,
    identity_status: "resolved",
    security_score: 55,
    risk_level: "red",
    risk_summary: "위험",
    recommended_actions: ["관리자 비밀번호를 바꿔 주세요"],
    ...overrides,
  };
}

function makeState(device: ReturnType<typeof makeDevice>, readOnly = false) {
  return {
    selectedDevice: device,
    devices: [device],
    history: (readOnly ? ["guardianMode"] : []) as string[],
    screen: "detail",
    guardianDashboard: null,
  };
}

const actions = {
  goBack: () => false,
  setScreen: () => {},
  renameDevice: async () => {},
  retryScan: () => {},
  shareScanWithGuardian: () => {},
};

function renderJson(device: ReturnType<typeof makeDevice>, readOnly = false): string {
  return JSON.stringify(render(device, readOnly).toJSON());
}

function render(device: ReturnType<typeof makeDevice>, readOnly = false): TestRenderer.ReactTestRenderer {
  let tree: TestRenderer.ReactTestRenderer | undefined;
  act(() => {
    tree = TestRenderer.create(
      <DeviceDetailScreen state={makeState(device, readOnly) as never} actions={actions as never} />,
    );
  });
  return tree!;
}

type JsonNode = {
  type?: string;
  props?: Record<string, unknown>;
  children?: unknown;
};

function textInTree(json: unknown, text: string): boolean {
  if (json == null) return false;
  if (typeof json === "string") return json.includes(text);
  if (Array.isArray(json)) return json.some((item) => textInTree(item, text));
  if (typeof json === "object") return textInTree((json as JsonNode).children, text);
  return false;
}

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

describe("DeviceDetailScreen (설치 전 화면 검증)", () => {
  it("제조사·종류·모델코드가 모두 담긴 이름을 표시한다", () => {
    expect(renderJson(makeDevice())).toContain("삼성 냉장고 (RF85N9003SL)");
  });

  it("별칭을 써도 확인된 제품 이름과 긴 품번을 따로 보여 주고 잘라 숨기지 않는다", () => {
    const canonicalName = "삼성 냉장고 (RF85N9003SL-ABCDEFGHIJKLMN)";
    const tree = render(
      makeDevice({
        name: canonicalName,
        canonical_name: canonicalName,
        alias: "주방 냉장고",
        model: "RF85N9003SL-ABCDEFGHIJKLMN",
      }),
    ).toJSON();

    expect(textInTree(tree, "주방 냉장고")).toBe(true);
    expect(textInTree(tree, "확인된 제품 이름과 품번")).toBe(true);
    expect(textInTree(tree, canonicalName)).toBe(true);
    expect(findTextNode(tree, "주방 냉장고")?.props?.numberOfLines).toBeUndefined();
    expect(findTextNode(tree, canonicalName)?.props?.numberOfLines).toBeUndefined();
    expect(JSON.stringify(tree)).toContain(`확인된 제품 이름과 품번: ${canonicalName}`);
  });

  it("일반 사용자 화면에는 서버의 기술적인 취약점·조치 원문을 그대로 보여 주지 않는다", () => {
    const rawVulnerability = "CVE-2026-9999 RTSP API 설정을 바꾸세요";
    const rawRemediation = "HTTP API에서 포트 8443 설정을 바꾸세요";
    const rawAction = "UPnP와 RTSP API를 확인하세요";
    const json = renderJson(
      makeDevice({
        vulnerabilities: [
          {
            cve_id: "CVE-2026-9999",
            severity: "high",
            summary_ko: rawVulnerability,
            remediation_ko: rawRemediation,
          },
        ],
        recommended_actions: [rawAction],
      }),
    );

    expect(json).not.toContain(rawVulnerability);
    expect(json).not.toContain(rawRemediation);
    expect(json).not.toContain(rawAction);
    expect(json).toContain("제조사에서 알린 보안 문제가 있어요. 바로 확인해 주세요.");
    expect(json).toContain("보호자에게 이 화면을 보여 주세요.");
  });

  it("보호자 읽기 전용 화면도 서버의 기술적인 취약점·조치 원문을 그대로 보여 주지 않는다", () => {
    const rawVulnerability = "CVE-2026-9999 RTSP API 설정을 바꾸세요";
    const rawRemediation = "HTTP API에서 포트 8443 설정을 바꾸세요";
    const rawAction = "UPnP와 RTSP API를 확인하세요";
    const json = renderJson(
      makeDevice({
        vulnerabilities: [
          {
            cve_id: "CVE-2026-9999",
            severity: "high",
            summary_ko: rawVulnerability,
            remediation_ko: rawRemediation,
          },
        ],
        recommended_actions: [rawAction],
      }),
      true,
    );

    expect(json).not.toContain(rawVulnerability);
    expect(json).not.toContain(rawRemediation);
    expect(json).not.toContain(rawAction);
    expect(json).toContain("제조사에서 알린 보안 문제가 있어 바로 확인이 필요합니다.");
    expect(json).toContain("사용자에게 이 화면을 보여 주고 함께 확인해 주세요.");
  });

  it("이름 바꾸기 버튼과 위험 기기 차단 안내를 표시한다", () => {
    const json = renderJson(makeDevice());
    expect(json).toContain("이름 바꾸기");
    expect(json).toContain("이 기기를 차단하려면");
  });

  it("조치 안내(체크리스트)가 깨지지 않고 렌더된다", () => {
    const json = renderJson(makeDevice());
    expect(json).toContain("지금 할 수 있는 일");
    expect(json).toContain("보호자에게 이 화면을 보여 주세요.");
  });
});
