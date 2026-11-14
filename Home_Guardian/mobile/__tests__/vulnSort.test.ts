import { confirmedVulnerabilities } from "../src/utils/riskCopy";
import type { Device } from "../src/api/types";

function dev(vulns: any[]): Device {
  return {
    device_id: "d", name: "x", device_type: "camera", manufacturer: "x", model: "x",
    ip_address: "192.168.0.9", mac_address: "UNKNOWN-9", open_ports: [], services: [],
    discovery_sources: ["mdns"], fingerprints: [], risk_level: "red", score: 40,
    summary: "", reasons: [], recommended_actions: [], vulnerabilities: vulns,
  } as unknown as Device;
}

describe("confirmedVulnerabilities 정렬", () => {
  it("심각도 높은 순(critical→high→medium)으로 정렬해 slice(0,4)에서 critical 이 안 밀린다", () => {
    const v = confirmedVulnerabilities(
      dev([
        { cve_id: "CVE-m1", severity: "medium" },
        { cve_id: "CVE-m2", severity: "medium" },
        { cve_id: "CVE-m3", severity: "medium" },
        { cve_id: "CVE-m4", severity: "medium" },
        { cve_id: "CVE-crit", severity: "critical" },
      ]),
    );
    expect(v[0].cve_id).toBe("CVE-crit"); // 가장 심각한 것이 맨 앞
    expect(v.slice(0, 4).map((x) => x.cve_id)).toContain("CVE-crit"); // 상세 목록에 포함
  });
});
