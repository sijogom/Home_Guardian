import type { ScanResult } from "../src/api/types";
import { presentScanResult } from "../src/utils/devicePresentation";
import {
  deviceCacheAfterScan,
  hasConfirmedRedRisk,
  identityResearchState,
  scanCoverageState,
  scanIncompleteMessage,
} from "../src/utils/scanCoverage";

function result(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scan_id: "scan-coverage",
    status: "completed",
    progress: 100,
    scan_source: "android-native",
    current_step: "completed",
    devices_found: 0,
    high_risk_devices: 0,
    identity_pending_count: 0,
    identity_research_status: "complete",
    identity_findings: [],
    scan_profile: "quick",
    devices: [],
    security_score: { score: 95, risk_level: "green" },
    ...overrides,
  };
}

describe("scanCoverageState", () => {
  it("treats new server partial status and scan_complete=false as partial", () => {
    expect(scanCoverageState({ status: "partial", scan_complete: false })).toEqual({
      coverageComplete: false,
      tcpScanTimedOut: false,
      isPartial: true,
    });
  });

  it("supports legacy native coverage and timeout diagnostics", () => {
    expect(
      scanCoverageState({
        network_context: {
          scan_diagnostics: {
            candidate_coverage_complete: false,
            tcp_scan_timed_out: true,
          },
        },
      }),
    ).toEqual({ coverageComplete: false, tcpScanTimedOut: true, isPartial: true });
  });

  it("accepts the server endpoint quarantine diagnostic without changing coverage", () => {
    expect(
      scanCoverageState({
        network_context: {
          scan_diagnostics: {
            coverage_complete: true,
            endpoint_evidence_quarantined: 2,
          },
        },
      }),
    ).toEqual({ coverageComplete: true, tcpScanTimedOut: false, isPartial: false });
  });

  it("lets an incomplete signal win over a complete signal", () => {
    expect(
      scanCoverageState(
        { coverage_complete: true },
        { network_context: { scan_diagnostics: { candidate_coverage_complete: false } } },
      ).isPartial,
    ).toBe(true);
  });

  it("holds coverage for actual execution loss, timeout-independent capacity loss, or Wi-Fi binding", () => {
    const diagnosticsCases = [
      { coverage_complete: true, candidate_stimulation_complete: false },
      { coverage_complete: true, tcp_transport_complete: false },
      { coverage_complete: true, wifi_network_socket_binding_complete: false },
      { coverage_complete: true, scan_partial: true },
      { coverage_complete: true, observation_limit_reached: true },
      { coverage_complete: true, observation_overflow_events: 1 },
      { coverage_complete: true, observation_hosts_dropped: 1 },
      { coverage_complete: true, observation_hosts_evicted: 1 },
      { coverage_complete: true, observation_receive_buffer_dropped: 1 },
    ];

    diagnosticsCases.forEach((scan_diagnostics) => {
      expect(scanCoverageState({ network_context: { scan_diagnostics } })).toEqual({
        coverageComplete: false,
        tcpScanTimedOut: false,
        isPartial: true,
      });
    });
  });

  it("treats unavailable Android neighbour tables as diagnostics when the scan itself completed", () => {
    const source = {
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      network_context: {
        scan_diagnostics: {
          coverage_complete: true,
          candidate_coverage_complete: true,
          candidate_stimulation_complete: true,
          tcp_transport_complete: true,
          wifi_network_socket_binding_complete: true,
          tcp_scan_timed_out: false,
          scan_partial: false,
          neighbor_proc_source_available_before: false,
          neighbor_ip_source_available_before: false,
          neighbor_source_available_before: false,
          neighbor_proc_source_available_after: false,
          neighbor_ip_source_available_after: false,
          neighbor_source_available_after: false,
          neighbor_probe_complete: false,
          neighbor_presence_confirmed: false,
          neighbor_coverage_complete: false,
          arp_entries_before_probe: 0,
          arp_entries_after_probe: 0,
          arp_stale_entries_suppressed: 1,
          neighbor_unverified_hosts: 1,
        },
      },
    };

    expect(scanCoverageState(source)).toEqual({
      coverageComplete: true,
      tcpScanTimedOut: false,
      isPartial: false,
    });
  });

  it("does not infer partial coverage from neighbour diagnostics alone", () => {
    expect(
      scanCoverageState({
        scan_diagnostics: {
          neighbor_source_available_before: false,
          neighbor_source_available_after: false,
          neighbor_probe_complete: false,
          neighbor_presence_confirmed: false,
          neighbor_coverage_complete: false,
          arp_entries_before_probe: 0,
          arp_entries_after_probe: 0,
        },
      }),
    ).toEqual({ coverageComplete: null, tcpScanTimedOut: false, isPartial: false });
  });

  it("does not promote one successful coverage component into a complete scan", () => {
    expect(
      scanCoverageState({
        network_context: {
          scan_diagnostics: {
            candidate_stimulation_complete: true,
            neighbor_probe_complete: true,
            tcp_transport_complete: true,
            wifi_network_socket_binding_complete: true,
          },
        },
      }),
    ).toEqual({ coverageComplete: null, tcpScanTimedOut: false, isPartial: false });
  });

  it("keeps physical coverage complete while product identity research is pending", () => {
    const source = {
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      identity_pending_count: 2,
      identity_research_status: "review_required" as const,
    };

    expect(identityResearchState(source)).toEqual({
      status: "review_required",
      pendingCount: 2,
      isIncomplete: true,
      hasExplicitContract: true,
    });
    expect(scanCoverageState(source)).toEqual({
      coverageComplete: true,
      tcpScanTimedOut: false,
      isPartial: false,
    });
  });

  it("drops Wi-Fi A devices when a partial attempt now observes Wi-Fi B", () => {
    const wifiADevices = [{ device_id: "wifi-a-router" }, { device_id: "wifi-a-fridge" }];
    const wifiBPartialDevices = [{ device_id: "wifi-b-router" }];

    const nextCache = deviceCacheAfterScan(wifiBPartialDevices);

    expect(nextCache).toBe(wifiBPartialDevices);
    expect(nextCache).not.toEqual(expect.arrayContaining(wifiADevices));
  });

  it("drops old-only same-Wi-Fi devices after a partial current observation", () => {
    const previousComplete = [
      { device_id: "same-wifi-router", last_seen: "old" },
      { device_id: "same-wifi-old-only-camera", last_seen: "old" },
    ];
    const currentPartial = [{ device_id: "same-wifi-router", last_seen: "current" }];

    const nextCache = deviceCacheAfterScan(currentPartial);

    expect(nextCache).toEqual(currentPartial);
    expect(nextCache).not.toContainEqual(previousComplete[1]);
  });

  it("retains confirmed red evidence independently of a withheld score", () => {
    expect(hasConfirmedRedRisk({ security_score: { risk_level: "red" } })).toBe(true);
    expect(hasConfirmedRedRisk({ high_risk_devices: 1 })).toBe(true);
    expect(hasConfirmedRedRisk({ devices: [{ risk_level: "red" }] })).toBe(true);
    expect(
      hasConfirmedRedRisk({
        high_risk_devices: 0,
        security_score: { risk_level: "green" },
        devices: [{ risk_level: "yellow" }],
      }),
    ).toBe(false);
  });

});

describe("scan-level incomplete public copy", () => {
  it("keeps pending identity details private and adds the red instruction only for confirmed risk", () => {
    const withoutRed = scanIncompleteMessage(false);
    const withRed = scanIncompleteMessage(true);

    expect(withoutRed).toBe(
      "점검을 모두 마치지 못했어요. 안전 점수를 확정하지 않았어요. 잠시 후 다시 점검해 주세요.",
    );
    expect(withRed).toBe(
      "점검을 모두 마치지 못했어요. 안전 점수를 확정하지 않았어요. 확인된 위험 안내를 먼저 살펴보세요. 잠시 후 다시 점검해 주세요.",
    );
    expect(withoutRed).not.toContain("확인된 위험 안내");
    for (const publicCopy of [withoutRed, withRed]) {
      expect(publicCopy).not.toMatch(/제품|식별|연결\s*\d+\s*개|추가로 감지된 연결/);
    }
  });
});

describe("presentScanResult partial coverage", () => {
  it("keeps a completed score when Android exposes no neighbour-table rows", () => {
    const presented = presentScanResult(
      result({
        status: "completed",
        scan_complete: true,
        coverage_complete: true,
        network_context: {
          scan_diagnostics: {
            coverage_complete: true,
            candidate_coverage_complete: true,
            candidate_stimulation_complete: true,
            tcp_transport_complete: true,
            wifi_network_socket_binding_complete: true,
            neighbor_source_available_before: false,
            neighbor_source_available_after: false,
            neighbor_probe_complete: false,
            neighbor_presence_confirmed: false,
            neighbor_coverage_complete: false,
            arp_entries_before_probe: 0,
            arp_entries_after_probe: 0,
          },
        },
      }),
    );

    expect(presented).toMatchObject({
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      tcp_scan_timed_out: false,
      security_score: { score: 95, risk_level: "green" },
    });
  });

  it("keeps verified findings but does not keep a definitive score or private network context", () => {
    const presented = presentScanResult(
      result({
        network_context: {
          ssid: "private-home-name",
          local_ip: "192.168.0.8",
          scan_diagnostics: { candidate_coverage_complete: false, tcp_scan_timed_out: true },
        },
      }),
    );

    expect(presented).toMatchObject({
      status: "partial",
      scan_complete: false,
      coverage_complete: false,
      tcp_scan_timed_out: true,
      security_score: { score: null, risk_level: "yellow" },
    });
    expect(presented?.network_context).toBeUndefined();
  });

  it("withholds a partial score without downgrading a confirmed red aggregate", () => {
    const presented = presentScanResult(
      result({
        status: "partial",
        scan_complete: false,
        coverage_complete: false,
        high_risk_devices: 1,
        security_score: { score: 42, risk_level: "red" },
      }),
    );

    expect(presented).toMatchObject({
      status: "partial",
      scan_complete: false,
      security_score: { score: null, risk_level: "red" },
    });
  });

  it("keeps only an explicitly provisional observed score during partial coverage", () => {
    const presented = presentScanResult(
      result({
        status: "partial",
        scan_complete: false,
        coverage_complete: false,
        high_risk_devices: 1,
        security_score: { score: 42, score_status: "provisional", risk_level: "red" },
      }),
    );

    expect(presented).toMatchObject({
      status: "partial",
      scan_complete: false,
      coverage_complete: false,
      security_score: { score: 42, score_status: "provisional", risk_level: "red" },
    });
  });

  it("keeps completion and score while removing a generic detected-connection card", () => {
    const presented = presentScanResult(
      result({
        status: "completed",
        scan_complete: true,
        coverage_complete: true,
        devices_found: 1,
        high_risk_devices: 1,
        identity_pending_count: 1,
        identity_research_status: "review_required",
        detected_connections: [
          {
            device_id: "detected-coverage-1",
            identity_status: "unresolved",
            display_name: "연결된 장비",
            name: "연결된 장비",
            identity_note: "제품명이 없어도 확인된 연결과 보안 신호를 점수에 반영했어요.",
            identity_candidates: [],
            identity_evidence: [],
            device_type: "network",
            online: true,
            last_seen: "2026-08-24T00:00:00Z",
            risk_level: "yellow",
            risk_summary: "확인된 보안 신호를 기준으로 현재 상태를 계산했어요.",
            detected: true,
            is_identity_finding: true,
          },
        ],
        identity_findings: [],
        security_score: { score: 80, risk_level: "red" },
      }),
    );

    expect(presented).toMatchObject({
      status: "completed",
      scan_complete: true,
      coverage_complete: true,
      devices_found: 0,
      high_risk_devices: 1,
      identity_pending_count: 0,
      identity_research_status: "review_required",
      identity_findings: [],
      security_score: { score: 80, risk_level: "red" },
    });
  });

  it("drops a legacy cached result that still contains individual research findings", () => {
    const legacy = result({ identity_findings: [] }) as ScanResult & Record<string, unknown>;
    delete legacy.identity_pending_count;
    delete legacy.identity_research_status;
    legacy.identity_findings = [
      {
        device_id: "legacy-private-finding",
        identity_status: "unresolved",
        display_name: "legacy private label",
        identity_note: "legacy private note",
        identity_candidates: [],
        identity_evidence: [],
        online: true,
        last_seen: "2026-08-21T00:00:00Z",
        risk_level: "red",
        risk_summary: "legacy private risk",
        detected: true,
      },
    ];

    expect(presentScanResult(legacy)).toBeNull();
  });
});
