import type { Device, RiskLevel } from "../api/types";

export type RiskAudience = "user" | "guardian";

export type AudienceRiskCopy = {
  title: string;
  body: string;
  reason: string;
  fix: string;
  actionLabel: string;
};

export type UserHomeCopy = {
  title: string;
  body: string;
  actionTitle: string;
  actionBody: string;
};

type Diagnosis = {
  guardianTitle: string;
  guardianBody: string;
  reason: string;
  fix: string;
  userBody: string;
};

export function audienceRiskCopy(device: Device, audience: RiskAudience): AudienceRiskCopy {
  const diagnosis = primaryDiagnosis(device);
  if (audience === "guardian") {
    return {
      title: diagnosis.guardianTitle,
      body: diagnosis.guardianBody,
      reason: diagnosis.reason,
      fix: diagnosis.fix,
      actionLabel: "상세 진단 보기",
    };
  }

  return {
    title: userRiskTitle(device.risk_level),
    body: diagnosis.userBody,
    reason: simpleUserReason(device.risk_level),
    fix: userRiskFix(device.risk_level),
    actionLabel:
      device.risk_level === "red"
        ? "보호자에게 보여주기"
        : device.risk_level === "yellow"
        ? "쉬운 안내 보기"
        : "상태 보기",
  };
}

// 심각도 우선순위(작을수록 심각). 상세 화면이 상위 4개만 보여주므로(slice), 정렬이 없으면
// NVD 조회로 취약점이 5개 이상일 때 critical 이 목록 밖으로 밀려 안 보일 수 있다 → 가장 심각한 것부터.
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function confirmedVulnerabilities(device: Device) {
  const seenCveIds = new Set<string>();
  return (device.vulnerabilities ?? [])
    .filter((vuln) => {
      if (vuln.matched_on === "vendor-only" || vuln.confidence === "low") {
        return false;
      }
      const cveId = String(vuln.cve_id ?? "").trim();
      if (!cveId || seenCveIds.has(cveId)) {
        return false;
      }
      seenCveIds.add(cveId);
      return true;
    })
    .sort(
      (a, b) =>
        (SEVERITY_RANK[String(a.severity).toLowerCase()] ?? 4) -
        (SEVERITY_RANK[String(b.severity).toLowerCase()] ?? 4),
    );
}

export function userRiskTitle(level: RiskLevel) {
  if (level === "red") return "위험해요!";
  if (level === "yellow") return "주의해요";
  if (level === "green") return "괜찮아요";
  return "아직 몰라요";
}

export function guardianRiskTitle(level: RiskLevel) {
  if (level === "red") return "즉시 조치가 필요한 항목입니다.";
  if (level === "yellow") return "확인이 필요한 항목입니다.";
  if (level === "green") return "현재 주요 위험은 없습니다.";
  return "아직 검사 결과가 없습니다.";
}

export function userHomeCopy(level: RiskLevel, hasScan: boolean, highRiskCount: number): UserHomeCopy {
  if (!hasScan) {
    return {
      title: "오늘은 한 번만 검사해요",
      body: "큰 버튼을 누르면 위험한 물건만 먼저 골라서 알려드릴게요.",
      actionTitle: "시작할 일",
      actionBody: "검사 시작하기 버튼을 누르세요.",
    };
  }

  if (level === "red") {
    return {
      title: "위험해요!",
      body: `먼저 볼 물건이 ${highRiskCount}개 있어요. 혼자 고치려고 하지 말고 보호자에게 보여 주세요.`,
      actionTitle: "지금 할 일",
      actionBody: "빨간 카드를 누르고 보호자에게 화면을 보여 주세요.",
    };
  }

  if (level === "yellow") {
    return {
      title: "확인이 필요해요",
      body: "큰 위험은 아니지만 한 번 보면 더 안전해지는 물건이 있어요.",
      actionTitle: "다음 할 일",
      actionBody: "노란 카드를 눌러 쉬운 순서대로 확인하세요.",
    };
  }

  if (level === "green") {
    return {
      title: "지금은 괜찮아요",
      body: "오늘 검사에서는 큰 위험이 보이지 않았어요.",
      actionTitle: "기억할 일",
      actionBody: "새 물건을 연결하거나 공유기를 바꾸면 다시 검사하세요.",
    };
  }

  return {
    title: "아직 몰라요",
    body: "검사를 끝내면 위험한 물건부터 보여드릴게요.",
    actionTitle: "시작할 일",
    actionBody: "검사 시작하기 버튼을 누르세요.",
  };
}

export function guardianDashboardLead(devices: Device[]) {
  const firstRisk = [...devices].sort((a, b) => riskOrder(a.risk_level) - riskOrder(b.risk_level))[0];
  if (!firstRisk) {
    return {
      title: "현재 조치할 위험은 없습니다.",
      body: "새 검사가 끝나거나 위험 신호가 생기면 대상, 원인, 조치가 이 영역에 표시됩니다.",
    };
  }
  const copy = audienceRiskCopy(firstRisk, "guardian");
  return {
    title: copy.title,
    body: `${firstRisk.name} · ${copy.reason}`,
  };
}

function primaryDiagnosis(device: Device): Diagnosis {
  const encryption = (device.encryption || "").toLowerCase();
  if (
    encryption.includes("none") ||
    encryption.includes("open") ||
    encryption.includes("no password") ||
    encryption.includes("unencrypted")
  ) {
    return {
      guardianTitle: "와이파이 보호 설정 확인 필요",
      guardianBody:
        `${device.name}이 암호 없이 접속 가능한 네트워크에서 확인됐습니다. ` +
        "근처 사람이 같은 네트워크에 들어오면 기기 설정에 접근할 가능성이 커집니다.",
      reason: "와이파이 보호 설정 확인 필요",
      fix: "공유기 앱에서 와이파이 보호 설정과 비밀번호를 확인한 뒤, 기기를 다시 연결하세요.",
      userBody: "집 와이파이가 열려 있을 수 있어요. 지금 보호자에게 보여 주세요.",
    };
  }

  if (device.default_credentials) {
    return {
      guardianTitle: "관리자 비밀번호가 초기값일 수 있습니다.",
      guardianBody:
        `${device.name}에서 초기 관리자 비밀번호 사용 가능성이 감지됐습니다. ` +
        "카메라나 공유기라면 외부인이 설정에 접근할 수 있습니다.",
      reason: "기본 비밀번호 가능성: 있음",
      fix: "기기 앱이나 관리자 설정에서 관리자 비밀번호를 새 비밀번호로 바꾸고, 같은 비밀번호 재사용을 피하세요.",
      userBody: "이 물건을 다른 사람이 볼 수도 있어요. 비밀번호를 새로 만들 수 있게 도움을 받아 주세요.",
    };
  }

  if (device.open_ports.includes(23)) {
    return {
      guardianTitle: "외부 연결 설정 확인 필요",
      guardianBody:
        `${device.name}에서 외부 연결을 허용하는 설정이 켜져 있을 수 있습니다. ` +
        "사용하지 않는 외부 연결은 꺼 두는 것이 안전합니다.",
      reason: "외부 연결 설정이 켜져 있을 수 있음",
      fix: "기기 앱이나 공유기 앱에서 외부 연결 허용 설정을 끄고 다시 검사하세요.",
      userBody: "이 물건에 바깥에서 들어올 수 있는 문이 열려 있을 수 있어요. 보호자와 함께 꺼 주세요.",
    };
  }

  if (hasAdminSurface(device)) {
    return {
      guardianTitle: "설정 화면 보호 확인 필요",
      guardianBody:
        `${device.name}의 관리자 설정으로 보이는 서비스가 감지됐습니다. ` +
        "비밀번호가 약하면 설정이 바뀔 위험이 있습니다.",
      reason: "설정 화면이 외부에 열려 있을 수 있음",
      fix: "관리자 비밀번호를 바꾸고, 공유기 앱에서 외부 연결 허용 설정을 확인하세요.",
      userBody: "이 물건의 설정이 열려 있을 수 있어요. 보호자에게 확인을 부탁해 주세요.",
    };
  }

  const severeVulnerability = confirmedVulnerabilities(device).find((vuln) =>
    ["critical", "high", "medium"].includes((vuln.severity || "").toLowerCase()),
  );
  if (severeVulnerability) {
    return {
      guardianTitle: "알려진 보안 취약점이 있습니다.",
      guardianBody: `${device.name}에서 제조사가 알린 보안 문제가 확인됐습니다.`,
      reason: "제조사에서 알린 보안 문제",
      fix: "제조사 앱에서 업데이트가 있는지 확인하고, 비밀번호도 함께 바꿔 주세요.",
      userBody: "이 물건은 알려진 문제가 있을 수 있어요. 업데이트를 도와줄 사람에게 보여 주세요.",
    };
  }

  if (device.risk_level === "red") {
    return {
      guardianTitle: "높은 위험 신호가 확인되었습니다.",
      guardianBody: `${device.name}에서 바로 확인할 위험 신호가 있습니다.`,
      reason: "위험 신호 확인됨",
      fix: "기기 비밀번호와 업데이트 상태를 먼저 확인하세요.",
      userBody: "이 물건은 지금 바로 확인이 필요해요. 카드를 눌러 쉬운 순서대로 따라해 주세요.",
    };
  }

  if (device.risk_level === "yellow") {
    return {
      guardianTitle: "주의 항목이 확인되었습니다.",
      guardianBody: `${device.name}에서 한 번 확인할 항목이 있습니다.`,
      reason: "주의 신호 확인됨",
      fix: "비밀번호와 업데이트 상태를 차례로 확인하세요.",
      userBody: "큰일은 아니지만 한 번 확인하면 더 안전해져요. 카드를 눌러 봐 주세요.",
    };
  }

  if (device.risk_level === "green") {
    return {
      guardianTitle: "현재 주요 위험은 없습니다.",
      guardianBody: `${device.name}은 현재 검사 결과에서 큰 위험 신호가 없습니다.`,
      reason: "검사 결과 안전",
      fix: "새 기기를 연결했거나 공유기 설정을 바꾼 뒤에는 다시 검사하세요.",
      userBody: "이 물건은 지금은 괜찮아요. 새 물건을 연결하면 다시 검사해 주세요.",
    };
  }

  return {
    guardianTitle: "아직 검사 결과가 없습니다.",
    guardianBody: `${device.name}은 아직 충분한 검사 정보가 없습니다.`,
    reason: "검사 전",
    fix: "사용자 휴대폰에서 같은 와이파이에 연결한 뒤 검사를 시작하세요.",
    userBody: "아직 이 물건은 잘 몰라요. 한 번 검사하면 알려드릴게요.",
  };
}

function simpleUserReason(level: RiskLevel) {
  if (level === "red") return "바로 확인 필요";
  if (level === "yellow") return "한 번 확인 필요";
  if (level === "green") return "현재는 안심";
  return "검사 전";
}

function userRiskFix(level: RiskLevel) {
  if (level === "red") return "혼자 해결하려고 하지 말고 보호자에게 보여 주세요.";
  if (level === "yellow") return "카드를 눌러 쉬운 순서대로 확인해 주세요.";
  if (level === "green") return "새 물건을 연결하면 다시 검사해 주세요.";
  return "검사 버튼을 눌러 상태를 확인해 주세요.";
}

function hasAdminSurface(device: Device) {
  const adminPorts = [80, 443, 8080, 8443, 5000, 5001, 7547, 8888, 9000];
  const serviceText = (device.services ?? []).join(" ").toLowerCase();
  return (device.open_ports ?? []).some((port) => adminPorts.includes(port)) || /admin|http|web|router/.test(serviceText);
}

function riskOrder(level: RiskLevel) {
  if (level === "red") return 0;
  if (level === "yellow") return 1;
  if (level === "green") return 2;
  return 3;
}
