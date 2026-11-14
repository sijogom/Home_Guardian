import type { RiskLevel } from "../api/types";
import { TrafficLightBadge } from "./TrafficLightBadge";

type RiskBadgeProps = {
  riskLevel: RiskLevel;
};

// 신호등 4단계 배지. TrafficLightBadge 의 얇은 alias 로 유지해
// 기존 import 경로(`../components/RiskBadge`)를 깨지 않으면서 새 디자인 토큰을 그대로 적용한다.
export function RiskBadge({ riskLevel }: RiskBadgeProps) {
  return <TrafficLightBadge level={riskLevel} size="sm" />;
}
