import {
  Bot,
  Camera,
  Cpu,
  Globe,
  Lightbulb,
  Lock,
  Monitor,
  Network,
  Plug,
  Printer,
  Refrigerator,
  Router,
  Server,
  Smartphone,
  Speaker,
  Tablet,
  Thermometer,
  Tv,
  Volume2,
  Wifi,
  Wind,
} from "lucide-react-native";
import type { LucideIcon } from "lucide-react-native";

/**
 * device_type → 아이콘 매핑(단일 출처).
 *
 * 백엔드 `DEVICE_TYPE_LABELS`(backend/app/services/device_identity.py)가 내는 19종을 모두 덮는다.
 * 이전에는 DeviceCard/RiskHighlightCard/DeviceDetailScreen 이 각자 7종만 가진 맵을 중복 보유해,
 * 백엔드가 식별한 fridge/light/robot/computer 등이 전부 generic WiFi 아이콘으로 떨어졌다
 * (예: '삼성 냉장고'로 정확히 식별돼도 아이콘은 WiFi). 한 곳에서 관리해 재발을 막는다.
 */
export const DEVICE_ICONS: Record<string, LucideIcon> = {
  router: Router,
  camera: Camera,
  fridge: Refrigerator,
  tv: Tv,
  speaker: Speaker,
  audio: Volume2,
  lock: Lock,
  plug: Plug,
  hub: Network,
  phone: Smartphone,
  tablet: Tablet,
  computer: Monitor,
  nas: Server,
  printer: Printer,
  iot: Cpu,
  "web-device": Globe,
  light: Lightbulb,
  robot: Bot,
  thermostat: Thermometer,
  air_conditioner: Wind,
};

/** device_type 에 맞는 아이콘을 반환한다. 미상/미매핑이면 WiFi(연결됨) 아이콘으로 폴백. */
export function deviceIcon(deviceType: string | null | undefined): LucideIcon {
  if (!deviceType) {
    return Wifi;
  }
  return DEVICE_ICONS[deviceType] ?? Wifi;
}
