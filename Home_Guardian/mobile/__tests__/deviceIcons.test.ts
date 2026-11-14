import { Wifi } from "lucide-react-native";

import { DEVICE_ICONS, deviceIcon } from "../src/utils/deviceIcons";

// 백엔드 DEVICE_TYPE_LABELS(backend/app/services/device_identity.py)가 내는 공개 종류.
// 모바일 아이콘 맵이 이 중 하나라도 빠지면 그 기기는 generic WiFi 아이콘으로 떨어진다
// (예: '삼성 냉장고'로 정확히 식별돼도 아이콘이 WiFi). 빠짐을 이 테스트가 잡는다.
const BACKEND_DEVICE_TYPES = [
  "camera", "router", "fridge", "tv", "speaker", "audio", "lock", "plug",
  "hub", "phone", "computer", "nas", "printer", "iot", "web-device",
  "light", "robot", "thermostat", "air_conditioner",
];

describe("deviceIcons", () => {
  it("백엔드 공개 device_type 이 모두 전용 아이콘을 가진다(WiFi 폴백으로 안 떨어짐)", () => {
    for (const type of BACKEND_DEVICE_TYPES) {
      expect(DEVICE_ICONS[type]).toBeDefined();
      // 전용 아이콘이므로 폴백(WiFi)과 달라야 한다.
      expect(deviceIcon(type)).not.toBe(Wifi);
    }
  });

  it("사용자 주 기기(냉장고)는 WiFi 가 아니라 냉장고 계열 아이콘", () => {
    expect(deviceIcon("fridge")).toBe(DEVICE_ICONS.fridge);
    expect(deviceIcon("fridge")).not.toBe(Wifi);
  });

  it("미상/미매핑 device_type 은 WiFi 로 안전 폴백", () => {
    expect(deviceIcon("definitely-unknown-type")).toBe(Wifi);
    expect(deviceIcon(null)).toBe(Wifi);
    expect(deviceIcon(undefined)).toBe(Wifi);
  });
});
