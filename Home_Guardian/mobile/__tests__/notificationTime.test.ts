import { residentNotificationTime } from "../src/utils/devicePresentation";

describe("residentNotificationTime", () => {
  it("formats a valid timestamp as easy Korean text instead of an ISO value", () => {
    const rawTimestamp = "2026-08-13T00:05:00Z";
    const formatted = residentNotificationTime(rawTimestamp);

    expect(formatted).toMatch(/^\d{4}년 \d{1,2}월 \d{1,2}일 (?:오전|오후) \d{1,2}시 \d{2}분$/);
    expect(formatted).not.toContain("T");
    expect(formatted).not.toContain("Z");
  });

  it.each([undefined, "", "not-a-date", "CVE-2026-0001", "2026-02-30T00:00:00Z"])(
    "uses a friendly fallback for an invalid notification time: %p",
    (createdAt) => {
      expect(residentNotificationTime(createdAt)).toBe("시간을 확인할 수 없어요.");
    },
  );
});
