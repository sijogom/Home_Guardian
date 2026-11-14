import { HomeGuardianApi, normalizeApiBaseUrl } from "../src/api/homeGuardianApi";

function response(status: number, data: unknown) {
  return {
    status,
    ok: status >= 200 && status < 300,
    json: jest.fn().mockResolvedValue(data),
  } as unknown as Response;
}

function apiPayload<T>(data: T) {
  return {
    success: true,
    data,
    error: null,
    timestamp: "2026-08-13T00:00:00Z",
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function flushMicrotasks() {
  for (let index = 0; index < 6; index += 1) {
    await Promise.resolve();
  }
}

describe("HomeGuardianApi refresh single-flight", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("동시에 만료된 요청이 와도 refresh handler를 한 번만 실행하고 모두 새 access token으로 재시도한다", async () => {
    const refresh = deferred<string | null>();
    const refreshHandler = jest.fn(() => refresh.promise);
    const api = new HomeGuardianApi("https://api.example.test");
    api.setAuthToken("expired-access-token");
    api.setRefreshHandler(refreshHandler);

    const fetchMock = jest.fn();
    fetchMock.mockImplementation(() => {
      const callNumber = fetchMock.mock.calls.length;
      if (callNumber <= 2) {
        return Promise.resolve(response(401, { success: false, data: null, error: null, timestamp: "" }));
      }
      return Promise.resolve(response(200, apiPayload({ items: [], total: 0 })));
    });
    global.fetch = fetchMock as unknown as typeof fetch;

    const firstRequest = api.getDevices();
    const secondRequest = api.getDevices();
    await flushMicrotasks();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(refreshHandler).toHaveBeenCalledTimes(1);

    refresh.resolve("renewed-access-token");
    await expect(Promise.all([firstRequest, secondRequest])).resolves.toEqual([
      { items: [], total: 0 },
      { items: [], total: 0 },
    ]);

    expect(fetchMock).toHaveBeenCalledTimes(4);
    const authorizationHeaders = fetchMock.mock.calls.map(([, options]) => {
      const headers = (options as RequestInit).headers as Record<string, string>;
      return headers.Authorization;
    });
    expect(authorizationHeaders).toEqual([
      "Bearer expired-access-token",
      "Bearer expired-access-token",
      "Bearer renewed-access-token",
      "Bearer renewed-access-token",
    ]);
  });
});

describe("HomeGuardianApi refresh request contract", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("sends the persisted response-loss recovery id with refresh", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    const fetchMock = jest.fn().mockResolvedValue(
      response(
        200,
        apiPayload({
          access_token: "renewed-access",
          refresh_token: "renewed-refresh",
          token_type: "Bearer",
          expires_in: 900,
          user: {
            user_id: "user-1",
            email: "user@example.test",
            nickname: "User",
            role: "user",
            email_verified: true,
            home_id: "home-1",
          },
        }),
      ),
    );
    global.fetch = fetchMock as unknown as typeof fetch;

    await api.refreshAuthSession("stored-refresh-token", "refresh-attempt-123456");

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({
      refresh_token: "stored-refresh-token",
      refresh_attempt_id: "refresh-attempt-123456",
    });
  });

  it("does not send mutable guardian identity when accepting an invite", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    const fetchMock = jest.fn().mockResolvedValue(
      response(
        200,
        apiPayload({
          guardian: {},
          wards: [],
          total: 0,
          active_ward: {},
          dashboard: {},
        }),
      ),
    );
    global.fetch = fetchMock as unknown as typeof fetch;

    await api.acceptGuardianInvite("ABC123");

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({ invite: "ABC123" });
  });

  it("sends only the explicit Android native scan contract", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    const fetchMock = jest.fn().mockResolvedValue(
      response(
        200,
        apiPayload({
          scan_id: "scan-contract",
          status: "running",
          progress: 0,
          scan_source: "android-native",
          current_step: "queued",
          devices_found: 0,
          high_risk_devices: 0,
        }),
      ),
    );
    global.fetch = fetchMock as unknown as typeof fetch;

    await api.startScan({
      scan_profile: "quick",
      scan_source: "android-native",
      network_context: {
        ssid: "Home Wi-Fi",
        local_ip: "192.168.0.9",
        gateway_ip: "192.168.0.1",
        subnet_cidr: "192.168.0.0/24",
        interface_type: "wifi",
      },
      devices: [{ ip_address: "192.168.0.20", discovery_sources: ["arp"] }],
    });

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({
      scan_profile: "quick",
      scan_source: "android-native",
      network_context: {
        ssid: "Home Wi-Fi",
        local_ip: "192.168.0.9",
        gateway_ip: "192.168.0.1",
        subnet_cidr: "192.168.0.0/24",
        interface_type: "wifi",
      },
      devices: [{ ip_address: "192.168.0.20", discovery_sources: ["arp"] }],
    });
  });
});

describe("HomeGuardianApi release transport boundary", () => {
  it("운영 빌드에서는 저장된 HTTP API 주소를 버리고 HTTPS 주소만 사용한다", () => {
    expect(normalizeApiBaseUrl("http://old-local-server.example.test", true)).toBe("");
    expect(normalizeApiBaseUrl("https://api.example.test/", true)).toBe("https://api.example.test");
  });
});

describe("HomeGuardianApi v1 contract boundary", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("구버전 서버의 인증 경로 404를 서버 버전 불일치로 구분한다", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    global.fetch = jest.fn().mockResolvedValue(response(404, { detail: "Not Found" })) as unknown as typeof fetch;

    await expect(api.googleLogin({ idToken: "id-token-for-test" })).rejects.toMatchObject({
      code: "SERVER_VERSION_MISMATCH",
      message: "서비스 연결이 아직 준비되지 않았어요. 관리자에게 앱과 서버를 함께 업데이트해 달라고 알려 주세요.",
    });
  });

  it("빈 404 응답도 JSON 파싱 전에 서버 버전 불일치로 구분한다", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    global.fetch = jest.fn().mockResolvedValue(new Response("", { status: 404 })) as unknown as typeof fetch;

    await expect(api.googleLogin({ idToken: "id-token-for-test" })).rejects.toMatchObject({
      code: "SERVER_VERSION_MISMATCH",
    });
  });

  it("실제 스캔 시작 경로의 구버전 404도 서버 버전 불일치로 구분한다", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    global.fetch = jest.fn().mockResolvedValue(new Response("", { status: 404 })) as unknown as typeof fetch;

    await expect(
      api.startScan({ scan_source: "android-native", network_context: {}, devices: [] }),
    ).rejects.toMatchObject({ code: "SERVER_VERSION_MISMATCH" });
  });

  it("일반 리소스 404는 서버 버전 불일치로 오인하지 않는다", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    global.fetch = jest.fn().mockResolvedValue(response(404, { detail: "Not Found" })) as unknown as typeof fetch;

    await expect(api.getDevice("missing-device")).rejects.toMatchObject({ code: "UNKNOWN" });
  });
});

describe("HomeGuardianApi FCM token lifecycle", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("등록 토큰 삭제의 204 응답을 정상 처리한다", async () => {
    const api = new HomeGuardianApi("https://api.example.test");
    api.setAuthToken("access-token");
    const fetchMock = jest.fn().mockResolvedValue(new Response(null, { status: 204 }));
    global.fetch = fetchMock as unknown as typeof fetch;

    await expect(api.deleteFcmToken("device-token")).resolves.toBeUndefined();

    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(options.method).toBe("DELETE");
    expect(JSON.parse(String(options.body))).toEqual({ fcm_token: "device-token" });
  });
});
