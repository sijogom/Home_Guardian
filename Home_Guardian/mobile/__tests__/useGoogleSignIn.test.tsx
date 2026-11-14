import { act } from "react-test-renderer";
import TestRenderer from "react-test-renderer";

const mockPromptAsync = jest.fn();
const mockUseIdTokenAuthRequest = jest.fn();
const mockPerformExchange = jest.fn();
const mockAccessTokenRequest = jest.fn().mockImplementation(() => ({
  performAsync: (...args: unknown[]) => mockPerformExchange(...args),
}));
const mockGoogleLogin = jest.fn();

jest.mock("expo-auth-session/providers/google", () => ({
  discovery: { tokenEndpoint: "https://oauth2.googleapis.com/token" },
  useIdTokenAuthRequest: (...args: unknown[]) => mockUseIdTokenAuthRequest(...args),
}));

jest.mock("expo-auth-session", () => ({
  AccessTokenRequest: mockAccessTokenRequest,
}));

jest.mock("../src/services/googleAuth", () => ({
  getGoogleClientId: () => "android-client-id",
}));

jest.mock("../src/api/homeGuardianApi", () => ({
  HomeGuardianApiError: class HomeGuardianApiError extends Error {
    code: string;

    constructor(message: string, code: string) {
      super(message);
      this.code = code;
    }
  },
  homeGuardianApi: {
    googleLogin: (...args: unknown[]) => mockGoogleLogin(...args),
  },
}));

import { useGoogleSignIn, type GoogleSignInController } from "../src/hooks/useGoogleSignIn";

function Probe({ onUpdate }: { onUpdate: (controller: GoogleSignInController) => void }) {
  onUpdate(useGoogleSignIn());
  return null;
}

describe("useGoogleSignIn", () => {
  beforeEach(() => {
    mockPromptAsync.mockReset();
    mockUseIdTokenAuthRequest.mockReset();
    mockPerformExchange.mockReset();
    mockAccessTokenRequest.mockClear();
    mockGoogleLogin.mockReset();
    mockUseIdTokenAuthRequest.mockReturnValue([
      {
        redirectUri: "com.homeguardian.app:/oauthredirect",
        codeVerifier: "pkce-verifier",
      },
      null,
      mockPromptAsync,
    ]);
  });

  it("disables the provider exchange so the manual PKCE path is the single owner", () => {
    act(() => {
      TestRenderer.create(<Probe onUpdate={() => undefined} />);
    });

    expect(mockUseIdTokenAuthRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        androidClientId: "android-client-id",
        shouldAutoExchangeCode: false,
      }),
    );
  });
});
