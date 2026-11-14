import React from "react";
import { useColorScheme } from "react-native";
import TestRenderer, { act } from "react-test-renderer";

const mockAsyncValues = (
  globalThis as typeof globalThis & {
    __HOME_GUARDIAN_ASYNC_STORAGE_MOCK__: { values: Map<string, string> };
  }
).__HOME_GUARDIAN_ASYNC_STORAGE_MOCK__.values;
const mockSetColorScheme = jest.fn();

jest.mock("expo-secure-store", () => ({
  getItemAsync: jest.fn(async () => null),
  setItemAsync: jest.fn(async () => undefined),
  deleteItemAsync: jest.fn(async () => undefined),
}));

jest.mock("react-native", () => ({
  Appearance: { setColorScheme: (...args: unknown[]) => mockSetColorScheme(...args) },
  useColorScheme: jest.fn(),
}));

import { StorageKeys, storageSet } from "../src/state/storage";
import { ThemeProvider, type ThemePreference, useAppTheme, useThemedStyles } from "../src/theme";

type ThemeSnapshot = ReturnType<typeof useAppTheme>;
type ThemeCapture = { current: ThemeSnapshot | null };
type ThemedSurfaceCapture = {
  current: null | { background: string; foreground: string; divider: string; heroBackground: string; heroForeground: string };
};

const mockedUseColorScheme = useColorScheme as jest.MockedFunction<typeof useColorScheme>;

function ThemeProbe({ capture }: { capture: ThemeCapture }) {
  capture.current = useAppTheme();
  return null;
}

const createProbeStyles = (colors: ThemeSnapshot["colors"]) => ({
  background: colors.bg,
  foreground: colors.text,
  divider: colors.divider,
  heroBackground: colors.heroBg,
  heroForeground: colors.heroText,
});

function ThemedSurfaceProbe({ capture }: { capture: ThemedSurfaceCapture }) {
  const { styles } = useThemedStyles(createProbeStyles);
  capture.current = styles;
  return null;
}

async function settleThemeEffect() {
  await Promise.resolve();
  await Promise.resolve();
}

async function renderTheme(capture: ThemeCapture): Promise<TestRenderer.ReactTestRenderer> {
  let renderer!: TestRenderer.ReactTestRenderer;
  await act(async () => {
    renderer = TestRenderer.create(
      <ThemeProvider>
        <ThemeProbe capture={capture} />
      </ThemeProvider>,
    );
    await settleThemeEffect();
  });
  return renderer;
}

async function unmount(renderer: TestRenderer.ReactTestRenderer) {
  await act(async () => {
    renderer.unmount();
  });
}

function channel(hex: string, offset: number): number {
  return Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
}

function luminance(hex: string): number {
  const linear = (value: number) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear(channel(hex, 1)) + 0.7152 * linear(channel(hex, 3)) + 0.0722 * linear(channel(hex, 5));
}

function contrastRatio(foreground: string, background: string): number {
  const foregroundLuminance = luminance(foreground);
  const backgroundLuminance = luminance(background);
  const lighter = Math.max(foregroundLuminance, backgroundLuminance);
  const darker = Math.min(foregroundLuminance, backgroundLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

describe("theme preference persistence", () => {
  beforeEach(() => {
    mockAsyncValues.clear();
    mockedUseColorScheme.mockReset();
    mockedUseColorScheme.mockReturnValue(null);
    mockSetColorScheme.mockReset();
  });

  it("starts in the readable light palette before a saved preference is restored", async () => {
    mockedUseColorScheme.mockReturnValue("dark");
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);

    expect(capture.current?.preference).toBe("light");
    expect(capture.current?.mode).toBe("light");
    expect(capture.current?.colors.bg).toBe("#FFFFFF");

    await unmount(renderer);
  });

  it("keeps primary light-mode surfaces white and reserves subtle cool planes for hierarchy", async () => {
    mockedUseColorScheme.mockReturnValue("light");
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);
    const colors = capture.current?.colors;

    expect(colors).toBeDefined();
    for (const surface of [
      colors?.bg,
      colors?.surface,
      colors?.surfaceElevated,
      colors?.paperWarm,
    ]) {
      expect(surface).toBe("#FFFFFF");
    }
    for (const plane of [colors?.surfaceSoft, colors?.surfaceMuted, colors?.careBg, colors?.protectBg, colors?.calmBg]) {
      expect(plane).toMatch(/^#(?:E|F)[0-9A-F]{5}$/);
    }
    expect(colors?.infoBg).toBe(colors?.unknownBg);
    expect(colors?.safeBg).not.toBe(colors?.surface);
    expect(colors?.warnBg).not.toBe(colors?.surface);
    expect(colors?.dangerBg).not.toBe(colors?.surface);

    await unmount(renderer);
  });

  it("keeps dark semantic planes distinct from an ordinary surface", async () => {
    mockedUseColorScheme.mockReturnValue("dark");
    await storageSet(StorageKeys.themePreference, "dark");
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);
    const colors = capture.current?.colors;

    expect(colors?.surface).toBe("#151E2A");
    for (const plane of [colors?.paperWarm, colors?.careBg, colors?.protectBg, colors?.calmBg]) {
      expect(plane).not.toBe(colors?.surface);
    }

    await unmount(renderer);
  });

  it.each([
    ["light", "dark", "light", "#FFFFFF"],
    ["dark", "light", "dark", "#101418"],
  ] as const)("restores the %s preference independently from the device scheme", async (preference, systemScheme, mode, background) => {
    mockedUseColorScheme.mockReturnValue(systemScheme);
    await storageSet(StorageKeys.themePreference, preference);
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);

    expect(capture.current?.preference).toBe(preference);
    expect(capture.current?.mode).toBe(mode);
    expect(capture.current?.colors.bg).toBe(background);

    await unmount(renderer);
  });

  it("restores the system preference and follows the current system palette", async () => {
    let systemScheme: "light" | "dark" = "dark";
    mockedUseColorScheme.mockImplementation(() => systemScheme);
    await storageSet(StorageKeys.themePreference, "system");
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);

    expect(capture.current?.preference).toBe("system");
    expect(capture.current?.mode).toBe("dark");
    expect(capture.current?.colors.bg).toBe("#101418");

    systemScheme = "light";
    await act(async () => {
      renderer.update(
        <ThemeProvider>
          <ThemeProbe capture={capture} />
        </ThemeProvider>,
      );
      await settleThemeEffect();
    });

    expect(capture.current?.mode).toBe("light");
    expect(capture.current?.colors.bg).toBe("#FFFFFF");

    await unmount(renderer);
  });

  it.each(["light", "dark", "system"] as const)("persists the %s preference", async (preference: ThemePreference) => {
    mockedUseColorScheme.mockReturnValue("dark");
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);

    await act(async () => {
      capture.current?.setPreference(preference);
      await settleThemeEffect();
    });

    expect(capture.current?.preference).toBe(preference);
    expect(mockAsyncValues.get(StorageKeys.themePreference)).toBe(JSON.stringify(preference));

    await unmount(renderer);
  });

  it("returns every representative surface to the exact light palette after light-dark-light", async () => {
    mockedUseColorScheme.mockReturnValue("light");
    const themeCapture: ThemeCapture = { current: null };
    const surfaceCapture: ThemedSurfaceCapture = { current: null };
    let renderer!: TestRenderer.ReactTestRenderer;
    await act(async () => {
      renderer = TestRenderer.create(
        <ThemeProvider>
          <ThemeProbe capture={themeCapture} />
          <ThemedSurfaceProbe capture={surfaceCapture} />
        </ThemeProvider>,
      );
      await settleThemeEffect();
    });
    const initialLight = { ...surfaceCapture.current! };

    await act(async () => {
      themeCapture.current?.setPreference("dark");
      await settleThemeEffect();
    });
    expect(surfaceCapture.current?.background).toBe("#101418");
    expect(surfaceCapture.current?.heroBackground).toBe("#172A3E");

    await act(async () => {
      themeCapture.current?.setPreference("light");
      await settleThemeEffect();
    });
    expect(surfaceCapture.current).toEqual(initialLight);
    expect(mockSetColorScheme).toHaveBeenCalledWith("dark");
    expect(mockSetColorScheme).toHaveBeenLastCalledWith("light");

    await unmount(renderer);
  });

  it.each(["light", "dark"] as const)("keeps primary and semantic text readable in %s mode", async (preference) => {
    mockedUseColorScheme.mockReturnValue(preference);
    await storageSet(StorageKeys.themePreference, preference);
    const capture: ThemeCapture = { current: null };
    const renderer = await renderTheme(capture);
    const colors = capture.current?.colors;

    expect(colors).toBeDefined();
    const pairs = [
      [colors?.text, colors?.bg],
      [colors?.textMuted, colors?.bg],
      [colors?.ctaText, colors?.cta],
      [colors?.heroText, colors?.heroBg],
      [colors?.safeStrong, colors?.safeBg],
      [colors?.warnStrong, colors?.warnBg],
      [colors?.dangerStrong, colors?.dangerBg],
      [colors?.unknownStrong, colors?.unknownBg],
    ] as const;
    for (const [foreground, background] of pairs) {
      expect(foreground).toBeDefined();
      expect(background).toBeDefined();
      expect(contrastRatio(foreground!, background!)).toBeGreaterThanOrEqual(4.5);
    }

    await unmount(renderer);
  });
});
