import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Appearance, useColorScheme } from "react-native";

import { StorageKeys, storageGet, storageSet } from "./state/storage";

declare function require<T = unknown>(path: string): T;

export type ThemePreference = "light" | "dark" | "system";
export type ThemeMode = "light" | "dark";

/**
 * Colors are grouped by visual responsibility.  Existing names stay public so
 * screen-level UI can migrate without breaking its theme contract.
 */
export type ThemeColors = {
  bg: string;
  surface: string;
  surfaceSoft: string;
  surfaceElevated: string;
  surfaceMuted: string;
  paperWarm: string;
  careBg: string;
  careStrong: string;
  protectBg: string;
  protectStrong: string;
  calmBg: string;
  calmStrong: string;
  text: string;
  textMuted: string;
  divider: string;
  borderSubtle: string;
  borderStrong: string;
  focus: string;
  shadow: string;
  safeBg: string;
  safeStrong: string;
  safePressed: string;
  warnBg: string;
  warnStrong: string;
  dangerBg: string;
  dangerStrong: string;
  dangerPressed: string;
  unknownBg: string;
  unknownStrong: string;
  cta: string;
  ctaPressed: string;
  ctaText: string;
  ctaOverlay: string;
  ctaOutline: string;
  heroBg: string;
  heroPressed: string;
  heroText: string;
  heroOverlay: string;
  heroOutline: string;
  infoBg: string;
};

const lightColors: ThemeColors = {
  bg: "#FFFFFF",
  surface: "#FFFFFF",
  surfaceSoft: "#F6F8FC",
  surfaceElevated: "#FFFFFF",
  surfaceMuted: "#EAF1F8",
  paperWarm: "#FFFFFF",
  careBg: "#F1F6FC",
  careStrong: "#1C4F80",
  protectBg: "#F1F8F4",
  protectStrong: "#2D624A",
  calmBg: "#F2F7FB",
  calmStrong: "#1D6B58",
  text: "#101828",
  textMuted: "#526277",
  divider: "#D9E3EE",
  borderSubtle: "#E4EBF3",
  borderStrong: "#C4D2E1",
  focus: "#2C6EA7",
  shadow: "#0F172A",
  safeBg: "#EFF9F2",
  safeStrong: "#1F6A47",
  safePressed: "#185438",
  warnBg: "#FFF7E8",
  warnStrong: "#8A5A14",
  dangerBg: "#FFF1F1",
  dangerStrong: "#AB2E34",
  dangerPressed: "#88242A",
  unknownBg: "#F1F4F7",
  unknownStrong: "#4B5C70",
  cta: "#174E80",
  ctaPressed: "#0E365D",
  ctaText: "#FFFFFF",
  ctaOverlay: "rgba(255,255,255,0.14)",
  ctaOutline: "rgba(255,255,255,0.38)",
  heroBg: "#174E80",
  heroPressed: "#0E365D",
  heroText: "#FFFFFF",
  heroOverlay: "rgba(255,255,255,0.14)",
  heroOutline: "rgba(255,255,255,0.28)",
  infoBg: "#F1F4F7",
};

const darkColors: ThemeColors = {
  bg: "#101418",
  surface: "#151E2A",
  surfaceSoft: "#1B2634",
  surfaceElevated: "#1C2837",
  surfaceMuted: "#202D3C",
  paperWarm: "#182330",
  careBg: "#1B2B3B",
  careStrong: "#A9CDF2",
  protectBg: "#193229",
  protectStrong: "#B5CDE7",
  calmBg: "#1A2A38",
  calmStrong: "#9DDFC4",
  text: "#F4F7FB",
  textMuted: "#C5D0DD",
  divider: "#3D4C5D",
  borderSubtle: "#2C3B4C",
  borderStrong: "#536579",
  focus: "#A9CDF2",
  shadow: "#000000",
  safeBg: "#173C2B",
  safeStrong: "#A6E4BF",
  safePressed: "#7CD7A3",
  warnBg: "#4A3A1B",
  warnStrong: "#F7D58B",
  dangerBg: "#48252B",
  dangerStrong: "#F3ADB1",
  dangerPressed: "#F27C84",
  unknownBg: "#273545",
  unknownStrong: "#C5D0DD",
  cta: "#A9CDF2",
  ctaPressed: "#D2E5FA",
  ctaText: "#10233A",
  ctaOverlay: "rgba(16,35,58,0.12)",
  ctaOutline: "rgba(16,35,58,0.32)",
  heroBg: "#172A3E",
  heroPressed: "#223D57",
  heroText: "#F4F7FB",
  heroOverlay: "rgba(255,255,255,0.14)",
  heroOutline: "rgba(255,255,255,0.28)",
  infoBg: "#1D3145",
};

type ThemeContextValue = {
  colors: ThemeColors;
  mode: ThemeMode;
  preference: ThemePreference;
  setPreference: (preference: ThemePreference) => void;
};

const ThemeContext = createContext<ThemeContextValue>({
  colors: lightColors,
  mode: "light",
  preference: "light",
  setPreference: () => undefined,
});

export function ThemeProvider({ children }: { children: ReactNode }) {
  const systemScheme = useColorScheme();
  const [preference, setStoredPreference] = useState<ThemePreference>("light");
  const preferenceWriteRef = useRef<Promise<void>>(Promise.resolve());
  const userSelectedPreferenceRef = useRef(false);

  useEffect(() => {
    void storageGet<ThemePreference>(StorageKeys.themePreference).then((saved) => {
      if (
        !userSelectedPreferenceRef.current &&
        (saved === "light" || saved === "dark" || saved === "system")
      ) {
        setStoredPreference(saved);
      }
    });
  }, []);

  const setPreference = useCallback((nextPreference: ThemePreference) => {
    userSelectedPreferenceRef.current = true;
    setStoredPreference(nextPreference);
    // 빠르게 여러 번 바꿔도 이전 쓰기가 나중에 도착해 최종 선택을 덮지 않도록
    // 저장 순서를 직렬화한다.
    preferenceWriteRef.current = preferenceWriteRef.current
      .catch(() => undefined)
      .then(() => storageSet(StorageKeys.themePreference, nextPreference));
  }, []);
  const mode: ThemeMode = preference === "system" ? (systemScheme === "dark" ? "dark" : "light") : preference;

  useEffect(() => {
    // React Native 화면뿐 아니라 Alert, 입력창, Android 시스템 chrome도 앱의
    // 선택 테마와 같은 uiMode를 사용해야 반쪽짜리 테마가 남지 않는다.
    Appearance.setColorScheme(preference === "system" ? null : mode);
  }, [mode, preference]);

  const value = useMemo(
    () => ({ colors: mode === "dark" ? darkColors : lightColors, mode, preference, setPreference }),
    [mode, preference, setPreference],
  );
  return createElement(ThemeContext.Provider, { value }, children);
}

export function useAppTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

/**
 * Static StyleSheet definitions capture color strings when their module is loaded.
 * Build palette-dependent styles inside a component so a preference change redraws
 * every visible surface, border, and text color.
 */
export function useThemedStyles<T>(factory: (palette: ThemeColors) => T): { colors: ThemeColors; styles: T } {
  const { colors } = useAppTheme();
  const styles = useMemo(() => factory(colors), [colors, factory]);
  return { colors, styles };
}

/** Keeps continuous decorative motion optional for people who reduce motion system-wide. */
type AccessibilityMotionInfo = {
  isReduceMotionEnabled?: () => Promise<boolean>;
  addEventListener?: (
    event: "reduceMotionChanged",
    listener: (enabled: boolean) => void,
  ) => { remove: () => void };
};

function loadAccessibilityMotionInfo(): AccessibilityMotionInfo | null {
  try {
    const module = require<{ AccessibilityInfo?: AccessibilityMotionInfo }>("react-native");
    return module.AccessibilityInfo ?? null;
  } catch {
    return null;
  }
}

export function useReducedMotion(): boolean {
  const [reducedMotion, setReducedMotion] = useState(false);

  useEffect(() => {
    const accessibilityInfo = loadAccessibilityMotionInfo();
    if (!accessibilityInfo?.isReduceMotionEnabled) return;

    let active = true;
    void accessibilityInfo
      .isReduceMotionEnabled()
      .then((enabled: boolean) => {
        if (active) setReducedMotion(enabled);
      })
      .catch(() => undefined);
    const subscription = accessibilityInfo.addEventListener?.("reduceMotionChanged", setReducedMotion);
    return () => {
      active = false;
      subscription?.remove();
    };
  }, []);

  return reducedMotion;
}

export const radius = { xs: 8, sm: 12, md: 16, lg: 20, xl: 28, pill: 999 };
export const spacing = { xs: 8, sm: 12, md: 16, lg: 24, xl: 32, xxl: 40 };

export const text = {
  caption: 20,
  body: 20,
  bodyStrong: 20,
  label: 20,
  section: 24,
  title: 32,
  metric: 56,
  hero: 72,
  heroBig: 96,
};

export const lineHeight = {
  caption: 28,
  body: 30,
  bodyStrong: 30,
  label: 28,
  section: 32,
  title: 40,
  metric: 64,
  hero: 80,
  heroBig: 104,
};

export const fontWeight = {
  body: "500" as const,
  bodyStrong: "700" as const,
  label: "700" as const,
  section: "800" as const,
  title: "800" as const,
  metric: "900" as const,
  hero: "900" as const,
};

export const motion = {
  pressScale: 0.985,
  pressOpacity: 0.9,
  quick: 140,
  standard: 220,
};

export const touchTargetMin = 56;
export const ctaHeight = 80;

export type ToneKey = "green" | "yellow" | "red" | "unknown";
export type ToneStyle = { bg: string; fg: string; label: string };

export function tone(level: ToneKey | string | null | undefined, palette: ThemeColors): ToneStyle {
  switch (level) {
    case "green":
      return { bg: palette.safeBg, fg: palette.safeStrong, label: "안전" };
    case "yellow":
      return { bg: palette.warnBg, fg: palette.warnStrong, label: "주의" };
    case "red":
      return { bg: palette.dangerBg, fg: palette.dangerStrong, label: "위험" };
    default:
      return { bg: palette.unknownBg, fg: palette.unknownStrong, label: "점검 전" };
  }
}
