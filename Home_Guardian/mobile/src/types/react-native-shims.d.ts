declare namespace JSX {
  interface IntrinsicAttributes {
    key?: string;
  }
}

declare module "react" {
  export type ReactNode = any;
  export function useCallback<T extends (...args: any[]) => any>(callback: T, deps: unknown[]): T;
  export function useMemo<T>(factory: () => T, deps: unknown[]): T;
  export function useState<T>(initialValue: T | (() => T)): [T, (value: T | ((previous: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: unknown[]): void;
  export function useRef<T>(initialValue: T): { current: T };
  export function createContext<T>(defaultValue: T): { Provider: any };
  export function useContext<T>(context: { Provider: any }): T;
  export function createElement(type: any, props: any, ...children: any[]): any;
}

declare module "react/jsx-runtime" {
  export const jsx: unknown;
  export const jsxs: unknown;
  export const Fragment: unknown;
}

declare module "react-native" {
  export type StyleValue = Record<string, unknown> | Array<Record<string, unknown>>;
  export type PressableState = { pressed: boolean };

  export const ActivityIndicator: any;
  export const Pressable: any;
  export const SafeAreaView: any;
  export const ScrollView: any;
  export const StatusBar: any;
  export const Text: any;
  export const TextInput: any;
  export const View: any;
  export const Keyboard: { dismiss: () => void };
  export const Appearance: {
    setColorScheme: (colorScheme: "light" | "dark" | null | undefined) => void;
  };
  export function useColorScheme(): "light" | "dark" | null;
  export function useWindowDimensions(): {
    width: number;
    height: number;
    scale: number;
    fontScale: number;
  };

  export const Animated: {
    Value: new (value: number) => {
      setValue: (value: number) => void;
      interpolate: (config: { inputRange: number[]; outputRange: any[] }) => any;
    };
    View: any;
    timing: (value: any, config: any) => { start: (cb?: () => void) => void };
    loop: (animation: { start: (cb?: () => void) => void; stop?: () => void }) => {
      start: (cb?: () => void) => void;
      stop: () => void;
    };
    sequence: (
      animations: Array<{ start: (cb?: () => void) => void }>,
    ) => { start: (cb?: () => void) => void };
  };

  export const Easing: {
    linear: any;
    inOut: (easing: any) => any;
    ease: any;
  };

  export const StyleSheet: {
    create<T extends Record<string, StyleValue>>(styles: T): T;
  };
}
