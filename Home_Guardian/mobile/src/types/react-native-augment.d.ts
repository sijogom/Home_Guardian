// react-native 0.81 + typescript 5.9 에서 일부 named export 타입이 누락되는 문제를
// module augmentation 으로 보강한다. 실제 구현은 react-native 가 그대로 제공한다.

import "react-native";

declare module "react-native" {
  export const BackHandler: {
    addEventListener: (
      event: "hardwareBackPress",
      handler: () => boolean,
    ) => { remove: () => void };
  };

  export const Platform: {
    OS: "ios" | "android" | "macos" | "windows" | "web";
    Version: number | string;
  };

  export const ToastAndroid: {
    SHORT: number;
    LONG: number;
    show: (message: string, duration: number) => void;
  };

  export const KeyboardAvoidingView: React.ComponentType<{
    behavior?: "height" | "position" | "padding";
    keyboardVerticalOffset?: number;
    children?: React.ReactNode;
    style?: unknown;
  }>;

  export const Modal: React.ComponentType<{
    animationType?: "none" | "fade" | "slide";
    children?: React.ReactNode;
    onRequestClose?: () => void;
    transparent?: boolean;
    visible?: boolean;
  }>;

  export const Share: {
    share: (
      content: { message?: string; title?: string; url?: string },
      options?: { dialogTitle?: string; subject?: string },
    ) => Promise<{ action: string; activityType?: string | null }>;
  };

  export const Alert: {
    alert: (
      title: string,
      message?: string,
      buttons?: Array<{
        text?: string;
        style?: "default" | "cancel" | "destructive";
        onPress?: () => void;
      }>,
    ) => void;
  };

  export const Linking: {
    getInitialURL: () => Promise<string | null>;
    addEventListener: (
      event: "url",
      handler: (event: { url: string }) => void,
    ) => { remove: () => void };
  };
}
