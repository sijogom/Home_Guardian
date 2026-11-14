import { NativeModule, requireNativeModule } from 'expo';

import type {
  HomeGuardianNetworkScannerModuleEvents,
  NativeScanOptions,
  NativeScanPayload,
} from './HomeGuardianNetworkScanner.types';

declare class HomeGuardianNetworkScannerModule extends NativeModule<HomeGuardianNetworkScannerModuleEvents> {
  scanNetworkAsync(options: NativeScanOptions): Promise<NativeScanPayload>;
}

export default requireNativeModule<HomeGuardianNetworkScannerModule>('HomeGuardianNetworkScanner');
