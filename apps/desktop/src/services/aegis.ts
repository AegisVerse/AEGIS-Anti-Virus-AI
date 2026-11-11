import { invoke } from '@tauri-apps/api/core';
import type { AegisRequest, ErrorCode } from '../types/aegis';

export interface IpcError {
  code: ErrorCode;
  message: string;
}

export interface ConnectionInfo {
  connected: boolean;
  mode: 'service' | 'user' | null;
  pipe: string | null;
  privileged_allowed: boolean;
  service_version: string | null;
  error: string | null;
}

export function isElectron(): boolean {
  return typeof window !== 'undefined' && Boolean((window as any).electronAPI);
}

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

export function isDesktop(): boolean {
  return isElectron() || isTauri();
}

export async function callAegis<T = any>(request: AegisRequest): Promise<T> {
  if (isElectron()) {
    try {
      const data = await (window as any).electronAPI.aegisCall(request);
      return data as T;
    } catch (err: any) {
      throw err;
    }
  }

  if (isTauri()) {
    try {
      const data = await invoke<T>('aegis_call', { request });
      return data;
    } catch (err: any) {
      throw err;
    }
  }

  throw {
    code: 'unavailable' as ErrorCode,
    message: 'Not connected: Application is running outside desktop runtime. Please launch using the desktop app.',
  };
}

export async function getConnectionInfo(): Promise<ConnectionInfo> {
  if (isElectron()) {
    try {
      return await (window as any).electronAPI.getConnectionInfo();
    } catch (err: any) {
      return {
        connected: false,
        mode: null,
        pipe: null,
        privileged_allowed: false,
        service_version: null,
        error: String(err),
      };
    }
  }

  if (isTauri()) {
    try {
      return await invoke<ConnectionInfo>('aegis_connection');
    } catch (err: any) {
      return {
        connected: false,
        mode: null,
        pipe: null,
        privileged_allowed: false,
        service_version: null,
        error: String(err),
      };
    }
  }

  return {
    connected: false,
    mode: null,
    pipe: null,
    privileged_allowed: false,
    service_version: null,
    error: 'Running outside desktop runtime',
  };
}

export async function startUserEngine(): Promise<ConnectionInfo> {
  if (isElectron()) {
    return await (window as any).electronAPI.startUserEngine();
  }
  if (isTauri()) {
    return await invoke<ConnectionInfo>('aegis_start_user_engine');
  }
  throw new Error('Running outside desktop runtime');
}

export async function openPath(path: string): Promise<boolean> {
  if (isElectron()) {
    try {
      return await (window as any).electronAPI.openPath(path);
    } catch (e) {
      console.error('Failed to open path in Electron:', e);
      return false;
    }
  } else if (isTauri()) {
    try {
      await invoke('aegis_open_path', { path });
      return true;
    } catch (e) {
      console.error('Failed to open path in Tauri:', e);
      return false;
    }
  }
  return false;
}

export async function installBrowserExtension(browser: string): Promise<{ success: boolean; message: string }> {
  if (isElectron()) {
    try {
      return await (window as any).electronAPI.installBrowserExtension(browser);
    } catch (e: any) {
      return { success: false, message: e.message || String(e) };
    }
  }
  return { success: false, message: 'Tarayıcı eklentisi yükleme yalnızca masaüstü uygulamasında desteklenir.' };
}
