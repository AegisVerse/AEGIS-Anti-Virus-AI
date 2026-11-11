import { create } from 'zustand';
import tr from '../locales/tr.json';
import en from '../locales/en.json';
import type { ConnectionInfo } from '../services/aegis';

type Language = 'tr' | 'en';
type Theme = 'dark' | 'light';

interface AppState {
  language: Language;
  theme: Theme;
  activePage: string;
  connection: ConnectionInfo;
  setLanguage: (lang: Language) => void;
  setTheme: (theme: Theme) => void;
  setActivePage: (page: string) => void;
  setConnection: (conn: ConnectionInfo) => void;
  t: (path: string) => string;
}

const translations: Record<Language, any> = { tr, en };

export const useAppStore = create<AppState>((set, get) => ({
  language: 'tr',
  theme: 'dark',
  activePage: 'dashboard',
  connection: {
    connected: false,
    mode: null,
    pipe: null,
    privileged_allowed: false,
    service_version: null,
    error: null,
  },
  setLanguage: (lang) => {
    localStorage.setItem('aegis_lang', lang);
    set({ language: lang });
  },
  setTheme: (theme) => {
    localStorage.setItem('aegis_theme', theme);
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    set({ theme });
  },
  setActivePage: (page) => set({ activePage: page }),
  setConnection: (conn) => set({ connection: conn }),
  t: (path: string) => {
    const lang = get().language;
    const dict = translations[lang] || translations.tr;
    const parts = path.split('.');
    let cur = dict;
    for (const p of parts) {
      if (cur && typeof cur === 'object' && p in cur) {
        cur = cur[p];
      } else {
        return path;
      }
    }
    return typeof cur === 'string' ? cur : path;
  },
}));

