import { create } from 'zustand';
import tr from '../locales/tr.json';
import en from '../locales/en.json';
import de from '../locales/de.json';
import es from '../locales/es.json';
import fr from '../locales/fr.json';
import ru from '../locales/ru.json';
import type { ConnectionInfo } from '../services/aegis';

export type Language = 'tr' | 'en' | 'de' | 'es' | 'fr' | 'ru';
export type Theme = 'dark' | 'light';

export const SUPPORTED_LANGUAGES: { code: Language; label: string; flag: string }[] = [
  { code: 'tr', label: 'Türkçe', flag: '🇹🇷' },
  { code: 'en', label: 'English', flag: '🇬🇧' },
  { code: 'de', label: 'Deutsch', flag: '🇩🇪' },
  { code: 'es', label: 'Español', flag: '🇪🇸' },
  { code: 'fr', label: 'Français', flag: '🇫🇷' },
  { code: 'ru', label: 'Русский', flag: '🇷🇺' },
];

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

const translations: Record<Language, any> = { tr, en, de, es, fr, ru };

const savedLang = (typeof localStorage !== 'undefined' ? localStorage.getItem('aegis_lang') : null) as Language | null;
const initialLang: Language = savedLang && savedLang in translations ? savedLang : 'tr';

export const useAppStore = create<AppState>((set, get) => ({
  language: initialLang,
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

