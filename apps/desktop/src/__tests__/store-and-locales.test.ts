import { describe, it, expect, beforeEach } from 'vitest';
import trLocale from '../locales/tr.json';
import enLocale from '../locales/en.json';
import deLocale from '../locales/de.json';
import esLocale from '../locales/es.json';
import frLocale from '../locales/fr.json';
import ruLocale from '../locales/ru.json';
import { useAppStore, SUPPORTED_LANGUAGES } from '../stores/useAppStore';

describe('Localization parity', () => {
  const allLocales = [trLocale, enLocale, deLocale, esLocale, frLocale, ruLocale];

  it('has identical top-level keys across all locales', () => {
    const trKeys = Object.keys(trLocale).sort();
    for (const loc of allLocales) {
      expect(Object.keys(loc).sort()).toEqual(trKeys);
    }
  });

  it('contains expected categories in all languages', () => {
    const requiredSections = ['app', 'nav', 'status', 'actions', 'common'];
    for (const loc of allLocales) {
      for (const section of requiredSections) {
        expect(loc).toHaveProperty(section);
      }
    }
  });

  it('translates app name and basic navigation across all languages', () => {
    for (const loc of allLocales) {
      expect(loc.app.name).toBe('AEGIS AI Security');
      expect(loc.nav.dashboard).toBeDefined();
    }
  });
});

describe('useAppStore', () => {
  beforeEach(() => {
    useAppStore.setState({
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
    });
  });

  it('switches between all supported languages', () => {
    expect(useAppStore.getState().language).toBe('tr');
    for (const lang of SUPPORTED_LANGUAGES) {
      useAppStore.getState().setLanguage(lang.code);
      expect(useAppStore.getState().language).toBe(lang.code);
      expect(useAppStore.getState().t('app.name')).toBe('AEGIS AI Security');
    }
  });

  it('toggles theme between dark and light', () => {
    expect(useAppStore.getState().theme).toBe('dark');
    useAppStore.getState().setTheme('light');
    expect(useAppStore.getState().theme).toBe('light');
  });

  it('updates activePage smoothly', () => {
    expect(useAppStore.getState().activePage).toBe('dashboard');
    useAppStore.getState().setActivePage('quarantine');
    expect(useAppStore.getState().activePage).toBe('quarantine');
  });

  it('translates string using t helper', () => {
    useAppStore.getState().setLanguage('tr');
    expect(useAppStore.getState().t('app.name')).toBe('AEGIS AI Security');
    expect(useAppStore.getState().t('nav.dashboard')).toBe(trLocale.nav.dashboard);

    useAppStore.getState().setLanguage('en');
    expect(useAppStore.getState().t('nav.dashboard')).toBe(enLocale.nav.dashboard);
  });

  it('updates connection state', () => {
    expect(useAppStore.getState().connection.connected).toBe(false);
    useAppStore.getState().setConnection({
      connected: true,
      mode: 'service',
      pipe: '\\\\.\\pipe\\aegis-ai-security.v1',
      privileged_allowed: true,
      service_version: '0.1.0',
      error: null,
    });
    expect(useAppStore.getState().connection.connected).toBe(true);
    expect(useAppStore.getState().connection.mode).toBe('service');
  });
});
