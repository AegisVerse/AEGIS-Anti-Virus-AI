import { describe, it, expect, beforeEach } from 'vitest';
import trLocale from '../locales/tr.json';
import enLocale from '../locales/en.json';
import { useAppStore } from '../stores/useAppStore';

describe('Localization parity', () => {
  it('has identical top-level keys between TR and EN locales', () => {
    const trKeys = Object.keys(trLocale).sort();
    const enKeys = Object.keys(enLocale).sort();
    expect(trKeys).toEqual(enKeys);
  });

  it('contains expected categories in both languages', () => {
    const requiredSections = ['app', 'nav', 'status', 'actions', 'common'];
    for (const section of requiredSections) {
      expect(trLocale).toHaveProperty(section);
      expect(enLocale).toHaveProperty(section);
    }
  });

  it('translates app name and basic navigation', () => {
    expect(trLocale.app.name).toBe('AEGIS AI Security');
    expect(enLocale.app.name).toBe('AEGIS AI Security');
    expect(trLocale.nav.dashboard).toBeDefined();
    expect(enLocale.nav.dashboard).toBeDefined();
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

  it('toggles language between TR and EN', () => {
    expect(useAppStore.getState().language).toBe('tr');
    useAppStore.getState().setLanguage('en');
    expect(useAppStore.getState().language).toBe('en');
    useAppStore.getState().setLanguage('tr');
    expect(useAppStore.getState().language).toBe('tr');
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
