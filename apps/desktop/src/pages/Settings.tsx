import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, Shield, Cpu, Bell, HardDrive, Bot, Lock, Wifi, RefreshCw, Globe, Check } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore, SUPPORTED_LANGUAGES, type Language } from '../stores/useAppStore';
import type { Settings } from '../types/aegis';

export function SettingsPage() {
  const { language, setLanguage, theme, setTheme } = useAppStore();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saving, setSaving] = useState(false);

  const fetchSettings = async () => {
    try {
      const res = await callAegis<Settings>({ cmd: 'get_settings' });
      setSettings(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleSave = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await callAegis<Settings>({ cmd: 'update_settings', args: { settings } });
      setSettings(updated);
      alert('Ayarlar başarıyla kaydedildi.');
    } catch (e: any) {
      alert(e.message || String(e));
    } finally {
      setSaving(false);
    }
  };

  if (!settings) {
    return (
      <div className="flex items-center justify-center h-full text-slate-400">
        <RefreshCw className="w-6 h-6 animate-spin mr-2" />
        <span>Ayarlar yükleniyor...</span>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header and Save Button */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <SettingsIcon className="w-6 h-6 text-cyan-400" />
            <span>Genel Güvenlik ve Sistem Ayarları</span>
          </h2>
          <p className="text-xs text-slate-400">
            Tarama limitleri, koruma modülleri, yerel AI uç noktası ve gizlilik tercihleri.
          </p>
        </div>

        <button
          disabled={saving}
          onClick={handleSave}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
        >
          <Save className="w-4 h-4" />
          <span>Ayarları Kaydet</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Language Selection Card */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4 md:col-span-2">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>{language === 'tr' ? 'Uygulama Dili / Language' : 'Application Language'}</span>
            </h3>
            <span className="text-xs text-slate-400">
              {SUPPORTED_LANGUAGES.find((l) => l.code === language)?.label} ({language.toUpperCase()})
            </span>
          </div>

          <p className="text-xs text-slate-400">
            {language === 'tr'
              ? 'Tüm menüler, koruma başlıkları, bildirimler ve arayüz seçilen dilde anında güncellenir.'
              : 'All menus, protection titles, alerts, and interface labels update instantly in your selected language.'}
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2">
            {SUPPORTED_LANGUAGES.map((item) => {
              const isSelected = language === item.code;
              return (
                <button
                  key={item.code}
                  type="button"
                  onClick={() => setLanguage(item.code)}
                  className={`flex items-center justify-between p-3 rounded-xl border text-xs font-semibold transition-all cursor-pointer ${
                    isSelected
                      ? 'border-cyan-500 bg-cyan-500/10 text-cyan-300 shadow-md shadow-cyan-500/10'
                      : 'border-slate-800 bg-slate-950/60 text-slate-400 hover:text-white hover:border-slate-700'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <span className="text-base">{item.flag}</span>
                    <span>{item.label}</span>
                  </span>
                  {isSelected && <Check className="w-4 h-4 text-cyan-400" />}
                </button>
              );
            })}
          </div>
        </div>
        {/* Core Protection Preferences */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>Çekirdek Koruma & Eylem Politikası</span>
          </h3>

          <div className="space-y-4 text-xs">
            <div>
              <label className="text-slate-300 font-semibold block mb-1">Otomatik Müdahale Davranışı</label>
              <select
                value={settings.auto_action}
                onChange={(e) => setSettings({ ...settings, auto_action: e.target.value as any })}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white"
              >
                <option value="notify_only">Yalnızca Bildir (Kullanıcı Onayı İste)</option>
                <option value="quarantine_confirmed">Onaylanmış Tehditleri Otomatik Karantinaya Al</option>
              </select>
            </div>

            <div className="flex items-center justify-between py-2 border-t border-slate-800/60">
              <div>
                <p className="font-semibold text-white">Oyun Modu (Gaming Mode)</p>
                <p className="text-[11px] text-slate-400">Tam ekran uygulamalarda arka plan taramalarını ve bildirimleri erteler.</p>
              </div>
              <input
                type="checkbox"
                checked={settings.gaming_mode}
                onChange={(e) => setSettings({ ...settings, gaming_mode: e.target.checked })}
                className="w-4 h-4"
              />
            </div>

            <div className="flex items-center justify-between py-2 border-t border-slate-800/60">
              <div>
                <p className="font-semibold text-white">Fidye Kalkanı (Ransomware Shield)</p>
                <p className="text-[11px] text-slate-400">Kitlesel dosya değişikliği ve şifreleme uzantısı tespiti.</p>
              </div>
              <input
                type="checkbox"
                checked={settings.ransomware_enabled}
                onChange={(e) => setSettings({ ...settings, ransomware_enabled: e.target.checked })}
                className="w-4 h-4"
              />
            </div>
          </div>
        </div>

        {/* Scanner Engine Limits */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <HardDrive className="w-4 h-4 text-cyan-400" />
            <span>Tarayıcı Limitleri & Arşiv Güvenliği</span>
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-300">ZIP Arşivlerini İncele</span>
              <input
                type="checkbox"
                checked={settings.scan_archives}
                onChange={(e) => setSettings({ ...settings, scan_archives: e.target.checked })}
                className="w-4 h-4"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Maksimum Arşiv Derinliği</span>
              <input
                type="number"
                min="1"
                max="10"
                value={settings.max_archive_depth}
                onChange={(e) => setSettings({ ...settings, max_archive_depth: Number(e.target.value) })}
                className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-white font-mono text-right"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Maksimum Genişletilmiş Boyut (MB)</span>
              <input
                type="number"
                min="16"
                max="2048"
                value={settings.max_archive_expanded_mb}
                onChange={(e) => setSettings({ ...settings, max_archive_expanded_mb: Number(e.target.value) })}
                className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-white font-mono text-right"
              />
            </div>

            <div className="flex items-center justify-between">
              <span className="text-slate-300">Düşük Öncelikli Tarama (CPU Koruması)</span>
              <input
                type="checkbox"
                checked={settings.low_priority_scans}
                onChange={(e) => setSettings({ ...settings, low_priority_scans: e.target.checked })}
                className="w-4 h-4"
              />
            </div>
          </div>
        </div>

        {/* Local AI Endpoint */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Bot className="w-4 h-4 text-cyan-400" />
            <span>Yerel Yapay Zeka Analisti (Ollama / Local LLM)</span>
          </h3>

          <div className="space-y-3 text-xs">
            <div>
              <label className="text-slate-300 font-semibold block mb-1">Yerel LLM API Uç Noktası</label>
              <input
                type="text"
                value={settings.analyst_endpoint}
                onChange={(e) => setSettings({ ...settings, analyst_endpoint: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs"
                placeholder="http://127.0.0.1:11434"
              />
            </div>

            <div>
              <label className="text-slate-300 font-semibold block mb-1">Model Adı</label>
              <input
                type="text"
                value={settings.analyst_model}
                onChange={(e) => setSettings({ ...settings, analyst_model: e.target.value })}
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-800 text-white font-mono text-xs"
                placeholder="llama3.2:3b"
              />
            </div>

            <p className="text-[11px] text-slate-400 pt-1">
              Ollama çalışmıyorsa sistem otomatik olarak yerel kural tabanlı uzman analiz motoruna geçer.
            </p>
          </div>
        </div>

        {/* Privacy & Telemetry */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/40 backdrop-blur-md space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <span>Gizlilik ve Telemetri Bildirimi</span>
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between py-1">
              <div>
                <p className="font-semibold text-white">Anonim Hata Telemetrisi</p>
                <p className="text-[11px] text-slate-400">Varsayılan olarak KAPALIDIR. Kullanıcı dosyaları veya geçmişi asla gönderilmez.</p>
              </div>
              <input
                type="checkbox"
                checked={settings.telemetry_enabled}
                onChange={(e) => setSettings({ ...settings, telemetry_enabled: e.target.checked })}
                className="w-4 h-4"
              />
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/60">
              <span className="text-slate-300">Olay Günlüğü Saklama Süresi (Gün)</span>
              <input
                type="number"
                min="7"
                max="365"
                value={settings.event_retention_days}
                onChange={(e) => setSettings({ ...settings, event_retention_days: Number(e.target.value) })}
                className="w-20 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-white font-mono text-right"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

