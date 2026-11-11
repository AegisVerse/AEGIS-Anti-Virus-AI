import React, { useState, useRef, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, Wifi, WifiOff, Globe, RefreshCw, ChevronDown, Check } from 'lucide-react';
import { useAppStore, SUPPORTED_LANGUAGES, type Language } from '../../stores/useAppStore';
import { getConnectionInfo, startUserEngine } from '../../services/aegis';

export function TopBar() {
  const { language, setLanguage, connection, setConnection, activePage, t } = useAppStore();
  const [langMenuOpen, setLangMenuOpen] = useState(false);
  const langMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (langMenuRef.current && !langMenuRef.current.contains(e.target as Node)) {
        setLangMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const currentLang = SUPPORTED_LANGUAGES.find((l) => l.code === language) || SUPPORTED_LANGUAGES[0];

  const handleRefreshConnection = async () => {
    const conn = await getConnectionInfo();
    setConnection(conn);
  };

  const handleStartUser = async () => {
    try {
      const conn = await startUserEngine();
      setConnection(conn);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <header className="h-16 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-xl px-6 flex items-center justify-between select-none">
      {/* Title */}
      <div>
        <h2 className="text-base font-bold text-white capitalize">
          {t(`nav.${activePage}`)}
        </h2>
        <p className="text-xs text-slate-400">
          AEGIS AI • {t('app.tagline')}
        </p>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-4">
        {/* Connection status badge */}
        <div className="flex items-center gap-2">
          {connection.connected ? (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>
                {connection.mode === 'service' ? t('app.service_mode') : t('app.user_mode')}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
                <span className="w-2 h-2 rounded-full bg-rose-400" />
                <span>{t('app.disconnected')}</span>
              </div>
              <button
                onClick={handleStartUser}
                className="px-2.5 py-1 text-xs rounded-lg font-medium border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                title={t('app.start_user_engine')}
              >
                {t('app.start_user_engine')}
              </button>
            </div>
          )}

          <button
            onClick={handleRefreshConnection}
            className="p-1.5 rounded-lg border border-slate-800 text-slate-400 hover:text-white hover:bg-slate-900 transition-colors"
            title={t('app.retry')}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="h-4 w-px bg-slate-800" />

        {/* Language selector dropdown */}
        <div className="relative" ref={langMenuRef}>
          <button
            onClick={() => setLangMenuOpen(!langMenuOpen)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border border-slate-800 bg-slate-900/60 text-slate-300 hover:text-white hover:border-slate-700 transition-colors cursor-pointer"
            title="Dili Değiştir / Select Language"
          >
            <Globe className="w-3.5 h-3.5 text-cyan-400" />
            <span>{currentLang.flag}</span>
            <span className="font-bold">{currentLang.code.toUpperCase()}</span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {langMenuOpen && (
            <div className="absolute right-0 mt-2 w-44 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl py-1.5 z-50 backdrop-blur-xl animate-in fade-in zoom-in-95 duration-100">
              <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800 mb-1">
                Dil / Language
              </div>
              {SUPPORTED_LANGUAGES.map((item) => (
                <button
                  key={item.code}
                  onClick={() => {
                    setLanguage(item.code);
                    setLangMenuOpen(false);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-1.5 text-xs text-left transition-colors cursor-pointer ${
                    language === item.code
                      ? 'bg-cyan-500/10 text-cyan-400 font-bold'
                      : 'text-slate-300 hover:bg-slate-800/80 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <span>{item.flag}</span>
                    <span>{item.label}</span>
                  </span>
                  {language === item.code && <Check className="w-3.5 h-3.5 text-cyan-400" />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

