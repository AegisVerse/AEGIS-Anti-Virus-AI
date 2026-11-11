import React from 'react';
import { ShieldCheck, ShieldAlert, Wifi, WifiOff, Globe, RefreshCw } from 'lucide-react';
import { useAppStore } from '../../stores/useAppStore';
import { getConnectionInfo, startUserEngine } from '../../services/aegis';

export function TopBar() {
  const { language, setLanguage, connection, setConnection, activePage, t } = useAppStore();

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

        {/* Language selector */}
        <button
          onClick={() => setLanguage(language === 'tr' ? 'en' : 'tr')}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border border-slate-800 bg-slate-900/60 text-slate-300 hover:text-white transition-colors cursor-pointer"
        >
          <Globe className="w-3.5 h-3.5 text-cyan-400" />
          <span>{language.toUpperCase()}</span>
        </button>
      </div>
    </header>
  );
}

