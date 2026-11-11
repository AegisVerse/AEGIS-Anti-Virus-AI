import React, { useEffect, useState } from 'react';
import { Sidebar } from './components/layout/Sidebar';
import { TopBar } from './components/layout/TopBar';
import { SplashScreen } from './components/layout/SplashScreen';
import { useAppStore } from './stores/useAppStore';
import { getConnectionInfo, startUserEngine } from './services/aegis';

// Import all 18 pages
import { Dashboard } from './pages/Dashboard';
import { SecurityScan } from './pages/SecurityScan';
import { RealTimeProtection } from './pages/RealTimeProtection';
import { ThreatCenter } from './pages/ThreatCenter';
import { Quarantine } from './pages/Quarantine';
import { RatSpyware } from './pages/RatSpyware';
import { MemoryMonitoring } from './pages/MemoryMonitoring';
import { RansomwareProtection } from './pages/RansomwareProtection';
import { NetworkSecurity } from './pages/NetworkSecurity';
import { WebAdProtection } from './pages/WebAdProtection';
import { StartupProtection } from './pages/StartupProtection';
import { UsbSecurity } from './pages/UsbSecurity';
import { SystemAudit } from './pages/SystemAudit';
import { AiAnalyst } from './pages/AiAnalyst';
import { SecurityHistory } from './pages/SecurityHistory';
import { Updates } from './pages/Updates';
import { SettingsPage } from './pages/Settings';
import { AboutDiagnostics } from './pages/AboutDiagnostics';

export function App() {
  const { activePage, connection, setConnection, t } = useAppStore();
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    const checkConn = async () => {
      const conn = await getConnectionInfo();
      setConnection(conn);
    };
    checkConn();
    const interval = setInterval(checkConn, 5000);
    return () => clearInterval(interval);
  }, [setConnection]);

  const renderPage = () => {
    switch (activePage) {
      case 'dashboard':
        return <Dashboard />;
      case 'scan':
        return <SecurityScan />;
      case 'realtime':
        return <RealTimeProtection />;
      case 'threats':
        return <ThreatCenter />;
      case 'quarantine':
        return <Quarantine />;
      case 'rat':
        return <RatSpyware />;
      case 'memory':
        return <MemoryMonitoring />;
      case 'ransomware':
        return <RansomwareProtection />;
      case 'network':
        return <NetworkSecurity />;
      case 'web':
        return <WebAdProtection />;
      case 'startup':
        return <StartupProtection />;
      case 'usb':
        return <UsbSecurity />;
      case 'audit':
        return <SystemAudit />;
      case 'ai':
        return <AiAnalyst />;
      case 'history':
        return <SecurityHistory />;
      case 'updates':
        return <Updates />;
      case 'settings':
        return <SettingsPage />;
      case 'about':
        return <AboutDiagnostics />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <>
      {showSplash && <SplashScreen onFinish={() => setShowSplash(false)} />}
      <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <TopBar />
          <main className="flex-1 overflow-hidden relative bg-slate-950/50">
            {renderPage()}
          </main>
        </div>
      </div>
    </>
  );
}
export default App;

