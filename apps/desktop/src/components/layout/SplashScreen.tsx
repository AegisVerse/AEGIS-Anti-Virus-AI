import React, { useState, useEffect } from 'react';
import { ShieldCheck, Cpu, Database, Activity, Lock, CheckCircle2 } from 'lucide-react';

interface SplashScreenProps {
  onFinish: () => void;
}

const STEPS = [
  { label: 'Yerel YARA-X Kural Motoru Yükleniyor...', progress: 20, icon: Cpu },
  { label: 'Fidye Kalkanı ve Bellek Denetleyicisi Aktifleştiriliyor...', progress: 45, icon: Lock },
  { label: 'RAT & Casus Yazılım İzleme Sensörleri Başlatılıyor...', progress: 70, icon: Activity },
  { label: 'Yerel SQLite Adli Kayıt Veritabanı Doğrulanıyor...', progress: 90, icon: Database },
  { label: 'AEGIS AI Security Çekirdeği Hazır • Sistem Korumada', progress: 100, icon: ShieldCheck },
];

export function SplashScreen({ onFinish }: SplashScreenProps) {
  const [stepIndex, setStepIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [fadingOut, setFadingOut] = useState(false);

  useEffect(() => {
    // Step progression timer
    const interval = setInterval(() => {
      setStepIndex((prev) => {
        if (prev < STEPS.length - 1) {
          return prev + 1;
        } else {
          clearInterval(interval);
          setTimeout(() => {
            setFadingOut(true);
            setTimeout(onFinish, 600);
          }, 400);
          return prev;
        }
      });
    }, 550);

    return () => clearInterval(interval);
  }, [onFinish]);

  // Smooth progress animation
  useEffect(() => {
    const target = STEPS[stepIndex].progress;
    const progressTimer = setInterval(() => {
      setProgress((cur) => {
        if (cur < target) {
          return Math.min(target, cur + 2);
        }
        return cur;
      });
    }, 20);

    return () => clearInterval(progressTimer);
  }, [stepIndex]);

  // Keyboard skip on Space or Enter
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.code === 'Space' || e.code === 'Enter') {
        setFadingOut(true);
        setTimeout(onFinish, 300);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onFinish]);

  const CurrentIcon = STEPS[stepIndex].icon;

  return (
    <div
      className={`fixed inset-0 z-50 flex flex-col items-center justify-center bg-slate-950 text-white select-none transition-opacity duration-700 ${
        fadingOut ? 'opacity-0 pointer-events-none' : 'opacity-100'
      }`}
      style={{
        background: 'radial-gradient(circle at 50% 45%, #082f49 0%, #030712 60%, #020617 100%)',
      }}
    >
      {/* Ambient background glows */}
      <div className="absolute w-[600px] h-[600px] rounded-full bg-cyan-500/10 blur-[120px] pointer-events-none animate-pulse" />
      <div className="absolute w-[400px] h-[400px] rounded-full bg-blue-600/10 blur-[90px] pointer-events-none" />

      {/* Main 3D Card Container */}
      <div className="relative flex flex-col items-center text-center space-y-6 max-w-md px-6 z-10 aegis-3d-wrapper">
        {/* 3D Animated Logo Emblem */}
        <div className="relative flex items-center justify-center">
          {/* Outer glowing aura rings */}
          <div className="absolute inset-0 rounded-full border border-cyan-500/20 w-44 h-44 -m-4 animate-ping opacity-25" />
          <div className="absolute inset-0 rounded-full border border-cyan-400/30 w-40 h-40 -m-2 animate-spin-slow opacity-60" />

          {/* Logo with 3D tilt & drop shadow */}
          <div className="w-36 h-36 relative flex items-center justify-center aegis-3d-logo">
            <img
              src="./logo.png"
              alt="AEGIS AI Security Logo"
              className="w-full h-full object-contain drop-shadow-[0_0_35px_rgba(6,182,212,0.7)]"
            />
          </div>
        </div>

        {/* Title & Brand */}
        <div className="space-y-1.5 pt-2">
          <h1 className="text-2xl font-black tracking-[0.25em] text-white font-mono flex items-center justify-center gap-2 drop-shadow-[0_2px_10px_rgba(6,182,212,0.4)]">
            <span>AEGIS</span>
            <span className="text-cyan-400">AI</span>
            <span>SECURITY</span>
          </h1>
          <p className="text-[11px] font-semibold text-cyan-400/90 tracking-widest uppercase font-mono">
            Yeni Nesil Yerel Uç Nokta Güvenliği
          </p>
        </div>

        {/* Dynamic Progress Indicator */}
        <div className="w-80 space-y-3 pt-4">
          <div className="w-full h-1.5 rounded-full bg-slate-900 border border-slate-800 overflow-hidden relative">
            <div
              className="h-full bg-gradient-to-r from-cyan-500 via-blue-500 to-cyan-400 transition-all duration-300 ease-out shadow-[0_0_12px_rgba(6,182,212,0.8)]"
              style={{ width: `${progress}%` }}
            />
          </div>

          {/* Current Loading Subsystem Status */}
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 h-5 px-1">
            <div className="flex items-center gap-1.5 truncate">
              <CurrentIcon className="w-3.5 h-3.5 text-cyan-400 shrink-0 animate-pulse" />
              <span className="text-[11px] text-slate-300 truncate">
                {STEPS[stepIndex].label}
              </span>
            </div>
            <span className="text-cyan-400 font-bold text-[11px] shrink-0 ml-2">
              %{progress}
            </span>
          </div>
        </div>

        {/* Skip hint */}
        <div className="pt-2">
          <button
            onClick={() => {
              setFadingOut(true);
              setTimeout(onFinish, 300);
            }}
            className="text-[10px] text-slate-500 hover:text-cyan-400 transition-colors font-mono cursor-pointer"
          >
            Atlamak için [Boşluk] tuşuna basın veya tıklayın
          </button>
        </div>
      </div>

      {/* Footer System Specs */}
      <div className="absolute bottom-6 flex items-center gap-4 text-[10px] text-slate-600 font-mono">
        <span>v0.1.0 (x86_64)</span>
        <span>•</span>
        <span>YARA-X Core Engine</span>
        <span>•</span>
        <span>Sıfır Telemetri • Yerel Koruma</span>
      </div>
    </div>
  );
}

