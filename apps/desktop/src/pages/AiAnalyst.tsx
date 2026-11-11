import React, { useState, useEffect } from 'react';
import { Bot, Send, ShieldAlert, Cpu, Sparkles, AlertCircle, Info, RefreshCw } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { useAppStore } from '../stores/useAppStore';
import type { AiStatus, AnalystAnswer, SourceRef } from '../types/aegis';

interface Message {
  sender: 'user' | 'assistant';
  text: string;
  sources?: SourceRef[];
  backend?: string;
  warnings?: string[];
  ts: string;
}

export function AiAnalyst() {
  const { language, t } = useAppStore();
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'assistant',
      text:
        language === 'tr'
          ? 'Merhaba, ben AEGIS Yerel Güvenlik Analistiyim. Bilgisayarınızdaki güvenlik olayları, şüpheli işlemler ve koruma durumu hakkında sorularınızı yanıtlayabilirim. Nasıl yardımcı olabilirim?'
          : 'Hello, I am the AEGIS Local Security Analyst. I can answer questions about your security events, suspicious processes, and protection posture based strictly on real telemetry. How can I help?',
      ts: new Date().toLocaleTimeString(),
    },
  ]);

  const quickQuestions =
    language === 'tr'
      ? [
          'Bilgisayarımda RAT belirtisi var mı?',
          'Son 24 saatte neler engellendi?',
          'Bu EXE neden şüpheli?',
          'Bilgisayarım neden yavaşladı?',
          'Tarayıcıma reklam virüsü bulaşmış olabilir mi?',
          'Bu internet bağlantısı ne işe yarıyor?',
        ]
      : [
          'Are there any signs of a RAT on my PC?',
          'What was blocked in the last 24 hours?',
          'Why is this EXE considered suspicious?',
          'Why did my PC slow down?',
          'Could my browser be infected with adware?',
          'What is this network connection used for?',
        ];

  const fetchStatus = async () => {
    try {
      const res = await callAegis<AiStatus>({ cmd: 'get_ai_status' });
      setAiStatus(res);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleSend = async (questionText?: string) => {
    const q = questionText || input;
    if (!q.trim() || loading) return;

    const userMsg: Message = {
      sender: 'user',
      text: q,
      ts: new Date().toLocaleTimeString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const ans = await callAegis<AnalystAnswer>({
        cmd: 'ask_analyst',
        args: { question: q, language },
      });

      const assistantMsg: Message = {
        sender: 'assistant',
        text: ans.answer,
        sources: ans.sources,
        backend: ans.backend,
        warnings: ans.warnings,
        ts: new Date().toLocaleTimeString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e: any) {
      const errorMsg: Message = {
        sender: 'assistant',
        text: `Hata: ${e.message || String(e)}`,
        ts: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 flex flex-col h-[calc(100vh-4rem)] space-y-6">
      {/* Header and Model Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Bot className="w-6 h-6 text-cyan-400" />
            <span>Yapay Zeka Güvenlik Analisti</span>
          </h2>
          <p className="text-xs text-slate-400">
            Gerçek veritabanı kayıtları ve işlem olaylarına dayalı yerel güvenlik asistanı.
          </p>
        </div>

        {/* Model Status Badge */}
        <div className="flex items-center gap-2 text-xs">
          <div className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>
              {aiStatus?.classifier_detail || 'AI sınıflandırma modeli henüz kurulmadı.'}
            </span>
          </div>
        </div>
      </div>

      {/* Read-Only Safeguard Banner */}
      <div className="p-3.5 rounded-xl border border-cyan-500/20 bg-cyan-950/20 text-cyan-300 text-xs flex items-center gap-3">
        <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0" />
        <p className="leading-relaxed">
          <strong>Güvenlik Prensibi:</strong> Analist yalnızca salt-okunur (read-only) güvenlik telemetrisini
          özetler ve açıklar. Asistan asla otomatik olarak sistem ayarlarını değiştiremez veya komut istemi çalıştıramaz.
        </p>
      </div>

      {/* Chat Messages Log */}
      <div className="flex-1 overflow-y-auto space-y-4 p-5 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md scrollbar-thin">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div
              className={`max-w-2xl p-4 rounded-2xl text-xs leading-relaxed space-y-2 ${
                m.sender === 'user'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white rounded-br-none shadow-lg shadow-cyan-500/10'
                  : 'bg-slate-950 border border-slate-800 text-slate-200 rounded-bl-none'
              }`}
            >
              <p className="whitespace-pre-wrap">{m.text}</p>

              {/* Source chips */}
              {m.sources && m.sources.length > 0 && (
                <div className="pt-2 border-t border-slate-800/80 space-y-1">
                  <p className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                    Kaynak Referansları ({m.backend}):
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {m.sources.map((s, sIdx) => (
                      <span
                        key={sIdx}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-slate-800"
                        title={s.label}
                      >
                        {s.label}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {m.warnings && m.warnings.length > 0 && (
                <p className="text-[10px] text-amber-400 italic pt-1">
                  {m.warnings.join(' • ')}
                </p>
              )}
            </div>
            <span className="text-[10px] text-slate-500 mt-1 px-1 font-mono">{m.ts}</span>
          </div>
        ))}

        {loading && (
          <div className="flex items-center gap-2 text-xs text-slate-400 p-2">
            <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
            <span>Sistem telemetrisi inceleniyor ve yanıt oluşturuluyor...</span>
          </div>
        )}
      </div>

      {/* Suggested Questions */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
        {quickQuestions.map((q, i) => (
          <button
            key={i}
            onClick={() => handleSend(q)}
            className="px-3 py-1.5 rounded-lg text-[11px] font-medium bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 whitespace-nowrap transition-all cursor-pointer"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Chat Input */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder="Güvenlik durumunuz hakkında bir soru sorun..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSend()}
          className="flex-1 px-4 py-3 rounded-xl text-xs bg-slate-900 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
        />
        <button
          disabled={loading || !input.trim()}
          onClick={() => handleSend()}
          className="px-5 py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer"
        >
          <Send className="w-4 h-4" />
          <span>Gönder</span>
        </button>
      </div>
    </div>
  );
}

