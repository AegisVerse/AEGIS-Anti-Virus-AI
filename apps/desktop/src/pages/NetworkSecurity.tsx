import React, { useState, useEffect } from 'react';
import { Wifi, ShieldAlert, Ban, Check, Search, AlertCircle } from 'lucide-react';
import { callAegis } from '../services/aegis';
import { ReputationBadge } from '../components/ui/Badge';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import type { ConnectionInfo, DomainProtectionStatus } from '../types/aegis';

export function NetworkSecurity() {
  const [connections, setConnections] = useState<ConnectionInfo[]>([]);
  const [domainStatus, setDomainStatus] = useState<DomainProtectionStatus | null>(null);
  const [blockIpTarget, setBlockIpTarget] = useState<string | null>(null);
  const [search, setSearch] = useState('');

  const fetchData = async () => {
    try {
      const conns = await callAegis<ConnectionInfo[]>({ cmd: 'list_connections' });
      setConnections(conns);
      const ds = await callAegis<DomainProtectionStatus>({ cmd: 'get_domain_status' });
      setDomainStatus(ds);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleBlockIp = async () => {
    if (!blockIpTarget) return;
    try {
      await callAegis({ cmd: 'block_ip', args: { ip: blockIpTarget, confirm: true } });
      setBlockIpTarget(null);
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const handleUnblockIp = async (ip: string) => {
    try {
      await callAegis({ cmd: 'unblock_ip', args: { ip } });
      fetchData();
    } catch (e: any) {
      alert(e.message || String(e));
    }
  };

  const filteredConnections = connections.filter(
    (c) =>
      (c.remote_addr && c.remote_addr.includes(search)) ||
      (c.process_name && c.process_name.toLowerCase().includes(search.toLowerCase())) ||
      String(c.pid).includes(search)
  );

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)] scrollbar-thin">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Wifi className="w-6 h-6 text-cyan-400" />
          <span>Ağ Güvenliği & Bağlantı Gözetmeni</span>
        </h2>
        <p className="text-xs text-slate-400">
          Uygulamaların yerel ve uzak IP/port bağlantıları, soket durumları ve Windows Güvenlik Duvarı IP engelleme.
        </p>
      </div>

      {/* Network Reputation Principle Notice */}
      <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/60 text-xs text-slate-300 flex items-center gap-3">
        <AlertCircle className="w-5 h-5 text-cyan-400 flex-shrink-0" />
        <p className="leading-relaxed">
          <strong>İtibar İlkesi:</strong> "Bilinmeyen (UNKNOWN)" durumu, o IP adresinin zararlı olduğu anlamına gelmez.
          Yalnızca kurumsal onaylı veya bilinen C2 listelerinde kayıtlı olmadığını belirtir.
          Gereksiz yere bilinmeyen bağlantıları engellemek meşru yazılımların internet erişimini kesebilir.
        </p>
      </div>

      {/* Blocked IPs Management */}
      {domainStatus?.blocked_ips && domainStatus.blocked_ips.length > 0 && (
        <div className="p-6 rounded-2xl border border-rose-500/20 bg-rose-950/10 backdrop-blur-md space-y-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Ban className="w-4 h-4 text-rose-400" />
            <span>Engellenen IP Adresleri ({domainStatus.blocked_ips.length})</span>
          </h3>
          <div className="flex flex-wrap gap-2">
            {domainStatus.blocked_ips.map((ip) => (
              <div
                key={ip}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-rose-500/30 bg-rose-950/40 text-xs font-mono text-rose-300"
              >
                <span>{ip}</span>
                <button
                  onClick={() => handleUnblockIp(ip)}
                  className="text-slate-400 hover:text-white transition-colors cursor-pointer"
                  title="Engeli Kaldır"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Connections Table */}
      <div className="p-6 rounded-2xl border border-slate-800/80 bg-slate-900/40 backdrop-blur-md space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <h3 className="text-sm font-bold text-white">
            Aktif Ağ Soketleri ({filteredConnections.length})
          </h3>
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="IP veya işlem adı ara..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9 pr-3 py-1.5 rounded-lg text-xs bg-slate-950 border border-slate-800 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-64"
            />
          </div>
        </div>

        <div className="overflow-x-auto max-h-96 overflow-y-auto scrollbar-thin">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-500">
              <tr>
                <th className="py-2.5">İşlem</th>
                <th className="py-2.5">PID</th>
                <th className="py-2.5">Protokol</th>
                <th className="py-2.5">Yerel Uç Nokta</th>
                <th className="py-2.5">Uzak Uç Nokta</th>
                <th className="py-2.5">Durum</th>
                <th className="py-2.5">İtibar</th>
                <th className="py-2.5 text-right">Eylem</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredConnections.map((c, i) => (
                <tr key={i} className="hover:bg-slate-900/60">
                  <td className="py-3 font-semibold text-white">{c.process_name || 'Bilinmiyor'}</td>
                  <td className="py-3 font-mono text-slate-400">{c.pid}</td>
                  <td className="py-3 font-mono text-cyan-400">{c.protocol}</td>
                  <td className="py-3 font-mono text-[11px] text-slate-400">
                    {c.local_addr}:{c.local_port}
                  </td>
                  <td className="py-3 font-mono text-[11px] text-white">
                    {c.remote_addr ? `${c.remote_addr}:${c.remote_port}` : '0.0.0.0:*'}
                  </td>
                  <td className="py-3 font-mono text-[10px] text-slate-400">{c.state}</td>
                  <td className="py-3">
                    <ReputationBadge reputation={c.reputation} />
                  </td>
                  <td className="py-3 text-right">
                    {c.remote_addr && !c.is_private_remote && (
                      <button
                        onClick={() => setBlockIpTarget(c.remote_addr!)}
                        className="px-2 py-1 rounded bg-rose-600/20 text-rose-400 hover:bg-rose-600/30 border border-rose-500/30 text-[10px] font-semibold cursor-pointer"
                      >
                        IP Engelle
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Block IP Confirm Dialog */}
      <ConfirmDialog
        isOpen={Boolean(blockIpTarget)}
        title="Uzak IP Adresini Engelle"
        description={`'${blockIpTarget}' IP adresine yönelik giden tüm ağ trafiği Windows Güvenlik Duvarı kuralı eklenerek engellenecektir.`}
        danger={true}
        confirmText="IP'yi Engelle"
        onConfirm={handleBlockIp}
        onCancel={() => setBlockIpTarget(null)}
      />
    </div>
  );
}

