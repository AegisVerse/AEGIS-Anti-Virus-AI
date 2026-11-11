// AEGIS AI Web Shield - Options Script

document.addEventListener('DOMContentLoaded', () => {
  const optMalware = document.getElementById('opt-malware');
  const optTrackers = document.getElementById('opt-trackers');
  const optAds = document.getElementById('opt-ads');
  const logsTbody = document.getElementById('logs-tbody');
  const btnResetStats = document.getElementById('btn-reset-stats');

  function renderLogs(logs) {
    if (!logs || logs.length === 0) {
      logsTbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Henüz engelleme kaydı oluşmadı.</td></tr>';
      return;
    }

    logsTbody.innerHTML = logs.map(log => {
      const date = new Date(log.timestamp).toLocaleTimeString();
      let badgeClass = 'badge-tag badge-malware';
      let label = 'Zararlı';
      if (log.category === 'trackers') {
        badgeClass = 'badge-tag badge-trackers';
        label = 'İzleyici';
      } else if (log.category === 'ads') {
        badgeClass = 'badge-tag badge-ads';
        label = 'Reklam';
      }

      return `
        <tr>
          <td>${date}</td>
          <td><code style="color: #38bdf8;">${escapeHtml(log.domain)}</code></td>
          <td><span class="${badgeClass}">${label}</span></td>
          <td><span style="color: #34d399; font-weight: 600;">Engellendi</span></td>
        </tr>
      `;
    }).join('');
  }

  function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Load status
  chrome.runtime.sendMessage({ action: 'get_status' }, (response) => {
    if (!response || !response.settings) return;
    const { settings } = response;
    optMalware.checked = settings.blockMalware;
    optTrackers.checked = settings.blockTrackers;
    optAds.checked = settings.blockAds;
    renderLogs(settings.recentBlocks);
  });

  optMalware.addEventListener('change', () => {
    chrome.runtime.sendMessage({ action: 'toggle_setting', key: 'blockMalware', value: optMalware.checked });
  });

  optTrackers.addEventListener('change', () => {
    chrome.runtime.sendMessage({ action: 'toggle_setting', key: 'blockTrackers', value: optTrackers.checked });
  });

  optAds.addEventListener('change', () => {
    chrome.runtime.sendMessage({ action: 'toggle_setting', key: 'blockAds', value: optAds.checked });
  });

  btnResetStats.addEventListener('click', () => {
    if (confirm('Engelleme istatistikleri ve kayıtları sıfırlansın mı?')) {
      chrome.runtime.sendMessage({ action: 'reset_stats' }, (response) => {
        if (response && response.settings) {
          renderLogs(response.settings.recentBlocks);
        }
      });
    }
  });
});

