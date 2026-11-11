// AEGIS AI Web & Ad Shield - Popup Script

document.addEventListener('DOMContentLoaded', async () => {
  const toggleAds = document.getElementById('toggle-ads');
  const togglePopups = document.getElementById('toggle-popups');
  const toggleMalware = document.getElementById('toggle-malware');
  const toggleTrackers = document.getElementById('toggle-trackers');

  const statAds = document.getElementById('stat-ads');
  const statPopups = document.getElementById('stat-popups');
  const statMalware = document.getElementById('stat-malware');
  const statTotal = document.getElementById('stat-total');

  const currentDomainEl = document.getElementById('current-domain');
  const statusBadge = document.getElementById('status-badge');
  const btnOptions = document.getElementById('btn-options');

  // Query active tab domain
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const url = new URL(tab.url);
      currentDomainEl.textContent = url.hostname || 'Yerel Sayfa';
    } else {
      currentDomainEl.textContent = 'Bağlantı Yok';
    }
  } catch {
    currentDomainEl.textContent = 'Bilinmiyor';
  }

  // Get current status from background service worker
  chrome.runtime.sendMessage({ action: 'get_status' }, (response) => {
    if (!response || !response.settings) return;
    const { settings } = response;

    toggleAds.checked = settings.blockAds !== false;
    togglePopups.checked = settings.blockPopups !== false;
    toggleMalware.checked = settings.blockMalware !== false;
    toggleTrackers.checked = settings.blockTrackers !== false;

    statAds.textContent = settings.stats.adsBlocked || 0;
    statPopups.textContent = settings.stats.popupsBlocked || 0;
    statMalware.textContent = settings.stats.malwareBlocked || 0;
    statTotal.textContent = settings.stats.totalBlocked || 0;

    updateBadge(settings);
  });

  function updateBadge(settings) {
    const isAnyActive =
      settings.blockAds ||
      settings.blockPopups ||
      settings.blockMalware ||
      settings.blockTrackers;

    if (isAnyActive) {
      statusBadge.textContent = 'AKTİF';
      statusBadge.className = 'badge badge-active';
    } else {
      statusBadge.textContent = 'KAPALI';
      statusBadge.className = 'badge badge-inactive';
    }
  }

  function bindToggle(el, key) {
    el.addEventListener('change', () => {
      chrome.runtime.sendMessage(
        { action: 'toggle_setting', key, value: el.checked },
        (res) => {
          if (res && res.settings) updateBadge(res.settings);
        }
      );
    });
  }

  bindToggle(toggleAds, 'blockAds');
  bindToggle(togglePopups, 'blockPopups');
  bindToggle(toggleMalware, 'blockMalware');
  bindToggle(toggleTrackers, 'blockTrackers');

  btnOptions.addEventListener('click', () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options.html'));
    }
  });
});
