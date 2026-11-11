// AEGIS AI Web & Ad Shield - Background Service Worker

const DEFAULT_SETTINGS = {
  blockMalware: true,
  blockTrackers: true,
  blockAds: true,
  blockPopups: true,
  stats: {
    malwareBlocked: 0,
    trackersBlocked: 0,
    adsBlocked: 0,
    popupsBlocked: 0,
    totalBlocked: 0,
  },
  recentBlocks: [],
};

const POPUNDER_DOMAINS = [
  'popads.net', 'popcash.net', 'propellerads.com', 'adsterra.com',
  'exoclick.com', 'monetag.com', 'hilltopads.com', 'clickadu.com',
  'adcash.com', 'trafficjunky.com', 'zeroredirect.com', 'yllix.com',
  'plugrush.com', 'trafficfactory.biz', 'bidvertiser.com', 'juicyads.com',
  'update-flash-player.com', 'chrome-security-update.net',
  'windows-defender-critical-alert.info', 'system-infected-scan.site'
];

// Initialize settings on install
chrome.runtime.onInstalled.addListener(async () => {
  const data = await chrome.storage.local.get(['settings']);
  const settings = data.settings ? { ...DEFAULT_SETTINGS, ...data.settings } : DEFAULT_SETTINGS;
  await chrome.storage.local.set({ settings });
  updateRulesets(settings);
  updateBadge(settings.stats.totalBlocked);
});

// Update DeclarativeNetRequest active rulesets based on user settings
async function updateRulesets(settings) {
  const enableRulesetIds = [];
  const disableRulesetIds = [];

  if (settings.blockMalware) enableRulesetIds.push('ruleset_malware');
  else disableRulesetIds.push('ruleset_malware');

  if (settings.blockTrackers) enableRulesetIds.push('ruleset_trackers');
  else disableRulesetIds.push('ruleset_trackers');

  if (settings.blockAds) enableRulesetIds.push('ruleset_ads');
  else disableRulesetIds.push('ruleset_ads');

  try {
    await chrome.declarativeNetRequest.updateEnabledRulesets({
      enableRulesetIds,
      disableRulesetIds,
    });
  } catch (err) {
    console.error('[AEGIS Shield] Failed to update rulesets:', err);
  }
}

function updateBadge(count) {
  try {
    if (count > 0) {
      chrome.action.setBadgeText({ text: count > 999 ? '999+' : String(count) });
      chrome.action.setBadgeBackgroundColor({ color: '#06b6d4' }); // cyan
    } else {
      chrome.action.setBadgeText({ text: '' });
    }
  } catch (e) {}
}

// Intercept unrequested new tabs created by popunder / clickjack scripts
chrome.webNavigation.onCreatedNavigationTarget.addListener(async (details) => {
  const data = await chrome.storage.local.get(['settings']);
  const settings = data.settings || DEFAULT_SETTINGS;

  if (!settings.blockPopups) return;

  const url = details.url || '';
  const isPopunder = POPUNDER_DOMAINS.some((d) => url.includes(d));

  if (isPopunder) {
    console.warn('[AEGIS Shield] Otomatik açılan zararlı pop-up sekmesi kapatıldı:', url);
    chrome.tabs.remove(details.tabId).catch(() => {});

    settings.stats.popupsBlocked += 1;
    settings.stats.totalBlocked += 1;
    settings.recentBlocks.unshift({
      domain: new URL(url).hostname || 'popup',
      category: 'popups',
      timestamp: new Date().toISOString(),
    });
    if (settings.recentBlocks.length > 50) settings.recentBlocks.pop();

    await chrome.storage.local.set({ settings });
    updateBadge(settings.stats.totalBlocked);
  }
});

// Listen to messages from popup, options, or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'get_status') {
    chrome.storage.local.get(['settings'], (res) => {
      sendResponse({ success: true, settings: res.settings || DEFAULT_SETTINGS });
    });
    return true;
  }

  if (message.action === 'toggle_setting') {
    const { key, value } = message;
    chrome.storage.local.get(['settings'], async (res) => {
      const settings = res.settings || DEFAULT_SETTINGS;
      settings[key] = value;
      await chrome.storage.local.set({ settings });
      await updateRulesets(settings);
      sendResponse({ success: true, settings });
    });
    return true;
  }

  if (message.action === 'popup_blocked') {
    chrome.storage.local.get(['settings'], async (res) => {
      const settings = res.settings || DEFAULT_SETTINGS;
      settings.stats.popupsBlocked += 1;
      settings.stats.totalBlocked += 1;
      if (message.url) {
        let domain = 'popup';
        try { domain = new URL(message.url).hostname; } catch (e) {}
        settings.recentBlocks.unshift({
          domain,
          category: 'popups',
          timestamp: new Date().toISOString(),
        });
        if (settings.recentBlocks.length > 50) settings.recentBlocks.pop();
      }
      await chrome.storage.local.set({ settings });
      updateBadge(settings.stats.totalBlocked);
      sendResponse({ success: true, stats: settings.stats });
    });
    return true;
  }

  if (message.action === 'reset_stats') {
    chrome.storage.local.get(['settings'], async (res) => {
      const settings = res.settings || DEFAULT_SETTINGS;
      settings.stats = {
        malwareBlocked: 0,
        trackersBlocked: 0,
        adsBlocked: 0,
        popupsBlocked: 0,
        totalBlocked: 0,
      };
      settings.recentBlocks = [];
      await chrome.storage.local.set({ settings });
      updateBadge(0);
      sendResponse({ success: true, settings });
    });
    return true;
  }
});
