// AEGIS AI Web Shield - YouTube Main World Ad Interceptor (Brave Shields & uBlock Standard)
// Runs directly in YouTube's main JavaScript context before player initialization
(function () {
  'use strict';

  function sanitizePlayerResponse(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    try {
      if (obj.adPlacements) obj.adPlacements = [];
      if (obj.adSlots) obj.adSlots = [];
      if (obj.playerAds) obj.playerAds = [];
      if (obj.adBreakHeartbeatParams) delete obj.adBreakHeartbeatParams;
      if (obj.playbackTracking) {
        if (obj.playbackTracking.videostatsPlaybackUrl) delete obj.playbackTracking.videostatsPlaybackUrl;
        if (obj.playbackTracking.videostatsDelayplayUrl) delete obj.playbackTracking.videostatsDelayplayUrl;
        if (obj.playbackTracking.videostatsWatchtimeUrl) delete obj.playbackTracking.videostatsWatchtimeUrl;
      }
    } catch (e) {}
    return obj;
  }

  // 1. Hook JSON.parse - Strips ads from ANY player data parsed anywhere in YouTube
  const originalJSONParse = JSON.parse;
  JSON.parse = function (text, reviver) {
    const data = originalJSONParse.apply(this, arguments);
    if (data && typeof data === 'object') {
      if (data.adPlacements || data.adSlots || data.playerAds || data.adBreakHeartbeatParams) {
        sanitizePlayerResponse(data);
      }
    }
    return data;
  };

  // 2. Intercept and sanitize ytInitialPlayerResponse
  let currentResponse = window.ytInitialPlayerResponse ? sanitizePlayerResponse(window.ytInitialPlayerResponse) : undefined;
  try {
    Object.defineProperty(window, 'ytInitialPlayerResponse', {
      configurable: true,
      enumerable: true,
      get: function () {
        return currentResponse;
      },
      set: function (val) {
        currentResponse = sanitizePlayerResponse(val);
      },
    });
  } catch (e) {}

  // 3. Intercept fetch for /youtubei/v1/player
  const originalFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await originalFetch.apply(this, args);
    try {
      const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
      if (url.includes('/youtubei/v1/player') || url.includes('/youtubei/v1/next')) {
        const clone = response.clone();
        const data = await clone.json();
        if (data && (data.adPlacements || data.adSlots || data.playerAds)) {
          sanitizePlayerResponse(data);
          return new Response(JSON.stringify(data), {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
          });
        }
      }
    } catch (err) {}
    return response;
  };

  // 4. Intercept XMLHttpRequest for /youtubei/v1/player
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._aegisUrl = typeof url === 'string' ? url : '';
    return originalXHROpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    if (this._aegisUrl && (this._aegisUrl.includes('/youtubei/v1/player') || this._aegisUrl.includes('/youtubei/v1/next'))) {
      this.addEventListener('readystatechange', () => {
        if (this.readyState === 4 && this.status === 200) {
          try {
            const parsed = originalJSONParse(this.responseText);
            if (parsed && (parsed.adPlacements || parsed.adSlots || parsed.playerAds)) {
              sanitizePlayerResponse(parsed);
              const sanitizedText = JSON.stringify(parsed);
              Object.defineProperty(this, 'responseText', { value: sanitizedText, configurable: true });
              Object.defineProperty(this, 'response', { value: sanitizedText, configurable: true });
            }
          } catch (e) {}
        }
      });
    }
    return originalXHRSend.apply(this, arguments);
  };

  // 5. Disable YouTube Anti-Adblock telemetry beacon
  const originalSendBeacon = navigator.sendBeacon;
  if (originalSendBeacon) {
    navigator.sendBeacon = function (url, data) {
      if (typeof url === 'string' && (url.includes('/api/stats/ads') || url.includes('/pagead/'))) {
        return true;
      }
      return originalSendBeacon.apply(this, arguments);
    };
  }

  console.log('[AEGIS Shield] YouTube derin reklam arındırıcı (Brave & uBlock Standardı) devrede.');
})();
