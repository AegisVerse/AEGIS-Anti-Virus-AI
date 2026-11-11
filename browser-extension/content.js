// AEGIS AI Web Shield - Anti-Popunder & Smart AdBlock Content Script
(function () {
  'use strict';

  // Check if protection is enabled from storage
  let shieldActive = true;
  let popunderShield = true;
  let cosmeticAdBlock = true;

  try {
    chrome.storage.local.get(['settings'], (res) => {
      if (res && res.settings) {
        shieldActive = res.settings.blockMalware !== false;
        popunderShield = res.settings.blockPopups !== false;
        cosmeticAdBlock = res.settings.blockAds !== false;
        if (cosmeticAdBlock) injectAdHidingCSS();
      }
    });
  } catch (e) {
    injectAdHidingCSS();
  }

  // Known suspicious ad / popunder parameters and patterns
  const POPUP_BLACKLIST_PATTERNS = [
    /popunder/i,
    /popcash/i,
    /popads/i,
    /propeller/i,
    /adsterra/i,
    /monetag/i,
    /exoclick/i,
    /clickadu/i,
    /zeroredirect/i,
    /hilltopads/i,
    /redirect.*aff/i,
    /tracking.*click/i,
    /trafficjunky/i,
    /adnxs/i,
    /doubleclick/i,
    /adservice/i,
    /install.*update/i,
    /warning.*virus/i,
    /clean.*pc/i,
  ];

  // 1. NEUTER WINDOW.OPEN POPUNDERS
  const originalWindowOpen = window.open;
  window.open = function (url, target, features) {
    if (!popunderShield || !shieldActive) {
      return originalWindowOpen.apply(this, arguments);
    }

    const urlStr = String(url || '');
    
    // Check if URL matches suspicious popunder patterns
    const isSuspicious = POPUP_BLACKLIST_PATTERNS.some((pat) => pat.test(urlStr));

    // Check if call was triggered by automatic script rather than direct trusted click
    if (isSuspicious || (!urlStr.startsWith('/') && !urlStr.includes(window.location.hostname) && (urlStr.includes('ad') || urlStr.includes('click') || urlStr.includes('aff')))) {
      console.warn('[AEGIS Shield] Engellenen şüpheli pop-up / yeni sekme:', urlStr);
      
      // Notify background worker to increment blocked count
      try {
        chrome.runtime.sendMessage({ action: 'popup_blocked', url: urlStr });
      } catch (err) {}

      showBlockedNotification('İstenmeyen reklam sekmesi engellendi');
      return null;
    }

    return originalWindowOpen.apply(this, arguments);
  };

  // 2. PREVENT INVISIBLE CLICKJACKING OVERLAY TRAPS
  document.addEventListener('DOMContentLoaded', () => {
    removeClickjackOverlays();
    
    // Watch for dynamic overlays injected by shady scripts
    const observer = new MutationObserver(() => {
      removeClickjackOverlays();
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true,
    });
  });

  function removeClickjackOverlays() {
    if (!popunderShield) return;
    try {
      const allDivs = document.querySelectorAll('div, a, iframe');
      const winW = window.innerWidth;
      const winH = window.innerHeight;

      for (let i = 0; i < allDivs.length; i++) {
        const el = allDivs[i];
        const style = window.getComputedStyle(el);

        // Detect full-screen invisible / high-z-index clickable traps
        if (
          (style.position === 'fixed' || style.position === 'absolute') &&
          parseInt(style.zIndex, 10) > 9999 &&
          parseFloat(style.opacity) < 0.1
        ) {
          const rect = el.getBoundingClientRect();
          if (rect.width >= winW * 0.8 && rect.height >= winH * 0.8) {
            console.warn('[AEGIS Shield] Kaldırılan şüpheli clickjacking tuzak katmanı:', el);
            el.remove();
          }
        }
      }
    } catch (e) {}
  }

  // 3. COSMETIC AD-HIDING CSS
  function injectAdHidingCSS() {
    const css = `
      .adsbygoogle, 
      [id*="google_ads_iframe"], 
      [class*="ad-banner"], 
      [class*="popup-banner"],
      [id*="popunder"],
      [class*="popunder"],
      [class*="sponsored-post"],
      [data-ad-client],
      iframe[src*="doubleclick.net"],
      iframe[src*="adnxs.com"] {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
        width: 0 !important;
        pointer-events: none !important;
      }
    `;

    try {
      const styleEl = document.createElement('style');
      styleEl.id = 'aegis-adblock-styles';
      styleEl.textContent = css;
      (document.head || document.documentElement).appendChild(styleEl);
    } catch (e) {}
  }

  // 4. SUBTLE BLOCKED TOAST
  function showBlockedNotification(msg) {
    try {
      const existing = document.getElementById('aegis-toast');
      if (existing) existing.remove();

      const toast = document.createElement('div');
      toast.id = 'aegis-toast';
      toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #0f172a;
        color: #38bdf8;
        border: 1px solid #0284c7;
        box-shadow: 0 4px 14px rgba(0,0,0,0.4);
        padding: 10px 16px;
        border-radius: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 12px;
        font-weight: 600;
        z-index: 2147483647;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: opacity 0.3s ease;
        pointer-events: none;
      `;
      toast.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span>AEGIS: ${msg}</span>
      `;

      document.body.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
      }, 2500);
    } catch (e) {}
  }

  // 5. YOUTUBE AD-SKIPPER & ANTI-ANTI-ADBLOCK SHIELD
  function initYouTubeShield() {
    if (!window.location.hostname.includes('youtube.com')) return;

    // A. YouTube Cosmetic Ad Hiding CSS
    const ytCss = `
      #masthead-ad,
      ytd-ad-slot-renderer,
      ytd-in-feed-ad-layout-renderer,
      ytd-banner-promo-renderer,
      ytd-statement-banner-renderer,
      ytd-promoted-sparkles-web-renderer,
      ytd-promoted-video-renderer,
      ytd-video-masthead-ad-v3-renderer,
      ytd-player-legacy-desktop-watch-ads-renderer,
      .ytd-companion-slot-renderer,
      #player-ads,
      .ytp-ad-module,
      .ytp-ad-overlay-container,
      .ytp-ad-message-container,
      .ytp-ad-progress-list,
      ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"],
      ytd-enforcement-message-view-model,
      tp-yt-paper-dialog:has(ytd-enforcement-message-view-model),
      tp-yt-iron-overlay-backdrop:has(+ tp-yt-paper-dialog ytd-enforcement-message-view-model) {
        display: none !important;
        visibility: hidden !important;
        height: 0 !important;
        width: 0 !important;
        pointer-events: none !important;
      }
    `;

    try {
      const ytStyleEl = document.createElement('style');
      ytStyleEl.id = 'aegis-yt-styles';
      ytStyleEl.textContent = ytCss;
      (document.head || document.documentElement).appendChild(ytStyleEl);
    } catch (e) {}

    // B. High-Frequency Video Ad Detection & Fast-Forward Skip
    let wasAdActive = false;
    let savedVolume = 1;
    let savedMuted = false;

    function handleYouTubeAds() {
      // 1. Check Anti-Adblock Enforcement Dialogs
      const enforcementDialog = document.querySelector(
        'ytd-enforcement-message-view-model, tp-yt-paper-dialog:has(ytd-enforcement-message-view-model)'
      );
      if (enforcementDialog) {
        const dismissBtn = enforcementDialog.querySelector('#dismiss-button, button[aria-label="Close"], yt-button-renderer button');
        if (dismissBtn) {
          dismissBtn.click();
        } else {
          enforcementDialog.remove();
        }
        document.querySelectorAll('tp-yt-iron-overlay-backdrop').forEach((el) => el.remove());
        const v = document.querySelector('video');
        if (v && v.paused) v.play().catch(() => {});
      }

      // 2. Check Video Player Ads
      const moviePlayer = document.getElementById('movie_player') || document.querySelector('.html5-video-player');
      const video = document.querySelector('video');

      if (!moviePlayer || !video) return;

      const isAdActive =
        moviePlayer.classList.contains('ad-showing') ||
        moviePlayer.classList.contains('ad-interrupting') ||
        Boolean(document.querySelector('.ytp-ad-player-overlay, .ytp-ad-text, .ytp-ad-preview-container, .ytp-ad-skip-button-slot, .video-ads.ytp-ad-module > div, div[class*="ytp-ad-image"]')) ||
        Boolean(video.src && (video.src.includes('&ad_type=') || video.src.includes('&adformat=')));

      if (isAdActive) {
        if (!wasAdActive) {
          wasAdActive = true;
          savedVolume = video.volume;
          savedMuted = video.muted;
        }

        // Mute immediately and accelerate to max speed (16x)
        video.muted = true;
        video.playbackRate = 16;

        // Skip immediately to the end of the ad duration
        if (!isNaN(video.duration) && video.duration > 0) {
          video.currentTime = video.duration;
        } else {
          video.currentTime = 99999;
        }

        // Call YouTube internal player skipAd API if available
        if (typeof moviePlayer.skipAd === 'function') {
          try { moviePlayer.skipAd(); } catch (e) {}
        }

        // Click any skip button that appears
        const skipButtons = document.querySelectorAll(
          '.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button, .ytp-ad-skip-button-slot button, [id^="skip-button"] button, button[class*="ytp-ad-skip"]'
        );
        skipButtons.forEach((btn) => btn.click());

        // Remove any ad overlays
        document.querySelectorAll('.ytp-ad-overlay-container, .ytp-ad-message-container').forEach((el) => el.remove());

        try {
          chrome.runtime.sendMessage({ action: 'ad_blocked' });
        } catch (e) {}
      } else if (wasAdActive) {
        // Ad finished, restore regular video playback state
        wasAdActive = false;
        video.playbackRate = 1;
        video.muted = savedMuted;
        video.volume = savedVolume;
        if (video.paused) {
          video.play().catch(() => {});
        }
      }
    }

    // Run check loop (50ms - 20 times per second for instant reaction)
    setInterval(handleYouTubeAds, 50);

    // Also observe DOM changes
    const ytObserver = new MutationObserver(() => {
      handleYouTubeAds();
    });
    ytObserver.observe(document.documentElement, { childList: true, subtree: true });
  }

  initYouTubeShield();
})();

