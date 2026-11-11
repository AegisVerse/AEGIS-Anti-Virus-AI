// AEGIS AI Web Shield - Blocked Interstitial Page

document.addEventListener('DOMContentLoaded', () => {
  const targetDomainEl = document.getElementById('target-domain');
  const threatCategoryEl = document.getElementById('threat-category');
  const btnBack = document.getElementById('btn-back');
  const btnDetails = document.getElementById('btn-details');
  const detailsPanel = document.getElementById('details-panel');

  const params = new URLSearchParams(window.location.search);
  const domain = params.get('url') || params.get('domain') || 'Zararlı Alan Adı';
  const category = params.get('cat') || 'Zararlı Yazılım / Oltalama';

  targetDomainEl.textContent = domain;
  threatCategoryEl.textContent = category;

  btnBack.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'about:blank';
    }
  });

  btnDetails.addEventListener('click', () => {
    detailsPanel.classList.toggle('hidden');
  });
});

