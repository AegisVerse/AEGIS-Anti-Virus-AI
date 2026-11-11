const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  isElectron: true,
  aegisCall: (request) => ipcRenderer.invoke('aegis-call', request),
  getConnectionInfo: () => ipcRenderer.invoke('aegis-connection'),
  startUserEngine: () => ipcRenderer.invoke('aegis-start-user-engine'),
  openPath: (path) => ipcRenderer.invoke('aegis-open-path', path),
  installBrowserExtension: (browser) => ipcRenderer.invoke('aegis-install-browser-extension', browser),
});

