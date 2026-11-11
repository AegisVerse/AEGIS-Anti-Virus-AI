const fs = require('fs');
const path = require('path');
const os = require('os');
const logFile = path.join(os.tmpdir(), 'aegis_electron_debug.log');
function log(msg) {
  try { fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`); } catch {}
}
log('Main process started. Node version: ' + process.versions.node + ', Electron version: ' + process.versions.electron);

process.on('uncaughtException', (err) => {
  log('Uncaught Exception: ' + err.stack);
});
process.on('unhandledRejection', (err) => {
  log('Unhandled Rejection: ' + (err.stack || err));
});

const electron = require('electron');
log('require electron type: ' + typeof electron + ', value: ' + (typeof electron === 'string' ? electron : Object.keys(electron).join(',')));
const { app, BrowserWindow, ipcMain, shell, clipboard } = electron;
const net = require('net');
const { spawn, exec } = require('child_process');

const username = (process.env.USERNAME || 'user').toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 40);
const USER_PIPE = `\\\\.\\pipe\\aegis-ai-security.user.${username}`;
const SERVICE_PIPE = `\\\\.\\pipe\\aegis-ai-security.v1`;

let mainWindow = null;
let engineProcess = null;

// Find root directory and aegis-service executable
const rootDir = path.resolve(__dirname, '../../..');
function getServiceExePath() {
  const candidates = [
    path.join(rootDir, 'target', 'release', 'aegis-service.exe'),
    path.join(rootDir, 'release', 'aegis-service.exe'),
    path.join(rootDir, 'target', 'debug', 'aegis-service.exe'),
    path.join(process.resourcesPath || '', 'aegis-service.exe'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return candidates[0];
}

function ensureEngineRunning() {
  return new Promise((resolve) => {
    // Test if pipe is active
    const testClient = net.createConnection(USER_PIPE, () => {
      testClient.end();
      resolve(true);
    });
    testClient.on('error', () => {
      // Pipe not active, spawn engine in user mode
      const exePath = getServiceExePath();
      if (fs.existsSync(exePath)) {
        console.log('[AEGIS Electron] Spawning engine:', exePath, '--run-user');
        engineProcess = spawn(exePath, ['--run-user'], {
          detached: true,
          stdio: 'ignore',
          windowsHide: true,
        });
        engineProcess.unref();
        setTimeout(() => resolve(true), 1500);
      } else {
        console.warn('[AEGIS Electron] aegis-service.exe not found at:', exePath);
        resolve(false);
      }
    });
  });
}

function sendPipeRequest(reqObj) {
  return new Promise((resolve, reject) => {
    // Try USER_PIPE first, fallback to SERVICE_PIPE
    let targetPipe = USER_PIPE;
    
    function connectTo(pipePath) {
      const client = net.createConnection(pipePath, () => {
        // Send Hello Handshake
        const hello = Buffer.from(JSON.stringify({
          protocol_version: 1,
          client_name: 'aegis-electron',
          client_version: '0.1.0'
        }), 'utf8');
        const helloLen = Buffer.alloc(4);
        helloLen.writeUInt32LE(hello.length, 0);
        client.write(Buffer.concat([helloLen, hello]));
      });

      let state = 'waiting_ack';
      let buffer = Buffer.alloc(0);

      client.on('data', (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);
        while (buffer.length >= 4) {
          const msgLen = buffer.readUInt32LE(0);
          if (buffer.length < 4 + msgLen) break;

          const msgBytes = buffer.slice(4, 4 + msgLen);
          buffer = buffer.slice(4 + msgLen);
          const msgStr = msgBytes.toString('utf8');

          if (state === 'waiting_ack') {
            state = 'waiting_resp';
            const reqBytes = Buffer.from(JSON.stringify(reqObj), 'utf8');
            const reqLen = Buffer.alloc(4);
            reqLen.writeUInt32LE(reqBytes.length, 0);
            client.write(Buffer.concat([reqLen, reqBytes]));
          } else if (state === 'waiting_resp') {
            try {
              const resp = JSON.parse(msgStr);
              client.end();
              resolve(resp);
            } catch (err) {
              client.end();
              reject(err);
            }
            return;
          }
        }
      });

      client.on('error', (err) => {
        if (pipePath === USER_PIPE) {
          // Retry with SERVICE_PIPE
          connectTo(SERVICE_PIPE);
        } else {
          reject(err);
        }
      });

      setTimeout(() => {
        client.destroy();
        reject(new Error('Named pipe request timed out'));
      }, 15000);
    }

    connectTo(targetPipe);
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#020617', // slate-950
    autoHideMenuBar: true,
    title: 'AEGIS AI Security',
    icon: path.join(__dirname, '../public/icon.ico'),
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
    },
  });

  const isDev = process.env.NODE_ENV === 'development' || process.argv.includes('--dev');
  if (isDev) {
    mainWindow.loadURL('http://localhost:1420');
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.webContents.on('did-fail-load', (e, code, desc) => {
    log('Failed to load: ' + code + ' ' + desc);
  });

  mainWindow.webContents.on('console-message', (e, level, message, line, sourceId) => {
    log(`[Renderer] ${message} (${sourceId}:${line})`);
  });

  mainWindow.webContents.on('did-finish-load', () => {
    log('Renderer finished loading successfully');
  });

  // F12 or Ctrl+Shift+I to toggle DevTools
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.key === 'F12' || (input.control && input.shift && input.key === 'I')) {
      mainWindow.webContents.toggleDevTools();
      event.preventDefault();
    }
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// IPC Handlers
ipcMain.handle('aegis-call', async (event, request) => {
  try {
    const resp = await sendPipeRequest(request);
    if (resp.ok) {
      return resp.data !== undefined ? resp.data : null;
    } else {
      throw resp.error || { code: 'internal', message: 'Unknown engine error' };
    }
  } catch (err) {
    console.error('[AEGIS IPC Error]:', err);
    throw {
      code: 'unavailable',
      message: err.message || 'Failed to communicate with AEGIS security engine',
    };
  }
});

ipcMain.handle('aegis-connection', async () => {
  try {
    const resp = await sendPipeRequest({ cmd: 'ping' });
    if (resp.ok) {
      return {
        connected: true,
        mode: 'user',
        pipe: USER_PIPE,
        privileged_allowed: true,
        service_version: '0.1.0',
        error: null,
      };
    }
  } catch (err) {
    // Not connected
  }
  return {
    connected: false,
    mode: null,
    pipe: null,
    privileged_allowed: false,
    service_version: null,
    error: 'AEGIS engine not connected',
  };
});

ipcMain.handle('aegis-start-user-engine', async () => {
  await ensureEngineRunning();
  return ipcMain.emit('aegis-connection');
});

ipcMain.handle('aegis-open-path', async (event, targetPath) => {
  try {
    if (!targetPath || typeof targetPath !== 'string') return false;
    let cleanPath = targetPath.trim().replace(/^["']|["']$/g, '');
    
    if (cleanPath === 'browser-extension' || cleanPath.endsWith('browser-extension')) {
      const extDir = getExtensionDir();
      if (fs.existsSync(extDir)) {
        const manifest = path.join(extDir, 'manifest.json');
        if (fs.existsSync(manifest)) {
          shell.showItemInFolder(manifest);
        } else {
          await shell.openPath(extDir);
        }
        return true;
      }
    }

    cleanPath = path.resolve(cleanPath);
    log('[open-path] Request to open: ' + cleanPath);

    if (fs.existsSync(cleanPath)) {
      const stat = fs.statSync(cleanPath);
      if (stat.isDirectory()) {
        await shell.openPath(cleanPath);
      } else {
        shell.showItemInFolder(cleanPath);
      }
      return true;
    }

    // If file was deleted or quarantined, open the parent directory
    const parentDir = path.dirname(cleanPath);
    if (fs.existsSync(parentDir)) {
      log('[open-path] File not found, opening parent folder: ' + parentDir);
      await shell.openPath(parentDir);
      return true;
    }

    log('[open-path] Path does not exist: ' + cleanPath);
    return false;
  } catch (err) {
    log('[open-path] Error opening path: ' + err.message);
    return false;
  }
});

function getExtensionDir() {
  const candidates = [
    path.join(__dirname, '../../../browser-extension'),
    path.join(process.resourcesPath || '', 'browser-extension'),
    path.join(__dirname, '../../browser-extension'),
    path.resolve('browser-extension'),
    path.resolve('release/electron/win-unpacked/resources/browser-extension'),
    'C:\\Users\\Kaan\\Desktop\\AEGIS Anti-Virus AI\\browser-extension',
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return path.resolve(c);
  }
  return path.resolve('browser-extension');
}

function getBrowserExe(browser) {
  const localAppData = process.env.LOCALAPPDATA || '';
  const programFiles = process.env['ProgramFiles'] || 'C:\\Program Files';
  const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';

  if (browser === 'edge') {
    const candidates = [
      path.join(programFilesX86, 'Microsoft/Edge/Application/msedge.exe'),
      path.join(programFiles, 'Microsoft/Edge/Application/msedge.exe'),
    ];
    return candidates.find(fs.existsSync);
  }
  if (browser === 'brave') {
    const candidates = [
      path.join(programFiles, 'BraveSoftware/Brave-Browser/Application/brave.exe'),
      path.join(programFilesX86, 'BraveSoftware/Brave-Browser/Application/brave.exe'),
      path.join(localAppData, 'BraveSoftware/Brave-Browser/Application/brave.exe'),
    ];
    return candidates.find(fs.existsSync);
  }
  if (browser === 'chrome') {
    const candidates = [
      path.join(programFiles, 'Google/Chrome/Application/chrome.exe'),
      path.join(programFilesX86, 'Google/Chrome/Application/chrome.exe'),
      path.join(localAppData, 'Google/Chrome/Application/chrome.exe'),
    ];
    return candidates.find(fs.existsSync);
  }
  return null;
}

ipcMain.handle('aegis-install-browser-extension', async (event, browserName) => {
  try {
    const extPath = getExtensionDir();
    log('[browser-extension] Resolved extension path: ' + extPath);

    if (!fs.existsSync(extPath)) {
      return { success: false, message: 'Tarayıcı eklentisi klasörü bulunamadı: ' + extPath, path: null };
    }

    // 1. Copy extension path to Windows clipboard so user can just paste it
    clipboard.writeText(extPath);

    // 2. Determine target browser extensions page URL
    let extensionsUrl = 'chrome://extensions';
    if (browserName === 'edge') extensionsUrl = 'edge://extensions';
    else if (browserName === 'brave') extensionsUrl = 'brave://extensions';

    const browserExe = getBrowserExe(browserName);
    if (browserExe) {
      log(`[browser-extension] Spawning ${browserExe} with ${extensionsUrl}`);
      const child = spawn(browserExe, [extensionsUrl], {
        detached: true,
        stdio: 'ignore',
      });
      child.unref();
    } else {
      shell.openExternal(extensionsUrl).catch(() => {});
    }

    // 3. Open Windows Explorer highlighting the browser-extension directory itself
    // This allows the user to directly drag-and-drop the highlighted folder into the browser!
    if (fs.existsSync(extPath)) {
      shell.showItemInFolder(extPath);
    } else {
      shell.openPath(path.dirname(extPath));
    }

    return {
      success: true,
      browser: browserName,
      path: extPath,
      message: `${browserName.toUpperCase()} eklentiler sayfası açıldı ve klasör gezginde gösterildi.`,
    };
  } catch (err) {
    log('[browser-extension] Error: ' + err.message);
    return { success: false, message: err.message, path: null };
  }
});

app.whenReady().then(async () => {
  log('app.whenReady fired');
  try {
    await ensureEngineRunning();
    log('ensureEngineRunning finished');
    createWindow();
    log('createWindow finished');
  } catch (err) {
    log('Error in whenReady: ' + err.stack);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
