const { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain, Notification, clipboard, shell, screen } = require('electron');
const path = require('path');
const { analyzeText, RISK_COLORS, RISK_LABELS } = require('./engine');

let tray = null;
let mainWindow = null;
let alertWindow = null;
let isMonitoring = true;
let lastClipboard = '';
let clipboardInterval = null;
let alertHistory = [];

// Hide the dock icon on mac, prevent taskbar on windows
app.setAppUserModelId('com.thresholdinteractivestudios.shield');

// Prevent multiple instances
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); }

// CRITICAL — hide any console/terminal window on Windows
if (process.platform === 'win32') {
  try {
    // Detach from console so no terminal window appears
    const { execSync } = require('child_process');
    process.stdout.write = () => {};
    process.stderr.write = () => {};
  } catch(e) {}
}

app.whenReady().then(() => {
  app.dock && app.dock.hide();
  // Seed lastClipboard with current contents so we don't alert on pre-existing clipboard
  try { lastClipboard = clipboard.readText() || ''; } catch(e) {}
  createTray();
  createMainWindow();
  startClipboardMonitor();
});

// CRITICAL — never quit when all windows closed, keep running in tray
app.on('window-all-closed', (e) => e.preventDefault());
app.on('before-quit', (e) => {
  // Only quit if explicitly triggered from tray menu
  if (!app._explicitQuit) e.preventDefault();
});

// ─── Tray ─────────────────────────────────────────────────────────────────────

function createTray() {
  // Create a simple colored icon programmatically
  const icon = createTrayIcon('safe');
  tray = new Tray(icon);
  tray.setToolTip('Shield — Social Engineering Protection\nThreshold Interactive Studios');
  updateTrayMenu();
  tray.on('click', () => showMainWindow());
}

function createTrayIcon(status) {
  const { nativeImage } = require('electron');
  // Create 16x16 PNG programmatically using raw pixel data
  // Simple shield shape in the appropriate color
  const colors = {
    safe:    [34,  197, 94,  255],  // green
    alert:   [239, 68,  68,  255],  // red
    paused:  [136, 136, 170, 255],  // gray
    monitoring: [79, 142, 247, 255] // blue
  };
  const [r, g, b, a] = colors[status] || colors.safe;

  // 16x16 RGBA buffer — draw a filled shield shape pixel by pixel
  const size = 16;
  const buf = Buffer.alloc(size * size * 4, 0);

  // Shield pixel mask (16x16)
  const shield = [
    '0000011111100000',
    '0000111111110000',
    '0001111111111000',
    '0011111111111100',
    '0111111111111110',
    '0111111111111110',
    '0111111111111110',
    '0111111111111110',
    '0111111111111110',
    '0011111111111100',
    '0001111111111000',
    '0000111111110000',
    '0000011111100000',
    '0000001111000000',
    '0000000110000000',
    '0000000000000000',
  ];

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const idx = (y * size + x) * 4;
      if (shield[y] && shield[y][x] === '1') {
        buf[idx]   = r;
        buf[idx+1] = g;
        buf[idx+2] = b;
        buf[idx+3] = a;
      }
    }
  }

  return nativeImage.createFromBuffer(buf, { width: size, height: size });
}

function updateTrayMenu() {
  const alerts = alertHistory.slice(0, 5);
  const alertItems = alerts.length ? [
    { type: 'separator' },
    { label: `Recent alerts (${alertHistory.length})`, enabled: false },
    ...alerts.map(a => ({
      label: `${getRiskEmoji(a.risk)} ${a.text.substring(0,40)}...`,
      click: () => showAlert(a)
    }))
  ] : [];

  const menu = Menu.buildFromTemplate([
    { label: 'Shield — Active', enabled: false },
    { label: 'by Threshold Interactive Studios', enabled: false },
    { type: 'separator' },
    {
      label: isMonitoring ? '● Monitoring — ON' : '○ Monitoring — OFF',
      click: toggleMonitoring
    },
    { label: 'Open Shield', click: showMainWindow },
    { label: 'Test scanner', click: runTest },
    { type: 'separator' },
    ...alertItems,
    { type: 'separator' },
    { label: 'Quit Shield', click: () => { app._explicitQuit = true; app.exit(0); } }
  ]);
  tray.setContextMenu(menu);
}

function getRiskEmoji(risk) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', safe: '✅' }[risk] || '⚪';
}

// ─── Main Window ──────────────────────────────────────────────────────────────

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 720,
    height: 600,
    show: false,
    frame: false,
    backgroundColor: '#0d0d1a',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  mainWindow.loadFile('src/index.html');
  mainWindow.on('close', (e) => { e.preventDefault(); mainWindow.hide(); });
}

function showMainWindow() {
  if (!mainWindow) createMainWindow();
  mainWindow.show();
  mainWindow.focus();
  mainWindow.webContents.send('refresh-alerts', alertHistory);
}

// ─── Alert Window ─────────────────────────────────────────────────────────────

function showAlert(result) {
  if (alertWindow && !alertWindow.isDestroyed()) alertWindow.close();

  alertWindow = new BrowserWindow({
    width: 420,
    height: 320,
    frame: false,
    alwaysOnTop: true,
    resizable: false,
    backgroundColor: '#0d0d1a',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // Position bottom right
  const { screen } = require('electron');
  const display = screen.getPrimaryDisplay();
  const { width, height } = display.workAreaSize;
  alertWindow.setPosition(width - 440, height - 340);
  alertWindow.loadFile('src/alert.html');
  alertWindow.webContents.on('did-finish-load', () => {
    alertWindow.webContents.send('alert-data', result);
  });

  // Auto dismiss after 12 seconds
  setTimeout(() => {
    if (alertWindow && !alertWindow.isDestroyed()) alertWindow.close();
  }, 12000);
}

// ─── Clipboard Monitor ────────────────────────────────────────────────────────

function startClipboardMonitor() {
  clipboardInterval = setInterval(() => {
    if (!isMonitoring) return;
    try {
      const text = clipboard.readText();
      if (text && text !== lastClipboard && text.trim().length > 15) {
        lastClipboard = text;
        const result = analyzeText(text);
        if (result) {
          alertHistory.unshift(result);
          if (alertHistory.length > 100) alertHistory.pop();
          showAlert(result);
          updateTrayMenu();
          tray.setImage(createTrayIcon('alert'));
          // Reset icon after 10s
          setTimeout(() => tray.setImage(createTrayIcon('safe')), 10000);
          // Also send Windows notification
          if (Notification.isSupported()) {
            new Notification({
              title: `Shield — ${result.risk.toUpperCase()} RISK`,
              body: result.reasons.map(r => r.category).join(', ') + ' detected',
              urgency: result.risk === 'critical' ? 'critical' : 'normal'
            }).show();
          }
          // Update main window if open
          if (mainWindow && mainWindow.isVisible()) {
            mainWindow.webContents.send('refresh-alerts', alertHistory);
          }
        }
      }
    } catch(e) {}
  }, 800); // check every 800ms
}

function toggleMonitoring() {
  isMonitoring = !isMonitoring;
  tray.setImage(createTrayIcon(isMonitoring ? 'safe' : 'paused'));
  tray.setToolTip(`Shield — ${isMonitoring ? 'Monitoring active' : 'PAUSED'}`);
  updateTrayMenu();
  if (mainWindow && mainWindow.isVisible()) {
    mainWindow.webContents.send('monitoring-status', isMonitoring);
  }
}

// ─── Test Function ────────────────────────────────────────────────────────────

function runTest() {
  const testMsg = `Hi, this is the Account Review Team at your financial institution. We've detected some irregular activity on your account ending in 4821 that requires your attention. For your security, your online access has been temporarily restricted. To restore full access, please verify your identity using the link below within the next 24 hours — failure to do so may result in your account being permanently suspended. Please do not contact your local branch as this is handled exclusively by our online security department. https://secure-account-verify.com/restore`;

  // Pause monitor briefly so writing the test message doesn't self-trigger
  // Then resume and let the NEXT clipboard read (by user copying it) trigger naturally
  // Instead — analyze directly and show alert without writing to clipboard
  const result = analyzeText(testMsg);
  if (result) {
    alertHistory.unshift(result);
    if (alertHistory.length > 100) alertHistory.pop();
    showAlert(result);
    updateTrayMenu();
    tray.setImage(createTrayIcon('alert'));
    setTimeout(() => tray.setImage(createTrayIcon('safe')), 10000);
    if (mainWindow && mainWindow.isVisible()) {
      mainWindow.webContents.send('refresh-alerts', alertHistory);
    }
  }
}

// ─── IPC ──────────────────────────────────────────────────────────────────────

ipcMain.on('win-close', () => mainWindow && mainWindow.hide());
ipcMain.on('win-minimize', () => mainWindow && mainWindow.minimize());
ipcMain.on('close-alert', () => alertWindow && !alertWindow.isDestroyed() && alertWindow.close());
ipcMain.on('toggle-monitoring', toggleMonitoring);
ipcMain.on('run-test', runTest);
ipcMain.on('open-url', (e, url) => shell.openExternal(url));
ipcMain.on('clear-history', () => {
  alertHistory = [];
  updateTrayMenu();
  if (mainWindow && mainWindow.isVisible()) mainWindow.webContents.send('refresh-alerts', alertHistory);
});
ipcMain.handle('get-state', () => ({ isMonitoring, alertHistory, version: '1.0.0' }));
ipcMain.handle('analyze-text', (e, text) => analyzeText(text));
