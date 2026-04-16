const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('shield', {
  close: () => ipcRenderer.send('win-close'),
  minimize: () => ipcRenderer.send('win-minimize'),
  closeAlert: () => ipcRenderer.send('close-alert'),
  toggleMonitoring: () => ipcRenderer.send('toggle-monitoring'),
  runTest: () => ipcRenderer.send('run-test'),
  clearHistory: () => ipcRenderer.send('clear-history'),
  openUrl: (url) => ipcRenderer.send('open-url', url),
  getState: () => ipcRenderer.invoke('get-state'),
  analyzeText: (text) => ipcRenderer.invoke('analyze-text', text),
  onAlertData: (cb) => ipcRenderer.on('alert-data', (e, data) => cb(data)),
  onRefreshAlerts: (cb) => ipcRenderer.on('refresh-alerts', (e, data) => cb(data)),
  onMonitoringStatus: (cb) => ipcRenderer.on('monitoring-status', (e, data) => cb(data)),
});
