const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const si = require('systeminformation');
const path = require('path');
const fs = require('fs');
const LogManager = require('./log-manager');

let mainWindow;
let monitoringInterval = null;
let alertThresholds = {
  cpu: 80,
  memory: 80,
  disk: 90,
  network: 100
};
let baselineConfig = {
  cpu: { min: 0, max: 70, enabled: true },
  memory: { min: 0, max: 70, enabled: true },
  disk: { min: 0, max: 85, enabled: true }
};
let recentSamples = {
  cpu: [],
  memory: [],
  disk: []
};
const MAX_SAMPLES = 5;
let anomalyReports = [];
let reportsDir = '';
let cooldownUntil = { cpu: 0, memory: 0, disk: 0 };
const COOLDOWN_MS = 60000;
let alertHistory = [];
let maxHistoryPoints = 60;
let logIntervalMs = 60000;
let splitStrategy = 'daily';
let maxFileSize = 50 * 1024 * 1024;

let logManager = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 680,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    icon: path.join(__dirname, 'assets', 'icon.png')
  });

  mainWindow.loadFile('index.html');
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();
  initReportsDir();
  loadAnomalyReports();
  startMonitoring();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

function initReportsDir() {
  reportsDir = path.join(app.getPath('userData'), 'anomaly_reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
}

function loadAnomalyReports() {
  const indexPath = path.join(reportsDir, '.reports_index.json');
  anomalyReports = [];
  if (fs.existsSync(indexPath)) {
    try {
      const content = fs.readFileSync(indexPath, 'utf-8');
      anomalyReports = JSON.parse(content);
    } catch (err) {
      console.error('加载异常报告索引失败:', err);
      anomalyReports = [];
    }
  }
}

function saveReportsIndex() {
  const indexPath = path.join(reportsDir, '.reports_index.json');
  try {
    fs.writeFileSync(indexPath, JSON.stringify(anomalyReports, null, 2), 'utf-8');
  } catch (err) {
    console.error('保存异常报告索引失败:', err);
  }
}

app.on('window-all-closed', async () => {
  stopMonitoring();
  if (logManager) {
    await logManager.stop();
  }
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

function startMonitoring() {
  if (monitoringInterval) return;
  
  monitoringInterval = setInterval(async () => {
    try {
      const data = await collectSystemData();
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('system-data', data);
      }
      checkAlerts(data);
      checkBaselineAnomalies(data);
      
      if (logManager && logManager.isLogging) {
        logManager.addRecord(data);
      }
    } catch (err) {
      console.error('数据采集错误:', err);
    }
  }, 2000);
}

function stopMonitoring() {
  if (monitoringInterval) {
    clearInterval(monitoringInterval);
    monitoringInterval = null;
  }
}

async function collectSystemData() {
  const [cpu, mem, fsSize, networkStats, processes] = await Promise.all([
    si.currentLoad(),
    si.mem(),
    si.fsSize(),
    si.networkStats(),
    si.processes()
  ]);

  const cpuUsage = cpu.currentLoad;
  const memoryUsage = (mem.active / mem.total) * 100;
  
  let diskUsage = 0;
  if (fsSize && fsSize.length > 0) {
    const mainDisk = fsSize[0];
    diskUsage = mainDisk.use;
  }

  let networkUp = 0;
  let networkDown = 0;
  if (networkStats && networkStats.length > 0) {
    networkStats.forEach(iface => {
      networkUp += iface.tx_sec || 0;
      networkDown += iface.rx_sec || 0;
    });
  }

  const topProcesses = processes.list
    .sort((a, b) => b.cpu - a.cpu)
    .slice(0, 10)
    .map(p => ({
      pid: p.pid,
      name: p.name,
      cpu: parseFloat(p.cpu.toFixed(2)),
      mem: parseFloat(p.mem.toFixed(2)),
      memBytes: Math.round(p.memVsz || p.memRss || 0)
    }));

  return {
    timestamp: new Date().toISOString(),
    cpu: {
      usage: parseFloat(cpuUsage.toFixed(2)),
      cores: cpu.cpus.length,
      coresLoad: cpu.cpus.map(c => parseFloat(c.load.toFixed(2)))
    },
    memory: {
      usage: parseFloat(memoryUsage.toFixed(2)),
      total: mem.total,
      used: mem.active,
      free: mem.available
    },
    disk: {
      usage: parseFloat(diskUsage.toFixed(2)),
      total: fsSize[0] ? fsSize[0].size : 0,
      used: fsSize[0] ? fsSize[0].used : 0,
      fs: fsSize[0] ? fsSize[0].fs : '',
      mount: fsSize[0] ? fsSize[0].mount : ''
    },
    network: {
      up: networkUp,
      down: networkDown,
      upMB: parseFloat((networkUp / 1024 / 1024).toFixed(2)),
      downMB: parseFloat((networkDown / 1024 / 1024).toFixed(2))
    },
    topProcesses
  };
}

function checkAlerts(data) {
  const alerts = [];
  
  if (data.cpu.usage >= alertThresholds.cpu) {
    alerts.push({
      type: 'cpu',
      level: data.cpu.usage >= 95 ? 'critical' : 'warning',
      message: `CPU使用率过高: ${data.cpu.usage}%`,
      value: data.cpu.usage,
      threshold: alertThresholds.cpu,
      timestamp: data.timestamp
    });
  }
  
  if (data.memory.usage >= alertThresholds.memory) {
    alerts.push({
      type: 'memory',
      level: data.memory.usage >= 95 ? 'critical' : 'warning',
      message: `内存使用率过高: ${data.memory.usage}%`,
      value: data.memory.usage,
      threshold: alertThresholds.memory,
      timestamp: data.timestamp
    });
  }
  
  if (data.disk.usage >= alertThresholds.disk) {
    alerts.push({
      type: 'disk',
      level: data.disk.usage >= 98 ? 'critical' : 'warning',
      message: `磁盘使用率过高: ${data.disk.usage}%`,
      value: data.disk.usage,
      threshold: alertThresholds.disk,
      timestamp: data.timestamp
    });
  }
  
  if (alerts.length > 0) {
    alertHistory.unshift(...alerts);
    if (alertHistory.length > 100) {
      alertHistory = alertHistory.slice(0, 100);
    }
    
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('alerts', alerts);
    }
  }
}

function isOutsideBaseline(type, value) {
  const config = baselineConfig[type];
  if (!config || !config.enabled) return false;
  return value < config.min || value > config.max;
}

function checkBaselineAnomalies(data) {
  const metrics = [
    { type: 'cpu', value: data.cpu.usage },
    { type: 'memory', value: data.memory.usage },
    { type: 'disk', value: data.disk.usage }
  ];

  for (const metric of metrics) {
    recentSamples[metric.type].push({
      value: metric.value,
      timestamp: data.timestamp,
      processes: data.topProcesses
    });

    if (recentSamples[metric.type].length > MAX_SAMPLES) {
      recentSamples[metric.type].shift();
    }

    if (recentSamples[metric.type].length === MAX_SAMPLES) {
      const allOutside = recentSamples[metric.type].every(
        s => isOutsideBaseline(metric.type, s.value)
      );

      const now = Date.now();
      if (allOutside && now > cooldownUntil[metric.type]) {
        generateAnomalyReport(metric.type, [...recentSamples[metric.type]]);
        cooldownUntil[metric.type] = now + COOLDOWN_MS;
        recentSamples[metric.type] = [];
      }
    }
  }
}

function generateAnomalyReport(type, samples) {
  const config = baselineConfig[type];
  const values = samples.map(s => s.value);
  const avg = values.reduce((a, b) => a + b, 0) / values.length;
  const max = Math.max(...values);
  const min = Math.min(...values);

  const exceedAmount = Math.max(0, max - config.max) + Math.max(0, config.min - min);
  const baselineRange = config.max - config.min;
  const exceedPercent = baselineRange > 0 ? parseFloat(((exceedAmount / baselineRange) * 100).toFixed(2)) : 0;

  const allProcesses = samples.flatMap(s => s.processes || []);
  const processMap = new Map();
  for (const p of allProcesses) {
    if (!processMap.has(p.pid)) {
      processMap.set(p.pid, { ...p, count: 0, cpuSum: 0, memSum: 0 });
    }
    const existing = processMap.get(p.pid);
    existing.count++;
    existing.cpuSum += p.cpu;
    existing.memSum += p.mem;
  }

  const topProcesses = Array.from(processMap.values())
    .map(p => ({
      pid: p.pid,
      name: p.name,
      avgCpu: parseFloat((p.cpuSum / p.count).toFixed(2)),
      avgMem: parseFloat((p.memSum / p.count).toFixed(2)),
      occurrenceCount: p.count
    }))
    .sort((a, b) => {
      if (type === 'cpu') return b.avgCpu - a.avgCpu;
      return b.avgMem - a.avgMem;
    })
    .slice(0, 3);

  const reportId = `${type}_${Date.now()}`;
  const now = new Date();
  const fileName = `anomaly_${type}_${now.toISOString().slice(0, 10)}_${now.toISOString().slice(11, 19).replace(/:/g, '-')}.json`;
  const filePath = path.join(reportsDir, fileName);

  const report = {
    id: reportId,
    type,
    typeName: { cpu: 'CPU', memory: '内存', disk: '磁盘' }[type],
    generatedAt: now.toISOString(),
    startTime: samples[0].timestamp,
    endTime: samples[samples.length - 1].timestamp,
    sampleCount: samples.length,
    baseline: {
      min: config.min,
      max: config.max
    },
    statistics: {
      average: parseFloat(avg.toFixed(2)),
      maximum: parseFloat(max.toFixed(2)),
      minimum: parseFloat(min.toFixed(2))
    },
    exceedPercent,
    samples: samples.map(s => ({
      timestamp: s.timestamp,
      value: s.value
    })),
    topProcesses
  };

  try {
    fs.writeFileSync(filePath, JSON.stringify(report, null, 2), 'utf-8');

    anomalyReports.unshift({
      id: reportId,
      type,
      typeName: report.typeName,
      generatedAt: report.generatedAt,
      startTime: report.startTime,
      endTime: report.endTime,
      sampleCount: report.sampleCount,
      statistics: report.statistics,
      exceedPercent,
      fileName,
      filePath
    });

    if (anomalyReports.length > 500) {
      anomalyReports = anomalyReports.slice(0, 500);
    }

    saveReportsIndex();

    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('anomaly-report-generated', anomalyReports[0]);
    }

    console.log(`异常报告已生成: ${filePath}`);
  } catch (err) {
    console.error('生成异常报告失败:', err);
  }
}

ipcMain.on('start-logging', async (event) => {
  if (logManager && logManager.isLogging) {
    event.reply('logging-status', getLoggingStatus());
    return;
  }

  const result = await dialog.showOpenDialog(mainWindow, {
    title: '选择日志保存目录',
    defaultPath: app.getPath('documents'),
    properties: ['openDirectory', 'createDirectory']
  });

  if (result.canceled || result.filePaths.length === 0) {
    event.reply('logging-status', { running: false, file: '' });
    return;
  }

  const logDir = result.filePaths[0];

  logManager = new LogManager({
    splitStrategy,
    maxFileSize,
    flushInterval: Math.max(2000, logIntervalMs),
    logDir,
    baseName: 'performance_log'
  });

  logManager.on('file-created', (info) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('log-file-created', info);
    }
  });

  logManager.on('flushed', (info) => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('log-flushed', info);
    }
  });

  logManager.on('error', (err) => {
    console.error('日志管理错误:', err);
  });

  try {
    await logManager.start();
    event.reply('logging-status', getLoggingStatus());
  } catch (err) {
    event.reply('logging-status', { running: false, file: '', error: err.message });
  }
});

ipcMain.on('stop-logging', async (event) => {
  if (logManager) {
    await logManager.stop();
  }
  event.reply('logging-status', getLoggingStatus());
});

ipcMain.on('get-logging-status', (event) => {
  event.reply('logging-status', getLoggingStatus());
});

function getLoggingStatus() {
  if (!logManager) {
    return { running: false, file: '', records: 0, files: [] };
  }
  return {
    running: logManager.isLogging,
    file: logManager.getCurrentFile(),
    records: logManager.getCurrentRecordCount(),
    totalRecords: logManager.getTotalRecordCount(),
    files: logManager.getFileList()
  };
}

ipcMain.on('get-alert-history', (event) => {
  event.reply('alert-history', alertHistory);
});

ipcMain.on('update-thresholds', (event, thresholds) => {
  alertThresholds = { ...alertThresholds, ...thresholds };
  if (thresholds.splitStrategy) {
    splitStrategy = thresholds.splitStrategy;
  }
  if (thresholds.maxFileSize) {
    maxFileSize = thresholds.maxFileSize;
  }
  event.reply('thresholds-updated', { ...alertThresholds, splitStrategy, maxFileSize });
});

ipcMain.on('get-thresholds', (event) => {
  event.reply('thresholds-data', { ...alertThresholds, splitStrategy, maxFileSize });
});

ipcMain.on('export-report', async (event, options = {}) => {
  if (!logManager) {
    event.reply('export-error', { error: '未启动日志记录' });
    return;
  }

  const totalRecords = logManager.getTotalRecordCount();
  if (totalRecords === 0) {
    event.reply('export-error', { error: '没有可导出的数据' });
    return;
  }

  const filters = [];
  if (options.startTime) filters.push(`开始时间: ${options.startTime}`);
  if (options.endTime) filters.push(`结束时间: ${options.endTime}`);
  const filterStr = filters.length > 0 ? `_${filters.map(f => f.replace(/[:\s]/g, '-')).join('_')}` : '';

  const result = await dialog.showSaveDialog(mainWindow, {
    title: '导出性能报告',
    defaultPath: `performance_report_${new Date().toISOString().slice(0, 10)}${filterStr}.${options.format || 'csv'}`,
    filters: [
      { name: 'CSV 文件', extensions: ['csv'] },
      { name: 'JSON 文件', extensions: ['json'] }
    ]
  });

  if (result.canceled) return;

  const filePath = result.filePath;
  const format = filePath.endsWith('.csv') ? 'csv' : 'json';
  
  try {
    const exportResult = await logManager.exportReport({
      format,
      outputPath: filePath,
      startTime: options.startTime,
      endTime: options.endTime,
      includeProcesses: options.includeProcesses !== false
    });
    
    event.reply('export-success', { 
      file: filePath, 
      count: exportResult.totalExported 
    });
  } catch (err) {
    event.reply('export-error', { error: err.message });
  }
});

ipcMain.on('query-history', async (event, options = {}) => {
  if (!logManager) {
    event.reply('history-result', { data: [], total: 0, hasMore: false });
    return;
  }

  try {
    const result = await logManager.queryRecords(options);
    event.reply('history-result', result);
  } catch (err) {
    event.reply('history-result', { data: [], total: 0, hasMore: false, error: err.message });
  }
});

ipcMain.on('get-log-files', (event) => {
  if (!logManager) {
    event.reply('log-files', []);
    return;
  }
  event.reply('log-files', logManager.getFileList());
});

ipcMain.on('set-log-interval', (event, ms) => {
  logIntervalMs = ms;
  event.reply('log-interval-updated', logIntervalMs);
});

ipcMain.on('delete-old-logs', async (event, daysToKeep) => {
  if (!logManager) {
    event.reply('old-logs-deleted', { count: 0 });
    return;
  }
  
  try {
    const count = await logManager.deleteOldFiles(daysToKeep);
    event.reply('old-logs-deleted', { count });
  } catch (err) {
    event.reply('export-error', { error: err.message });
  }
});

ipcMain.on('get-history-data', (event) => {
  event.reply('history-data', []);
});

ipcMain.on('get-baseline-config', (event) => {
  event.reply('baseline-config', JSON.parse(JSON.stringify(baselineConfig)));
});

ipcMain.on('update-baseline-config', (event, newConfig) => {
  try {
    baselineConfig = {
      cpu: { ...baselineConfig.cpu, ...newConfig.cpu },
      memory: { ...baselineConfig.memory, ...newConfig.memory },
      disk: { ...baselineConfig.disk, ...newConfig.disk }
    };
    event.reply('baseline-config-updated', JSON.parse(JSON.stringify(baselineConfig)));
  } catch (err) {
    event.reply('baseline-config-error', { error: err.message });
  }
});

ipcMain.on('get-anomaly-reports', (event) => {
  event.reply('anomaly-reports', JSON.parse(JSON.stringify(anomalyReports)));
});

ipcMain.on('get-anomaly-report-detail', (event, reportId) => {
  try {
    const reportMeta = anomalyReports.find(r => r.id === reportId);
    if (!reportMeta) {
      event.reply('anomaly-report-detail', { error: '报告不存在' });
      return;
    }

    const content = fs.readFileSync(reportMeta.filePath, 'utf-8');
    const reportDetail = JSON.parse(content);
    event.reply('anomaly-report-detail', reportDetail);
  } catch (err) {
    event.reply('anomaly-report-detail', { error: err.message });
  }
});

ipcMain.on('download-anomaly-report', async (event, reportId) => {
  try {
    const reportMeta = anomalyReports.find(r => r.id === reportId);
    if (!reportMeta) {
      event.reply('download-report-error', { error: '报告不存在' });
      return;
    }

    const result = await dialog.showSaveDialog(mainWindow, {
      title: '保存异常报告',
      defaultPath: reportMeta.fileName,
      filters: [{ name: 'JSON 文件', extensions: ['json'] }]
    });

    if (result.canceled) return;

    const content = fs.readFileSync(reportMeta.filePath, 'utf-8');
    fs.writeFileSync(result.filePath, content, 'utf-8');
    event.reply('download-report-success', { file: result.filePath });
  } catch (err) {
    event.reply('download-report-error', { error: err.message });
  }
});

ipcMain.on('delete-anomaly-report', (event, reportId) => {
  try {
    const index = anomalyReports.findIndex(r => r.id === reportId);
    if (index === -1) {
      event.reply('delete-report-error', { error: '报告不存在' });
      return;
    }

    const reportMeta = anomalyReports[index];
    if (fs.existsSync(reportMeta.filePath)) {
      fs.unlinkSync(reportMeta.filePath);
    }

    anomalyReports.splice(index, 1);
    saveReportsIndex();
    event.reply('delete-report-success', { id: reportId });
  } catch (err) {
    event.reply('delete-report-error', { error: err.message });
  }
});
