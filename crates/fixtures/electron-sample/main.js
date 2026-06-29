// Deliberately insecure Electron main process — used as a known-vulnerable
// fixture for Achilles' static-analysis rules. DO NOT copy these settings into
// a real app.
const { app, BrowserWindow } = require("electron");

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      sandbox: false, // disables the renderer sandbox
      nodeIntegration: true, // exposes Node APIs to the renderer
      contextIsolation: false, // shares the main-world context with preload
      webSecurity: false, // disables same-origin enforcement
    },
  });

  win.loadFile("index.html");
}

app.whenReady().then(createWindow);
