const path = require("node:path");

async function loadElectronMain() {
  try {
    return require("electron");
  } catch (error) {
    // Fall through to alternate module shapes used by some Electron builds.
  }
  try {
    const mod = await import("electron/main");
    return mod.default ?? mod;
  } catch (error) {
    const mod = await import("electron");
    return mod.default ?? mod;
  }
}

async function main() {
  const electron = await loadElectronMain();
  const { app, BrowserWindow, dialog, ipcMain } = electron;
  if (!app || !BrowserWindow || !dialog || !ipcMain) {
    throw new Error("Electron main-process APIs are unavailable.");
  }

  function createWindow() {
    const window = new BrowserWindow({
      width: 1060,
      height: 760,
      minWidth: 900,
      minHeight: 640,
      webPreferences: {
        preload: path.join(__dirname, "preload.js"),
        contextIsolation: false,
        sandbox: false
      }
    });

    window.loadFile(path.join(__dirname, "renderer", "index.html"));
  }

  await app.whenReady();
  ipcMain.handle("headless:choose-project-directory", async () => {
    const result = await dialog.showOpenDialog({
      title: "Choose Projects Directory",
      properties: ["openDirectory", "createDirectory"]
    });
    if (result.canceled || !result.filePaths.length) {
      return null;
    }
    return result.filePaths[0];
  });
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
  app.on("window-all-closed", () => {
    if (process.platform !== "darwin") {
      app.quit();
    }
  });
  app.on("will-quit", () => {
    ipcMain.removeHandler("headless:choose-project-directory");
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
