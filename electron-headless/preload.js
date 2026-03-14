const { randomUUID } = require("node:crypto");

const baseUrl = process.env.GHIDRA_BACKEND_URL || "http://127.0.0.1:8089";

async function jsonRequest(path, method = "GET", body = null) {
  const options = {
    method,
    headers: {
      "Content-Type": "application/json",
      "X-Request-Id": randomUUID()
    }
  };
  if (body !== null) {
    options.body = JSON.stringify(body);
  }
  const response = await fetch(`${baseUrl}${path}`, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error?.message || `HTTP ${response.status}`);
  }
  return payload;
}

const fallbackApi = {
  baseUrl,
  health: () => jsonRequest("/api/v1/health"),
  listProjects: () => jsonRequest("/api/v1/projects"),
  createProject: (projectPath, projectName) =>
    jsonRequest("/api/v1/projects", "POST", { projectPath, projectName }),
  chooseProjectDirectory: async () => {
    throw new Error("Native directory picker is not available.");
  }
};

try {
  const { contextBridge, ipcRenderer } = require("electron");
  const api = {
    ...fallbackApi,
    chooseProjectDirectory: () => {
      if (!ipcRenderer) {
        throw new Error("Electron IPC bridge is unavailable.");
      }
      return ipcRenderer.invoke("headless:choose-project-directory");
    }
  };

  window.headlessApi = api;
  if (contextBridge && process.contextIsolated) {
    contextBridge.exposeInMainWorld("headlessApi", api);
  }
} catch (error) {
  console.error(error);
  window.headlessApi = fallbackApi;
}
