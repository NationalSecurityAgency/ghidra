const healthEl = document.getElementById("health");
const projectsListEl = document.getElementById("projectsList");
const formMessageEl = document.getElementById("formMessage");
const projectPathEl = document.getElementById("createProjectPath");
const projectNameEl = document.getElementById("createProjectName");
const createProjectBtnEl = document.getElementById("createProjectBtn");
const browseProjectPathBtnEl = document.getElementById("browseProjectPathBtn");
const refreshProjectsBtnEl = document.getElementById("refreshProjectsBtn");
const api = window.headlessApi;

function requireApi() {
  if (!api) {
    throw new Error("Electron preload bridge is unavailable. Restart the app.");
  }
  return api;
}

function setHealth(text, online) {
  healthEl.textContent = text;
  healthEl.classList.toggle("online", online);
  healthEl.classList.toggle("offline", !online);
}

function setFormMessage(message, tone = "muted") {
  formMessageEl.textContent = message;
  formMessageEl.dataset.tone = tone;
}

function setBusy(isBusy) {
  createProjectBtnEl.disabled = isBusy;
  browseProjectPathBtnEl.disabled = isBusy;
}

async function refreshHealth() {
  try {
    const health = await requireApi().health();
    setHealth(`Backend ${health.data.status}`, true);
  } catch (error) {
    setHealth(`Backend offline: ${error.message}`, false);
  }
}

function formatProjectLocation(project) {
  const pathParts = project.projectPath.split(/[\\/]/);
  pathParts.pop();
  return pathParts.join("/") || project.projectPath;
}

function renderProjects(projects) {
  projectsListEl.innerHTML = "";
  if (!projects.length) {
    projectsListEl.innerHTML = `
      <div class="project-card empty-state">
        <div class="project-title">No remembered projects yet</div>
        <div class="project-meta">
          Create your first project and its location will appear here the next time you open the app.
        </div>
      </div>
    `;
    return;
  }

  for (const project of projects) {
    const card = document.createElement("div");
    card.className = "project-card";
    card.innerHTML = `
      <div class="project-title">${project.name}</div>
      <div class="project-meta"><strong>Directory:</strong> ${formatProjectLocation(project)}</div>
      <div class="project-meta"><strong>Project Path:</strong> ${project.projectPath}</div>
      <div class="project-meta">
        <strong>Status:</strong> ${project.existsOnDisk ? "available" : "missing on disk"}
      </div>
    `;
    projectsListEl.appendChild(card);
  }
}

async function refreshProjects() {
  const response = await requireApi().listProjects();
  renderProjects(response.data.projects || []);
}

async function browseProjectDirectory() {
  const selectedPath = await requireApi().chooseProjectDirectory();
  if (selectedPath) {
    projectPathEl.value = selectedPath;
    setFormMessage("Project directory selected.", "muted");
  }
}

async function createProject() {
  const projectPath = projectPathEl.value.trim();
  const projectName = projectNameEl.value.trim();
  if (!projectPath || !projectName) {
    throw new Error("Projects directory and project name are required.");
  }

  setBusy(true);
  setFormMessage("Creating project...", "muted");
  try {
    const response = await requireApi().createProject(projectPath, projectName);
    await refreshProjects();
    setFormMessage(
      `Created ${response.data.project.name} at ${response.data.project.projectPath}.`,
      "success"
    );
    projectNameEl.value = "";
  } finally {
    setBusy(false);
  }
}

browseProjectPathBtnEl.addEventListener("click", async () => {
  try {
    await browseProjectDirectory();
  } catch (error) {
    setFormMessage(error.message, "error");
  }
});

createProjectBtnEl.addEventListener("click", async () => {
  try {
    await createProject();
  } catch (error) {
    setFormMessage(error.message, "error");
  }
});

refreshProjectsBtnEl.addEventListener("click", async () => {
  try {
    await refreshProjects();
    setFormMessage("Remembered project locations refreshed.", "muted");
  } catch (error) {
    setFormMessage(error.message, "error");
  }
});

refreshHealth();
refreshProjects().catch((error) => {
  setFormMessage(error.message, "error");
});
