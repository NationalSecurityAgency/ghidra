/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.electron.headless;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

import com.google.gson.reflect.TypeToken;

class ProjectStore {
	private final Path storeFile;
	private final GhidraProjectOps projectOps;
	private final EventBroker eventBroker;
	private final Map<String, ProjectRecord> projectsById = new LinkedHashMap<>();

	ProjectStore(Path dataDir, GhidraProjectOps projectOps, EventBroker eventBroker)
			throws IOException {
		this.storeFile = dataDir.resolve("projects.json");
		this.projectOps = projectOps;
		this.eventBroker = eventBroker;
		Files.createDirectories(dataDir);
		load();
	}

	synchronized List<ProjectRecord> listProjects() {
		refreshExistsFlags();
		List<ProjectRecord> projects = new ArrayList<>(projectsById.values());
		projects.sort(Comparator.comparing(
			(ProjectRecord p) -> Optional.ofNullable(p.lastOpenedAt).orElse("")).reversed());
		return projects;
	}

	synchronized ProjectRecord getProject(String projectId) {
		ProjectRecord project = projectsById.get(projectId);
		if (project == null) {
			throw new ApiException(404, "PROJECT_NOT_FOUND",
				"The requested project could not be found.", Map.of("projectId", projectId));
		}
		project.existsOnDisk = Files.isDirectory(Paths.get(project.projectPath));
		return project;
	}

	synchronized ProjectRecord createProject(String projectDirectory, String projectName)
			throws IOException {
		projectOps.createProject(projectDirectory, projectName);
		ProjectRecord record = ProjectRecord.create(nextProjectId(), projectName,
			Paths.get(projectDirectory, projectName).toAbsolutePath().toString(), true, false);
		projectsById.put(record.projectId, record);
		save();
		eventBroker.publish("project.created", Map.of("projectId", record.projectId, "timestamp",
			Instant.now().toString(), "project", record));
		return record;
	}

	synchronized ProjectRecord openProjectById(String projectId) throws IOException {
		ProjectRecord record = getProject(projectId);
		return activateRecord(record);
	}

	synchronized ProjectRecord openProjectByPathAndName(String projectDirectory, String projectName)
			throws IOException {
		String fullPath = Paths.get(projectDirectory, projectName).toAbsolutePath().toString();
		ProjectRecord record =
			projectsById.values().stream().filter(p -> p.projectPath.equals(fullPath)).findFirst().orElse(null);
		if (record == null) {
			if (!projectOps.projectExists(projectDirectory, projectName)) {
				throw new ApiException(404, "PROJECT_NOT_FOUND",
					"The requested project could not be found.",
					Map.of("projectPath", fullPath));
			}
			record = ProjectRecord.create(nextProjectId(), projectName, fullPath, true, false);
			projectsById.put(record.projectId, record);
		}
		return activateRecord(record);
	}

	private ProjectRecord activateRecord(ProjectRecord record) throws IOException {
		Path fullPath = Paths.get(record.projectPath);
		projectOps.validateProjectOpen(Optional.ofNullable(fullPath.getParent()).orElse(fullPath).toString(),
			fullPath.getFileName().toString());
		for (ProjectRecord candidate : projectsById.values()) {
			candidate.isActive = false;
		}
		record.isActive = true;
		record.lastOpenedAt = Instant.now().toString();
		record.existsOnDisk = Files.isDirectory(Paths.get(record.projectPath));
		save();
		eventBroker.publish("project.opened", Map.of("projectId", record.projectId, "timestamp",
			record.lastOpenedAt, "project", record));
		return record;
	}

	private void refreshExistsFlags() {
		for (ProjectRecord record : projectsById.values()) {
			record.existsOnDisk = Files.isDirectory(Paths.get(record.projectPath));
		}
	}

	private String nextProjectId() {
		return "proj_" + UUID.randomUUID().toString().replace("-", "");
	}

	private void load() throws IOException {
		if (!Files.exists(storeFile)) {
			return;
		}
		String json = Files.readString(storeFile, StandardCharsets.UTF_8);
		List<ProjectRecord> records = JsonSupport.GSON.fromJson(json,
			new TypeToken<List<ProjectRecord>>() {
			}.getType());
		if (records == null) {
			return;
		}
		for (ProjectRecord record : records) {
			projectsById.put(record.projectId, record);
		}
	}

	private void save() throws IOException {
		Files.writeString(storeFile,
			JsonSupport.GSON.toJson(new ArrayList<>(projectsById.values())), StandardCharsets.UTF_8,
			StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
	}
}
