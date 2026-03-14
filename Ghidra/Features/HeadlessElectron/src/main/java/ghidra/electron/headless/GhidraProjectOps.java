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
import java.nio.file.*;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraJarApplicationLayout;
import ghidra.framework.*;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.util.NotOwnerException;
import ghidra.util.exception.NotFoundException;

interface GhidraProjectOps {
	void createProject(String projectDirectory, String projectName) throws IOException;

	void validateProjectOpen(String projectDirectory, String projectName) throws IOException;

	boolean projectExists(String projectDirectory, String projectName);
}

class DefaultGhidraProjectOps implements GhidraProjectOps {
	private static final Object INIT_LOCK = new Object();

	DefaultGhidraProjectOps() throws IOException {
	}

	@Override
	public void createProject(String projectDirectory, String projectName) throws IOException {
		ensureInitialized();
		Path parent = Paths.get(projectDirectory);
		if (!Files.isDirectory(parent)) {
			throw new ApiException(422, "VALIDATION_ERROR", "The request failed validation.",
				Map.of("fields", Map.of("projectPath", "Directory does not exist")));
		}
		ProjectLocator locator = new ProjectLocator(parent.toString(), projectName);
		if (locator.getProjectDir().exists()) {
			throw new ApiException(409, "PROJECT_ALREADY_EXISTS",
				"A project already exists at the requested location.",
				Map.of("projectPath", locator.getProjectDir().getAbsolutePath()));
		}
		ServiceProjectManager pm = new ServiceProjectManager();
		Project project = pm.createProject(locator, null, false);
		if (project != null) {
			project.close();
		}
	}

	@Override
	public void validateProjectOpen(String projectDirectory, String projectName) throws IOException {
		ensureInitialized();
		ProjectLocator locator = new ProjectLocator(projectDirectory, projectName);
		if (!locator.getProjectDir().exists()) {
			throw new ApiException(404, "PROJECT_NOT_FOUND", "The requested project could not be found.",
				Map.of("projectPath", locator.getProjectDir().getAbsolutePath()));
		}
		ServiceProjectManager pm = new ServiceProjectManager();
		try {
			Project project = pm.openProject(locator, false, false);
			project.close();
		}
		catch (NotFoundException e) {
			throw new ApiException(404, "PROJECT_NOT_FOUND",
				"The requested project could not be found.",
				Map.of("projectPath", locator.getProjectDir().getAbsolutePath()));
		}
		catch (NotOwnerException | LockException e) {
			throw new ApiException(409, "PROJECT_NOT_FOUND",
				"The requested project could not be opened.",
				Map.of("projectPath", locator.getProjectDir().getAbsolutePath(), "reason",
					e.getMessage()));
		}
	}

	@Override
	public boolean projectExists(String projectDirectory, String projectName) {
		return new ProjectLocator(projectDirectory, projectName).getProjectDir().exists();
	}

	private static void ensureInitialized() throws IOException {
		if (Application.isInitialized()) {
			return;
		}
		synchronized (INIT_LOCK) {
			if (Application.isInitialized()) {
				return;
			}
			System.setProperty("java.awt.headless", "true");
			GhidraApplicationLayout layout;
			try {
				layout = new GhidraApplicationLayout();
			}
			catch (IOException e) {
				layout = new GhidraJarApplicationLayout();
			}
			HeadlessGhidraApplicationConfiguration config =
				new HeadlessGhidraApplicationConfiguration();
			config.setInitializeLogging(false);
			Application.initializeApplication(layout, config);
		}
	}

	private static class ServiceProjectManager extends DefaultProjectManager {
		// Intentionally empty; exists only to expose the protected constructor.
	}
}
