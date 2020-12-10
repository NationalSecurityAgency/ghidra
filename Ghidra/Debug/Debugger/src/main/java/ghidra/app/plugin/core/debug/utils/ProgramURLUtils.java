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
package ghidra.app.plugin.core.debug.utils;

import java.net.MalformedURLException;
import java.net.URL;

import ghidra.app.services.ProgramManager;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;

public enum ProgramURLUtils {
	;

	public static URL getUrlFromProgram(Program program) {
		DomainFile file = program.getDomainFile();
		ProjectLocator projectLocator = file.getProjectLocator();
		if (projectLocator == null) {
			return null;
		}
		RepositoryAdapter repository = file.getParent().getProjectData().getRepository();
		if (repository != null) { // There is an associated remote repo
			if (file.isVersioned()) { // The domain file exists there
				ServerInfo server = repository.getServerInfo();
				return GhidraURL.makeURL(server.getServerName(), server.getPortNumber(),
					repository.getName(), file.getPathname());
			}
		}
		return hackAddLocalDomainFilePath(projectLocator.getURL(), file.getPathname());
	}

	protected static URL hackAddLocalDomainFilePath(URL localProjectURL, String pathname) {
		try {
			return new URL(localProjectURL.toExternalForm() + "!" + pathname);
		}
		catch (MalformedURLException e) {
			throw new AssertionError(e);
		}
	}

	public static DomainFile getFileForHackedUpGhidraURL(Project project, URL ghidraURL) {
		try {
			String asString = ghidraURL.toExternalForm();
			int bangLoc = asString.indexOf('!');
			if (bangLoc == -1) {
				ProjectData projectData = project.getProjectData(ghidraURL);
				if (projectData == null) {
					return null;
				}
				return projectData.getFile(ghidraURL.getPath());
			}
			URL localProjURL = new URL(asString.substring(0, bangLoc));
			ProjectData projectData = project.getProjectData(localProjURL);
			return projectData.getFile(asString.substring(bangLoc + 1));
		}
		catch (MalformedURLException e) {
			throw new AssertionError(e);
		}
	}

	public static Program openHackedUpGhidraURL(ProgramManager programManager, Project project,
			URL ghidraURL, int state) {
		DomainFile file = getFileForHackedUpGhidraURL(project, ghidraURL);
		return programManager.openProgram(file, DomainFile.DEFAULT_VERSION, state);
	}
}
