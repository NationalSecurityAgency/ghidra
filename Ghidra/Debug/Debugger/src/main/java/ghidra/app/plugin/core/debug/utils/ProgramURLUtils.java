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

import java.net.URL;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Program;

public enum ProgramURLUtils {
	;

	/**
	 * Get any URL for the given program, preferably its URL in a shared project.
	 * 
	 * @param program the program
	 * @return the URL or null, if the program does not belong to a project
	 */
	public static URL getUrlFromProgram(Program program) {
		DomainFile file = program.getDomainFile();
		/**
		 * TODO: Could we have a version that does not take ref? Could be a default method in
		 * DomainFile that just delegates using ref=null.
		 */
		URL sharedUrl = file.getSharedProjectURL(null);
		if (sharedUrl != null) {
			return sharedUrl;
		}
		return file.getLocalProjectURL(null);
	}

	public static boolean isProjectDataURL(ProjectData data, URL url) {
		URL projectURL = GhidraURL.getProjectURL(url);

		// TODO: This is a bit awkward. Could ProjectData have getSharedProjectURL?
		URL sharedURL = data.getRootFolder().getSharedProjectURL();
		if (sharedURL != null && GhidraURL.getProjectURL(sharedURL).equals(projectURL)) {
			return true;
		}
		// TODO: This is a bit awkward. Could ProjectData have getLocalProjectURL?
		URL localURL = data.getRootFolder().getLocalProjectURL();
		if (localURL != null && GhidraURL.getProjectURL(localURL).equals(projectURL)) {
			return true;
		}
		return false;
	}

	/**
	 * Get the domain file for the given URL from the given project or any of its open views.
	 * 
	 * <p>
	 * The URL may point to a file in a local or shared project. If the URL points to a shared
	 * project and there is a local checkout of the file, this will return the checked out copy,
	 * even though it may not be the latest from the repository (or maybe even hijacked). If the
	 * containing project is not currently open, this will return {@code null}.
	 * 
	 * @param project the active project
	 * @param url the URL of the domain file
	 * @return the domain file, or null
	 */
	public static DomainFile getDomainFileFromOpenProject(Project project, URL url) {
		if (isProjectDataURL(project.getProjectData(), url)) {
			return project.getProjectData().getFile(GhidraURL.getProjectPathname(url));
		}
		for (ProjectData data : project.getViewedProjectData()) {
			if (isProjectDataURL(data, url)) {
				return data.getFile(GhidraURL.getProjectPathname(url));
			}
		}
		return null;
	}

	/**
	 * Open the domain file for the given URL from the given project or any of its open views.
	 * 
	 * <p>
	 * This uses {@link #getDomainFileFromOpenProject(Project, URL)} to locate the domain file, so
	 * see its behavior and caveats. It opens the default version of the file. If the file does not
	 * exist, or its project is not currently open, this returns {@code null}.
	 * 
	 * @see #getDomainFileFromOpenProject(Project, URL)
	 * @param programManager the program manager
	 * @param project the active project
	 * @param url the URL fo the domain file
	 * @param state the initial open state of the program in the manager
	 * @return the program or null
	 */
	public static Program openDomainFileFromOpenProject(ProgramManager programManager,
			Project project, URL url, int state) {
		DomainFile file = getDomainFileFromOpenProject(project, url);
		if (file == null) {
			return null;
		}
		return programManager.openProgram(file, DomainFile.DEFAULT_VERSION, state);
	}
}
