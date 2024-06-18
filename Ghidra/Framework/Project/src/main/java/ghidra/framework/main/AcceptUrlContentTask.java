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
package ghidra.framework.main;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Set;

import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURLQueryTask;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class AcceptUrlContentTask extends GhidraURLQueryTask {

	private FrontEndPlugin plugin;

	public AcceptUrlContentTask(URL url, FrontEndPlugin plugin) {
		super("Accepting URL", url);
		this.plugin = plugin;
	}

	private boolean isSameLocalProject(ProjectLocator projectLoc1, ProjectLocator projectLoc2) {
		if (projectLoc1.isTransient() || projectLoc2.isTransient()) {
			return false;
		}
		if (!projectLoc1.getName().equals(projectLoc2.getName())) {
			return false;
		}
		try {
			File proj1Dir = projectLoc1.getProjectDir().getCanonicalFile();
			File proj2Dir = projectLoc2.getProjectDir().getCanonicalFile();
			return proj1Dir.equals(proj2Dir);
		}
		catch (IOException e) {
			return false;
		}
	}

	@Override
	public void processResult(DomainFile domainFile, URL url, TaskMonitor monitor)
			throws IOException {

		Project activeProject = AppInfo.getActiveProject();
		if (activeProject == null) {
			Msg.showError(this, null, "Ghidra Error",
				"Unable to accept URL without active project open");
			return;
		}

		Swing.runNow(() -> {
			if (FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE
					.equals(domainFile.getContentType())) {
				// Simply select folder link-file within project - do not follow - let user do that.
				if (isSameLocalProject(activeProject.getProjectLocator(),
					domainFile.getProjectLocator())) {
					// Select file within active project
					DomainFile df =
						activeProject.getProjectData().getFile(domainFile.getPathname());
					if (df == null) {
						return; // unexpected race condition
					}
					plugin.selectFiles(Set.of(df));
				}
				else {
					// Select file within read-only viewed project
					plugin.showInViewedProject(url, false);
				}
			}
			else {
				AppInfo.getFrontEndTool().getToolServices().launchDefaultToolWithURL(url);
			}
		});
	}

	@Override
	public void processResult(DomainFolder domainFolder, URL url, TaskMonitor monitor)
			throws IOException {

		Project activeProject = AppInfo.getActiveProject();
		if (activeProject == null) {
			Msg.showError(this, null, "Ghidra Error",
				"Unable to accept URL without active project open");
			return;
		}

		Swing.runNow(() -> {
			if (isSameLocalProject(activeProject.getProjectLocator(),
				domainFolder.getProjectLocator())) {
				// Select folder within active project
				DomainFolder df =
					activeProject.getProjectData().getFolder(domainFolder.getPathname());
				if (df == null) {
					return; // unexpected race condition
				}
				plugin.selectFolder(df);
			}
			else {
				// Select folder within read-only viewed project
				plugin.showInViewedProject(url, true);
			}
		});

	}

}
