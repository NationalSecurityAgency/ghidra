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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

import docking.action.MenuData;
import ghidra.framework.data.LinkHandler;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.ProjectData;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class ProjectDataFollowLinkAction extends FrontendProjectTreeAction {

	private FrontEndPlugin plugin;

	public ProjectDataFollowLinkAction(FrontEndPlugin plugin, String group) {
		super("Follow Link", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Follow Link" }, group));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Follow_Link"));
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {

		List<DomainFile> selectedFiles = context.getSelectedFiles();
		if (selectedFiles.size() != 1) {
			return;
		}
		DomainFile file = selectedFiles.get(0);
		if (!file.isLink()) {
			return;
		}

		// Folder link may refer to another folder link
		String linkPath;
		try {
			linkPath = LinkHandler.getAbsoluteLinkPath(file);
			if (linkPath == null) {
				Msg.showError(this, context.getComponent(), "Invalid Link",
					"Link-file failed to provide link path: " + file);
				return;
			}
		}
		catch (IOException e) {
			Msg.showError(this, context.getComponent(), "Invalid Link", e.getMessage());
			return;
		}

		boolean isFolderLink = file.getLinkInfo().isFolderLink();
		if (GhidraURL.isGhidraURL(linkPath)) {
			// Follow URL using a project view
			try {
				plugin.showInViewedProject(new URL(linkPath), isFolderLink);
				return;
			}
			catch (MalformedURLException e) {
				Msg.error(this, "Invalid link URL: " + e.getMessage());
				return;
			}
		}

		// Check internal link
		ProjectData projectData = context.getProjectData();
		boolean isFolder = isFolderLink && projectData.getFolder(linkPath) != null;
		if (!isFolder) {
			DomainFile referencedFile = projectData.getFile(linkPath);
			if (referencedFile == null) {
				// referenced folder or file not found
				return;
			}
		}

		// Path is local to its project data tree
		plugin.showInProjectTree(context.getProjectData(), linkPath, isFolder);
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		if (!(context.getComponent() instanceof DataTree)) {
			return false;
		}
		if (context.getFolderCount() != 0 || context.getFileCount() != 1) {
			return false;
		}
		DomainFile file = context.getSelectedFiles().get(0);
		return file.isLink();
	}
}
