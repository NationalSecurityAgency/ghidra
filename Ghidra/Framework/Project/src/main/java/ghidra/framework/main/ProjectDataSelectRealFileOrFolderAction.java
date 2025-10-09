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

import docking.action.MenuData;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class ProjectDataSelectRealFileOrFolderAction extends FrontendProjectTreeAction {

	private FrontEndPlugin plugin;

	public ProjectDataSelectRealFileOrFolderAction(FrontEndPlugin plugin, String group) {
		super("Select Real File or Folder", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Select Real File" }, group));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Select_Real_File_or_Folder"));
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {

		boolean isFolder = false;
		String pathname;

		try {
			if (context.getFolderCount() == 1 && context.getFileCount() == 0) {
				DomainFolder folder = context.getSelectedFolders().get(0);
				if (!(folder instanceof LinkedDomainFolder linkedFolder)) {
					return;
				}
				isFolder = true;
				pathname = linkedFolder.getRealFolder().getPathname();
			}
			else if (context.getFileCount() == 1 && context.getFolderCount() == 0) {
				DomainFile file = context.getSelectedFiles().get(0);
				if (!(file instanceof LinkedDomainFile linkedFile)) {
					return;
				}
				isFolder = false;
				pathname = linkedFile.getRealFile().getPathname();
			}
			else {
				return;
			}

			// Path is local to its project data tree
			plugin.showInProjectTree(context.getProjectData(), pathname, isFolder);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Linked Content Error",
				"Failed to resolve linked " + (isFolder ? "folder" : "file"), e);
			return;
		}

	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		boolean enabled = false;
		String contentType = "Content";
		if (context.getComponent() instanceof DataTree) {
			if (context.getFolderCount() == 1 && context.getFileCount() == 0) {
				DomainFolder folder = context.getSelectedFolders().get(0);
				if (folder instanceof LinkedDomainFolder) {
					contentType = "Folder";
					enabled = true;
				}
			}
			else if (context.getFileCount() == 1 && context.getFolderCount() == 0) {
				DomainFile file = context.getSelectedFiles().get(0);
				if (file instanceof LinkedDomainFile) {
					contentType = "File";
					enabled = true;
				}
			}
		}
		if (enabled) {
			setPopupMenuData(new MenuData(new String[] { "Select Real " + contentType },
				getPopupMenuData().getMenuGroup()));
		}
		return enabled;
	}
}
