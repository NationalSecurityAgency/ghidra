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
package ghidra.framework.main.projectdata.actions;

import java.awt.event.KeyEvent;
import java.util.List;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.model.DomainFile;

public class ProjectDataOpenDefaultToolAction extends FrontendProjectTreeAction {

	public ProjectDataOpenDefaultToolAction(String owner, String group) {
		super("Open File", owner);
		setPopupMenuData(new MenuData(new String[] { "Open in Default Tool" }, group));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_ENTER, 0));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		List<DomainFile> selectedFiles = context.getSelectedFiles();
		// NOTE: Seems like we should confirm opening more than one file
		AppInfo.getActiveProject().getToolServices().launchDefaultTool(selectedFiles);
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		if (!context.getSelectedFolders().isEmpty()) {
			return false;
		}
		List<DomainFile> selectedFiles = context.getSelectedFiles();
		if (selectedFiles.isEmpty()) {
			return false;
		}
		for (DomainFile file : context.getSelectedFiles()) {
			if (file.isLink() && file.getLinkInfo().isFolderLink()) {
				return false;
			}
		}
		return true;
	}
}
