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

import java.awt.event.InputEvent;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import generic.theme.GIcon;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.Project;
import ghidra.util.HelpLocation;

public class ProjectDataCopyAction extends ProjectDataCopyCutBaseAction {
	private static final Icon icon = new GIcon("icon.projectdata.copy");

	public ProjectDataCopyAction(String owner, String group) {
		super("Copy", owner);
		setPopupMenuData(new MenuData(new String[] { "Copy" }, icon, group));
		setKeyBindingData(new KeyBindingData('C', InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Copy"));
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		TreePath[] paths = adjustSelectionPaths(context.getSelectionPaths());

		DataTreeClipboardUtils.setClipboardContents(context.getTree(), paths);

	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		Project activeProject = AppInfo.getActiveProject();
		if (activeProject == null || !context.isInActiveProject()) {
			return true;
		}
		return !context.containsRootFolder();
	}
}
