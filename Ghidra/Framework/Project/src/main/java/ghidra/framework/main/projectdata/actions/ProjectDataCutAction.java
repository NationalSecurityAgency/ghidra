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
import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFolder;
import ghidra.util.HelpLocation;

public class ProjectDataCutAction extends ProjectDataCopyCutBaseAction {
	private static final Icon ICON = new GIcon("icon.projectdata.cut");

	public ProjectDataCutAction(String owner, String group) {
		super("Cut", owner);
		setPopupMenuData(new MenuData(new String[] { "Cut" }, ICON, group));
		setKeyBindingData(new KeyBindingData('X', InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Cut"));
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		TreePath[] paths = adjustSelectionPaths(context.getSelectionPaths());

		DataTreeClipboardUtils.setClipboardContents(context.getTree(), paths);

		markNodesCut(paths);
	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.isInActiveProject() || !context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		return !context.containsRootFolder() && canMarkNodesCut(context.getSelectionPaths());
	}

	private boolean canMarkNodesCut(TreePath[] paths) {
		for (TreePath treePath : paths) {
			GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
			DomainFolder folder;
			if (node instanceof DomainFileNode fileNode) {
				folder = fileNode.getDomainFile().getParent();
			}
			else if (node instanceof DomainFolderNode folderNode) {
				folder = folderNode.getDomainFolder();
			}
			else {
				return false;
			}
			if (!folder.isInWritableProject()) {
				// linked content may reside within a read-only project view
				return false;
			}
		}
		return true;
	}

	private void markNodesCut(TreePath[] paths) {
		for (TreePath treePath : paths) {
			GTreeNode node = (GTreeNode) treePath.getLastPathComponent();
			if (node instanceof Cuttable) {
				((Cuttable) node).setIsCut(true);
			}
		}
	}

}
