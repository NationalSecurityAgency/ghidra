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

import javax.swing.tree.TreePath;

import docking.action.ContextSpecificAction;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreeContext;
import ghidra.framework.main.datatree.*;

public class ProjectDataCollapseAction<T extends ProjectTreeContext>
		extends ContextSpecificAction<T> {

	public ProjectDataCollapseAction(String owner, String group, Class<T> contextClass) {
		super("Collapse All", owner, contextClass);
		setPopupMenuData(new MenuData(new String[] { "Collapse All" }, group));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(T context) {
		DataTree tree = context.getTree();
		TreePath[] paths = context.getSelectionPaths();
		collapse(tree, paths[0]);
	}

	@Override
	protected boolean isEnabledForContext(T context) {
		if (!context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		TreePath[] paths = context.getSelectionPaths();
		GTreeNode node = (GTreeNode) paths[0].getLastPathComponent();
		if (node instanceof DomainFolderNode folderNode) {
			return folderNode.isLoaded();
		}
		if (node instanceof DomainFileNode fileNode) {
			return fileNode.isFolderLink() && !fileNode.isLeaf() && fileNode.isLoaded();
		}
		return false;
	}

	/**
	 * Expand the first selected node; called from an action listener
	 * on a menu.
	 */
	private void collapse(DataTree tree, TreePath path) {
		tree.collapseAll((GTreeNode) path.getLastPathComponent());
	}
}
