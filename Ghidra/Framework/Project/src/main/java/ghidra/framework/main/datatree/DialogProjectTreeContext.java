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
package ghidra.framework.main.datatree;

import java.util.Collections;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.DialogActionContext;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatable.ProjectTreeContext;
import ghidra.framework.model.*;

/**
 * Context specific to the DataTreeDialog.
 * 
 * Note: this context is used from by the {@link ProjectDataTreePanel}.  This class may or may not
 * be in a dialog.  For convenience, this class extends a dialog action context, but may not always
 * be associated with a dialog.
 */
public class DialogProjectTreeContext extends DialogActionContext implements ProjectTreeContext {

	private TreePath[] selectionPaths;
	private DataTree tree;
	private List<DomainFolder> selectedFolders;
	private List<DomainFile> selectedFiles;

	public DialogProjectTreeContext(ProjectData projectData, TreePath[] selectionPaths,
			List<DomainFolder> folderList, List<DomainFile> fileList, DataTree tree) {
		super(getContextObject(selectionPaths), tree);
		this.selectionPaths = selectionPaths;
		this.selectedFolders = folderList;
		this.selectedFiles = fileList;
		this.tree = tree;
	}

	private static Object getContextObject(TreePath[] selectionPaths) {
		if (selectionPaths.length == 0) {
			return null;
		}
		return selectionPaths[0].getLastPathComponent();
	}

	@Override
	public TreePath[] getSelectionPaths() {
		return selectionPaths;
	}

	@Override
	public DataTree getTree() {
		return tree;
	}

	@Override
	public List<DomainFile> getSelectedFiles() {
		if (selectedFiles == null) {
			return Collections.emptyList();
		}
		return selectedFiles;
	}

	@Override
	public List<DomainFolder> getSelectedFolders() {
		if (selectedFolders == null) {
			return Collections.emptyList();
		}
		return selectedFolders;
	}

	@Override
	public int getFolderCount() {
		if (selectedFolders == null) {
			return 0;
		}
		return selectedFolders.size();
	}

	@Override
	public int getFileCount() {
		if (selectedFiles == null) {
			return 0;
		}
		return selectedFiles.size();
	}

	@Override
	public boolean hasExactlyOneFileOrFolder() {
		return (getFolderCount() + getFileCount()) == 1;
	}

	@Override
	public boolean hasOneOrMoreFilesAndFolders() {
		return getFolderCount() + getFileCount() > 0;
	}

	@Override
	public GTreeNode getContextNode() {
		return (GTreeNode) super.getContextObject();
	}
}
