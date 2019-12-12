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
package ghidra.app.plugin.core.datamgr;

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.widgets.tree.GTreeNode;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.datamgr.archive.ProjectArchive;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.ProjectArchiveNode;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

public class DataTypesActionContext extends ProgramActionContext implements DomainFileContext {
	private final GTreeNode clickedNode;
	private final boolean isToolbarAction;
	private DataTypeArchiveGTree archiveGTree;
	private List<DomainFile> domainFiles;

	public DataTypesActionContext(DataTypesProvider provider, Program program,
			DataTypeArchiveGTree archiveGTree, GTreeNode clickedNode) {
		this(provider, program, archiveGTree, clickedNode, false);
	}

	public DataTypesActionContext(DataTypesProvider provider, Program program,
			DataTypeArchiveGTree archiveGTree, GTreeNode clickedNode, boolean isToolbarAction) {

		super(provider, program, archiveGTree);
		this.archiveGTree = archiveGTree;
		this.clickedNode = clickedNode;
		this.isToolbarAction = isToolbarAction;
	}

	public boolean isToolbarAction() {
		return isToolbarAction;
	}

	public GTreeNode getSelectedNode() {
		return clickedNode;
	}

	@Override
	public List<DomainFile> getSelectedFiles() {
		if (domainFiles == null) {
			TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
			domainFiles = new ArrayList<DomainFile>();
			for (TreePath path : selectionPaths) {
				Object lastPathComponent = path.getLastPathComponent();
				if (lastPathComponent instanceof ProjectArchiveNode) {
					ProjectArchiveNode node = (ProjectArchiveNode) lastPathComponent;
					ProjectArchive archive = (ProjectArchive) node.getArchive();
					DomainFile originalDomainFile = archive.getDomainFile();
					domainFiles.add(originalDomainFile);
				}
			}
		}
		return domainFiles;
	}

	@Override
	public int getFileCount() {
		return getSelectedFiles().size();
	}

	@Override
	public boolean isInActiveProject() {
		return true;
	}

}
