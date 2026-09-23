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

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.util.*;

import javax.swing.tree.TreePath;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.listing.Program;

public class DataTypesActionContext extends ProgramActionContext
		implements DataTypeContext, DomainFileContext {

	private final GTreeNode clickedNode;
	private final boolean isToolbarAction;
	private DataTypeArchiveGTree archiveGTree;
	private List<DomainFile> domainFiles;

	private List<GTreeNode> clipboardNodes; // lazy
	private List<DataType> dataTypes; // lazy

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

	public List<GTreeNode> getClipboardNodes() {
		if (clipboardNodes != null) {
			return clipboardNodes;
		}

		// cache, since this could be slow 
		DataTypesProvider dtProvider = (DataTypesProvider) getComponentProvider();
		DataTypeManagerPlugin plugin = dtProvider.getPlugin();
		Clipboard clipboard = plugin.getClipboard();
		Transferable transferable = clipboard.getContents(this);
		if (transferable instanceof GTreeNodeTransferable) {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			clipboardNodes = gtTransferable.getAllData();
		}

		if (clipboardNodes == null) {
			clipboardNodes = Collections.emptyList();
		}
		return clipboardNodes;
	}

	public boolean isToolbarAction() {
		return isToolbarAction;
	}

	@Override
	public DataType getSelectedDataType() {
		TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
		if (selectionPaths.length > 1) {
			return null;
		}
		if (clickedNode instanceof DataTypeNode dtNode) {
			return dtNode.getDataType();
		}
		return null;
	}

	@Override
	public boolean hasSelectedDataTypes() {
		if (dataTypes != null) {
			return dataTypes.size() > 1;
		}

		TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			Object last = path.getLastPathComponent();
			if (last instanceof DataTypeNode) {
				return true;
			}
		}
		return false;
	}

	@Override
	public List<DataType> getSelectedDataTypes() {

		if (dataTypes != null) {
			return dataTypes;
		}

		List<DataType> types = new ArrayList<>();
		TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			Object last = path.getLastPathComponent();
			if (last instanceof DataTypeNode dtNode) {
				DataType dt = dtNode.getDataType();
				types.add(dt);
			}
		}

		dataTypes = Collections.unmodifiableList(types);
		return dataTypes;
	}

	public GTreeNode getClickedNode() {
		return clickedNode;
	}

	@Override
	public List<DomainFile> getSelectedFiles() {
		if (domainFiles == null) {
			TreePath[] selectionPaths = archiveGTree.getSelectionPaths();
			domainFiles = new ArrayList<DomainFile>();
			for (TreePath path : selectionPaths) {
				Object lastPathComponent = path.getLastPathComponent();
				if (lastPathComponent instanceof ProjectArchiveNode node) {
					DomainFile originalDomainFile = node.getOriginalDomainFile();
					if (originalDomainFile != null) {
						domainFiles.add(originalDomainFile);
					}
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

	public List<GTreeNode> getSelectedNodes() {
		Object contextObject = getContextObject();
		GTree gTree = (GTree) contextObject;
		return gTree.getSelectedNodes();
	}

	public List<DataTypeNode> getDisassociatableNodes() {

		Object contextObject = getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		return getDisassociatableNodes(selectionPaths);
	}

	private List<DataTypeNode> getDisassociatableNodes(TreePath[] paths) {

		List<DataTypeNode> nodes = new ArrayList<>();
		for (TreePath treePath : paths) {
			DataTypeNode node = getDisassociatableNode(treePath);
			if (node != null) {
				nodes.add(node);
			}
		}
		return nodes;
	}

	private DataTypeNode getDisassociatableNode(TreePath path) {
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}

		DataTypeNode dataTypeNode = (DataTypeNode) node;
		DataType dataType = dataTypeNode.getDataType();
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		SourceArchive sourceArchive = dataType.getSourceArchive();
		if (sourceArchive == null || dataTypeManager == null ||
			sourceArchive.equals(BuiltInSourceArchive.INSTANCE) ||
			sourceArchive.getSourceArchiveID().equals(dataTypeManager.getUniversalID())) {

			return null;
		}
		return dataTypeNode;
	}

	public List<ProjectDataTypeArchive> getSelectedProjectArchives() {
		List<ProjectDataTypeArchive> list = new ArrayList<>();

		List<GTreeNode> selectedNodes = getSelectedNodes();
		for (GTreeNode node : selectedNodes) {
			if (node instanceof ProjectArchiveNode projectNode) {
				ProjectDataTypeArchive archive = projectNode.getArchive();
				list.add(archive);
			}
		}
		return list;
	}
}
