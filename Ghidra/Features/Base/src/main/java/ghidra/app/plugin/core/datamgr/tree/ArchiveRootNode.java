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
package ghidra.app.plugin.core.datamgr.tree;

import java.util.*;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.exception.AssertException;

public class ArchiveRootNode extends DataTypeTreeNode {
	private static final String NAME = "Data Types";

	private final DataTypeManagerHandler archiveManager;
	private RootNodeListener archiveListener;

	private ArrayPointerFilterState filterState = new ArrayPointerFilterState();

	ArchiveRootNode(DataTypeManagerHandler archiveManager) {
		this.archiveManager = archiveManager;
		init();
	}

	private void init() {
		archiveListener = new RootNodeListener();
		archiveManager.addArchiveManagerListener(archiveListener);
	}

	public DataTypeManagerHandler getArchiveHandler() {
		return archiveManager;
	}

	// override clone to install the needed listeners
	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		ArchiveRootNode clone = (ArchiveRootNode) super.clone();
		clone.init();
		return clone;
	}

	@Override
	public void dispose() {
		archiveManager.removeArchiveManagerListener(archiveListener);
		super.dispose();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return DataTypeUtils.getRootIcon(expanded);
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	@Override
	public boolean isModifiable() {
		return false;
	}

	// a factory method to isolate non-OO inheritance checks
	private static final GTreeNode createArchiveNode(Archive archive,
			ArrayPointerFilterState filterState) {
		if (archive instanceof FileArchive) {
			return new FileArchiveNode((FileArchive) archive, filterState);
		}
		else if (archive instanceof ProjectArchive) {
			return new ProjectArchiveNode((ProjectArchive) archive, filterState);
		}
		else if (archive instanceof InvalidFileArchive) {
			return new InvalidArchiveNode((InvalidFileArchive) archive);
		}
		else if (archive instanceof ProgramArchive) {
			return new ProgramArchiveNode((ProgramArchive) archive, filterState);
		}
		else if (archive instanceof BuiltInArchive) {
			return new BuiltInArchiveNode((BuiltInArchive) archive, filterState);
		}
		return null;
	}

//==================================================================================================
//	Interface Methods
//==================================================================================================

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		return false;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	@Override
	public void setNodeCut(boolean isCut) {
		throw new AssertException("Cannot call setNodeCut() on ArchiveRootNode.");
	}

	/**
	 * This implementation returns null, since this class is the root of the hierarchy and does
	 * not have an archive.
	 * @see ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode#getArchiveNode()
	 */
	@Override
	public ArchiveNode getArchiveNode() {
		return null;
	}

	@Override
	public boolean canDelete() {
		return false;
	}

	public CategoryNode findCategoryNode(Category category) {
		Iterator<GTreeNode> iterator = getChildren().iterator();
		while (iterator.hasNext()) {
			GTreeNode node = iterator.next();
			ArchiveNode archiveNode = (ArchiveNode) node;
			CategoryNode categoryNode = archiveNode.findCategoryNode(category);
			if (categoryNode != null) {
				return categoryNode;
			}
		}
		return null;
	}

	public ArchiveNode getNodeForManager(DataTypeManager dtm) {
		Iterator<GTreeNode> iterator = getChildren().iterator();
		while (iterator.hasNext()) {
			GTreeNode node = iterator.next();
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			DataTypeManager manager = archive.getDataTypeManager();
			if (manager.equals(dtm)) {
				return archiveNode;
			}
		}
		return null;
	}

	@Override
	public List<GTreeNode> generateChildren() {
		List<GTreeNode> list = new ArrayList<>();
		Iterator<Archive> iterator = archiveManager.getAllArchives().iterator();
		while (iterator.hasNext()) {
			list.add(createArchiveNode(iterator.next(), filterState));
		}
		Collections.sort(list);
		return list;
	}

	private ArchiveNode getArchiveNode(Archive archive) {
		List<GTreeNode> allChildrenList = getChildren();
		for (GTreeNode node : allChildrenList) {
			if (node instanceof ArchiveNode) {
				ArchiveNode archiveNode = (ArchiveNode) node;
				if (archiveNode.archive == archive) {
					return archiveNode;
				}
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class RootNodeListener implements ArchiveManagerListener {

		@Override
		public void archiveClosed(Archive archive) {
			if (!isLoaded()) {
				return;
			}
			List<GTreeNode> allChildrenList = getChildren();
			Iterator<GTreeNode> iterator = allChildrenList.iterator();
			while (iterator.hasNext()) {
				GTreeNode node = iterator.next();
				ArchiveNode archiveNode = (ArchiveNode) node;
				if (archive == archiveNode.getArchive()) {
					removeNode(archiveNode);
					archiveNode.dispose();
					return;
				}
			}
		}

		@Override
		public void archiveOpened(Archive archive) {
			if (isLoaded()) {
				GTreeNode node = createArchiveNode(archive, filterState);
				List<GTreeNode> allChildrenList = getChildren();
				int index = Collections.binarySearch(allChildrenList, node);
				if (index < 0) {
					index = -index - 1;
					addNode(index, node);
				}
			}
		}

		@Override
		public void archiveDataTypeManagerChanged(Archive archive) {
			ArchiveNode archiveNode = getArchiveNode(archive);
			if (archiveNode != null) {
				archiveNode.dataTypeManagerChanged();
			}
		}

		@Override
		public void archiveStateChanged(Archive archive) {
			ArchiveNode archiveNode = getArchiveNode(archive);
			if (archiveNode != null) {
				archiveNode.archiveStateChanged();
			}
		}
	}

	public void setFilterArray(boolean enabled) {
		filterState.setFilterArrays(enabled);
	}

	public void setFilterPointer(boolean enabled) {
		filterState.setFilterPointers(enabled);
	}

}
