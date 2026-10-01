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
import ghidra.app.plugin.core.datamgr.ArchiveManager;
import ghidra.app.plugin.core.datamgr.ArchiveManagerListener;
import ghidra.app.plugin.core.datamgr.archive.InvalidArchive;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.database.dtarchive.FileDtArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.AssertException;

public class ArchiveRootNode extends DataTypeTreeNode {
	private static final String NAME = "Data Types";

	private ArchiveManager archiveManager;
	private RootNodeListener archiveListener;
	private boolean programDtmOnly;

	private ArchiveRootNodeListener listener;

	private DtFilterState dtFilterState = new DtFilterState();

	public ArchiveRootNode(ArchiveManager archiveManager) {
		this(archiveManager, false);
	}

	public ArchiveRootNode(ArchiveManager archiveManager, boolean programDtmOnly) {
		this.archiveManager = archiveManager;
		this.programDtmOnly = programDtmOnly;
		init();
	}

	private void init() {
		archiveListener = new RootNodeListener();
		archiveManager.addArchiveManagerListener(archiveListener);
	}

	/**
	 * Add a listener to know when the program archive node is added and removed.
	 * @param listener the listener
	 */
	public void setNodeListener(ArchiveRootNodeListener listener) {
		this.listener = listener;
	}

	/**
	 * Returns the modification count for any changes to any category or datatype in any
	 * open archive including the program.
	 * @return the modification count
	 */
	public long getModificationCount() {
		return archiveManager.getModificationCount();
	}

	public void setFilterState(DtFilterState dtFilterState) {
		this.dtFilterState = dtFilterState;
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
	private final ArchiveNode createArchiveNode(PersistentDataTypeArchive archive,
			DtFilterState filterState) {

		if (programDtmOnly) {
			return null;
		}

		if (archive instanceof FileDtArchiveDB fileArchive) {
			return new FileArchiveNode(fileArchive, filterState);
		}
		else if (archive instanceof ProjectDataTypeArchive projectArchive) {
			return new ProjectArchiveNode(projectArchive, filterState);
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
	public DataTypeStoreNode getArchiveNode() {
		return null;
	}

	@Override
	public boolean canDelete() {
		return false;
	}

	public CategoryNode findCategoryNode(Category category) {
		for (GTreeNode node : getChildren()) {
			DataTypeStoreNode archiveNode = (DataTypeStoreNode) node;
			CategoryNode categoryNode = archiveNode.findCategoryNode(category);
			if (categoryNode != null) {
				return categoryNode;
			}
		}
		return null;
	}

	public DataTypeStoreNode getNodeForManager(DataTypeManager dtm) {
		for (GTreeNode node : getChildren()) {
			if (node instanceof DataTypeStoreNode storeNode) {
				DataTypeStore archive = storeNode.getDataTypeStore();
				DataTypeManager manager = archive.getDataTypeManager();
				if (manager.equals(dtm)) {
					return storeNode;
				}
			}
		}
		return null;
	}

	@Override
	public List<GTreeNode> generateChildren() {
		List<GTreeNode> list = new ArrayList<>();
		addBuiltInNode(list);
		addProgramNode(list);
		addArchiveNodes(list);
		addInvalidNodes(list);
		Collections.sort(list);
		return list;
	}

	private void addBuiltInNode(List<GTreeNode> list) {
		if (programDtmOnly) {
			return;
		}
		DataTypeManager builtInDtm = BuiltInDataTypeManager.getDataTypeManager();
		DataTypeStore dataStore = builtInDtm.getDataStore();
		list.add(new BuiltInArchiveNode(dataStore, dtFilterState));
	}

	private void addProgramNode(List<GTreeNode> list) {
		Program program = archiveManager.getProgram();
		if (program != null) {
			list.add(new ProgramArchiveNode(program, dtFilterState));
		}
	}

	private void addArchiveNodes(List<GTreeNode> list) {

		for (PersistentDataTypeArchive archive : archiveManager.getOpenArchives()) {
			GTreeNode node = createArchiveNode(archive, dtFilterState);
			if (node != null) {
				list.add(node);
			}
		}
	}

	private void addInvalidNodes(List<GTreeNode> list) {
		List<InvalidArchive> invalidArchives = archiveManager.getInvalidArchives();
		for (InvalidArchive invalidArchive : invalidArchives) {
			InvalidArchiveNode node = new InvalidArchiveNode(invalidArchive);
			list.add(node);
		}
	}

	private DataTypeStoreNode getArchiveNode(DataTypeStore store) {
		List<GTreeNode> allChildrenList = getChildren();
		for (GTreeNode node : allChildrenList) {
			if (node instanceof DataTypeStoreNode) {
				DataTypeStoreNode archiveNode = (DataTypeStoreNode) node;
				if (archiveNode.dataTypeStore == store) {
					return archiveNode;
				}
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class RootNodeListener implements ArchiveManagerListener {
		@Override
		public void programClosed(Program program) {
			if (!isLoaded()) {
				return;
			}

			List<GTreeNode> allChildrenList = getChildren();
			for (GTreeNode node : allChildrenList) {
				if (node instanceof ProgramArchiveNode programNode) {
					if (program == programNode.getProgram()) {
						listener.archiveNodeRemoved(programNode);
						removeNode(programNode);
						programNode.dispose();
						return;
					}
				}
			}
		}

		@Override
		public void archiveClosed(PersistentDataTypeArchive archive) {
			if (!isLoaded()) {
				return;
			}

			List<GTreeNode> allChildrenList = getChildren();
			for (GTreeNode node : allChildrenList) {
				if (node instanceof ArchiveNode archiveNode) {
					if (archive == archiveNode.getArchive()) {
						listener.archiveNodeRemoved(archiveNode);
						removeNode(archiveNode);
						archiveNode.dispose();
						return;
					}
				}
			}
		}

		@Override
		public void programOpened(Program program) {
			if (!isLoaded()) {
				return;
			}
			ProgramArchiveNode programNode = new ProgramArchiveNode(program, dtFilterState);

			addDataStoreNode(programNode);
		}

		@Override
		public void archiveOpened(PersistentDataTypeArchive archive) {
			if (!isLoaded()) {
				return;
			}

			ArchiveNode node = createArchiveNode(archive, dtFilterState);
			if (node != null) {
				addDataStoreNode(node);
			}
		}

		private void addDataStoreNode(DataTypeStoreNode node) {
			List<GTreeNode> allChildrenList = getChildren();
			int index = Collections.binarySearch(allChildrenList, node);
			if (index < 0) {
				index = -index - 1;
			}
			addNode(index, node);

			listener.archiveNodeAdded(node);
		}

		@Override
		public void stateChanged(DataTypeStore dataTypeStore) {
			DataTypeStoreNode archiveNode = getArchiveNode(dataTypeStore);
			if (archiveNode != null) {
				archiveNode.nodeChanged();
			}
		}

		@Override
		public void invalidArchiveAdded(InvalidArchive invalidArchive) {
			if (!isLoaded()) {
				return;
			}
			addNode(new InvalidArchiveNode(invalidArchive));
		}

		@Override
		public void invalidArchiveRemoved(InvalidArchive invalidArchive) {
			if (!isLoaded()) {
				return;
			}
			List<GTreeNode> allChildrenList = getChildren();
			for (GTreeNode node : allChildrenList) {
				if (node instanceof InvalidArchiveNode invalidNode) {
					if (invalidArchive.equals(invalidNode.getInvalidArchive())) {
						removeNode(node);
						invalidNode.dispose();
						return;
					}
				}
			}
		}
	}
}
