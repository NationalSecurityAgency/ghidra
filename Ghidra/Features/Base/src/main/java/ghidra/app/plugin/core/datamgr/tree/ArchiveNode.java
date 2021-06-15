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

import java.util.List;

import javax.swing.Icon;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.program.model.data.*;
import ghidra.util.task.SwingUpdateManager;

public class ArchiveNode extends CategoryNode {

	protected Archive archive;
	protected ArchiveNodeCategoryChangeListener listener;
	private DataTypeManager dataTypeManager; // may be null

	public ArchiveNode(Archive archive, ArrayPointerFilterState filterState) {
		this(archive, archive.getDataTypeManager() == null ? null
				: archive.getDataTypeManager().getRootCategory(),
			filterState);
		this.dataTypeManager = archive.getDataTypeManager();
		updateDataTypeManager();
	}

	protected ArchiveNode(Archive archive, Category rootCategory,
			ArrayPointerFilterState filterState) {
		super(rootCategory, filterState);
		this.archive = archive;
	}

	protected void archiveStateChanged() {
		nodeChanged();
	}

	protected void dataTypeManagerChanged() {
		updateDataTypeManager();

		// old children are no longer valid--clear the cache and fire a node structure changed event
		structureChanged(); // notify children have been refreshed; tree cache needs to be cleared
		nodeChanged(); // notify that this nodes display data has changed
	}

	// override clone to install the needed listeners
	@Override
	public GTreeNode clone() throws CloneNotSupportedException {
		ArchiveNode clone = (ArchiveNode) super.clone();
		clone.installDataTypeManagerListener();
		return clone;
	}

	protected void installDataTypeManagerListener() {
		if (dataTypeManager == null) {
			return; // some nodes do not have DataTypeManagers, like InvalidFileArchives
		}
		listener = new ArchiveNodeCategoryChangeListener();
		dataTypeManager.addDataTypeManagerListener(listener);
	}

	protected void updateDataTypeManager() {
		if (dataTypeManager == null) {
			return; // some nodes do not have DataTypeManagers, like InvalidFileArchives
		}

		if (listener != null) {
			dataTypeManager.removeDataTypeManagerListener(listener);
			listener.dispose();
		}

		dataTypeManager = archive.getDataTypeManager();
		installDataTypeManagerListener();
		setCategory(dataTypeManager.getRootCategory());
	}

	@Override
	public void dispose() {
		if (dataTypeManager != null) {
			dataTypeManager.removeDataTypeManagerListener(listener);
		}

		if (listener != null) {
			listener.dispose();
		}

		super.dispose();
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return archive.getIcon(expanded);
	}

	@Override
	public String getName() {
		return archive.getName();
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
	public boolean isEditable() {
		return false;
	}

	public Archive getArchive() {
		return archive;
	}

	public void structureChanged() {
		setChildren(null);
	}

	public void nodeChanged() {
		fireNodeChanged(getParent(), this);

		GTree tree = getTree();
		if (tree != null) {
			tree.repaint();
		}
	}

	@Override
	/**
	 * Overridden since you cannot cut an archive node.
	 */
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	@Override
	/**
	 * The equals must not be based on the name since it can change
	 * based upon the underlying archive.  This must be consistent with
	 * the hashCode method implementation.
	 */
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		ArchiveNode otherNode = (ArchiveNode) o;
		return getArchive().equals(otherNode.getArchive());
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof ArchiveNode) {
			return archive.compareTo(((ArchiveNode) node).archive);
		}
		return -1; // All ArchiveNodes are before any other types of nodes
	}

	@Override
	/**
	 * The hashcode must not be based on the name since it can change
	 * based upon the underlying archive.  This must be consistent with
	 * the equals method implementation.
	 */
	public int hashCode() {
		return getArchive().hashCode();
	}

	@Override
	public ArchiveNode getArchiveNode() {
		return this;
	}

	@Override
	public boolean isModifiable() {
		return archive.isModifiable();
	}

	/**
	 * Finds the node that represents the given category.  
	 * 
	 * <P>Children <b>will not</b> be loaded when searching for the node.  This allows clients
	 * to search for data types of interest, only updating the tree when the nodes are loaded.
	 * 
	 * @param localCategory the category of interest
	 * @return the node if loaded; null if not loaded
	 */
	public CategoryNode findCategoryNode(Category localCategory) {
		return findCategoryNode(localCategory, false);
	}

	/**
	 * Finds the node that represents the given category.
	 * 
	 * @param localCategory the category of interest
	 * @param loadChildren true will load child nodes when searching; false will not load children
	 * @return the node
	 */
	public CategoryNode findCategoryNode(Category localCategory, boolean loadChildren) {

		// if we don't have to loadChildren and we are not loaded get out.
		if (!loadChildren && !isLoaded()) {
			return null;
		}

		if (localCategory == null) {
			return null;
		}

		if (getCategory() == localCategory) {
			return ArchiveNode.this;
		}

		Category parentCategory = localCategory.getParent();
		if (getParent() == null) {
			return null;
		}

		CategoryNode node = findCategoryNode(parentCategory, loadChildren);
		if (node == null) {
			return null;
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if (!(child instanceof CategoryNode)) {
				continue;
			}

			CategoryNode categoryNode = (CategoryNode) child;
			if (categoryNode.getCategory() == localCategory) {
				return categoryNode;
			}
		}
		return null;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ArchiveNodeCategoryChangeListener implements DataTypeManagerChangeListener {

		private SwingUpdateManager nodeChangedUpdater = new SwingUpdateManager(() -> nodeChanged());

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			Category newCategory = dtm.getCategory(path);
			if (newCategory == null) {
				return;
			}
			Category category = newCategory.getParent();
			CategoryNode categoryNode = findCategoryNode(category);
			if (categoryNode != null) {
				categoryNode.categoryAdded(newCategory);
			}
		}

		void dispose() {
			nodeChangedUpdater.dispose();
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			Category newCategory = dtm.getCategory(newPath);
			Category oldParent = dtm.getCategory(oldPath.getParent());
			CategoryNode categoryNode = findCategoryNode(oldParent);
			if (categoryNode != null) {
				categoryNode.categoryRemoved(oldPath.getName());
			}
			categoryNode = findCategoryNode(newCategory.getParent());
			if (categoryNode != null) {
				categoryNode.categoryAdded(newCategory);
			}
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			Category parentCategory = dtm.getCategory(path.getParent());
			CategoryNode categoryNode = findCategoryNode(parentCategory);
			if (categoryNode != null) {
				categoryNode.categoryRemoved(path.getName());
			}
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			if (oldPath.getParent() == null) { // root has no parent
				fireNodeChanged(null, ArchiveNode.this); // fire that the root changed
				return;
			}
			Category parentCategory = dtm.getCategory(oldPath.getParent());
			CategoryNode categoryNode = findCategoryNode(parentCategory);
			if (categoryNode != null) {
				categoryNode.categoryRemoved(oldPath.getName());
				Category newCategory = dtm.getCategory(newPath);
				categoryNode.categoryAdded(newCategory);
			}
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			Category parentCategory = dtm.getCategory(path.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(parentCategory);
			if (categoryNode != null) {
				DataType dataType = dtm.getDataType(path);

				// the data type can be changed before we get this call, since it's asynchronous
				if (dataType != null) {
					categoryNode.dataTypeAdded(dataType);
				}
			}
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			DataType dataType = dtm.getDataType(path);
			Category category = dtm.getCategory(path.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(category);
			if (categoryNode == null) {
				return;
			}
			List<GTreeNode> children = categoryNode.getChildren();
			for (GTreeNode node : children) {
				if (node instanceof DataTypeNode) {
					DataTypeNode dataTypeNode = (DataTypeNode) node;
					if (dataTypeNode.getDataType() == dataType) {
						dataTypeNode.dataTypeStatusChanged();
						return;
					}
				}
			}
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			Category dtmCategory = dtm.getCategory(path.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(dtmCategory);
			if (categoryNode != null) {
				DataType dataType = dtm.getDataType(path);

				// the data type can be changed before we get this call, since it's asynchronous
				if (dataType != null) {
					categoryNode.dataTypeChanged(dataType);
				}
			}
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			Category oldParent = dtm.getCategory(oldPath.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(oldParent);
			if (categoryNode != null) {
				categoryNode.dataTypeRemoved(oldPath.getDataTypeName());
			}

			Category newParent = dtm.getCategory(newPath.getCategoryPath());
			categoryNode = findCategoryNode(newParent);
			if (categoryNode != null) {
				DataType dataType = dtm.getDataType(newPath);

				// the data type can be changed before we get this call, since it's asynchronous
				if (dataType != null) {
					categoryNode.dataTypeAdded(dataType);
				}
			}
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			Category oldParent = dtm.getCategory(path.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(oldParent);
			if (categoryNode != null) {
				categoryNode.dataTypeRemoved(path.getDataTypeName());
			}
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			Category dtmCategory = dtm.getCategory(newPath.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(dtmCategory);
			if (categoryNode != null) {
				categoryNode.dataTypeRemoved(oldPath.getDataTypeName());
				DataType dataType = dtm.getDataType(newPath);

				// the data type can be changed before we get this call, since it's asynchronous
				if (dataType != null) {
					categoryNode.dataTypeAdded(dataType);
				}
			}
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			// Note: the replacement has already been added with its own event
			dataTypeRemoved(dtm, oldPath);
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager manager, SourceArchive sourceArchive) {
			// DT should these do anything?
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager manager, SourceArchive sourceArchive) {
			nodeChangedUpdater.update();
		}
	}
}
