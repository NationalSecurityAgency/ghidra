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

import java.util.Comparator;
import java.util.List;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.util.task.SwingUpdateManager;

/**
 * That have a valid DataTypeManager (program, file archive, project archive, built-in archive)
 */
public abstract class DataTypeStoreNode extends CategoryNode {

	protected static final String DEFAULT_DATA_ORG_DESCRIPTION =
		"[Using Default Data Organization]";

	protected DataTypeStore dataTypeStore;
	protected ArchiveNodeCategoryChangeListener listener;
	private DataTypeManager dataTypeManager; // may be null
	private Comparator<DataTypeStore> archiveComparator = new ArchiveComparator();

	protected DataTypeStoreNode(DataTypeStore archive, DtFilterState filterState) {
		super(archive.getDataTypeManager().getRootCategory(), filterState);
		this.dataTypeStore = archive;
		dataTypeManager = archive.getDataTypeManager();
		installDataTypeManagerListener();
	}

	public DataTypeManager getDataTypeManager() {
		return dataTypeStore.getDataTypeManager();
	}

	protected void stateChanged() {
		nodeChanged(); // notify that this nodes display data has changed
	}

	protected void installDataTypeManagerListener() {
		listener = new ArchiveNodeCategoryChangeListener();
		dataTypeManager.addDataTypeManagerListener(listener);
	}

	@Override
	public void dispose() {
		dataTypeManager.removeDataTypeManagerListener(listener);
		listener.dispose();
		super.dispose();
	}

	@Override
	public String getName() {
		return dataTypeStore.getName();
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

	public DataTypeStore getDataTypeStore() {
		return dataTypeStore;
	}

	public void structureChanged() {
		setChildren(null);
	}

	public void nodeChanged() {
		fireNodeChanged();

		GTree tree = getTree();
		if (tree != null) {
			tree.repaint();
		}
	}

	@Override
	public boolean canCut() {
		return false;
	}

	@Override
	public boolean isCut() {
		return false;
	}

	/**
	 * The equals must not be based on the name since it can change based upon the underlying
	 * archive. This must be consistent with the hashCode method implementation.
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		DataTypeStoreNode otherNode = (DataTypeStoreNode) o;
		return dataTypeStore == otherNode.dataTypeStore;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof DataTypeStoreNode archiveNode) {
			return archiveComparator.compare(dataTypeStore, archiveNode.dataTypeStore);
		}
		return -1; // All ArchiveNodes are before any other types of nodes
	}

	/**
	 * The hash code must not be based on the name since it can change based upon the underlying
	 * archive. This must be consistent with the equals method implementation.
	 */
	@Override
	public int hashCode() {
		return dataTypeStore.hashCode();
	}

	@Override
	public DataTypeStoreNode getArchiveNode() {
		return this;
	}

	@Override
	public boolean isModifiable() {
		return dataTypeStore.isChangeable();
	}

	/**
	 * Finds the node that represents the given category.
	 * 
	 * <P>
	 * Children <b>will not</b> be loaded when searching for the node. This allows clients to search
	 * for data types of interest, only updating the tree when the nodes are loaded.
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
			return DataTypeStoreNode.this;
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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

			Category parentCategory = dtm.getCategory(path.getParent());
			CategoryNode categoryNode = findCategoryNode(parentCategory);
			if (categoryNode != null) {
				categoryNode.categoryRemoved(path.getName());
			}
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			if (!isLoaded()) {
				return;
			}

			if (oldPath.getParent() == null) { // root has no parent
				DataTypeStoreNode.this.fireNodeChanged(); // fire that the root changed
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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

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
			if (!isLoaded()) {
				return;
			}

			Category oldParent = dtm.getCategory(path.getCategoryPath());
			CategoryNode categoryNode = findCategoryNode(oldParent);
			if (categoryNode != null) {
				categoryNode.dataTypeRemoved(path.getDataTypeName());
			}
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			if (!isLoaded()) {
				return;
			}

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

		@Override
		public void programArchitectureChanged(DataTypeManager manager) {
			// need to force all cached datatype tooltips to be cleared 
			// due to change in data organization
			unloadChildren();
			nodeChangedUpdater.update();
		}

		@Override
		public void restored(DataTypeManager manager) {
			// need to force all cached datatype tooltips to be cleared 
			// due to potential changes (e.g., undo/redo)
			unloadChildren();
			nodeChangedUpdater.update();
		}
	}
}
