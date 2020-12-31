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
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;

public class CategoryNode extends DataTypeTreeNode {

	private Category category;
	private String name;

	private boolean isCut;
	private ArrayPointerFilterState filterState;

	public CategoryNode(Category category, ArrayPointerFilterState filterState) {
		this.filterState = filterState;
		setCategory(category);
	}

	protected void setCategory(Category category) {
		this.category = category;
		if (category != null) {
			this.name = category.getName();
		}
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		if (category == null) {
			return Collections.emptyList();
		}
		Category[] subCategories = category.getCategories();
		DataType[] dataTypes = category.getDataTypes();
		List<GTreeNode> list = new ArrayList<>(subCategories.length + dataTypes.length);
		for (Category subCategory : subCategories) {
			list.add(new CategoryNode(subCategory, filterState));
		}

		for (DataType dataType : dataTypes) {
			if (!isFilteredType(dataType)) {
				list.add(new DataTypeNode(dataType));
			}
		}

		Collections.sort(list);

		return list;
	}

	private boolean isFilteredType(DataType dataType) {
		if (filterState.filterArrays() && dataType instanceof Array) {
			return true;
		}

		if (filterState.filterPointers() && (dataType instanceof Pointer) &&
			!(dataType.getDataTypeManager() instanceof BuiltInDataTypeManager)) {
			return true;
		}

		return false;
	}

	@Override
	public int compareTo(GTreeNode node) {
		if (node instanceof CategoryNode) {
			return super.compareTo(node);
		}

		return -1; // CategoryNodes are always come before ****everything else****
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (getClass() != o.getClass()) {
			return false;
		}
		CategoryNode otherNode = (CategoryNode) o;
		if (!category.equals(otherNode.category)) {
			return false;
		}
		return name.equals(otherNode.name);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		// always show leaf nodes as closed in addition to collapsed non-leaf nodes
		if (!expanded) {
			return DataTypeUtils.getClosedFolderIcon(isCut);
		}

		// expanded node with data
		return DataTypeUtils.getOpenFolderIcon(isCut);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return "<html>" + HTMLUtilities.escapeHTML(category.getCategoryPathName());
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

	public boolean canRename() {
		return isModifiable();
	}

	public Category getCategory() {
		return category;
	}

	public DataTypeNode getNode(DataType dataType) {
		// call this method to make sure children are loaded
		List<GTreeNode> children = getChildren();
		for (GTreeNode node : children) {
			if ((node instanceof DataTypeNode)) {
				DataTypeNode dataTypeNode = (DataTypeNode) node;
				if (dataTypeNode.getDataType() == dataType) {
					return dataTypeNode;
				}
			}
		}
		return null;
	}

	public void categoryAdded(Category newCategory) {

		if (!isLoaded()) {
			return;
		}

		CategoryNode node = new CategoryNode(newCategory, filterState);
		List<GTreeNode> children = getChildren();
		int index = Collections.binarySearch(children, node);
		if (index >= 0) {
			// if a node with that name exists, then we don't need to add one for the new category
			if (node.getName().equals(children.get(index).getName())) {
				return;
			}
		}
		if (index < 0) {
			index = -index - 1;
		}
		addNode(index, node);
	}

	public void dataTypeAdded(DataType dataType) {
		if (!isLoaded()) {
			return;
		}

		DataTypeArchiveGTree tree = (DataTypeArchiveGTree) getTree();

		if (tree == null) {
			return;
		}

		if (isFilteredType(dataType)) {
			return;
		}

		DataTypeNode node = new DataTypeNode(dataType);
		List<GTreeNode> allChildrenList = getChildren();
		int index = Collections.binarySearch(allChildrenList, node);
		if (index >= 0) {
			if (node.getName().equals(allChildrenList.get(index).getName())) {
				return;
			}
		}
		if (index < 0) {
			index = -index - 1;
		}
		addNode(index, node); // only add it if is not already there
	}

	public void categoryRemoved(String categoryName) {
		if (!isLoaded()) {
			return;
		}
		for (GTreeNode node : getChildren()) {
			if ((node instanceof CategoryNode) && node.getName().equals(categoryName)) {
				removeNode(node);
				return;
			}
		}
	}

	public void dataTypeRemoved(String dataTypeName) {
		if (!isLoaded()) {
			return;
		}

		for (GTreeNode node : getChildren()) {
			if ((node instanceof DataTypeNode) && node.getName().equals(dataTypeName)) {
				removeNode(node);
				return;
			}
		}
	}

	public void dataTypeChanged(DataType dataType) {
		if (!isLoaded()) {
			return;
		}

		String dataTypeName = dataType.getName();
		for (GTreeNode node : getChildren()) {
			if ((node instanceof DataTypeNode) && node.getName().equals(dataTypeName)) {
				((DataTypeNode) node).dataTypeChanged();
				return;
			}
		}
	}

	@Override
	public void valueChanged(Object newValue) {
		int transactionID = category.getDataTypeManager().startTransaction("rename");
		try {
			category.setName(newValue.toString());
		}
		catch (DuplicateNameException e) {
			Msg.showError(getClass(), null, "Rename Failed",
				"Category by the name " + newValue + " already exists in this category.");
		}
		catch (InvalidNameException exc) {
			String msg = exc.getMessage();
			if (msg == null) {
				msg = "Invalid name specified: " + newValue;
			}
			Msg.showError(getClass(), null, "Invalid name specified", exc.getMessage());
		}
		finally {
			category.getDataTypeManager().endTransaction(transactionID, true);
		}
	}

	@Override
	public boolean isEditable() {
		return isModifiable();
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Signals to this node that it has been cut during a cut operation, for example, like during
	 * a cut/paste operation.
	 * <p>
	 * This implementation will throw a runtime exception if this method is called and
	 * {@link #canCut()} returns false.
	 * @param isCut true signals that the node has been cut; false that it is not cut.
	 */
	@Override
	public void setNodeCut(boolean isCut) {
		if (!canCut()) {
			throw new AssertException("Cannot call isCut() on a node that cannot be cut.");
		}
		this.isCut = isCut;
		fireNodeChanged(getParent(), this);
	}

	@Override
	public boolean canCut() {
		return isModifiable();
	}

	@Override
	public boolean canPaste(List<GTreeNode> pastedNodes) {
		return isModifiable();
	}

	@Override
	public boolean isCut() {
		return isCut;
	}

	@Override
	public ArchiveNode getArchiveNode() {
		GTreeNode parent = getParent();
		if (parent == null) {
			return null; // could happen during tree mutations
		}

		return ((DataTypeTreeNode) parent).getArchiveNode();
	}

	@Override
	public boolean isModifiable() {
		ArchiveNode archiveNode = getArchiveNode();
		if (archiveNode == null) {
			return false;
		}
		return getArchiveNode().isModifiable();
	}

	/**
	 * This method is handy to signal whether this node is can be used to perform actions.
	 * Returning false from this method is essentially a way to disable the actions that can
	 * be performed upon this node.
	 *
	 * @return true if this node is enabled.
	 */
	public boolean isEnabled() {
		return true;
	}

	@Override
	public boolean canDelete() {
		return true;
	}
}
