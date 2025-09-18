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
package datagraph.data.graph.panel.model.row;

import java.util.*;

import ghidra.program.model.data.Array;
import ghidra.program.model.listing.Data;

/**
 * Manages open rows in a DataTrableModel. Since this manages the open rows for its parent data
 * object, it has one row for each sub data component in its parent data. Of course, each of these
 * rows can also potentially be expandable. If any of the top level rows managed by this object are
 * expanded, it creates a OpenDataChildren object to manage its sub rows. The OpenChildrenObjects
 * are store in a list that is ordered by its row index. 
 * <P>
 * To find out if a row is expanded or not, a binary search is used to find out if there is an 
 * OpenDataChildren object for that row. If it is expanded, that object is used to recursively go
 * down to get the leaf row object.
 */
public abstract class OpenDataChildren implements Comparable<OpenDataChildren> {
	// when arrays are bigger than 100, we group them into chunks of 100 each. The size
	// should be a power of 10 and 100 seems like a good choice.
	private static final int ARRAY_GROUP_SIZE = 100;
	private int rowIndex;	// row index relative to parent
	private int rowCount;	// number of rows represented by this node, including any open children
	private int componentIndex;
	private int componentCount;
	protected int indentLevel;
	protected List<OpenDataChildren> openChildren;
	protected Data data;

	/**
	 * Constructor
	 * @param data the data object that this is managing rows for its child data components
	 * @param rowIndex the row index is the overall row index of the first child element row
	 * @param componentIndex the index of the the managed data component within its parent
	 * @param componentCount the number of direct rows this managed component has. (It may have
	 * indirect rows if its rows have child rows)
	 * @param indentLevel the indent level for all direct rows managed by this object
	 */
	protected OpenDataChildren(Data data, int rowIndex, int componentIndex,
			int componentCount, int indentLevel) {
		this.data = data;
		this.rowIndex = rowIndex;
		this.componentCount = componentCount;
		this.rowCount = componentCount;
		this.componentIndex = componentIndex;
		this.indentLevel = indentLevel;
		openChildren = new ArrayList<>();
	}

	/**
	 * Convenience static factory method for create the correct subtype of an OpenDataChildren 
	 * object. (Arrays require special handling.)
	 * @param data the data object that is being expanded and this object will manage its child
	 * data components.
	 * @param rowIndex the overall row index of the first child row that is expanded
	 * @param componentIndex the component index of the data within its parent that this object
	 * is managing
	 * @param indentLevel the indent level for all rows directly managed by this object
	 * @return a new OpenDataChildren object
	 */
	public static OpenDataChildren createOpenDataNode(Data data, int rowIndex, int componentIndex,
			int indentLevel) {
		int numComponents = data.getNumComponents();
		if (data.getDataType() instanceof Array) {
			if (numComponents <= ARRAY_GROUP_SIZE) {
				return new ArrayElementsComponentNode(data, rowIndex, componentIndex, numComponents,
					0, indentLevel);
			}
			return new ArrayGroupComponentNode(data, rowIndex, componentIndex, 0, numComponents,
				indentLevel);
		}
		return new DataComponentNode(data, rowIndex, componentIndex, numComponents, indentLevel);

	}

	/**
	 * Private constructor used to create a object that can be used in a binary search
	 * @param rowIndex the row to search for
	 */
	private OpenDataChildren(int rowIndex) {
		this.rowIndex = rowIndex;
	}

	/** 
	 * {@return the total number of rows currently managed  by this object (includes rows 
	 * recursively managed by its expanded children)}
	 */
	public int getRowCount() {
		return rowCount;
	}

	/**
	 * {@return the row object for the given index.}
	 * @param childRowIndex the index to get a row for. This index is relative to this
	 * OpenDataChildren object and not the overall row index for the model.
	 */
	public DataRowObject getRow(int childRowIndex) {

		OpenDataChildren node = findChildNodeAtOrBefore(childRowIndex);
		if (node == null) {
			return generateRow(childRowIndex, false);
		}

		if (node.getRowIndex() == childRowIndex) {
			return generateRow(node.getComponentIndex(), true);
		}

		int childIndex = childRowIndex - node.getRowIndex() - 1;
		if (childIndex < node.getRowCount()) {
			return node.getRow(childIndex);
		}

		int childComponentIndex = node.getComponentIndex() + childRowIndex - node.getRowIndex() -
			node.getRowCount();
		return generateRow(childComponentIndex, false);
	}

	protected int getComponentIndex() {
		return componentIndex;
	}

	protected abstract DataRowObject generateRow(int childComponentIndex, boolean isOpen);

	/**
	 * Expands the sub child at the given relative row index
	 * @param childRowIndex relative index to this OpenDataChildren object and not the overall
	 * model row index.
	 * @return the number of additional rows this caused to be added to the overall model
	 */
	public int expandChild(int childRowIndex) {
		OpenDataChildren node = findChildNodeAtOrBefore(childRowIndex);
		if (node == null) {
			return insertNode(childRowIndex, childRowIndex);
		}
		int indexPastNode = childRowIndex - node.getRowIndex();
		if (indexPastNode == 0) {
			return 0; // we are already open
		}
		if (indexPastNode <= node.getRowCount()) {
			int diff = node.expandChild(indexPastNode - 1);
			rebuildNodeIndex();
			return diff;
		}
		int childComponentIndex = node.getComponentIndex() + indexPastNode - node.rowCount;
		return insertNode(childRowIndex, childComponentIndex);

	}

	/**
	 * Collapse the child at the relative index.
	 * @param childRowIndex the relative child index to collapse
	 * @return the number of rows removed from the overall model
	 */
	public int collapseChild(int childRowIndex) {
		OpenDataChildren node = findChildNodeAtOrBefore(childRowIndex);

		// the given index is not open, so do nothing
		if (node == null) {
			return 0;
		}

		// compute the number of indexes past the open node we found
		int offsetIndex = childRowIndex - node.rowIndex;

		// if we found a node at that index, just delete it since we only retain open nodes
		if (offsetIndex == 0) {
			openChildren.remove(node);
			rebuildNodeIndex();
			return node.getRowCount();
		}

		// if the index is contained in the node, recurse down to close
		if (offsetIndex <= node.getRowCount()) {
			int diff = node.collapseChild(offsetIndex - 1);
			rebuildNodeIndex();
			return diff;
		}

		// again, the given index is not open, so do nothing
		return 0;
	}

	protected void rebuildNodeIndex() {
		rowCount = componentCount;

		OpenDataChildren lastNode = null;
		for (OpenDataChildren node : openChildren) {
			if (lastNode == null) {
				node.rowIndex = node.componentIndex;
			}
			else {
				node.rowIndex = lastNode.rowIndex + node.componentIndex - lastNode.componentIndex +
					lastNode.rowCount;
			}
			rowCount += node.rowCount;
			lastNode = node;
		}
	}

	protected int insertNode(int childRowIndex, int childComponentIndex) {
		OpenDataChildren newNode = generatedNode(childRowIndex, childComponentIndex);
		if (newNode == null) {
			return 0;  // tried to open a node that can't be opened
		}
		int index = Collections.binarySearch(openChildren, newNode);

		// It should never be positive since we searched and didn't find one at this index
		if (index >= 0) {
			return 0;
		}
		int insertionIndex = -index - 1;
		openChildren.add(insertionIndex, newNode);
		rebuildNodeIndex();
		return newNode.getRowCount();
	}

	protected abstract OpenDataChildren generatedNode(int childRowIndex, int childComponentIndex);

	/**
	 * Returns the rowIndex of of this node relative to its parent.
	 * @return  the rowIndex of of this node relative to its parent
	 */
	int getRowIndex() {
		return rowIndex;
	}

	void setRowIndex(int rowIndex) {
		this.rowIndex = rowIndex;
	}

	@Override
	public int compareTo(OpenDataChildren o) {
		return getRowIndex() - o.getRowIndex();
	}

	public boolean refresh(Data newData) {
		int newComponentCount = data.getNumComponents();

		// if the data is different or it went to something not expandable (count == 0) 
		// return false to indicate to parent this node needs to be removed
		if (data != newData || newComponentCount == 0) {
			openChildren.clear();
			return false;
		}

		// if the number of components changes, this node can remain, but need to close any 
		// children it has because it gets too complicated to correct
		if (newComponentCount != componentCount) {

			openChildren.clear();
			componentCount = newComponentCount;
			rowCount = componentCount;
			return true;
		}

		// recursively refresh open children, removing any that can't be refreshed
		Iterator<OpenDataChildren> it = openChildren.iterator();
		while (it.hasNext()) {
			OpenDataChildren child = it.next();
			if (!child.refresh(data.getComponent(child.componentIndex))) {
				it.remove();
			}
		}
		rebuildNodeIndex();
		return true;
	}

	protected OpenDataChildren findChildNodeAtOrBefore(int childRowIndex) {
		if (openChildren.isEmpty()) {
			return null;
		}
		int index = Collections.binarySearch(openChildren, new SearchKeyNode(childRowIndex));
		if (index < 0) {
			index = -index - 2;
		}
		return index < 0 ? null : openChildren.get(index);
	}

	private static class SearchKeyNode extends OpenDataChildren {
		SearchKeyNode(int rowIndex) {
			super(rowIndex);
		}

		@Override
		protected DataRowObject generateRow(int childComponentIndex, boolean isOpen) {
			return null;
		}

		@Override
		protected OpenDataChildren generatedNode(int childRowIndex, int childComponentIndex) {
			return null;
		}
	}

	private static class DataComponentNode extends OpenDataChildren {

		public DataComponentNode(Data data, int rowIndex, int componentIndex,
				int numComponents, int indentLevel) {
			super(data, rowIndex, componentIndex, numComponents, indentLevel);
		}

		@Override
		protected DataRowObject generateRow(int childComponentIndex, boolean isOpen) {
			Data component = data.getComponent(childComponentIndex);
			return new ComponentDataRowObject(indentLevel, component, isOpen);
		}

		@Override
		protected OpenDataChildren generatedNode(int childRowIndex, int childComponentIndex) {
			Data component = data.getComponent(childComponentIndex);
			return createOpenDataNode(component, childRowIndex, childComponentIndex,
				indentLevel + 1);
		}

	}

	private static class ArrayElementsComponentNode extends OpenDataChildren {

		private int arrayStartIndex;
		private int totalArraySize;

		protected ArrayElementsComponentNode(Data data, int rowIndex, int componentIndex,
				int componentCount, int arrayStartIndex, int indentLevel) {
			super(data, rowIndex, componentIndex, componentCount, indentLevel);
			this.arrayStartIndex = arrayStartIndex;
			this.totalArraySize = data.getNumComponents();
		}

		@Override
		protected DataRowObject generateRow(int childComponentIndex, boolean isOpen) {
			Data component = data.getComponent(arrayStartIndex + childComponentIndex);
			return new ComponentDataRowObject(indentLevel + 1, component, isOpen);
		}

		@Override
		protected OpenDataChildren generatedNode(int childRowIndex, int childComponentIndex) {
			Data component = data.getComponent(arrayStartIndex + childComponentIndex);
			return createOpenDataNode(component, childRowIndex, childComponentIndex,
				indentLevel + 1);
		}

		@Override
		public boolean refresh(Data newData) {
			// NOTE: if this is a child of a array group node, this these check that can return
			// false can't happen as they have already been checked by the parent node. These
			// exist in case this is directly parented from a normal data node
			if (!(newData.getDataType() instanceof Array)) {
				return false;
			}
			int newTotalArraySize = data.getNumComponents();

			// if the data is different or the array changed size, it needs to be removed
			if (data != newData || newTotalArraySize != totalArraySize) {
				return false;
			}

			// recursively refresh open children. Since the elements are all the same type, if
			// one can't refresh, then none can refresh
			for (OpenDataChildren child : openChildren) {
				Data component = data.getComponent(arrayStartIndex + child.getComponentIndex());
				if (!child.refresh(component)) {
					openChildren.clear();
					break;
				}
			}
			rebuildNodeIndex();
			return true;
		}
	}

	private static class ArrayGroupComponentNode extends OpenDataChildren {

		private int arrayStartIndex;
		private int groupSize;
		private int arrayCount;
		private int totalArraySize;

		public ArrayGroupComponentNode(Data data, int rowIndex, int componentIndex,
				int arrayStartIndex, int arrayCount, int indentLevel) {
			super(data, rowIndex, componentIndex, getGroupCount(arrayCount), indentLevel);
			this.arrayStartIndex = arrayStartIndex;
			this.arrayCount = arrayCount;
			this.groupSize = getGroupSize(arrayCount);
			this.totalArraySize = data.getNumComponents();
		}

		private static int getGroupCount(int length) {
			int groupSize = ARRAY_GROUP_SIZE;
			int numGroups = (length + groupSize - 1) / groupSize;
			while (numGroups > ARRAY_GROUP_SIZE) {
				groupSize = groupSize * ARRAY_GROUP_SIZE;
				numGroups = (length + groupSize - 1) / groupSize;
			}
			return numGroups;
		}

		private static int getGroupSize(int length) {
			int groupSize = ARRAY_GROUP_SIZE;
			int numGroups = (length + groupSize - 1) / groupSize;
			while (numGroups > ARRAY_GROUP_SIZE) {
				groupSize = groupSize * ARRAY_GROUP_SIZE;
				numGroups = (length + groupSize - 1) / groupSize;
			}
			return groupSize;
		}

		@Override
		protected DataRowObject generateRow(int childComponentIndex, boolean isOpen) {
			int subArrayStartIndex = arrayStartIndex + childComponentIndex * groupSize;
			int length = Math.min(groupSize, arrayCount - (childComponentIndex * groupSize));
			return new ArrayGroupDataRowObject(data, subArrayStartIndex, length, indentLevel + 1,
				isOpen);
		}

		@Override
		protected OpenDataChildren generatedNode(int childRowIndex, int childComponentIndex) {
			int arrayOffsetFromStart = childComponentIndex * groupSize;
			int subArrayStartIndex = arrayStartIndex + arrayOffsetFromStart;
			int length = Math.min(groupSize, arrayCount - arrayOffsetFromStart);
			if (groupSize == ARRAY_GROUP_SIZE) {
				return new ArrayElementsComponentNode(data, childRowIndex, childComponentIndex,
					length, subArrayStartIndex, indentLevel + 1);
			}
			return new ArrayGroupComponentNode(data, childRowIndex, childComponentIndex,
				subArrayStartIndex, length, indentLevel + 1);
		}

		@Override
		public boolean refresh(Data newData) {
			if (!(newData.getDataType() instanceof Array)) {
				return false;
			}
			int newTotalArraySize = data.getNumComponents();

			// if the data is different or the array changed size,
			// it needs to be removed
			if (data != newData || newTotalArraySize != totalArraySize) {
				return false;
			}

			// recursively refresh open children. Since the elements are all the same type, if
			// one can't refresh, then none can refresh so clear all open children
			for (OpenDataChildren child : openChildren) {
				if (!child.refresh(data)) {
					openChildren.clear();
					break;
				}
			}
			rebuildNodeIndex();
			return true;
		}
	}
}
