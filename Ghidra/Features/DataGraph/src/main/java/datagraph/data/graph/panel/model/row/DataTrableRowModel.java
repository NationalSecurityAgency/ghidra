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

import docking.widgets.trable.AbstractGTrableRowModel;
import docking.widgets.trable.GTrable;
import ghidra.program.model.listing.Data;

/**
 * Row model for Data objects in {@link GTrable}. Most of the complexity is handled by
 * the {@link OpenDataChildren} object. If only the top most row is displaying (i.e. it is not
 * expanded), then the openChildren object is null. When row 0 is expanded, an OpenChildren is
 * created to manage the rows for the sub data child rows. This pattern is repeated inside the
 * OpenChilren node (open rows have corresponding OpenChildren objects to manage its child
 * rows.)
 */
public class DataTrableRowModel extends AbstractGTrableRowModel<DataRowObject> {
	private Data data;
	private OpenDataChildren openChildren;
	private DataRowObjectCache cache = new DataRowObjectCache();

	public DataTrableRowModel(Data data) {
		this.data = data;
	}

	public Data getData() {
		return data;
	}

	public void setData(Data data) {
		this.data = data;
		cache.clear();
		openChildren = null;
	}

	@Override
	public int getRowCount() {
		if (openChildren == null) {
			return 1;
		}
		return openChildren.getRowCount() + 1;
	}

	@Override
	public DataRowObject getRow(int rowIndex) {
		if (cache.contains(rowIndex)) {
			return cache.getDataRow(rowIndex);
		}
		DataRowObject row = generateRow(rowIndex);
		cache.putData(rowIndex, row);
		return row;
	}

	private DataRowObject generateRow(int rowIndex) {
		if (rowIndex == 0) {
			return new ComponentDataRowObject(0, data, openChildren != null);
		}
		return openChildren.getRow(rowIndex - 1);
	}

	@Override
	public boolean isExpandable(int rowIndex) {
		DataRowObject dataRow = getRow(rowIndex);
		return dataRow != null && dataRow.isExpandable();
	}

	@Override
	public boolean isExpanded(int rowIndex) {
		DataRowObject row = getRow(rowIndex);
		return row != null && row.isExpanded();
	}

	@Override
	public int collapseRow(int rowIndex) {
		cache.clear();
		if (rowIndex < 0 || rowIndex >= getRowCount()) {
			throw new IndexOutOfBoundsException();
		}
		if (rowIndex == 0) {
			if (openChildren == null) {
				return 0;
			}
			int diff = openChildren.getRowCount();
			openChildren = null;
			fireModelChanged();
			return diff;
		}
		int rowCountDiff = openChildren.collapseChild(rowIndex - 1);
		fireModelChanged();
		return rowCountDiff;
	}

	@Override
	public int expandRow(int rowIndex) {
		cache.clear();
		if (rowIndex < 0 || rowIndex >= getRowCount()) {
			throw new IndexOutOfBoundsException();
		}
		if (rowIndex == 0) {
			// are we already open?
			if (openChildren != null) {
				return 0;
			}
			openChildren = OpenDataChildren.createOpenDataNode(data, 0, 0, 1);
			fireModelChanged();
			return openChildren.getRowCount();
		}
		int diff = openChildren.expandChild(rowIndex - 1);
		fireModelChanged();
		return diff;
	}

	@Override
	public int getIndentLevel(int rowIndex) {
		DataRowObject row = getRow(rowIndex);
		return row.getIndentLevel();
	}

	public void refresh() {
		cache.clear();
		if (openChildren != null) {
			if (!openChildren.refresh(data)) {
				openChildren = null;
			}
		}
		fireModelChanged();
	}
}
