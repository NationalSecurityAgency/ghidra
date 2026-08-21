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
package docking.widgets.trable;

import java.util.ArrayList;
import java.util.List;

/**
 * Default implementation for a simple {@link GTrable} row data model.
 *
 * @param <T> the row object type
 */
public class DefaultGTrableRowModel<T extends GTrableRow<T>> extends AbstractGTrableRowModel<T> {
	protected List<T> rows;

	public DefaultGTrableRowModel(List<T> roots) {
		this.rows = new ArrayList<>(roots);
	}

	@Override
	public int getRowCount() {
		return rows.size();
	}

	@Override
	public T getRow(int index) {
		return rows.get(index);
	}

	@Override
	public int getIndentLevel(int rowIndex) {
		return rows.get(rowIndex).getIndentLevel();
	}

	@Override
	public boolean isExpanded(int rowIndex) {
		return rows.get(rowIndex).isExpanded();
	}

	@Override
	public boolean isExpandable(int rowIndex) {
		return rows.get(rowIndex).isExpandable();
	}

	@Override
	public int collapseRow(int lineIndex) {
		T row = rows.get(lineIndex);
		int indentLevel = row.getIndentLevel();
		int removedCount = removeIndentedRows(lineIndex + 1, indentLevel + 1);
		row.setExpanded(false);
		fireModelChanged();
		return removedCount;

	}

	protected int removeIndentedRows(int startIndex, int indentLevel) {
		int endIndex = findNextIndexAtLowerIndentLevel(startIndex, indentLevel);
		rows.subList(startIndex, endIndex).clear();
		return endIndex - startIndex;
	}

	protected int findNextIndexAtLowerIndentLevel(int startIndex, int indentLevel) {
		for (int i = startIndex; i < rows.size(); i++) {
			T line = rows.get(i);
			if (line.getIndentLevel() < indentLevel) {
				return i;
			}
		}
		return rows.size();
	}

	@Override
	public int expandRow(int lineIndex) {
		T row = rows.get(lineIndex);
		if (!row.isExpandable() || row.isExpanded()) {
			return 0;
		}
		List<T> children = row.getChildRows();
		rows.addAll(lineIndex + 1, children);
		row.setExpanded(true);
		fireModelChanged();
		return children.size();
	}

}
