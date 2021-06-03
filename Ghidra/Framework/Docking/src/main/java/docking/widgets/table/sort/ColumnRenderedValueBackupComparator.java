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
package docking.widgets.table.sort;

import static ghidra.util.table.column.GColumnRenderer.ColumnConstraintFilterMode.*;

import java.util.Comparator;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;

/**
 * A special version of the backup comparator that uses the column's rendered value for 
 * the backup sort, rather the just <code>toString</code>, which is what the default parent
 * table model will do.
 * 
 * @param <T> the row type 
 */
public class ColumnRenderedValueBackupComparator<T> implements Comparator<Object> {

	protected int sortColumn;
	protected DynamicColumnTableModel<T> model;

	// columns do not support sorting via their rendered value if the are marked
	// for column filtering only
	private boolean supportsColumnSorting = true;

	public ColumnRenderedValueBackupComparator(DynamicColumnTableModel<T> model,
			int sortColumn) {
		this.model = model;
		this.sortColumn = sortColumn;

		DynamicTableColumn<T, ?, ?> column = model.getColumn(sortColumn);
		@SuppressWarnings("unchecked")
		GColumnRenderer<Object> renderer = (GColumnRenderer<Object>) column.getColumnRenderer();
		if (renderer != null) {
			if (renderer.getColumnConstraintFilterMode() == ALLOW_CONSTRAINTS_FILTER_ONLY) {
				// this implies that the column has signaled that it does not support 
				// filtering/sorting using its rendered value
				supportsColumnSorting = false;
			}
		}
	}

	@Override
	public int compare(Object c1, Object c2) {
		if (c1 == c2) {
			return 0;
		}

		String s1 = getRenderedColumnStringValue(c1);
		String s2 = getRenderedColumnStringValue(c2);

		if (s1 == null || s2 == null) {
			return TableComparators.compareWithNullValues(s1, s2);
		}

		return s1.compareToIgnoreCase(s2);
	}

	// The case to Object is safe, but passing the object to the renderer below is potentially
	// unsafe.  We happen know that we retrieved the value from the column that we are passing
	// it to, so the casting and usage is indeed safe.
	@SuppressWarnings("unchecked")
	private String getRenderedColumnStringValue(Object columnValue) {

		if (!supportsColumnSorting) {
			return null;
		}

		DynamicTableColumn<T, ?, ?> column = model.getColumn(sortColumn);
		GColumnRenderer<Object> renderer = (GColumnRenderer<Object>) column.getColumnRenderer();
		if (renderer == null) {
			return columnValue == null ? null : columnValue.toString();
		}

		Settings settings = model.getColumnSettings(sortColumn);
		return renderer.getFilterString(columnValue, settings);
	}

	// this may be overridden to use caching
	protected Object getColumnValue(T t) {
		return model.getColumnValueForRow(t, sortColumn);
	}
}
