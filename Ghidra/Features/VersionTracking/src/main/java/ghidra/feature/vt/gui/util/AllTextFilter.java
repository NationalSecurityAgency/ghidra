/* ###
 * IP: GHIDRA
 * NOTE: references VT code
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
package ghidra.feature.vt.gui.util;

import docking.widgets.table.DisplayStringProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.feature.vt.gui.filters.Filter;
import ghidra.feature.vt.gui.plugin.VTController;

public class AllTextFilter<T> extends AbstractTextFilter<T> {

	private final ThreadedTableModel<T, ?> model;

	public AllTextFilter(VTController controller, GTable table, ThreadedTableModel<T, ?> model) {
		super(controller, table, "Filter");
		this.model = model;
	}

	@Override
	protected Filter<T> createEmptyCopy() {
		return new AllTextFilter<>(controller, table, model);
	}

	@Override
	public boolean passesFilter(T t) {
		String filterText = getTextFieldText();
		if (filterText == null || filterText.trim().length() == 0) {
			return true; // no text for this filter
		}

		filterText = filterText.toLowerCase();
		int columnCount = table.getColumnCount();
		for (int column = 0; column < columnCount; column++) {
			int modelColumn = table.convertColumnIndexToModel(column);
			Object value = model.getColumnValueForRow(t, modelColumn);
			if (value == null) {
				continue;
			}

			if (value instanceof DisplayStringProvider) {
				DisplayStringProvider displayable = (DisplayStringProvider) value;
				String displayString = displayable.getDisplayString();
				if (displayString != null) {
					displayString = displayString.toLowerCase();
					if (displayString.indexOf(filterText) != -1) {
						return true;
					}
				}
			}

			if (isJavaDisplayableAsString(value)) {
				String displayString = value.toString().toLowerCase();
				if (displayString.indexOf(filterText) != -1) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean isJavaDisplayableAsString(Object value) {
		return (value instanceof String) || (value instanceof Number) ||
			(value instanceof Character);
	}
}
