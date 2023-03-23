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
package ghidra.app.plugin.core.debug.gui.model;

import docking.widgets.table.*;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsPanel;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.GColumnRenderer;

public class QueryPanelTestHelper {

	public static ObjectTableModel getTableModel(DebuggerThreadsPanel panel) {
		return panel.tableModel;
	}

	public static GhidraTable getTable(AbstractQueryTablePanel<?, ?> panel) {
		return panel.table;
	}

	public static <T> GhidraTableFilterPanel<T> getFilterPanel(
			AbstractQueryTablePanel<T, ?> panel) {
		return panel.filterPanel;
	}

	@SuppressWarnings("unchecked")
	public static SpannedRenderer<Long> getSpannedCellRenderer(
			AbstractQueryTablePanel<?, ?> panel) {
		int count = panel.tableModel.getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<?, ?, ?> column = panel.tableModel.getColumn(i);
			GColumnRenderer<?> renderer = column.getColumnRenderer();
			if (renderer instanceof SpannedRenderer<?> spanned) {
				return (SpannedRenderer<Long>) spanned;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static RangeCursorTableHeaderRenderer<Long> getCursorHeaderRenderer(
			AbstractQueryTablePanel<?, ?> panel) {
		int count = panel.tableModel.getColumnCount();
		for (int i = 0; i < count; i++) {
			DynamicTableColumn<?, ?, ?> column = panel.tableModel.getColumn(i);
			GTableHeaderRenderer renderer = column.getHeaderRenderer();
			if (renderer instanceof RangeCursorTableHeaderRenderer<?> spanned) {
				return (RangeCursorTableHeaderRenderer<Long>) spanned;
			}
		}
		return null;
	}
}
