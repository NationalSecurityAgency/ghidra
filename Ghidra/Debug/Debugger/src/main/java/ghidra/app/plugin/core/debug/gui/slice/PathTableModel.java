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
package ghidra.app.plugin.core.debug.gui.slice;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.framework.plugintool.ServiceProvider;

/**
 * Table model for displaying a path of slice nodes.
 */
public class PathTableModel extends GDynamicColumnTableModel<PathRow, Object> {

	private final List<PathRow> rows = new ArrayList<>();

	public PathTableModel(ServiceProvider serviceProvider, List<PathRow> rows) {
		super(serviceProvider);
		this.rows.addAll(rows);
	}

	@Override
	public String getName() {
		return "Path";
	}

	@Override
	public List<PathRow> getModelData() {
		return rows;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	@Override
	protected TableColumnDescriptor<PathRow> createTableColumnDescriptor() {
		TableColumnDescriptor<PathRow> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new SnapPathColumn(), 1, true);
		descriptor.addVisibleColumn(new TypePathColumn(), 2, true);
		descriptor.addVisibleColumn(new ItemPathColumn());
		descriptor.addVisibleColumn(new LocationPathColumn());
		descriptor.addVisibleColumn(new CheckedPathColumn());
		return descriptor;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return getColumn(columnIndex) instanceof CheckedPathColumn;
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (!isCellEditable(rowIndex, columnIndex) || !(value instanceof Boolean checked) ||
			rowIndex < 0 || rowIndex >= rows.size()) {
			return;
		}
		rows.get(rowIndex).setChecked(checked);
		fireTableCellUpdated(rowIndex, columnIndex);
	}
}
