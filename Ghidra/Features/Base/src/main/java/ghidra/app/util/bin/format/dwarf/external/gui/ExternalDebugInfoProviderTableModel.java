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
package ghidra.app.util.bin.format.dwarf.external.gui;

import java.awt.FontMetrics;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.table.TableColumn;

import docking.widgets.table.*;
import generic.theme.GIcon;
import ghidra.app.util.bin.format.dwarf.external.DebugInfoProvider;
import ghidra.app.util.bin.format.dwarf.external.DebugInfoProviderStatus;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.GColumnRenderer;
import resources.Icons;

/**
 * Table model for the {@link ExternalDebugFilesConfigDialog} table
 */
class ExternalDebugInfoProviderTableModel
		extends GDynamicColumnTableModel<ExternalDebugInfoProviderTableRow, List<ExternalDebugInfoProviderTableRow>> {

	private List<ExternalDebugInfoProviderTableRow> rows = new ArrayList<>();
	private boolean dataChanged;

	ExternalDebugInfoProviderTableModel() {
		super(new ServiceProviderStub());
		setDefaultTableSortState(null);
	}

	boolean isEmpty() {
		return rows.isEmpty();
	}

	void setItems(List<DebugInfoProvider> newItems) {
		rows.clear();
		for (DebugInfoProvider item : newItems) {
			rows.add(new ExternalDebugInfoProviderTableRow(item));
		}
		fireTableDataChanged();
	}

	List<DebugInfoProvider> getItems() {
		return rows.stream().map(ExternalDebugInfoProviderTableRow::getItem).toList();
	}

	void addItem(DebugInfoProvider newItem) {
		ExternalDebugInfoProviderTableRow row = new ExternalDebugInfoProviderTableRow(newItem);
		rows.add(row);
		dataChanged = true;
		fireTableDataChanged();
	}

	void addItems(List<DebugInfoProvider> newItems) {
		for (DebugInfoProvider item : newItems) {
			rows.add(new ExternalDebugInfoProviderTableRow(item));
		}
		dataChanged = true;
		fireTableDataChanged();
	}

	void deleteRows(int[] rowIndexes) {
		for (int i = rowIndexes.length - 1; i >= 0; i--) {
			rows.remove(rowIndexes[i]);
		}
		dataChanged = true;
		fireTableDataChanged();
	}

	void moveRow(int rowIndex, int deltaIndex) {
		int destIndex = rowIndex + deltaIndex;
		if (rowIndex < 0 || rowIndex >= rows.size() || destIndex < 0 || destIndex >= rows.size()) {
			return;
		}

		ExternalDebugInfoProviderTableRow row1 = rows.get(rowIndex);
		ExternalDebugInfoProviderTableRow row2 = rows.get(destIndex);
		rows.set(destIndex, row1);
		rows.set(rowIndex, row2);

		dataChanged = true;

		fireTableDataChanged();
	}

	boolean isDataChanged() {
		return dataChanged;
	}

	void setDataChanged(boolean b) {
		this.dataChanged = b;
	}

	@Override
	public String getName() {
		return "External Debug Info Providers";
	}

	@Override
	public List<ExternalDebugInfoProviderTableRow> getModelData() {
		return rows;
	}

	@Override
	public List<ExternalDebugInfoProviderTableRow> getDataSource() {
		return rows;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		DynamicTableColumn<ExternalDebugInfoProviderTableRow, ?, ?> column = getColumn(columnIndex);
		if (column instanceof EnabledColumn && aValue instanceof Boolean boolVal) {
			ExternalDebugInfoProviderTableRow row = getRowObject(rowIndex);
			row.setEnabled(boolVal);
			dataChanged = true;
			fireTableDataChanged();
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		DynamicTableColumn<ExternalDebugInfoProviderTableRow, ?, ?> column = getColumn(columnIndex);
		return column instanceof EnabledColumn;
	}

	@Override
	protected TableColumnDescriptor<ExternalDebugInfoProviderTableRow> createTableColumnDescriptor() {
		TableColumnDescriptor<ExternalDebugInfoProviderTableRow> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new EnabledColumn());
		descriptor.addVisibleColumn(new StatusColumn());
		descriptor.addVisibleColumn(new LocationColumn());

		return descriptor;
	}

	//-------------------------------------------------------------------------------------------
	static class EnabledColumn
			extends AbstractDynamicTableColumnStub<ExternalDebugInfoProviderTableRow, Boolean>
			implements TableColumnInitializer {

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Enabled";
		}

		@Override
		public Boolean getValue(ExternalDebugInfoProviderTableRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isEnabled();
		}

		@Override
		public String getColumnName() {
			return "Enabled";
		}

		@Override
		public void initializeTableColumn(TableColumn col, FontMetrics fm, int padding) {
			int colWidth = fm.stringWidth("Enabled") + padding;
			col.setPreferredWidth(colWidth);
			col.setMaxWidth(colWidth * 2);
			col.setMinWidth(colWidth);
		}

	}

	private static class StatusColumn extends
			AbstractDynamicTableColumnStub<ExternalDebugInfoProviderTableRow, DebugInfoProviderStatus>
			implements TableColumnInitializer {

		private static final Icon VALID_ICON = new GIcon("icon.checkmark.green");
		private static final Icon INVALID_ICON = Icons.ERROR_ICON;

		private static Icon[] icons = new Icon[] { null, VALID_ICON, INVALID_ICON };
		private static String[] toolTips = new String[] { null, "Status: Ok", "Status: Failed" };

		EnumIconColumnRenderer<DebugInfoProviderStatus> renderer =
			new EnumIconColumnRenderer<>(DebugInfoProviderStatus.class, icons, toolTips);

		@Override
		public DebugInfoProviderStatus getValue(ExternalDebugInfoProviderTableRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getStatus();
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "Status";
		}

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public GColumnRenderer<DebugInfoProviderStatus> getColumnRenderer() {
			return renderer;
		}

		@Override
		public void initializeTableColumn(TableColumn col, FontMetrics fm, int padding) {
			int colWidth = fm.stringWidth("Status") + padding;
			col.setPreferredWidth(colWidth);
			col.setMaxWidth(colWidth * 2);
			col.setMinWidth(colWidth);
		}

	}

	private class LocationColumn
			extends AbstractDynamicTableColumnStub<ExternalDebugInfoProviderTableRow, String> {

		@Override
		public String getValue(ExternalDebugInfoProviderTableRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getItem().getDescriptiveName();
		}

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 250;
		}

	}
}
