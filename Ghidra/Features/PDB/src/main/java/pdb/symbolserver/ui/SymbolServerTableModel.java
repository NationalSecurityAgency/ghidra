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
package pdb.symbolserver.ui;

import static java.util.stream.Collectors.toList;
import static pdb.symbolserver.ui.SymbolServerRow.LocationStatus.INVALID;
import static pdb.symbolserver.ui.SymbolServerRow.LocationStatus.VALID;

import java.util.ArrayList;
import java.util.List;

import java.awt.Component;

import javax.swing.*;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.Swing;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.task.TaskLauncher;
import pdb.symbolserver.SymbolServer;
import resources.Icons;

/**
 * Table model for the {@link SymbolServerPanel} table
 */
class SymbolServerTableModel
		extends GDynamicColumnTableModel<SymbolServerRow, List<SymbolServerRow>> {

	private List<SymbolServerRow> rows = new ArrayList<>();
	private boolean dataChanged;

	SymbolServerTableModel() {
		super(new ServiceProviderStub());
		setDefaultTableSortState(null);
	}

	boolean isEmpty() {
		return rows.isEmpty();
	}

	void setSymbolServers(List<SymbolServer> symbolServers) {
		rows.clear();
		for (SymbolServer symbolServer : symbolServers) {
			rows.add(new SymbolServerRow(symbolServer));
		}
		fireTableDataChanged();
	}

	List<SymbolServer> getSymbolServers() {
		return rows.stream()
				.map(SymbolServerRow::getSymbolServer)
				.collect(toList());
	}

	void addSymbolServer(SymbolServer ss) {
		SymbolServerRow row = new SymbolServerRow(ss);
		rows.add(row);
		dataChanged = true;
		fireTableDataChanged();
	}

	void addSymbolServers(List<SymbolServer> symbolServers) {
		for (SymbolServer symbolServer : symbolServers) {
			rows.add(new SymbolServerRow(symbolServer));
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

	void refreshSymbolServerLocationStatus() {
		List<SymbolServerRow> rowsCopy = new ArrayList<>(this.rows);
		TaskLauncher.launchNonModal("Refresh Symbol Server Location Status", monitor -> {
			monitor.initialize(rowsCopy.size());
			monitor.setMessage("Refreshing symbol server status");
			try {
				for (SymbolServerRow row : rowsCopy) {
					if (monitor.isCancelled()) {
						break;
					}
					monitor.setMessage("Checking " + row.getSymbolServer().getName());
					row.setStatus(row.getSymbolServer().isValid(monitor) ? VALID : INVALID);
				}
			}
			finally {
				Swing.runLater(SymbolServerTableModel.this::fireTableDataChanged);
			}
		});
	}

	void moveRow(int rowIndex, int deltaIndex) {
		int destIndex = rowIndex + deltaIndex;
		if (rowIndex < 0 || rowIndex >= rows.size() || destIndex < 0 || destIndex >= rows.size()) {
			return;
		}

		SymbolServerRow symbolServerRow1 = rows.get(rowIndex);
		SymbolServerRow symbolServerRow2 = rows.get(destIndex);
		rows.set(destIndex, symbolServerRow1);
		rows.set(rowIndex, symbolServerRow2);

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
		return "Symbol Server Locations";
	}

	@Override
	public List<SymbolServerRow> getModelData() {
		return rows;
	}

	@Override
	public List<SymbolServerRow> getDataSource() {
		return rows;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return false;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		DynamicTableColumn<SymbolServerRow, ?, ?> column = getColumn(columnIndex);
		if (column instanceof EnabledColumn) {
			SymbolServerRow row = getRowObject(rowIndex);
			row.setEnabled((Boolean) aValue);
			dataChanged = true;
			fireTableDataChanged();
		}
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		DynamicTableColumn<SymbolServerRow, ?, ?> column = getColumn(columnIndex);
		return column instanceof EnabledColumn;
	}

	@Override
	protected TableColumnDescriptor<SymbolServerRow> createTableColumnDescriptor() {
		TableColumnDescriptor<SymbolServerRow> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new EnabledColumn());
		descriptor.addVisibleColumn(new StatusColumn());
		descriptor.addVisibleColumn(new LocationColumn());

		return descriptor;
	}

	//-------------------------------------------------------------------------------------------

	private static class StatusColumn extends
			AbstractDynamicTableColumnStub<SymbolServerRow, SymbolServerRow.LocationStatus> {

		private static final Icon VALID_ICON = Icons.get("images/checkmark_green.gif");
		private static final Icon INVALID_ICON = Icons.ERROR_ICON;

		private static Icon[] icons = new Icon[] { null, VALID_ICON, INVALID_ICON };
		private static String[] toolTips = new String[] { null, "Status: Ok", "Status: Failed" };

		EnumIconColumnRenderer<SymbolServerRow.LocationStatus> renderer =
			new EnumIconColumnRenderer<>(SymbolServerRow.LocationStatus.class, icons, toolTips);

		@Override
		public SymbolServerRow.LocationStatus getValue(SymbolServerRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getStatus();
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "";
		}

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public GColumnRenderer<SymbolServerRow.LocationStatus> getColumnRenderer() {
			return renderer;
		}

	}

	private static class EnabledColumn
			extends AbstractDynamicTableColumnStub<SymbolServerRow, Boolean> {

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "";
		}

		@Override
		public Boolean getValue(SymbolServerRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isEnabled();
		}

		@Override
		public String getColumnName() {
			return "Enabled";
		}

	}

	private static class LocationColumn
			extends AbstractDynamicTableColumnStub<SymbolServerRow, String> {

		@Override
		public String getValue(SymbolServerRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolServer().getDescriptiveName();
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

	/**
	 * Table column renderer to render an enum value as a icon
	 * 
	 * @param <E> enum type
	 */
	private static class EnumIconColumnRenderer<E extends Enum<E>>
			extends AbstractGColumnRenderer<E> {

		private Icon[] icons;
		private String[] toolTips;

		EnumIconColumnRenderer(Class<E> enumClass, Icon[] icons, String[] toolTips) {
			if (enumClass.getEnumConstants().length != icons.length ||
				icons.length != toolTips.length) {
				throw new IllegalArgumentException();
			}
			this.icons = icons;
			this.toolTips = toolTips;
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			E e = (E) data.getValue();
			renderer.setHorizontalAlignment(SwingConstants.CENTER);
			renderer.setText("");
			renderer.setIcon(e != null ? icons[e.ordinal()] : null);
			renderer.setToolTipText(e != null ? toolTips[e.ordinal()] : null);
			return renderer;
		}

		@Override
		protected String getText(Object value) {
			return "";
		}

		@Override
		public String getFilterString(E t, Settings settings) {
			return t == null ? "" : t.toString();
		}
	}
}
