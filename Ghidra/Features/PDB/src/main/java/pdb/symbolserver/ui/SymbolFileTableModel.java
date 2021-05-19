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

import java.util.ArrayList;
import java.util.List;

import java.awt.Component;

import javax.swing.*;

import docking.widgets.table.*;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import pdb.symbolserver.SymbolFileInfo;
import pdb.symbolserver.SymbolFileLocation;

/**
 * Table model for the SymbolFilePanel table.
 */
class SymbolFileTableModel
		extends GDynamicColumnTableModel<SymbolFileRow, List<SymbolFileRow>> {

	private List<SymbolFileRow> rows = new ArrayList<>();

	SymbolFileTableModel() {
		super(new ServiceProviderStub());
		setDefaultTableSortState(null);
	}

	void setRows(List<SymbolFileRow> rows) {
		this.rows = rows;
		fireTableDataChanged();
	}

	void setSearchResults(SymbolFileInfo symbolFileInfo, List<SymbolFileLocation> results) {
		List<SymbolFileRow> newRows = new ArrayList<>();
		for (SymbolFileLocation symbolFileLocation : results) {
			newRows.add(new SymbolFileRow(symbolFileLocation,
				symbolFileLocation.isExactMatch(symbolFileInfo)));
		}
		rows = newRows;
		fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Symbol Files";
	}

	@Override
	public List<SymbolFileRow> getModelData() {
		return rows;
	}

	@Override
	public List<SymbolFileRow> getDataSource() {
		return rows;
	}

	@Override
	protected TableColumnDescriptor<SymbolFileRow> createTableColumnDescriptor() {
		TableColumnDescriptor<SymbolFileRow> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new PdbExactMatchColumn());
		descriptor.addVisibleColumn(new PdbFileNameColumn());
		descriptor.addHiddenColumn(new PdbFilePathColumn());
		descriptor.addVisibleColumn(new GuidColumn());
		descriptor.addVisibleColumn(new PdbAgeColumn());
		descriptor.addHiddenColumn(new PdbVersionColumn());
		descriptor.addVisibleColumn(new PdbFileStatusColumn());
		descriptor.addVisibleColumn(new PdbFileLocationColumn());

		return descriptor;
	}

	private class PdbExactMatchColumn
			extends AbstractDynamicTableColumnStub<SymbolFileRow, Boolean> {

		BooleanIconColumnRenderer renderer =
			new BooleanIconColumnRenderer(LoadPdbDialog.MATCH_OK_ICON,
				LoadPdbDialog.MATCH_BAD_ICON, null, "Exact Match", "Not Exact Match", null);

		@Override
		public Boolean getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isExactMatch();
		}

		@Override
		public GColumnRenderer<Boolean> getColumnRenderer() {
			return renderer;
		}

		@Override
		public String getColumnName() {
			return "Exact Match";
		}

		@Override
		public String getColumnDisplayName(Settings settings) {
			return "";
		}

	}

	private class PdbFileNameColumn extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolFileInfo().getName();
		}

		@Override
		public String getColumnName() {
			return "PDB Filename";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}

	}

	private class PdbFilePathColumn extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolFileInfo().getPath();
		}

		@Override
		public String getColumnName() {
			return "PDB Filepath";
		}

	}

	private class GuidColumn extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolFileInfo().getUniqueName();
		}

		@Override
		public String getColumnName() {
			return "GUID / Signature";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 300;
		}

	}

	private class PdbVersionColumn extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return Integer.toString(rowObject.getSymbolFileInfo().getIdentifiers().getVersion());
		}

		@Override
		public String getColumnName() {
			return "PDB Version";
		}

	}

	private class PdbAgeColumn extends AbstractDynamicTableColumnStub<SymbolFileRow, Integer> {

		@Override
		public Integer getValue(SymbolFileRow rowObject, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSymbolFileInfo().getIdentifiers().getAge();
		}

		@Override
		public String getColumnName() {
			return "PDB Age";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 120;
		}

	}

	private class PdbFileStatusColumn
			extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow row, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.isAvailableLocal() ? "Local" : "Remote";
		}

		@Override
		public String getColumnName() {
			return "PDB File Status";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 120;
		}

	}

	private class PdbFileLocationColumn
			extends AbstractDynamicTableColumnStub<SymbolFileRow, String> {

		@Override
		public String getValue(SymbolFileRow row, Settings settings,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return row.getLocation().getLocationStr();
		}

		@Override
		public String getColumnName() {
			return "File Location";
		}

	}

	/**
	 * Table column renderer to render a boolean value as an icon
	 */
	private static class BooleanIconColumnRenderer extends AbstractGColumnRenderer<Boolean> {

		private Icon[] icons;
		private String[] toolTipStrings;

		BooleanIconColumnRenderer(Icon trueIcon, Icon falseIcon, Icon missingIcon,
				String trueTooltip, String falseTooltip, String missingTooltip) {
			this.icons = new Icon[] { missingIcon, falseIcon, trueIcon };
			this.toolTipStrings = new String[] { missingTooltip, falseTooltip, trueTooltip };
		}

		private int getValueOrdinal(GTableCellRenderingData data) {
			Boolean booleanValue = (Boolean) data.getValue();

			return booleanValue == null ? 0 : booleanValue.booleanValue() ? 2 : 1;
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			int ordinal = getValueOrdinal(data);
			renderer.setHorizontalAlignment(SwingConstants.CENTER);
			renderer.setText("");
			renderer.setIcon(icons[ordinal]);
			renderer.setToolTipText(toolTipStrings[ordinal]);
			return renderer;
		}

		@Override
		public String getFilterString(Boolean booleanValue, Settings settings) {
			return booleanValue == null ? "" : booleanValue.toString();
		}

	}
}
