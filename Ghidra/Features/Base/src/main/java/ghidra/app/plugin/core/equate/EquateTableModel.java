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
package ghidra.app.plugin.core.equate;

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JLabel;

import docking.widgets.table.*;
import ghidra.app.util.ToolTipUtils;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.database.symbol.EquateManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.util.UniversalID;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import util.CollectionUtils;

class EquateTableModel extends GDynamicColumnTableModel<Equate, Object> {

	private EquateTablePlugin plugin;
	private List<Equate> equateList = new ArrayList<>();

	// For testing
	static final int NAME_COL = 0;
	static final int VALUE_COL = 1;
	static final int REFS_COL = 2;

	EquateTableModel(EquateTablePlugin plugin) {
		super(plugin.getTool());
		this.plugin = plugin;
	}

	private void populateEquates() {

		equateList.clear();

		Program program = plugin.getProgram();

		if (program == null) {
			fireTableDataChanged();
			return;
		}

		EquateTable equateTable = program.getEquateTable();

		equateList = CollectionUtils.asList(equateTable.getEquates());

		fireTableDataChanged();
	}

	@Override
	public String getName() {
		return "Equates";
	}

	public void update() {
		populateEquates();
	}

	@Override
	public List<Equate> getModelData() {
		return equateList;
	}

	@Override
	protected TableColumnDescriptor<Equate> createTableColumnDescriptor() {

		TableColumnDescriptor<Equate> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new EquateNameColumn());
		descriptor.addVisibleColumn(new EquateValueColumn());
		descriptor.addVisibleColumn(new EquateReferenceCountColumn());
		descriptor.addHiddenColumn(new IsEnumBasedEquateColumn());
		return descriptor;
	}

	@Override
	public Object getDataSource() {
		return null;
	}

	@Override
	public boolean isCellEditable(int row, int column) {

		if (!getColumnName(column).equals(EquateNameColumn.NAME)) {
			// only the name
			return false;
		}

		return !getEquate(row).getName().startsWith(EquateManager.DATATYPE_TAG);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {

		if (!getColumnName(columnIndex).equals(EquateNameColumn.NAME)) {
			return;
		}

		if (!(aValue instanceof String)) {
			return;
		}
		plugin.renameEquate(equateList.get(rowIndex), (String) aValue);
	}

	public Equate getEquate(int rowIndex) {
		return equateList.get(rowIndex);
	}

	private class EquateNameColumn extends AbstractDynamicTableColumn<Equate, String, Object> {

		public static final String NAME = "Name";

		private GColumnRenderer<String> renderer = new AbstractGColumnRenderer<>() {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				boolean isSelected = data.isSelected();

				label.setText(" ");

				Equate eq = (Equate) data.getRowObject();
				if (eq == null) {
					return label;
				}

				if (!eq.isValidUUID()) { // Error equate
					label.setForeground((isSelected) ? Color.WHITE : Color.RED);
				} else if (!eq.isEnumBased()) { // User label
					label.setForeground((isSelected) ? Color.WHITE : Color.BLUE.brighter());
				}

				String tooltip = getEquateToolTip(eq);
				label.setToolTipText(tooltip);

				label.setText((String) data.getValue());
				return label;
			}

			@Override
			public String getFilterString(String t, Settings settings) {
				return t;
			}

			private String getEquateToolTip(Equate eq) {
				Program program = plugin.getProgram();
				DataTypeManager dtm = program.getDataTypeManager();
				UniversalID id = eq.getEnumUUID();
				if (id == null) {
					return eq.getName();
				}

				Enum enoom = (Enum) dtm.findDataTypeForID(id);
				if (enoom == null) {
					return null;
				}
				String tooltip = ToolTipUtils.getToolTipText(enoom);
				return tooltip;
			}

		};

		@Override
		public String getColumnName() {
			return NAME;
		}

		@Override
		public String getValue(Equate rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDisplayName();
		}

		@Override
		public GColumnRenderer<String> getColumnRenderer() {
			return renderer;
		}

	}

	private class EquateValueColumn extends AbstractDynamicTableColumn<Equate, Long, Object> {

		public static final String NAME = "Value";

		private GColumnRenderer<Long> renderer = new AbstractGColumnRenderer<>() {

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				Equate eq = (Equate) data.getRowObject();
				if (eq == null) {
					return label;
				}

				label.setToolTipText(eq.getDisplayValue());

				return label;
			}

			@Override
			public String getFilterString(Long t, Settings settings) {
				StringBuilder sb = new StringBuilder();
				// @formatter:off
				sb.append(Long.toHexString(t))
				.append(" ")
				.append(Long.toString(t));
				// @formatter:on
				return sb.toString();
			}
		};

		@Override
		public String getColumnName() {
			return NAME;
		}

		@Override
		public Long getValue(Equate rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			FormatSettingsDefinition formatDef = FormatSettingsDefinition.DEF;

			if (!formatDef.hasValue(settings)) {
				// We'll default-format this number in hex
				formatDef.setChoice(settings, FormatSettingsDefinition.HEX);
			}

			return rowObject.getValue();
		}

		@Override
		public GColumnRenderer<Long> getColumnRenderer() {
			return renderer;
		}

	}

	private class EquateReferenceCountColumn
	extends AbstractDynamicTableColumn<Equate, Integer, Object> {

		public static final String NAME = "# Refs";

		@Override
		public String getColumnName() {
			return NAME;
		}

		@Override
		public Integer getValue(Equate rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getReferenceCount();
		}

	}

	private class IsEnumBasedEquateColumn
	extends AbstractDynamicTableColumn<Equate, Boolean, Object> {

		public static final String NAME = "Is Enum-Based";

		@Override
		public String getColumnName() {
			return NAME;
		}

		@Override
		public Boolean getValue(Equate rowObject, Settings settings, Object data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.isEnumBased();
		}
	}
}
