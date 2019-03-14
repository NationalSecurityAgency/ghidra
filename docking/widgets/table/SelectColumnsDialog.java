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
package docking.widgets.table;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.table.*;

import docking.DialogComponentProvider;
import ghidra.util.HelpLocation;

public class SelectColumnsDialog extends DialogComponentProvider {
	private static final String DISCOVERED_TABLE_COLUMN_NAME = "Non-default";

	private GTable ghidraTable;
	private final TableModel sourceTablemodel;

	private List<TableColumnWrapper> columnList;
	private Map<TableColumn, Boolean> visibilityMap = new HashMap<>();
	private final GTableColumnModel columnModel;

	public SelectColumnsDialog(GTableColumnModel columnModel, TableModel model) {
		super("Select Columns", true, true, true, false);
		this.columnModel = columnModel;
		this.sourceTablemodel = model;

		initialize();

		TableModel tableModel = new SelectColumnsModel();

		ghidraTable = new GTable(tableModel);

		ghidraTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		ghidraTable.setAutoLookupColumn(1);
		TableColumn enabledColumn = ghidraTable.getColumnModel().getColumn(0);
		int enabledColumnWidth = 30;
		enabledColumn.setPreferredWidth(enabledColumnWidth);//visible column
		enabledColumn.setMaxWidth(enabledColumnWidth);
		enabledColumn.setCellRenderer(new ColumnSelectorBooleanRenderer());
		ghidraTable.getTableHeader().setReorderingAllowed(false);
		ghidraTable.setColumnHeaderPopupEnabled(false);

		// Skip column 0, which has already been set to a boolean renderer
		for (int i = 1; i < ghidraTable.getColumnCount(); i++) {
			ghidraTable.getColumnModel().getColumn(i).setCellRenderer(
				new ColumnSelectorStringRenderer());
		}

		ghidraTable.setBorder(BorderFactory.createEtchedBorder());
		Dimension size = new Dimension(400, 500);
		setPreferredSize(size.width, size.height);
		setRememberSize(true);

		JPanel panel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(ghidraTable);
		panel.add(scrollPane);
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation("Tables/GhidraTableHeaders.html", "SelectColumns"));
	}

	private void initialize() {
		List<TableColumn> columns = columnModel.getAllColumns();
		columnList = new ArrayList<>(columns.size());
		for (TableColumn column : columns) {
			visibilityMap.put(column, columnModel.isVisible(column));
			columnList.add(new TableColumnWrapper(sourceTablemodel, column));
		}

		Collections.sort(columnList, new ColumnComparator());
	}

	private class ColumnComparator implements Comparator<TableColumnWrapper> {
		@Override
		public int compare(TableColumnWrapper wrapper1, TableColumnWrapper wrapper2) {
			boolean isDefault1 = wrapper1.isDefault();
			boolean isDefault2 = wrapper2.isDefault();
			TableColumn column1 = wrapper1.getTableColumn();
			TableColumn column2 = wrapper2.getTableColumn();

			if (isDefault1 == isDefault2) {
				String headerString1 = column1.getHeaderValue().toString();
				String headerString2 = column2.getHeaderValue().toString();
				return headerString1.compareTo(headerString2);
			}

			if (isDefault1) {
				return -1; // prefer default columns
			}

			return 1;
		}
	}

	boolean isOK() {
		for (Boolean value : visibilityMap.values()) {
			if (value) {
				return true;
			}
		}
		return false;
	}

	@Override
	protected void okCallback() {
		if (!isOK()) {
			setStatusText("No Columns selected!");
			return;
		}

		Iterator<TableColumn> iter = visibilityMap.keySet().iterator();
		while (iter.hasNext()) {
			TableColumn column = iter.next();
			Boolean visible = visibilityMap.get(column);
			if (visible != columnModel.isVisible(column)) {
				columnModel.setVisible(column, visible);
			}
		}
		close();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ColumnSelectorStringRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JComponent c = (JComponent) super.getTableCellRendererComponent(data);

			int row = data.getRowViewIndex();
			boolean isSelected = data.isSelected();

			if (isSelected) {
				return c;
			}

			TableColumnWrapper tableColumnWrapper = columnList.get(row);
			if (!tableColumnWrapper.isDefault()) {
				c.setBackground(c.getBackground().darker());
				c.setOpaque(true);
			}

			String columnDescription = tableColumnWrapper.getColumnDescription();
			c.setToolTipText(columnDescription);
			return c;
		}
	}

	private class ColumnSelectorBooleanRenderer extends GBooleanCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JComponent c = (JComponent) super.getTableCellRendererComponent(data);

			int row = data.getRowViewIndex();
			boolean isSelected = data.isSelected();
			if (isSelected) {
				return c;
			}

			TableColumnWrapper tableColumnWrapper = columnList.get(row);
			if (!tableColumnWrapper.isDefault()) {
				c.setBackground(c.getBackground().darker());
				c.setOpaque(true);
			}

			String columnDescription = tableColumnWrapper.getColumnDescription();
			c.setToolTipText(columnDescription);
			return c;
		}
	}

	private class TableColumnWrapper {
		private final TableColumn column;
		private final TableModel model;

		TableColumnWrapper(TableModel model, TableColumn column) {
			this.model = model;
			this.column = column;
		}

		boolean isDefault() {
			VariableColumnTableModel variableModel = VariableColumnTableModel.from(model);
			if (variableModel == null) {
				return true;
			}
			int modelIndex = column.getModelIndex();
			return variableModel.isDefaultColumn(modelIndex);
		}

		String getColumnDescription() {
			VariableColumnTableModel variableModel = VariableColumnTableModel.from(model);
			if (variableModel == null) {
				return null;
			}

			int modelIndex = column.getModelIndex();
			return variableModel.getColumnDescription(modelIndex);
		}

		TableColumn getTableColumn() {
			return column;
		}
	}

	private class SelectColumnsModel extends DefaultTableModel {

		@Override
		public int getRowCount() {
			if (columnList == null) {
				return 0;
			}
			return columnList.size();
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			return column == 0;
		}

		@Override
		public Object getValueAt(int row, int column) {
			TableColumnWrapper tableColumnWrapper = columnList.get(row);
			TableColumn tableColumn = tableColumnWrapper.getTableColumn();
			if (column == 0) {
				return visibilityMap.get(tableColumn);
			}
			else if (column == 1) {
				return tableColumn.getHeaderValue();
			}
			else if (column == 2) {
				if (tableColumnWrapper.isDefault()) {
					return "Default";
				}
				return DISCOVERED_TABLE_COLUMN_NAME;
			}
			return "<<unknown>>";
		}

		@Override
		public void setValueAt(Object aValue, int row, int column) {
			if (column == 0) {
				TableColumnWrapper tableColumnWrapper = columnList.get(row);
				visibilityMap.put(tableColumnWrapper.getTableColumn(), (Boolean) aValue);
			}
		}

		@Override
		public int getColumnCount() {
			return 3;
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 0) {
				return Boolean.class;
			}
			else if (columnIndex == 2) {
				return String.class;
			}
			return String.class;
		}

		@Override
		public String getColumnName(int column) {
			if (column == 0) {
				return "Visible";
			}
			else if (column == 1) {
				return "Column Name";
			}
			else if (column == 2) {
				return "Is Default?";
			}
			return "<<unknown>>";
		}
	}
}
