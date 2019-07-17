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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.table.*;

import docking.DialogComponentProvider;
import ghidra.util.HelpLocation;
import util.CollectionUtils;

public class ChooseColumnsDialog extends DialogComponentProvider {

	private GTable ghidraTable;

	private List<TableColumnWrapper> columnList;
	private Map<TableColumn, Boolean> selectedMap = new HashMap<TableColumn, Boolean>();
	private final GTableColumnModel columnModel;

	private boolean wasCancelled;

	ChooseColumnsDialog(GTableColumnModel columnModel, TableModel model) {
		super("Select Columns", true, true, true, false);
		this.columnModel = columnModel;

		initialize();

		TableModel tableModel = new SelectColumnsModel();

		final TableCellRenderer renderer = new Renderer();

		ghidraTable = new GTable(tableModel) {
			@Override
			protected TableColumnModel createDefaultColumnModel() {
				return new DefaultTableColumnModel();
			}

			@Override
			public TableCellRenderer getCellRenderer(int row, int col) {
				return renderer;
			}
		};

		ghidraTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		ghidraTable.setAutoLookupColumn(1);
		TableColumn enabledColumn = ghidraTable.getColumnModel().getColumn(0);
		int enabledColumnWidth = 50;
		enabledColumn.setPreferredWidth(enabledColumnWidth);//visible column
		enabledColumn.setMaxWidth(enabledColumnWidth);
		ghidraTable.getTableHeader().setReorderingAllowed(false);
		ghidraTable.setColumnHeaderPopupEnabled(false);

		ghidraTable.setBorder(BorderFactory.createEtchedBorder());
		Dimension size = new Dimension(300, 400);
		setPreferredSize(size.width, size.height);
		setRememberSize(true);

		JPanel buttonPanel = new JPanel();
		JButton selectAllButton = new JButton("Select All");
		selectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setAllSelected(true);
			}
		});

		JButton deselectAllButton = new JButton("Deselect All");
		deselectAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setAllSelected(false);
			}
		});

		buttonPanel.add(selectAllButton);
		buttonPanel.add(deselectAllButton);

		JPanel panel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(ghidraTable);
		panel.add(scrollPane);
		panel.add(buttonPanel, BorderLayout.SOUTH);
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();

		setHelpLocation(new HelpLocation("Tables/GhidraTableHeaders.html", "SelectColumns"));
	}

	private void setAllSelected(boolean selected) {
		Set<TableColumn> keySet = selectedMap.keySet();
		for (TableColumn column : keySet) {
			selectedMap.put(column, selected);
		}

		ghidraTable.repaint();
	}

	private void initialize() {
		List<TableColumn> columns = CollectionUtils.asList(columnModel.getColumns());
		columnList = new ArrayList<TableColumnWrapper>(columns.size());
		for (TableColumn column : columns) {
			boolean visible = columnModel.isVisible(column);
			selectedMap.put(column, visible);
			if (visible) {
				columnList.add(new TableColumnWrapper(column));
			}
		}
	}

	boolean isOK() {
		for (Boolean value : selectedMap.values()) {
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

		close();
	}

	@Override
	protected void cancelCallback() {
		wasCancelled = true;
		super.cancelCallback();
	}

	int[] getChosenColumns() {
		if (wasCancelled) {
			return null;
		}

		List<Integer> columnIndices = new ArrayList<Integer>();
		for (TableColumnWrapper columnWrapper : columnList) {
			if (selectedMap.get(columnWrapper.getTableColumn())) {
				TableColumn column = columnWrapper.getTableColumn();
				int index = columnModel.getColumnIndex(column.getHeaderValue());
				columnIndices.add(index);
			}
		}

		int[] indices = new int[columnIndices.size()];
		for (int i = 0; i < indices.length; i++) {
			indices[i] = columnIndices.get(i);
		}
		return indices;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class Renderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Object value = data.getValue();
			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnViewIndex();
			boolean isSelected = data.isSelected();
			boolean hasFocus = data.hasFocus();

			JComponent renderer = null;
			if (column == 0) {
				TableCellRenderer booleanRenderer = table.getDefaultRenderer(Boolean.class);
				renderer =
					(JComponent) booleanRenderer.getTableCellRendererComponent(table, value,
						isSelected, hasFocus, row, column);
			}
			else {
				renderer =
					(JComponent) super.getTableCellRendererComponent(data);
			}

			if (isSelected) {
				return renderer;
			}

			return renderer;
		}
	}

	private class TableColumnWrapper {
		private final TableColumn column;

		TableColumnWrapper(TableColumn column) {
			this.column = column;
		}

		public TableColumn getTableColumn() {
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
				return selectedMap.get(tableColumn);
			}
			else if (column == 1) {
				return tableColumn.getHeaderValue();
			}
			return "<<unknown>>";
		}

		@Override
		public void setValueAt(Object aValue, int row, int column) {
			if (column == 0) {
				TableColumnWrapper tableColumnWrapper = columnList.get(row);
				selectedMap.put(tableColumnWrapper.getTableColumn(), (Boolean) aValue);
			}
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 0) {
				return Boolean.class;
			}
			return String.class;
		}

		@Override
		public String getColumnName(int column) {
			if (column == 0) {
				return "Copy";
			}
			else if (column == 1) {
				return "Column Name";
			}
			return "<<unknown>>";
		}
	}
}
