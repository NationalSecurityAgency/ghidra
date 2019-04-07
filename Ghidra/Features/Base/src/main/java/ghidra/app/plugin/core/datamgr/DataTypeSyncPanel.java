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
package ghidra.app.plugin.core.datamgr;

import java.awt.*;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.*;

import docking.widgets.table.GBooleanCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

/**
 * Left panel in the DataTypeSyncDialog. This panel displays a table with all the data types to
 * be synchronized (committed or updated) between a program and an archive.
 */
class DataTypeSyncPanel extends JPanel {
	private static final long serialVersionUID = 1L;

	private DataTypeSyncTableModel tableModel;
	private GhidraTable syncTable;
	private DataTypeSyncListener listener;
	private GhidraTableFilterPanel<RowData> tableFilterPanel;

	/**
	 * Construct a new data type synchronization table panel. 
	 * @param list list of LabelHistory objects
	 * @param listener listener that is notified when the user changes the selected
	 * row in the table.
	 */
	DataTypeSyncPanel(List<DataTypeSyncInfo> list, Set<DataTypeSyncInfo> preselectedInfos,
			DataTypeSyncListener listener) {
		super(new BorderLayout());
		this.listener = listener;
		create(list, preselectedInfos);
	}

	static class DataTypeSyncBooleanRenderer extends GBooleanCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			Component c = super.getTableCellRendererComponent(data);

			JTable table = data.getTable();
			int row = data.getRowViewIndex();
			int column = data.getColumnViewIndex();

			TableModel model = table.getModel();

			cb.setEnabled(model.isCellEditable(row, column));
			return c;
		}
	}

	void dispose() {
		tableFilterPanel.dispose();
		syncTable.dispose();
	}

	private void create(List<DataTypeSyncInfo> list, Set<DataTypeSyncInfo> preselectedInfos) {
		// Populate the table model.
		tableModel = new DataTypeSyncTableModel(list, preselectedInfos, true);

		syncTable = new GhidraTable(tableModel);
		syncTable.setDefaultRenderer(Boolean.class, new DataTypeSyncBooleanRenderer());
		JScrollPane sp = new JScrollPane(syncTable);

		Dimension d = new Dimension(940, 200);
		syncTable.setPreferredScrollableViewportSize(d);
		syncTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		tableFilterPanel = new GhidraTableFilterPanel<>(syncTable, tableModel);
		add(sp, BorderLayout.CENTER);
		add(tableFilterPanel, BorderLayout.SOUTH);
		tableModel.fireTableDataChanged();

		TableColumnModel columnModel = syncTable.getColumnModel();

		// Set default column sizes
		for (int i = 0; i < columnModel.getColumnCount(); i++) {
			TableColumn column = columnModel.getColumn(i);
			int modelIndex = column.getModelIndex();
			switch (modelIndex) {
				case DataTypeSyncTableModel.CHECKED_COL:
					column.setPreferredWidth(60);
					column.setMinWidth(60);
					column.setMaxWidth(60);
					column.setResizable(false);
					break;
				case DataTypeSyncTableModel.STATUS_COL:
					column.setPreferredWidth(70);
					column.setMinWidth(70);
					column.setMaxWidth(70);
					column.setResizable(false);
					break;
				case DataTypeSyncTableModel.REF_PATH_COL:
					column.setPreferredWidth(200);
					break;
				case DataTypeSyncTableModel.CHANGE_TIME_COL:
				case DataTypeSyncTableModel.NAME_COL:
					column.setPreferredWidth(140);
					break;
			}
		}

		// Set up notifier of selected row changing.
		ListSelectionModel selectionModel = syncTable.getSelectionModel();
		selectionModel.addListSelectionListener(e -> {
			int selectedIndex = tableFilterPanel.getModelRow(syncTable.getSelectedRow());
			if (selectedIndex >= 0) {
				listener.dataTypeSelected(tableModel.getSyncInfo(selectedIndex));
			}
			else {
				listener.dataTypeSelected(null);
			}
		});
	}

	public boolean hasUnresolvedDataTypes() {
		return tableModel.hasUnresolvedDataTypes();
	}

	public List<DataTypeSyncInfo> getSelectedInfos() {
		return tableModel.getSelectedItems();
	}

	public void selectAll() {
		tableModel.selectAll();

	}

	public void deselectAll() {
		tableModel.deselectAll();

	}
}
