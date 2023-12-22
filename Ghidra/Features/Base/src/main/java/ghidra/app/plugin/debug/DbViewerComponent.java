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
package ghidra.app.plugin.debug;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import db.*;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.app.plugin.debug.dbtable.DbSmallTableModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.SwingUpdateManager;

class DbViewerComponent extends JPanel {

	private static Table[] NO_TABLES = new Table[0];

	private static Comparator<Table> TABLE_NAME_COMPARATOR =
		(o1, o2) -> (o1).getName().compareTo((o2).getName());

	private DBHandle dbh;
	private DBListener dbListener;
	private JPanel centerPanel;
	private JComponent southComponent;
	private JLabel dbLabel;
	private JComboBox<TableItem> combo;
	private Table[] tables = NO_TABLES;
	private Map<String, TableStatistics[]> tableStats = new HashMap<>();

	private SwingUpdateManager updateMgr;

	private PluginTool tool;

	private GTableFilterPanel<DBRecord> tableFilterPanel;

	DbViewerComponent(PluginTool tool) {
		super(new BorderLayout());
		this.tool = tool;

		JPanel northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JPanel subNorthPanel = new JPanel(new PairLayout(4, 10));
		subNorthPanel.add(new GLabel("Database:"));
		dbLabel = new GDLabel();
		subNorthPanel.add(dbLabel);
		subNorthPanel.add(new GLabel("Tables:"));
		combo = new GComboBox<>();
		combo.addActionListener(e -> refreshTable());
		subNorthPanel.add(combo);
		northPanel.add(subNorthPanel);
		add(northPanel, BorderLayout.NORTH);

		updateMgr = new SwingUpdateManager(100, 2000, () -> refresh());
	}

	synchronized void closeDatabase() {
		if (dbh != null) {
			combo.removeAllItems();
			dbLabel.setText("");
			removeWidgets();
			tables = NO_TABLES;
			tableStats.clear();
			dbh = null;
			dbListener = null;

			revalidate();
		}
	}

	private void removeWidgets() {
		if (centerPanel != null) {
			remove(centerPanel);
			remove(southComponent);
			centerPanel = null;
			southComponent = null;
		}
	}

	synchronized void openDatabase(String name, DBHandle handle) {

		closeDatabase();

		this.dbh = handle;

		dbLabel.setText(name);
		updateTableChoices(null);

		dbListener = new InternalDBListener();
		handle.addListener(dbListener);
	}

	synchronized void refresh() {
		if (dbh == null) {
			return;
		}
		synchronized (dbh) {
			updateTableChoices((TableItem) combo.getSelectedItem());
			updateTable();
		}
	}

	synchronized void refreshTable() {
		if (dbh == null) {
			removeWidgets();
			return;
		}
		synchronized (dbh) {
			updateTable();
		}
	}

	synchronized void dispose() {
		updateMgr.dispose();
		tableFilterPanel.dispose();
		closeDatabase();
	}

	/**
	 * Get the statistics for the specified table.
	 * @param table the table
	 * @return arrays containing statistics. Element 0 provides
	 * statistics for primary table, element 1 provides combined
	 * statistics for all index tables.  Remaining array elements 
	 * should be ignored since they have been combined into element 1.
	 */
	private TableStatistics[] getStats(Table table) {
		TableStatistics[] stats = tableStats.get(table.getName());
		if (stats == null) {
			try {
				stats = table.getAllStatistics();
				for (int i = 2; i < stats.length; i++) {
					// combine index stats
					stats[1].bufferCount += stats[i].bufferCount;
					stats[1].chainedBufferCnt += stats[i].chainedBufferCnt;
					stats[1].interiorNodeCnt += stats[i].interiorNodeCnt;
					stats[1].recordNodeCnt += stats[i].recordNodeCnt;
					stats[1].size += stats[i].size;
				}
				tableStats.put(table.getName(), stats);
			}
			catch (IOException e) {
				Msg.debug(this, "Unexpected exception", e);
			}
		}
		return stats;
	}

	private void updateTableChoices(TableItem selectedTable) {

		tables = NO_TABLES;
		combo.removeAllItems();
		tableStats.clear();

		if (dbh != null) {
			tables = dbh.getTables();
			Arrays.sort(tables, TABLE_NAME_COMPARATOR);
		}

		int selIndex = -1;
		for (int i = 0; i < tables.length; i++) {
			combo.addItem(new TableItem(tables[i]));
			if (selectedTable != null && tables[i].getName().equals(selectedTable.name)) {
				selIndex = i;
			}
		}
		if (selIndex >= 0) {
			combo.setSelectedIndex(selIndex);
		}
	}

	private void updateTable() {

		removeWidgets();

		TableItem t = (TableItem) combo.getSelectedItem();
		if (t != null) {
			centerPanel = createCenterPanel(t.table);
			add(centerPanel, BorderLayout.CENTER);
			southComponent = createSouthComponent(t.table);
			add(southComponent, BorderLayout.SOUTH);

		}
		revalidate();
	}

	private JComponent createSouthComponent(Table table) {
		TableStatistics[] stats = getStats(table);
		String recCnt = "Records: " + Integer.toString(table.getRecordCount());
		String intNodeCnt = "";
		String recNodeCnt = "";
		String chainBufCnt = "";
		String size = "";
		if (stats != null) {
			intNodeCnt = "Interior Nodes: " + Integer.toString(stats[0].interiorNodeCnt);
			recNodeCnt = "Record Nodes: " + Integer.toString(stats[0].recordNodeCnt);
			chainBufCnt = "Chained Buffers: " + Integer.toString(stats[0].chainedBufferCnt);
			size = "Size (KB): " + Integer.toString(stats[0].size / 1024);
			if (stats.length > 1) {
				intNodeCnt += " / " + Integer.toString(stats[1].interiorNodeCnt);
				recNodeCnt += " / " + Integer.toString(stats[1].recordNodeCnt);
				chainBufCnt += " / " + Integer.toString(stats[1].chainedBufferCnt);
				size += " / " + Integer.toString(stats[1].size / 1024);
			}
		}
		return new GLabel(
			recCnt + "   " + intNodeCnt + "   " + recNodeCnt + "   " + chainBufCnt + "   " + size);
	}

	private JPanel createCenterPanel(Table table) {
		JPanel panel = new JPanel(new BorderLayout());
		DbSmallTableModel model = new DbSmallTableModel(tool, table);

		GThreadedTablePanel<DBRecord> threadedPanel = new GThreadedTablePanel<>(model);
		GTable gTable = threadedPanel.getTable();

		tableFilterPanel = new GTableFilterPanel<>(gTable, model);

		panel.add(threadedPanel, BorderLayout.CENTER);
		panel.add(tableFilterPanel, BorderLayout.SOUTH);
		return panel;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private static class TableItem {
		String name;
		Table table;

		TableItem(Table table) {
			this.table = table;
			name = table.getName();
		}

		@Override
		public String toString() {
			return name + " (" + table.getRecordCount() + ")";
		}
	}

	private class InternalDBListener implements DBListener {
		@Override
		public void dbClosed(DBHandle handle) {
			if (handle == DbViewerComponent.this.dbh) {
				closeDatabase();
			}
		}

		@Override
		public void dbRestored(DBHandle handle) {
			if (handle == DbViewerComponent.this.dbh) {
				updateMgr.updateLater();
			}
		}

		@Override
		public void tableAdded(DBHandle handle, Table table) {
			if (handle == DbViewerComponent.this.dbh) {
				updateMgr.updateLater();
			}
		}

		@Override
		public void tableDeleted(DBHandle handle, Table table) {
			if (handle == DbViewerComponent.this.dbh) {
				updateMgr.updateLater();
			}
		}
	}
}
