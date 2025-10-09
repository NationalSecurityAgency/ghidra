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
package db;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import db.buffers.LocalBufferFile;
import docking.framework.DockingApplicationConfiguration;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableFilterPanel;
import generic.application.GenericApplicationLayout;
import ghidra.app.plugin.debug.dbtable.DbSmallTableModel;
import ghidra.framework.Application;
import ghidra.framework.plugintool.ServiceProviderStub;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

/**
 * <code>DbViewer</code> is a diagnostic application for viewing a
 * Ghidra database.
 */
public class DbViewer extends JFrame {
	private static final String LAST_BUFFER_FILE_DIRECTORY = "LastBufferFileDirectory";
	private File dbFile;
	private DBHandle dbh;
	private JMenuItem openItem;
	private JMenuItem closeItem;
	private JPanel mainPanel;
	private JPanel southPanel;
	private JComboBox<String> combo;
	private Table[] tables;
	private Hashtable<String, TableStatistics[]> tableStats = new Hashtable<>();
	private GTableFilterPanel<DBRecord> tableFilterPanel;

	DbViewer() {
		super("Database Viewer");
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		buildGui();
	}

	void buildGui() {
		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("File");
		menuBar.add(menu);
		openItem = new JMenuItem("Open Database...");
		menu.add(openItem);
		openItem.addActionListener(e -> openDb());
		closeItem = new JMenuItem("Close Database");
		menu.add(closeItem);
		closeItem.setEnabled(false);
		closeItem.addActionListener(e -> closeDb());
		JMenuItem exitItem = new JMenuItem("Exit");
		menu.add(exitItem);
		exitItem.addActionListener(e -> System.exit(0));
		setJMenuBar(menuBar);
	}

	private class TableNameComparator implements Comparator<Table> {

		@Override
		public int compare(Table t1, Table t2) {
			return t1.getName().compareTo(t2.getName());
		}

	}

	private void openDb() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(this);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		fileChooser.setFileFilter(new ExtensionFileFilter("gbf", "Ghidra Buffer File"));
		fileChooser.setCurrentDirectory(new File("C:\\"));

		fileChooser.setLastDirectoryPreference(LAST_BUFFER_FILE_DIRECTORY);

		File selectedFile = fileChooser.getSelectedFile(true);
		fileChooser.dispose();
		if (selectedFile == null) {
			return;
		}

		if (dbh != null) {
			closeDb();
		}
		Msg.debug(this, "Buffer file = " + selectedFile.getName());

		tables = new Table[0];
		try {
			dbFile = selectedFile;
			LocalBufferFile bf = new LocalBufferFile(selectedFile, true);
			dbh = new DBHandle(bf);
			tables = dbh.getTables();
			Arrays.sort(tables, new TableNameComparator());
		}
		catch (IOException e) {
			try {
				PackedDatabase pdb =
					PackedDatabase.getPackedDatabase(selectedFile, TaskMonitor.DUMMY);
				dbh = pdb.open(TaskMonitor.DUMMY);
				tables = dbh.getTables();
				Arrays.sort(tables, new TableNameComparator());
			}
			catch (Exception e1) {
				Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
				return;
			}

		}
		createMainPanel();
		closeItem.setEnabled(true);
	}

	private void closeDb() {
		dbh.close();
		dbh = null;
		this.getContentPane().remove(mainPanel);
		closeItem.setEnabled(false);
	}

	private void createMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		JPanel northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JPanel subNorthPanel = new JPanel(new PairLayout(4, 10));
		subNorthPanel.add(new GLabel("Database:"));
		subNorthPanel.add(new GLabel(dbFile.getName()));
		subNorthPanel.add(new GLabel("Tables:"));
		String[] names = new String[tables.length];
		for (int i = 0; i < names.length; i++) {
			names[i] =
				tables[i].getName() + " (" + Integer.toString(tables[i].getRecordCount()) + ")";
		}
		combo = new GComboBox<>(names);
		combo.addItemListener(e -> updateTable());
		subNorthPanel.add(combo);
		northPanel.add(subNorthPanel);
		mainPanel.add(northPanel, BorderLayout.NORTH);
		getContentPane().add(mainPanel);
		southPanel = createSouthPanel(tables[0]);
		mainPanel.add(southPanel, BorderLayout.CENTER);
		validate();

	}

	private void updateTable() {
		Table table = tables[combo.getSelectedIndex()];
		mainPanel.remove(southPanel);
		southPanel = createSouthPanel(table);
		mainPanel.add(southPanel, BorderLayout.CENTER);
		validate();

	}

	private JPanel createSouthPanel(Table table) {
		JPanel panel = new JPanel(new BorderLayout());
		DbSmallTableModel model = new DbSmallTableModel(new ServiceProviderStub(), table);
		GTable gTable = new GTable(model);

		tableFilterPanel = new GTableFilterPanel<>(gTable, model);
		JScrollPane scroll = new JScrollPane(gTable);
		panel.add(scroll, BorderLayout.CENTER);
		panel.add(tableFilterPanel, BorderLayout.SOUTH);

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
		JLabel statsLabel = new GDLabel(
			recCnt + "   " + intNodeCnt + "   " + recNodeCnt + "   " + chainBufCnt + "   " + size);
		panel.add(statsLabel, BorderLayout.SOUTH);

		return panel;
	}

	/**
	 * Get the statistics for the specified table.
	 * @param table the table
	 * @return arrays containing statistics. Element 0 provides statistics for primary table, 
	 * element 1 provides combined statistics for all index tables.  Remaining array elements
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
				Msg.error(this, "Exception loading stats", e);
			}
		}
		return stats;
	}

	public static void main(String[] args) throws IOException {
		ApplicationLayout layout = new GenericApplicationLayout("DB Viewer", "1.0");
		DockingApplicationConfiguration configuration = new DockingApplicationConfiguration();
		configuration.setShowSplashScreen(false);
		Application.initializeApplication(layout, configuration);

		DbViewer viewer = new DbViewer();
		viewer.setSize(new Dimension(500, 400));
		viewer.setVisible(true);
	}

}
