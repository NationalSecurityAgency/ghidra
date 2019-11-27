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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import db.buffers.LocalBufferFile;
import docking.framework.DockingApplicationConfiguration;
import docking.framework.DockingApplicationLayout;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.framework.Application;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitorAdapter;
import utility.application.ApplicationLayout;

/**
 * <code>DbViewer</code> is a diagnostic application for viewing a
 * Ghidra database.
 */
public class DbViewer extends JFrame {
	private GhidraFileChooser fileChooser;
	private File dbFile;
	private DBHandle dbh;
	private JMenuItem openItem;
	private JMenuItem closeItem;
	private JPanel mainPanel;
	private JPanel southPanel;
	private JComboBox<String> combo;
	private Table[] tables;
	private Hashtable<String, TableStatistics[]> tableStats = new Hashtable<>();

	DbViewer() {
		super("Database Viewer");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		buildGui();
	}

	void buildGui() {
		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("File");
		menuBar.add(menu);
		openItem = new JMenuItem("Open Database...");
		menu.add(openItem);
		openItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				openDb();
			}
		});
		closeItem = new JMenuItem("Close Database");
		menu.add(closeItem);
		closeItem.setEnabled(false);
		closeItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				closeDb();
			}
		});
		JMenuItem exitItem = new JMenuItem("Exit");
		menu.add(exitItem);
		exitItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		setJMenuBar(menuBar);
	}

	private class TableNameComparator implements Comparator<Table> {

		@Override
		public int compare(Table t1, Table t2) {
			return t1.getName().compareTo(t2.getName());
		}

	}

	private void openDb() {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(this);
			fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
			fileChooser.setFileFilter(new ExtensionFileFilter("gbf", "Ghidra Buffer File"));
			fileChooser.setCurrentDirectory(new File("C:\\"));
		}

		File selectedFile = fileChooser.getSelectedFile(true);
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
				PackedDatabase pdb = PackedDatabase.getPackedDatabase(selectedFile,
					TaskMonitorAdapter.DUMMY_MONITOR);
				dbh = pdb.open(TaskMonitorAdapter.DUMMY_MONITOR);
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
		combo.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updateTable();
			}
		});
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
		TableModel model = null;
		if (table.getRecordCount() <= 10000) {
			model = new DbSmallTableModel(table);
		}
		else {
			model = new DbLargeTableModel(table);
		}
		JTable jtable = new JTable(model);

		JScrollPane scroll = new JScrollPane(jtable);
		panel.add(scroll, BorderLayout.CENTER);

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
	 * @param table
	 * @return arrays containing statistics. Element 0 provides
	 * statsitics for primary table, element 1 provides combined
	 * statsitics for all index tables.  Remaining array elements 
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
			}
		}
		return stats;
	}

	/**
	 * Launch the DbViewer application.
	 * @param args (not used)
	 */
	public static void main(String[] args) throws IOException {

		ApplicationLayout layout = new DockingApplicationLayout("DB Viewer", "1.0");

		DockingApplicationConfiguration configuration = new DockingApplicationConfiguration();
		configuration.setShowSplashScreen(false);

		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch (ClassNotFoundException e) {
		}
		catch (InstantiationException e) {
		}
		catch (IllegalAccessException e) {
		}
		catch (UnsupportedLookAndFeelException e) {
		}
		Application.initializeApplication(layout, configuration);

		DbViewer viewer = new DbViewer();
		viewer.setSize(new Dimension(500, 400));
		viewer.setVisible(true);

	}

}

class ColumnAdapter {
	static final int BYTE = 0;
	static final int BOOLEAN = 1;
	static final int SHORT = 2;
	static final int INT = 3;
	static final int LONG = 4;
	static final int STRING = 5;
	static final int BINARY = 6;

	int type;
	Class<?> valueClass;

	ColumnAdapter(Class<?> c) {
		if (c == ByteField.class) {
			type = BYTE;
			valueClass = Byte.class;
		}
		else if (c == BooleanField.class) {
			type = BOOLEAN;
			valueClass = Boolean.class;
		}
		else if (c == ShortField.class) {
			type = SHORT;
			valueClass = Short.class;
		}
		else if (c == IntField.class) {
			type = INT;
			valueClass = Integer.class;
		}
		else if (c == LongField.class) {
			type = LONG;
			//valueClass = Long.class;
			valueClass = String.class;
		}
		else if (c == StringField.class) {
			type = STRING;
			valueClass = String.class;
		}
		else if (c == BinaryField.class) {
			type = BINARY;
			valueClass = String.class;
		}

	}

	Class<?> getValueClass() {
		return valueClass;
	}

	Object getKeyValue(Record rec) {
		switch (type) {
			case BYTE:
				return new Byte(((ByteField) rec.getKeyField()).getByteValue());
			case BOOLEAN:
				return new Boolean(((BooleanField) rec.getKeyField()).getBooleanValue());
			case SHORT:
				return new Short(((ShortField) rec.getKeyField()).getShortValue());
			case INT:
				return new Integer(((IntField) rec.getKeyField()).getIntValue());
			case LONG:
				return "0x" + Long.toHexString(rec.getKey());
			//return new Long(rec.getKey());
			case STRING:
				return ((StringField) rec.getKeyField()).getString();
			case BINARY:
				byte[] bytes = ((BinaryField) rec.getKeyField()).getBinaryData();
				StringBuffer buf = new StringBuffer("  byte[" + bytes.length + "] = ");
				if (bytes.length > 0) {
					int len = Math.min(bytes.length, 20);
					buf.append(bytes[0]);
					for (int i = 1; i < len; i++) {
						buf.append(",");
						buf.append(bytes[i]);
					}
					if (bytes.length > 20) {
						buf.append("...");
					}
				}
				return buf.toString();
		}
		return "";
	}

	Object getValue(Record rec, int col) {
		switch (type) {
			case BYTE:
				return new Byte(rec.getByteValue(col));
			case BOOLEAN:
				return Boolean.valueOf(rec.getBooleanValue(col));
			case SHORT:
				return new Short(rec.getShortValue(col));
			case INT:
				return new Integer(rec.getIntValue(col));
			case LONG:
				return "0x" + Long.toHexString(rec.getLongValue(col));
			//return new Long(rec.getLongValue(col)); 
			case STRING:
				return "  " + rec.getString(col);
			case BINARY:
				byte[] bytes = rec.getBinaryData(col);
				StringBuffer buf = new StringBuffer("  byte[" + bytes.length + "] = ");
				if (bytes.length > 0) {
					int len = Math.min(bytes.length, 20);
					String str = getByteString(bytes[0]);
					buf.append(str);
					for (int i = 1; i < len; i++) {
						buf.append(",");
						buf.append(getByteString(bytes[i]));
					}
					if (bytes.length > 20) {
						buf.append("...");
					}
				}
				return buf.toString();
		}
		return "";
	}

	private String getByteString(byte b) {
		String str = Integer.toHexString(b);
		if (str.length() > 2) {
			str = str.substring(str.length() - 2);
		}
		return "0x" + str;
	}

//	private String format(long l, int size) {
//		String hex = Long.toHexString(l);
//		if (hex.length() > size) {
//			hex = hex.substring(hex.length()-size);
//		}
//		else if (hex.length() < size) {
//			StringBuffer b = new StringBuffer(20);
//			for(int i=hex.length();i<size;i++) {
//				b.append("");
//			}
//			b.append(hex);
//			hex = b.toString();
//		}
//		
//		return hex;
//	}
}

class DbSmallTableModel implements TableModel {
	ArrayList<TableModelListener> listeners = new ArrayList<>();
	Table table;
	Schema schema;
	ColumnAdapter[] colAdapters;
	ColumnAdapter keyAdapter;
	Record[] records;

	DbSmallTableModel(Table table) {
		this.table = table;
		schema = table.getSchema();

		records = new Record[table.getRecordCount()];

		keyAdapter = new ColumnAdapter(schema.getKeyFieldClass());

		colAdapters = new ColumnAdapter[schema.getFieldCount()];
		Class<?>[] classes = schema.getFieldClasses();
		for (int i = 0; i < colAdapters.length; i++) {
			colAdapters[i] = new ColumnAdapter(classes[i]);
		}

		try {
			RecordIterator it = table.iterator();
			for (int i = 0; i < records.length; i++) {
				records[i] = it.next();
			}
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#addTableModelListener(javax.swing.event.TableModelListener)
	 */
	@Override
	public void addTableModelListener(TableModelListener l) {
		listeners.add(l);
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0) {
			return keyAdapter.getValueClass();
		}
		return colAdapters[columnIndex - 1].getValueClass();

	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return schema.getFieldCount() + 1;
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int columnIndex) {
		if (columnIndex == 0) {
			return schema.getKeyName();
		}
		--columnIndex;
		int[] indexCols = table.getIndexedColumns();
		boolean isIndexed = false;
		for (int indexCol : indexCols) {
			if (indexCol == columnIndex) {
				isIndexed = true;
				break;
			}
		}
		return schema.getFieldNames()[columnIndex] + (isIndexed ? "*" : "");
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		return table.getRecordCount();
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Record rec = records[rowIndex];
		if (columnIndex == 0) {
			return keyAdapter.getKeyValue(rec);
		}
		return colAdapters[columnIndex - 1].getValue(rec, columnIndex - 1);
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#removeTableModelListener(javax.swing.event.TableModelListener)
	 */
	@Override
	public void removeTableModelListener(TableModelListener l) {
		listeners.remove(l);

	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#setValueAt(java.lang.Object, int, int)
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
	}

}

class DbLargeTableModel implements TableModel {
	ArrayList<TableModelListener> listeners = new ArrayList<>();
	Table table;
	Schema schema;
	ColumnAdapter keyAdapter;
	ColumnAdapter[] colAdapters;
	RecordIterator recIt;
	Record lastRecord;
	int lastIndex;
	Field minKey;
	Field maxKey;
	Field keyType;

	DbLargeTableModel(Table table) {
		this.table = table;
		schema = table.getSchema();
		keyAdapter = new ColumnAdapter(schema.getKeyFieldClass());
		try {
			keyType = schema.getKeyFieldClass().newInstance();
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		try {
			recIt = table.iterator();
			lastRecord = recIt.next();
			lastIndex = 0;
			findMaxKey();
			findMinKey();
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		colAdapters = new ColumnAdapter[schema.getFieldCount()];
		Class<?>[] classes = schema.getFieldClasses();
		for (int i = 0; i < colAdapters.length; i++) {
			colAdapters[i] = new ColumnAdapter(classes[i]);
		}

	}

	private void findMinKey() throws IOException {
		RecordIterator iter = table.iterator();
		Record rec = iter.next();
		minKey = rec.getKeyField();
	}

	private void findMaxKey() throws IOException {
		Field max = keyType.newField();
		if (table.useLongKeys()) {
			max.setLongValue(Long.MAX_VALUE);
		}
		else {
			byte[] maxBytes = new byte[128];
			Arrays.fill(maxBytes, 0, 128, (byte) 0x7f);
			max.setBinaryData(maxBytes);
		}
		RecordIterator iter = table.iterator(max);
		Record rec = iter.previous();
		maxKey = rec.getKeyField();
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#addTableModelListener(javax.swing.event.TableModelListener)
	 */
	@Override
	public void addTableModelListener(TableModelListener l) {
		listeners.add(l);
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0) {
			return keyAdapter.getValueClass();
		}
		return colAdapters[columnIndex - 1].getValueClass();
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return schema.getFieldCount() + 1;
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int columnIndex) {
		if (columnIndex == 0) {
			return schema.getKeyName();
		}
		--columnIndex;
		int[] indexCols = table.getIndexedColumns();
		boolean isIndexed = false;
		for (int indexCol : indexCols) {
			if (indexCol == columnIndex) {
				isIndexed = true;
				break;
			}
		}
		return schema.getFieldNames()[columnIndex] + (isIndexed ? "*" : "");
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		return table.getRecordCount();
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Record rec = getRecord(rowIndex);
		if (rec == null) {
			return null;
		}
		if (columnIndex == 0) {
			return keyAdapter.getKeyValue(rec);
		}
		return colAdapters[columnIndex - 1].getValue(rec, columnIndex - 1);
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#removeTableModelListener(javax.swing.event.TableModelListener)
	 */
	@Override
	public void removeTableModelListener(TableModelListener l) {
		listeners.remove(l);

	}

	/* (non-Javadoc)
	 * @see javax.swing.table.TableModel#setValueAt(java.lang.Object, int, int)
	 */
	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
	}

	private Record getRecord(int index) {
		try {
			if (index == lastIndex + 1) {
				if (!recIt.hasNext()) {
					// do something
				}
				lastRecord = recIt.next();
				lastIndex = index;
			}
			else if (index != lastIndex) {
				if (index < lastIndex && (lastIndex - index) < 200) {
					int backup = lastIndex - index + 1;
					for (int i = 0; i < backup; i++) {
						if (recIt.hasPrevious()) {
							recIt.previous();
						}
					}
					lastRecord = recIt.next();
					lastIndex = index;
				}
				else {
					findRecord(index);
					lastRecord = recIt.next();
					lastIndex = index;
				}
			}
		}
		catch (IOException e) {
			// XXX Auto-generated catch block
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		return lastRecord;
	}

	private void findRecord(int index) throws IOException {
		if (index < 1000) {
			recIt = table.iterator();
			for (int i = 0; i < index; i++) {
				recIt.next();
			}
		}
		else if (index > table.getRecordCount() - 1000) {
			recIt = table.iterator(maxKey);
			if (recIt.hasNext()) {
				recIt.next();
			}
			for (int i = 0; i < table.getRecordCount() - index; i++) {
				recIt.previous();
			}
		}
		else {
			recIt = table.iterator(approxKey(index));
		}
	}

	private Field approxKey(int index) {
		Field key = keyType.newField();
		if (table.useLongKeys()) {
			long min = minKey.getLongValue();
			long max = maxKey.getLongValue();
			long k = min + ((max - min) * index / table.getRecordCount());
			key.setLongValue(k);
		}
		else {
			long min = getLong(minKey.getBinaryData());
			long max = getLong(maxKey.getBinaryData());
			long k = min + ((max - min) * index / table.getRecordCount());
			byte[] bytes = new byte[8];
			for (int i = 7; i >= 0; i--) {
				bytes[i] = (byte) k;
				k >>= 8;
			}
			key.setBinaryData(bytes);
		}
		return key;
	}

	private long getLong(byte[] bytes) {
		if (bytes == null || bytes.length == 0) {
			return 0;
		}
		long value = 0;
		for (int i = 0; i < 8; i++) {
			value <<= 8;
			if (i < bytes.length) {
				value += bytes[i] & 0xff;
			}
		}
		return value;
	}
}
