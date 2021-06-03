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

import java.awt.Component;
import java.awt.Container;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.JTextComponent;

import docking.DockingWindowManager;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.task.*;

public final class GTableToCSV {
	final static String TITLE = "Export to CSV";

	public final static void writeCSV(File file, GTable table) {
		ConvertTask task = new ConvertTask(file, table);
		new TaskLauncher(task, table, 0);
	}

	public final static void writeCSVUsingColunns(File file, GTable table,
			List<Integer> selectedColumns) {
		ConvertTask task = new ConvertTask(file, table, selectedColumns);
		new TaskLauncher(task, table, 0);
	}

	final static void writeCSV(File file, GTable table,
			List<Integer> columns, TaskMonitor monitor) throws IOException {

		PrintWriter writer = new PrintWriter(file);
		writeCSV(writer, table, columns, monitor);
	}

	final static void writeCSV(PrintWriter writer, GTable table,
			List<Integer> columns, TaskMonitor monitor) {

		List<TableColumn> tableColumns = null;
		if (columns.isEmpty()) {
			tableColumns = getVisibleColumnsInOrder(table, monitor);
		}
		else {
			tableColumns = getTableColumnsByIndex(table, columns);
		}

		TableModel model = table.getModel();
		try {
			writeColumnNames(writer, tableColumns, model, monitor);
			writeNewLine(writer);
			writeModel(writer, table, tableColumns, model, monitor);
		}
		finally {
			writer.close();
		}
	}

	private static List<TableColumn> getVisibleColumnsInOrder(JTable table, TaskMonitor monitor) {

		TableColumnModel columnModel = table.getColumnModel();
		List<TableColumn> columns = new ArrayList<TableColumn>();
		for (int columnIndex = 0; columnIndex < table.getColumnCount(); ++columnIndex) {
			if (monitor.isCancelled()) {
				break;
			}
			TableColumn column = columnModel.getColumn(columnIndex);
			columns.add(column);
		}
		return columns;
	}

	private static List<TableColumn> getTableColumnsByIndex(JTable table,
			List<Integer> columnIndices) {

		TableColumnModel columnModel = table.getColumnModel();
		List<TableColumn> columns = new ArrayList<TableColumn>();
		for (Integer index : columnIndices) {
			TableColumn column = columnModel.getColumn(index);
			columns.add(column);
		}
		return columns;
	}

	private static void writeModel(PrintWriter writer, final GTable table,
			List<TableColumn> tableColumns, final TableModel model, TaskMonitor monitor) {

		int[] selectedRows = table.getSelectedRows();
		if (selectedRows.length == 0) {
			// if we are filtered, then this will only get the filtered data
			writeAllModelData(writer, table, model, monitor);
			return;
		}

		monitor.setMessage("Writing model...");
		monitor.initialize(selectedRows.length);

		int columnCount = tableColumns.size();
		for (int i = 0; i < selectedRows.length; ++i) {
			if (monitor.isCancelled()) {
				break;
			}

			monitor.setProgress(i);
			for (int j = 0; j < columnCount; j++) {
				if (monitor.isCancelled()) {
					break;
				}

				TableColumn tableColumn = tableColumns.get(j);
				int column = table.convertColumnIndexToView(tableColumn.getModelIndex());
				int row = getModelRow(selectedRows[i], model);
				row = selectedRows[i];
				String value = getColumnValue(table, model, row, column);
				if (value == null) {
					// not sure how this could happen...has the model changed out from under us?
					value = "";
				}

				value = HTMLUtilities.fromHTML(value);
				writeField(writer, value, monitor);
				if (j < columnCount - 1) {
					writeFieldSeparator(writer);
				}
			}
			writeNewLine(writer);
		}
	}

	private static String getColumnValue(final JTable table, final TableModel model, final int row,
			final int column) {
		final String[] result = new String[1];
		try {
			SwingUtilities
					.invokeAndWait(() -> result[0] = getTableCellValue(table, model, row, column));
		}
		catch (InterruptedException e) {
			return null;
		}
		catch (InvocationTargetException e) {
			return null;
		}

		return result[0];
	}

	/**
	 * Attempts to get the text value for the cell so that the data will match what the user sees. 
	 */
	private static String getTableCellValue(JTable table, TableModel model, int row, int column) {
		TableCellRenderer renderer = table.getCellRenderer(row, column);
		TableColumnModel columnModel = table.getColumnModel();
		TableColumn tableColumn = columnModel.getColumn(column);
		int modelIndex = tableColumn.getModelIndex();
		Object value = model.getValueAt(row, modelIndex);
		Component component =
			renderer.getTableCellRendererComponent(table, value, false, false, row, column);

		if (component instanceof JLabel) {
			JLabel label = (JLabel) component;
			return getTextForLabel(label);
		}

		String text = lookForTextInsideOfComponent(component);
		if (text != null) {
			return text;
		}

		return value == null ? "" : value.toString();
	}

	private static String getTextForLabel(JLabel label) {
		String text = label.getText();
		if (text != null) {
			return text;
		}

		Icon icon = label.getIcon();
		if (icon == null) {
			return null;
		}
		if (icon instanceof ImageIcon) {
			return ((ImageIcon) icon).getDescription();
		}

		return null;
	}

	private static String lookForTextInsideOfComponent(Component component) {
		if (!(component instanceof Container)) {
			return null;
		}
		Container container = (Container) component;
		Component[] components = container.getComponents();
		for (Component child : components) {
			if (child instanceof JLabel) {
				// check for a label with text (one without text could be used for an icon)
				JLabel label = (JLabel) child;
				String text = label.getText();
				if (text != null) {
					return text;
				}
			}
			else if (child instanceof JTextComponent) {
				// surely this is for displaying text
				JTextComponent textComponent = (JTextComponent) child;
				return textComponent.getText();
			}
		}

		return null;
	}

	private static int getModelRow(int viewRow, TableModel model) {
		if (model instanceof RowObjectFilterModel<?>) {
			RowObjectFilterModel<?> threadedModel = (RowObjectFilterModel<?>) model;
			return threadedModel.getModelRow(viewRow);
		}
		else if (model instanceof TableModelWrapper) {
			TableModelWrapper<?> wrapper = (TableModelWrapper<?>) model;
			return wrapper.getModelRow(viewRow);
		}
		return viewRow; // assume no filtering, as we don't know how to handle it anyway
	}

	private static void writeAllModelData(PrintWriter writer, JTable table, TableModel model,
			TaskMonitor monitor) {

		monitor.setMessage("Writing model...");
		monitor.initialize(model.getRowCount());

		int columnCount = table.getColumnCount();
		for (int row = 0; row < model.getRowCount(); ++row) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(row);
			for (int col = 0; col < columnCount; col++) {
				if (monitor.isCancelled()) {
					break;
				}

				String value = getColumnValue(table, model, row, col);
				if (value == null) {
					// not sure how this could happen...has the model changed out from under us?
					value = "";
				}

				writeField(writer, value, monitor);
				if (col < columnCount - 1) {
					writeFieldSeparator(writer);
				}
			}
			writeNewLine(writer);
		}
	}

	private static void writeColumnNames(PrintWriter writer, List<TableColumn> columns,
			TableModel model, TaskMonitor monitor) {

		monitor.setMessage("Writing columns...");
		monitor.initialize(columns.size());

		for (int i = 0; i < columns.size(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setProgress(i);

			TableColumn column = columns.get(i);
			int modelIndex = column.getModelIndex();
			writeField(writer, model.getColumnName(modelIndex), monitor);
			if (i < columns.size() - 1) {
				writeFieldSeparator(writer);
			}
		}
	}

	private static void writeNewLine(PrintWriter writer) {
		writer.print('\n');
	}

	private static void writeFieldSeparator(PrintWriter writer) {
		writer.print(',');
	}

	/**
	 * Write the given field value into the file specified by the writer.
	 * All fields will be enclosed in double-quotes. Also, all embedded
	 * double-quotes will be escaped.
	 * <p>
	 * Note: when importing into Excel, the quotes are stripped off.
	 */
	private final static void writeField(PrintWriter writer, String fieldValue,
			TaskMonitor monitor) {
		writer.print("\"");
		for (int i = 0; i < fieldValue.length(); ++i) {
			if (monitor.isCancelled()) {
				break;
			}

			if (fieldValue.charAt(i) == '"') {//embedded separator
				writer.print("\\\"");
			}
			else if (fieldValue.charAt(i) == ',') {
				writer.print("\\,");
			}
			else {
				writer.print(fieldValue.charAt(i));
			}
		}
		writer.print("\"");
	}

	private static class ConvertTask extends Task {
		private final GTable table;

		private File file;
		private List<Integer> columns = new ArrayList<Integer>();

		ConvertTask(File file, GTable table) {
			super(GTableToCSV.TITLE, true, true, true);
			this.file = file;
			this.table = table;
		}

		ConvertTask(File file, GTable table, List<Integer> columns) {
			super(GTableToCSV.TITLE, true, true, true);
			this.file = file;
			this.table = table;
			this.columns = columns;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				GTableToCSV.writeCSV(file, table, columns, monitor);
			}
			catch (IOException e) {
				Msg.error(GTableToCSV.class.getName(), e.getMessage());
			}

			DockingWindowManager manager = DockingWindowManager.getInstance(table);
			if (manager != null) { // can happen during testing
				manager.setStatusText("Finished writing CSV data");
			}
		}
	}
}
