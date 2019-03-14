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
package ghidra.framework.main.logviewer.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.table.AbstractTableModel;

import org.apache.logging.log4j.Level;

/**
 * The model that backs the {@link FVTable} table. This model defines 4 columns: date,
 * time, log level, and the message.
 *
 */
public class FVTableModel extends AbstractTableModel {

	// Column indices
	public static final int DATE_COL = 0;
	public static final int TIME_COL = 1;
	public static final int LEVEL_COL = 2;
	public static final int MESSAGE_COL = 3;

	// Regex matching a date pattern of the form XXXX-XX-XX. All dates in our logs follow this format. 
	// Note:	We could get more complicated and restrict digits based on actual month/day
	//        	values, but that's really not necessary.
	private static final Pattern dateRegex =
		Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
	
	private static final String spaceRegex = "\\s+";

	// Regex matching a time pattern of the form HH:MM:SS. The hour component will match
	// a 24-hour clock, while the minutes and seconds restrict digits as you'd
	// expect.
	private static final Pattern timeRegex =
		Pattern.compile("(?:[01]\\d|2[0123]):(?:[012345]\\d):(?:[012345]\\d(,\\d\\d\\d)?)");

	// Regex matching any of the log levels defined by log4j. 
	//@formatter:off
	private static final Pattern levelRegex = Pattern.compile(
			spaceRegex + Level.OFF + spaceRegex + "|" + 
			spaceRegex + Level.DEBUG.toString() + spaceRegex + "|" +
			spaceRegex + Level.TRACE.toString() + spaceRegex + "|" +
			spaceRegex + Level.WARN.toString() + spaceRegex + "|" + 
			spaceRegex + Level.INFO.toString() + spaceRegex + "|" +
			spaceRegex + Level.ERROR.toString() + spaceRegex + "|" + 
			spaceRegex + Level.FATAL.toString() + spaceRegex);
	//@formatter:on

	// Holds all data to be displayed in the table. These lists should always contain the
	// same number of entries.
	private List<String> dates = new ArrayList<>();
	private List<String> times = new ArrayList<>();
	private List<String> levels = new ArrayList<>();
	private List<String> messages = new ArrayList<>();

	@Override
	public int getRowCount() {
		return messages.size();
	}

	@Override
	public int getColumnCount() {
		return 4;
	}

	@Override
	public String getColumnName(int column) {

		switch (column) {
			case DATE_COL:
				return "Date";
			case TIME_COL:
				return "Time";
			case LEVEL_COL:
				return "Level";
			case MESSAGE_COL:
				return "Message";
		}

		return "unknown";
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex < 0 || rowIndex >= messages.size()) {
			return null;
		}

		switch (columnIndex) {
			case DATE_COL:
				return dates.get(rowIndex);
			case TIME_COL:
				return times.get(rowIndex);
			case LEVEL_COL:
				return levels.get(rowIndex);
			case MESSAGE_COL:
				return messages.get(rowIndex);
		}

		return null;
	}

	/**
	 * Adds a row to the model.
	 * 
	 * @param row the data to add
	 * @param notify if true, a notification will be sent to subscribers
	 */
	public void addRow(String row, boolean notify) {
		addRow(row, messages.size(), notify);
	}

	/**
	 * Adds a row to the model
	 * 
	 * @param row the data to add
	 * @param index the position within the model to add this to
	 * @param notify if true, a notification will be sent to subscribers
	 */
	public void addRow(String row, int index, boolean notify) {

		String date = getDate(row);
		dates.add(index, date);
		row = row.replaceFirst(date, "");

		String time = getTime(row);
		times.add(index, time);
		row = row.replaceFirst(time, "");

		String level = getLevel(row);
		levels.add(index, level);
		row = row.replaceFirst(level, "");

		messages.add(index, row.trim());

		if (notify) {
			fireTableRowsInserted(messages.size() - 1, messages.size() - 1);
		}
	}

	/**
	 * Adds a list of rows to the model and fires off a notification.
	 * 
	 * @param rows
	 */
	public void addRowsToTop(List<String> rows) {
		for (int i = 0; i < rows.size(); i++) {
			addRow(rows.get(i), i, false);
		}

		fireTableDataChanged();
	}

	/**
	 * Adds a list of rows to the model and fires off a notification.
	 * 
	 * @param rows
	 */
	public void addRowsToBottom(List<String> rows) {
		for (String row : rows) {
			addRow(row, false);
		}
		fireTableDataChanged();
	}

	/**
	 * Removes a set of rows from the bottom of the view.
	 * 
	 * @param count the number of rows to remove
	 */
	public void removeRowsFromBottom(int count) {
		for (int i = 0; i < count; i++) {
			levels.remove(levels.size() - 1);
			dates.remove(dates.size() - 1);
			messages.remove(messages.size() - 1);
			times.remove(times.size() - 1);
		}
		fireTableDataChanged();
	}

	/**
	 * Removes a set of rows from the top of the view.
	 * 
	 * @param count the number of rows to remove
	 */
	public void removeRowsFromTop(int count) {
		for (int i = 0; i < count; i++) {
			if (!messages.isEmpty()) {
				messages.remove(0);
				dates.remove(0);
				levels.remove(0);
				times.remove(0);
			}
		}
		fireTableDataChanged();
	}

	/**
	 * Clears all lines from the model and fires off a notification.
	 */
	public void clear() {
		dates.clear();
		levels.clear();
		messages.clear();
		times.clear();
		fireTableDataChanged();
	}

	/**
	 * Returns the date portion of the given string.
	 * 
	 * @param row the row data
	 * @return the date, or empty string if not present
	 */
	private String getDate(String row) {
		Matcher m = dateRegex.matcher(row);
		return m.find() ? m.group() : "";
	}

	/**
	 * Returns the log level portion of the given string.
	 * 
	 * @param row the row data
	 * @return the log level, or empty string if not present
	 */
	private String getLevel(String row) {
		Matcher m = levelRegex.matcher(row);
		return m.find() ? m.group().trim() : "";
	}

	/**
	 * Returns the time portion of the given string.
	 * 
	 * @param row the row data
	 * @return the time, or empty string if not present
	 */
	private String getTime(String row) {
		Matcher m = timeRegex.matcher(row);
		return m.find() ? m.group() : "";
	}
}
