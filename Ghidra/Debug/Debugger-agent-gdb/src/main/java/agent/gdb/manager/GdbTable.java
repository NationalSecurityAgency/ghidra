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
package agent.gdb.manager;

import java.util.*;
import java.util.Map.Entry;

import agent.gdb.manager.parsing.GdbMiParser.GdbMiFieldList;
import ghidra.util.Msg;

/**
 * A parsed table output from a GDB/MI command
 * 
 * GDB provides many equivalent GDB/MI commands for CLI commands that output formatted tables of
 * information. The GDB/MI format can be a little obtuse to traverse, but at least it is relatively
 * well structured. This object provides two views of the table: as rows and columns. Generally, a
 * table has column headings and entries. Viewed as rows, it is a collection of entries where each
 * entry is a map of column head to cell value. Viewed as columns, it is a map of column head to
 * column where each column is a collection of cells.
 */
public class GdbTable {
	/*
	 * Piece for parsing the table data
	 */
	private static class Column {
		final int num;
		final String name;
		final String head;

		Column(int num, String name, String head) {
			this.num = num;
			this.name = name;
			this.head = head;
		}

		Column(int num, GdbMiFieldList map) {
			this(num, map.getString("col_name"), map.getString("colhdr"));
		}
	}

	/*
	 * Implementation of the row-oriented view
	 * 
	 * view is a list of maps: TableRowView
	 * 
	 * each item is a map: TableRowCellMap
	 * 
	 * each map has an entry set, a set of head-cell pairs: TableRowCellSet
	 * 
	 * each entry set must be iterable, an iterator of head-cell pairs: TableRowCellIterator
	 * 
	 * each iterator traverses the head-cell pairs: TableRowCellEntry
	 * 
	 * The other methods are implemented by the abstract base classes provided by Java's
	 * collections.
	 */

	private class TableRowCellEntry implements Entry<String, String> {
		@Override
		public String getKey() {
			return columns[colIndex].head;
		}

		@Override
		public String getValue() {
			return cells[rowIndex * colCount + colIndex];
		}

		@Override
		public String setValue(String value) {
			throw new UnsupportedOperationException();
		}
	}

	private class TableRowCellIterator implements Iterator<Entry<String, String>> {
		@Override
		public boolean hasNext() {
			return colIndex < colCount - 1;
		}

		@Override
		public Entry<String, String> next() {
			colIndex++;
			return rowCellEntry;
		}
	}

	private class TableRowCellSet extends AbstractSet<Entry<String, String>> {
		@Override
		public Iterator<Entry<String, String>> iterator() {
			colIndex = -1;
			return rowCellIterator;
		}

		@Override
		public int size() {
			return colCount;
		}
	}

	private class TableRowCellMap extends AbstractMap<String, String> {
		@Override
		public int size() {
			return colCount;
		}

		@Override
		public boolean containsKey(Object key) {
			return colsByHead.containsKey(key);
		}

		@Override
		public String get(Object key) {
			Column col = colsByHead.get(key);
			if (col == null) {
				return null;
			}
			return cells[rowIndex * colCount + col.num];
		}

		@Override
		public Set<Entry<String, String>> entrySet() {
			return rowCellSet;
		}
	}

	public class TableRowView extends AbstractList<Map<String, String>> {
		@Override
		public Map<String, String> get(int index) {
			if (0 <= index && index < rowCount) {
				rowIndex = index;
				return rowCellMap;
			}
			throw new IndexOutOfBoundsException(Integer.toString(index));
		}

		@Override
		public int size() {
			return rowCount;
		}
	}

	/*
	 * Implementation of the column-oriented view
	 * 
	 * view is a map of lists: TableColumnView
	 * 
	 * the map has an entry set, a set of head-list pairs: TableColumnSet
	 * 
	 * the set must be iteratable, an iterator of head-list pairs: TableColumnIterator
	 * 
	 * the iterator traverses head-list pairs: TableColumnEntry
	 * 
	 * each list is a list of cells: TableColumnCellList
	 * 
	 * The other methods are implemented by the abstract base classes provided by Java's
	 * collections.
	 */

	private class TableColumnCellList extends AbstractList<String> {
		@Override
		public String get(int index) {
			return cells[index * colCount + colIndex];
		}

		@Override
		public int size() {
			return rowCount;
		}
	}

	private class TableColumnEntry implements Entry<String, List<String>> {
		@Override
		public String getKey() {
			return columns[colIndex].head;
		}

		@Override
		public List<String> getValue() {
			return columnCellList;
		}

		@Override
		public List<String> setValue(List<String> value) {
			throw new UnsupportedOperationException();
		}
	}

	private class TableColumnIterator implements Iterator<Entry<String, List<String>>> {
		@Override
		public boolean hasNext() {
			return colIndex < colCount - 1;
		}

		@Override
		public Entry<String, List<String>> next() {
			colIndex++;
			return columnEntry;
		}
	}

	private class TableColumnSet extends AbstractSet<Entry<String, List<String>>> {
		@Override
		public Iterator<Entry<String, List<String>>> iterator() {
			colIndex = -1;
			return columnIterator;
		}

		@Override
		public int size() {
			return colCount;
		}
	}

	public class TableColumnView extends AbstractMap<String, List<String>> {
		@Override
		public Set<Entry<String, List<String>>> entrySet() {
			return columnSet;
		}
	}

	/*
	 * Table class definition
	 */

	private final int rowCount;
	private final int colCount;
	private final String[] cells;
	private final Column[] columns;
	private final Map<String, Column> colsByHead;
	//private final Map<String, Column> colsByName = new HashMap<>();

	private int rowIndex = -1;
	private int colIndex = -1;

	private final TableRowView rowView = new TableRowView();
	private final TableRowCellMap rowCellMap = new TableRowCellMap();
	private final TableRowCellSet rowCellSet = new TableRowCellSet();
	private final TableRowCellIterator rowCellIterator = new TableRowCellIterator();
	private final TableRowCellEntry rowCellEntry = new TableRowCellEntry();

	private final TableColumnView columnView = new TableColumnView();
	private final TableColumnSet columnSet = new TableColumnSet();
	private final TableColumnIterator columnIterator = new TableColumnIterator();
	private final TableColumnEntry columnEntry = new TableColumnEntry();
	private final TableColumnCellList columnCellList = new TableColumnCellList();

	/**
	 * Convert a parsed GDB/MI structure into a table
	 * 
	 * See GDB's GDB/MI documentation for any command yielding a table for more information on the
	 * expected structure of GDB/MI table data.
	 * 
	 * @param dataMap the parsed structure
	 * @param rowKey the key assigned to each row
	 */
	public GdbTable(GdbMiFieldList dataMap, String rowKey) {
		rowCount = Integer.parseInt(dataMap.getString("nr_rows"));
		colCount = Integer.parseInt(dataMap.getString("nr_cols"));
		cells = new String[rowCount * colCount];
		columns = new Column[colCount];

		List<GdbMiFieldList> hdr = dataMap.getListOf(GdbMiFieldList.class, "hdr");
		if (hdr.size() != colCount) {
			Msg.warn(this, "hdr contains fewer than nr_cols");
		}
		Map<String, Column> byHead = new LinkedHashMap<>();
		for (int colno = 0; colno < colCount; colno++) {
			Column column = new Column(colno, hdr.get(colno));
			columns[colno] = column;
			//colsByName.put(column.name, column);
			byHead.put(column.head, column);
		}
		this.colsByHead = Collections.unmodifiableMap(byHead);

		@SuppressWarnings({ "unchecked", "rawtypes" })
		Collection<GdbMiFieldList> body = (Collection) dataMap.getFieldList("body").get(rowKey);
		if (body.size() != rowCount) {
			Msg.warn(this, "body contains fewer than nr_rows");
		}
		int rowno = 0;
		for (GdbMiFieldList row : body) {
			for (Column column : columns) {
				cells[colCount * rowno + column.num] = row.getString(column.name);
			}
			rowno++;
		}
	}

	/**
	 * Get the table as rows: a list of head-to-cell maps
	 * 
	 * @return the row view
	 */
	public TableRowView rows() {
		return rowView;
	}

	/**
	 * Get the table as columns: a head-to-cell-list map
	 * 
	 * @return the column view
	 */
	public TableColumnView columns() {
		return columnView;
	}
}
