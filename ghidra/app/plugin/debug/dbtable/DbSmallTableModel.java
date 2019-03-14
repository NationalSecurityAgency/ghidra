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
package ghidra.app.plugin.debug.dbtable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.*;
import docking.widgets.table.AbstractSortedTableModel;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

public class DbSmallTableModel extends AbstractSortedTableModel<Record> {
	private Table table;
	private Schema schema;
	private List<AbstractColumnAdapter> columns = new ArrayList<>();
	private List<Record> records;

	public DbSmallTableModel(Table table) {
		this.table = table;
		schema = table.getSchema();

		records = new ArrayList<>(table.getRecordCount());

		columns.add(getColumn(schema.getKeyFieldClass()));

		Class<?>[] classes = schema.getFieldClasses();
		int fieldCount = schema.getFieldCount();
		for (int i = 0; i < fieldCount; i++) {
			columns.add(getColumn(classes[i]));
		}

		try {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				records.add(it.next());
			}
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private AbstractColumnAdapter getColumn(Class<?> c) {
		if (c == ByteField.class) {
			return new ByteColumnAdapter();
		}
		else if (c == BooleanField.class) {
			return new BooleanColumnAdapter();
		}
		else if (c == ShortField.class) {
			return new ShortColumnAdapter();
		}
		else if (c == IntField.class) {
			return new IntegerColumnAdapter();
		}
		else if (c == LongField.class) {
			return new LongColumnAdapter();
		}
		else if (c == StringField.class) {
			return new StringColumnAdapter();
		}
		else if (c == BinaryField.class) {
			return new BinaryColumnAdapter();
		}
		throw new AssertException("New, unexpected DB column class type: " + c);
	}

	@Override
	public String getName() {
		return "DB Small Table";
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getValueClass();

	}

	@Override
	public int getColumnCount() {
		return schema.getFieldCount() + 1;
	}

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

	@Override
	public int getRowCount() {
		return table.getRecordCount();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public Object getColumnValueForRow(Record rec, int columnIndex) {
		if (columnIndex == 0) { // key column
			return columns.get(columnIndex).getKeyValue(rec);
		}

		int dbColumn = columnIndex - 1; // -1, since the DB indices do not have the key column included
		return columns.get(columnIndex).getValue(rec, dbColumn);
	}

	@Override
	public List<Record> getModelData() {
		return records;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}
}
