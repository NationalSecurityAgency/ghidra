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

public class DbSmallTableModel extends AbstractSortedTableModel<DBRecord> {
	private Table table;
	private Schema schema;
	private List<AbstractColumnAdapter> columns = new ArrayList<>();
	private List<DBRecord> records;

	public DbSmallTableModel(Table table) {
		this.table = table;
		schema = table.getSchema();

		records = new ArrayList<>(table.getRecordCount());

		columns.add(getColumn(schema.getKeyFieldType()));

		Field[] fields = schema.getFields();
		for (Field field : fields) {
			columns.add(getColumn(field));
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

	private AbstractColumnAdapter getColumn(Field field) {
		if (field instanceof ByteField) {
			return new ByteColumnAdapter();
		}
		else if (field instanceof BooleanField) {
			return new BooleanColumnAdapter();
		}
		else if (field instanceof ShortField) {
			return new ShortColumnAdapter();
		}
		else if (field instanceof IntField) {
			return new IntegerColumnAdapter();
		}
		else if (field instanceof LongField) {
			return new LongColumnAdapter();
		}
		else if (field instanceof StringField) {
			return new StringColumnAdapter();
		}
		else if (field instanceof BinaryField) {
			return new BinaryColumnAdapter();
		}
		throw new AssertException(
			"New, unexpected DB column type: " + field.getClass().getSimpleName());
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
	public Object getColumnValueForRow(DBRecord rec, int columnIndex) {
		if (columnIndex == 0) { // key column
			return columns.get(columnIndex).getKeyValue(rec);
		}

		int dbColumn = columnIndex - 1; // -1, since the DB indices do not have the key column included
		return columns.get(columnIndex).getValue(rec, dbColumn);
	}

	@Override
	public List<DBRecord> getModelData() {
		return records;
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}
}
