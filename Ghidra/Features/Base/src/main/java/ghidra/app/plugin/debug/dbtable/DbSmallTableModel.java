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

import db.*;
import docking.widgets.table.TableColumnDescriptor;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DbSmallTableModel extends ThreadedTableModel<DBRecord, Object> {
	private Table table;
	private Schema schema;

	public DbSmallTableModel(ServiceProvider serviceProvider, Table table) {
		super("DB Records Model", serviceProvider);
		this.table = table;
		schema = table.getSchema();

		reloadColumns(); // we must do this after 'schema' has been set
	}

	@Override
	protected void doLoad(Accumulator<DBRecord> accumulator, TaskMonitor monitor)
			throws CancelledException {

		monitor.initialize(table.getRecordCount());

		try {
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				monitor.checkCancelled();
				accumulator.add(it.next());
			}
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private AbstractColumnAdapter getColumn(Field field, int column) {

		String columnName = loadColumnName(column);
		if (field instanceof ByteField) {
			return new ByteColumnAdapter(columnName, column);
		}
		else if (field instanceof BooleanField) {
			return new BooleanColumnAdapter(columnName, column);
		}
		else if (field instanceof ShortField) {
			return new ShortColumnAdapter(columnName, column);
		}
		else if (field instanceof IntField) {
			return new IntegerColumnAdapter(columnName, column);
		}
		else if (field instanceof LongField) {
			return new LongColumnAdapter(columnName, column);
		}
		else if (field instanceof StringField) {
			return new StringColumnAdapter(columnName, column);
		}
		else if (field instanceof BinaryField) {
			return new BinaryColumnAdapter(columnName, column);
		}
		throw new AssertException(
			"New, unexpected DB column type: " + field.getClass().getSimpleName());
	}

	private String loadColumnName(int columnIndex) {
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
	protected TableColumnDescriptor<DBRecord> createTableColumnDescriptor() {

		TableColumnDescriptor<DBRecord> descriptor = new TableColumnDescriptor<>();
		if (schema == null) {
			return descriptor;
		}

		// 0 is the key
		descriptor.addVisibleColumn(getColumn(schema.getKeyFieldType(), 0));

		Field[] fields = schema.getFields();
		int offset = 1;
		for (Field field : fields) {
			descriptor.addVisibleColumn(getColumn(field, offset++));
		}

		return descriptor;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public Object getDataSource() {
		return null;
	}
}
