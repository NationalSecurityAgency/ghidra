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
package ghidra.feature.vt.api.db;

import java.util.*;

import db.Field;
import ghidra.util.Msg;

public class TableDescriptor {

	private TableColumn[] columns;

	protected TableDescriptor() {
		this.columns = discoverTableColumns();
	}

	private TableColumn[] discoverTableColumns() {

		Class<? extends TableDescriptor> clazz = getClass();
		java.lang.reflect.Field[] fields = clazz.getFields();
		List<TableColumn> list = new ArrayList<TableColumn>(fields.length);
		for (java.lang.reflect.Field field : fields) {
			Class<?> type = field.getType();
			if (!TableColumn.class.isAssignableFrom(type)) {
				continue;
			}

			try {
				TableColumn column = (TableColumn) field.get(null);
				column.setName(field.getName());
				column.setOrdinal(list.size());
				list.add(column);
			}
			catch (IllegalArgumentException e) {
				// shouldn't happen
			}
			catch (IllegalAccessException e) {
				Msg.showError(this, null, "Class Usage Error",
					"You must provide public " + "static members for your TableColumns");
			}

		}

		return list.toArray(new TableColumn[list.size()]);
	}

	public int[] getIndexedColumns() {
		int count = 0;
		for (TableColumn column : columns) {
			if (column.isIndexed()) {
				count++;
			}
		}
		int[] indexedColumns = new int[count];
		count = 0;
		for (TableColumn column : columns) {
			if (column.isIndexed()) {
				indexedColumns[count++] = column.column();
			}
		}
		return indexedColumns;
	}

	public String[] getColumnNames() {
		List<String> list = new LinkedList<String>();
		for (TableColumn column : columns) {
			list.add(column.name());
		}
		return list.toArray(new String[columns.length]);
	}

	public Field[] getColumnFields() {
		Field[] fields = new Field[columns.length];
		for (int i = 0; i < fields.length; i++) {
			fields[i] = columns[i].getColumnField().newField();
		}
		return fields;
	}

}
