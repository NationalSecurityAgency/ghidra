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

import db.DBRecord;
import docking.widgets.table.AbstractDynamicTableColumnStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;

abstract class AbstractColumnAdapter extends AbstractDynamicTableColumnStub<DBRecord, Object> {

	protected LongRenderer longRenderer = new LongRenderer();

	protected int column;
	private String columnName;

	AbstractColumnAdapter(String columnName, int column) {
		this.column = column;
		this.columnName = columnName;
	}

	@Override
	public Object getValue(DBRecord rowObject, Settings settings, ServiceProvider serviceProvider)
			throws IllegalArgumentException {

		if (column == 0) {
			return getKeyValue(rowObject);
		}

		// -1, since the DB indices do not have the key column included
		int dbColumn = column - 1;
		return getValue(rowObject, dbColumn);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Class<Object> getColumnClass() {
		return (Class<Object>) getValueClass();
	}

	@Override
	public String getColumnName() {
		return columnName;
	}

	abstract Class<?> getValueClass();

	abstract Object getKeyValue(DBRecord rec);

	abstract Object getValue(DBRecord rec, int dbColumn);

	protected String getByteString(byte b) {
		String str = Integer.toHexString(b);
		if (str.length() > 2) {
			str = str.substring(str.length() - 2);
		}
		return "0x" + str;
	}

}
