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

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import db.*;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.AddressSet;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class VTMatchSetTableDBAdapter {

	public enum ColumnDescription {
		CORRELATOR_CLASS_COL(StringField.INSTANCE),
		CORRELATOR_NAME_COL(StringField.INSTANCE),
		OPTIONS_COL(StringField.INSTANCE);

		private final Field columnField;

		private ColumnDescription(Field columnField) {
			this.columnField = columnField;

		}

		public Field getColumnField() {
			return columnField;
		}

		public int column() {
			return ordinal();
		}

		private static String[] getColumnNames() {
			ColumnDescription[] columns = ColumnDescription.values();
			List<String> list = new LinkedList<String>();
			for (ColumnDescription column : columns) {
				list.add(column.name());
			}
			return list.toArray(new String[columns.length]);
		}

		private static Field[] getColumnFields() {
			ColumnDescription[] columns = ColumnDescription.values();
			Field[] fields = new Field[columns.length];
			for (int i = 0; i < fields.length; i++) {
				fields[i] = columns[i].getColumnField();
			}
			return fields;
		}
	}

	static String TABLE_NAME = "MatchSetTable";
	static Schema TABLE_SCHEMA = new Schema(0, "Key", ColumnDescription.getColumnFields(),
		ColumnDescription.getColumnNames());

	static VTMatchSetTableDBAdapter createAdapter(DBHandle dbHandle) throws IOException {
		return new VTMatchSetTableDBAdapterV0(dbHandle);
	}

	static VTMatchSetTableDBAdapter getAdapter(DBHandle dbHandle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new VTMatchSetTableDBAdapterV0(dbHandle, openMode);
	}

	public abstract DBRecord createMatchSetRecord(long key, VTProgramCorrelator correlator)
			throws IOException;

	public abstract RecordIterator getRecords() throws IOException;

	public abstract AddressSet getSourceAddressSet(DBRecord record, AddressMap addressMap)
			throws IOException;

	public abstract AddressSet getDestinationAddressSet(DBRecord record, AddressMap addressMap)
			throws IOException;

	public abstract long getNextMatchSetID();

	public abstract DBRecord getRecord(long key) throws IOException;
}
