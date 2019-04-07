/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import db.*;

/**
 * Abstract adapter for the database table that holds tags for version tracking matches.
 */
public abstract class VTMatchTagDBAdapter {

	public enum ColumnDescription {
		TAG_NAME_COL(StringField.class);

		private final Class<? extends Field> columnClass;

		private ColumnDescription(Class<? extends Field> columnClass) {
			this.columnClass = columnClass;
		}

		public Class<? extends Field> getColumnClass() {
			return columnClass;
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

		@SuppressWarnings("unchecked")
		// we know our class types are safe
		private static Class<? extends Field>[] getColumnClasses() {
			ColumnDescription[] columns = ColumnDescription.values();
			List<Class<? extends Field>> list = new LinkedList<Class<? extends Field>>();
			for (ColumnDescription column : columns) {
				list.add(column.getColumnClass());
			}
			return list.toArray(new Class[columns.length]);
		}
	}

	static String TABLE_NAME = "MatchTagTable";
	static Schema TABLE_SCHEMA =
		new Schema(0, LongField.class, "Key", ColumnDescription.getColumnClasses(),
			ColumnDescription.getColumnNames());

	static VTMatchTagDBAdapter createAdapter(DBHandle dbHandle) throws IOException {
		return new VTMatchTagDBAdapterV0(dbHandle);
	}

	static VTMatchTagDBAdapter getAdapter(DBHandle dbHandle, OpenMode openMode, TaskMonitor monitor)
			throws VersionException {
		return new VTMatchTagDBAdapterV0(dbHandle, openMode, monitor);
	}

	public abstract Record insertRecord(String tagName) throws IOException;

	public abstract RecordIterator getRecords() throws IOException;

	abstract Record getRecord(long tagRecordKey) throws IOException;

	abstract int getRecordCount();

	abstract void updateRecord(Record record) throws IOException;

	abstract boolean deleteRecord(long tagRecordKey) throws IOException;
}
