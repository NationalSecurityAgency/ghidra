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

import ghidra.feature.vt.api.main.VTMatchInfo;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

import db.*;

public abstract class VTMatchTableDBAdapter {

	public enum ColumnDescription {
		TAG_KEY_COL(LongField.class),
		MATCH_SET_COL(LongField.class),
		SIMILARITY_SCORE_COL(StringField.class),
		CONFIDENCE_SCORE_COL(StringField.class),
		LENGTH_TYPE(StringField.class),
		SOURCE_LENGTH_COL(IntField.class),
		DESTINATION_LENGTH_COL(IntField.class),
		ASSOCIATION_COL(LongField.class);

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

	static String TABLE_NAME = "MatchTable";
	static Schema TABLE_SCHEMA =
		new Schema(0, "Key", ColumnDescription.getColumnClasses(),
			ColumnDescription.getColumnNames());

	static VTMatchTableDBAdapter createAdapter(DBHandle dbHandle, long tableID) throws IOException {
		return new VTMatchTableDBAdapterV0(dbHandle, tableID);
	}

	static VTMatchTableDBAdapter getAdapter(DBHandle dbHandle, long tableID, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new VTMatchTableDBAdapterV0(dbHandle, tableID, openMode, monitor);
	}

	public abstract Record insertMatchRecord(VTMatchInfo info, VTMatchSetDB matchSet,
			VTAssociationDB associationDB, VTMatchTagDB tag) throws IOException;

	public abstract RecordIterator getRecords() throws IOException;

	abstract Record getMatchRecord(long matchRecordKey) throws IOException;

	abstract int getRecordCount();

	abstract void updateRecord(Record record) throws IOException;

	abstract boolean deleteRecord(long matchRecordKey) throws IOException;

	abstract RecordIterator getRecords(long associationID) throws IOException;
}
