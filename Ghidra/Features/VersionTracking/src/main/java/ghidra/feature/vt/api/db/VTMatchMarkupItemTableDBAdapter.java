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

import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.*;

import java.io.IOException;

import db.*;
import ghidra.feature.vt.api.impl.MarkupItemStorage;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public abstract class VTMatchMarkupItemTableDBAdapter {

	public static class MarkupTableDescriptor extends ghidra.feature.vt.api.db.TableDescriptor {
		public static TableColumn ASSOCIATION_KEY_COL = new TableColumn(LongField.INSTANCE, true);
		public static TableColumn ADDRESS_SOURCE_COL = new TableColumn(StringField.INSTANCE);
		public static TableColumn DESTINATION_ADDRESS_COL = new TableColumn(LongField.INSTANCE);
		public static TableColumn MARKUP_TYPE_COL = new TableColumn(ShortField.INSTANCE);
		public static TableColumn SOURCE_ADDRESS_COL = new TableColumn(LongField.INSTANCE);
		public static TableColumn SOURCE_VALUE_COL = new TableColumn(StringField.INSTANCE);
		public static TableColumn ORIGINAL_DESTINATION_VALUE_COL =
			new TableColumn(StringField.INSTANCE);
		public static TableColumn STATUS_COL = new TableColumn(ByteField.INSTANCE);
		public static TableColumn STATUS_DESCRIPTION_COL = new TableColumn(StringField.INSTANCE);

		public static MarkupTableDescriptor INSTANCE = new MarkupTableDescriptor();
	}

	protected static String TABLE_NAME = "MatchMarkupItemTable";
	static Schema TABLE_SCHEMA =
		new Schema(0, "Key", INSTANCE.getColumnFields(), INSTANCE.getColumnNames());

	protected static int[] INDEXED_COLUMNS = INSTANCE.getIndexedColumns();

	public static VTMatchMarkupItemTableDBAdapter createAdapter(DBHandle dbHandle)
			throws IOException {
		return new VTMatchMarkupItemTableDBAdapterV0(dbHandle);
	}

	public static VTMatchMarkupItemTableDBAdapter getAdapter(DBHandle dbHandle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new VTMatchMarkupItemTableDBAdapterV0(dbHandle, openMode, monitor);
	}

	public abstract RecordIterator getRecords() throws IOException;

	public abstract void removeMatchMarkupItemRecord(long key) throws IOException;

	public abstract DBRecord getRecord(long key) throws IOException;

	public abstract RecordIterator getRecords(long AssociationKey) throws IOException;

	abstract void updateRecord(DBRecord record) throws IOException;

	public abstract int getRecordCount();

	public abstract DBRecord createMarkupItemRecord(MarkupItemStorage markupItem) throws IOException;
}
