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
package ghidra.program.database.sourcemap;

import java.io.IOException;
import java.util.Arrays;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.util.exception.VersionException;

/**
 * Initial version of {@link SourceFileAdapter}.
 */
class SourceFileAdapterV0 extends SourceFileAdapter implements DBListener {

	final static int SCHEMA_VERSION = 0;
	static final int V0_PATH_COL = 0;
	static final int V0_ID_TYPE_COL = 1;
	static final int V0_ID_COL = 2;

	private final static Schema V0_SCHEMA = new Schema(SCHEMA_VERSION, "ID",
		new Field[] { StringField.INSTANCE, ByteField.INSTANCE, BinaryField.INSTANCE },
		new String[] { "Path", "IdType", "Identifier" }, new int[] { V0_PATH_COL });

	private Table table; // lazy creation, null if empty
	private final DBHandle dbHandle;
	private static final int[] INDEXED_COLUMNS = new int[] { V0_PATH_COL };

	SourceFileAdapterV0(DBHandle dbHandle, OpenMode openMode) throws VersionException {
		this.dbHandle = dbHandle;

		// As in FunctionTagAdapterV0, we need to add this as a database listener.
		// Since the table is created lazily, undoing a transaction which (for example) caused
		// the table to be created can leave the table in a bad state. 
		// The implementation of dbRestored(DBHandle) solves this issue.  
		this.dbHandle.addListener(this);

		if (!openMode.equals(OpenMode.CREATE)) {
			table = dbHandle.getTable(TABLE_NAME);
			if (table == null) {
				return; // perform lazy table creation
			}
			int version = table.getSchema().getVersion();
			if (version != SCHEMA_VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		table = dbh.getTable(TABLE_NAME);
	}

	@Override
	public void dbClosed(DBHandle dbh) {
		// nothing to do
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table deletedTable) {
		// nothing to do
	}

	@Override
	public void tableAdded(DBHandle dbh, Table addedTable) {
		// nothing to do
	}

	@Override
	RecordIterator getRecords() throws IOException {
		if (table == null) {
			return new EmptyRecordIterator();
		}
		return table.iterator();
	}

	@Override
	DBRecord getRecord(long id) throws IOException {
		if (table == null) {
			return null;
		}
		return table.getRecord(id);
	}

	@Override
	DBRecord getRecord(SourceFile sourceFile) throws IOException {
		if (table == null) {
			return null;
		}
		StringField field = new StringField(sourceFile.getPath());
		RecordIterator iter = table.indexIterator(V0_PATH_COL, field, field, true);
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			if (rec.getByteValue(V0_ID_TYPE_COL) != sourceFile.getIdType().getIndex()) {
				continue;
			}
			if (Arrays.equals(sourceFile.getIdentifier(), rec.getBinaryData(V0_ID_COL))) {
				return rec;
			}
		}
		return null;

	}

	@Override
	DBRecord createSourceFileRecord(SourceFile sourceFile) throws IOException {
		DBRecord rec = getRecord(sourceFile);
		if (rec == null) {
			rec = V0_SCHEMA.createRecord(getTable().getKey());
			rec.setString(V0_PATH_COL, sourceFile.getPath());
			rec.setByteValue(V0_ID_TYPE_COL, sourceFile.getIdType().getIndex());
			rec.setBinaryData(V0_ID_COL, sourceFile.getIdentifier());
			getTable().putRecord(rec);
		}
		return rec;
	}

	@Override
	boolean removeSourceFileRecord(long id) throws IOException {
		if (table != null) {
			return table.deleteRecord(id);
		}
		return false;
	}

	private Table getTable() throws IOException {
		if (table == null) {
			table = dbHandle.createTable(TABLE_NAME, V0_SCHEMA, INDEXED_COLUMNS);
		}
		return table;
	}

}
