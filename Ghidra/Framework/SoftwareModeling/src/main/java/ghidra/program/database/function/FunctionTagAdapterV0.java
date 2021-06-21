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
package ghidra.program.database.function;

import java.io.IOException;

import db.*;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.util.exception.VersionException;

/**
 * Initial version of the {@link FunctionTagAdapter}.
 */
class FunctionTagAdapterV0 extends FunctionTagAdapter implements DBListener {

	final static int SCHEMA_VERSION = 0;
	static final int V0_TAG_NAME_COL = 0;
	static final int V0_COMMENT_COL = 1;

	final static Schema V0_SCHEMA = new Schema(CURRENT_VERSION, "ID",
		new Field[] { StringField.INSTANCE, StringField.INSTANCE },
		new String[] { "Tag", "Comment" });

	private Table table; // lazy creation, null if empty
	private final DBHandle dbHandle;

	FunctionTagAdapterV0(DBHandle dbHandle, boolean create) throws VersionException {

		this.dbHandle = dbHandle;

		// This deserves an explanation:
		//
		// Both function tag tables are transient, meaning they're created only when necessary,
		// and destroyed when possible. Because of this, the Table object maintained by this
		// class will at times be invalid and generate an exception if accessed. To protect
		// against this, we listen for db updates and refresh that Table object when the 
		// database is restored. 
		dbHandle.addListener(this);

		if (!create) {
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
	DBRecord getRecord(String tag) throws IOException {
		if (table == null) {
			return null;
		}
		// NOTE: could consider either keeping all tags in memory or
		// using an indexed column.
		RecordIterator iter = table.iterator();
		while (iter.hasNext()) {
			DBRecord rec = iter.next();
			if (rec.getString(V0_TAG_NAME_COL).equals(tag)) {
				return rec;
			}
		}
		return null;
	}

	@Override
	DBRecord createTagRecord(String tag, String comment) throws IOException {

		// See if there is already a record for this tag name. If so,
		// just return that one.
		DBRecord rec = getRecord(tag);

		if (rec == null) {
			rec = V0_SCHEMA.createRecord(getTable().getKey());
			rec.setString(V0_TAG_NAME_COL, tag);
			rec.setString(V0_COMMENT_COL, comment);
			updateRecord(rec);
		}

		return rec;
	}

	@Override
	void removeTagRecord(long id) throws IOException {
		if (table != null) {
			table.deleteRecord(id);
		}
	}

	@Override
	RecordIterator getRecords() throws IOException {
		if (table == null) {
			return new EmptyRecordIterator();
		}
		return table.iterator();
	}

	@Override
	int getNumTags() {
		if (table == null) {
			return 0;
		}
		return table.getRecordCount();
	}

	@Override
	DBRecord getRecord(long id) throws IOException {
		if (table == null) {
			return null;
		}
		return table.getRecord(id);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		getTable().putRecord(record);
	}

	private Table getTable() throws IOException {
		if (table == null) {
			table = dbHandle.createTable(TABLE_NAME, V0_SCHEMA);
		}
		return table;
	}

	@Override
	public void dbRestored(DBHandle dbh) {
		table = dbh.getTable(TABLE_NAME);
	}

	@Override
	public void dbClosed(DBHandle dbh) {
	}

	@Override
	public void tableDeleted(DBHandle dbh, Table table) {
	}

	@Override
	public void tableAdded(DBHandle dbh, Table table) {
		// do nothing
	}
}
