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
package ghidra.program.database.code;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 0 adapter for the comments table.
 */
class CommentsDBAdapterV0 extends CommentsDBAdapter {

	/** column for end of line comment */
	private static final int V0_EOL_COMMENT_COLUMN = 0;
	/** comment type that goes before a code unit */
	private static final int V0_PRE_COMMENT_COLUMN = 1;
	/** comment type that follows after a code unit */
	private static final int V0_POST_COMMENT_COLUMN = 2;
	/** Property name for plate comment type */
	private static final int V0_PLATE_COMMENT_COLUMN = 3;

	/** Version 0 comment table schema. */
//	private static final Schema V0_SCHEMA = new Schema(0, "Address",
//							new Class[] {StringField.class, StringField.class,
//										StringField.class, StringField.class},
//							"EOL", "Pre", "Post", "Plate");
	/** the comment table. */
	private Table commentTable;
	private AddressMap addrMap;

	/**
	 * Constructor 
	 * 
	 */
	@SuppressWarnings("unused")
	public CommentsDBAdapterV0(DBHandle handle, AddressMap addrMap)
			throws IOException, VersionException {
		this.addrMap = addrMap.getOldAddressMap();

		commentTable = handle.getTable(COMMENTS_TABLE_NAME);
		if (commentTable == null) {
			throw new VersionException("Missing Table: " + COMMENTS_TABLE_NAME);
		}
		if (commentTable.getSchema().getVersion() != 0) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	@Override
	public DBRecord getRecord(long addr) throws IOException {
		return v0ConvertRecord(commentTable.getRecord(addr));
	}

	@Override
	public DBRecord createRecord(long addr, int commentCol, String comment) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean deleteRecord(long addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean deleteRecords(Address start, Address end) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void updateRecord(DBRecord commentRec) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public AddressKeyIterator getKeys(Address start, Address end, boolean atStart)
			throws IOException {
		if (atStart) {
			return new AddressKeyIterator(commentTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(commentTable, addrMap, start, end, end, false);
	}

	@Override
	public AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException {
		if (forward) {
			return new AddressKeyIterator(commentTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(commentTable, addrMap, set, set.getMaxAddress(), false);
	}

	@Override
	public RecordIterator getRecords(Address start, Address end, boolean atStart)
			throws IOException {
		RecordIterator it = null;
		if (atStart) {
			it = new AddressKeyRecordIterator(commentTable, addrMap, start, end, start, true);
		}
		else {
			it = new AddressKeyRecordIterator(commentTable, addrMap, start, end, end, false);
		}
		return new RecordIteratorAdapter(it);
	}

	@Override
	public RecordIterator getRecords(Address addr) throws IOException {
		return new RecordIteratorAdapter(
			new AddressKeyRecordIterator(commentTable, addrMap, addr, true));
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(commentTable, addrMap));
	}

	@Override
	public void putRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getRecordCount() throws IOException {
		return commentTable.getRecordCount();
	}

	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns a record matching the current data base schema from the version 0 record.
	 * @param recV0 the record matching the version 0 schema.
	 * @return a current comment record.
	 */
	private DBRecord v0ConvertRecord(DBRecord recV0) {
		if (recV0 == null)
			return null;
		DBRecord record = COMMENTS_SCHEMA.createRecord(recV0.getKey());

		String comment = recV0.getString(V0_EOL_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(EOL_COMMENT_COL, comment);
		}

		comment = recV0.getString(V0_PRE_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(PRE_COMMENT_COL, comment);
		}

		comment = recV0.getString(V0_POST_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(POST_COMMENT_COL, comment);
		}

		comment = recV0.getString(V0_PLATE_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(PLATE_COMMENT_COL, comment);
		}

		return record;
	}

	class RecordIteratorAdapter implements RecordIterator {
		RecordIterator it;

		RecordIteratorAdapter(RecordIterator it) {
			this.it = it;
		}

		@Override
		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		@Override
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return v0ConvertRecord(rec);
		}

		@Override
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return v0ConvertRecord(rec);
		}

	}
}
