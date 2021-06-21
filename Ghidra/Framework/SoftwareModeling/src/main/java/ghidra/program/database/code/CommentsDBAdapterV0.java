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
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 0 adapter for the comments table.
 */
class CommentsDBAdapterV0 extends CommentsDBAdapter {

	/** column for end of line comment */
	private static final int EOL_COMMENT_COLUMN = 0;
	/** comment type that goes before a code unit */
	private static final int PRE_COMMENT_COLUMN = 1;
	/** comment type that follows after a code unit */
	private static final int POST_COMMENT_COLUMN = 2;
	/** Property name for plate comment type */
	private static final int PLATE_COMMENT_COLUMN = 3;
	/** The number of comment fields in this version. */
	/** Version 0 comment column names. */
	private static final String[] V0_NAMES = new String[4];
	static {
		V0_NAMES[EOL_COMMENT_COLUMN] = "EOL";
		V0_NAMES[PRE_COMMENT_COLUMN] = "Pre";
		V0_NAMES[POST_COMMENT_COLUMN] = "Post";
		V0_NAMES[PLATE_COMMENT_COLUMN] = "Plate";
	}
	/** Version 0 comment table schema. */
//	private static final Schema V0_SCHEMA = new Schema(0, "Address",
//							new Class[] {StringField.class, StringField.class,
//										StringField.class, StringField.class},
//							V0_NAMES);
	/** the comment table. */
	private Table commentTable;
	private AddressMap addrMap;

	/**
	 * Constructor 
	 * 
	 */
	@SuppressWarnings("unused")
	public CommentsDBAdapterV0(DBHandle handle, AddressMap addrMap) throws IOException,
			VersionException {
		this.addrMap = addrMap.getOldAddressMap();

		commentTable = handle.getTable(COMMENTS_TABLE_NAME);
		if (commentTable == null) {
			throw new VersionException("Missing Table: " + COMMENTS_TABLE_NAME);
		}
		if (commentTable.getSchema().getVersion() != 0) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getRecord(long)
	 */
	@Override
	public DBRecord getRecord(long addr) throws IOException {
		return adaptRecord(commentTable.getRecord(addr));
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#createRecord(long, int, java.lang.String)
	 */
	@Override
	public DBRecord createRecord(long addr, int commentCol, String comment) throws IOException {
		return null;
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#deleteRecord(long)
	 */
	@Override
	public boolean deleteRecord(long addr) throws IOException {
		return false;
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#deleteRecords(long, long)
	 */
	@Override
	public boolean deleteRecords(Address start, Address end) throws IOException {
		return false;
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#updateRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	public void updateRecord(DBRecord commentRec) throws IOException {
	}

	/**
	 * 
	 * @see ghidra.program.database.code.CommentsDBAdapter#getKeys(long, long, boolean)
	 */
	@Override
	public AddressKeyIterator getKeys(Address start, Address end, boolean atStart)
			throws IOException {
		if (atStart) {
			return new AddressKeyIterator(commentTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(commentTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getKeys(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	public AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException {
		if (forward) {
			return new AddressKeyIterator(commentTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(commentTable, addrMap, set, set.getMaxAddress(), false);
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getRecords(Address, Address, boolean)
	 */
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

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getRecords(Address)
	 */
	@Override
	public RecordIterator getRecords(Address addr) throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(commentTable, addrMap, addr,
			true));
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getRecords()
	 */
	@Override
	public RecordIterator getRecords() throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(commentTable, addrMap));
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#putRecord(db.DBRecord)
	 */
	@Override
	public void putRecord(DBRecord record) throws IOException {
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#getRecordCount()
	 */
	@Override
	public int getRecordCount() throws IOException {
		return commentTable.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.code.CommentsDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
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
	private DBRecord adaptRecord(DBRecord recV0) {
		if (recV0 == null)
			return null;
		DBRecord record = COMMENTS_SCHEMA.createRecord(recV0.getKey());

		String comment = recV0.getString(EOL_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(CodeUnit.EOL_COMMENT, comment);
		}

		comment = recV0.getString(PRE_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(CodeUnit.PRE_COMMENT, comment);
		}

		comment = recV0.getString(POST_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(CodeUnit.POST_COMMENT, comment);
		}

		comment = recV0.getString(PLATE_COMMENT_COLUMN);
		if (comment != null) {
			record.setString(CodeUnit.PLATE_COMMENT, comment);
		}

		return record;
	}

	class RecordIteratorAdapter implements RecordIterator {
		RecordIterator it;

		RecordIteratorAdapter(RecordIterator it) {
			this.it = it;
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#delete()
		 */
		public boolean delete() throws IOException {
			return false;
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#hasNext()
		 */
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#hasPrevious()
		 */
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#next()
		 */
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return adaptRecord(rec);
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#previous()
		 */
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return adaptRecord(rec);
		}

	}
}
