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
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 1 adapter for the comments table.
 */
class CommentsDBAdapterV1 extends CommentsDBAdapter {

//	/** comment type for end of line */
//	private static final int EOL_COMMENT_COLUMN = 0;
//	/** comment type that goes before a code unit */
//	private static final int PRE_COMMENT_COLUMN = 1;
//	/** comment type that follows after a code unit */
//	private static final int POST_COMMENT_COLUMN = 2; 
//	/** Property name for plate comment type */
//	private static final int PLATE_COMMENT_COLUMN = 3;
//	/** Property name for plate comment type */
//	private static final int REPEATABLE_COMMENT_COLUMN = 4;
//	/** The number of comment fields in this version. */
//	private static final int COMMENT_COL_COUNT = 5;
//	/** Version 0 comment column names. */
//	private static final String[] V1_NAMES = new String[5];
//	static {
//		V1_NAMES[EOL_COMMENT_COLUMN] = "EOL";
//		V1_NAMES[PRE_COMMENT_COLUMN] = "Pre";
//		V1_NAMES[POST_COMMENT_COLUMN] = "Post";
//		V1_NAMES[PLATE_COMMENT_COLUMN] = "Plate";
//		V1_NAMES[REPEATABLE_COMMENT_COLUMN] = "Repeatable";
//	}
//	/** Version 0 comment table schema. */
//	private static final Schema V1_SCHEMA = new Schema(1, "Address",
//							new Class[] {StringField.class, StringField.class,
//										StringField.class, StringField.class,
//										StringField.class},
//							V1_NAMES);
	/** the comment table. */
	private Table commentTable;
	private AddressMap addrMap;


	CommentsDBAdapterV1(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
			VersionException {

		this.addrMap = addrMap;
		if (create) {
			commentTable = handle.createTable(COMMENTS_TABLE_NAME, COMMENTS_SCHEMA);
		}
		else {
			commentTable = handle.getTable(COMMENTS_TABLE_NAME);
			if (commentTable == null) {
				throw new VersionException("Missing Table: " + COMMENTS_TABLE_NAME);
			}
			if (commentTable.getSchema().getVersion() != 1) {
				int version = commentTable.getSchema().getVersion();
				if (version < 1) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	DBRecord getRecord(long addr) throws IOException {
		return commentTable.getRecord(addr);
	}

	@Override
	DBRecord createRecord(long addr, int commentCol, String comment) throws IOException {
		DBRecord record = COMMENTS_SCHEMA.createRecord(addr);
		record.setString(commentCol, comment);
		commentTable.putRecord(record);
		return record;
	}

	@Override
	boolean deleteRecord(long addr) throws IOException {
		return commentTable.deleteRecord(addr);
	}

	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		return AddressRecordDeleter.deleteRecords(commentTable, addrMap, start, end);
	}

	@Override
	void updateRecord(DBRecord commentRec) throws IOException {
		commentTable.putRecord(commentRec);
	}

	@Override
	AddressKeyIterator getKeys(Address start, Address end, boolean atStart) throws IOException {
		if (atStart) {
			return new AddressKeyIterator(commentTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(commentTable, addrMap, start, end, end, false);
	}

	@Override
	AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException {
		if (forward) {
			return new AddressKeyIterator(commentTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(commentTable, addrMap, set, set.getMaxAddress(), false);
	}

	@Override
	RecordIterator getRecords(Address start, Address end, boolean atStart) throws IOException {
		if (atStart) {
			return new AddressKeyRecordIterator(commentTable, addrMap, start, end, start, true);
		}
		return new AddressKeyRecordIterator(commentTable, addrMap, start, end, end, false);
	}

	@Override
	RecordIterator getRecords(Address addr) throws IOException {
		return new AddressKeyRecordIterator(commentTable, addrMap, addr, true);
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new AddressKeyRecordIterator(commentTable, addrMap);
	}

	@Override
	void putRecord(DBRecord record) throws IOException {
		commentTable.putRecord(record);
	}

	@Override
	int getRecordCount() throws IOException {
		return commentTable.getRecordCount();
	}

	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		DatabaseTableUtils.updateAddressKey(commentTable, addrMap, fromAddr, toAddr, length,
			monitor);
	}
}
