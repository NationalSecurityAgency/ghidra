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
import ghidra.program.database.map.AddressKeyIterator;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the comments table for code units. The primary key
 * for the table is the address. The record contains all of the comment
 * types: Pre, Post, EOL, Plate, and Repeatable.
 */
abstract class CommentsDBAdapter {

	static final String COMMENTS_TABLE_NAME = "Comments";

	static final Schema COMMENTS_SCHEMA;

	static final int PRE_COMMENT_COL = CodeUnit.PRE_COMMENT;
	static final int POST_COMMENT_COL = CodeUnit.POST_COMMENT;
	static final int EOL_COMMENT_COL = CodeUnit.EOL_COMMENT;
	static final int PLATE_COMMENT_COL = CodeUnit.PLATE_COMMENT;
	static final int REPEATABLE_COMMENT_COL = CodeUnit.REPEATABLE_COMMENT;

	static final int COMMENT_COL_COUNT = 5;

	static final String[] NAMES;

	static {
		NAMES = new String[5];
		NAMES[PRE_COMMENT_COL] = "Pre";
		NAMES[POST_COMMENT_COL] = "Post";
		NAMES[EOL_COMMENT_COL] = "EOL";
		NAMES[PLATE_COMMENT_COL] = "Plate";
		NAMES[REPEATABLE_COMMENT_COL] = "Repeatable";

		COMMENTS_SCHEMA =
			new Schema(1, "Address", new Field[] { StringField.INSTANCE, StringField.INSTANCE,
				StringField.INSTANCE, StringField.INSTANCE, StringField.INSTANCE }, NAMES);
	}

//	/** comment type for end of line */
//	static final int EOL_COMMENT = 0;
//	/** comment type that goes before a code unit */
//	static final int PRE_COMMENT = 1;
//	/** comment type that follows after a code unit */
//	static final int POST_COMMENT = 2; 
//	/** plate comment type */
//	static final int PLATE_COMMENT = 3;
//	/** repeatable comment type */
//	static final int REPEATABLE_COMMENT = 4;

	static CommentsDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new CommentsDBAdapterV1(dbHandle, addrMap, true);
		}

		try {
			CommentsDBAdapter adapter = new CommentsDBAdapterV1(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			CommentsDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static CommentsDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws VersionException, IOException {
		try {
			return new CommentsDBAdapterV1(handle, addrMap.getOldAddressMap(), false);
		}
		catch (VersionException e) {
		}

		return new CommentsDBAdapterV0(handle, addrMap);
	}

	private static CommentsDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			CommentsDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Comments...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			CommentsDBAdapter tmpAdapter = new CommentsDBAdapterV1(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getKey());
				rec.setKey(addrMap.getKey(addr, true));
				tmpAdapter.updateRecord(rec);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(COMMENTS_TABLE_NAME);
			CommentsDBAdapter newAdapter = new CommentsDBAdapterV1(dbHandle, addrMap, true);

			iter = tmpAdapter.getRecords();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				newAdapter.updateRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * @return
	 */
	abstract int getRecordCount() throws IOException;

	/**
	 * Get the record at the given address.
	 * @param addr key for the record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long addr) throws IOException;

	/**
	 * Create a comment record for the given comment type/
	 * @param addr key for the record.
	 * @param commentCol comment column (type)
	 * @param comment comment
	 * @return new comment record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createRecord(long addr, int commentCol, String comment) throws IOException;

	/**
	 * Delete the record at the given address
	 * @param addr key for the record
	 * @return true if the record was deleted
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean deleteRecord(long addr) throws IOException;

	/**
	 * Delete the records in the given range.
	 * @param start start address (key)
	 * @param end address (key)
	 * @return true if at least one record was removed in the range
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean deleteRecords(Address start, Address end) throws IOException;

	/**
	 * Update the record with the comments from the given record.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord commentRec) throws IOException;

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#getRecords(long, long, boolean)
	 */
	abstract RecordIterator getRecords(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Gets an iterator of all comment records in the program.
	 * @return iterator of all comment records
	 * @throws IOException 
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Get the keys in the given range.
	 * @param start start of the range
	 * @param end end of the range
	 * @param atStart true means to position iterator at start of the range
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract AddressKeyIterator getKeys(Address start, Address end, boolean atStart)
			throws IOException;

	/**
	 * Puts the given record into the table
	 * @param record the record to put.
	 * @throws IOException if a database io error occurs
	 */
	abstract void putRecord(DBRecord record) throws IOException;

	/**
	 * Returns a record iterator starting with the record at addr
	 * @param addr the address to start the iteration.
	 * @throws IOException if a database io error occurs
	 */
	abstract RecordIterator getRecords(Address addr) throws IOException;

	/**
	 * Returns an address key iterator over the given address set in the given direction.
	 * @param addrSetView the set to iterator over (null for all defined memory).
	 * @param forward the direction to iterate.
	 */
	abstract AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException;

	/**
	 * Update the addresses in all records to reflect the movement of a memory block.
	 * @param fromAddr minimum address of the original block to be moved
	 * @param toAddr the new minimum address after the block move
	 * @param length the number of bytes in the memory block being moved
	 * @param monitor progress monitor
	 * @throws CancelledException
	 * @throws IOException 
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;

}
