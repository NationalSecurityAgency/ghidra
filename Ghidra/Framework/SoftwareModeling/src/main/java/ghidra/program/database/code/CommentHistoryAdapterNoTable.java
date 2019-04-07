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
package ghidra.program.database.code;

import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.Address;

import java.io.IOException;

import db.Record;
import db.RecordIterator;

/**
 * Adapter needed for a read-only version of Program that is not going
 * to be upgraded, and there is no comment history table in the Program.
 */
class CommentHistoryAdapterNoTable extends CommentHistoryAdapter {

	/* (non Javadoc)
	 * @see ghidra.program.database.code.CommentHistoryAdapter#createRecord(long, byte, int, int, java.lang.String)
	 */
	@Override
	public void createRecord(long addr, byte commentType, int pos1, int pos2, String data)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getRecordsByAddress(long)
	 */
	@Override
	public RecordIterator getRecordsByAddress(Address addr) throws IOException {
		return new EmptyRecordIterator();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getAllRecords()
	 */
	@Override
	public RecordIterator getAllRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#updateRecord(db.Record)
	 */
	@Override
	void updateRecord(Record rec) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#deleteRecords(ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.CommentHistoryAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() {
		return 0;
	}

}
