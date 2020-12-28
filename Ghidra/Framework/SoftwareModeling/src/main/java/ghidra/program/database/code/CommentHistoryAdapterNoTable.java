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

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.address.Address;

/**
 * Adapter needed for a read-only version of Program that is not going
 * to be upgraded, and there is no comment history table in the Program.
 */
class CommentHistoryAdapterNoTable extends CommentHistoryAdapter {

	@Override
	public void createRecord(long addr, byte commentType, int pos1, int pos2, String data,
			long date) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public RecordIterator getRecordsByAddress(Address addr) throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	public RecordIterator getAllRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	void updateRecord(DBRecord rec) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	int getRecordCount() {
		return 0;
	}
}
