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
package ghidra.program.database.data;

import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.util.UniversalID;

import java.io.IOException;

import db.*;

/**
 * Adapter needed for a read-only version of data type manager that is not going
 * to be upgraded, and there is no Address Model table in the data type manager.
 */
class AddressModelDBAdapterNoTable extends AddressModelDBAdapter {

	/**
	 * Gets a pre-table version of the adapter for the Address Model database table.
	 * @param handle handle to the database which doesn't contain the table.
	 */
	public AddressModelDBAdapterNoTable(DBHandle handle) {
		// no table required
	}

	@Override
	DBRecord createRecord(long dataTypeID, byte modelID) throws IOException {
		throw new UnsupportedOperationException(
			"Not allowed to update version prior to existence of Address Model Data Types table.");
	}

	@Override
	public DBRecord getRecord(long addrModelID) throws IOException {
		return null;
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	public void updateRecord(DBRecord record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long addrModelID) throws IOException {
		return false;
	}

	@Override
	protected void deleteTable(DBHandle handle) {
		// do nothing
	}

}
