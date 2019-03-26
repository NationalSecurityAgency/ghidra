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
package ghidra.program.database.data;

import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.util.UniversalID;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 * Adapter needed for a read-only version of data type manager that is not going
 * to be upgraded, and there is no Function Signature Definition table in the data type manager.
 */
class FunctionDefinitionDBAdapterNoTable extends FunctionDefinitionDBAdapter {

	/**
	 * Gets a pre-table version of the adapter for the Function Definition database table.
	 * @param handle handle to the database which doesn't contain the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionDefinitionDBAdapterNoTable(DBHandle handle) {
	}

	@Override
	public Record createRecord(String name, String comments, long categoryID, long returnDtID,
			boolean hasVarArgs, GenericCallingConvention genericCallingConvention,
			long sourceArchiveID, long sourceDataTypeID, long lastChangeTime) throws IOException {
		throw new UnsupportedOperationException(
			"Not allowed to update version prior to existence of Function Definition Data Types table.");
	}

	@Override
	public Record getRecord(long functionDefID) throws IOException {
		return null;
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	public void updateRecord(Record record, boolean setLastChangeTime) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long functionDefID) throws IOException {
		return false;
	}

	@Override
	protected void deleteTable(DBHandle handle) {
	}

	@Override
	public long[] getRecordIdsInCategory(long categoryID) throws IOException {
		return new long[0];
	}

	@Override
	long[] getRecordIdsForSourceArchive(long archiveID) throws IOException {
		return new long[0];
	}

	@Override
	Record getRecordWithIDs(UniversalID sourceID, UniversalID datatypeID) throws IOException {
		return null;
	}

}
