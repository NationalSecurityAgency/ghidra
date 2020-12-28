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

import java.io.IOException;

import db.*;
import ghidra.program.database.util.EmptyRecordIterator;
import ghidra.util.exception.VersionException;

/**
 * Adapter needed for a read-only version of data type manager that is not going
 * to be upgraded, and there is no Function Definition Parameters table in the data type manager.
 */
class FunctionParameterAdapterNoTable extends FunctionParameterAdapter {

	/**
	 * Gets a pre-table version of the adapter for the Function Definition Parameters database table.
	 * @param handle handle to the database which doesn't contain the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public FunctionParameterAdapterNoTable(DBHandle handle) {
		// no table required
	}

	@Override
	public DBRecord createRecord(long dataTypeID, long parentID, int ordinal, String name,
			String comment, int dtLength) throws IOException {
		return null;
	}

	@Override
	public DBRecord getRecord(long parameterID) throws IOException {
		return null;
	}

	@Override
	protected RecordIterator getRecords() {
		return new EmptyRecordIterator();
	}

	@Override
	public void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean removeRecord(long parameterID) throws IOException {
		return false;
	}

	@Override
	protected void deleteTable(DBHandle handle) throws IOException {
		// do nothing
	}

	@Override
	public Field[] getParameterIdsInFunctionDef(long functionDefID) throws IOException {
		return Field.EMPTY_ARRAY;
	}

}
