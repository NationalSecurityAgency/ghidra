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

import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.DBHandle;
import db.Record;

/**
 * Adapter needed for a read-only version of data type manager that is not going
 * to be upgraded, and there is no Enumeration Data Type Values table in the data type manager.
 */
class EnumValueDBAdapterNoTable extends EnumValueDBAdapter {

	/**
	 * Gets a pre-table version of the adapter for the enumeration data type values database table.
	 * @param handle handle to the database which doesn't contain the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 */
	public EnumValueDBAdapterNoTable(DBHandle handle) {
	}

	@Override
	public void createRecord(long enumID, String name, long value) throws IOException {
	}

	@Override
	public Record getRecord(long valueID) throws IOException {
		return null;
	}

	@Override
	public void updateRecord(Record record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeRecord(long valueID) throws IOException {
	}

	@Override
	public long[] getValueIdsInEnum(long enumID) throws IOException {
		return new long[0];
	}

}
