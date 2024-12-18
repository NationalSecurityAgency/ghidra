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
import java.util.Set;

import db.DBHandle;
import ghidra.util.exception.VersionException;

class ParentChildDBAdapterNoTable extends ParentChildAdapter {

	/**
	 * Gets a pre-table version of the adapter for the Parent Child database table.
	 * @param handle handle to the database which doesn't contain the table.
	 * @throws VersionException if the table's version does not match the expected version
	 * for this adapter.
	 */
	ParentChildDBAdapterNoTable(DBHandle handle) {
		// no table required
	}

	@Override
	void createRecord(long parentID, long childID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	void removeRecord(long parentID, long childID) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	Set<Long> getChildIds(long parentID) throws IOException {
		return Set.of();
	}

	@Override
	Set<Long> getParentIds(long childID) throws IOException {
		return Set.of();
	}

	@Override
	boolean hasParent(long childID) throws IOException {
		return false;
	}

	@Override
	boolean needsInitializing() {
		return false;
	}

	@Override
	void removeAllRecordsForParent(long parentID) throws IOException {
		// stub
	}

	@Override
	void removeAllRecordsForChild(long childID) throws IOException {
		// stub
	}
}
