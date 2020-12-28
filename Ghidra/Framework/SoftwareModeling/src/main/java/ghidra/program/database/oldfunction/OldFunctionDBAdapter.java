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
package ghidra.program.database.oldfunction;

import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

import java.io.IOException;

import db.*;

/**
 * Database adapter for functions.
 */
abstract class OldFunctionDBAdapter {

	static final int RETURN_DATA_TYPE_ID_COL = OldFunctionDBAdapterV1.V1_RETURN_DATA_TYPE_ID_COL;
	static final int STACK_DEPTH_COL = OldFunctionDBAdapterV1.V1_STACK_DEPTH_COL;
	static final int STACK_PARAM_OFFSET_COL = OldFunctionDBAdapterV1.V1_STACK_PARAM_OFFSET_COL;
	static final int STACK_RETURN_OFFSET_COL = OldFunctionDBAdapterV1.V1_STACK_RETURN_OFFSET_COL;
	static final int STACK_LOCAL_SIZE_COL = OldFunctionDBAdapterV1.V1_STACK_LOCAL_SIZE_COL;
	static final int REPEATABLE_COMMENT_COL = OldFunctionDBAdapterV1.V1_REPEATABLE_COMMENT_COL;

	static final Schema FUNCTIONS_SCHEMA = OldFunctionDBAdapterV1.V1_FUNCTIONS_SCHEMA;

	protected AddressMap addrMap;

	static OldFunctionDBAdapter getAdapter(DBHandle handle, AddressMap map) throws VersionException {

		try {
			return new OldFunctionDBAdapterV1(handle, map);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				throw e;
			}
		}
		return new OldFunctionDBAdapterV0(handle, map);
	}

	OldFunctionDBAdapter(AddressMap map) {
		addrMap = map;
	}

	/**
	 * @param handle
	 */
	abstract protected void deleteTable(DBHandle handle) throws IOException;

	/**
	 * Returns a count of functions records.
	 * @return a count of functions records
	 */
	abstract int getRecordCount();

	/**
	 * Get a function record.
	 * @param functionKey
	 * @return Record
	 */
	abstract DBRecord getFunctionRecord(long functionKey) throws IOException;

	/**
	 * Iterate over all function records.
	 * @return RecordIterator
	 */
	abstract RecordIterator iterateFunctionRecords() throws IOException;

}
