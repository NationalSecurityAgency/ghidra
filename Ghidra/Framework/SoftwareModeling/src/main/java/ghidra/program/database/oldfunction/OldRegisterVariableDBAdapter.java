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

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.util.exception.VersionException;

/**
 * Database adapter for register variables.
 * 
 * 
 */
abstract class OldRegisterVariableDBAdapter {

	static final int REG_VAR_FUNCTION_KEY_COL =
		OldRegisterVariableDBAdapterV0.V0_REG_VAR_FUNCTION_KEY_COL;
	static final int REG_VAR_REGNAME_COL = OldRegisterVariableDBAdapterV0.V0_REG_VAR_REGNAME_COL;
	static final int REG_VAR_DATA_TYPE_ID_COL =
		OldRegisterVariableDBAdapterV0.V0_REG_VAR_DATA_TYPE_ID_COL;
	static final int REG_VAR_NAME_COL = OldRegisterVariableDBAdapterV0.V0_REG_VAR_NAME_COL;
	static final int REG_VAR_COMMENT_COL = OldRegisterVariableDBAdapterV0.V0_REG_VAR_COMMENT_COL;

	static final Schema REG_PARAMS_SCHEMA = OldRegisterVariableDBAdapterV0.V0_REG_PARAMS_SCHEMA;

	static OldRegisterVariableDBAdapter getAdapter(DBHandle handle, AddressMap map)
			throws VersionException {

		return new OldRegisterVariableDBAdapterV0(handle, map);
	}

	abstract void deleteTable(DBHandle handle) throws IOException;

	abstract int getRecordCount();

	/**
	 * Get a register variable record.
	 * @param key
	 * @return Record
	 */
	abstract DBRecord getRegisterVariableRecord(long key) throws IOException;

	/**
	 * Get all register variable keys which correspond to a function.
	 * @param functionKey
	 * @return array of register variable keys as LongField values within Field array.
	 * @throws IOException if IO error occurs
	 */
	abstract Field[] getRegisterVariableKeys(long functionKey) throws IOException;

}
