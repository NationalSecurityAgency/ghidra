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
package ghidra.program.database.function;

import java.io.IOException;

import db.DBRecord;

/**
 * Adapter needed for a read-only version of Program that is not going
 * to be upgraded, and there is no Calling Convention table in the Program.
 *
 */
class CallingConventionDBAdapterNoTable extends CallingConventionDBAdapter {

	/**
	 *
	 */
	public CallingConventionDBAdapterNoTable() {
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.function.CallingConventionDBAdapter#createCallingConventionRecord(java.lang.String)
	 */
	@Override
	public DBRecord createCallingConventionRecord(String name) throws IOException {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.function.CallingConventionDBAdapter#getCallingConventionRecord(byte)
	 */
	@Override
	public DBRecord getCallingConventionRecord(byte callingConventionID) throws IOException {
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.function.CallingConventionDBAdapter#getCallingConventionRecord(java.lang.String)
	 */
	@Override
	public DBRecord getCallingConventionRecord(String name) throws IOException {
		return null;
	}

}
