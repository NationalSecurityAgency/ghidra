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

import db.*;
import ghidra.program.database.util.EmptyRecordIterator;

/**
 * Adapter for the read-only version of the function tag mapping adapter that cannot
 * be upgraded.
 * 
 */
class FunctionTagMappingAdapterNoTable extends FunctionTagMappingAdapter {

	FunctionTagMappingAdapterNoTable(DBHandle dbHandle) {
	}

	/******************************************************************************
	 * PUBLIC METHODS
	 ******************************************************************************/

	@Override
	DBRecord getRecord(long functionID, long tagID) throws IOException {
		return null;
	}

	@Override
	DBRecord createFunctionTagRecord(long functionID, long tagID)
			throws IOException {
		throw new UnsupportedOperationException("create record not supported");
	}

	@Override
	boolean removeFunctionTagRecord(long functionID, long tagID)
			throws IOException {
		throw new UnsupportedOperationException("remove record not supported");
	}

	@Override
	void removeFunctionTagRecord(long tagID) throws IOException {
		throw new UnsupportedOperationException("remove record not supported");
	}

	@Override
	RecordIterator getRecordsByFunctionID(long functionID) throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	boolean isTagAssigned(long id) throws IOException {
		return false;
	}

	@Override
	protected RecordIterator getRecords() throws IOException {
		return new EmptyRecordIterator();
	}
}
