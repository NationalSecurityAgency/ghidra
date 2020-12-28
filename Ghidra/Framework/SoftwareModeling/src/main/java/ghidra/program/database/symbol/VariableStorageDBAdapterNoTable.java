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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.database.util.EmptyRecordIterator;

public class VariableStorageDBAdapterNoTable extends VariableStorageDBAdapter {

	VariableStorageDBAdapterNoTable() {
	}

	@Override
	long getNextStorageID() {
		throw new UnsupportedOperationException();
	}

	@Override
	long findRecordKey(long hash) throws IOException {
		return -1;
	}

	@Override
	void deleteRecord(long key) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	DBRecord getRecord(long key) throws IOException {
		return null;
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new EmptyRecordIterator();
	}

	@Override
	int getRecordCount() {
		return 0;
	}
}
