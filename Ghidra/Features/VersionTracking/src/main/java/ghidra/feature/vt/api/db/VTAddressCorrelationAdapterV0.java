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
package ghidra.feature.vt.api.db;

import static ghidra.feature.vt.api.db.VTAddressCorrelatorAdapter.AddressCorrelationTableDescriptor.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import db.*;

public class VTAddressCorrelationAdapterV0 extends VTAddressCorrelatorAdapter {

	private Table table;

	public VTAddressCorrelationAdapterV0(DBHandle dbHandle) throws IOException {
		super(dbHandle);
		table = dbHandle.createTable(TABLE_NAME, TABLE_SCHEMA);
	}

	public VTAddressCorrelationAdapterV0(DBHandle dbHandle, TaskMonitor monitor) throws VersionException {
		super(dbHandle);
		table = dbHandle.getTable(TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		else if(table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table "+ TABLE_NAME + 
					" but got "+table.getSchema().getVersion());
		}
	}

	@Override
	void createAddressRecord(long sourceEntryLong, long sourceLong,long destinationLong) throws IOException {
		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());
		
		record.setLongValue(SOURCE_ENTRY_COL.column(), sourceLong);
		record.setLongValue(SOURCE_ADDRESS_COL.column(), sourceLong);
		record.setLongValue(DESTINATION_ADDRESS_COL.column(), destinationLong);
		
		table.putRecord(record);
	}

	@Override
	List<DBRecord> getAddressRecords(long sourceEntryLong) throws IOException {
		LongField value = new LongField(sourceEntryLong);
		RecordIterator indexIterator = table.indexIterator(0, value, value, true);
		List<DBRecord>records = new ArrayList<DBRecord>();
		while(indexIterator.hasNext()) {
			records.add(indexIterator.next());
		}
		return records;
	}

}
