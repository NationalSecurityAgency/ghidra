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

import static ghidra.feature.vt.api.db.VTAssociationTableDBAdapter.AssociationTableDescriptor.*;
import ghidra.feature.vt.api.main.VTAssociationStatus;
import ghidra.feature.vt.api.main.VTAssociationType;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import db.*;

public class VTAssociationTableDBAdapterV0 extends VTAssociationTableDBAdapter {

	private Table table;

	public VTAssociationTableDBAdapterV0(DBHandle dbHandle) throws IOException {
		table = dbHandle.createTable(TABLE_NAME, TABLE_SCHEMA, TABLE_INDEXES);
	}

	public VTAssociationTableDBAdapterV0(DBHandle dbHandle, OpenMode openMode, TaskMonitor monitor)
			throws VersionException {
		table = dbHandle.getTable(TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException("Expected version 0 for table " + TABLE_NAME + " but got " +
				table.getSchema().getVersion());
		}
	}

	@Override
	DBRecord insertRecord(long sourceAddressID, long destinationAddressID, VTAssociationType type,
			VTAssociationStatus lockedStatus, int voteCount) throws IOException {
		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());
		record.setLongValue(SOURCE_ADDRESS_COL.column(), sourceAddressID);
		record.setLongValue(DESTINATION_ADDRESS_COL.column(), destinationAddressID);
		record.setByteValue(TYPE_COL.column(), (byte) type.ordinal());
		record.setByteValue(STATUS_COL.column(), (byte) lockedStatus.ordinal());
		record.setIntValue(VOTE_COUNT_COL.column(), voteCount);
		table.putRecord(record);
		return record;
	}

	@Override
	void deleteRecord(long key) throws IOException {
		table.deleteRecord(key);
	}

	@Override
	DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	RecordIterator getRecordsForDestinationAddress(long addressID) throws IOException {
		LongField longField = new LongField(addressID);
		return table.indexIterator(DESTINATION_ADDRESS_COL.column(), longField, longField, true);
	}

	@Override
	RecordIterator getRecordsForSourceAddress(long addressID) throws IOException {
		LongField longField = new LongField(addressID);
		return table.indexIterator(SOURCE_ADDRESS_COL.column(), longField, longField, true);
	}

	@Override
	Set<DBRecord> getRelatedAssociationRecordsBySourceAndDestinationAddress(long sourceAddressID,
			long destinationAddressID) throws IOException {
		Set<DBRecord> recordSet = new HashSet<DBRecord>();

		RecordIterator iterator = getRecordsForSourceAddress(sourceAddressID);
		while (iterator.hasNext()) {
			recordSet.add(iterator.next());
		}

		iterator = getRecordsForDestinationAddress(destinationAddressID);
		while (iterator.hasNext()) {
			recordSet.add(iterator.next());
		}

		return recordSet;
	}

	@Override
	Set<DBRecord> getRelatedAssociationRecordsBySourceAddress(long sourceAddressID)
			throws IOException {
		Set<DBRecord> recordSet = new HashSet<DBRecord>();

		RecordIterator iterator = getRecordsForSourceAddress(sourceAddressID);
		while (iterator.hasNext()) {
			recordSet.add(iterator.next());
		}

		return recordSet;
	}

	@Override
	Set<DBRecord> getRelatedAssociationRecordsByDestinationAddress(long destinationAddressID)
			throws IOException {
		Set<DBRecord> recordSet = new HashSet<DBRecord>();

		RecordIterator iterator = getRecordsForDestinationAddress(destinationAddressID);
		while (iterator.hasNext()) {
			recordSet.add(iterator.next());
		}

		return recordSet;
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	void removeAssociaiton(long id) throws IOException {
		table.deleteRecord(id);
	}
}
