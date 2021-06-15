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

import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.ADDRESS_SOURCE_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.ASSOCIATION_KEY_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.DESTINATION_ADDRESS_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.MARKUP_TYPE_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.ORIGINAL_DESTINATION_VALUE_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.SOURCE_ADDRESS_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.SOURCE_VALUE_COL;
import static ghidra.feature.vt.api.db.VTMatchMarkupItemTableDBAdapter.MarkupTableDescriptor.STATUS_COL;
import ghidra.feature.vt.api.impl.MarkupItemStorage;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.api.markuptype.VTMarkupTypeFactory;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

public class VTMatchMarkupItemTableDBAdapterV0 extends VTMatchMarkupItemTableDBAdapter {

	private Table table;

	public VTMatchMarkupItemTableDBAdapterV0(DBHandle dbHandle) throws IOException {
		table = dbHandle.createTable(TABLE_NAME, TABLE_SCHEMA, INDEXED_COLUMNS);
	}

	public VTMatchMarkupItemTableDBAdapterV0(DBHandle dbHandle, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
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
	public DBRecord createMarkupItemRecord(MarkupItemStorage markupItem) throws IOException {

		DBRecord record = TABLE_SCHEMA.createRecord(table.getKey());

		VTAssociationDB association = (VTAssociationDB) markupItem.getAssociation();
		VTSession manager = association.getSession();

		Program sourceProgram = manager.getSourceProgram();
		Program destinationProgram = manager.getDestinationProgram();

		record.setLongValue(ASSOCIATION_KEY_COL.column(), association.getKey());
		record.setString(ADDRESS_SOURCE_COL.column(), markupItem.getDestinationAddressSource());
		record.setLongValue(SOURCE_ADDRESS_COL.column(), getAddressID(sourceProgram,
			markupItem.getSourceAddress()));

		Address destinationAddress = markupItem.getDestinationAddress();
		if (destinationAddress != null) {
			record.setLongValue(DESTINATION_ADDRESS_COL.column(), getAddressID(destinationProgram,
				markupItem.getDestinationAddress()));
		}
		record.setShortValue(MARKUP_TYPE_COL.column(),
			(short) VTMarkupTypeFactory.getID(markupItem.getMarkupType()));
		record.setString(SOURCE_VALUE_COL.column(), Stringable.getString(
			markupItem.getSourceValue(), sourceProgram));
		record.setString(ORIGINAL_DESTINATION_VALUE_COL.column(), Stringable.getString(
			markupItem.getDestinationValue(), destinationProgram));
		record.setByteValue(STATUS_COL.column(), (byte) markupItem.getStatus().ordinal());

		table.putRecord(record);
		return record;
	}

	private long getAddressID(Program program, Address address) {
		AddressMap addressMap = program.getAddressMap();
		return addressMap.getKey(address, false);
	}

	@Override
	public void removeMatchMarkupItemRecord(long key) throws IOException {
		table.deleteRecord(key);
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public RecordIterator getRecords(long associationKey) throws IOException {
		LongField longField = new LongField(associationKey);
		return table.indexIterator(ASSOCIATION_KEY_COL.column(), longField, longField, true);
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	void updateRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public int getRecordCount() {
		return table.getRecordCount();
	}
}
