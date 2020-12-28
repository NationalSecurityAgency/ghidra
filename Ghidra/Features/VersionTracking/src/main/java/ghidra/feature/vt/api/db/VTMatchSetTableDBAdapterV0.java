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

import static ghidra.feature.vt.api.db.VTMatchSetTableDBAdapter.ColumnDescription.*;

import java.io.IOException;
import java.io.StringWriter;

import org.jdom.Element;
import org.jdom.output.XMLOutputter;

import db.*;
import ghidra.feature.vt.api.main.VTProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.VersionException;
import ghidra.util.xml.GenericXMLOutputter;

public class VTMatchSetTableDBAdapterV0 extends VTMatchSetTableDBAdapter {

	private Table table;

	private static final Schema STORED_ADDRESS_RANGE_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE }, new String[] { "addr1", "addr2" });

	private final DBHandle dbHandle;

	public VTMatchSetTableDBAdapterV0(DBHandle dbHandle) throws IOException {
		this.dbHandle = dbHandle;
		table = dbHandle.createTable(TABLE_NAME, TABLE_SCHEMA);
	}

	public VTMatchSetTableDBAdapterV0(DBHandle dbHandle, OpenMode openMode)
			throws VersionException {
		this.dbHandle = dbHandle;
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
	public DBRecord createMatchSetRecord(long key, VTProgramCorrelator correlator)
			throws IOException {
		DBRecord record = TABLE_SCHEMA.createRecord(key);

		record.setString(CORRELATOR_CLASS_COL.column(), correlator.getClass().getName());
		record.setString(CORRELATOR_NAME_COL.column(), correlator.getName());
		record.setString(OPTIONS_COL.column(), getOptionsString(correlator));
		createSourceAddressSetTable(correlator, record);
		createDestinationAddressSetTable(correlator, record);
		table.putRecord(record);
		return record;
	}

	private String getOptionsString(VTProgramCorrelator correlator) {
		ToolOptions options = correlator.getOptions();
		if (options.getOptionNames().isEmpty()) {
			return null;
		}
		Element optionsElement = options.getXmlRoot(true);

		XMLOutputter xmlout = new GenericXMLOutputter();
		StringWriter writer = new StringWriter();
		try {
			xmlout.output(optionsElement, writer);
			return writer.toString();
		}
		catch (IOException ioe) {
		}
		return null;
	}

	private void createSourceAddressSetTable(VTProgramCorrelator correlator, DBRecord record)
			throws IOException {

		Program program = correlator.getSourceProgram();
		AddressSetView addressSet = correlator.getSourceAddressSet();
		String tableName = getSourceTableName(record);

		writeAddressSet(addressSet, tableName, program.getAddressMap());
	}

	private void createDestinationAddressSetTable(VTProgramCorrelator correlator, DBRecord record)
			throws IOException {

		Program program = correlator.getDestinationProgram();
		AddressSetView addressSet = correlator.getDestinationAddressSet();
		String tableName = getDestinationTableName(record);

		writeAddressSet(addressSet, tableName, program.getAddressMap());
	}

	private String getSourceTableName(DBRecord record) {
		return "Source Address Set " + record.getKey();
	}

	private String getDestinationTableName(DBRecord record) {
		return "Destination Address Set " + record.getKey();
	}

	@Override
	public RecordIterator getRecords() throws IOException {
		return table.iterator();
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	private void writeAddressSet(AddressSetView set, String tableName, AddressMap addressMap)
			throws IOException {

		if (set != null) {
			Table addressSetTable = dbHandle.createTable(tableName, STORED_ADDRESS_RANGE_SCHEMA);
			DBRecord rec = STORED_ADDRESS_RANGE_SCHEMA.createRecord(0);
			int rangeKey = 1;
			for (KeyRange range : addressMap.getKeyRanges(set, false, false)) {
				rec.setKey(rangeKey++);
				rec.setLongValue(0, range.minKey);
				rec.setLongValue(1, range.maxKey);
				addressSetTable.putRecord(rec);
			}
		}
	}

	@Override
	public AddressSet getDestinationAddressSet(DBRecord record, AddressMap addressMap)
			throws IOException {
		return readAddressSet(record, getDestinationTableName(record), addressMap);
	}

	@Override
	public AddressSet getSourceAddressSet(DBRecord record, AddressMap addressMap) throws IOException {
		return readAddressSet(record, getSourceTableName(record), addressMap);
	}

	private AddressSet readAddressSet(DBRecord record, String tableName, AddressMap addressMap)
			throws IOException {

		Table addressSetTable = dbHandle.getTable(tableName);
		if (addressSetTable == null) {
			return null;
		}

		AddressSet addressSet = new AddressSet();

		RecordIterator it = addressSetTable.iterator();
		while (it.hasNext()) {
			DBRecord rec = it.next();
			Address addr1 = addressMap.decodeAddress(rec.getLongValue(0));
			Address addr2 = addressMap.decodeAddress(rec.getLongValue(1));
			addressSet.addRange(addr1, addr2);
		}
		return addressSet;
	}

	@Override
	public long getNextMatchSetID() {
		return table.getKey();
	}
}
