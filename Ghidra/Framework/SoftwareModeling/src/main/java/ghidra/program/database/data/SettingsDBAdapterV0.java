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
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import db.*;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 0 implementation for the accessing the data type settings database table.
 * This version stored settings name as a string within each record.
 */
class SettingsDBAdapterV0 extends SettingsDBAdapter {

	// Default Settings Columns
	static final int V0_SETTINGS_ASSOCIATION_ID_COL = 0; // e.g., Address-key, Datatype-ID
	static final int V0_SETTINGS_NAME_COL = 1; // string - must translate to short index with name map
	static final int V0_SETTINGS_LONG_VALUE_COL = 2;
	static final int V0_SETTINGS_STRING_VALUE_COL = 3;
	// static final int V0_SETTINGS_BYTE_VALUE_COL = 4; // discarded during V1 upgrade

	private static final int V0_SCHEMA_VERSION = 0;

//  Keep for reference
//	static final Schema V0_SETTINGS_SCHEMA = new Schema(0, "SettingsID",
//		new Field[] { LongField.INSTANCE, StringField.INSTANCE, LongField.INSTANCE,
//			StringField.INSTANCE, BinaryField.INSTANCE },
//		new String[] { "AssociationID", "Settings Name", "Long Value", "String Value",
//			"Byte Value" });

	private Table settingsTable;

	private HashMap<Short, String> nameIndexMap = new HashMap<>();
	private HashMap<String, Short> nameStringMap = new HashMap<>();

	SettingsDBAdapterV0(String tableName, DBHandle handle)
			throws VersionException {

		settingsTable = handle.getTable(tableName);
		if (settingsTable == null) {
			throw new VersionException("Missing Table: " + tableName);
		}
		int ver = settingsTable.getSchema().getVersion();
		if (ver != V0_SCHEMA_VERSION) {
			throw new VersionException(false);
		}
	}

	@Override
	String getTableName() {
		return settingsTable.getName();
	}

	@Override
	public DBRecord createSettingsRecord(long associationId, String name, String strValue,
			long longValue) throws IOException {
		throw new ReadOnlyException();
	}

	@Override
	public Field[] getSettingsKeys(long associationId) throws IOException {
		return settingsTable.findRecords(new LongField(associationId),
			V0_SETTINGS_ASSOCIATION_ID_COL);
	}

	@Override
	void removeAllSettingsRecords(long associationId) throws IOException {
		for (Field key : getSettingsKeys(associationId)) {
			removeSettingsRecord(key.getLongValue());
		}
	}

	@Override
	public boolean removeSettingsRecord(long settingsID) throws IOException {
		throw new ReadOnlyException();
	}

	@Override
	boolean removeSettingsRecord(long associationId, String name) throws IOException {
		throw new ReadOnlyException();
	}

	@Override
	String[] getSettingsNames(long associationId) throws IOException {
		ArrayList<String> list = new ArrayList<>();
		for (Field key : getSettingsKeys(associationId)) {
			DBRecord rec = settingsTable.getRecord(key);
			list.add(rec.getString(V0_SETTINGS_NAME_COL));
		}
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	@Override
	void addAllValues(String name, Set<String> set) throws IOException {
		RecordIterator recIter = settingsTable.iterator();
		while (recIter.hasNext()) {
			DBRecord rec = recIter.next();
			if (name.equals(rec.getString(V0_SETTINGS_NAME_COL))) {
				String s = rec.getString(V0_SETTINGS_STRING_VALUE_COL);
				if (!StringUtils.isBlank(s)) {
					set.add(s);
				}
			}
		}
	}

	@Override
	protected String getSettingName(DBRecord normalizedRecord) {
		short nameIndex = normalizedRecord.getShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL);
		return nameIndexMap.get(nameIndex);
	}

	@Override
	void invalidateNameCache() {
		// ignore - name map values can be retained
	}

	private short assignNameIndexValue(String name) {
		Short index = nameStringMap.get(name);
		if (index == null) {
			index = (short) nameStringMap.size();
			nameStringMap.put(name, index);
			nameIndexMap.put(index, name);
		}
		return index;
	}

	@Override
	public DBRecord getSettingsRecord(long settingsID) throws IOException {
		return translateV0Record(settingsTable.getRecord(settingsID));
	}

	@Override
	DBRecord getSettingsRecord(long associationId, String name) throws IOException {
		for (Field key : getSettingsKeys(associationId)) {
			DBRecord rec = settingsTable.getRecord(key);
			if (rec.getString(V0_SETTINGS_NAME_COL).equals(name)) {
				return translateV0Record(rec);
			}
		}
		return null;
	}

	@Override
	public void updateSettingsRecord(DBRecord record) throws IOException {
		throw new ReadOnlyException();
	}

	@Override
	DBRecord updateSettingsRecord(long associationId, String name, String strValue, long longValue)
			throws IOException {
		throw new ReadOnlyException();
	}

	@Override
	int getRecordCount() {
		return settingsTable.getRecordCount();
	}

	@Override
	RecordIterator getRecords() throws IOException {
		return new TranslatedRecordIterator(settingsTable.iterator(), r -> translateV0Record(r));
	}

	@Override
	RecordIterator getRecords(long minAssociationId, long maxAssociationId) throws IOException {
		return settingsTable.indexIterator(V0_SETTINGS_ASSOCIATION_ID_COL, new LongField(minAssociationId),
			new LongField(maxAssociationId), true);
	}

	@Override
	void delete(long minAssociationId, long maxAssociationId, TaskMonitor monitor) throws CancelledException, IOException {
		throw new ReadOnlyException();
	}

	private DBRecord translateV0Record(DBRecord rec) {
		if (rec == null) {
			return null;
		}
		DBRecord normalizedRecord =
			SettingsDBAdapterV1.V1_SETTINGS_SCHEMA.createRecord(rec.getKey());
		normalizedRecord.setLongValue(SETTINGS_ASSOCIATION_ID_COL,
			rec.getLongValue(V0_SETTINGS_ASSOCIATION_ID_COL));
		String name = rec.getString(V0_SETTINGS_NAME_COL);
		normalizedRecord.setShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL,
			assignNameIndexValue(name));
		normalizedRecord.setLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL,
			rec.getLongValue(V0_SETTINGS_LONG_VALUE_COL));
		normalizedRecord.setString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL,
			rec.getString(V0_SETTINGS_STRING_VALUE_COL));
		return normalizedRecord;
	}

}
