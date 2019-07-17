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
import java.math.BigInteger;
import java.util.*;

import db.Record;
import ghidra.docking.settings.Settings;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;
import ghidra.util.datastruct.LongObjectHashtable;
import ghidra.util.datastruct.ObjectLongHashtable;
import ghidra.util.exception.NoValueException;

/**
 * Database implementation for the enumerated data type.
 *
 */
class EnumDB extends DataTypeDB implements Enum {

	private EnumDBAdapter adapter;
	private EnumValueDBAdapter valueAdapter;
	private ObjectLongHashtable<String> nameMap;
	private LongObjectHashtable<String> valueMap;
	private List<BitGroup> bitGroups;

	EnumDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache, EnumDBAdapter adapter,
			EnumValueDBAdapter valueAdapter, Record record) throws IOException {
		super(dataMgr, cache, record);
		this.adapter = adapter;
		this.valueAdapter = valueAdapter;
		nameMap = new ObjectLongHashtable<>();
		valueMap = new LongObjectHashtable<>();
		initialize();
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(EnumDBAdapter.ENUM_CAT_COL);
	}

	@Override
	protected String doGetName() {
		return record.getString(EnumDBAdapter.ENUM_NAME_COL);
	}

	private void initialize() throws IOException {
		bitGroups = null;
		nameMap.removeAll();
		valueMap.removeAll();
		long[] ids = valueAdapter.getValueIdsInEnum(key);

		for (int i = 0; i < ids.length; i++) {
			Record rec = valueAdapter.getRecord(ids[i]);
			String valueName = rec.getString(EnumValueDBAdapter.ENUMVAL_NAME_COL);
			long value = rec.getLongValue(EnumValueDBAdapter.ENUMVAL_VALUE_COL);
			nameMap.put(valueName, value);
			valueMap.put(value, valueName);
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#getValue(java.lang.String)
	 */
	@Override
	public long getValue(String name) throws NoSuchElementException {
		lock.acquire();
		try {
			checkIsValid();
			return nameMap.get(name);
		}
		catch (NoValueException e) {
			throw new NoSuchElementException(name + " does not exist in this enum");
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#getName(long)
	 */
	@Override
	public String getName(long value) {
		lock.acquire();
		try {
			checkIsValid();
			return valueMap.get(value);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#isDynamicallySized()
	 */
	@Override
	public boolean isDynamicallySized() {
		return false;
	}

	/**
	 * @see ghidra.program.model.data.Enum#getValues()
	 */
	@Override
	public long[] getValues() {
		lock.acquire();
		try {
			checkIsValid();
			long[] values = valueMap.getKeys();
			Arrays.sort(values);
			return values;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#getNames()
	 */
	@Override
	public String[] getNames() {
		lock.acquire();
		try {
			checkIsValid();
			String[] names = nameMap.getKeys(new String[nameMap.size()]);
			Arrays.sort(names);
			return names;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#getCount()
	 */
	@Override
	public int getCount() {
		lock.acquire();
		try {
			checkIsValid();
			return nameMap.size();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#add(java.lang.String, long)
	 */
	@Override
	public void add(String name, long value) {
		lock.acquire();
		bitGroups = null;
		try {
			checkDeleted();
			if (nameMap.contains(name)) {
				throw new IllegalArgumentException(name + " already exists in this enum");
			}
			try {
				valueAdapter.createRecord(key, name, value);
				nameMap.put(name, value);
				if (!valueMap.contains(value)) {
					valueMap.put(value, name);
				}
				adapter.updateRecord(record, true);
				dataMgr.dataTypeChanged(this);
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#remove(java.lang.String)
	 */
	@Override
	public void remove(String name) {
		lock.acquire();
		bitGroups = null;
		try {
			checkDeleted();
			if (!nameMap.contains(name)) {
				return;
			}
			long value = nameMap.get(name);
			nameMap.remove(name);
			if (name.equals(valueMap.get(value))) {
				valueMap.remove(value);
			}
			long[] ids = valueAdapter.getValueIdsInEnum(key);

			for (int i = 0; i < ids.length; i++) {
				Record rec = valueAdapter.getRecord(ids[i]);
				if (name.equals(rec.getString(EnumValueDBAdapter.ENUMVAL_NAME_COL))) {
					valueAdapter.removeRecord(ids[i]);
					break;
				}
			}
			adapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		catch (NoValueException e) {
			// can't happen
		}
		finally {
			lock.release();
		}
	}

	/*
	 * @see ghidra.program.model.data.Enum#replace(ghidra.program.model.data.Enum)
	 */
	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}
		Enum enumm = (Enum) dataType;
		lock.acquire();
		bitGroups = null;
		try {
			checkDeleted();
			int oldLength = getLength();
			nameMap.removeAll();
			valueMap.removeAll();
			long[] ids = valueAdapter.getValueIdsInEnum(key);
			for (int i = 0; i < ids.length; i++) {
				valueAdapter.removeRecord(ids[i]);
			}
			String[] names = enumm.getNames();
			for (int i = 0; i < names.length; i++) {
				if (nameMap.contains(names[i])) {
					throw new IllegalArgumentException(names[i] + " already exists in this Enum");
				}
				long value = enumm.getValue(names[i]);
				valueAdapter.createRecord(key, names[i], value);
				nameMap.put(names[i], value);
				valueMap.put(value, names[i]);
			}

			int newLength = enumm.getLength();
			record.setByteValue(EnumDBAdapter.ENUM_SIZE_COL, (byte) newLength);
			adapter.updateRecord(record, true);

			if (oldLength != newLength) {
				notifySizeChanged();
			}
			else {
				dataMgr.dataTypeChanged(this);
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType copy(DataTypeManager dtm) {
		EnumDataType enumDataType =
			new EnumDataType(getCategoryPath(), getName(), getLength(), dtm);
		enumDataType.setDescription(getDescription());
		enumDataType.replaceWith(this);
		return enumDataType;
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		EnumDataType enumDataType =
			new EnumDataType(getCategoryPath(), getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		enumDataType.setDescription(getDescription());
		enumDataType.replaceWith(this);
		return enumDataType;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getMnemonic(ghidra.docking.settings.Settings)
	 */
	@Override
	public String getMnemonic(Settings settings) {
		lock.acquire();
		try {
			checkIsValid();
			return getDisplayName();
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getLength()
	 */
	@Override
	public int getLength() {
		lock.acquire();
		try {
			checkIsValid();
			return record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getDescription()
	 */
	@Override
	public String getDescription() {
		lock.acquire();
		try {
			checkIsValid();
			String s = record.getString(EnumDBAdapter.ENUM_COMMENT_COL);
			return s == null ? "" : s;
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Enum#setDescription(java.lang.String)
	 */
	@Override
	public void setDescription(String description) {
		lock.acquire();
		try {
			checkDeleted();
			record.setString(EnumDBAdapter.ENUM_COMMENT_COL, description);
			adapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.DataType#getValue(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		lock.acquire();
		try {
			checkIsValid();
			long value = 0;
			switch (getLength()) {
				case 1:
					value = buf.getByte(0);
					break;
				case 2:
					value = buf.getShort(0);
					break;
				case 4:
					value = buf.getInt(0);
					break;
				case 8:
					value = buf.getLong(0);
					break;
			}
			return new Scalar(length * 8, value);
		}
		catch (MemoryAccessException e) {
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Scalar.class;
	}

	/**
	 * @see ghidra.program.model.data.DataType#getRepresentation(ghidra.program.model.mem.MemBuffer, ghidra.docking.settings.Settings, int)
	 */
	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		lock.acquire();
		try {
			checkIsValid();
			long value = 0;

			switch (getLength()) {
				case 1:
					value = buf.getByte(0) & 0xffL;
					break;
				case 2:
					value = buf.getShort(0) & 0xffffL;
					break;
				case 4:
					value = buf.getInt(0) & 0xffffffffL;
					break;
				case 8:
					value = buf.getLong(0);
					break;
			}
			return getRepresentation(value);
		}
		catch (MemoryAccessException e) {
			return "??";
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getRepresentation(BigInteger bigInt, Settings settings, int bitLength) {
		return getRepresentation(bigInt.longValue());
	}

	private String getRepresentation(long value) {
		String valueName = getName(value);
		if (valueName == null) {
			valueName = getCompoundValue(value);
		}
		return valueName;
	}

	private String getCompoundValue(long value) {
		if (value == 0) {
			return "0";
		}
		List<BitGroup> list = getBitGroups();
		StringBuffer buf = new StringBuffer();
		for (BitGroup bitGroup : list) {
			long subValue = bitGroup.getMask() & value;
			if (subValue != 0) {
				String part = getName(subValue);
				if (part == null) {
					part = getStringForNoMatchingValue(subValue);
				}
				if (buf.length() != 0) {
					buf.append(" | ");
				}
				buf.append(part);
			}
		}
		return buf.toString();
	}

	private List<BitGroup> getBitGroups() {
		if (bitGroups == null) {
			bitGroups = EnumValuePartitioner.partition(getValues());
		}
		return bitGroups;
	}

	private String getStringForNoMatchingValue(long value) {
		String valueName;
		String valueStr;
		if (value < 0 || value >= 32) {
			valueStr = "0x" + Long.toHexString(value);
		}
		else {
			valueStr = Long.toString(value);
		}
		valueName = "" + valueStr;
		return valueName;
	}

	/**
	 * @see ghidra.program.model.data.DataType#isEquivalent(ghidra.program.model.data.DataType)
	 */
	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null || !(dt instanceof Enum)) {
			return false;
		}

		checkIsValid();
		Enum enumm = (Enum) dt;
		if (!DataTypeUtilities.equalsIgnoreConflict(getName(), enumm.getName()) ||
			getLength() != enumm.getLength() || getCount() != enumm.getCount()) {
			return false;
		}
		String[] names = getNames();
		String[] otherNames = enumm.getNames();
		try {
			for (int i = 0; i < names.length; i++) {
				long value = getValue(names[i]);
				long otherValue = enumm.getValue(names[i]);
				if (!names[i].equals(otherNames[i]) || value != otherValue) {
					return false;
				}
			}
		}
		catch (NoSuchElementException e) {
			return false; // named element not found
		}
		return true;
	}

	/**
	 * @see ghidra.program.database.DatabaseObject#refresh()
	 */
	@Override
	protected boolean refresh() {
		try {
			Record rec = adapter.getRecord(key);
			if (rec != null) {
				record = rec;
				initialize();
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeReplaced(ghidra.program.model.data.DataType, ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
		// not applicable
	}

	@Override
	protected void doSetCategoryPathRecord(long categoryID) throws IOException {
		record.setLongValue(EnumDBAdapter.ENUM_CAT_COL, categoryID);
		adapter.updateRecord(record, false);
	}

	@Override
	protected void doSetNameRecord(String name) throws IOException {
		record.setString(EnumDBAdapter.ENUM_NAME_COL, name);
		adapter.updateRecord(record, true);
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeDeleted(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeDeleted(DataType dt) {
		// not applicable
	}

	/**
	 * @see ghidra.program.model.data.DataType#dataTypeNameChanged(ghidra.program.model.data.DataType, java.lang.String)
	 */
	@Override
	public void dataTypeNameChanged(DataType dt, String oldName) {
		// not applicable
	}

	@Override
	public String getDefaultLabelPrefix() {
		return getName();
	}

	@Override
	public long getLastChangeTime() {
		return record.getLongValue(EnumDBAdapter.ENUM_LAST_CHANGE_TIME_COL);
	}

	@Override
	public long getLastChangeTimeInSourceArchive() {
		return record.getLongValue(EnumDBAdapter.ENUM_SOURCE_SYNC_TIME_COL);
	}

	@Override
	public UniversalID getUniversalID() {
		return new UniversalID(record.getLongValue(EnumDBAdapter.ENUM_UNIVERSAL_DT_ID_COL));
	}

	@Override
	protected void setUniversalID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_UNIVERSAL_DT_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return new UniversalID(record.getLongValue(EnumDBAdapter.ENUM_SOURCE_ARCHIVE_ID_COL));
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_SOURCE_ARCHIVE_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_LAST_CHANGE_TIME_COL, lastChangeTime);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		lock.acquire();
		try {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_SOURCE_SYNC_TIME_COL,
				lastChangeTimeInSourceArchive);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

}
