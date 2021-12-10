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

import org.apache.commons.lang3.StringUtils;

import db.DBRecord;
import db.Field;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;

/**
 * Database implementation for the enumerated data type.
 */
class EnumDB extends DataTypeDB implements Enum {

	private static final SettingsDefinition[] ENUM_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private EnumDBAdapter adapter;
	private EnumValueDBAdapter valueAdapter;

	private Map<String, Long> nameMap; // name to value
	private TreeMap<Long, List<String>> valueMap; // value to names
	private Map<String, String> commentMap; // name to comment
	private List<BitGroup> bitGroups;

	EnumDB(DataTypeManagerDB dataMgr, DBObjectCache<DataTypeDB> cache, EnumDBAdapter adapter,
			EnumValueDBAdapter valueAdapter, DBRecord record) {
		super(dataMgr, cache, record);
		this.adapter = adapter;
		this.valueAdapter = valueAdapter;
	}

	@Override
	protected long doGetCategoryID() {
		return record.getLongValue(EnumDBAdapter.ENUM_CAT_COL);
	}

	@Override
	protected String doGetName() {
		return record.getString(EnumDBAdapter.ENUM_NAME_COL);
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return ENUM_SETTINGS_DEFINITIONS;
	}

	private void initializeIfNeeded() {
		if (nameMap != null) {
			return;
		}
		try {
			initialize();
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	private void initialize() throws IOException {
		bitGroups = null;
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();

		Field[] ids = valueAdapter.getValueIdsInEnum(key);
		for (Field id : ids) {
			DBRecord rec = valueAdapter.getRecord(id.getLongValue());
			String valueName = rec.getString(EnumValueDBAdapter.ENUMVAL_NAME_COL);
			long value = rec.getLongValue(EnumValueDBAdapter.ENUMVAL_VALUE_COL);
			String comment = rec.getString(EnumValueDBAdapter.ENUMVAL_COMMENT_COL);
			addToCache(valueName, value, comment);
		}
	}

	private void addToCache(String valueName, long value, String comment) {
		nameMap.put(valueName, value);
		List<String> list = valueMap.computeIfAbsent(value, v -> new ArrayList<>());
		list.add(valueName);
		if (!StringUtils.isBlank(comment)) {
			commentMap.put(valueName, comment);
		}
	}

	private boolean removeFromCache(String valueName) {
		Long value = nameMap.remove(valueName);
		if (value == null) {
			return false;
		}
		List<String> list = valueMap.get(value);
		Iterator<String> iter = list.iterator();
		while (iter.hasNext()) {
			if (valueName.equals(iter.next())) {
				iter.remove();
				break;
			}
		}
		if (list.isEmpty()) {
			valueMap.remove(value);
		}
		commentMap.remove(valueName);
		return true;
	}

	@Override
	public long getValue(String valueName) throws NoSuchElementException {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			Long value = nameMap.get(valueName);
			if (value == null) {
				throw new NoSuchElementException("No value for " + valueName);
			}
			return value;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getName(long value) {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			List<String> list = valueMap.get(value);
			if (list == null || list.isEmpty()) {
				return null;
			}
			return list.get(0);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return false;
	}

	@Override
	public String getComment(String valueName) {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			String comment = commentMap.get(valueName);
			if (comment == null) {
				comment = "";
			}
			return comment;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public long[] getValues() {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			return valueMap.keySet().stream().mapToLong(Long::longValue).toArray();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String[] getNames() {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();

			// names are first sorted by int value, then sub-sorted by name value
			List<String> names = new ArrayList<>();
			Collection<List<String>> values = valueMap.values();
			for (List<String> list : values) {
				Collections.sort(list);
				names.addAll(list);
			}
			return names.toArray(new String[0]);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getCount() {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			return nameMap.size();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void add(String valueName, long value) {
		add(valueName, value, null);
	}

	@Override
	public void add(String valueName, long value, String comment) {
		lock.acquire();
		try {
			checkDeleted();
			checkValue(value);
			initializeIfNeeded();
			if (nameMap.containsKey(valueName)) {
				throw new IllegalArgumentException(valueName + " already exists in this enum");
			}

			if (StringUtils.isBlank(comment)) {
				comment = null; // use null values in the db to save space
			}

			bitGroups = null;
			valueAdapter.createRecord(key, valueName, value, comment);
			adapter.updateRecord(record, true);
			addToCache(valueName, value, comment);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void checkValue(long value) {
		int length = getLength();
		if (length == 8) {
			return; // all long values permitted
		}
		// compute maximum enum value as a positive value: (2^length)-1
		long max = (1L << (getLength() * 8)) - 1;
		if (value > max) {
			throw new IllegalArgumentException(
				getName() + " enum value 0x" + Long.toHexString(value) +
					" is outside the range of 0x0 to 0x" + Long.toHexString(max));

		}
	}

	@Override
	public void remove(String valueName) {
		lock.acquire();
		try {
			checkDeleted();
			initializeIfNeeded();
			if (!removeFromCache(valueName)) {
				return;
			}

			bitGroups = null;
			Field[] ids = valueAdapter.getValueIdsInEnum(key);
			for (Field id : ids) {
				DBRecord rec = valueAdapter.getRecord(id.getLongValue());
				if (valueName.equals(rec.getString(EnumValueDBAdapter.ENUMVAL_NAME_COL))) {
					valueAdapter.removeRecord(id.getLongValue());
					break;
				}
			}
			adapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}

		Enum enumm = (Enum) dataType;
		lock.acquire();
		try {
			checkDeleted();

			bitGroups = null;
			nameMap = new HashMap<>();
			valueMap = new TreeMap<>();
			commentMap = new HashMap<>();

			Field[] ids = valueAdapter.getValueIdsInEnum(key);
			for (Field id : ids) {
				valueAdapter.removeRecord(id.getLongValue());
			}

			int oldLength = getLength();
			int newLength = enumm.getLength();
			if (oldLength != newLength) {
				record.setByteValue(EnumDBAdapter.ENUM_SIZE_COL, (byte) newLength);
				adapter.updateRecord(record, true);
			}

			String[] names = enumm.getNames();
			for (String valueName : names) {
				long value = enumm.getValue(valueName);
				String comment = enumm.getComment(valueName);
				if (StringUtils.isBlank(comment)) {
					comment = null; // use null values in the db to save space
				}
				valueAdapter.createRecord(key, valueName, value, comment);
				adapter.updateRecord(record, true);
				addToCache(valueName, value, comment);
			}

			if (oldLength != newLength) {
				notifySizeChanged(false);
			}
			else {
				dataMgr.dataTypeChanged(this, false);
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

	@Override
	public void setDescription(String description) {
		lock.acquire();
		try {
			checkDeleted();
			record.setString(EnumDBAdapter.ENUM_COMMENT_COL, description);
			adapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}

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
		StringBuilder buf = new StringBuilder();
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
			bitGroups = EnumValuePartitioner.partition(getValues(), getLength());
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

	@Override
	public boolean isEquivalent(DataType dt) {
		if (dt == this) {
			return true;
		}
		if (dt == null || !(dt instanceof Enum)) {
			return false;
		}

		Enum enumm = (Enum) dt;
		if (!DataTypeUtilities.equalsIgnoreConflict(getName(), enumm.getName()) ||
			getLength() != enumm.getLength() || getCount() != enumm.getCount()) {
			return false;
		}

		if (!isEachValueEquivalent(enumm)) {
			return false;
		}
		return true;
	}

	private boolean isEachValueEquivalent(Enum enumm) {
		String[] names = getNames();
		String[] otherNames = enumm.getNames();
		try {
			for (int i = 0; i < names.length; i++) {
				if (!names[i].equals(otherNames[i])) {
					return false;
				}

				long value = getValue(names[i]);
				long otherValue = enumm.getValue(names[i]);
				if (value != otherValue) {
					return false;
				}

				String comment = getComment(names[i]);
				String otherComment = enumm.getComment(names[i]);
				if (!comment.equals(otherComment)) {
					return false;
				}
			}
			return true;
		}
		catch (NoSuchElementException e) {
			return false; // named element not found
		}
	}

	@Override
	protected boolean refresh() {
		try {
			nameMap = null;
			valueMap = null;
			commentMap = null;
			bitGroups = null;
			DBRecord rec = adapter.getRecord(key);
			if (rec != null) {
				record = rec;
				return super.refresh();
			}
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		return false;
	}

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

	@Override
	public void dataTypeDeleted(DataType dt) {
		// not applicable
	}

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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
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
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
		finally {
			lock.release();
		}
	}
}
