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

import static ghidra.program.database.data.EnumSignedState.*;

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
	private SortedMap<Long, List<String>> valueMap; // value to names
	private Map<String, String> commentMap; // name to comment
	private List<BitGroup> bitGroups;
	private EnumSignedState signedState = null;

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
		signedState = computeSignedness();
	}

	private EnumSignedState computeSignedness() {
		int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);

		if (valueMap.isEmpty()) {
			return NONE;
		}

		long minValue = valueMap.firstKey();
		long maxValue = valueMap.lastKey();

		if (minValue < 0) {
			return SIGNED;
		}
		if (maxValue > getMaxPossibleValue(length, true)) {
			return UNSIGNED;
		}

		return NONE;		// we have no negatives and no large unsigned values
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
	public String[] getNames(long value) {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			List<String> list = valueMap.get(value);
			if (list == null || list.isEmpty()) {
				return new String[0];
			}
			return list.toArray(new String[0]);
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
			initializeIfNeeded();
			checkValue(value);
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
			signedState = computeSignedness();
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
		int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
		if (length == 8) {
			return; // all long values permitted
		}

		long min = getMinPossibleValue();
		long max = getMaxPossibleValue();
		if (value < min || value > max) {
			throw new IllegalArgumentException(
				"Attempted to add a value outside the range for this enum: (" + min + ", " + max +
					"): " + value);
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
			signedState = computeSignedness();
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
			signedState = computeSignedness();
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
		if (dtm == getDataTypeManager()) {
			return this;
		}
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
	public int getAlignedLength() {
		return getLength();
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
					part = Long.toHexString(subValue).toUpperCase() + 'h';
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
	public long getMinPossibleValue() {
		lock.acquire();
		try {
			checkIsValid();
			int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
			return getMinPossibleValue(length, signedState != UNSIGNED);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public long getMaxPossibleValue() {
		lock.acquire();
		try {
			checkIsValid();
			int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
			return getMaxPossibleValue(length, signedState == SIGNED);
		}
		finally {
			lock.release();
		}
	}

	private long getMaxPossibleValue(int bytes, boolean allowNegativeValues) {
		if (bytes == 8) {
			return Long.MAX_VALUE;
		}
		int bits = bytes * 8;
		if (allowNegativeValues) {
			bits -= 1;  // take away 1 bit for the sign
		}

		// the largest value that can be held in n bits in 2^n -1
		return (1L << bits) - 1;
	}

	private long getMinPossibleValue(int bytes, boolean allowNegativeValues) {
		if (!allowNegativeValues) {
			return 0;
		}
		int bits = bytes * 8;

		// smallest value (largest negative) that can be stored in n bits is when the sign bit
		// is on (and sign extended), and all less significant bits are 0
		return -1L << (bits - 1);
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

	@Override
	public boolean contains(String name) {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			return nameMap.containsKey(name);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean contains(long value) {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			return valueMap.containsKey(value);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isSigned() {
		lock.acquire();
		try {
			checkIsValid();
			initializeIfNeeded();
			return signedState == SIGNED;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getMinimumPossibleLength() {
		lock.acquire();
		try {
			if (valueMap.isEmpty()) {
				return 1;
			}
			long minValue = valueMap.firstKey();
			long maxValue = valueMap.lastKey();
			boolean hasNegativeValues = minValue < 0;

			// check the min and max values in this enum to see if they fit in 1 byte enum, then 
			// 2 byte enum, then 4 byte enum. If the min min and max values fit, then all other values
			// will fit as well
			for (int size = 1; size < 8; size *= 2) {
				long minPossible = getMinPossibleValue(size, hasNegativeValues);
				long maxPossible = getMaxPossibleValue(size, hasNegativeValues);
				if (minValue >= minPossible && maxValue <= maxPossible) {
					return size;
				}
			}
			return 8;
		}
		finally {
			lock.release();
		}
	}
}
