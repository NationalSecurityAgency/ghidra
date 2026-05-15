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
import java.util.List;
import java.util.NoSuchElementException;

import org.apache.commons.lang3.StringUtils;

import db.DBRecord;
import db.Field;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.data.Enum;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Lock.Closeable;
import ghidra.util.UniversalID;

/**
 * Database implementation for the enumerated data type.
 */
class EnumDB extends DataTypeDB implements Enum {
	private static final SettingsDefinition[] ENUM_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private EnumDBAdapter adapter;
	private EnumValueDBAdapter valueAdapter;
	private EnumValues lazyEnumValues;
	private List<BitGroup> bitGroups; // lazy initialization

	/**
	 * Constructor
	 * @param dataMgr the datatypes manager
	 * @param adapter the enum database adapter
	 * @param valueAdapter the enum values database adapter
	 * @param record the enum record
	 */
	EnumDB(DataTypeManagerDB dataMgr, EnumDBAdapter adapter,
			EnumValueDBAdapter valueAdapter, DBRecord record) {
		super(dataMgr, record);
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

	private EnumValues getEnumValues() {
		EnumValues local = lazyEnumValues;
		if (local == null) {
			try {
				local = new EnumValues(this, valueAdapter);
				lazyEnumValues = local;
			}
			catch (IOException e) {
				dataMgr.dbError(e);
			}
		}
		return local;

	}

	@Override
	public long getValue(String valueName) throws NoSuchElementException {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getValue(valueName);
		}
	}

	@Override
	public String getName(long value) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getName(value);
		}
	}

	@Override
	public String[] getNames(long value) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getNames(value);
		}
	}

	@Override
	public boolean hasLanguageDependantLength() {
		return false;
	}

	@Override
	public String getComment(String valueName) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getComment(valueName);
		}
	}

	@Override
	public long[] getValues() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getValues();
		}
	}

	@Override
	public String[] getNames() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getNames();
		}
	}

	@Override
	public int getCount() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.size();
		}
	}

	@Override
	public void add(String valueName, long value) {
		add(valueName, value, null);
	}

	@Override
	public void add(String valueName, long value, String comment) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			EnumValues enumValues = getEnumValues();
			if (enumValues.containsName(valueName)) {
				throw new IllegalArgumentException(valueName + " already exists in this enum");
			}
			checkValue(value);
			bitGroups = null;

			if (StringUtils.isBlank(comment)) {
				comment = null; // use null values in the db to save space
			}

			valueAdapter.createRecord(key, valueName, value, comment);
			adapter.updateRecord(record, true);
			enumValues.addValue(valueName, value, comment);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
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
		try (Closeable c = lock.write()) {
			checkDeleted();
			lazyEnumValues = null;
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
	}

	@Override
	public void replaceWith(DataType dataType) {
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}

		Enum enumm = (Enum) dataType;
		try (Closeable c = lock.write()) {
			checkDeleted();

			bitGroups = null;
			lazyEnumValues = null;
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
	public Enum clone(DataTypeManager dtm) {
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
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return getDisplayName();
		}
	}

	@Override
	public int getLength() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
		}
	}

	@Override
	public int getAlignedLength() {
		return getLength();
	}

	@Override
	public String getDescription() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			String s = record.getString(EnumDBAdapter.ENUM_COMMENT_COL);
			return s == null ? "" : s;
		}
	}

	@Override
	public void setDescription(String description) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			record.setString(EnumDBAdapter.ENUM_COMMENT_COL, description);
			adapter.updateRecord(record, true);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int length) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
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
	}

	@Override
	public Class<?> getValueClass(Settings settings) {
		return Scalar.class;
	}

	@Override
	public String getRepresentation(MemBuffer buf, Settings settings, int length) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
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
	}

	@Override
	public String getRepresentation(BigInteger bigInt, Settings settings, int bitLength) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return getRepresentation(bigInt.longValue());
		}
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
	protected boolean isEquivalent(DataType dt, DataTypeConflictHandler handler) {
		if (dt == this) {
			return true;
		}
		if (dt == null || !(dt instanceof Enum)) {
			return false;
		}

		Enum enumm = (Enum) dt;
		if (!DataTypeUtilities.equalsIgnoreConflict(getName(), enumm.getName())) {
			return false;
		}

		if (handler != null &&
			ConflictResult.USE_EXISTING == handler.resolveConflict(enumm, this)) {
			// treat this type as equivalent if existing type will be used
			return true;
		}

		if (getLength() != enumm.getLength() || getCount() != enumm.getCount()) {
			return false;
		}

		return isEachValueEquivalent(enumm);
	}

	@Override
	public boolean isEquivalent(DataType dt) {
		return isEquivalent(dt, null);
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
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
			return getMinPossibleValue(length, enumValues.getSignedState() != UNSIGNED);
		}
	}

	@Override
	public long getMaxPossibleValue() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			int length = record.getByteValue(EnumDBAdapter.ENUM_SIZE_COL);
			return getMaxPossibleValue(length, enumValues.getSignedState() == SIGNED);
		}
	}

	@Override
	protected boolean refresh() {
		try {
			lazyEnumValues = null;
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
	public void dataTypeReplaced(DataType oldDt, DataType newDt) {
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
		try (Closeable c = lock.write()) {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_UNIVERSAL_DT_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	protected UniversalID getSourceArchiveID() {
		return new UniversalID(record.getLongValue(EnumDBAdapter.ENUM_SOURCE_ARCHIVE_ID_COL));
	}

	@Override
	protected void setSourceArchiveID(UniversalID id) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_SOURCE_ARCHIVE_ID_COL, id.getValue());
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void setLastChangeTime(long lastChangeTime) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_LAST_CHANGE_TIME_COL, lastChangeTime);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public void setLastChangeTimeInSourceArchive(long lastChangeTimeInSourceArchive) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			record.setLongValue(EnumDBAdapter.ENUM_SOURCE_SYNC_TIME_COL,
				lastChangeTimeInSourceArchive);
			adapter.updateRecord(record, false);
			dataMgr.dataTypeChanged(this, false);
		}
		catch (IOException e) {
			dataMgr.dbError(e);
		}
	}

	@Override
	public boolean contains(String name) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.containsName(name);
		}
	}

	@Override
	public boolean contains(long value) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.containsValue(value);
		}
	}

	@Override
	public boolean isSigned() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getSignedState() == SIGNED;
		}
	}

	@Override
	public EnumSignedState getSignedState() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getSignedState();
		}
	}

	@Override
	public int getMinimumPossibleLength() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			EnumValues enumValues = getEnumValues();
			return enumValues.getMinimumPossbileLength();
		}
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(getPathName() + "\n");
		buf.append("\tDescription: " + getDescription());
		buf.append("\nValues: \n");
		for (String name : getNames()) {
			buf.append("\t" + name + ": " + getValue(name));
			String comment = getComment(name);
			if (comment != null) {
				buf.append(" comment");
			}
			buf.append("\n");
		}
		return buf.toString();
	}

	static long getMaxPossibleValue(int bytes, boolean allowNegativeValues) {
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

	static long getMinPossibleValue(int bytes, boolean allowNegativeValues) {
		if (!allowNegativeValues) {
			return 0;
		}
		int bits = bytes * 8;

		// smallest value (largest negative) that can be stored in n bits is when the sign bit
		// is on (and sign extended), and all less significant bits are 0
		return -1L << (bits - 1);
	}
}
