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
package ghidra.program.model.data;

import static ghidra.program.database.data.EnumSignedState.*;

import java.math.BigInteger;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.database.data.EnumSignedState;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.UniversalID;

public class EnumDataType extends GenericDataType implements Enum {

	private static final SettingsDefinition[] ENUM_SETTINGS_DEFINITIONS =
		new SettingsDefinition[] { MutabilitySettingsDefinition.DEF };

	private Map<String, Long> nameMap; // name to value
	private Map<String, String> commentMap; // name to comment
	private SortedMap<Long, List<String>> valueMap; // value to names 
	private int length;
	private String description;
	private List<BitGroup> bitGroups;
	private EnumSignedState signedState = NONE;

	public EnumDataType(String name, int length) {
		this(CategoryPath.ROOT, name, length, null);
	}

	public EnumDataType(CategoryPath path, String name, int length) {
		this(path, name, length, null);
	}

	public EnumDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
		super(path, name, dtm);
		if (length < 1 || length > 8) {
			throw new IllegalArgumentException("unsupported enum length: " + length);
		}
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		this.length = length;
	}

	public EnumDataType(CategoryPath path, String name, int length, UniversalID universalID,
			SourceArchive sourceArchive, long lastChangeTime, long lastChangeTimeInSourceArchive,
			DataTypeManager dtm) {
		super(path, name, universalID, sourceArchive, lastChangeTime, lastChangeTimeInSourceArchive,
			dtm);
		if (length < 1 || length > 8) {
			throw new IllegalArgumentException("unsupported enum length: " + length);
		}
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		this.length = length;
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return ENUM_SETTINGS_DEFINITIONS;
	}

	@Override
	public long getValue(String valueName) throws NoSuchElementException {
		Long value = nameMap.get(valueName);
		if (value == null) {
			throw new NoSuchElementException("No value for " + valueName);
		}
		return value;
	}

	@Override
	public String getName(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return null;
		}
		return list.get(0);
	}

	@Override
	public String[] getNames(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return null;
		}
		return list.toArray(new String[0]);
	}

	@Override
	public String getComment(String valueName) {
		String comment = commentMap.get(valueName);
		if (comment == null) {
			comment = "";
		}
		return comment;
	}

	@Override
	public long[] getValues() {
		long[] values = valueMap.keySet().stream().mapToLong(Long::longValue).toArray();
		return values;
	}

	@Override
	public String[] getNames() {
		// names are first sorted by int value, then sub-sorted by name value
		List<String> names = new ArrayList<>();
		Collection<List<String>> values = valueMap.values();
		for (List<String> list : values) {
			Collections.sort(list);
			names.addAll(list);
		}
		return names.toArray(new String[0]);
	}

	@Override
	public int getCount() {
		return nameMap.size();
	}

	@Override
	public void add(String valueName, long value) {
		add(valueName, value, null);
	}

	@Override
	public void add(String valueName, long value, String comment) {
		bitGroups = null;
		checkValue(value);
		if (nameMap.containsKey(valueName)) {
			throw new IllegalArgumentException(valueName + " already exists in this enum");
		}

		nameMap.put(valueName, value);
		List<String> list = valueMap.computeIfAbsent(value, v -> new ArrayList<>());
		list.add(valueName);

		if (!StringUtils.isBlank(comment)) {
			commentMap.put(valueName, comment);
		}
		signedState = computeSignedness();

	}

	private EnumSignedState computeSignedness() {
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

	@Override
	public void remove(String valueName) {
		bitGroups = null;
		Long value = nameMap.get(valueName);
		if (value == null) {
			return;
		}

		nameMap.remove(valueName);
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
		signedState = computeSignedness();
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
		if (getDataTypeManager() == dtm) {
			return this;
		}
		EnumDataType enumDataType =
			new EnumDataType(getCategoryPath(), getName(), getLength(), getUniversalID(),
				getSourceArchive(), getLastChangeTime(), getLastChangeTimeInSourceArchive(), dtm);
		enumDataType.setDescription(description);
		enumDataType.replaceWith(this);
		return enumDataType;
	}

	@Override
	public String getMnemonic(Settings settings) {
		return name;
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public int getAlignedLength() {
		return getLength();
	}

	public void setLength(int newLength) {
		if (newLength == length) {
			return;
		}

		int minLength = getMinimumPossibleLength();
		if (newLength < minLength || newLength > 8) {
			throw new IllegalArgumentException(
				"Enum length must be between " + minLength + "and 8 inclusive");

		}
		this.length = newLength;
	}

	private void checkValue(long value) {
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
	public boolean isSigned() {
		return signedState == SIGNED;
	}

	@Override
	public long getMinPossibleValue() {
		return getMinPossibleValue(length, signedState != UNSIGNED);
	}

	@Override
	public long getMaxPossibleValue() {
		return getMaxPossibleValue(length, signedState == SIGNED);
	}

	@Override
	public int getMinimumPossibleLength() {
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
	public String getDescription() {
		return description == null ? "" : description;
	}

	@Override
	public void setDescription(String description) {
		this.description = description;
	}

	@Override
	public Object getValue(MemBuffer buf, Settings settings, int valueLength) {

		try {
			long value = 0;
			switch (valueLength) {
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
			return new Scalar(valueLength * 8, value);
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
	public String getRepresentation(MemBuffer buf, Settings settings, int valueLength) {
		try {
			long value = 0;
			switch (this.length) {
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
		if (!DataTypeUtilities.equalsIgnoreConflict(name, enumm.getName()) ||
			length != enumm.getLength() || getCount() != enumm.getCount()) {
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
	public void replaceWith(DataType dataType) {
		bitGroups = null;
		if (!(dataType instanceof Enum)) {
			throw new IllegalArgumentException();
		}
		Enum enumm = (Enum) dataType;
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();
		setLength(enumm.getLength());
		String[] names = enumm.getNames();
		for (String valueName : names) {
			add(valueName, enumm.getValue(valueName), enumm.getComment(valueName));
		}
		computeSignedness();
	}

	@Override
	public String getDefaultLabelPrefix() {
		return name;
	}

	@Override
	public boolean contains(String entryName) {
		return nameMap.containsKey(entryName);

	}

	@Override
	public boolean contains(long value) {
		return valueMap.containsKey(value);
	}

	/**
	 * Sets this enum to it smallest (power of 2) size that it can be and still represent all its
	 * current values.
	 */
	public void pack() {
		setLength(getMinimumPossibleLength());
	}
}
