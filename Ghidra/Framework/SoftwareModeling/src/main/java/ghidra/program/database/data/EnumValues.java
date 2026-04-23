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
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import db.DBRecord;
import db.Field;

/** 
 * Immutable class to hold the name/values for an {@link EnumDB} object. It is created lazily by an
 * EnumDB as needed. Any change to the name/values for an enum will cause this class to be nulled 
 * out in it enum owner.
 */
class EnumValues {

	private Map<String, Long> nameMap;
	private SortedMap<Long, List<String>> valueMap;
	private Map<String, String> commentMap;
	private EnumSignedState signedState = null;
	private EnumDB enumm;

	EnumValues(EnumDB enumm, EnumValueDBAdapter valueAdapter) throws IOException {
		this.enumm = enumm;
		nameMap = new HashMap<>();
		valueMap = new TreeMap<>();
		commentMap = new HashMap<>();

		Field[] ids = valueAdapter.getValueIdsInEnum(enumm.getKey());
		for (Field id : ids) {
			DBRecord rec = valueAdapter.getRecord(id.getLongValue());
			String valueName = rec.getString(EnumValueDBAdapter.ENUMVAL_NAME_COL);
			long value = rec.getLongValue(EnumValueDBAdapter.ENUMVAL_VALUE_COL);
			String comment = rec.getString(EnumValueDBAdapter.ENUMVAL_COMMENT_COL);
			doAddValue(valueName, value, comment);
		}
		signedState = computeSignedness();
	}

	/**
	 * Returns the value for a given name.
	 * @param valueName the name to get a value for
	 * @return the value for a given name
	 * @throws NoSuchElementException if there is no value defined for the given name
	 */
	long getValue(String valueName) {
		Long value = nameMap.get(valueName);
		if (value == null) {
			throw new NoSuchElementException("No value for " + valueName);
		}
		return value;
	}

	/**
	 * Returns the name for a given value. If there more than one name for a value, the first
	 * in alphabetical order is returned.
	 * @param value the value for which to find a name
	 * @return the first name for a given value, or null if there is not name for that value
	 */
	String getName(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return null;
		}
		return list.get(0);
	}

	/**
	 * Returns all the names for a given value.
	 * @param value the value for which to find defined names
	 * @return all the names for a given value
	 */
	String[] getNames(long value) {
		List<String> list = valueMap.get(value);
		if (list == null || list.isEmpty()) {
			return new String[0];
		}
		return list.toArray(new String[0]);
	}

	/**
	 * Returns the comment for a given value name.
	 * @param valueName the name of the value to get a comment for
	 * @return the comment for the given name or null if no comment set
	 */
	String getComment(String valueName) {
		String comment = commentMap.get(valueName);
		if (comment == null) {
			comment = "";
		}
		return comment;
	}

	/**
	 * {@return an array of all values defined in this enum}
	 */
	long[] getValues() {
		return valueMap.keySet().stream().mapToLong(Long::longValue).toArray();
	}

	/**
	 * {@return an array of all names defined in this enum.}
	 */
	String[] getNames() {
		List<String> names = new ArrayList<>();
		Collection<List<String>> values = valueMap.values();
		for (List<String> list : values) {
			names.addAll(list);
		}
		return names.toArray(new String[0]);
	}

	/**
	 * {@return the number of defined names in this enum}
	 */
	int size() {
		return nameMap.size();
	}

	/**
	 * Returns true if the given name has been defined in this enum.
	 * @param valueName the name to check if it has been defined
	 * @return true if the given name has been defined in this enum
	 */
	boolean containsName(String valueName) {
		return nameMap.containsKey(valueName);
	}

	/**
	 * Returns true if the given value has been defined in this enum.
	 * @param value the value to check if it has been defined
	 * @return true if the given value has been defined in this enum
	 */
	boolean containsValue(long value) {
		return valueMap.containsKey(value);
	}

	/**
	 * {@return the EnumSignedState for this enum}
	 */
	EnumSignedState getSignedState() {
		return signedState;
	}

	/**
	 * {@return the minimum size that enum can be and still represent all defined values}
	 */
	int getMinimumPossbileLength() {
		if (valueMap.isEmpty()) {
			return 1;
		}
		long minValue = valueMap.firstKey();
		long maxValue = valueMap.lastKey();
		boolean hasNegativeValues = minValue < 0;

		// check the min and max values in this enum to see if they fit in 1 byte enum, then 
		// 2 byte enum, then 4 byte enum. If the min and max values fit, then all other values
		// will fit as well
		for (int size = 1; size < 8; size *= 2) {
			long minPossible = EnumDB.getMinPossibleValue(size, hasNegativeValues);
			long maxPossible = EnumDB.getMaxPossibleValue(size, hasNegativeValues);
			if (minValue >= minPossible && maxValue <= maxPossible) {
				return size;
			}
		}
		return 8;
	}

	private EnumSignedState computeSignedness() {

		if (valueMap.isEmpty()) {
			return NONE;
		}

		long minValue = valueMap.firstKey();
		long maxValue = valueMap.lastKey();

		if (maxValue > EnumDB.getMaxPossibleValue(enumm.getLength(), true)) {
			if (minValue < 0) {
				return INVALID;
			}
			return UNSIGNED;
		}

		if (minValue < 0) {
			return SIGNED;
		}

		return NONE;		// we have no negatives and no large unsigned values
	}

	void addValue(String valueName, long value, String comment) {
		doAddValue(valueName, value, comment);
		signedState = computeSignedness();
	}

	private void doAddValue(String valueName, long value, String comment) {
		nameMap.put(valueName, value);
		List<String> list = valueMap.computeIfAbsent(value, v -> new ArrayList<>());
		list.add(valueName);
		Collections.sort(list);
		if (!StringUtils.isBlank(comment)) {
			commentMap.put(valueName, comment);
		}
	}

}
