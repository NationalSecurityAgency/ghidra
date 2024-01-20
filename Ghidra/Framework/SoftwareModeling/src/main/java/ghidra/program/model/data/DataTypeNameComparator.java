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

import java.util.*;

import ghidra.program.database.data.DataTypeUtilities;

/**
 * {@link DataTypeNameComparator} provides the preferred named-based comparison of {@link DataType}
 * which handles both some degree of case-insensity as well as proper grouping and ordering of
 * conflict datatypes.
 */
public class DataTypeNameComparator implements Comparator<String> {

	public static final DataTypeNameComparator INSTANCE = new DataTypeNameComparator();

	@Override
	public int compare(String dt1Name, String dt2Name) {

		String name1 = DataTypeUtilities.getNameWithoutConflict(dt1Name);
		String name2 = DataTypeUtilities.getNameWithoutConflict(dt2Name);

		int len1 = name1.length();
		int len2 = name2.length();

		int len = Math.min(len1, len2); // overlapping length
		int baseNameLen = len; // Length of overlapping portion of base-name (no decorations)

		// Case-insensitive compare of significant overlapping portion of name
		int baseCaseCompare = 0;
		for (int i = 0; i < len; i++) {
			char c1 = name1.charAt(i);
			char c2 = name2.charAt(i);
			char lc1 = Character.toLowerCase(c1);
			char lc2 = Character.toLowerCase(c2);
			// first space treated as end of base-name
			if (lc1 == ' ') {
				if (lc2 == ' ') {
					baseNameLen = i;
					break;
				}
				return -1;
			}
			if (lc2 == ' ') {
				return 1;
			}
			if (lc1 != lc2) {
				return lc1 - lc2;
			}
			if (baseCaseCompare == 0) {
				baseCaseCompare = c1 - c2;
			}
		}

		if (len1 > baseNameLen && name1.charAt(baseNameLen) != ' ') {
			return 1; // first name has longer base-name
		}

		if (len2 > baseNameLen && name2.charAt(baseNameLen) != ' ') {
			return -1; // second name has longer base-name
		}

		if (baseCaseCompare != 0) {
			return baseCaseCompare;
		}

		// Same base-name, order by conflict
		int conflict1 = getConflictValue(dt1Name);
		int conflict2 = getConflictValue(dt2Name);
		if (conflict1 != conflict2) {
			return conflict1 - conflict2;
		}

		return name1.compareTo(name2);
	}

	private int getConflictValue(String dtName) {
		String conflict = DataTypeUtilities.getConflictString(dtName);
		if (conflict == null) {
			return -1;
		}
		if (conflict.length() == 0) {
			return 0;
		}
		return Integer.parseInt(conflict);
	}

}
