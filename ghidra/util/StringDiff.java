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
package ghidra.util;

import org.apache.commons.lang3.StringUtils;

/**
 * Container object that holds a start and end position within a string.
 * A list of StringDiffs is used to keep track of changes made to a string.
 *
 */
public class StringDiff {
	/**
	 * Start position of the string.
	 */
	public int pos1;
	/**
	 * End position of the string used when part of the string is replaced. 
	 */
	public int pos2;
	/**
	 * String being inserted.
	 */
	public String insertData;

	/**
	 * Construct a new StringDiff with pos1 and pos2 are initialized to -1.
	 * @param replaceData string 
	 */
	public StringDiff(String replaceData) {
		pos1 = -1;
		pos2 = -1;
		insertData = replaceData;
	}

	/**
	 * Construct a new StringDiff that indicates text was deleted from
	 * pos1 to pos2.
	 * @param pos1 position 1 for the diff
	 * @param pos2 position 2 for the diff
	 */
	public StringDiff(int pos1, int pos2) {
		this.pos1 = pos1;
		this.pos2 = pos2;
	}

	/**
	 * Construct a new StringDiff that indicates that insertData was
	 * inserted at pos.
	 * @param pos position where the insertData was inserted
	 * @param insertData inserted string
	 */
	public StringDiff(int pos, String insertData) {
		this.pos1 = pos;
		this.insertData = insertData;
	}

	/**
	 * Construct a new StringDiff that indicates given data is inserted
	 * from pos1 to pos2.
	 * @param pos1 position 1
	 * @param pos2 position 2
	 * @param data data the replaces string data
	 */
	public StringDiff(int pos1, int pos2, String data) {
		this.pos1 = pos1;
		this.pos2 = pos2;
		insertData = data;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof StringDiff) {
			StringDiff other = (StringDiff) obj;
			return pos1 == other.pos1 && pos2 == other.pos2 &&
				StringUtils.equals(insertData, other.insertData);
		}
		return false;
	}

	@Override
	public String toString() {
		if (insertData != null) {
			if (pos1 >= 0) {
				return "StringDiff: inserted <" + insertData + "> at " + pos1;
			}

			return "StringDiff: replace with <" + insertData + ">";
		}
		return "StringDiff: deleted text from " + pos1 + " to " + pos2;
	}
}
