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
package ghidra.program.database.code;

import java.util.Objects;

/**
 * Container object that holds a start and end position within a string. A list of StringDiffs 
 * is used to keep track of changes made to a string.
 */
public class StringDiff {

	/**
	 * Start position of the string used when text is inserted or replaced
	 */
	int start;

	/**
	 * End position of the string used when part of the string is replaced
	 */
	int end;

	/**
	 * String being inserted.  This can be an insert or a complete replace (the positions will both
	 * be -1 in a replace; pos1 will be non-negative during an insert).
	 */
	public String text;

	/**
	 * Construct a new StringDiff with pos1 and pos2 are initialized to -1
	 * 
	 * @param newText string 
	 * @return the new diff 
	 */
	public static StringDiff allTextReplaced(String newText) {
		return new StringDiff(-1, -1, newText);
	}

	/**
	 * Construct a new StringDiff that indicates text was deleted from pos1 to pos2
	 * 
	 * @param start position 1 for the diff
	 * @param end position 2 for the diff
	 * @return the new diff
	 */
	public static StringDiff textDeleted(int start, int end) {
		return new StringDiff(start, end, null);
	}

	/**
	 * Construct a new StringDiff that indicates that insertData was inserted at the given position
	 * 
	 * @param newText inserted string
	 * @param start position where the text was inserted
	 * @return the new diff
	 */
	public static StringDiff textInserted(String newText, int start) {
		return new StringDiff(start, -1, newText);
	}

	// for restoring from saved record
	public static StringDiff restore(String text, int start, int end) {
		return new StringDiff(start, end, text);
	}

	private StringDiff(int start, int end, String text) {
		this.start = start;
		this.end = end;
		this.text = text;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((text == null) ? 0 : text.hashCode());
		result = prime * result + start;
		result = prime * result + end;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		StringDiff other = (StringDiff) obj;
		if (!Objects.equals(text, other.text)) {
			return false;
		}
		if (start != other.start) {
			return false;
		}
		if (end != other.end) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		if (text != null) {
			if (start >= 0) {
				return "StringDiff: inserted <" + text + "> at " + start;
			}

			return "StringDiff: replace with <" + text + ">";
		}
		return "StringDiff: deleted text from " + start + " to " + end;
	}

}
