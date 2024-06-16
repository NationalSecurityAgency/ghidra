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
package ghidra.app.util.bin.format.dwarf;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.datastruct.WeakValueHashMap;

/**
 * Represents a DWARF string table, backed by a memory section like .debug_str.
 * <p>
 * Strings are read from the section the first time requested, and then cached in a weak lookup
 * table.
 */
public class StringTable {
	/**
	 * Creates a StringTable instance, if the supplied BinaryReader is non-null.
	 * 
	 * @param reader BinaryReader
	 * @return new instance, or null if reader is null
	 */
	public static StringTable of(BinaryReader reader) {
		if (reader == null) {
			return null;
		}
		return new StringTable(reader);
	}

	protected BinaryReader reader;
	protected WeakValueHashMap<Long, String> cache = new WeakValueHashMap<>();

	/**
	 * Creates a StringTable
	 * 
	 * @param reader {@link BinaryReader} .debug_str or .debug_line_str
	 */
	public StringTable(BinaryReader reader) {
		this.reader = reader;
	}

	/**
	 * Returns true if the specified offset is a valid offset for this string table.
	 * <p>
	 * @param offset location of possible string
	 * @return boolean true if location is valid
	 */
	public boolean isValid(long offset) {
		return reader.isValidIndex(offset);
	}

	public void clear() {
		reader = null;
		cache.clear();
	}

	/**
	 * Returns the string found at <code>offset</code>, or throws an {@link IOException}
	 * if the offset is out of bounds.
	 *
	 * @param offset location of string
	 * @return a string, never null
	 * @throws IOException if not valid location
	 */
	public String getStringAtOffset(long offset) throws IOException {
		if (!isValid(offset)) {
			throw new IOException("Invalid offset requested " + offset);
		}

		String s = cache.get(offset);
		if (s == null) {
			s = reader.readUtf8String(offset);
			cache.put(offset, s);
		}

		return s;
	}

}
