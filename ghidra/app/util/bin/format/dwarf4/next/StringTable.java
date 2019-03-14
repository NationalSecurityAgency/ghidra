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
package ghidra.app.util.bin.format.dwarf4.next;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.ByteProvider;

/**
 * A offset-to-String string table backed by a simple byte array (encoded as UTF-8).
 * <p>
 * Requested strings are instantiated when requested.
 */
public class StringTable {
	private byte[] bytes;

	/**
	 * Create a {@link StringTable} by reading the entire contents of a {@link ByteProvider}
	 * into memory.
	 * <p>
	 * If the specified {@link ByteProvider} is null, an empty string table will be constructed.
	 * <p>
	 * @param bp
	 * @return
	 * @throws IOException
	 */
	public static StringTable readStringTable(ByteProvider bp) throws IOException {
		byte[] bytes = (bp != null) ? bp.readBytes(0, bp.length()) : new byte[0];
		return new StringTable(bytes);
	}

	/**
	 * Creates a StringTable using the bytes contained in the supplied array.
	 */
	public StringTable(byte[] bytes) {
		this.bytes = bytes;
	}

	/**
	 * Returns true if the specified offset is a valid offset for this string table.
	 * <p>
	 * @param offset
	 * @return
	 */
	public boolean isValid(long offset) {
		return (offset >= 0) && (offset < bytes.length);
	}

	public void clear() {
		bytes = null;
	}

	/**
	 * Returns the string found at <code>offset</code>, or throws an {@link IOException}
	 * if the offset is out of bounds.
	 *
	 * @param offset
	 * @return a string, never null.
	 * @throws IOException if not found
	 */
	public String getStringAtOffset(long offset) throws IOException {
		if (!isValid(offset)) {
			throw new IOException("Invalid offset requested " + offset);
		}

		String tmp = new String(bytes, (int) offset, getNullTermStringLen(bytes, (int) offset),
			StandardCharsets.UTF_8);

		return tmp;
	}

	private static final int getNullTermStringLen(byte[] bytes, int startOffset) {
		int cp = startOffset;
		while (cp < bytes.length && bytes[cp] != 0) {
			cp++;
		}
		return cp - startOffset;
	}

	public int getByteCount() {
		return bytes.length;
	}

	/**
	 * Modifies the string table to add a string at a specified offset, growing the
	 * internal byte[] storage as necessary to accommodate the string at the offset.
	 * <p>
	 * Used for unit tests to construct a custom string table for test cases.
	 * <p>
	 * @param offset where to place the string in the table
	 * @param s string to insert into table
	 */
	public void add(int offset, String s) {
		byte[] sBytes = s.getBytes();
		int newLen = Math.max(bytes.length, offset + sBytes.length + 1);
		byte[] newBytes = new byte[newLen];
		System.arraycopy(bytes, 0, newBytes, 0, bytes.length);
		System.arraycopy(sBytes, 0, newBytes, offset, sBytes.length);

		this.bytes = newBytes;
	}

}
