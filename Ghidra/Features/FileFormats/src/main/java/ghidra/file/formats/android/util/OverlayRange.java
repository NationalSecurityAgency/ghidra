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
package ghidra.file.formats.android.util;

import java.io.IOException;

public class OverlayRange {

	private int overlayIndex;
	private byte[] overlayBytes;

	public OverlayRange(long overlayIndex, byte[] overlayBytes) {
		this((int) overlayIndex, overlayBytes);
	}

	public OverlayRange(int overlayIndex, byte[] overlayBytes) {
		this.overlayIndex = overlayIndex;
		this.overlayBytes = overlayBytes;
	}

	/**
	 * Get the start index of this range.
	 * @return the start index of this range
	 */
	public int getStartIndex() {
		return overlayIndex;
	}

	/**
	 * Get the end index of this range.
	 * @return the end index of this range
	 */
	public int getEndIndex() {
		return overlayIndex + overlayBytes.length;
	}

	/**
	 * Returns true if this range contains the specific index.
	 * @param index the specific index
	 * @return true if this range contains the specific index
	 */
	public boolean containsIndex(int index) {
		return index >= getStartIndex() && index <= getEndIndex();
	}

	/**
	 * Returns true if this range contains the specific index.
	 * @param index the specific index
	 * @return true if this range contains the specific index
	 */
	public boolean containsIndex(long index) {
		return containsIndex((int) index);
	}

	/**
	 * Returns the byte at the specified index.
	 * @param index the specific index
	 * @return the byte at the specified index
	 */
	public byte getByte(int index) {
		return overlayBytes[index - overlayIndex];
	}

	/**
	 * Returns the byte at the specified index.
	 * @param index the specific index
	 * @return the byte at the specified index
	 */
	public byte getByte(long index) {
		return getByte((int) index);
	}

	/**
	 * Returns the byte array starting at index with specified length.
	 * @param index the index into the range
	 * @param length the length of the bytes from the range
	 * @return the byte array starting at index with specified length
	 * @throws IOException if the index or length is out of range
	 */
	public byte[] getBytes(int index, int length) throws IOException {
		try {
			byte[] bytes = new byte[length];
			System.arraycopy(overlayBytes, index - overlayIndex, bytes, 0, length);
			return bytes;
		}
		catch (Exception e) {
			throw new IOException("specified index and length are out of range");
		}
	}

	/**
	 * Returns the byte array starting at index with specified length.
	 * @param index the index into the range
	 * @param length the length of the bytes from the range
	 * @return the byte array starting at index with specified length
	 * @throws IOException if the index or length is out of range
	 */
	public byte[] getBytes(long index, long length) throws IOException {
		return getBytes((int) index, (int) length);
	}

	/**
	 * Returns all bytes contained in this range.
	 * @return all bytes contained in this range
	 */
	public byte[] getAllBytes() {
		return overlayBytes;
	}
}
