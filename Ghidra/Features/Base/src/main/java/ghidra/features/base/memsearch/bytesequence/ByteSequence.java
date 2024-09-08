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
package ghidra.features.base.memsearch.bytesequence;

/**
 * An interface for accessing bytes from a byte source.
 */
public interface ByteSequence {

	/**
	 * Returns the length of available bytes.
	 * @return the length of the sequence of bytes
	 */
	public int getLength();

	/**
	 * Returns the byte at the given index. The index must between 0 and the extended length.
	 * @param index the index in the byte sequence to retrieve a byte value
	 * @return the byte at the given index
	 */
	public byte getByte(int index);

	/**
	 * A convenience method for checking if this sequence can provide a range of bytes from some
	 * offset.
	 * @param index the index of the start of the range to check for available bytes
	 * @param length the length of the range to check for available bytes
	 * @return true if bytes are available for the given range
	 */
	public boolean hasAvailableBytes(int index, int length);

	/**
	 * Returns a byte array containing the bytes from the given range.
	 * @param start the start index of the range to get bytes
	 * @param length the number of bytes to get
	 * @return a byte array containing the bytes from the given range
	 */
	public byte[] getBytes(int start, int length);

}
