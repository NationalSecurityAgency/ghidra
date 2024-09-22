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
 * A class for accessing a contiguous sequence of bytes from some underlying byte source to 
 * be used for searching for a byte pattern within the byte source. This sequence of bytes 
 * consists of two parts; the primary sequence and an extended sequence. Search matches
 * must begin in the primary sequence, but may extend into the extended sequence.
 * <P>
 * Searching large ranges of memory can be partitioned into searching smaller chunks. But
 * to handle search sequences that span chunks, two chunks are presented at a time, with the second
 * chunk being the extended bytes. On the next iteration of the search loop, the extended chunk
 * will become the primary chunk, with the next chunk after that becoming the extended sequence
 * and so on.
 */
public class ExtendedByteSequence implements ByteSequence {

	private ByteSequence main;
	private ByteSequence extended;
	private int extendedLength;

	/**
	 * Constructs an extended byte sequence from two {@link ByteSequence}s.
	 * @param main the byte sequence where search matches may start
	 * @param extended the byte sequence where search matches may extend into
	 * @param extendedLimit specifies how much of the extended byte sequence to allow search
	 * matches to extend into. (The extended buffer will be the primary buffer next time, so
	 * it is a full size buffer, but we only need to use a portion of it to support overlap.
	 */
	public ExtendedByteSequence(ByteSequence main, ByteSequence extended, int extendedLimit) {
		this.main = main;
		this.extended = extended;
		this.extendedLength = main.getLength() + Math.min(extendedLimit, extended.getLength());
	}

	@Override
	public int getLength() {
		return main.getLength();
	}

	/**
	 * Returns the overall length of sequence of available bytes. This will be the length of
	 * the primary sequence as returned by {@link #getLength()} plus the length of the available
	 * extended bytes, if any.
	 * @return the 
	 */
	public int getExtendedLength() {
		return extendedLength;
	}

	@Override
	public byte getByte(int i) {
		int mainLength = main.getLength();
		if (i >= mainLength) {
			return extended.getByte(i - mainLength);
		}
		return main.getByte(i);
	}

	@Override
	public byte[] getBytes(int index, int size) {
		if (index < 0 || index + size > extendedLength) {
			throw new IndexOutOfBoundsException();
		}
		int length = main.getLength();
		if (index + size < length) {
			return main.getBytes(index, size);
		}
		if (index >= length) {
			return extended.getBytes(index - length, size);
		}
		// otherwise it spans
		byte[] results = new byte[size];
		for (int i = 0; i < size; i++) {
			results[i] = getByte(index + i);
		}
		return results;
	}

	@Override
	public boolean hasAvailableBytes(int index, int length) {
		return index >= 0 && index + length <= getExtendedLength();
	}
}
