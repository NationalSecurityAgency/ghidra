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
package ghidra.util.bytesearch;

import java.util.Objects;

/**
 * A class for accessing a contiguous sequence of bytes from some underlying byte source to 
 * be used for searching for a byte pattern within the byte source. This sequence of bytes 
 * consists of three parts; the primary sequence, a pre sequence, and an extended sequence. 
 * Search matches must begin in the primary sequence, but may extend into the extended sequence. The
 * pre-sequence is used for searching that supports look-behind such as some regular expressions. 
 * <P>
 * Searching large ranges of memory can be partitioned into searching smaller chunks. But
 * to handle search sequences that span chunks, three chunks are presented at a time. Look-behind
 * patterns can use the pre-chunk to see the bytes before the main chunk. Actual matches must start
 * in the main chunk, but can extend into the extended chunk. On the next iteration of the search
 * loop, the main chunk becomes the pre-chunk and the extended chunk becomes the main chunk and a 
 * new post-chunk is read from the input source.
 */
public class ExtendedByteSequence implements ByteSequence {
	private static final ByteSequence EMPTY = new EmptyByteSequence();
	private ByteSequence mainSequence;
	private ByteSequence postSequence;
	private ByteSequence preSequence;
	private int mainLength;
	private int extendedLength;
	private int preLength;

	/**
	 * Constructs an extended byte sequence from two {@link ByteSequence}s.
	 * @param main the byte sequence where search matches may start
	 * @param pre the byte sequence bytes before the main byte sequence used by searchers
	 * that support "look behind"
	 * @param post the byte sequence where search matches may extend into
	 * @param overlap specifies how much of the extended byte sequence to allow search
	 * matches to extend into. (The extended buffer will be the primary buffer next time, so
	 * it is a full size buffer, but we only need to use a portion of it to support overlap.
	 */
	public ExtendedByteSequence(ByteSequence main, ByteSequence pre,
			ByteSequence post, int overlap) {
		this.mainSequence = Objects.requireNonNull(main);
		this.preSequence = Objects.requireNonNullElse(pre, EMPTY);
		this.postSequence = Objects.requireNonNullElse(post, EMPTY);
		this.mainLength = mainSequence.getLength();
		this.extendedLength = main.getLength() + Math.min(overlap, postSequence.getLength());
		this.preLength = Math.min(overlap, preSequence.getLength());
	}

	@Override
	public int getLength() {
		return mainSequence.getLength();
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

	/**
	 * {@return the length of the pre sequence that is available}
	 */
	public int getPreLength() {
		return preLength;
	}

	@Override
	public byte getByte(int i) {
		if (i < 0) {
			return preSequence.getByte(i + preSequence.getLength());
		}
		if (i >= mainLength) {
			return postSequence.getByte(i - mainLength);
		}
		return mainSequence.getByte(i);
	}

	@Override
	public byte[] getBytes(int index, int size) {
		if (index < -preLength || index + size > extendedLength) {
			throw new IndexOutOfBoundsException();
		}
		if (index < 0 && index + size <= 0) {
			return preSequence.getBytes(index + preSequence.getLength(), size);
		}
		if (index >= 0 && index + size < mainLength) {
			return mainSequence.getBytes(index, size);
		}
		if (index >= mainLength) {
			return postSequence.getBytes(index - mainLength, size);
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
		return index >= -preLength && index + length <= extendedLength;
	}

	private static class EmptyByteSequence implements ByteSequence {

		@Override
		public int getLength() {
			return 0;
		}

		@Override
		public byte getByte(int index) {
			return 0;
		}

		@Override
		public boolean hasAvailableBytes(int index, int length) {
			return false;
		}

		@Override
		public byte[] getBytes(int start, int length) {
			return new byte[0];
		}

	}
}
