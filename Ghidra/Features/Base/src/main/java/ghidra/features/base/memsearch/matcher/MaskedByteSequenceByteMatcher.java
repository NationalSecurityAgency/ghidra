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
package ghidra.features.base.memsearch.matcher;

import java.util.Iterator;

import org.bouncycastle.util.Arrays;

import ghidra.features.base.memsearch.bytesequence.ByteSequence;
import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.gui.SearchSettings;

/**
 * {@link ByteMatcher} where the user search input has been parsed into a sequence of bytes and
 * masks to be used for searching a byte sequence.
 */
public class MaskedByteSequenceByteMatcher extends ByteMatcher {

	private final byte[] searchBytes;
	private final byte[] masks;

	/**
	 * Constructor where no masking will be required. The bytes must match exactly.
	 * @param input the input text used to create this matcher
	 * @param bytes the sequence of bytes to use for searching
	 * @param settings the {@link SearchSettings} used to parse the input text
	 */
	public MaskedByteSequenceByteMatcher(String input, byte[] bytes, SearchSettings settings) {
		this(input, bytes, null, settings);
	}

	/**
	 * Constructor that includes a mask byte for each search byte.
	 * @param input the input text used to create this matcher
	 * @param bytes the sequence of bytes to use for searching
	 * @param masks the sequence of mask bytes to use for search. Each mask byte will be applied
	 * to the bytes being search before comparing them to the target bytes.
	 * @param settings the {@link SearchSettings} used to parse the input text
	 */
	public MaskedByteSequenceByteMatcher(String input, byte[] bytes, byte[] masks,
			SearchSettings settings) {
		super(input, settings);

		if (masks == null) {
			masks = new byte[bytes.length];
			Arrays.fill(masks, (byte) 0xff);
		}

		if (bytes.length != masks.length) {
			throw new IllegalArgumentException("Search bytes and mask bytes must be same length!");
		}

		this.searchBytes = bytes;
		this.masks = masks;
	}

	@Override
	public Iterable<ByteMatch> match(ExtendedByteSequence byteSequence) {
		return new MatchIterator(byteSequence);
	}

	@Override
	public String getDescription() {
		return getByteString(searchBytes);
	}

	@Override
	public String getToolTip() {
		return "Mask = " + getByteString(masks);
	}

	private String getByteString(byte[] bytes) {
		StringBuilder buf = new StringBuilder();
		for (byte b : bytes) {
			String hexString = Integer.toHexString(b & 0xff);
			if (hexString.length() == 1) {
				buf.append("0");
			}
			buf.append(hexString);
			buf.append(" ");
		}
		return buf.toString().trim();
	}

//==================================================================================================
// Methods to facilitate testing
//==================================================================================================
	public byte[] getBytes() {
		return searchBytes;
	}

	public byte[] getMask() {
		return masks;
	}

//==================================================================================================
// Inner classes
//==================================================================================================
	private class MatchIterator implements Iterator<ByteMatch>, Iterable<ByteMatch> {

		private ByteSequence byteSequence;
		private int startIndex = 0;
		private ByteMatch nextMatch;

		public MatchIterator(ByteSequence byteSequence) {
			this.byteSequence = byteSequence;
			nextMatch = findNextMatch();
		}

		@Override
		public Iterator<ByteMatch> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			return nextMatch != null;
		}

		@Override
		public ByteMatch next() {
			if (nextMatch == null) {
				return null;
			}
			ByteMatch returnValue = nextMatch;
			nextMatch = findNextMatch();
			return returnValue;
		}

		private ByteMatch findNextMatch() {
			int nextPossibleStart = findNextPossibleStart(startIndex);
			while (nextPossibleStart >= 0) {
				startIndex = nextPossibleStart + 1;
				if (isValidMatch(nextPossibleStart)) {
					return new ByteMatch(nextPossibleStart, searchBytes.length);
				}
				nextPossibleStart = findNextPossibleStart(startIndex);
			}
			return null;
		}

		private boolean isValidMatch(int possibleStart) {
			if (!byteSequence.hasAvailableBytes(possibleStart, searchBytes.length)) {
				return false;
			}
			// we know 1st byte matches, check others
			for (int i = 1; i < searchBytes.length; i++) {
				if (searchBytes[i] != (byteSequence.getByte(possibleStart + i) & masks[i])) {
					return false;
				}
			}
			return true;
		}

		private int findNextPossibleStart(int start) {
			for (int i = start; i < byteSequence.getLength(); i++) {
				if (searchBytes[0] == (byteSequence.getByte(i) & masks[0])) {
					return i;
				}
			}
			return -1;
		}

	}

}
