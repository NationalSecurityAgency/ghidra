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
package ghidra.util.ascii;

import ghidra.program.model.data.StringDataType;

/** 
 * Instances of this class will find sequences of characters that are in the given char set and
 * of a minimum length.  Characters a fed one at a time into this object. Adding a char may trigger
 * the discovery of a sequence if the char is a 0 or not in the char set and we already have seen
 * a sequence of included chars at least as long as the minimum length.
 *
 */

public class MinLengthCharSequenceMatcher {
	private final int minimumSequenceLength;
	long sequenceStartIndex = -1;
	long currentIndex = -1;
	boolean inAsciiSequence = false;
	private CharSetRecognizer charSet;
	private Sequence lastSequence;
	private int alignment;

	public MinLengthCharSequenceMatcher(int minimumSequenceLength, CharSetRecognizer charSet,
			int alignment) {
		this.minimumSequenceLength = minimumSequenceLength;
		this.charSet = charSet;
		this.alignment = alignment;
	}

	/**
	 * Adds a character to this sequence matcher.
	 * @param c the character to add.
	 * @return a Sequence if the added char triggered an end of a valid sequence, otherwise null.
	 */
	public boolean addChar(int c) {
		lastSequence = null;
		currentIndex++;
		if (charSet.contains(c)) {
			if (!inAsciiSequence && meetsAlignmentRequirement()) {
				sequenceStartIndex = currentIndex;
				inAsciiSequence = true;
			}
		}
		else if (c == 0) {
			return checkSequence(sequenceStartIndex, currentIndex, true);
		}
		else {
			return checkSequence(sequenceStartIndex, currentIndex - 1, false);
		}
		return false;
	}

	private boolean meetsAlignmentRequirement() {
		return currentIndex % alignment == 0;
	}

	/**
	 * Indicates there are no more contiguous chars to add to this matcher.  If a minimum or more
	 * number of included chars have been seen before this call, then a sequence is returned.
	 * @return a Sequence if there was a sequence of chars &gt;= the min length just before this call. 
	 */
	public boolean endSequence() {
		lastSequence = null;
		return checkSequence(sequenceStartIndex, currentIndex, false);
	}

	public void reset() {
		currentIndex = -1;
		inAsciiSequence = false;
		lastSequence = null;
	}

	public Sequence getSequence() {
		return lastSequence;
	}

	private boolean checkSequence(long start, long end, boolean nullTerminated) {
		if (!inAsciiSequence) {
			return false;
		}
		inAsciiSequence = false;
		long length = end - start + 1;
		if (nullTerminated) {
			length--;		// seems we don't count the 0 in the length for purposes of minimum string length
		}
		if (length >= minimumSequenceLength) {
			lastSequence = new Sequence(start, end, StringDataType.dataType, nullTerminated);
		}
		return lastSequence != null;
	}

}
