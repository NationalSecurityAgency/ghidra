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

/**
 * Represents a match of a DittedBitSequence at a given offset in a byte sequence.
 * 
 * There is a hidden assumption that the sequence is actually a Pattern
 * that might have a ditted-bit-sequence, a set of match actions,
 * and post match rules/checks
 * 
 */
public class Match {
	private DittedBitSequence sequence;	// Pattern that matched
	private long offset;			    // Offset within bytestream where the match occurred

	/**
	 * Construct a Match of a DittedBitSequence at an offset within a byte stream.
	 * Object normally used when a match occurs during a MemoryBytePatternSearch.
	 * @param sequence that matched
	 * @param offset from the start of byte stream where the matched occured
	 */
	public Match(DittedBitSequence sequence, long offset) {
		this.sequence = sequence;
		this.offset = offset;
	}

	/**
	 * If the sequence corresponds to a PatternPair, return the number of postbits
	 * @return the number of post bits
	 */
	public int getNumPostBits() {
		if (!(sequence instanceof Pattern)) {
			return 0;
		}
		int marked = ((Pattern) sequence).getMarkOffset();
		if (marked == 0) {
			return sequence.getNumFixedBits();
		}
		return sequence.getNumFixedBits() - sequence.getNumInitialFixedBits(marked);
	}

	/**
	 * @return actions associated with this match
	 */
	public MatchAction[] getMatchActions() {
		return ((Pattern) sequence).getMatchActions();
	}

	/**
	 * @return size in bytes of sequence
	 */
	public int getSequenceSize() {
		return sequence.getSize();
	}

	/**
	 * @return index of sequence in a possibly longer set of sequences
	 */
	public int getSequenceIndex() {
		return sequence.getIndex();
	}

	/**
	 * @return the offset of the match within a longer byte sequence
	 */
	public long getMarkOffset() {
		return offset + ((Pattern) sequence).getMarkOffset();
	}

	/** 
	 * @return offset of match in sequence of bytes
	 */
	public long getMatchStart() {
		return offset;
	}

	/**
	 * Check that the possible post rules are satisfied
	 * 
	 * @param streamoffset offset within from match location to check postrules.
	 * 
	 * @return true if post rules are satisfied
	 */
	public boolean checkPostRules(long streamoffset) {
		long curoffset = streamoffset + offset;
		Pattern pattern = (Pattern) sequence;
		PostRule[] postRules = pattern.getPostRules();
		for (PostRule postRule : postRules) {
			if (!postRule.apply(pattern, curoffset)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * @return ditted bit sequence as a string
	 */
	public String getHexString() {
		return sequence.getHexString();
	}

	/**
	 * @return the sequence that was matched
	 */
	public DittedBitSequence getSequence() {
		return sequence;
	}
}
