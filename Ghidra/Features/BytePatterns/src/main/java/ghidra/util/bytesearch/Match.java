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

public class Match {
	private DittedBitSequence sequence;	// Pattern that matches
	private long offset;			// starting offset within bytestream of match

	public Match(DittedBitSequence seq, long off) {
		sequence = seq;
		offset = off;
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

	public MatchAction[] getMatchActions() {
		return ((Pattern) sequence).getMatchActions();
	}

	public int getSequenceSize() {
		return sequence.getSize();
	}

	public int getSequenceIndex() {
		return sequence.getIndex();
	}

	public long getMarkOffset() {
		return offset + ((Pattern) sequence).getMarkOffset();
	}

	public long getMatchStart() {
		return offset;
	}

	public boolean checkPostRules(long streamoffset) {
		long curoffset = streamoffset + offset;
		Pattern pattern = (Pattern) sequence;
		PostRule[] postRules = pattern.getPostRules();
		for (int i = 0; i < postRules.length; ++i) {
			if (!postRules[i].apply(pattern, curoffset)) {
				return false;
			}
		}
		return true;
	}

	public String getHexString() {
		return sequence.getHexString();
	}

	public DittedBitSequence getSequence() {
		return sequence;
	}
}
