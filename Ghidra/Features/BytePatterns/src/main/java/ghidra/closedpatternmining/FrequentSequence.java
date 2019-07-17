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
package ghidra.closedpatternmining;

import java.util.List;

/**
 * Objects of this class represent frequent sequences and contain a sequence and it support.
 */
public class FrequentSequence {

	private List<SequenceItem> sequence;
	private int support;

	/**
	 * Create a new {@link FrequentSequence} with the given sequence and support
	 * @param sequence the sequence
	 * @param support the support
	 */
	public FrequentSequence(List<SequenceItem> sequence, int support) {
		this.sequence = sequence;
		this.support = support;
	}

	/**
	 * Returns the sequence
	 * @return the sequence
	 */
	public List<SequenceItem> getSequence() {
		return sequence;
	}

	/**
	 * Returns the support
	 * @return the support
	 */
	public int getSupport() {
		return support;
	}

	@Override
	public int hashCode() {
		int hash = 17;
		hash = 31 * hash + sequence.hashCode();
		hash = 31 * hash + support;
		return hash;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof FrequentSequence)) {
			return false;
		}
		FrequentSequence otherSeq = (FrequentSequence) o;
		return (otherSeq.sequence.equals(sequence)) && (otherSeq.support == support);
	}

}
