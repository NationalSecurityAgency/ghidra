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

import java.util.*;
import java.util.Map.Entry;

/**
 * 
 * The class stores the collection of sequences to be mined.
 *
 */

public class SequenceDatabase {
	private int sequenceLength;
	private List<Sequence> sequences;
	private int totalNumSeqs;

	/**
	 * Creates a new {@link SequenceDatabase}
	 * @param sequencesToMine the sequences to mine for closed patterns
	 * @param sequenceLength all sequences in the database must be of length 
	 * {@code sequenceLength}
	 */
	public SequenceDatabase(List<Sequence> sequencesToMine, int sequenceLength) {
		if (sequenceLength < 1) {
			throw new IllegalArgumentException("length must be positive!");
		}
		this.sequenceLength = sequenceLength;

		sequences = sequencesToMine;
		totalNumSeqs = 0;

		for (Sequence seq : sequences) {
			if (seq.getSequenceAsString().length() != sequenceLength) {
				throw new IllegalArgumentException("sequence " + seq.getSequenceAsString() +
					" does not have length " + sequenceLength);
			}
			totalNumSeqs += seq.getCount();
		}
	}

	/**
	 * Returns the length of a sequence in the database (all sequences in a database must have the same length)
	 * @return the length
	 */
	public int getSequenceLength() {
		return sequenceLength;
	}

	/**
	 * Returns the sequences in the database
	 * @return the sequences
	 */
	public List<Sequence> getSequences() {
		return sequences;
	}

	/**
	 * Get the total number of sequences in the database
	 * @return total number of sequences
	 */
	public int getTotalNumSeqs() {
		return totalNumSeqs;
	}

	/**
	 * returns the set of all items occuring in at least {@code minSupport} sequences
	 * in the database.
	 * @param minSupport minimum number of sequences that must contain an item
	 * @return set of frequent items
	 */
	public TreeSet<FrequentSequenceItem> getGloballyFrequentItems(int minSupport) {
		Map<SequenceItem, Integer> itemBag = new HashMap<SequenceItem, Integer>();
		TreeSet<FrequentSequenceItem> frequentItemSet = new TreeSet<FrequentSequenceItem>();
		//count all items
		for (Sequence seq : sequences) {
			for (int i = 0; i < sequenceLength; ++i) {
				SequenceItem fItem = new SequenceItem(seq.getSequenceAsString().substring(i, i + 1), i);
				Integer count = itemBag.get(fItem);
				if (count == null) {
					itemBag.put(fItem, new Integer(seq.getCount()));
				}
				else {
					itemBag.put(fItem, count + seq.getCount());
				}
			}
		}

		//iterate through itemBag and save the frequent items
		for (Entry<SequenceItem, Integer> itemAndCount : itemBag.entrySet()) {
			int count = itemAndCount.getValue();
			if (count >= minSupport) {
				frequentItemSet.add(new FrequentSequenceItem(count, itemAndCount.getKey()));
			}
		}
		return frequentItemSet;
	}
}
