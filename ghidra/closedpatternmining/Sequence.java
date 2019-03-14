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
 * 
 * An object in this class in represents a string of characters along
 * with a count.  The count represents the number of occurrences of the
 * sequence.  
 *
 */
public class Sequence {

	private String sequence;
	private int count;

	/**
	 * Creates a new {@link Sequence} with a given count
	 * @param sequence sequence
	 * @param count number of times the sequence occurs in the database
	 */
	public Sequence(String sequence, int count) {
		this.sequence = sequence;
		this.count = count;
	}

	/**
	 * Gets the sequence
	 * @return sequence
	 */
	public String getSequenceAsString() {
		return sequence;
	}

	/**
	 * Gets the number of times the sequence occurs in the database
	 * @return count
	 */
	public int getCount() {
		return count;
	}

	/**
	 * If all items in {@code prefixSequence} occur in {@code sequence}, returns
	 * the index of the item in {@code sequence} immediately after the last item
	 * in {@code prefixSequence}.  If {@code prefixSequence} does not occur in 
	 * {{@code sequence} as a subsequence, then this method returns -1.
	 * 
	 * <p>Note: this method assumes that {@code prefixSequence} is sorted in
	 * ascending order of Item.index.
	 * 
	 * @param prefixSequence prefix
	 * @return index
	 */
	public int getIndexAfterFirstInstance(List<SequenceItem> prefixSequence) {
		if (prefixSequence == null) {
			return 0;
		}
		if (prefixSequence.isEmpty()) {
			return 0;
		}
		int index = 0;
		for (SequenceItem item : prefixSequence) {
			if ((item.getIndex() + 1) > sequence.length()) {
				index = -1;
				break;
			}
			String symbol = sequence.substring(item.getIndex(), item.getIndex() + 1);
			if (!symbol.equals(item.getSymbol())) {
				index = -1;
				break;
			}
			index = item.getIndex() + 1;
		}
		return index;
	}

}
