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

import java.util.Collection;

/**
 * 
 * An object of this class represents a frequent item in a sequence:
 * it is an item along with the support (= number of sequences containing the item)
 *
 */

public class FrequentSequenceItem implements Comparable<FrequentSequenceItem> {

	private int support;     //number of sequences which contain the item
	private SequenceItem frequentItem;

	/**
	 * Create a {@link FrequentSequenceItem} with a specified support and underlying {@link SequenceItem}
	 * @param support
	 * @param frequentItem
	 */
	public FrequentSequenceItem(int support, SequenceItem frequentItem) {
		if (support <= 0) {
			throw new IllegalArgumentException("support must be positive");
		}
		this.support = support;
		this.frequentItem = frequentItem;
	}

	/**
	 * Returns the support (number of sequences which contain the item)
	 * @return the support
	 */
	public int getSupport() {
		return support;
	}

	/**
	 * Returns the item
	 * @return the item
	 */
	public SequenceItem getItem() {
		return frequentItem;
	}

	@Override
	public int hashCode() {
		return 23 * support + frequentItem.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FrequentSequenceItem other = (FrequentSequenceItem) obj;
		if (!other.getItem().equals(frequentItem)) {
			return false;
		}
		if (!(other.getSupport() == support)) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("support (number of sequences containing the item): ");
		sb.append(Integer.toString(support));
		sb.append(", ");
		sb.append(frequentItem.toString());
		sb.append("\n");
		return sb.toString();
	}

	/**
	 * Gets a pretty string representation of a Collection of {@link FrequentSequenceItem}s.
	 * @param The collection to pretty-print
	 * @return the pretty String
	 */
	public static String getPrettyString(Collection<FrequentSequenceItem> items) {
		StringBuilder sb = new StringBuilder();
		sb.append("\n");
		if (items.size() == 0) {
			sb.append("empty!");
		}
		else {
			for (FrequentSequenceItem fItem : items) {
				sb.append(fItem.toString());
			}
		}
		return sb.toString();
	}

	/**
	 * Compares based on the support, which is the number of sequences
	 * which contain the item.
	 */
	@Override
	public int compareTo(FrequentSequenceItem arg0) {
		int itemCompare = getItem().compareTo(arg0.getItem());
		if (itemCompare == 0) {
			return support - arg0.getSupport();
		}
		return itemCompare;
	}
}
