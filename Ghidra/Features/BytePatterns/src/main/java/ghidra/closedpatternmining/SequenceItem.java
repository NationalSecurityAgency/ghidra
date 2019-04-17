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
 * A SequenceItem objects represents a item (character) in a sequence.
 * We include the index as part of the character - so an "A" in the
 * first position is not the same item as an "A" in the second position
 * (in the literature both instances of A would normally be considered 
 * the same item)
 *
 */

public class SequenceItem implements Comparable<SequenceItem> {
	private String symbol;
	private int index;

	public SequenceItem(String item, int index) {
		if (item.length() != 1) {
			throw new IllegalArgumentException("frequent item " + item + " must be of length 1");
		}
		this.index = index;
		this.symbol = item;
	}

	/**
	 * Get the symbol associated with this item
	 * @return the symbol
	 */
	public String getSymbol() {
		return symbol;
	}

	/**
	 * Get the index associated with this item
	 * @return the index
	 */
	public int getIndex() {
		return index;
	}

	@Override
	public int hashCode() {
		return symbol.hashCode() + 31 * index;
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
		SequenceItem other = (SequenceItem) obj;
		if (!other.getSymbol().equals(symbol)) {
			return false;
		}
		if (!(other.getIndex() == index)) {
			return false;
		}
		return true;
	}

	/**
	 * Generates a String from a list of {@link SequenceItem}s with each missing {@link SequenceItem} replaces by a "."
	 * @param itemList list of items
	 * @param totalLength length of String to write, including each "."
	 * @return the String
	 */
	public static String getDittedString(List<SequenceItem> itemList, int totalLength) {
		StringBuilder sb = new StringBuilder();
		int symbolsWritten = 0;
		for (SequenceItem currentItem : itemList) {
			if (currentItem.getIndex() < symbolsWritten) {
				throw new IllegalArgumentException(
					"itemList must be in ascending order of item index");
			}
			while (currentItem.getIndex() > symbolsWritten) {
				sb.append(".");//add a dit
				symbolsWritten++;
			}
			sb.append(currentItem.getSymbol());
			symbolsWritten++;
		}
		if (symbolsWritten > totalLength) {
			throw new IllegalArgumentException("mismatch between itemList and totalLength");
		}
		while (symbolsWritten < totalLength) {
			sb.append(".");
			symbolsWritten++;
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("item: ");
		sb.append(symbol);
		sb.append(", index: ");
		sb.append(index);
		return sb.toString();
	}

	@Override
	public int compareTo(SequenceItem arg0) {
		if (index != arg0.getIndex()) {
			return index - arg0.getIndex();
		}
		return symbol.compareTo(arg0.getSymbol());
	}

}
