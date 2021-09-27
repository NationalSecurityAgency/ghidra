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
package ghidra.app.plugin.core.format;

import java.util.*;

/**
 * Defines a selection for byte blocks.
 * 
 * The selection is a list of disjoint ranges.
 */
public class ByteBlockSelection {
	private final List<ByteBlockRange> list;

	/**
	 * Construct a selection from a list of ranges
	 * 
	 * @param ranges the ranges
	 */
	public ByteBlockSelection(List<ByteBlockRange> ranges) {
		list = new ArrayList<>(ranges);
	}

	/**
	 * Construct an empty selection.
	 */
	public ByteBlockSelection() {
		this(new ArrayList<>());
	}

	/**
	 * Construct a selection from an array of ranges
	 * 
	 * @param ranges the ranges
	 */
	public ByteBlockSelection(ByteBlockRange[] ranges) {
		this(Arrays.asList(ranges));
	}

	/**
	 * Add a range to the selection.
	 * 
	 * @param range the range to add
	 */
	public void add(ByteBlockRange range) {
		list.add(range);
	}

	/**
	 * Get the number of byte block ranges in this selection.
	 * 
	 * @return the number of (disjoint) ranges
	 */
	public int getNumberOfRanges() {
		return list.size();
	}

	/**
	 * Get the byte block range at the given index.
	 * 
	 * @param index the index of the range to get
	 * @return the requested range
	 */
	public ByteBlockRange getRange(int index) {
		return list.get(index);
	}

}
