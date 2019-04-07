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
package ghidra.program.model.data;

import java.util.HashSet;
import java.util.Set;

/**
 * Class used to organize long values into sets of values with overlapping bits.
 * For example, if you had values 1,2,3, 8, 12, you could partition them into two bit groups.
 * The values 1,2,3, would be in one bit group because they all either use the "1" or "2" bit
 * (If there was on "3", then 1 and 2 could be in separate groups). Also the values "8" and "12"
 * are in the same group since they share the "8" bit.
 */
public class BitGroup {
	private Set<Long> values = new HashSet<>();
	private long mask;

	/**
	 * Creates a new BitGroup seeded with a value.
	 * @param value the value to start the bit group.
	 */
	BitGroup(long value) {
		values.add(value);
		mask = value;
	}

	/**
	 * Tests if this bit group has any overlapping bits with the given bit group.
	 * @param bitGroup the BitGroup to test for overlap.
	 * @return true if the groups have any bits in common.
	 */
	public boolean intersects(BitGroup bitGroup) {
		return (mask & bitGroup.mask) != 0;
	}

	/**
	 * Merges the given BitGroup into the group.  All of its values will be added to this
	 * group's values and the masks will be or'ed together.
	 * @param bitGroup the BitGroup to merge into this one.
	 */
	public void merge(BitGroup bitGroup) {
		values.addAll(bitGroup.values);
		mask = mask | bitGroup.mask;
	}

	@Override
	public String toString() {
		StringBuffer buf = new StringBuffer("BitGroup - Mask: ");
		buf.append(Long.toHexString(mask));
		buf.append(" values: ");
		for (Long value : values) {
			buf.append(value);
			buf.append(",");
		}
		return buf.toString();
	}

	/**
	 * Returns the mask that represents all the bits that are used by the values in this
	 * BitGroup.
	 * @return the mask that represents all the bits that are used by the values in this
	 * BitGroup.
	 */
	public long getMask() {
		return mask;
	}

	/**
	 * Gets the set of values that make up this BitGroup.
	 * @return the set of values that make up this BitGroup.
	 */
	public Set<Long> getValues() {
		return values;
	}
}
