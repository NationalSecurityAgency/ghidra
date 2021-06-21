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

import java.util.*;

/**
 * This is a static utility class used to partition a set of long values into as many
 * non-intersecting BitGroups as possible.
 */
public class EnumValuePartitioner {

	private static void merge(List<BitGroup> list, BitGroup bitGroup) {
		Iterator<BitGroup> iterator = list.iterator();
		while (iterator.hasNext()) {
			BitGroup next = iterator.next();
			if (bitGroup.intersects(next)) {
				bitGroup.merge(next);
				iterator.remove();
			}
		}
		list.add(bitGroup);
	}

	/**
	 * Partition the given values into a list of non-intersecting BitGroups.
	 * @param values the values to be partitioned.
	 * @param size size of enum value in bytes
	 * @return a list of BitGroups with non-intersecting bits.
	 */
	public static List<BitGroup> partition(long[] values, int size) {
		List<BitGroup> list = new LinkedList<>();
		long totalMask = 0;
		for (long value : values) {
			totalMask |= value;
			BitGroup bitGroup = new BitGroup(value);
			merge(list, bitGroup);
		}
		// now create a BitGroup for all bits not accounted for
		long enumMask = ~(-1 << (size * 8));
		list.add(new BitGroup(~totalMask & enumMask));

		return list;
	}
}
