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
package datagraph.data.graph.panel;

import java.util.Comparator;

/**
 * Comparator for comparing two data component paths
 */
public class DtComponentPathComparator implements Comparator<int[]> {
	@Override
	public int compare(int[] o1, int[] o2) {
		int level = 0;
		int length1 = o1.length;
		int length2 = o2.length;
		while (level < length1 && level < length2) {
			int index1 = o1[level];
			int index2 = o2[level];
			if (index1 != index2) {
				return index1 - index2;
			}
			level++;
		}
		if (length1 == length2) {
			return 0;
		}
		return length1 - length2;

	}
}
