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
package docking.widgets.table;

import java.util.Comparator;

/**
 * A utility class for tables to use when sorting
 */
public class TableComparators {

	private static final Comparator<Object> NO_SORT_COMPARATOR = (o1, o2) -> 0;

	@SuppressWarnings("unchecked") // we are casting to Object; safe since everything is an Object
	public static <T> Comparator<T> getNoSortComparator() {
		return (Comparator<T>) NO_SORT_COMPARATOR;
	}

	public static int compareWithNullValues(Object o1, Object o2) {
		// If both values are null return 0
		if (o1 == null && o2 == null) {
			return 0;
		}

		if (o1 == null) { // Define null less than everything.
			return -1;
		}

		return 1; // o2 is null, so the o1 comes after
	}
}
