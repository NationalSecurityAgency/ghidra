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
package docking.widgets.table.sort;

import java.util.Comparator;

import docking.widgets.table.TableComparators;

/**
 * A column comparator that is used when columns do not supply their own comparator.   This
 * comparator will use the natural sorting (i.e., the value implements Comparable), 
 * defaulting to the String representation for the given value.
 */
public class DefaultColumnComparator implements Comparator<Object> {

	@Override
	@SuppressWarnings("unchecked") // we checked cast to be safe
	public int compare(Object o1, Object o2) {

		if (o1 == null || o2 == null) {
			return TableComparators.compareWithNullValues(o1, o2);
		}

		Class<? extends Object> c1 = o1.getClass();
		Class<? extends Object> c2 = o2.getClass();
		if (String.class == c1 && String.class == c2) {
			return compareAsStrings(o1, o2);
		}

		if (Comparable.class.isAssignableFrom(c1) && c1 == c2) {
			@SuppressWarnings("rawtypes")
			Comparable comparable = (Comparable) o1;
			int result = comparable.compareTo(o2);
			return result;
		}

		// At this point we do not know how to compare these items well.  Return 0, which 
		// will signal to any further comparators that more comparing is needed.
		return 0;
	}

	private int compareAsStrings(Object o1, Object o2) {
		String s1 = o1.toString();
		String s2 = o2.toString();
		return s1.compareToIgnoreCase(s2);
	}
}
