/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.datastruct;

import java.util.Comparator;

/**
 * Comparator for sorting Strings in a case insensitive way except that case insensitive duplicates
 * are then sub-sorted by reverse case so that lower case is before upper case.
 *
 * Example:   the strings "abc", "bob", "Bob", "zzz" would always sort as shown.  In a normal case 
 * insensitive sort, the "bob" and "Bob" order would be arbitrary.
 * 
 */
public class CaseInsensitiveDuplicateStringComparator implements Comparator<String> {

	@Override
	public int compare(String name1, String name2) {

		// if the names are the same ignoring case...
		int result = name1.compareToIgnoreCase(name2);
		if (result == 0) {
			// ... then reverse sort case-sensitive so lower-case comes first
			result = -name1.compareTo(name2);
		}
		return result;
	}
}
