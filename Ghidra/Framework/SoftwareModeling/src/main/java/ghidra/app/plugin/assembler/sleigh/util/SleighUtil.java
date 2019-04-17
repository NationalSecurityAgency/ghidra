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
package ghidra.app.plugin.assembler.sleigh.util;

import java.util.Collection;
import java.util.Iterator;

/**
 * Utilities for {@link Collection}s
 */
public class SleighUtil {
	/**
	 * Compare two collections by their corresponding elements in order
	 * 
	 * If the collections have differing sizes, the ordering does not matter. The smaller
	 * collection precedes the larger. Otherwise, each corresponding pair of elements are compared.
	 * Once an unequal pair is found, the collections are ordered by those elements. This is
	 * analogous to {@link String} comparison.
	 * @param a the first set
	 * @param b the second set
	 * @return a comparison result as in {@link Comparable#compareTo(Object)}
	 */
	public static <T extends Comparable<T>> int compareInOrder(Collection<T> a, Collection<T> b) {
		int result;
		result = a.size() - b.size();
		if (result != 0) {
			return result;
		}
		Iterator<T> ita = a.iterator();
		Iterator<T> itb = b.iterator();
		while (ita.hasNext()) {
			result = ita.next().compareTo(itb.next());
			if (result != 0) {
				return result;
			}
		}
		return 0;
	}

	/**
	 * Compare two byte arrays by their corresponding entries
	 * 
	 * If the two arrays have differing lengths, the shorter precedes the longer. Otherwise, they
	 * are compared as in C's {@code memcmp}, except that Java {@code byte}s are signed.
	 * @param a the first array
	 * @param b the second array
	 * @return a comparison result as in {@link Comparable#compareTo(Object)}
	 */
	public static int compareArrays(byte[] a, byte[] b) {
		int result;
		result = a.length - b.length;
		if (result != 0) {
			return result;
		}
		for (int i = 0; i < a.length; i++) {
			result = a[i] - b[i];
			if (result != 0) {
				return result;
			}
		}
		return 0;
	}

}
