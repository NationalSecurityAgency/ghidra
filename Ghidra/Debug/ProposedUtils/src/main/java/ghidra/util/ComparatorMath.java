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
package ghidra.util;

import java.util.Comparator;

public enum ComparatorMath {
	;

	public static <C> C cmin(C a, C b, Comparator<C> comp) {
		return comp.compare(a, b) <= 0 ? a : b;
	}

	public static <C extends Comparable<C>> C cmin(C a, C b) {
		return cmin(a, b, Comparator.naturalOrder());
	}

	public static <C> C cmax(C a, C b, Comparator<C> comp) {
		return comp.compare(a, b) >= 0 ? a : b;
	}

	public static <C extends Comparable<C>> C cmax(C a, C b) {
		return cmax(a, b, Comparator.naturalOrder());
	}
}
