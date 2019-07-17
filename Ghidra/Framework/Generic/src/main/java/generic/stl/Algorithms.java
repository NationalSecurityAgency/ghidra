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
package generic.stl;


public class Algorithms {
	public static <T> IteratorSTL<T> lower_bound(IteratorSTL<T> start, IteratorSTL<T> end, T key) {
		if (!(key instanceof Comparable)) {
			throw new IllegalArgumentException("Element must implement Comparable");
		}
		Comparable<T> comparableKey = (Comparable<T>)key;
		IteratorSTL<T> cur = start.copy();
		for(;!cur.equals(end);cur.increment()) {
			int result = comparableKey.compareTo( cur.get() );
			if (result <= 0) {
				return cur;
			}
		}
		return end;
	}
	public static <T> IteratorSTL<T> upper_bound(IteratorSTL<T> start, IteratorSTL<T> end, T key) {
		if (!(key instanceof Comparable)) {
			throw new IllegalArgumentException("Element must implement Comparable");
		}
		Comparable<T> comparableKey = (Comparable<T>)key;
		IteratorSTL<T> cur = start.copy();
		for(;!cur.equals(end);cur.increment()) {
			int result = comparableKey.compareTo( cur.get() );
			if (result < 0) {
				return cur;
			}
		}
		return end;
	}
}
