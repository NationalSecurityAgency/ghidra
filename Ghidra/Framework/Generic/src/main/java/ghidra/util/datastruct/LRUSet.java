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
package ghidra.util.datastruct;

import java.util.Iterator;

/**
 * An ordered set-like data structure.   
 * <P>
 * Use this when you need a collection of unique items (hence set) that are also ordered by 
 * insertion time.
 *
 * @param <T> the type of items in the set
 */
public class LRUSet<T> extends LRUMap<T, T> implements Iterable<T> {

	/**
	 * Constructs this set with the given size.  As elements are added, the oldest elements 
	 * (by access time) will fall off the bottom of the set.
	 * <p>
	 * If you do not wish to have a set bounded by size, then you can override 
	 * {@link #removeEldestEntry(java.util.Map.Entry)} to do nothing.
	 * 
	 * @param size The size to which this set will be restricted.
	 */
	public LRUSet(int size) {
		super(size);
	}

	public void add(T t) {
		put(t, t);
	}

	@Override
	public Iterator<T> iterator() {
		return keySet().iterator();
	}

	@Override
	public String toString() {
		return map.keySet().toString();
	}
}
