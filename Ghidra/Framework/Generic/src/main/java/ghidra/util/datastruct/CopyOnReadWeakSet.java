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

import java.util.*;

public class CopyOnReadWeakSet<T> extends WeakSet<T> {

	protected CopyOnReadWeakSet() {
		// restrict access; use factory method in WeakDataStructureFactory
	}

	/**
	 * Add the given object to the set.
	 */
	@Override
	public synchronized void add(T t) {
		maybeWarnAboutAnonymousValue(t);
		weakHashStorage.put(t, null);
	}

	/**
	 * Remove the given object from the data structure
	 */
	@Override
	public synchronized void remove(T t) {
		weakHashStorage.remove(t);
	}

	/**
	 * Remove all elements from this data structure
	 */
	@Override
	public synchronized void clear() {
		weakHashStorage.clear();
	}

	/**
	 * Returns an iterator over the elements in this data structure.
	 */
	@Override
	public synchronized Iterator<T> iterator() {
		Set<T> ks = weakHashStorage.keySet();
		List<T> list = new ArrayList<>(ks);
		return list.iterator();
	}

	@Override
	public synchronized Collection<T> values() {
		return weakHashStorage.keySet();
	}

	@Override
	public synchronized boolean isEmpty() {
		return weakHashStorage.isEmpty();
	}

	@Override
	public synchronized int size() {
		return weakHashStorage.size();
	}

	@Override
	public synchronized boolean contains(T t) {
		return weakHashStorage.containsKey(t);
	}
}
