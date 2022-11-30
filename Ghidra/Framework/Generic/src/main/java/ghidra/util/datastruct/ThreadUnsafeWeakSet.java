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

import java.util.Collection;
import java.util.Iterator;
import java.util.stream.Stream;

class ThreadUnsafeWeakSet<T> extends WeakSet<T> {

	ThreadUnsafeWeakSet() {
		// restrict access; use factory method in base class
	}

	@Override
	public void add(T t) {
		maybeWarnAboutAnonymousValue(t);
		weakHashStorage.put(t, null);
	}

	@Override
	public void remove(T t) {
		weakHashStorage.remove(t);
	}

	@Override
	public void clear() {
		weakHashStorage.clear();
	}

	@Override
	public Iterator<T> iterator() {
		return weakHashStorage.keySet().iterator();
	}

	@Override
	public Collection<T> values() {
		return weakHashStorage.keySet();
	}

	@Override
	public boolean isEmpty() {
		return weakHashStorage.isEmpty();
	}

	@Override
	public int size() {
		return weakHashStorage.size();
	}

	@Override
	public boolean contains(T t) {
		return weakHashStorage.containsKey(t);
	}

	@Override
	public String toString() {
		return weakHashStorage.toString();
	}

	@Override
	public Stream<T> stream() {
		return values().stream();
	}

}
