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
import java.util.stream.Stream;

/**
 * A copy on read set that will create a copy of its internal data for iteration operations.  This
 * allows clients to avoid concurrency issue by allowing mutates during reads.  All operations
 * of this class are synchronized to allow clients to use non-iterative methods without the need
 * for a copy operation.
 *
 * @param <T> the type
 */
class CopyOnReadWeakSet<T> extends WeakSet<T> {

	protected CopyOnReadWeakSet() {
		// restrict access; use factory method in WeakDataStructureFactory
	}

	private synchronized Collection<T> createCopy() {
		Set<T> ks = weakHashStorage.keySet();
		return new ArrayList<>(ks);
	}

	@Override
	public synchronized void add(T t) {
		maybeWarnAboutAnonymousValue(t);
		weakHashStorage.put(t, null);
	}

	@Override
	public synchronized void remove(T t) {
		weakHashStorage.remove(t);
	}

	@Override
	public synchronized void clear() {
		weakHashStorage.clear();
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

	@Override
	public synchronized String toString() {
		return weakHashStorage.keySet().toString();
	}

	@Override
	public synchronized Iterator<T> iterator() {
		return createCopy().iterator();
	}

	@Override
	public synchronized Collection<T> values() {
		return createCopy();
	}

	@Override
	public synchronized Stream<T> stream() {
		return createCopy().stream();
	}

}
