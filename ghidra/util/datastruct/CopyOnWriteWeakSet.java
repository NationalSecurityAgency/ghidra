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

import org.apache.commons.collections4.IteratorUtils;

/**
 * A set that avoids {@link ConcurrentModificationException}s by copying the internal storage 
 * <b>for every mutation operation</b>.  Thus, this data structure is only efficient when the 
 * number of event notification operations significantly out numbers mutations to this structure
 * (e.g., adding and removing items.
 * <p>
 * An example use cases where using this class is a good fit would be a listener list where 
 * listeners are added during initialization, but not after that.   Further, this hypothetical 
 * list fires a large number of events.
 * <p>
 * A bad use of this class would be as a container to store widgets where the container the 
 * contents are changed often, but iterated over very little.
 * <p>
 * Finally, if this structure is only ever used from a single thread, like the Swing thread, then
 * you do not need the overhead of this class, as the Swing thread synchronous access guarantees
 * that the structure cannot be mutated while it is being iterated.  See 
 * {@link WeakDataStructureFactory#createSingleThreadAccessWeakSet()}.
 *
 * @param <T>
 * @see WeakSet
 */
class CopyOnWriteWeakSet<T> extends WeakSet<T> {

	CopyOnWriteWeakSet() {
		// restrict access; use factory method in base class
	}

	@Override
	public synchronized Iterator<T> iterator() {
		return IteratorUtils.unmodifiableIterator(weakHashStorage.keySet().iterator());
	}

	@Override
	public synchronized void add(T t) {
		maybeWarnAboutAnonymousValue(t);
		weakHashStorage = new WeakHashMap<>(weakHashStorage);
		weakHashStorage.put(t, null);
	}

	@Override
	public synchronized void remove(T t) {
		weakHashStorage = new WeakHashMap<>(weakHashStorage);
		weakHashStorage.remove(t);
	}

	@Override
	public synchronized void clear() {
		weakHashStorage = new WeakHashMap<>();
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
