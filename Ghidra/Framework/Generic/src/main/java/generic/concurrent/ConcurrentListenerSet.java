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
package generic.concurrent;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A listener set that is weakly consistent.  This allows for iteration of the set while other
 * threads modify the set.
 */
public class ConcurrentListenerSet<T> implements Iterable<T> {

	// we use a ConcurrentHashMap because Java has no ConcurrentHashSet
	private ConcurrentHashMap<T, T> storage = new ConcurrentHashMap<>();

	public void add(T t) {
		storage.put(t, t);
	}

	public void remove(T t) {
		storage.remove(t);
	}

	public void clear() {
		storage.clear();
	}

	@Override
	public Iterator<T> iterator() {
		return storage.keySet().iterator();
	}

	public List<T> asList() {
		return new ArrayList<>(storage.keySet());
	}
}
