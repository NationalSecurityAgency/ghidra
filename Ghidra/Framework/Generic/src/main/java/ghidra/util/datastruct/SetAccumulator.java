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
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * An accumulator backed by a thread safe set.  This class has methods to retrieve the data once all
 * loading has finished. 
 *
 * <P>
 * API uses of the accumulator are inherently multi-threaded.  The set in this class is 
 * synchronized so that the data in the accumulator will be visible to the client thread.
 *
 * @param <T> the type
 */
public class SetAccumulator<T> implements Accumulator<T>, Iterable<T> {

	private Set<T> set = ConcurrentHashMap.newKeySet();

	@Override
	public void add(T t) {
		set.add(t);
	}

	@Override
	public void addAll(Collection<T> collection) {
		set.addAll(collection);
	}

	public boolean contains(T t) {
		return set.contains(t);
	}

	public Collection<T> get() {
		return set;
	}

	public Set<T> asSet() {
		return set;
	}

	@Override
	public int getProgress() {
		return set.size();
	}

	public int size() {
		return set.size();
	}

	@Override
	public Iterator<T> iterator() {
		return set.iterator();
	}

	public Stream<T> stream() {
		return StreamSupport.stream(spliterator(), false);
	}

	@Override
	public String toString() {
		return set.toString();
	}
}
