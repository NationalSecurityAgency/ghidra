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
package ghidra.util.datastruct;

import java.util.*;

public class SetAccumulator<T> implements Accumulator<T> {

	private Set<T> set;

	public SetAccumulator() {
		this.set = new HashSet<T>();
	}

	public SetAccumulator(Set<T> set) {
		this.set = set;
	}

	@Override
	public void add(T t) {
		set.add(t);
	}

	@Override
	public void addAll(Collection<T> collection) {
		set.addAll(collection);
	}

	@Override
	public boolean contains(T t) {
		return set.contains(t);
	}

	@Override
	public Collection<T> get() {
		return set;
	}

	public Set<T> asSet() {
		return set;
	}

	@Override
	public int size() {
		return set.size();
	}

	@Override
	public Iterator<T> iterator() {
		return set.iterator();
	}

	@Override
	public String toString() {
		return set.toString();
	}
}
