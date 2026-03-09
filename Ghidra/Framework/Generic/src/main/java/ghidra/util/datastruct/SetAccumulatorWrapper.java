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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An accumulator that will only pass on unique items to the wrapped accumulator.  This class uses
 * a concurrent set, which means that the data will be copied in this accumulator while it is being 
 * used.
 *
 * @param <T> the type
 */
public class SetAccumulatorWrapper<T> implements Accumulator<T> {

	private Set<T> set = ConcurrentHashMap.newKeySet();
	private Accumulator<T> accumulator;

	public SetAccumulatorWrapper(Accumulator<T> accumulator) {
		this.accumulator = accumulator;
	}

	@Override
	public void add(T t) {
		if (set.add(t)) {
			accumulator.add(t);
		}
	}

	@Override
	public void addAll(Collection<T> collection) {
		for (T t : collection) {
			add(t);
		}
	}

	@Override
	public int getProgress() {
		return set.size();
	}

	/**
	 * Returns the internal Set used by this class.  This should only be called when the data is 
	 * finished loading.
	 * @return the set
	 */
	public Set<T> asSet() {
		return set;
	}
}
