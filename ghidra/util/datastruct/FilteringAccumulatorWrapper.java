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
import java.util.function.Predicate;

/**
 * A class that allows clients to wrap a given accumulator, only adding elements that pass the
 * given filter.
 *
 * @param <T> the type of the accumulator
 */
public class FilteringAccumulatorWrapper<T> implements Accumulator<T> {

	private Accumulator<T> accumulator;
	private Predicate<T> predicate;

	/**
	 * Constructor.
	 *  
	 * @param accumulator the accumulator to pass items to
	 * @param passesFilterPredicate the predicate that will return true for items that should be
	 *        allowed to pass
	 */
	public FilteringAccumulatorWrapper(Accumulator<T> accumulator,
			Predicate<T> passesFilterPredicate) {
		this.predicate = passesFilterPredicate;
		this.accumulator = Objects.requireNonNull(accumulator);
	}

	private boolean passesFilter(T t) {
		return predicate.test(t);
	}

	@Override
	public Iterator<T> iterator() {
		return accumulator.iterator();
	}

	@Override
	public void add(T t) {
		if (passesFilter(t)) {
			accumulator.add(t);
		}
	}

	@Override
	public void addAll(Collection<T> collection) {
		collection.forEach(t -> {
			if (passesFilter(t)) {
				accumulator.add(t);
			}
		});
	}

	@Override
	public boolean contains(T t) {
		return accumulator.contains(t);
	}

	@Override
	public Collection<T> get() {
		return accumulator.get();
	}

	@Override
	public int size() {
		return accumulator.size();
	}

}
