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

public class SizeLimitedAccumulatorWrapper<T> implements Accumulator<T> {

	private Accumulator<T> accumulator;
	private int maxSize;

	/**
	 * Constructor.
	 *  
	 * @param accumulator the accumulator to pass items to
	 * @param maxSize the maximum number of items this accumulator will hold
	 */
	public SizeLimitedAccumulatorWrapper(Accumulator<T> accumulator, int maxSize) {
		this.accumulator = Objects.requireNonNull(accumulator);
		this.maxSize = maxSize;
	}

	@Override
	public Iterator<T> iterator() {
		return accumulator.iterator();
	}

	@Override
	public void add(T t) {
		accumulator.add(t);
	}

	@Override
	public void addAll(Collection<T> collection) {
		accumulator.addAll(collection);
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

	/**
	 * Returns true if this size of this accumulator is greater than or equal to the given 
	 * maximum size
	 * 
	 * @return true if the max size has been reachged
	 */
	public boolean hasReachedSizeLimit() {
		return accumulator.size() >= maxSize;
	}
}
