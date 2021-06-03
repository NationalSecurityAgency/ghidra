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
import java.util.function.Consumer;

/**
 * An implementation of {@link Accumulator} that allows clients to easily process items as
 * they arrive. 
 * 
 * <P>This class is different than normal accumulators in that the values are <b>not</b> 
 * stored internally.  As such, calls to {@link #get()}, {@link #iterator()} and 
 * {@link #size()} will reflect having no data.
 *
 * @param <T> the type of the item being accumulated
 */
public class CallbackAccumulator<T> implements Accumulator<T> {

	private final Collection<T> NULL_COLLECTION = Collections.emptyList();

	private Consumer<T> consumer;

	/**
	 * Constructor
	 * 
	 * @param consumer the consumer that will get called each time an item is added
	 */
	public CallbackAccumulator(Consumer<T> consumer) {
		this.consumer = Objects.requireNonNull(consumer, "Consumer callback cannot be null");
	}

	@Override
	public void add(T t) {
		consumer.accept(t);
	}

	@Override
	public void addAll(Collection<T> collection) {
		for (T t : collection) {
			consumer.accept(t);
		}
	}

	@Override
	public boolean contains(T t) {
		return false;
	}

	@Override
	public Collection<T> get() {
		return NULL_COLLECTION;
	}

	@Override
	public Iterator<T> iterator() {
		return NULL_COLLECTION.iterator();
	}

	@Override
	public int size() {
		return 0;
	}

}
