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
package ghidra.util.database;

import java.util.Spliterator;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Wraps an unsynchronized spliterator in one that synchronizes on a given object's intrinsic lock,
 * often the collection that provided the stream or spliterator.
 * 
 * @param <T> the type of elements
 */
public class SynchronizedSpliterator<T> implements Spliterator<T> {
	private final Spliterator<T> spliterator;
	private final Object lock;

	public SynchronizedSpliterator(Spliterator<T> spliterator, Object lock) {
		this.spliterator = spliterator;
		this.lock = lock;
	}

	@Override
	public boolean tryAdvance(Consumer<? super T> action) {
		AtomicReference<T> ref = new AtomicReference<>();
		boolean result;
		synchronized (lock) {
			result = spliterator.tryAdvance(ref::set);
		}
		if (!result) {
			return false;
		}
		action.accept(ref.get());
		return true;
	}

	@Override
	public Spliterator<T> trySplit() {
		Spliterator<T> newSplit;
		synchronized (lock) {
			newSplit = spliterator.trySplit();
		}
		if (newSplit == null) {
			return null;
		}
		return new SynchronizedSpliterator<>(newSplit, lock);
	}

	@Override
	public long estimateSize() {
		synchronized (lock) {
			return spliterator.estimateSize();
		}
	}

	@Override
	public int characteristics() {
		synchronized (lock) {
			return spliterator.characteristics();
		}
	}
}
