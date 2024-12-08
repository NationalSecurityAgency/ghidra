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
package ghidra.util;

import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.util.database.DBSynchronizedSpliterator;
import ghidra.util.database.SynchronizedSpliterator;

/**
 * Some utilities for streams
 */
public class StreamUtils {
	private StreamUtils() {
	}

	/**
	 * Union two sorted streams into a single sorted stream
	 * 
	 * @param <T> the type of elements
	 * @param streams the streams to be merged
	 * @param comparator the comparator that orders each stream and that will order the resulting
	 *            stream
	 * @return the sorted stream
	 */
	@SuppressWarnings("unchecked")
	public static <T> Stream<T> merge(Collection<? extends Stream<? extends T>> streams,
			Comparator<? super T> comparator) {
		if (streams.size() == 1) {
			return (Stream<T>) streams.iterator().next();
		}
		return StreamSupport.stream(new MergeSortingSpliterator<>(
			streams.stream().map(s -> s.spliterator()).toList(), comparator), false);
	}

	/**
	 * Adapt a stream into an iterable
	 * 
	 * @param <T> the type of elements
	 * @param stream the stream
	 * @return an iterable over the same elements in the stream in the same order
	 */
	@SuppressWarnings("unchecked")
	public static <T> Iterable<T> iter(Stream<? extends T> stream) {
		return () -> (Iterator<T>) stream.iterator();
	}

	/**
	 * Wrap the given stream into a synchronized stream on the given object's intrinsic lock
	 * 
	 * <p>
	 * <b>NOTE:</b> This makes no guarantees regarding the consistency or visit order if the
	 * underlying resource is modified between elements being visited. It merely prevents the stream
	 * client from accessing the underlying resource concurrently. For such guarantees, the client
	 * may need to acquire the lock for its whole use of the stream.
	 * 
	 * @param <T> the type of elements
	 * @param lock the object on which to synchronize
	 * @param stream the (un)synchronized stream
	 * @return the synchronized stream
	 */
	public static <T> Stream<T> sync(Object lock, Stream<T> stream) {
		var wrapped = new SynchronizedSpliterator<T>(stream.spliterator(), lock);
		return StreamSupport.stream(wrapped, stream.isParallel());
	}

	/**
	 * Wrap the given stream into a synchronized stream on the given lock
	 * 
	 * <p>
	 * <b>NOTE:</b> This makes no guarantees regarding the consistency or visit order if the
	 * underlying resource is modified between elements being visited. It merely prevents the stream
	 * client from accessing the underlying resource concurrently. For such guarantees, the client
	 * may need to acquire the lock for its whole use of the stream.
	 * 
	 * @param <T> the type of elements
	 * @param lock the lock
	 * @param stream the (un)synchronized stream
	 * @return the synchronized stream
	 */
	public static <T> Stream<T> lock(java.util.concurrent.locks.Lock lock, Stream<T> stream) {
		var wrapped = new DBSynchronizedSpliterator<T>(stream.spliterator(), lock);
		return StreamSupport.stream(wrapped, stream.isParallel());
	}
}
