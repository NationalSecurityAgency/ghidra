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
package ghidra.async;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Predicate;

/**
 * A queue of claims on an associated event
 * 
 * Often a single event handler processes all events of a given type or from a given source. This
 * class offers a means of "claiming" an event, so that it can be processed by a specific handler.
 * The general handler must call the {@link #satisfy(Object)} method, foregoing its usual handling
 * if it returns true.
 * 
 * This permits other threads to claim the next (unclaimed) event from the source. This is
 * particularly useful when the claimant knows it will also be the cause of the event, allowing it
 * to override the usual event processing with its own. Care must be taken to claim the event before
 * performing the action that will cause the event, otherwise a race condition arises wherein the
 * caused event may occur before the causer has claimed it.
 * 
 * @param <T> the type of the event
 */
public class AsyncClaimQueue<T> {
	private static class Entry<T> {
		final CompletableFuture<T> future;
		final Predicate<T> predicate;

		Entry(CompletableFuture<T> future, Predicate<T> predicate) {
			this.future = future;
			this.predicate = predicate;
		}
	}

	private final Deque<Entry<T>> queue = new LinkedList<>();

	/**
	 * Claim the next unclaimed occurrence of the event.
	 * 
	 * @return a future which completes with the claimed occurrence
	 */
	public CompletableFuture<T> claim() {
		return claim(t -> true);
	}

	/**
	 * Claim, upon a predicate, the next unclaimed occurrence of the event.
	 * 
	 * If the occurrence does not satisfy the predicate, the next claim in the queue is tried, if
	 * present.
	 * 
	 * NOTE: The predicate should be fast and non-blocking, since it is executed while holding the
	 * lock to the internal queue.
	 * 
	 * @param predicate a condition upon which to claim the occurrence
	 * @return a future which completes with the claimed occurrence
	 */
	public CompletableFuture<T> claim(Predicate<T> predicate) {
		synchronized (queue) {
			CompletableFuture<T> future = new CompletableFuture<T>();
			queue.add(new Entry<>(future, predicate));
			return future;
		}
	}

	/**
	 * Notify a claimant, if any, of the occurrence of the event.
	 * 
	 * This method should be called by the usual handler for every occurrence the event of interest.
	 * If the occurrence is claimed, the claimant is notified, and true is returned. If the
	 * occurrence is free, false is returned, and the handler should proceed as usual.
	 * 
	 * @param t the event occurrence
	 * @return true if claimed, false otherwise
	 */
	public boolean satisfy(T t) {
		Entry<T> entry = null;
		synchronized (queue) {
			Iterator<Entry<T>> eit = queue.iterator();
			while (eit.hasNext()) {
				Entry<T> e = eit.next();
				if (e.predicate.test(t)) {
					entry = e;
					eit.remove();
					break;
				}
			}
		}
		if (entry == null) {
			return false;
		}
		entry.future.complete(t);
		return true;
	}
}
