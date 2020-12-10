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

import java.util.Deque;
import java.util.LinkedList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Consumer;

/**
 * A race which orders futures by completion time
 * 
 * This is roughly equivalent to Java's
 * {@link CompletableFuture#acceptEither(CompletionStage, Consumer)} or
 * {@link CompletableFuture#anyOf(CompletableFuture...)}; however, it is more general. Many futures
 * may participate in the race. Each call to {@link #include(CompletableFuture)} adds a participant
 * to the race. A call to {@link #next()} returns a future which completes when the first
 * participant completes. This subsumes and provides a shorthand for the standard methods. A second
 * call to {@link #next()} returns a future which completes when the second participant completes,
 * and so on.
 * 
 * This primitive does not provide a means to identify the winning participants. If identification
 * is desired, it must be done via the yielded object, or out of band.
 * 
 * @param <T> the type of object yielded by race participants
 */
public class AsyncRace<T> {
	private final Deque<T> finishers = new LinkedList<>();
	private final Deque<CompletableFuture<? super T>> queue = new LinkedList<>();

	/**
	 * Include a participant in this race
	 * 
	 * @param future the participant to add
	 */
	public AsyncRace<T> include(CompletableFuture<? extends T> future) {
		future.thenAccept(t -> {
			synchronized (this) {
				if (queue.isEmpty()) {
					finishers.offer(t);
				}
				else {
					queue.poll().complete(t);
				}
			}
		});
		return this;
	}

	/**
	 * Obtain a future that completes with the result of the first (since last called) finishing
	 * participant
	 * 
	 * @return the next "any of" future
	 */
	public synchronized CompletableFuture<T> next() {
		if (finishers.isEmpty()) {
			CompletableFuture<T> future = new CompletableFuture<>();
			queue.offer(future);
			return future;
		}
		return CompletableFuture.completedFuture(finishers.poll());
	}
}
