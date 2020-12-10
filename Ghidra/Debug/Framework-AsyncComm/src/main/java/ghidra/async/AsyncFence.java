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

import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * A fence that completes when all participating futures complete
 * 
 * This provides an alternative shorthand for Java's
 * {@link CompletableFuture#thenAcceptBoth(CompletionStage, BiConsumer)} or
 * {@link CompletableFuture#allOf(CompletableFuture...)}.
 * 
 * Example:
 * 
 * <pre>
 * public CompletableFuture<Void> processAll(List<Integer> list) {
 * 	AsyncFence fence = new AsyncFence();
 * 	for (int entry : list) {
 * 		fence.include(process(entry));
 * 	}
 * 	return fence.ready();
 * }
 * </pre>
 */
public class AsyncFence {
	private final ArrayList<CompletableFuture<?>> participants = new ArrayList<>();
	private CompletableFuture<Void> ready;

	/**
	 * Include a participant with this fence
	 * 
	 * The result of the participating future is ignored implicitly. If the result is needed, it
	 * must be consumed out of band, e.g., by using {@link CompletableFuture#thenAccept(Consumer)}:
	 * 
	 * <pre>
	 * fence.include(process(entry).thenAccept(result::addTo));
	 * </pre>
	 * 
	 * Calling this method after {@link #ready()} will yield undefined results.
	 * 
	 * @param future the participant to add
	 */
	public synchronized AsyncFence include(CompletableFuture<?> future) {
		if (ready != null) {
			throw new IllegalStateException("Fence already ready");
		}
		participants.add(future);
		return this;
	}

	/**
	 * Obtain a future that completes when all participating futures have completed
	 * 
	 * Calling this method more than once will yield undefined results.
	 * 
	 * @return the "all of" future
	 */
	public synchronized CompletableFuture<Void> ready() {
		if (ready == null) {
			ready = CompletableFuture
					.allOf((participants.toArray(new CompletableFuture[participants.size()])));
		}
		return ready;
	}

	/**
	 * TODO
	 * 
	 * Diagnostic
	 * 
	 * @return
	 */
	public Set<CompletableFuture<?>> getPending() {
		return participants.stream().filter(f -> !f.isDone()).collect(Collectors.toSet());
	}
}
