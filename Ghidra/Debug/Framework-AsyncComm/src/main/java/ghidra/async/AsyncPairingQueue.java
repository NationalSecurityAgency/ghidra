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

public class AsyncPairingQueue<T> {
	private final Deque<CompletableFuture<? extends T>> givers = new LinkedList<>();
	private final Deque<CompletableFuture<T>> takers = new LinkedList<>();

	public void give(CompletableFuture<? extends T> giver) {
		CompletableFuture<T> taker;
		synchronized (givers) {
			if (takers.isEmpty()) {
				givers.add(giver);
				return;
			}
			taker = takers.poll();
		}
		pair(giver, taker);
	}

	public CompletableFuture<T> give() {
		CompletableFuture<T> giver = new CompletableFuture<>();
		give(giver);
		return giver;
	}

	public CompletableFuture<T> take() {
		CompletableFuture<T> taker = new CompletableFuture<>();
		CompletableFuture<? extends T> giver;
		synchronized (givers) {
			if (givers.isEmpty()) {
				takers.add(taker);
				return taker;
			}
			giver = givers.poll();
		}
		pair(giver, taker);
		return taker;
	}

	private void pair(CompletableFuture<? extends T> giver, CompletableFuture<T> taker) {
		giver.handle((val, exc) -> {
			if (exc != null) {
				taker.completeExceptionally(exc);
			}
			else {
				taker.complete(val);
			}
			return null;
		});
	}
}
