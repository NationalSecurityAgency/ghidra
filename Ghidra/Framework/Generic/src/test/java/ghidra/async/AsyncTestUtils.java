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

import java.util.concurrent.*;

import ghidra.util.SystemUtilities;

public interface AsyncTestUtils {
	static final long TIMEOUT_MS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;
	static final long RETRY_INTERVAL_MS = 100;

	default <T> T waitOnNoValidate(CompletableFuture<T> future) throws Throwable {
		// Do this instead of plain ol' .get(time), to ease debugging
		// When suspended in .get(time), you can't introspect much, otherwise
		long started = System.currentTimeMillis();
		while (true) {
			try {
				return future.get(100, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException e) {
				if (Long.compareUnsigned(System.currentTimeMillis() - started, TIMEOUT_MS) >= 0) {
					throw e;
				}
			}
			catch (Exception e) {
				throw AsyncUtils.unwrapThrowable(e);
			}
		}
	}

	default void validateCompletionThread() {
	}

	default <T> T waitOn(CompletableFuture<T> future) throws Throwable {
		/**
		 * NB. CF's may issue dependent callbacks either on the thread completing the dependency, or
		 * on the thread chaining the dependent. If the CF completes before the chain, then the
		 * callback comes to me, and so currentThread will not be the model's callback thread. Thus,
		 * I should not validate the currentThread at callback if it is the currentThread now.
		 */
		Thread waitingThread = Thread.currentThread();
		CompletableFuture<T> validated = future.whenComplete((t, ex) -> {
			if (Thread.currentThread() != waitingThread) {
				validateCompletionThread();
			}
		});
		return waitOnNoValidate(validated);
	}
}
