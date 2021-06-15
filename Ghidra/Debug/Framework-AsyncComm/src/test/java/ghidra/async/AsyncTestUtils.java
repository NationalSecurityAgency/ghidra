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

import java.util.Collection;
import java.util.concurrent.*;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.async.AsyncUtils.TemperamentalRunnable;
import ghidra.async.AsyncUtils.TemperamentalSupplier;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public interface AsyncTestUtils {
	static final long TIMEOUT_MS =
		SystemUtilities.isInTestingBatchMode() ? 5000 : Long.MAX_VALUE;
	static final long RETRY_INTERVAL_MS = 100;

	default <T> T waitOnNoValidate(CompletableFuture<T> future) {
		// Do this instead of plain ol' .get(time), to ease debugging
		// When suspended in .get(time), you can't introspect much, otherwise
		long started = System.currentTimeMillis();
		while (true) {
			try {
				return future.get(100, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException e) {
				if (Long.compareUnsigned(System.currentTimeMillis() - started, TIMEOUT_MS) >= 0) {
					throw new RuntimeException(AsyncUtils.unwrapThrowable(e));
				}
			}
			catch (Exception e) {
				Throwable unwrapped = AsyncUtils.unwrapThrowable(e);
				if (unwrapped instanceof RuntimeException) {
					throw (RuntimeException) unwrapped;
				}
				return ExceptionUtils.rethrow(e);
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

	default void retryVoid(TemperamentalRunnable runnable,
			Collection<Class<? extends Throwable>> retriable) throws Throwable {
		retry(() -> {
			runnable.run();
			return null;
		}, retriable);
	}

	default <T> T retry(TemperamentalSupplier<T> supplier,
			Collection<Class<? extends Throwable>> retriable) throws Throwable {
		return retry(TIMEOUT_MS, supplier, retriable);
	}

	default <T> T retry(long timeoutMs, TemperamentalSupplier<T> supplier,
			Collection<Class<? extends Throwable>> retriable) throws Throwable {
		long retryAttempts = timeoutMs / RETRY_INTERVAL_MS;
		Throwable lastExc = null;
		for (int i = 0; i < retryAttempts; i++) {
			if (i != 0) {
				Thread.sleep(RETRY_INTERVAL_MS);
			}
			try {
				return supplier.get();
			}
			catch (Throwable e) {
				if (i < 10) {
					Msg.debug(this, "Retrying after " + e);
				}
				lastExc = e;
				for (Class<? extends Throwable> et : retriable) {
					if (et.isAssignableFrom(e.getClass())) {
						e = null;
						break;
					}
				}
				if (e != null) {
					throw e;
				}
			}
		}
		throw lastExc;
	}
}
