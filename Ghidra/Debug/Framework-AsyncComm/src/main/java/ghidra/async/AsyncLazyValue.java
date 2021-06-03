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

import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * A value to be completed once upon the first request, asynchronously
 *
 * This contains a single lazy value. It is computed only if requested. When requested, a future is
 * returned and the computation is started. If the computation succeeds, the completed future is
 * cached indefinitely. Any subsequent requests return the same future, even if the computation has
 * not yet completed. Thus, when it completes, all requests will be fulfilled by the result of the
 * first request. If the computation completes exceptionally, the result is immediately discarded.
 * Thus, a subsequent request will retry the computation.
 *
 * @param <T> the type of the value
 */
public class AsyncLazyValue<T> {
	private CompletableFuture<T> future;
	private Throwable lastExc = null;
	private Supplier<CompletableFuture<T>> supplier;

	/**
	 * Construct a lazy value for the given computation
	 * 
	 * @param supplier specifies the computation
	 */
	public AsyncLazyValue(Supplier<CompletableFuture<T>> supplier) {
		this.supplier = supplier;
	}

	/**
	 * Request the value
	 * 
	 * If this is called before {@link #provide()}, the computation given at construction is
	 * launched. The {@link CompletableFuture} it provides is returned immediately. Subsequent calls
	 * to either {@link #request()} or {@link #provide()} return the same future without starting
	 * any new computation.
	 * 
	 * @return a future, possibly already completed, for the value
	 */
	public synchronized CompletableFuture<T> request() {
		if (future == null) {
			future = supplier.get();
			future.exceptionally((exc) -> {
				synchronized (this) {
					lastExc = exc;
					future = null;
				}
				// We return the future, not the result of exceptionally
				// So no need to rethrow here
				return null;
			});
		}
		// It's possible the future completed exceptionally on this thread, so future may be null
		if (future == null) {
			return CompletableFuture.failedFuture(lastExc);
		}
		return future;
	}

	/**
	 * Provide the value out of band
	 * 
	 * If this is called before {@link #request()}, the computation given at construction is
	 * ignored. A new {@link CompletableFuture} is returned instead. The caller must see to this
	 * future's completion. Subsequent calls to either {@link #request()} or {@link #provide()}
	 * return this same future without starting any computation.
	 * 
	 * Under normal circumstances, the caller cannot determine whethor or not is has "claimed" the
	 * computation. If the usual computation is already running, then the computations are
	 * essentially in a race. As such, it is essential that alternative computations result in the
	 * same value as the usual computation. In other words, the functions must not differ, but the
	 * means of computation can differ. Otherwise, race conditions may arise.
	 * 
	 * @return a promise that the caller must fulfill or arrange to have fulfilled
	 */
	public synchronized CompletableFuture<T> provide() {
		if (future == null) {
			future = new CompletableFuture<>();
			future.exceptionally((exc) -> {
				synchronized (this) {
					future = null;
				}
				return ExceptionUtils.rethrow(exc);
			});
		}
		return future;
	}

	/**
	 * Forget the value
	 * 
	 * Instead of returning a completed (or even in-progress) future, the next request will cause
	 * the value to be re-computed.
	 */
	public synchronized void forget() {
		future = null;
	}

	@Override
	public synchronized String toString() {
		if (future == null) {
			return "(lazy)";
		}
		if (!future.isDone()) {
			return "(lazy-req)";
		}
		if (future.isCompletedExceptionally()) {
			return "(lazy-err)";
		}
		return future.getNow(null).toString();
	}

	/**
	 * Check if the value has been requested, but not yet completed
	 * 
	 * This will also return true if something is providing the value out of band.
	 * 
	 * @return true if {@link #request()} or {@link #provide()} has been called, but not completed
	 */
	public synchronized boolean isBusy() {
		return future != null && !future.isDone();
	}

	/**
	 * Check the the value is available immediately
	 * 
	 * @return true if {@link #request()} or {@link #provide()} has been called and completed.
	 */
	public synchronized boolean isDone() {
		return future != null && future.isDone();
	}
}
