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

import java.lang.ref.Cleaner;
import java.util.concurrent.*;
import java.util.function.BiFunction;

import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * Some conveniences when dealing with Java's {@link CompletableFuture}s.
 */
public interface AsyncUtils {
	Cleaner CLEANER = Cleaner.create();

	ExecutorService FRAMEWORK_EXECUTOR = Executors.newWorkStealingPool();
	ExecutorService SWING_EXECUTOR = SwingExecutorService.LATER;

	// NB. This was a bad idea, because CFs may maintain refs to dependents.
	//CompletableFuture<Void> NIL = CompletableFuture.completedFuture(null);

	public static <T> CompletableFuture<T> nil() {
		return CompletableFuture.completedFuture(null);
	}

	public interface TemperamentalRunnable {
		public void run() throws Throwable;
	}

	public interface TemperamentalSupplier<T> {
		public T get() throws Throwable;
	}

	/**
	 * Unwrap {@link CompletionException}s and {@link ExecutionException}s to get the real cause
	 * 
	 * @param e the (usually wrapped) exception
	 * @return the nearest cause in the chain that is not a {@link CompletionException}
	 */
	public static Throwable unwrapThrowable(Throwable e) {
		Throwable exc = e;
		while (exc instanceof CompletionException || exc instanceof ExecutionException) {
			exc = exc.getCause();
		}
		return exc;
	}

	/**
	 * Create a {@link BiFunction} that copies a result from one {@link CompletableFuture} to
	 * another
	 * 
	 * <p>
	 * The returned function is suitable for use in {@link CompletableFuture#handle(BiFunction)} and
	 * related methods, as in:
	 * 
	 * <pre>
	 * sourceCF().handle(AsyncUtils.copyTo(destCF));
	 * </pre>
	 * 
	 * <p>
	 * This will effectively cause {@code destCF} to be completed identically to {@code sourceCF}.
	 * The returned future from {@code handle} will also behave identically to {@code source CF},
	 * except that {@code destCF} is guaranteed to complete before the returned future does.
	 * 
	 * @param <T> the type of the future result
	 * @param dest the future to copy into
	 * @return a function which handles the source future
	 */
	public static <T> BiFunction<T, Throwable, T> copyTo(CompletableFuture<T> dest) {
		return (t, ex) -> {
			if (ex != null) {
				dest.completeExceptionally(ex);
				return ExceptionUtils.rethrow(ex);
			}
			dest.complete(t);
			return t;
		};
	}
}
