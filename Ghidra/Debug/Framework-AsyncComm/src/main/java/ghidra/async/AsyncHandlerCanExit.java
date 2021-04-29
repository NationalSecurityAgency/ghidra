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
import java.util.function.BiFunction;

/**
 * Methods for exiting a chain common to all handlers
 *
 * @param <R> the type of result for the whole construct
 */
public interface AsyncHandlerCanExit<R> {
	/**
	 * Complete the whole loop
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)}. While it can be invoked directly, consider the
	 * convenience methods {@link #exit(Object)} and {@link #exit(Throwable)} instead.
	 * 
	 * When the subordinate completes, the whole construct completes and terminates with the same,
	 * possibly exceptional, result.
	 * 
	 * @param result the result of completion
	 * @param exc the exception if completed exceptionally
	 * @return
	 */
	public Void exit(R result, Throwable exc);

	/**
	 * Complete the chain with the given result
	 * 
	 * @param result the result
	 */
	public default void exit(R result) {
		exit(result, null);
	}

	/**
	 * Complete the chain with {@code null}
	 */
	public default void exit() {
		exit(null, null);
	}

	/**
	 * Complete the chain exceptionally
	 * 
	 * @param exc the exception
	 */
	public default void exit(Throwable exc) {
		exit(null, exc);
	}
}
