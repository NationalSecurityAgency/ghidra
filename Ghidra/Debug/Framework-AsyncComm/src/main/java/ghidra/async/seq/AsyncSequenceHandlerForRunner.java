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
package ghidra.async.seq;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;

import ghidra.async.*;

public interface AsyncSequenceHandlerForRunner<R> extends AsyncHandlerCanExit<R> {
	/**
	 * Execute the next action or complete the sequence with null
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)}. This should rarely if ever be invoked directly
	 * since it is most often used to handle future completion of a subordinate asynchronous task.
	 * If it is invoked directly, consider merging this action with the following one. If this is
	 * the final action, consider using {@link #exit(Object)} instead, especially to provide a
	 * non-null result.
	 * 
	 * If the subordinate completes without exception, the next action is executed. If this is the
	 * final action, the sequence is completed with {@code null}. If it completes exceptionally,
	 * then the whole sequence completes exceptionally and terminates.
	 * 
	 * @param v null placeholder for {@link Void}
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public Void next(Void v, Throwable exc);

	/**
	 * Do like {@link #next(Void, Throwable)}, but ignore the result of a subordinate task
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)} for any type. There is not need to invoke this
	 * method directly. If the subordinate asynchronous task produces a result, and that result does
	 * not need to be consumed by the following action, this method must be used, since
	 * {@link #next(Void, Throwable)} requires the {@link CompletableFuture} to provide a
	 * {@link Void} result. If the result cannot be ignored, then the following action must accept
	 * the result, or the result must be stored in an {@link AtomicReference}. See
	 * {@link AsyncUtils#sequence(TypeSpec)}.
	 * 
	 * @param result the result to ignore
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public default Void nextIgnore(Object result, Throwable exc) {
		return next(null, exc);
	}
}
