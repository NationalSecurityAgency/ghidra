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
package ghidra.async.loop;

import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;

import ghidra.async.*;

/**
 * The handler given to the second or only action of a loop
 *
 * @param <R> the type of result for the whole loop
 */
public interface AsyncLoopHandlerForSecond<R> extends AsyncHandlerCanExit<R> {
	/**
	 * Re-execute the producer action or complete the loop exceptionally
	 * 
	 * For single-action loops, this re-executes the single action
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)}. While it can be invoked directly, consider the
	 * convenience method {@link #repeat()}.
	 * 
	 * If the subordinate completes without exception, the loop is repeated. If it completes
	 * exceptionally, then the whole loop completes exceptionally and terminates.
	 * 
	 * @param v null placeholder for {@link Void}
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public Void repeat(Void v, Throwable exc);

	/**
	 * Re-execute the producer action or exit conditionally, or complete exceptionally
	 * 
	 * For single-action loops, this re-executes the single action
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)}. While it can be invoked directly, consider the
	 * convenience method {@link #repeatWhile(boolean)}.
	 * 
	 * If the subordinate completes without exception, its result value {@code b} is examined. If
	 * equal to {@link Boolean.TRUE}, the loop is repeated; otherwise the loop exits, i.e.,
	 * completes normally. If the subordinate completes exceptionally, then the whole loop completes
	 * exceptionally and terminates.
	 * 
	 * @param b the value of the predicate
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public default Void repeatWhile(Boolean b, Throwable exc) {
		return exc == null && b == Boolean.TRUE ? repeat(null, exc) : exit(null, exc);
	}

	/**
	 * Do like {@link #repeat(Void, Throwable)}, but ignore the result of a subordinate task
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)} for any type. There is no need to invoke this
	 * method directly. If the subordinate asynchronous task produces a result, and that result does
	 * not need to be processed before the loop repeats, this method must be used, since
	 * {@link #repeat(Void, Throwable)} requires the {@link CompletableFuture} to provide a
	 * {@link Void} result. If the result cannot be ignored, consider using a two-action loop, i.e.,
	 * {@link AsyncUtils#loop(TypeSpec, AsyncLoopFirstActionProduces, TypeSpec, AsyncLoopSecondActionConsumes)}
	 * or
	 * {@link AsyncUtils#each(TypeSpec, Iterator, AsyncLoopFirstActionConsumesAndProduces, TypeSpec, AsyncLoopSecondActionConsumes)}.
	 * If this is already a two-action loop, then consider nesting
	 * {@link AsyncUtils#sequence(TypeSpec)} in a single-action loop.
	 * 
	 * @param v any value, because it is ignored
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public default Void repeatIgnore(Object v, Throwable exc) {
		return repeat(null, exc);
	}

	/**
	 * Re-execute the loop
	 */
	public default void repeat() {
		repeat(null, null);
	}

	/**
	 * Re-execute the loop conditionally
	 * 
	 * @param b the value of the predicate
	 */
	public default void repeatWhile(boolean b) {
		repeatWhile(b, null);
	}
}
