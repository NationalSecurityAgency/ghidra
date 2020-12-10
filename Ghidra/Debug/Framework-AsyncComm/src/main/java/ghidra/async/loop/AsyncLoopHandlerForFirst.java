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
 * The handler given to the first action of a two-action loop
 *
 * @param <R> the type of result for the whole loop
 * @param <T> the type of object produced, i.e., provided by the subordinate asynchronous task
 */
public interface AsyncLoopHandlerForFirst<R, T> extends AsyncHandlerCanExit<R> {
	/**
	 * Execute the consumer action or complete the loop exceptionally
	 * 
	 * This method is suitable for passing by reference to
	 * {@link CompletableFuture#handle(BiFunction)}. This should rarely if ever be invoked directly
	 * since it is most often used to handle future completion of a subordinate asynchronous task.
	 * If it is invoked directly, consider using a single-action loop, i.e.,
	 * {@link AsyncUtils#loop(TypeSpec, AsyncLoopOnlyActionRuns)} or
	 * {@link AsyncUtils#each(TypeSpec, Iterator, AsyncLoopSecondActionConsumes)}.
	 * 
	 * If the subordinate completes without exception, the consumer is executed with the result. If
	 * it completes exceptionally, then the whole loop completes exceptionally and terminates.
	 * 
	 * @param elemResult the result of completion
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public Void consume(T elemResult, Throwable exc);
}
