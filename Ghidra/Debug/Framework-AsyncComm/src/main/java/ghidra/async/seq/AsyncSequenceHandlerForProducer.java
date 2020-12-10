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
import java.util.function.BiFunction;

import ghidra.async.AsyncHandlerCanExit;

/**
 * The handler given to sequence actions that produce a temporary value
 *
 * @param <R> the type of result of the whole sequence
 * @param <U> the type of temporary produced
 */
public interface AsyncSequenceHandlerForProducer<R, U> extends AsyncHandlerCanExit<R> {
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
	 * If the subordinate completes without exception, the next action is executed with the result.
	 * If this is the final action, the sequence is completed with {@code null}. If it completes
	 * exceptionally, then the whole sequence completes exceptionally and terminates.
	 * 
	 * @param result the result of completion, producing the temporary value
	 * @param exc the exception if completed exceptionally
	 * @return null
	 */
	public Void next(U result, Throwable exc);
}
