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
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import ghidra.async.*;
import ghidra.async.seq.AsyncSequenceWithTemp.*;
import ghidra.util.Msg;

/**
 * Part of the underlying implementation of {@link AsyncUtils#sequence(TypeSpec)}
 *
 * @param <R> the type of result for the whole sequence
 */
public class AsyncSequenceWithoutTemp<R> {
	// The temporary "result" -- will be null, but notified upon completion
	private final CompletableFuture<Void> tmpResult;
	// The result for the whole sequence
	private final CompletableFuture<R> seqResult;

	/**
	 * Construct a new sequence without a temporary value
	 * 
	 * Do not call this directly. Please use {@link AsyncUtils#sequence(TypeSpec)}.
	 * 
	 * @param seqResult the result of the whole sequence, passed to each appended sequence
	 * @param tmpResult the result of the current final action
	 */
	public AsyncSequenceWithoutTemp(CompletableFuture<R> seqResult,
			CompletableFuture<Void> tmpResult) {
		this.seqResult = seqResult;
		this.tmpResult = tmpResult;
	}

	/**
	 * Append an action to this sequence that produces a temporary value
	 * 
	 * @param action the action
	 * @param type the type of temporary value that action will produce
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithTemp<R, U> then(AsyncSequenceActionProduces<R, U> action,
			TypeSpec<U> type) {
		return new AsyncSequenceWithTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForProducer<R, U> handler = new HandlerForProducer<>(seqResult);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append an action to this sequence that produces a temporary value
	 * 
	 * @param action the action
	 * @param type the type of temporary value that action will produce
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithTemp<R, U> then(Executor executor,
			AsyncSequenceActionProduces<R, U> action, TypeSpec<U> type) {
		return new AsyncSequenceWithTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForProducer<R, U> handler = new HandlerForProducer<>(seqResult);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Append an action to this sequence that stores a value
	 * 
	 * @param action the action
	 * @param storage a reference to receive the result upon completion
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithoutTemp<R> then(AsyncSequenceActionProduces<R, U> action,
			AtomicReference<U> storage) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForStorer<R, U> handler = new HandlerForStorer<>(seqResult, storage);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append an action to this sequence that stores a value
	 * 
	 * @param action the action
	 * @param storage a reference to receive the result upon completion
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithoutTemp<R> then(Executor executor,
			AsyncSequenceActionProduces<R, U> action, AtomicReference<U> storage) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForStorer<R, U> handler = new HandlerForStorer<>(seqResult, storage);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Append an action to this sequence
	 * 
	 * @param action the action
	 * @return the new sequence with the appended action
	 */
	public AsyncSequenceWithoutTemp<R> then(AsyncSequenceActionRuns<R> action) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForRunner<R> handler = new HandlerForRunner<>(seqResult);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append an action to this sequence
	 * 
	 * @param action the action
	 * @return the new sequence with the appended action
	 */
	public AsyncSequenceWithoutTemp<R> then(Executor executor, AsyncSequenceActionRuns<R> action) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForRunner<R> handler = new HandlerForRunner<>(seqResult);
			try {
				action.accept(handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Finish defining this sequence of actions and obtain its future result
	 * 
	 * When an action in the sequence calls {@link AsyncHandlerCanExit#exit(Object, Throwable)}, the
	 * returned {@link CompletableFuture} is completed. If any action completes exceptionally, the
	 * returned {@link CompletableFuture} is completed exceptionally. If the final action executes,
	 * {@link AsyncSequenceHandlerForRunner#next(Void, Throwable)}, the returned
	 * {@link CompletableFuture} is completed with {@code null}.
	 * 
	 * @return the future result of the sequence
	 */
	public CompletableFuture<R> finish() {
		return then((seq) -> {
			seq.exit(null, null);
		}).seqResult;
	}

	/**
	 * Register an action to execute on sequence completion
	 * 
	 * All registered actions are submitted for execution simultaneously when an action in the
	 * sequence calls {@link AsyncHandlerCanExit#exit(Object, Throwable)}. This is useful for
	 * methods that begin executing sequences "with a context". It is roughly equivalent to a
	 * {@code finally} block. On-exit actions can be registered before other actions are appended to
	 * the chain.
	 * 
	 * An uncaught exception in an on-exit action will simply be logged and ignored.
	 * 
	 * @param action the action to execute
	 */
	public AsyncSequenceWithoutTemp<R> onExit(BiConsumer<? super R, Throwable> action) {
		seqResult.handle((result, exc) -> {
			try {
				action.accept(result, exc);
			}
			catch (Throwable t) {
				Msg.error(this, "Uncaught exception in onExit", t);
			}
			return result;
		});
		return this;
	}
}
