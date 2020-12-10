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

/**
 * Part of the underlying implementation of {@link AsyncUtils#sequence(TypeSpec)}
 *
 * @param <R> the type of result for the whole sequence
 * @param <T> the type of temporary value produced by the current final action
 */
public class AsyncSequenceWithTemp<R, T> {
	/**
	 * Common handler implementation
	 *
	 * @param <R> the type of result for the shole sequence
	 * @param <T> the type of temporary value produced
	 */
	static abstract class AbstractHandler<R, T> implements AsyncHandlerCanExit<R> {
		final CompletableFuture<R> seqResult;
		final CompletableFuture<T> future = new CompletableFuture<>();

		public AbstractHandler(CompletableFuture<R> seqResult) {
			this.seqResult = seqResult;
		}

		@Override
		public Void exit(R result, Throwable exc) {
			if (exc != null) {
				seqResult.completeExceptionally(exc);
			}
			else {
				seqResult.complete(result);
			}
			return null;
		}
	}

	/**
	 * The handler given to actions that produce or store a temporary value
	 *
	 * @param <R> the type of result for the whole sequence
	 * @param <T> the type of value produced or stored
	 * @param <U> the type of temporary value produced -- {@link Void} for actions that store
	 */
	static abstract class AbstractHandlerForProducer<R, T, U> extends AbstractHandler<R, U>
			implements AsyncSequenceHandlerForProducer<R, T> {
		public AbstractHandlerForProducer(CompletableFuture<R> seqResult) {
			super(seqResult);
		}

		@Override
		public Void next(T result, Throwable exc) {
			if (exc != null) {
				seqResult.completeExceptionally(exc);
			}
			else {
				proceedWithoutException(result);
			}
			return null;
		}

		/**
		 * Implements the portion of {@link #next(Object, Throwable)} to execute when the result of
		 * the subordinate task is not exceptional
		 * 
		 * @param result the result of the subordinate task
		 */
		protected abstract void proceedWithoutException(T result);
	}

	/**
	 * The handler given to actions that produce a temporary value
	 *
	 * @param <R> the type of result for the shole sequence
	 * @param <T> the type of temporary value produced
	 */
	static class HandlerForProducer<R, T> extends AbstractHandlerForProducer<R, T, T> {
		public HandlerForProducer(CompletableFuture<R> seqResult) {
			super(seqResult);
		}

		@Override
		public void proceedWithoutException(T futureResult) {
			future.complete(futureResult);
		}
	}

	/**
	 * The handler given to actions that store a value
	 *
	 * @param <R> the type of result for the shole sequence
	 * @param <T> the type of value stored
	 */
	static class HandlerForStorer<R, T> extends AbstractHandlerForProducer<R, T, Void> {
		private final AtomicReference<T> storage;

		public HandlerForStorer(CompletableFuture<R> seqResult, AtomicReference<T> storage) {
			super(seqResult);
			this.storage = storage;
		}

		@Override
		public void proceedWithoutException(T futureResult) {
			storage.set(futureResult);
			future.complete(null);
		}
	}

	/**
	 * The handler given to actions that do not produce a value
	 *
	 * @param <R> the type of result for the whole sequence
	 */
	static class HandlerForRunner<R> extends AbstractHandler<R, Void>
			implements AsyncSequenceHandlerForRunner<R> {
		public HandlerForRunner(CompletableFuture<R> seqResult) {
			super(seqResult);
		}

		@Override
		public Void next(Void result, Throwable exc) {
			if (exc != null) {
				seqResult.completeExceptionally(exc);
			}
			else {
				future.complete(result);
			}
			return null;
		}
	}

	// The temporary result
	private final CompletableFuture<T> tmpResult;
	// The result for the whole sequence
	private final CompletableFuture<R> seqResult;

	AsyncSequenceWithTemp(CompletableFuture<R> seqResult, CompletableFuture<T> tmpResult) {
		this.seqResult = seqResult;
		this.tmpResult = tmpResult;
	}

	/**
	 * Append to this sequence an action that consumes the temporary value and produces another
	 * 
	 * @param action the action
	 * @param type the type of temporary value the action will produce
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithTemp<R, U> then(
			AsyncSequenceActionConsumesAndProduces<R, T, U> action, TypeSpec<U> type) {
		return new AsyncSequenceWithTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForProducer<R, U> handler = new HandlerForProducer<>(seqResult);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append to this sequence an action that consumes the temporary value and produces another
	 * 
	 * @param executor the thread pool for this action
	 * @param action the action
	 * @param type the type of temporary value the action will produce
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithTemp<R, U> then(Executor executor,
			AsyncSequenceActionConsumesAndProduces<R, T, U> action, TypeSpec<U> type) {
		return new AsyncSequenceWithTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForProducer<R, U> handler = new HandlerForProducer<>(seqResult);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Append to this sequence an action that consumes the temporary value and stores another
	 * 
	 * @param action the action
	 * @param storage a reference to receive the result upon completion
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithoutTemp<R> then(
			AsyncSequenceActionConsumesAndProduces<R, T, U> action, AtomicReference<U> storage) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForStorer<R, U> handler = new HandlerForStorer<>(seqResult, storage);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append to this sequence an action that consumes the temporary value and stores another
	 * 
	 * @param executor the thread pool for this action
	 * @param action the action
	 * @param storage a reference to receive the result upon completion
	 * @return the new sequence with the appended action
	 */
	public <U> AsyncSequenceWithoutTemp<R> then(Executor executor,
			AsyncSequenceActionConsumesAndProduces<R, T, U> action, AtomicReference<U> storage) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForStorer<R, U> handler = new HandlerForStorer<>(seqResult, storage);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Append to this sequence an action that consumes the temporary value
	 * 
	 * @param action the action
	 * @return the new sequence with the appended action
	 */
	public AsyncSequenceWithoutTemp<R> then(AsyncSequenceActionConsumes<R, T> action) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenCompose((result) -> {
			HandlerForRunner<R> handler = new HandlerForRunner<>(seqResult);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}));
	}

	/**
	 * Append to this sequence an action that consumes the temporary value
	 * 
	 * @param executor the thread pool for this action
	 * @param action the action
	 * @return the new sequence with the appended action
	 */
	public AsyncSequenceWithoutTemp<R> then(Executor executor,
			AsyncSequenceActionConsumes<R, T> action) {
		return new AsyncSequenceWithoutTemp<>(seqResult, tmpResult.thenComposeAsync((result) -> {
			HandlerForRunner<R> handler = new HandlerForRunner<>(seqResult);
			try {
				action.accept(result, handler);
			}
			catch (Throwable e) {
				seqResult.completeExceptionally(e);
				throw e;
			}
			return handler.future;
		}, executor));
	}

	/**
	 * Register an action to execute on sequence completion
	 * 
	 * @see AsyncSequenceWithoutTemp#onExit(BiConsumer)
	 * @param action the action to execute
	 */
	public AsyncSequenceWithTemp<R, T> onExit(BiConsumer<? super R, Throwable> action) {
		seqResult.handle((result, exc) -> {
			action.accept(result, exc);
			return result;
		});
		return this;
	}
}
