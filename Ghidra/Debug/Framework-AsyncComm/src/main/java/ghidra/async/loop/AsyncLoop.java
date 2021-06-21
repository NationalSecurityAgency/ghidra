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

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;

/**
 * The underlying implementation of
 * {@link AsyncUtils#loop(TypeSpec, AsyncLoopFirstActionProduces, TypeSpec, AsyncLoopSecondActionConsumes)}
 *
 * @param <R> the type of result for the whole loop, usually {@link TypeSpec#VOID}
 * @param <T> the type of result produced by the subordinate asynchronous task
 */
public class AsyncLoop<R, T> extends CompletableFuture<R> {
	private final AsyncLoopFirstActionProduces<R, T> producer;
	private final AsyncLoopSecondActionConsumes<R, ? super T> consumer;

	/**
	 * Execute the first action of the loop
	 */
	public void begin() {
		consumeHandler.repeat(null, null);
	}

	/**
	 * The handler given to the producer action of the loop
	 */
	private final AsyncLoopHandlerForFirst<R, T> produceHandler =
		new AsyncLoopHandlerForFirst<R, T>() {
			@Override
			public Void consume(T iterate, Throwable exc) {
				if (exc != null) {
					completeExceptionally(exc);
				}
				else {
					try {
						consumer.accept(iterate, consumeHandler);
					}
					catch (Throwable e) {
						completeExceptionally(e);
					}
				}
				return null;
			}

			@Override
			public Void exit(R result, Throwable exc) {
				if (exc != null) {
					completeExceptionally(exc);
				}
				else {
					complete(result);
				}
				return null;
			}
		};

	/**
	 * The handler given to the consumer action of the loop
	 */
	private final AsyncLoopHandlerForSecond<R> consumeHandler = new AsyncLoopHandlerForSecond<R>() {
		@Override
		public Void repeat(Void v, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				// This is a hack to avoid stack overflows
				AsyncUtils.FRAMEWORK_EXECUTOR.submit(() -> {
					try {
						producer.accept(produceHandler);
					}
					catch (Throwable e) {
						completeExceptionally(e);
					}
				});
			}
			return null;
		}

		@Override
		public Void exit(R result, Throwable exc) {
			if (exc != null) {
				completeExceptionally(exc);
			}
			else {
				complete(result);
			}
			return null;
		}
	};

	/**
	 * Construct a loop with the given producer and consumer
	 * 
	 * @param producer the producer (first) action
	 * @param type the type of object passed from producer to consumer
	 * @param consumer the consumer (second) action
	 */
	public AsyncLoop(AsyncLoopFirstActionProduces<R, T> producer, TypeSpec<T> type,
			AsyncLoopSecondActionConsumes<R, ? super T> consumer) {
		this.producer = producer;
		this.consumer = consumer;
	}
}
