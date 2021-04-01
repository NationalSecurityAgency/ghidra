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
import java.nio.channels.*;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.*;
import java.util.function.*;

import org.apache.commons.lang3.exception.ExceptionUtils;

import ghidra.async.loop.*;
import ghidra.async.seq.*;
import ghidra.util.Msg;

/**
 * A wrapper for Java's {@link CompletableFuture} that provides additional fluency
 * 
 * <p>
 * The {@link CompletableFuture} class is very useful for organizing asynchronous tasks into tidy
 * sequences. See {@link CompletableFuture#thenCompose(Function)} for more information, though
 * better examples are available in other online resources.
 * 
 * <p>
 * These utilities seek to ease some operations, e.g., loops, and provide some control of execution
 * in sequences not otherwise given by Java's futures. While some verboseness is eliminated, these
 * utilities have tradeoffs. They interoperate, permitting use of each according to circumstances
 * and taste.
 * 
 * <p>
 * Additional conveniences allow Java's non-blocking IO to interoperate more closely with futures.
 * See {@link AsynchronousByteChannel}. The "nio" API predates {@link CompletableFuture}, so they
 * cannot readily interact. They use {@link CompletionHandler}s instead of futures. This class
 * provides API wrappers that return {@link CompletableFuture}s.
 * 
 * <p>
 * An asynchronous method is one that returns control immediately, and may promise to provide a
 * completed result at some future time. In the case of computation, the method may launch a thread
 * or queue the computation on an executor. In the case of non-blocking IO, the method may queue a
 * handler on an asynchronous channel. The method is said to "promise" a completed result. It
 * instantiates the promise and arranges its fulfillment. It can then return control immediately by
 * returning the corresponding "future" object. When the promise is fulfilled, the result is stored
 * in the future object, optionally invoking a callback.
 * 
 * <p>
 * Java implements this pattern in {@link CompletableFuture}. Java does not provide a separate class
 * for the promise. The asynchronous method instantiates the completable future, arranging for its
 * completion, and immediately returns it to the caller. Anything with a referece to the future may
 * complete it. The "promise" and "future" objects are not distinct. Note that
 * {@link AsynchronousByteChannel} does provide methods that return {@link Future}, but the
 * underlying implementation is not a {@link CompletableFuture}, so it cannot accept callbacks.
 * 
 * <p>
 * There are generally two ways the caller can consume the value. The simplest is to wait, by
 * blocking, on the result. This defeats the purpose of asynchronous processing. For example:
 * 
 * <pre>
 * System.out.println(processAsync(input1).get());
 * System.out.println(processAsync(input2).get());
 * </pre>
 * 
 * <p>
 * This block is not any more efficient than the following sequential program:
 * 
 * <pre>
 * System.out.println(processSync(input1));
 * System.out.println(processSync(input2));
 * </pre>
 * 
 * <p>
 * In fact, it may be worse from the overhead of multi-threading, queueing, scheduling, etc. To take
 * advantage of multi-threaded executors, processing should be performed in parallel when possible.
 * For example:
 * 
 * <pre>
 * CompletableFuture<Long> future1 = processAsync(input1);
 * CompletableFuture<Long> future2 = processAsync(input2);
 * System.out.println(future1.get());
 * System.out.println(future2.get());
 * </pre>
 * 
 * <p>
 * Now, both inputs can be processed simultaneously. The other way to consume the value is via
 * callback. This elegant option may seem complex. It is especially effective when the calling
 * thread cannot or should not block. For example:
 * 
 * <pre>
 * processAsync(input1).thenAccept((result1) -> {
 * 	System.out.println(result1);
 * });
 * processAsync(input2).thenAccept((result2) -> {
 * 	System.out.println(result2);
 * });
 * </pre>
 * 
 * <p>
 * Now, both inputs can be processed simultaneously, and each result is printed the moment it
 * becomes available. Another notable difference: If processing of input2 finishes first, it can be
 * printed without waiting on input1. Furthermore, the calling thread is not blocked. Long chains of
 * asynchronous callbacks, however, an become difficult to manage.
 * 
 * <p>
 * Suppose a program must fetch a list of integers from a storage system, then process each entry by
 * submitting it to a remote service, and finally aggregate the results with a given initial value.
 * 
 * <p>
 * The traditional implementation might look like this:
 * 
 * <pre>
 * public int doWork(int start) {
 * 	Storage store = connectStorage(ADDR1);
 * 	Service serve = connectService(ADDR2);
 * 	List<Integer> list = store.fetchList();
 * 	int sum = start;
 * 	for (int entry : list) {
 * 		sum += serve.process(entry);
 * 	}
 * 	store.close();
 * 	serve.close();
 * 	return sum;
 * }
 * </pre>
 * 
 * <p>
 * Now, suppose the connect methods, the fetch method, and the process method all perform their work
 * asynchronously, providing results via futures. The implementation ought to provide for parallel
 * execution. The chain of asynchronous tasks essentially becomes a composite task, itself
 * implementing the future pattern. One scheme is to create a class extending
 * {@link CompletableFuture} and containing all callback methods in the chain:
 * 
 * <pre>
 * class FetchAndProcess extends CompletableFuture<Integer> {
 * 	Storage storage;
 * 	Service service;
 * 	AtomicInteger sum = new AtomicInteger();
 * 
 * 	FetchAndProcess(int start) {
 * 		sum = start;
 * 		connectStorage(ADDR1).handle(this::storageConnected);
 * 	}
 * 
 * 	Void storageConnected(Storage s, Throwable exc) {
 * 		if (exc != null) {
 * 			completeExceptionally(exc);
 * 		}
 * 		else {
 * 			storage = s;
 * 			connectService(ADDR2).handle(this::serviceConnected);
 * 		}
 * 		return null;
 * 	}
 * 
 * 	Void serviceConnected(Service s, Throwable exc) {
 * 		if (exc != null) {
 * 			completeExceptionally(exc);
 * 		}
 * 		else {
 * 			service = s;
 * 			storage.fetchList().handle(this::fetchedList);
 * 		}
 * 		return null;
 * 	}
 * 
 * 	Void fetchedList(List<Integer> list, Throwable exc) {
 * 		if (exc != null) {
 * 			completeExceptionally(exc);
 * 		}
 * 		else {
 * 			List<CompletableFuture<Void>> futures = new ArrayList<>();
 * 			for (int entry : list) {
 * 				futures.add(service.process(entry).thenAccept((result) -> {
 * 					sum.addAndGet(result);
 * 				}));
 * 			}
 * 			CompletableFuture.allOf(futures.toArray(new CompletableFuture[list.size()]))
 * 					.handle(this::processedList);
 * 		}
 * 		return null;
 * 	}
 * 
 * 	Void processedList(Void v, Throwable exc) {
 * 		if (exc != null) {
 * 			completeExceptionally(exc);
 * 		}
 * 		else {
 * 			complete(sum.get());
 * 		}
 * 		return null;
 * 	}
 * }
 * 
 * public CompletableFuture<Integer> doWork(int start) {
 * 	return new FetchAndProcess(start);
 * }
 * </pre>
 * 
 * <p>
 * The asynchronous method then just instantiates the class and returns it. The final callback in
 * the chain must call {@link CompletableFuture#complete(Object)}. The main deficit to this method
 * is that the operational steps are buried between method declarations and error checks. Also,
 * because the method must return {@link Void}, not just {@code void}, all the methods must return
 * {@code null}. Furthermore, errors that occur in the callback methods do not get communicated to
 * the caller of {@code doWork}. Additional try-cache blocks would be required.
 * 
 * <p>
 * Lambda functions could be substituted for method references avoiding the class declaration, but
 * that would result in nesting several levels deep -- at least one level per callback in the chain.
 * To avoid nesting, Java provides {@link CompletableFuture#thenCompose(Function)}, which provides a
 * fairly elegant implementation:
 * 
 * <pre>
 * public CompletableFuture<Integer> doWork(int start) {
 * 	AtomicReference<Storage> store = new AtomicReference<>();
 * 	AtomicReference<Service> serve = new AtomicReference<>();
 * 	AtomicInteger sum = new AtomicInteger(start);
 * 	return connectStorage(ADDR1).thenCompose((s) -> {
 * 		store.set(s);
 * 		return connectService(ADDR2);
 * 	}).thenCompose((s) -> {
 * 		serve.set(s);
 * 		return store.get().fetchList();
 * 	}).thenCompose((list) -> {
 * 		List<CompletableFuture<Void>> futures = new ArrayList<>();
 * 		for (int entry : list) {
 * 			futures.add(serve.get().process(entry).thenAccept((result) -> {
 * 				sum.addAndGet(result);
 * 			}));
 * 		}
 * 		return CompletableFuture.allOf(futures.toArray(new CompletableFuture[list.size()]));
 * 	}).thenApply((v) -> {
 * 		store.get().close();
 * 		serve.get().close();
 * 		return sum.get();
 * 	});
 * }
 * </pre>
 * 
 * <p>
 * This does have a couple notable deficits, though. First, the {@code return} keyword is almost
 * abused. The callbacks are defined inline as if they were simply actions within the method. In
 * this context, {@code return} can become misleading, because that is not the point where the
 * method terminates with a result, but rather the point where the action provides the next
 * subordinate asynchronous task in the chain. Second, not all the actions are presented at the same
 * nesting level, even though they reside in the same sequence. Because of this, it's not
 * immediately obvious that, e.g., {@code connectStorage} precedes {@code connectService}, or
 * perhaps a more subtle example, that {@code process} precedes {@code sumAndGet}.
 * 
 * <p>
 * With the utilities, we can write this sequence a little differently. The goal is to mimic
 * sequential programming not just in its appearance, but also in its control structure:
 * 
 * <pre>
 * public CompletableFuture<Integer> doWork(int start) {
 * 	AtomicReference<Storage> store = new AtomicReference<>();
 * 	AtomicReference<Service> serve = new AtomicReference<>();
 * 	AtomicInteger sum = new AtomicInteger(start);
 * 	return sequence(TypeSpec.INT).then((seq) -> {
 * 		connectStorage(ADDR1).handle(seq::next);
 * 	}, store).then((seq) -> {
 * 		connectService(ADDR2).handle(seq::next);
 * 	}, serve).then((seq) -> {
 * 		store.get().fetchList().handle(seq::next);
 * 	}, TypeSpec.obj((List<Integer>) null)).then((list, seq) -> {
 * 		AsyncFence fence = new AsyncFence();
 * 		for (int entry : list) {
 * 			fence.include(sequence(TypeSpec.VOID).then((seq2) -> {
 * 				serve.get().process(entry).handle(seq2::next);
 * 			}, TypeSpec.INT).then((result, seq2) -> {
 * 				sum.addAndGet(result);
 * 				seq2.exit();
 * 			}).asCompletableFuture());
 * 		}
 * 		fence.ready().handle(seq::next);
 * 	}).then((seq) -> {
 * 		store.get().close();
 * 		serve.get().close();
 * 		seq.exit(sum.get());
 * 	}).asCompletableFuture();
 * }
 * </pre>
 * 
 * <p>
 * The implementation is slightly longer because the body of the for-loop is also implemented as a
 * two-step sequence instead of using {@link CompletableFuture#thenAccept(Consumer)}. First, notice
 * that the sequence starts with a call to {@link #sequence(TypeSpec)}. This essentially declares an
 * inline asynchronous method whose result will have the given type. This mimics a standard method
 * declaration where the type is given first; whereas
 * {@link CompletableFuture#thenCompose(Function)} implicitly takes the return type of the final
 * callback.
 * 
 * <p>
 * Second, notice that the callback is given a reference to the sequence. Technically, this is just
 * a contextual view of the sequence's handlers. It implements two methods which may be passed to
 * {@link CompletableFuture#handle(BiFunction)}. This constitutes a major difference from the
 * composition pattern. Instead of returning a {@link CompletableFuture} to wait on, the action must
 * explicitly call {@code handle(seq::next)}. This permits the execution of additional code after
 * calling the asynchronous method in parallel. While this provides more flexibility, it also
 * provies more opportunities for mistakes. Usually, passing or calling the handler is the last line
 * in a callback action. See {@link AsyncSequenceHandlerForRunner#next(Void, Throwable)} and
 * {@link AsyncSequenceHandlerForProducer#next(Object, Throwable)}.
 * 
 * <p>
 * Third, notice that the call to {@code connectStorage} is now at the same nesting level as
 * {@code connectService}. This keeps the operative parts of each action immediately visible as they
 * are left justified, have the same indentation, and are not preceded by {@code return}. However,
 * it is easy to forget {@link CompletableFuture#handle(BiFunction)}.
 * 
 * <p>
 * Fourth, notice that each action is always separated by a call to
 * {@link AsyncSequenceWithoutTemp#then(AsyncSequenceActionRuns)} or one of its variants in
 * {@link AsyncSequenceWithTemp}. This generally means the lines between actions can be ignored. In
 * the composition pattern, the reader would need to see that the final action is given by
 * {@link CompletableFuture#thenApply(Function)} in order to properly comprehend the return
 * statement properly. It is not another asynchronous method as in the previous actions. Rather it
 * is the final result. The line between actions in the sequence pattern cannot be ignored when a
 * value is passed from one action directly to the following action. The call to {@code then}
 * includes the type of the passed value. Worse yet, this sometimes requires casting {@code null} to
 * an arbitrary type. In the example, a list is retrieved in the third action and processed in the
 * fourth. To specify the type, {@code null} is cast to
 * {@link List}{@code <}{@link Integer}{@code >} and passed to {@link TypeSpec#obj(Object)}. The
 * list retrieved by {@code fetchList} is received in the following action's first parameter
 * ({@code list}) of its lambda function.
 * 
 * <p>
 * Fifth, notice the use of {@link AsyncFence}. This convenience class does essentially the same
 * thing as the composition and class patterns did, but provides more meaningful method names and a
 * more succinct syntax.
 * 
 * <p>
 * Finally, notice the call to to {@link AsyncSequenceHandlerForRunner#exit(Object)} passing the
 * final result of the sequence. Requiring this is a bit of a nuisance, but it makes clear what the
 * result of the sequence is. Furthermore, {@code exit} can be called by any action, not just the
 * final one. In the composition pattern, execution cannot be truncated except by error handling. In
 * the sequence pattern, any action can terminate the sequence and "return" the result. Every action
 * must either call or pass one of these handlers or the sequence will abruptly halt. Also, some
 * action, usually the final one, must pass or invoke the {@code exit} handler. If the final action
 * uses {@code next}, the sequence will "return" {@code null}. In summary, {@code next} passes a
 * value to the following action while {@code exit} passes a value as the sequence result, skipping
 * the remaining actions. The result of composed sequence of actions is communicated via its own
 * completable future. This future is obtained via {@link AsyncSequenceWithoutTemp#finish()}. Note
 * that a sequence whose final action produces a temporary value does not yield a completable
 * future.
 * 
 * <p>
 * Java's built-in mechanisms provide for error handling. Usually invoking
 * {@link CompletableFuture#exceptionally(Function)} on the result of
 * {@link AsyncSequenceWithoutTemp#finish()} is sufficient. To illustrate, the two connections from
 * the example are assuredly closed by appending a call to {@code exceptionally}:
 * 
 * <pre>
 * return sequence(TypeSpec.INT).then((seq) -> {
 * 	// ...
 * }).asCompletableFuture().exceptionally((exc) -> {
 * 	if (store.get() != null) {
 * 		store.get().close();
 * 	}
 * 	if (serve.get() != null) {
 * 		serve.get().close();
 * 	}
 * 	return ExceptionUtils.rethrow(exc);
 * });
 * </pre>
 * 
 * <p>
 * If errors must be handled in a more granular fashion, consider invoking
 * {@link CompletableFuture#exceptionally(Function)} on the appropriate asynchronous task before
 * calling {@link CompletableFuture#handle(BiFunction)}. For example:
 * 
 * <pre>
 * store.get().fetchList().exceptionally((exc) -> {
 * 	if (exc instanceof ListNotFoundException) {
 * 		return DEFAULT_LIST;
 * 	}
 * 	return ExceptionUtils.rethrow(exc);
 * }).handle(seq::next);
 * </pre>
 * 
 * <p>
 * Alternatively:
 * 
 * <pre>
 * store.get().fetchList().handle(seq::next).exceptionally((exc) -> {
 * 	if (exc instanceof ListNotFoundException) {
 * 		seq.next(DEFAULT_LIST);
 * 	}
 * 	else {
 * 		seq.exit(exc);
 * 	}
 * 	return null;
 * });
 * </pre>
 */
public interface AsyncUtils<T> {
	Cleaner CLEANER = Cleaner.create();

	ExecutorService FRAMEWORK_EXECUTOR = Executors.newWorkStealingPool();
	ExecutorService SWING_EXECUTOR = SwingExecutorService.INSTANCE;

	CompletableFuture<Void> NIL = CompletableFuture.completedFuture(null);

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static <T> CompletableFuture<T> nil() {
		return (CompletableFuture) NIL;
	}

	/**
	 * Repeatedly launch an asynchronous task and process the result
	 * 
	 * <p>
	 * This loosely corresponds to a while loop. The invocation consists of two actions: One to
	 * launch a subordinate task, likely producing a result, and the second to consume the result
	 * and repeat the loop. Note that the loop may be repeated in parallel to the processing of the
	 * result by calling {@link AsyncLoopHandlerForSecond#repeat()} early in the consumer action.
	 * Either action may explicitly exit the loop, optionally providing a result. Ordinarily, the
	 * loop repeats indefinitely.
	 * 
	 * <p>
	 * Example:
	 * 
	 * <pre>
	 * loop(TypeSpec.VOID, (loop) -> {
	 * 	receiveData().handle(loop::consume);
	 * }, TypeSpec.BYTE_ARRAY, (data, loop) -> {
	 * 	loop.repeat();
	 * 	processData(data);
	 * });
	 * </pre>
	 * 
	 * @param loopType the type of the result of the whole loop. This is usually
	 *            {@link TypeSpec#VOID}.
	 * @param producer an action invoking a subordinate asynchronous task, usually producing some
	 *            result.
	 * @param iterateType the type of result produced by the subordinate asynchronous task
	 * @param consumer an action consuming the result of the task and explicitly repeating or
	 *            exiting the loop
	 * @return a future which completes upon explicit loop termination
	 */
	public static <T, U> CompletableFuture<T> loop(TypeSpec<T> loopType,
			AsyncLoopFirstActionProduces<T, U> producer, TypeSpec<U> iterateType,
			AsyncLoopSecondActionConsumes<T, ? super U> consumer) {
		AsyncLoop<T, U> loop = new AsyncLoop<>(producer, iterateType, consumer);
		loop.begin();
		return loop;
	}

	/**
	 * Repeatedly launch an asynchronous task
	 * 
	 * This loosely corresponds to a while loop. This invocation consists of a single action: To
	 * launch a subordinate task, producing no result, or to exit the loop. The subordinate task
	 * should repeat the loop upon completion. If the loop does not require a subordinate
	 * asynchronous task, then please use an actual Java {@code while} loop. If the subordinate task
	 * does produce a result, it must be ignored using
	 * {@link AsyncLoopHandlerForSecond#repeatIgnore(Object, Throwable)}.
	 * 
	 * Example:
	 * 
	 * <pre>
	 * loop(TypeSpec.VOID, (loop) -> {
	 * 	someTask().handle(loop::repeat);
	 * });
	 * </pre>
	 * 
	 * @param loopType the type of the result of the whole loop. This is usually
	 *            {@link TypeSpec.VOID}.
	 * @param action an action launching a subordinate task, producing no, i.e., a {@link Void}
	 *            result, upon whose completion the loop repeats.
	 * @return a future which completes upon explicit loop termination
	 */
	public static <T> CompletableFuture<T> loop(TypeSpec<T> loopType,
			AsyncLoopOnlyActionRuns<T> action) {
		return loop(loopType, (handler) -> {
			handler.consume(null, null);
		}, TypeSpec.VOID, (v, handler) -> {
			action.accept(handler);
		});
	}

	/**
	 * Launch a task for each element given by an iterator and process the result
	 * 
	 * This loosely corresponds to a for loop. This invocation consists of two actions: One to
	 * consume the element and launch a subordinate task, likely producing a result, and the second
	 * to consume the result and repeat the loop. Note that the loop may be repeated in parallel to
	 * the processing of the result by calling {@link AsyncLoopHandlerForSecond#repeat()} early in
	 * the consumer action. Either action may explicitly exit the loop, optionally providing a
	 * result. Ordinarily, the loop executes until the iterator is exhausted, completing with
	 * {@code null}.
	 * 
	 * This operates similarly to
	 * {@link #loop(TypeSpec, AsyncLoopFirstActionProduces, TypeSpec, AsyncLoopSecondActionConsumes)}
	 * except that it is controlled by an iterator.
	 * 
	 * Example:
	 * 
	 * <pre>
	 * each(TypeSpec.VOID, mySet.iterator(), (item, loop) -> {
	 * 	sendItem().handle(loop::consume);
	 * }, TypeSpec.STRING, (message, loop) -> {
	 * 	loop.repeat();
	 * 	logResult(message);
	 * });
	 * </pre>
	 * 
	 * @param loopType the type of the result of the whole loop. This is usually
	 *            {@link TypeSpec#VOID}.
	 * @param it the iterator controlling the loop and providing elements
	 * @param producer an action consuming each element and invoking a subordinate asynchronous
	 *            task, usually producing some result.
	 * @param iterateType the type of result produced by the subordinate asynchronous task.
	 * @param consumer and action consuming the result of the task and explicitly repeating or
	 *            exiting the loop.
	 * @return a future which completes upon loop termination
	 */
	public static <T, E, U> CompletableFuture<T> each(TypeSpec<T> loopType, Iterator<E> it,
			AsyncLoopFirstActionConsumesAndProduces<T, E, U> producer, TypeSpec<U> iterateType,
			AsyncLoopSecondActionConsumes<T, U> consumer) {
		return loop(loopType, (handler) -> {
			if (it.hasNext()) {
				E elem;
				try {
					elem = it.next();
				}
				catch (Throwable exc) {
					handler.exit(null, exc);
					return;
				}
				producer.accept(elem, handler);
			}
			else {
				handler.exit(null, null);
			}
		}, iterateType, consumer);
	}

	/**
	 * Launch a task for each element given by an iterator
	 * 
	 * This loosely corresponds to a for loop. This invocation consists of a single action: To
	 * consume the element and launch a subordinate task, producing no result, or to exit the loop.
	 * The subordinate task should repeat the loop upon completion. If the loop does not require a
	 * subordinate asynchronous task, then please use an actual Java {@code for} loop. If the
	 * subordinate task does produce a result, it must be ignored using
	 * {@link AsyncLoopHandlerForSecond#repeatIgnore(Object, Throwable)}.
	 * 
	 * Example:
	 * 
	 * <pre>
	 * each(TypeSpec.VOID, mySet.iterator(), (item, loop) -> {
	 * 	sendItem().handle(loop::repeatIgnore);
	 * });
	 * </pre>
	 * 
	 * @param loopType the type of the result of the whole loop. This is usually
	 *            {@link TypeSpec#VOID}.
	 * @param it the iterator controlling the loop and providing elements
	 * @param action an action consuming each element and launching a subordinate asynchronous task,
	 *            producing no result, upon whose completion the loop repeats.
	 * @return a future which completes upon loop termination
	 */
	public static <T, E> CompletableFuture<T> each(TypeSpec<T> loopType, Iterator<E> it,
			AsyncLoopSecondActionConsumes<T, E> action) {
		return each(loopType, it, (e, loop) -> {
			loop.consume(e, null);
		}, TypeSpec.obj((E) null), action);
	}

	/**
	 * Begin executing a sequence of actions
	 * 
	 * This is a wrapper for Java's {@link CompletableFuture#thenCompose(Function)}. It aims to
	 * provide a little more flexibility. See the class documentation for a more thorough
	 * explanation with examples.
	 * 
	 * Example:
	 * 
	 * <pre>
	 * public CompletableFuture<Void> exampleSeq() {
	 * 	return sequence(TypeSpec.VOID).then((seq) -> {
	 * 		fetchValue().handle(seq::next);
	 * 	}, TypeSpec.INT).then((val, seq) -> {
	 * 		convertValue(val + 10).handle(seq::next);
	 * 	}, TypeSpec.STRING).then((str, seq) -> {
	 * 		System.out.println(str);
	 * 		seq.exit();
	 * 	}).asCompletableFuture();
	 * }
	 * </pre>
	 * 
	 * Note that the sequence begins executing on the calling thread.
	 * 
	 * @param type the type "returned" by the sequence
	 * @return an empty sequence ready to execute actions on the calling thread.
	 */
	public static <R> AsyncSequenceWithoutTemp<R> sequence(TypeSpec<R> type) {
		return sequence(new CompletableFuture<>());
	}

	/**
	 * Begin executing a sequence of actions to complete a given future
	 * 
	 * When using this variant, take care to call {@link AsyncSequenceWithoutTemp#finish()} or use
	 * {@link AsyncHandlerCanExit#exit(Object, Throwable)} in the final action. Otherwise, the
	 * sequence will not notify dependents of completion.
	 * 
	 * @see #sequence(TypeSpec)
	 * @param on the future to complete
	 * @return an empty sequence ready to execute actions on the calling thread.
	 */
	public static <R> AsyncSequenceWithoutTemp<R> sequence(CompletableFuture<R> on) {
		return new AsyncSequenceWithoutTemp<>(on, AsyncUtils.NIL);
	}

	/**
	 * An adapter for methods accepting {@link CompletionHandler}s
	 * 
	 * This class implements {@link CompletionHandler} with a wrapped {@link CompletableFuture}. It
	 * can be given to a method expecting a {@link CompletionHandler}, and the wrapped future can be
	 * given as the result for an asynchronous task. This allows methods expecting a
	 * {@link CompletionHandler} to participate in action callback chains.
	 *
	 * @param <T> the type "returned" by the asynchronous task
	 * @param <A> the type of attachment expected by the method. Usually {@link Object} is
	 *            sufficient, because the attachment is not passed to the wrapped future.
	 */
	static class FutureCompletionHandler<T, A> implements CompletionHandler<T, A> {
		CompletableFuture<T> future = new CompletableFuture<>();

		@Override
		public void completed(T result, A attachment) {
			future.complete(result);
		}

		@Override
		public void failed(Throwable exc, A attachment) {
			future.completeExceptionally(exc);
		}
	}

	/**
	 * An interface describing methods that accept an attachment and a {@link CompletionHandler}
	 *
	 * @param <T> the type "returned" to the {@link CompletionHandler}
	 */
	interface TakesCompletionHandlerArity0<T> {
		<A> void launch(A attachment, CompletionHandler<T, ? super A> handler);
	}

	/**
	 * Like {@link TakesCompletionHandlerArity0} but with one additional parameter
	 *
	 * @param <T> the type "returned" to the {@link CompletionHandler}
	 * @param <P0> the type of the first parameter
	 */
	interface TakesCompletionHandlerArity1<T, P0> {
		<A> void launch(P0 arg0, A attachment, CompletionHandler<T, ? super A> handler);
	}

	/**
	 * Like {@link TakesCompletionHandlerArity0} but with two additional parameters
	 *
	 * @param <T> the type "returned" to the {@link CompletionHandler}
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 */
	interface TakesCompletionHandlerArity2<T, P0, P1> {
		<A> void launch(P0 arg0, P1 arg1, A attachment, CompletionHandler<T, ? super A> handler);
	}

	/**
	 * Like {@link TakesCompletionHandlerArity0} but with three additional parameters
	 *
	 * @param <T> the type "returned" to the {@link CompletionHandler}
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 * @param <P2> the type of the third parameter
	 */
	interface TakesCompletionHandlerArity3<T, P0, P1, P2> {
		<A> void launch(P0 arg0, P1 arg1, P2 arg2, A attachment,
				CompletionHandler<T, ? super A> handler);
	}

	/**
	 * Like {@link TakesCompletionHandlerArity0} but with four additional parameters
	 *
	 * @param <T> the type "returned" to the {@link CompletionHandler}
	 * @param <P0> the type of the first parameter
	 * @param <P1> the type of the second parameter
	 * @param <P2> the type of the third parameter
	 * @param <P3> the type of the fourth parameter
	 */
	interface TakesCompletionHandlerArity4<T, P0, P1, P2, P3> {
		<A> void launch(P0 arg0, P1 arg1, P2 arg2, P3 arg3, A attachment,
				CompletionHandler<T, ? super A> handler);
	}

	/**
	 * Wrap an NIO asynchronous method in a {@link CompletableFuture}
	 * 
	 * Many non-blocking IO methods' last two parameters are an attachment and a
	 * {@link CompletionHandler}, e.g.,
	 * {@link AsynchronousSocketChannel#read(java.nio.ByteBuffer, Object, CompletionHandler)}. This
	 * method can wrap those methods, returning a {@link CompletableFuture} instead.
	 * 
	 * Example:
	 * 
	 * <pre>
	 * completable(TypeSpec.INT, channel::read, buf).thenAccept((len) -> {
	 * 	// Check length and process received data
	 * });
	 * </pre>
	 * 
	 * To help Java's template resolution, the first parameter is a {@link TypeSpec}. The second is
	 * a reference to the NIO method. Following that are up to four parameters to pass to the
	 * wrapped method. These correspond to the arguments preceding the attachment. Mismatched types
	 * are detected at compile time.
	 * 
	 * @param type the type "returned" by the {@link CompletionHandler}
	 * @param func the function launching the asynchronous task
	 * @return the future to receive the completion result
	 */
	public static <T, A> CompletableFuture<T> completable(TypeSpec<T> type,
			TakesCompletionHandlerArity0<T> func) {
		FutureCompletionHandler<T, A> handler = new FutureCompletionHandler<>();
		func.launch(null, handler);
		return handler.future;
	}

	/**
	 * Wrap an NIO asynchronous method in a {@link CompletableFuture}
	 * 
	 * @see #completable(TypeSpec, TakesCompletionHandlerArity0)
	 * 
	 * @param type the type "returned" by the {@link CompletionHandler}
	 * @param func the function launching the asynchronous task
	 * @return the future to receive the completion result
	 */
	public static <T, P0, A> CompletableFuture<T> completable(TypeSpec<T> type,
			TakesCompletionHandlerArity1<T, P0> func, P0 arg0) {
		FutureCompletionHandler<T, A> handler = new FutureCompletionHandler<>();
		func.launch(arg0, null, handler);
		return handler.future;
	}

	/**
	 * Wrap an NIO asynchronous method in a {@link CompletableFuture}
	 * 
	 * @see #completable(TypeSpec, TakesCompletionHandlerArity0)
	 * 
	 * @param type the type "returned" by the {@link CompletionHandler}
	 * @param func the function launching the asynchronous task
	 * @return the future to receive the completion result
	 */
	public static <T, P0, P1, A> CompletableFuture<T> completable(TypeSpec<T> type,
			TakesCompletionHandlerArity2<T, P0, P1> func, P0 arg0, P1 arg1) {
		FutureCompletionHandler<T, A> handler = new FutureCompletionHandler<>();
		func.launch(arg0, arg1, null, handler);
		return handler.future;
	}

	/**
	 * Wrap an NIO asynchronous method in a {@link CompletableFuture}
	 * 
	 * @see #completable(TypeSpec, TakesCompletionHandlerArity0)
	 * 
	 * @param type the type "returned" by the {@link CompletionHandler}
	 * @param func the function launching the asynchronous task
	 * @return the future to receive the completion result
	 */
	public static <T, P0, P1, P2, A> CompletableFuture<T> completable(TypeSpec<T> type,
			TakesCompletionHandlerArity3<T, P0, P1, P2> func, P0 arg0, P1 arg1, P2 arg2) {
		FutureCompletionHandler<T, A> handler = new FutureCompletionHandler<>();
		func.launch(arg0, arg1, arg2, null, handler);
		return handler.future;
	}

	/**
	 * Wrap an NIO asynchronous method in a {@link CompletableFuture}
	 * 
	 * @see #completable(TypeSpec, TakesCompletionHandlerArity0)
	 * 
	 * @param type the type "returned" by the {@link CompletionHandler}
	 * @param func the function launching the asynchronous task
	 * @return the future to receive the completion result
	 */
	public static <T, P0, P1, P2, P3, A> CompletableFuture<T> completable(TypeSpec<T> type,
			TakesCompletionHandlerArity4<T, P0, P1, P2, P3> func, P0 arg0, P1 arg1, P2 arg2,
			P3 arg3) {
		FutureCompletionHandler<T, A> handler = new FutureCompletionHandler<>();
		func.launch(arg0, arg1, arg2, arg3, null, handler);
		return handler.future;
	}

	/**
	 * Wrap a {@link CompletableFuture} as a {@link CompletionHandler}-style asynchronous task
	 * 
	 * This is used only in diagnostic classes to implement {@link CompletionHandler}-style
	 * asynchronous tasks. It is the opposite adapter to
	 * {@link #completable(TypeSpec, TakesCompletionHandlerArity0)} and its overloaded variants.
	 * 
	 * @param future the future to wrap
	 * @param handler a handler to receive the callback on future completion
	 */
	public static <T, A> void handle(CompletableFuture<T> future, A attachment,
			CompletionHandler<T, ? super A> handler) {
		future.handle((result, exc) -> {
			if (exc != null) {
				handler.failed(exc, attachment);
			}
			else {
				handler.completed(result, attachment);
			}
			return null;
		});
	}

	public interface TemperamentalRunnable {
		public void run() throws Throwable;
	}

	public interface TemperamentalSupplier<T> {
		public T get() throws Throwable;
	}

	/**
	 * A convenience for protecting engines from errors in user callbacks
	 * 
	 * If not used, then when multiple listeners are present, those following a listener whose
	 * callback generates an error may never actually be notified.
	 * 
	 * @param cb the invocation of the user callback
	 */
	public static void defensive(TemperamentalRunnable cb) {
		try {
			cb.run();
		}
		catch (Throwable e) {
			Msg.error(cb, "Error in callback", e);
		}
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
