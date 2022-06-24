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

import java.util.Timer;
import java.util.concurrent.*;
import java.util.function.Supplier;

/**
 * A timer for asynchronous scheduled tasks
 * 
 * <p>
 * This object provides a futures which complete at specified times. This is useful for pausing amid
 * a chain of callback actions, i.e., between iterations of a loop. A critical tenant of
 * asynchronous reactive programming is to never block a thread, at least not for an indefinite
 * period of time. If an action blocks, it may prevent completion of other tasks in its executor's
 * queue, possibly resulting in deadlock. An easy and tempting way to accidentally block is to call
 * {@link Object#wait()} or {@link Thread#sleep(long)} when trying to wait for a specific period of
 * time. Unfortunately, this does not just block the chain, but blocks the thread. Java provides a
 * {@link Timer}, but its {@link Future}s are not {@link CompletableFuture}s. The same is true of
 * {@link ScheduledThreadPoolExecutor}.
 * 
 * <p>
 * A delay is achieved using {@link #mark()}, then {@link #after(long)}. For example, within a
 * {@link AsyncUtils#sequence(TypeSpec)}:
 * 
 * <pre>
 * timer.mark().after(1000).handle(seq::next);
 * </pre>
 * 
 * <p>
 * {@link #mark()} marks the current system time; all subsequent calls to {@link #after(long)}
 * schedule futures relative to this mark. Using {@link #after(long)} before {@link #mark()} gives
 * undefined behavior. Scheduling a timed sequence of actions is best accomplished using times
 * relative to a single mark. For example:
 * 
 * <pre>
 * sequence(TypeSpec.VOID).then((seq) -> {
 * 	timer.mark().after(1000).handle(seq::next);
 * }).then((seq) -> {
 * 	doTaskAtOneSecond().handle(seq::next);
 * }).then((seq) -> {
 * 	timer.after(2000).handle(seq::next);
 * }).then((seq) -> {
 * 	doTaskAtTwoSeconds().handle(seq::next);
 * }).asCompletableFuture();
 * </pre>
 * 
 * <p>
 * This provides slightly more precise scheduling than delaying for a fixed period between tasks.
 * Consider a second example:
 * 
 * <pre>
 * sequence(TypeSpec.VOID).then((seq) -> {
 * 	timer.mark().after(1000).handle(seq::next);
 * }).then((seq) -> {
 * 	doTaskAtOneSecond().handle(seq::next);
 * }).then((seq) -> {
 * 	timer.mark().after(1000).handle(seq::next);
 * }).then((seq) -> {
 * 	doTaskAtTwoSeconds().handle(seq::next);
 * }).asCompletableFuture();
 * </pre>
 * 
 * <p>
 * In the first example, {@code doTaskAtTwoSeconds} executes at 2000ms from the mark + some
 * scheduling overhead. In the second example, {@code doTaskAtTwoSeconds} executes at 1000ms + some
 * scheduling overhead + the time to execute {@code doTaskAtOneSecond} + 1000ms + some more
 * scheduling overhead. Using the second pattern repeatedly can lead to increased inaccuracies as
 * overhead accumulates over time. This may be an issue for some applications. Using the first
 * pattern, there is no accumulation. The actual scheduled time will always be the specified time
 * from the mark + some scheduling overhead. The scheduling overhead is generally bounded to a small
 * constant and depends on the accuracy of the host OS and JVM.
 * 
 * <p>
 * Like {@link Timer}, each {@link AsyncTimer} is backed by a single thread which uses
 * {@link Object#wait()} to implement its timing. Thus, this is not suitable for real-time
 * applications. Unlike {@link Timer}, the backing thread is always a daemon. It will not prevent
 * process termination. If a task is long running, the sequence should queue it on another executor,
 * perhaps using {@link CompletableFuture#supplyAsync(Supplier, Executor)}. Otherwise, other
 * scheduled tasks may be inordinately delayed.
 */
public class AsyncTimer {
	public static final AsyncTimer DEFAULT_TIMER = new AsyncTimer();

	protected ExecutorService thread = Executors.newSingleThreadExecutor();

	public class Mark {
		protected final long mark;

		protected Mark(long mark) {
			this.mark = mark;
		}

		/**
		 * Schedule a task to run when the given number of milliseconds has passed since this mark
		 * 
		 * The method returns immediately, giving a future result. The future completes "soon after"
		 * the requested interval, since the last mark, passes. There is some minimal overhead, but
		 * the scheduler endeavors to complete the future as close to the given time as possible.
		 * The actual scheduled time will not precede the requested time.
		 * 
		 * @param intervalMillis the interval after which the returned future completes
		 * @return a future that completes soon after the given interval
		 */
		public CompletableFuture<Void> after(long intervalMillis) {
			return atSystemTime(mark + intervalMillis);
		}

		/**
		 * Time a future out after the given interval
		 * 
		 * @param <T> the type of the future
		 * @param future the future whose value is expected in the given interval
		 * @param millis the time interval in milliseconds
		 * @param valueIfLate a supplier for the value if the future doesn't complete in time
		 * @return a future which completes with the given futures value, or the late value if it
		 *         times out.
		 */
		public <T> CompletableFuture<T> timeOut(CompletableFuture<T> future, long millis,
				Supplier<T> valueIfLate) {
			return CompletableFuture.anyOf(future, after(millis)).thenApply(v -> {
				if (future.isDone()) {
					return future.getNow(null);
				}
				return valueIfLate.get();
			});
		}
	}

	/**
	 * Create a new timer
	 * 
	 * <p>
	 * Except to reduce contention among threads, most applications need only create one timer
	 * instance. See {@link AsyncTimer#DEFAULT_TIMER}.
	 */
	public AsyncTimer() {
	}

	/**
	 * Schedule a task to run when {@link System#currentTimeMillis()} has passed a given time
	 * 
	 * <p>
	 * This method returns immediately, giving a future result. The future completes "soon after"
	 * the current system time passes the given time in milliseconds. There is some minimal
	 * overhead, but the scheduler endeavors to complete the future as close to the given time as
	 * possible. The actual scheduled time will not precede the requested time.
	 * 
	 * @param timeMillis the time after which the returned future completes
	 * @return a future that completes soon after the given time
	 */
	public CompletableFuture<Void> atSystemTime(long timeMillis) {
		if (timeMillis - System.currentTimeMillis() <= 0) {
			return AsyncUtils.NIL;
		}

		long delta = timeMillis - System.currentTimeMillis();
		Executor executor =
			delta <= 0 ? thread : CompletableFuture.delayedExecutor(delta, TimeUnit.MILLISECONDS);
		return CompletableFuture.runAsync(() -> {
		}, executor);
	}

	/**
	 * Mark the current system time
	 * 
	 * @return this same timer
	 */
	public Mark mark() {
		return new Mark(System.currentTimeMillis());
	}
}
