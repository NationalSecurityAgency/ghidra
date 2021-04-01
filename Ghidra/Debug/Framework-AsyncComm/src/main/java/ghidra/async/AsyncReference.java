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

import java.lang.ref.Cleaner.Cleanable;
import java.lang.ref.WeakReference;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.function.Predicate;

import ghidra.util.Msg;
import ghidra.util.TriConsumer;

/**
 * An observable reference useful for asynchronous computations
 * 
 * <p>
 * The reference supports the usual set and get operations. The set operation accepts an optional
 * "cause" argument which is forwarded to some observers. The set operation may also be intercepted
 * by an optional filter. The filter function is provided a copy of the current value, proposed
 * value, and cause. The value it returns becomes the new value. If that value is different than the
 * current value, the observers are notified. The default filter returns the new value, always.
 * 
 * <p>
 * The reference provides three types of observation callbacks. The first is to listen for all
 * changes. This follows the listener pattern. When the value changes, i.e., is set to a value
 * different than the current value, all change listener are invoked with a copy of the new value
 * and a reference to the provided cause, if given. The second is to wait for the very next change.
 * It follows the promises pattern. The returned future completes with the new value upon the very
 * next change. The cause is not provided to the type of observer. The third is to wait for a given
 * value. It, too, follows the promises pattern. The returned future completes as soon as the
 * reference takes the given value. The cause is not provided to this type of observer.
 *
 * @param <T> the type of object stored by reference
 * @param <C> when updated, the type of the causes of those updates (often {@link Void})
 */
public class AsyncReference<T, C> {
	private T val;
	private List<TriConsumer<? super T, ? super T, ? super C>> listeners = new ArrayList<>();
	private CompletableFuture<T> changePromise = null;
	private final Map<T, CompletableFuture<Void>> waitsFor = new HashMap<>();
	private final List<WaitUntilFuture<T>> waitsUntil = new ArrayList<>();
	private FilterFunction<T, ? super C> filter = (cur, set, cause) -> set;
	private Throwable disposalReason;

	/**
	 * A function to filter updates to an {@link AsyncReference}
	 *
	 * @param <T> the type of object stored by the reference
	 * @param <C> when updated, the type of the causes of those updates
	 */
	@FunctionalInterface
	public interface FilterFunction<T, C> {
		/**
		 * Filter an incoming update, i.e., call to {@link AsyncReference#set(Object, Object)}
		 * 
		 * @param cur the current value of the reference
		 * @param set the incoming value from the update
		 * @param cause the cause of the update
		 * @return the new value to assign to the reference
		 */
		T filter(T cur, T set, C cause);
	}

	/**
	 * For {@link AsyncReference#waitUntil}
	 * 
	 * @param <T> the type of the associated reference
	 */
	private static class WaitUntilFuture<T> extends CompletableFuture<T> {
		private final Predicate<T> predicate;

		public WaitUntilFuture(Predicate<T> predicate) {
			this.predicate = predicate;
		}
	}

	/**
	 * Construct a new reference initialized to {@code null}
	 */
	public AsyncReference() {
		this(null);
	}

	/**
	 * Construct a new reference initialized to the given value
	 * 
	 * @param t the initial value
	 */
	public AsyncReference(T t) {
		this.val = t;
	}

	/**
	 * Apply a filter function to all subsequent updates
	 * 
	 * <p>
	 * The given function replaces the current function.
	 * 
	 * @param newFilter the filter
	 */
	public synchronized void filter(FilterFunction<T, ? super C> newFilter) {
		if (newFilter == null) {
			throw new NullPointerException();
		}
		this.filter = newFilter;
	}

	/**
	 * Get the current value of this reference
	 * 
	 * @return the current value
	 */
	public synchronized T get() {
		return val;
	}

	protected CompletableFuture<T> getAndClearChangePromise() {
		CompletableFuture<T> promise = changePromise;
		changePromise = null;
		return promise;
	}

	protected CompletableFuture<Void> getAndRemoveWaitFor(T t) {
		return waitsFor.remove(t);
	}

	protected List<WaitUntilFuture<T>> getAndRemoveUntils(T t) {
		List<WaitUntilFuture<T>> untils = new ArrayList<>();
		for (Iterator<WaitUntilFuture<T>> it = waitsUntil.iterator(); it.hasNext();) {
			WaitUntilFuture<T> wuf = it.next();
			if (wuf.predicate.test(t)) {
				it.remove();
				untils.add(wuf);
			}
		}
		return untils;
	}

	protected boolean filterAndSet(T t, C cause) {
		t = filter.filter(this.val, t, cause);
		if (Objects.equals(this.val, t)) {
			return false;
		}
		this.val = t;
		return true;
	}

	protected void invokeListeners(List<TriConsumer<? super T, ? super T, ? super C>> copy,
			T oldVal, T newVal, C cause) {
		for (TriConsumer<? super T, ? super T, ? super C> listener : copy) {
			try {
				listener.accept(oldVal, newVal, cause);
			}
			catch (RejectedExecutionException exc) {
				Msg.trace(this, "Ignoring rejection: " + exc);
			}
			catch (Throwable exc) {
				Msg.error(this, "Ignoring exception on async reference listener: ", exc);
			}
		}
	}

	protected void invokePromise(CompletableFuture<T> promise, T t) {
		if (promise != null) {
			promise.complete(t);
		}
	}

	protected void invokeWaitFor(CompletableFuture<Void> waiter) {
		if (waiter != null) {
			waiter.complete(null);
		}
	}

	protected void invokeWaitUntils(List<WaitUntilFuture<T>> untils, T t) {
		for (WaitUntilFuture<T> wuf : untils) {
			wuf.complete(t);
		}
	}

	/**
	 * Update this reference to the given value because of the given cause
	 * 
	 * @param newVal the proposed value (subject to the filter)
	 * @param cause the cause, often {@code null}
	 * @return true if the value of this reference changed (post filter)
	 */
	public boolean set(T newVal, C cause) {
		List<TriConsumer<? super T, ? super T, ? super C>> volatileListeners;
		CompletableFuture<T> promise;
		CompletableFuture<Void> waiter;
		List<WaitUntilFuture<T>> untils = new ArrayList<>();
		T oldVal;
		synchronized (this) {
			oldVal = this.val;
			if (!filterAndSet(newVal, cause)) {
				return false;
			}
			newVal = this.val;

			// Invoke listeners without the lock
			volatileListeners = listeners;
			promise = getAndClearChangePromise();
			waiter = getAndRemoveWaitFor(newVal);
			untils = getAndRemoveUntils(newVal);
		}
		invokeListeners(volatileListeners, oldVal, newVal, cause);
		invokePromise(promise, newVal);
		invokeWaitFor(waiter);
		invokeWaitUntils(untils, newVal);

		return true;
	}

	/**
	 * Update this reference using the given function because of the given cause
	 * 
	 * @param func the function taking the current value and returning the proposed value (subject
	 *            to the filter)
	 * @param cause the cause, often {@code null}
	 * @return the new value of this reference (post filter)
	 */
	public T compute(Function<? super T, ? extends T> func, C cause) {
		List<TriConsumer<? super T, ? super T, ? super C>> volatileListeners;
		CompletableFuture<T> promise;
		CompletableFuture<Void> waiter;
		List<WaitUntilFuture<T>> untils = new ArrayList<>();
		T newVal;
		T oldVal;
		synchronized (this) {
			oldVal = this.val;
			newVal = func.apply(this.val);
			if (!filterAndSet(newVal, cause)) {
				return this.val;
			}
			newVal = this.val;

			// Invoke listeners without the lock
			volatileListeners = listeners;
			promise = getAndClearChangePromise();
			waiter = getAndRemoveWaitFor(newVal);
			untils = getAndRemoveUntils(newVal);
		}
		invokeListeners(volatileListeners, oldVal, newVal, cause);
		invokePromise(promise, newVal);
		invokeWaitFor(waiter);
		invokeWaitUntils(untils, newVal);

		return newVal;
	}

	/**
	 * Add a listener for any change to this reference's value
	 * 
	 * <p>
	 * Updates that get "filtered out" do not cause a change listener to fire.
	 * 
	 * @param listener the listener, which is passed the new value (post-filter) and cause
	 */
	public void addChangeListener(TriConsumer<? super T, ? super T, ? super C> listener) {
		List<TriConsumer<? super T, ? super T, ? super C>> copy = new ArrayList<>(listeners);
		copy.add(listener);
		synchronized (this) {
			listeners = copy;
		}
	}

	/**
	 * Remove a change listener
	 * 
	 * @param listener the listener to remove
	 */
	public synchronized void removeChangeListener(TriConsumer<T, T, C> listener) {
		List<TriConsumer<? super T, ? super T, ? super C>> copy = new ArrayList<>(listeners);
		copy.remove(listener);
		synchronized (this) {
			listeners = copy;
		}
	}

	/**
	 * Wait for the next change and capture the new value
	 * 
	 * The returned future completes with the value of the very next change, at the time of that
	 * change. Subsequent changes to the value of the reference do not affect the returned future.
	 * 
	 * @return the future value at the next change
	 */
	public synchronized CompletableFuture<T> waitChanged() {
		if (disposalReason != null) {
			return CompletableFuture.failedFuture(disposalReason);
		}
		if (changePromise == null) {
			changePromise = new CompletableFuture<>();
		}
		return changePromise;
	}

	/**
	 * Wait for this reference to accept a particular value (post-filter)
	 * 
	 * <p>
	 * If the reference already has the given value, a completed future is returned.
	 * 
	 * @param t the expected value to wait on
	 * @return a future that completes the next time the reference accepts the given value
	 */
	public synchronized CompletableFuture<Void> waitValue(T t) {
		if (disposalReason != null) {
			return CompletableFuture.failedFuture(disposalReason);
		}
		if (Objects.equals(this.val, t)) {
			return AsyncUtils.NIL;
		}
		CompletableFuture<Void> waiter = waitsFor.get(t);
		if (waiter == null) {
			waiter = new CompletableFuture<>();
			waitsFor.put(t, waiter);
		}
		return waiter;
	}

	/**
	 * Wait for this reference to accept the first value meeting the given condition (post-filter)
	 * 
	 * <p>
	 * If the current value already meets the condition, a completed future is returned.
	 * 
	 * @param predicate the condition to meet
	 * @return a future that completes the next time the reference accepts a passing value
	 */
	public synchronized CompletableFuture<T> waitUntil(Predicate<T> predicate) {
		if (disposalReason != null) {
			return CompletableFuture.failedFuture(disposalReason);
		}
		if (predicate.test(val)) {
			return CompletableFuture.completedFuture(val);
		}
		WaitUntilFuture<T> waiter = new WaitUntilFuture<>(predicate);
		waitsUntil.add(waiter);
		return waiter;
	}

	/**
	 * Clear out the queues of future, completing each exceptionally
	 * 
	 * @param reason the reason for disposal
	 */
	public void dispose(Throwable reason) {
		List<CompletableFuture<?>> toExcept = new ArrayList<>();
		synchronized (this) {
			disposalReason = reason;
			toExcept.addAll(waitsFor.values());
			waitsFor.clear();
			toExcept.addAll(waitsUntil);
			waitsUntil.clear();
			if (changePromise != null) {
				toExcept.add(changePromise);
				changePromise = null;
			}
		}

		ExecutionException ex = new ExecutionException("Disposed", reason);
		for (CompletableFuture<?> future : toExcept) {
			future.completeExceptionally(ex);
		}
	}

	/**
	 * Used for debouncing
	 */
	protected static class ChangeRecord<T, C> {
		final T val;
		final C cause;

		public ChangeRecord(T val, C cause) {
			this.val = val;
			this.cause = cause;
		}
	}

	protected static class DebouncedAsyncReference<T, C> extends AsyncReference<T, C> {
		static class State<T, C> implements Runnable, TriConsumer<T, T, C> {
			final WeakReference<DebouncedAsyncReference<T, C>> to;
			final AsyncReference<T, C> from;
			final AsyncDebouncer<ChangeRecord<T, C>> db;

			public State(WeakReference<DebouncedAsyncReference<T, C>> to, AsyncReference<T, C> from,
					AsyncTimer timer, long windowMillis) {
				this.to = to;
				this.from = from;
				this.db = new AsyncDebouncer<>(timer, windowMillis);
				from.addChangeListener(this);
				db.addListener(r -> {
					DebouncedAsyncReference<T, C> ref = to.get();
					if (ref == null) {
						return;
					}
					ref.doSet(r.val, r.cause);
				});
			}

			@Override
			public void accept(T oldVal, T newVal, C c) {
				db.contact(new ChangeRecord<>(newVal, c));
			}

			@Override
			public void run() {
				from.removeChangeListener(this);
			}
		}

		final State<T, C> state;
		final Cleanable cleanable;

		public DebouncedAsyncReference(AsyncReference<T, C> from, AsyncTimer timer,
				long windowMillis) {
			super(from.val);
			this.state = new State<>(new WeakReference<>(this), from, timer, windowMillis);
			this.cleanable = AsyncUtils.CLEANER.register(this, state);
		}

		@Override
		public boolean set(T t, C cause) {
			throw new IllegalStateException("Cannot set a debounced async reference.");
		}

		private boolean doSet(T t, C cause) {
			return super.set(t, cause);
		}
	}

	/**
	 * Obtain a new {@link AsyncReference} whose value is updated after this reference has settled
	 * 
	 * <p>
	 * The original {@link AsyncReference} continues to behave as usual, except that is has an
	 * additional listener on it. When this reference is updated, the update is passed through an
	 * {@link AsyncDebouncer} configured with the given timer and window. When the debouncer
	 * settles, the debounced reference is updated.
	 * 
	 * <p>
	 * Directly updating, i.e., calling {@link #set(Object, Object)} on, the debounced reference
	 * subverts the debouncing mechanism, and will result in an exception. Only the original
	 * reference should be updated directly.
	 * 
	 * <p>
	 * Setting a filter on the debounced reference may have undefined behavior.
	 * 
	 * <p>
	 * If the original reference changes value rapidly, settling on the debounced reference's
	 * current value, no update event is produced by the debounced reference. If the original
	 * reference changes value rapidly, settling on a value different from the debounced reference's
	 * current value, an update event is produced, using the cause of the final update, even if an
	 * earlier cause was associated with the same final value.
	 * 
	 * @param timer a timer for measuring the window
	 * @param windowMillis the period of inactive time to consider this reference settled
	 * @return the new {@link AsyncReference}
	 */
	public AsyncReference<T, C> debounced(AsyncTimer timer, long windowMillis) {
		return new DebouncedAsyncReference<>(this, timer, windowMillis);
	}
}
