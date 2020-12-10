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
package utilities.util;

import java.util.*;
import java.util.function.*;

/**
 * A mechanism for preventing callback loops, stack overflows, event storms, etc.
 * 
 * <p>
 * This thing really is a terrible hack, but it becomes necessary when the cause of an event cannot
 * be reliably determined. In cases where the callback (lacking a cause parameter) is expected to be
 * invoked on the same stack as the method calling, this mechanism can optionally suppress that
 * callback.
 * 
 * <p>
 * Suppression is implemented on a per-thread basis, so that suppression requests are only effective
 * when the callback is in fact on the same stack as the request.
 * 
 * <p>
 * A common use case is for a method to suppress any recursive calls, i.e., it is self suppressing,
 * e.g.:
 * 
 * <pre>
 * private final SuppressableCallback<Void> cbDoSomething = new SuppressableCallback<>();
 * 
 * public boolean doSomething() {
 * 	cbDoSomething.invoke(__ -> {
 * 		try (Suppression supp = cbDoSomething.supppress(null)) {
 * 			// do the thing
 * 			return doAnotherThing();
 * 		}
 * 	}, false);
 * }
 * 
 * public boolean doAnotherThing() {
 * 	// do the other thing
 * 	return doSomething();
 * }
 * </pre>
 * 
 * <p>
 * This example is very trivial, but this sort of thing can easily happen in event driven
 * programming. Consider the case where a state change causes an update to a table selection, which
 * fires the selection changed event, in turn requesting the same state change. Checking for
 * equality of the requested state with the current state can resolve some cases, but such checks
 * are thwarted when any two events requesting unequal state get queued on an event thread,
 * resulting in unending oscillation between the requested states. A more robust solution demands we
 * know the cause(s) of events. For now, the solution is to suppress event firing whenever a state
 * change is due to receiving an event.
 */
public class SuppressableCallback<T> {
	/**
	 * A suppression handle on the callback, for a specific thread
	 */
	public static class Suppression implements AutoCloseable {
		private final SuppressableCallback<?> cb;
		private final Thread thread;

		private <T> Suppression(SuppressableCallback<T> cb, Thread thread, T value) {
			this.cb = cb;
			this.thread = thread;
			cb.stack.get().push(value);
		}

		@Override
		public void close() {
			if (thread != Thread.currentThread()) {
				throw new IllegalStateException(
					"Must close on the same thread as suppressed the callback");
			}
			cb.stack.get().pop();
		}
	}

	// Carry a cached read-only view with the list
	private static class ListWithView<T> extends LinkedList<T> {
		private final List<T> view = Collections.unmodifiableList(this);
	}

	/**
	 * The stack of values from each suppression, probably just one
	 */
	private final ThreadLocal<ListWithView<T>> stack = ThreadLocal.withInitial(ListWithView::new);

	/**
	 * Suppress this callback, providing the given value as information
	 * 
	 * <p>
	 * This should almost always be used in a try-with-resources block. The only exception is
	 * perhaps to wrap this in another {@link AutoCloseable}. The information is usually one of the
	 * parameters, or perhaps a n-tuple of all parameters. For many use cases, {@code null} is all
	 * that is needed. The information is needed if the callback would like to make the suppression
	 * decision based on that information, e.g., is this callback telling me to "go to" a place I'm
	 * already "going to"?
	 * 
	 * @param value the value
	 * @return a handle to the request
	 */
	public Suppression suppress(T value) {
		return new Suppression(this, Thread.currentThread(), value);
	}

	/**
	 * Run the given callback unless it has been suppressed
	 * 
	 * <p>
	 * The values on the stack of suppression requests do not matter. If there's a request, the
	 * callback is suppressed.
	 * 
	 * @param callback the callback
	 */
	public void invoke(Runnable callback) {
		if (stack.get().isEmpty()) {
			callback.run();
		}
	}

	/**
	 * Run the given callback, returning its value, unless it has been suppressed
	 * 
	 * <p>
	 * Works like {@link #invoke(Runnable)}, except that the callback can return a value. If the
	 * callback is suppressed, a fallback value is returned instead.
	 * 
	 * @param <R> the return type
	 * @param callback the callback
	 * @param fallback a fallback value in case of suppression
	 * @return the value from the callback, or the fallback value
	 */
	public <R> R invoke(Supplier<R> callback, R fallback) {
		if (stack.get().isEmpty()) {
			return callback.get();
		}
		return fallback;
	}

	/**
	 * Run the given callback with the topmost suppression value or {@code null} if not suppressed
	 * 
	 * <p>
	 * The callback is always invoked, allow it to decide what actions to take (or not take) based
	 * on the given value. Not for a {@code SuppressableCallback<T>}, this method is useless, as the
	 * provided value will always be {@code null}, whether or not suppressed.
	 * 
	 * @param callback the callback
	 */
	public void invokeWithTop(Consumer<T> callback) {
		ListWithView<T> s = stack.get();
		if (s.isEmpty()) {
			callback.accept(null);
		}
		else {
			callback.accept(s.get(0));
		}
	}

	/**
	 * Run the given callback with the topmost value, returning its value
	 * 
	 * <p>
	 * This works like {@link #invokeWithTop(Consumer)}, except that the callback can return a
	 * value. Note that a fallback parameter is not taken, since the callback is always invoked. The
	 * callback should implement its own fallback logic.
	 * 
	 * @param <R> the return type
	 * @param callback the callback
	 * @return the value from the callback
	 */
	public <R> R invokeWithTop(Function<T, R> callback) {
		ListWithView<T> s = stack.get();
		return s.isEmpty() ? callback.apply(null) : callback.apply(s.get(0));
	}

	/**
	 * Run the given callback with the values from the stack of suppression requests
	 * 
	 * <p>
	 * The callback is always invoked, allowing it to decide what actions to take (or not take)
	 * based on the values present in the stack.
	 * 
	 * @param callback
	 */
	public void invokeWithStack(Consumer<List<T>> callback) {
		callback.accept(stack.get().view);
	}

	/**
	 * Run the given callback with the stack, returning its value
	 * 
	 * <p>
	 * This works like {@link #invokeWithStack(Consumer)}, except that the callback can return a
	 * value. Note that a fallback parameter is not taken, since the callback is always invoked. The
	 * callback should implement its own fallback logic.
	 * 
	 * @param <R> the return type
	 * @param callback the callback
	 * @return the value from the callback
	 */
	public <R> R invokeWithStack(Function<List<T>, R> callback) {
		return callback.apply(stack.get().view);
	}
}
