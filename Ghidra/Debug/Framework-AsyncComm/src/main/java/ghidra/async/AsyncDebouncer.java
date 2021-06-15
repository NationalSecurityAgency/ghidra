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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * A debouncer for asynchronous events
 * 
 * <P>
 * A debouncer has an input "contact" event and produces an output "settled" once sufficient time
 * has passed since the last contact event. The goal is to prevent the needless frequent firing of
 * asynchronous events if the next event is going to negate the current one. The idea is that a
 * series of events, each negating the previous, can be fired within relative temporal proximity.
 * Without a debouncer, event processing time may be wasted. By passing the events through a
 * debouncer configured with a time window that contains all the events, only the final event in the
 * cluster will be processed. The cost of doing this is a waiting period, so event processing may be
 * less responsive, but will also be less frantic.
 */
public class AsyncDebouncer<T> {
	protected final AsyncTimer timer;
	protected final long windowMillis;

	protected final List<Consumer<T>> listeners = new ArrayList<>();
	protected CompletableFuture<T> settledPromise;

	protected T lastContact;
	protected CompletableFuture<Void> alarm;

	/**
	 * Construct a new debouncer
	 * 
	 * @param timer the timer to use for delay
	 * @param windowMillis the timing window of changes to elide
	 */
	public AsyncDebouncer(AsyncTimer timer, long windowMillis) {
		this.timer = timer;
		this.windowMillis = windowMillis;
	}

	/**
	 * Add a listener for the settled event
	 * 
	 * @param listener the listener
	 */
	public synchronized void addListener(Consumer<T> listener) {
		listeners.add(listener);
	}

	/**
	 * Remove a listener from the settled event
	 * 
	 * @param listener the listener
	 */
	public synchronized void removeListener(Consumer<T> listener) {
		listeners.remove(listener);
	}

	protected void doSettled() {
		List<Consumer<T>> ls;
		CompletableFuture<T> promise;
		synchronized (this) {
			alarm = null;

			// Avoid synchronization issues
			ls = new ArrayList<>(this.listeners); // This seems wasteful

			promise = settledPromise;
			settledPromise = null;
		}
		for (Consumer<T> listener : ls) {
			listener.accept(lastContact);
		}
		if (promise != null) {
			promise.complete(lastContact);
		}
	}

	/**
	 * Send a contact event
	 * 
	 * <P>
	 * This sets or resets the timer for the event window. The settled event will fire with the
	 * given value after this waiting period, unless another contact event occurs first.
	 * 
	 * @param val
	 */
	public synchronized void contact(T val) {
		lastContact = val;
		if (alarm != null) {
			alarm.cancel(false);
		}
		alarm = timer.mark().after(windowMillis).thenRun(this::doSettled);
	}

	/**
	 * Receive the next settled event
	 * 
	 * @return a future which completes with the value of the next settled event.
	 */
	public synchronized CompletableFuture<T> settled() {
		if (settledPromise == null) {
			settledPromise = new CompletableFuture<>();
		}
		return settledPromise;
	}
}
