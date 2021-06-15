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
package ghidra.util.task;

/**
 * A class to allow clients to buffer events.  UI components may receive numbers events to make
 * changes to their underlying data model.  Further, for many of these clients, it is sufficient
 * to perform one update to capture all of the changes.  In this scenario, the client can use this
 * class to keep pushing off internal updates until: 1) the flurry of events has settled down, or
 * 2) some specified amount of time has expired.
 * <p>
 * The various methods dictate when the client will get a callback:<p>
 * <ul>
 * 	<li>{@link #update()} - if this is the first call to <code>update</code>, then do the work
 *                          immediately; otherwise, buffer the update request until the
 *                          timeout has expired.</li>
 *  <li>{@link #updateNow()} - perform the callback now.</li>
 *  <li>{@link #updateLater()} - buffer the update request until the timeout has expired.</li>
 *  <li>Non-blocking update now - this is a conceptual use-case, where the client wishes to perform an
 *                          immediate update, but not during the current Swing event.  To achieve
 *                          this, you could call something like:
 *                          <pre>{@literal
 *                          	SwingUtilities.invokeLater(() -> updateManager.updateNow());
 *                          }</pre>
 *  </li>
 * </ul>
 *
 * <P> This class is safe to use in a multi-threaded environment.   State variables are guarded
 * via synchronization on this object.   The Swing thread is used to perform updates, which
 * guarantees that only one update will happen at a time.  
 */
public class SwingUpdateManager extends AbstractSwingUpdateManager {

	private final Runnable clientRunnable;

	/**
	 * Constructs a new SwingUpdateManager with default values for min and max delay.  See
	 * {@link #DEFAULT_MIN_DELAY} and {@value #DEFAULT_MAX_DELAY}.
	 *
	 * @param r the runnable that performs the client work.
	 */
	public SwingUpdateManager(Runnable r) {
		this(DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY, r);
	}

	/**
	 * Constructs a new SwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param r the runnable that performs the client work.
	 */
	public SwingUpdateManager(int minDelay, Runnable r) {
		this(minDelay, DEFAULT_MAX_DELAY, r);
	}

	/**
	 * Constructs a new SwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param maxDelay the maximum amount of time to wait between gui updates.
	 * @param r the runnable that performs the client work.
	 */
	public SwingUpdateManager(int minDelay, int maxDelay, Runnable r) {
		super(minDelay, maxDelay, DEFAULT_NAME);
		this.clientRunnable = r;
	}

	/**
	 * Constructs a new SwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, regardless of
	 * the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param maxDelay the maximum amount of time to wait between gui updates.
	 * @param name The name of this update manager; this allows for selective trace logging
	 * @param r the runnable that performs the client work.
	 */
	public SwingUpdateManager(int minDelay, int maxDelay, String name, Runnable r) {
		super(minDelay, maxDelay, name);
		this.clientRunnable = r;
	}

	@Override
	protected void swingDoWork() {
		clientRunnable.run();
	}

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	@Override
	public synchronized void update() {
		super.update();
	}

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	@Override
	public synchronized void updateLater() {
		super.updateLater();
	}

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	@Override
	public void updateNow() {
		super.updateNow();
	}

}
