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

import javax.swing.Timer;

import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A base class to allow clients to buffer events.  UI components may receive numbers events to make
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
public abstract class AbstractSwingUpdateManager {

	protected static final long NONE = 0;
	public static final int DEFAULT_MAX_DELAY = 30000;
	protected static final int MIN_DELAY_FLOOR = 10;
	protected static final int DEFAULT_MIN_DELAY = 250;
	protected static final String DEFAULT_NAME = AbstractSwingUpdateManager.class.getSimpleName();
	private static final WeakSet<AbstractSwingUpdateManager> instances =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	protected final Timer timer;
	private final int minDelay;
	private final int maxDelay;

	private final String name;
	private String inceptionInformation;

	private long requestTime = NONE;
	private long bufferingStartTime;
	private boolean disposed = false;

	// This is true when work has begun and is not finished.  This is only mutated on the 
	// Swing thread, but is read by other threads.
	protected boolean isWorking;

	/**
	 * Constructs a new SwingUpdateManager with default values for min and max delay.  See
	 * {@link #DEFAULT_MIN_DELAY} and {@value #DEFAULT_MAX_DELAY}.
	 */
	protected AbstractSwingUpdateManager() {
		this(DEFAULT_MIN_DELAY, DEFAULT_MAX_DELAY);
	}

	/**
	 * Constructs a new AbstractSwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen
	 */
	protected AbstractSwingUpdateManager(int minDelay) {
		this(minDelay, DEFAULT_MAX_DELAY);
	}

	/**
	 * Constructs a new AbstractSwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param maxDelay the maximum amount of time to wait between gui updates.
	 */
	protected AbstractSwingUpdateManager(int minDelay, int maxDelay) {
		this(minDelay, maxDelay, DEFAULT_NAME);
	}

	/**
	 * Constructs a new AbstractSwingUpdateManager
	 * <p>
	 * <b>Note: </b>The <code>minDelay</code> will always be at least {@link #MIN_DELAY_FLOOR}, 
	 * regardless of the given value.
	 *
	 * @param minDelay the minimum number of milliseconds to wait once the event stream stops
	 *                 coming in before actually updating the screen.
	 * @param maxDelay the maximum amount of time to wait between gui updates.
	 * @param name The name of this update manager; this allows for selective trace logging
	 */
	protected AbstractSwingUpdateManager(int minDelay, int maxDelay, String name) {

		this.maxDelay = maxDelay;
		this.name = name;

		recordInception();
		this.minDelay = Math.max(MIN_DELAY_FLOOR, minDelay);
		timer = new Timer(minDelay, e -> timerCallback());
		timer.setRepeats(false);
		instances.add(this);
	}

	/**
	 * The subclass callback to perform work.
	 */
	protected abstract void swingDoWork();

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	protected synchronized void update() {
		if (disposed) {
			return;
		}

		requestTime = System.currentTimeMillis();
		Swing.runLater(this::checkForWork);
	}

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	protected synchronized void updateLater() {
		if (disposed) {
			return;
		}

		requestTime = System.currentTimeMillis();
		bufferingStartTime = bufferingStartTime == NONE ? requestTime : bufferingStartTime;
		scheduleCheckForWork();
	}

	/**
	 * Signals to perform an update.  See the class header for the usage of the various
	 * update methods.
	 */
	protected void updateNow() {
		synchronized (this) {
			if (disposed) {
				return;
			}

			// force an update by disabling buffering with a new request
			requestTime = System.currentTimeMillis();
			bufferingStartTime = NONE;	// set so that the max delay check will trigger work
		}

		Swing.runNow(this::checkForWork);
	}

	/**
	 * Causes this run manager to run if it has a pending update
	 */
	public void flush() {
		synchronized (this) {
			if (disposed) {
				return;
			}

			if (!hasPendingUpdates()) {
				return;
			}

			// force an update by disabling buffering with a new request
			requestTime = System.currentTimeMillis();
			bufferingStartTime = NONE;	// set so that the max delay check will trigger work
		}

		Swing.runNow(this::checkForWork);
	}

	/**
	 * Signals to stop any buffered work.   This will not stop any in-progress work.
	 */
	public synchronized void stop() {
		if (disposed) {
			return;
		}

		timer.stop();
		requestTime = NONE;
		bufferingStartTime = NONE;
	}

	/**
	 * Returns true if there is a pending request that hasn't started yet.  Any currently
	 * executing requests will not affect this call.
	 *
	 * @return true if there is a pending request that hasn't started yet.
	 */
	public synchronized boolean hasPendingUpdates() {
		if (disposed) {
			return false;
		}

		return requestTime != NONE;
	}

	/**
	 * Returns true if any work is being performed or if there is buffered work
	 * @return true if any work is being performed or if there is buffered work
	 */
	public synchronized boolean isBusy() {
		if (disposed) {
			return false;
		}

		return requestTime != NONE || isWorking;
	}

	public synchronized void dispose() {
		timer.stop();
		instances.remove(this);
		requestTime = NONE;
		bufferingStartTime = NONE;
		disposed = true;
	}

	public synchronized boolean isDisposed() {
		return disposed;
	}

	@Override
	public String toString() {
		return name + " @ " + inceptionInformation;
	}

	public String toStringDebug() {
		//@formatter:off
		return "{\n" +
			"\tname: " + name + "\n" +
			"\tcreator: " + inceptionInformation + " ("+System.identityHashCode(this)+")\n" +
			"\trequest time: "+requestTime + "\n" +
			"\twork count: " + isWorking + "\n" +
		"}";
		//@formatter:on
	}

	// note: this is called on the Swing thread
	protected void checkForWork() {

		if (shouldDoWork()) {
			swingExecutePendingWork();
		}
	}

	// This is similar to checkForWork except that it resets the task buffering when
	// the time expires and there is no work to do.
	private void timerCallback() {

		if (shouldDoWork()) {
			swingExecutePendingWork();
		}
		else if (requestTime == NONE) {
			bufferingStartTime = NONE; // The timer has fired and there is no pending work
		}
	}

	// note: this is called on the Swing thread
	private synchronized boolean shouldDoWork() {

		// If no pending request, exit without restarting timer
		if (requestTime == NONE) {
			return false;
		}

		long now = System.currentTimeMillis();
		if (isTimeToWork(now)) {
			bufferingStartTime = now;
			requestTime = NONE;
			isWorking = true;
			return true;
		}

		scheduleCheckForWork();
		return false;
	}

	protected void scheduleCheckForWork() {
		timer.start();
	}

	private boolean isTimeToWork(long now) {

		// if past maximum delay, always do work
		long timeSinceBufferingStart = now - bufferingStartTime;
		if (timeSinceBufferingStart > maxDelay) {
			return true;
		}

		// if no new requests have come in since the last time we checked, do work
		long timeSinceLastRequest = now - requestTime;
		if (timeSinceLastRequest > minDelay) {
			return true;
		}

		return false;
	}

	// note: this is called on the Swing thread
	private void swingExecutePendingWork() {
		try {
			swingDoWork();
		}
		catch (Throwable t) {
			// catch exceptions so we don't kill the timer
			Msg.showError(this, null, "Unexpected Exception",
				"Unexpected exception in Swing Update Manager", t);
		}

		isWorking = false;

		// we need to clear the buffering flag after the minDelay has passed, so start the timer
		scheduleCheckForWork();
	}

//==================================================================================================
// Inception Info
//==================================================================================================

	private void recordInception() {
		inceptionInformation = getInceptionFromTheFirstClassThatIsNotUs();
	}

	private String getInceptionFromTheFirstClassThatIsNotUs() {
		Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan(getClass());

		StackTraceElement[] trace = t.getStackTrace();
		String classInfo = trace[0].toString();

		/*
		// debug source of creation
		Throwable filtered = ReflectionUtilities.filterJavaThrowable(t);
		String string = ReflectionUtilities.stackTraceToString(filtered);
		classInfo = classInfo + "\n\tfrom:\n\n" + string;
		*/

		return classInfo;
	}

}
