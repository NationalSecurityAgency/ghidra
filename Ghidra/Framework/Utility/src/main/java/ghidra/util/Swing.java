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
package ghidra.util;

import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.SwingUtilities;

import ghidra.util.exception.AssertException;
import ghidra.util.exception.UnableToSwingException;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A utility class to handle running code on the AWT Event Dispatch Thread
 */
public class Swing {

	private static final String SWING_TIMEOUT_SECONDS_PROPERTY =
		Swing.class.getName().toLowerCase() + ".timeout.seconds";
	private static final int SWING_TIMEOUT_SECONDS_DEFAULT_VALUE = 20;

	private static int loadTimeout() {
		String timeoutString = System.getProperty(SWING_TIMEOUT_SECONDS_PROPERTY,
			Integer.toString(SWING_TIMEOUT_SECONDS_DEFAULT_VALUE));

		try {
			return Integer.parseInt(timeoutString);
		}
		catch (NumberFormatException e) {
			return SWING_TIMEOUT_SECONDS_DEFAULT_VALUE;
		}
	}

	private static final int SWING_TIMEOUT_SECONDS_VALUE = loadTimeout();

	private static final String SWING_RUN_ERROR_MSG =
		"Unexpected exception running a task in the Swing Thread:  ";

	public static final String GSWING_THREAD_POOL_NAME = "GSwing Worker";

	/**
	 * Returns true if this is the event dispatch thread. Note that this method returns true in
	 * headless mode because any thread in headless mode can dispatch its own events. In swing
	 * environments, the swing thread is usually used to dispatch events.
	 *
	 * @return  true if this is the event dispatch thread -OR- is in headless mode.
	 */
	public static boolean isSwingThread() {
		if (isInHeadlessMode()) {
			return true;
		}

		// Note: just calling this method may trigger the AWT thread to get created
		return SwingUtilities.isEventDispatchThread();
	}

	/**
	 * Wait until AWT event queue (Swing) has been flushed and no more (to a point) events
	 * are pending.
	 */
	public static void allowSwingToProcessEvents() {
		Runnable r = () -> {
			// do nothing...this is just a placeholder runnable that gets put onto the stack
		};
		runNow(r);
		runNow(r);
		runNow(r);
	}

	/**
	 * Logs a stack trace if the current calling thread is not the Swing thread
	 * @param errorMessage The message to display when not on the Swing thread
	 * @return true if the calling thread is the Swing thread
	 */
	public static boolean assertSwingThread(String errorMessage) {
		if (!isSwingThread()) {
			Throwable t =
				ReflectionUtilities.filterJavaThrowable(new AssertException(errorMessage));
			Msg.error(Swing.class, errorMessage, t);
			return false;
		}
		return true;
	}

	/**
	 * Calls the given runnable on the Swing thread in the future by putting the request on
	 * the back of the event queue.
	 *
	 * @param r the runnable
	 */
	public static void runLater(Runnable r) {
		doRun(r, false, SWING_RUN_ERROR_MSG);
	}

	/**
	 * Runs the given runnable now if the caller is on the Swing thread.  Otherwise, the 
	 * runnable will be posted later.
	 * 
	 * @param r the runnable
	 */
	public static void runIfSwingOrRunLater(Runnable r) {
		if (isInHeadlessMode()) {
			r.run();
			return;
		}

		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
		}
		else {
			SwingUtilities.invokeLater(r);
		}
	}

	/**
	 * Calls the given suppler on the Swing thread, blocking with a
	 * {@link SwingUtilities#invokeAndWait(Runnable)} if not on the Swing thread.  
	 * 
	 * <p>Use this method when you are not on the Swing thread and you need to get a value 
	 * that is managed/synchronized by the Swing thread.
	 *
	 * <pre>{@literal
	 * 		String value = runNow(() -> label.getText());
	 * }</pre>
	 *
	 * @param s the supplier that will be called on the Swing thread
	 * @return the result of the supplier
	 * @see #runNow(Runnable)
	 */
	public static <T> T runNow(Supplier<T> s) {
		AtomicReference<T> ref = new AtomicReference<>();
		runNow(() -> ref.set(s.get()));
		return ref.get();
	}

	/**
	 * Calls the given runnable on the Swing thread
	 *
	 * @param r the runnable
	 * @see #runNow(Supplier) if you need to return a value from the Swing thread.
	 */
	public static void runNow(Runnable r) {

		try {
			// not sure what a reasonable wait is for a background thread; we can make this larger
			// if we find that a really slow system UI causes this to fail
			runNow(r, SWING_TIMEOUT_SECONDS_VALUE, TimeUnit.SECONDS);
		}
		catch (UnableToSwingException e) {

			//
			// Special Cases: if we are in production mode, then this is most likely a deadlock.
			// In that case, log the thread state.  In development mode, it is possible for this
			// to happen while debugging.  In that case, log a message, and then post the work
			// to be done without a timeout.
			//
			String warning = "Timed-out waiting to run a Swing task--potential deadlock!";
			if (SystemUtilities.isInReleaseMode()) {
				Throwable threadDump = ReflectionUtilities.createJavaFilteredThrowable();
				Msg.error(Swing.class, warning + "\nThreads State:\n" + threadDump);
				throw new RuntimeException(warning, e);
			}

			//
			// dev or testing mode
			//

			// note: using Swing.class for the originator does not work (presumably it conflicts
			//       with another logger sharing its name.  So, use the full name here.
			String originator = Swing.class.getName();
			Msg.debug(originator, warning + "  Ignore this message if debugging");
			doRun(r, true, SWING_RUN_ERROR_MSG);
		}
	}

	/**
	 * Calls the given runnable on the Swing thread
	 * 
	 * <p>This method will throw an exception if the Swing thread is not available within the
	 * given timeout.  This method is useful for preventing deadlocks.
	 *
	 * @param r the runnable
	 * @param timeout the timeout value
	 * @param unit the time unit of the timeout value
	 * @throws UnableToSwingException if the timeout was reach waiting for the Swing thread 
	 * @see #runNow(Supplier) if you need to return a value from the Swing thread.
	 */
	public static void runNow(Runnable r, long timeout, TimeUnit unit)
			throws UnableToSwingException {

		if (isInHeadlessMode() || SystemUtilities.isEventDispatchThread()) {
			doRun(r, true, SWING_RUN_ERROR_MSG);
			return;
		}

		/*
		 	We use the CyclicBarrier to force this thread and the Swing thread to wait for each
		 	other.  This allows the calling thread to know if/when the Swing thread starts and 
		 	the Swing thread to know if the calling thread timed-out.
		 */
		CyclicBarrier start = new CyclicBarrier(2);
		CyclicBarrier end = new CyclicBarrier(2);

		runLater(() -> {

			if (!waitFor(start)) {
				return; // interrupted or timed-out
			}

			try {
				r.run();
			}
			finally {
				waitFor(end);
			}

		});

		if (!waitFor(start, timeout, unit)) {
			// Special case: if the wait() returns false, then it was interrupted.  If the 
			// timeout occurred, an exception would have been thrown.   Interrupts are expected, 
			// so just exit.
			return;
		}

		waitFor(end);
	}

	private static boolean waitFor(CyclicBarrier barrier, long timeout, TimeUnit unit)
			throws UnableToSwingException {

		try {
			barrier.await(timeout, unit);
			return true;
		}
		catch (InterruptedException e) {
			// our Swing tasks may be interrupted from the framework
		}
		catch (BrokenBarrierException | TimeoutException e) {
			throw new UnableToSwingException(
				"Timed-out waiting for Swing thread lock in " + timeout + " " + unit);
		}

		// timed-out or was interrupted
		return false;
	}

	private static boolean waitFor(CyclicBarrier barrier) {

		try {
			barrier.await();
			return true;
		}
		catch (InterruptedException | BrokenBarrierException e) {
			// our Swing tasks may be interrupted from the framework
		}
		return false;
	}

	private static boolean isInHeadlessMode() {
		return SystemUtilities.isInHeadlessMode();
	}

	private static void doRun(Runnable r, boolean wait, String errorMessage) {
		if (isInHeadlessMode()) {
			r.run();
			return;
		}

		if (!wait) {
			SwingUtilities.invokeLater(r);
			return;
		}

		if (SwingUtilities.isEventDispatchThread()) {
			r.run();
			return;
		}

		try {
			SwingUtilities.invokeAndWait(r);
		}
		catch (InterruptedException e) {
			// we sometimes interrupt our tasks intentionally, so don't report it
		}
		catch (InvocationTargetException e) {
			Msg.error(Swing.class, errorMessage + "\nException Message: " + e.getMessage(), e);
		}
	}

	private Swing() {
		// utility class
	}
}
