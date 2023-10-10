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
package generic.test;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * A class which handles exceptions that occur off of the main test thread.  Exceptions can be
 * reported to this class, which will later be checked by {@link AbstractGenericTest}.
 */
public class ConcurrentTestExceptionHandler implements UncaughtExceptionHandler {

	// Exception messages that we choose to ignore
	private static final String[] IGNORABLE_ERROR_MESSAGES =
		new String[] { "DerivedColor$UIResource cannot be cast to", // test machine timing issue
			"FontUIResource cannot be cast to javax.swing.Painter", // test machine timing issue
		};

	private static final List<TestExceptionTracker> throwables =
		Collections.synchronizedList(new ArrayList<>());

	private static volatile boolean enabled = true;

	/**
	 * Installs this exception handler as the default uncaught exception handler.  See
	 * {@link Thread#setDefaultUncaughtExceptionHandler(UncaughtExceptionHandler)}
	 */
	public static void registerHandler() {
		// Note: not sure why this is done on the Swing thread later.  Seems like this could be done
		// when this method is called, from any thread.
		Swing.runLater(() -> {
			Thread.setDefaultUncaughtExceptionHandler(new ConcurrentTestExceptionHandler());
		});
	}

	/**
	 * Tells this class to process the given throwable
	 * @param thread the thread that encountered the throwable
	 * @param t the throwable
	 */
	public synchronized static void handle(Thread thread, Throwable t) {

		if (!enabled) {
			return;
		}

		if (t instanceof InvocationTargetException) {
			t = t.getCause();
		}

		if (isKnownTestMachineTimingBug(t)) {
			Msg.error(ConcurrentTestExceptionHandler.class,
				"Found known Java Swing timing bug.  Reporting, but not failing.", t);
			return;
		}

		TestExceptionTracker tracker = new TestExceptionTracker(thread.getName(), t);
		throwables.add(tracker);

		ConcurrentTestExceptionHandler.class.notifyAll();
	}

	/**
	 * Some exceptions that happen off the test thread are not serious enough to fail the test.
	 * For example, some exceptions happen on the headless test server due more to
	 * environmental issues rather than real problems.  This method is intended to ignore
	 * these less-than-serious issues.
	 *
	 * @param t the throwable to examine
	 * @return true if it should be ignored
	 */
	private static boolean isKnownTestMachineTimingBug(Throwable t) {

		String message = t.getMessage();
		if (message == null) {
			return false;
		}

		return StringUtils.containsAny(message, IGNORABLE_ERROR_MESSAGES);
	}

	/**
	 * Clears all exceptions being tracked by this class
	 */
	public synchronized static void clear() {
		throwables.clear();
	}

	/**
	 * Enables this class after a call to {@link #disable()} has been made
	 */
	public synchronized static void enable() {
		enabled = true;
	}

	/**
	 * Disables this class's tracking of exceptions.  Clients use this method to have this class
	 * ignore expected exceptions.   This is a bit course-grained, as it does not allow clients to
	 * ignore specific expected exceptions.
	 */
	public synchronized static void disable() {
		enabled = false;
	}

	/**
	 * Returns true if this class is enabled.  When disabled this class does not track exceptions.
	 * @return true if enabled
	 */
	public synchronized static boolean isEnabled() {
		return enabled;
	}

	/**
	 * Returns all exceptions tracked by this class
	 * @return all exceptions tracked by this class
	 */
	public static synchronized List<TestExceptionTracker> getExceptions() {
		return new ArrayList<>(throwables);
	}

	/**
	 * Returns true if this class has been given any exceptions to handle since last being cleared
	 * @return true if this class has been given any exceptions to handle since last being cleared
	 */
	public static synchronized boolean hasException() {
		return !throwables.isEmpty();
	}

	@Override
	public void uncaughtException(Thread thread, Throwable t) {
		handle(thread, t);
	}
}
