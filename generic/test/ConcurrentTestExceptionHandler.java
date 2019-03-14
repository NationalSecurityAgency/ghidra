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
import ghidra.util.SystemUtilities;

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

	public static void registerHandler() {
		SystemUtilities.runSwingLater(() -> {
			// do this on the Swing thread
			Thread.setDefaultUncaughtExceptionHandler(new ConcurrentTestExceptionHandler());
		});
	}

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
	 * @param throwable the throwable to examine
	 * @return true if it should be ignored
	 */
	private static boolean isKnownTestMachineTimingBug(Throwable t) {

		String message = t.getMessage();
		if (message == null) {
			return false;
		}

		return StringUtils.containsAny(message, IGNORABLE_ERROR_MESSAGES);
	}

	public synchronized static void clear() {
		throwables.clear();
	}

	public synchronized static void enable() {
		enabled = true;
	}

	public synchronized static void disable() {
		enabled = false;
	}

	public synchronized static boolean isEnabled() {
		return enabled;
	}

	public static synchronized List<TestExceptionTracker> getExceptions() {
		return new ArrayList<>(throwables);
	}

	public static synchronized boolean hasException() {
		return !throwables.isEmpty();
	}

	@Override
	public void uncaughtException(Thread thread, Throwable t) {
		handle(thread, t);
	}
}
