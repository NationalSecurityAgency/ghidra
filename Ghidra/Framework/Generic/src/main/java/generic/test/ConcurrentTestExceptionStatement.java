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

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.junit.runners.model.Statement;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;
import junit.framework.AssertionFailedError;
import util.CollectionUtils;

public class ConcurrentTestExceptionStatement extends Statement {

	// set this value to 'true' (ignoring case) to disable the test timeout feature
	public static final String DISABLE_TEST_TIMEOUT_PROPERTY =
		"ghidra.test.property.timeout.disable";
	public static final String TEST_TIMEOUT_MILLIS_PROPERTY =
		"ghidra.test.property.timeout.milliseconds";

	/** The time period after which a test will be forcibly terminated */
	private static long TIMEOUT_MILLIS = 10 /*mins*/ * 60 /*secs*/ * 1000 /*millis*/;
	private static Thread lastTestThread = null;

	private final Statement testStatement;
	private final GTimerMonitor timoutMonitor;

	public ConcurrentTestExceptionStatement(Statement originalStatement) {
		testStatement = originalStatement;
		ConcurrentTestExceptionHandler.clear();

		// enable timeout monitor by default; disable to permit extended debugging when running 
		// from eclipse or when set via a system property 
		if (ignoreTimeout()) {
			timoutMonitor = null;
		}
		else {
			long testTimeout = getTestTimeout();
			timoutMonitor = GTimer.scheduleRunnable(testTimeout, () -> {
				// no-op; we will use the monitor directly
			});
		}
	}

	private long getTestTimeout() {
		String timeoutOverrideString =
			System.getProperty(TEST_TIMEOUT_MILLIS_PROPERTY, null);
		if (timeoutOverrideString == null) {
			return TIMEOUT_MILLIS;
		}

		try {
			long timeout = Long.parseLong(timeoutOverrideString);
			Msg.info(this, "Using test timeout override value " + timeout + "ms");
			return timeout;
		}
		catch (NumberFormatException e) {
			Msg.error(this,
				"Unable to parse " + TEST_TIMEOUT_MILLIS_PROPERTY + " Long value '" +
					timeoutOverrideString + "'");
		}
		return TIMEOUT_MILLIS;
	}

	private boolean isTestTimeoutDisabled() {
		String disableProperty =
			System.getProperty(DISABLE_TEST_TIMEOUT_PROPERTY, Boolean.FALSE.toString());
		return Boolean.parseBoolean(disableProperty.trim());
	}

	private boolean ignoreTimeout() {
		if (isTestTimeoutDisabled()) {
			Msg.info(this, "Test timeout feature disabled");
			return true;
		}
		return isRunningFromEclipse();
	}

	private boolean isRunningFromEclipse() {
		// TODO: this may need adjustment for other Eclipse platforms/versions
		return System.getProperty("java.class.path").endsWith(".cp");
	}

	@Override
	public void evaluate() throws Throwable {

		//
		// We must wait so the next test does not start before the last test is finished.  This
		// can happen when we throw an exception from this method.
		// 
		waitForPreviousTestToFinish();

		TestThread testThread = new TestThread(testStatement);
		lastTestThread = testThread;
		testThread.start();

		waitForTestUnlessExceptions(testThread);

		//
		// Print any exceptions not from the test thread.
		//
		printNonTestThreadExceptions();

		// 
		// Throw any exceptions in order to fail the test.
		//

		// Prefer test exception over non-test thread exceptions.
		if (testThread.exceptionFromTest != null) {
			maybePrintConsoleTestThreadExceptionMessage();
			throw testThread.exceptionFromTest;
		}

		TestExceptionTracker nonTestThreadTracker = getFirstNonTestThreadExceptionTracker();
		if (nonTestThreadTracker == null) {
			return; // no exceptions to report
		}

		//
		// Throw the non-test thread exception.  This normally would not trigger a test failure, 
		// but we want to clean these up, so fail the test.
		//
		throw nonTestThreadTracker.getCombinedException();
	}

	private void maybePrintConsoleTestThreadExceptionMessage() {
		if (!ConcurrentTestExceptionHandler.hasException()) {
			return;
		}

		Msg.error(this, "The exceptions above may be side effects of test " +
			"Assert failure messages--see the junit test results");
	}

	private TestExceptionTracker getFirstNonTestThreadExceptionTracker() {

		// returns null if empty
		List<TestExceptionTracker> trackers = ConcurrentTestExceptionHandler.getExceptions();
		return CollectionUtils.any(trackers);
	}

	/**
	 * Prints all exceptions found that did not occur on the test thread.  This is useful 
	 * for debugging.
	 */
	private void printNonTestThreadExceptions() {
		List<TestExceptionTracker> trackers = ConcurrentTestExceptionHandler.getExceptions();
		if (trackers.isEmpty()) {
			return;
		}

		Msg.error(this, "Found unhandled exceptions (" + trackers.size() + "): ");
		for (int i = 0; i < trackers.size(); i++) {
			TestExceptionTracker tracker = trackers.get(i);
			Throwable combinedException = tracker.getCombinedException();
			Msg.error(this, "Exception " + (i + 1) + " of " + trackers.size() + '\n',
				combinedException);
		}
	}

	private void waitForTestUnlessExceptions(TestThread testThread) {

		while (!testThread.finished) {
			synchronized (ConcurrentTestExceptionHandler.class) {

				checkForTestTimeout(testThread);

				if (ConcurrentTestExceptionHandler.hasException()) {
					interruptTestThread(testThread);
					break;
				}

				try {
					ConcurrentTestExceptionHandler.class.wait(100);
				}
				catch (InterruptedException e) {
					// try again
				}
			}
		}
	}

	@SuppressWarnings("deprecation")  // Thread.stop()
	private void checkForTestTimeout(TestThread testThread) {

		if (timoutMonitor == null || !timoutMonitor.didRun()) {
			return;
		}

		if (SystemUtilities.isInDevelopmentMode()) {
			throw new AssertionFailedError("Test timeout after " +
				TimeUnit.MINUTES.convert(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS) + " mins");
		}

		String vmTrace = AbstractGenericTest.createStackTraceForAllThreads();
		Msg.error(ConcurrentTestExceptionStatement.class,
			"\n\nThreads at time of interrupt:\n" + vmTrace);

		interruptTestThread(testThread);

		StackTraceElement[] trace = testThread.getStackTrace();

		// if we get here, we are one step away from System.exit(1), so do the 
		// bad thing and kill the thread
		testThread.stop();
		lastTestThread = null; // don't try to join
		AssertionFailedError error =
			new AssertionFailedError("Test locked-up--aborting!  See log for details");
		error.setStackTrace(trace);
		throw error;
	}

	private void interruptTestThread(TestThread testThread) {
		testThread.interrupt();

		try {
			// give the test thread a chance to register any exceptions; if we don't wait, we 
			// may report exceptions before the test thread is given back control
			testThread.join(250);
		}
		catch (InterruptedException e) {
			// we tried
		}
	}

	private void waitForPreviousTestToFinish() {
		if (lastTestThread == null) {
			return;
		}

		long reasonableTimeoutMillis = 15000;
		try {
			lastTestThread.join(reasonableTimeoutMillis);
		}
		catch (InterruptedException e) {
			// we tried our best; just continue on
		}
	}

}
