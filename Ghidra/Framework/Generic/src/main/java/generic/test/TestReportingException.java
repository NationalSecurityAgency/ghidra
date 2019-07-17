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

import java.io.*;
import java.util.Objects;

import org.apache.commons.lang3.ArrayUtils;

import utilities.util.reflection.ReflectionUtilities;

/**
 * A {@link RuntimeException} that will print a custom stack trace.  
 * 
 * <P>This class will print not only the trace info for the exception passed at construction 
 * time, but will also print a trace for the test thread at the time of the exception.  Also,
 * the trace information printed will be filtered of entries that are not useful for 
 * debugging, like Java class entries.
 */
public class TestReportingException extends RuntimeException {

	private static final String[] GENERAL_USELESS_STACK_ELEMET_PATTERNS =
		new String[] { "java.awt.WaitDispatchSupport" };

	//@formatter:off
	private static final String[] SWING_STACK_ELEMENT_PATTERNS = 
		ArrayUtils.addAll(GENERAL_USELESS_STACK_ELEMET_PATTERNS, 
						  "java.awt.Event", 
						  "java.security", 
						  "java.awt.event");
	//@formatter:on

	private String userMessage;
	private String threadName;
	private Throwable t;
	private StackTraceElement[] testThreadTrace;

	/**
	 * Creates a new {@link TestReportingException} using an exception that was generated on 
	 * the Swing thread.
	 * 
	 * @param message an optional custom message that will be printed first in the stack trace
	 * @param t the original exception
	 * @return the new {@link TestReportingException}
	 */
	public static TestReportingException fromSwingThread(String message, Throwable t) {

		StackTraceElement[] testThreadTrace = null;
		if (TestThread.isTestThread()) {
			Throwable testThrowable =
				ReflectionUtilities.createThrowableWithStackOlderThan(TestReportingException.class);
			testThreadTrace = testThrowable.getStackTrace();
			testThreadTrace = TestThread.filterTrace(testThreadTrace);

			StackTraceElement[] awtThreadTrace = t.getStackTrace();
			awtThreadTrace = TestThread.filterTrace(awtThreadTrace);
			t.setStackTrace(awtThreadTrace);
		}

		TestReportingException e =
			new TestReportingException("AWT-EventQueue-0", t, testThreadTrace);
		e.userMessage = message;
		return e;
	}

	TestReportingException(String threadName, Throwable t) {
		this(threadName, t, null);
	}

	TestReportingException(String threadName, Throwable t, StackTraceElement[] testThreadTrace) {
		this.t = Objects.requireNonNull(t);
		this.threadName = Objects.requireNonNull(threadName);
		this.testThreadTrace = testThreadTrace;
	}

	public static String getSwingThreadTraceString(Throwable throwable) {
		StackTraceElement[] trace = throwable.getStackTrace();
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, SWING_STACK_ELEMENT_PATTERNS);

		String className = throwable.getClass().getSimpleName();
		String message = throwable.getMessage();

		if (message != null) {
			message = className + ": " + message;
		}
		else {
			message = className;
		}

		StringWriter stringWriter = new StringWriter();
		PrintWriter writer = new PrintWriter(stringWriter);

		writer.append(message);
		writer.append('\n');

		printTrace(filtered, writer);

		return stringWriter.toString();
	}

	@Override
	public void printStackTrace(PrintStream s) {
		String trace = buildStackTraceString();
		s.println(trace);
	}

	@Override
	public void printStackTrace(PrintWriter s) {
		String trace = buildStackTraceString();
		s.println(trace);
	}

	@Override
	public StackTraceElement[] getStackTrace() {
		// this is overridden for clients that do not call printStackTrace()
		StackTraceElement[] trace = t.getStackTrace();
		return filterTrace(trace);
	}

	@Override
	public String getMessage() {
		// this is overridden for clients that do not call printStackTrace()
		return "(See log for more stack trace info)\n\n" + generateMessge();
	}

	private String buildStackTraceString() {

		String m = generateMessge();

		StringWriter stringWriter = new StringWriter();
		PrintWriter writer = new PrintWriter(stringWriter);
		writer.append(m);
		writer.append('\n');

		StackTraceElement[] trace = t.getStackTrace();
		trace = filterTrace(trace);
		printTrace(trace, writer);

		addAllCauseExceptions(writer);

		if (testThreadTrace != null) {
			writer.append("\nTest thread stack at that time:\n");
			printTrace(testThreadTrace, writer);
		}

		String output = stringWriter.toString();
		return output;
	}

	private void addAllCauseExceptions(PrintWriter writer) {
		addCauseException(t, writer);
	}

	private void addCauseException(Throwable currentThrowable, PrintWriter writer) {
		Throwable theCause = currentThrowable.getCause();
		if (theCause == null) {
			return;
		}

		String defaultMessage = theCause.getClass().getSimpleName();
		String message = theCause.getMessage();
		message = message == null ? defaultMessage : message;
		writer.append("\nCaused By:\n");
		writer.append('\t').append(message).append('\n');

		StackTraceElement[] causeByTrace = theCause.getStackTrace();
		causeByTrace = filterTrace(causeByTrace);
		printTrace(causeByTrace, writer);

		addCauseException(theCause, writer);
	}

	private String generateMessge() {

		String message = t.getMessage();
		message = message != null ? message : "";
		String messageWithName =
			t.getClass().getSimpleName() + ": " + message + " (thread '" + threadName + "')";

		if (userMessage != null) {
			messageWithName = userMessage + "\n\n" + messageWithName;
		}

		return messageWithName;
	}

	private StackTraceElement[] filterTrace(StackTraceElement[] trace) {
		if (threadName.contains("AWT-EventQueue")) {

			StackTraceElement[] filtered =
				ReflectionUtilities.filterStackTrace(trace, SWING_STACK_ELEMENT_PATTERNS);
			return filtered;
		}
		StackTraceElement[] filtered =
			ReflectionUtilities.filterStackTrace(trace, GENERAL_USELESS_STACK_ELEMET_PATTERNS);
		return filtered;
	}

	private static void printTrace(StackTraceElement[] trace, PrintWriter writer) {
		for (StackTraceElement element : trace) {
			writer.append("\tat ").append(element.toString()).append('\n');
		}
	}

}
