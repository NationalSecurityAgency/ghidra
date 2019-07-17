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

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * A class to take an exception and capture test system state for later reporting.
 */
public class TestExceptionTracker {

	private String threadName;
	private Throwable t;
	private StackTraceElement[] testThreadTrace;

	public TestExceptionTracker(String threadName, Throwable t) {
		this.threadName = threadName;
		this.t = t;
		this.testThreadTrace = recordTestThreadState();
	}

	private StackTraceElement[] recordTestThreadState() {

		Map<Thread, StackTraceElement[]> allStackTraces = Thread.getAllStackTraces();
		Set<Entry<Thread, StackTraceElement[]>> entrySet = allStackTraces.entrySet();
		for (Entry<Thread, StackTraceElement[]> entry : entrySet) {

			Thread thread = entry.getKey();
			if (TestThread.isTestThread(thread)) {

				// grab the state of the test thread, but chop out some uninteresting calls
				StackTraceElement[] fullTrace = entry.getValue();
				StackTraceElement[] filtered = TestThread.filterTrace(fullTrace);
				return filtered;
			}
		}

		return new StackTraceElement[0];
	}

	public Throwable getException() {
		return t;
	}

	public Throwable getCombinedException() {

		TestReportingException exception =
			new TestReportingException(threadName, t, testThreadTrace);
		return exception;
	}

	public void printStackTrace() {
		Throwable throwable = getCombinedException();
		throwable.printStackTrace();
	}

	public StackTraceElement[] getStackTrace() {
		return testThreadTrace;
	}

	public String getExceptionMessage() {
		String message = t.getMessage();
		if (message != null) {
			return message;
		}
		return t.getClass().getSimpleName();
	}

	public String getThreadName() {
		return threadName;
	}
}
