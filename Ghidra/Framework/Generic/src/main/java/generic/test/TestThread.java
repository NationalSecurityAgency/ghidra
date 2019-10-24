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

import org.junit.runners.model.Statement;

import utilities.util.reflection.ReflectionUtilities;

public class TestThread extends Thread {

	private static final String SUN_PACKAGE = "sun.";
	private static final String JAVA_LANG_PACKAGE = "java.lang";
	private static final String JAVA_AWT_EVENT_PACKAGE = "java.awt.EventQueue";
	private static final String JUNIT_FRAMEWORK_PACKAGE = "junit.framework";
	private static final String JUNIT_ORG_PACKAGE = "org.junit";
	private static final String MOCKIT_JUNIT_PACKAGE = "mockit.integration.junit";

	private static final String GHIDRA_SWING_RUNNER = "ExceptionHandlingRunner";

	public static final String NAME_PREFIX = "Test-";

//==================================================================================================
// Static Methods
//==================================================================================================	

	/**
	 * Returns true if the current thread is the test thread
	 * 
	 * @return true if the current thread is the test thread
	 */
	public static boolean isTestThread() {
		return isTestThread(Thread.currentThread());
	}

	/**
	 * Returns true if the given thread is the test thread
	 * 
	 * @param t the thread to check
	 * @return true if the given thread is the test thread
	 */
	public static boolean isTestThread(Thread t) {
		return t.getName().startsWith(NAME_PREFIX);
	}

	/**
	 * Returns true if the given thread name is the test thread name
	 * 
	 * @param name the thread name to check
	 * @return true if the given thread name is the test thread name
	 */
	public static boolean isTestThreadName(String name) {
		return name.startsWith(NAME_PREFIX);
	}

	/**
	 * Filters the given stack trace to remove entries known to be present in the test 
	 * thread that offer little forensic value
	 * 
	 * @param trace the trace to filter
	 * @return the filtered trace
	 */
	public static StackTraceElement[] filterTrace(StackTraceElement[] trace) {
		//@formatter:off
		StackTraceElement[] filtered =
				ReflectionUtilities.filterStackTrace(trace, JUNIT_ORG_PACKAGE, 
															JUNIT_FRAMEWORK_PACKAGE,
															MOCKIT_JUNIT_PACKAGE,
															JAVA_AWT_EVENT_PACKAGE, 
															JAVA_LANG_PACKAGE, 
															SUN_PACKAGE, 
															GHIDRA_SWING_RUNNER);
		//@formatter:on
		return filtered;
	}

//==================================================================================================
// Instance Methods
//==================================================================================================	

	/*package*/ final Statement statement;
	/*package*/ volatile boolean finished = false;
	/*package*/ volatile Throwable exceptionFromTest = null;

	TestThread(Statement statement) {
		this.statement = statement;
		String defaultName = getName();
		setName(NAME_PREFIX + defaultName);
	}

	@Override
	public void run() {
		try {
			statement.evaluate();
		}
		catch (InterruptedException e) {
			// No need to log this, as we may have triggered it
		}
		catch (Throwable e) {
			exceptionFromTest = e;
		}
		finally {
			finished = true;
		}
	}
}
