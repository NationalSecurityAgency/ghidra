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
package ghidra;

import java.lang.Thread.UncaughtExceptionHandler;
import java.lang.reflect.InvocationTargetException;
import java.rmi.ConnectException;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.ClosedException;
import utilities.util.reflection.ReflectionUtilities;

/**
 * Class to handle exceptions caught within the Swing event dispatch thread.
 */
public class SwingExceptionHandler implements UncaughtExceptionHandler {

	/**
	 * Handle exception caught within the Swing event dispatch thread.
	 * @param t exception
	 * @throws Throwable error occurred while attempting to handle exception
	 */
	public void handle(Throwable t) throws Throwable {
		handleUncaughtException(t);
	}

	/**
	 * Register SwingExceptionHandler
	 */
	public static void registerHandler() {
		SystemUtilities.runSwingLater(() -> {
			// do this on the Swing thread
			Thread.setDefaultUncaughtExceptionHandler(new SwingExceptionHandler());
		});
	}

	public static void handleUncaughtException(Throwable t) {
		if (t instanceof InvocationTargetException) {
			t = t.getCause();
		}

		if (shouldIgnore(t)) {
			return;
		}

		String details = "";
		if (t instanceof OutOfMemoryError) {
			Runtime rt = Runtime.getRuntime();
			details = "\nMemory: free=" + rt.freeMemory() + " max=" + rt.maxMemory() + " total=" +
				rt.totalMemory();
		}
		else {
			String message = t.getMessage();
			if (message != null) {
				details = "\n" + t.getClass().getSimpleName() + " - " + message;
			}
		}

		Msg.showError(SwingExceptionHandler.class, null, "Error", "Uncaught Exception! " + details,
			t);
	}

	private static boolean shouldIgnore(Throwable t) {

		if (t instanceof ThreadDeath) {
			return true;
		}

		if (t instanceof ConnectException) {
			return true;
		}

		if (t instanceof ClosedException) {
			return true;
		}

		if (isKnownJavaHelpException(t)) {
			return true;
		}

		return false;
	}

	private static boolean isKnownJavaHelpException(Throwable t) {

		String stackString = ReflectionUtilities.stackTraceToString(t);
		if (stackString.contains("com.sun.java.help.impl.JHelpPrintHandler$JHFrame.validate")) {
			// This happens in the Java Help API when trying to print.  We do not have license to 
			// change that code, so squash the exception here.   Printing still seems to work as 
			// expected.
			return true;
		}

		// 
		// There is an exception(s) that happens if the user has shown the Help Window and then 
		// switches themes.  This exception is harder to test for, since it has not stack elements
		// specific to the help API.  Below are some (hopefully) help-specific stack elements that 
		// we can use to filter out this exception(s).
		// 
		if (stackString.contains("javax.help.plaf.basic.BasicTOCNavigatorUI")) {
			return true;
		}

		if (stackString.contains("javax.swing.text.html.BlockView") &&
			stackString.contains("javax.swing.text.html.HTMLDocument.fireChangedUpdate")) {
			// Log a message since this type of exception may happen outside of the help system.  It
			// may help developers to see this in the console.
			Msg.debug(SwingExceptionHandler.class, "Squashed an assumed help exception");
			return true;
		}

		return false;
	}

	@Override
	public void uncaughtException(Thread t, Throwable e) {
		handleUncaughtException(e);
	}
}
