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

		if (t instanceof ThreadDeath) {
			return;
		}

		if (t instanceof ConnectException) {
			return;
		}

		if (t instanceof ClosedException) {
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

	@Override
	public void uncaughtException(Thread t, Throwable e) {
		handleUncaughtException(e);
	}
}
