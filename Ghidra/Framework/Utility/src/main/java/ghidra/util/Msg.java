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

import java.awt.Component;

/**
 * Class with static methods to report errors as either a short message or a
 * more detailed message (e.g., stacktrace).
 * 
 * <P>The 'message' parameter for these calls is typically a String.  However, it can also 
 * be a log4j <code>Message</code> object as well.   (See log4j2 for details.) 
 */
public class Msg {
	private static ErrorLogger errorLogger = new DefaultErrorLogger();
	private static ErrorDisplay errorDisplay = new ConsoleErrorDisplay();

	private Msg() {
		// static utility class
	}

	/**
	 * Sets the error logger (by default it's a DefaultErrorLogger).
	 * 
	 * @param errLogger
	 *            the error logger
	 */
	public static void setErrorLogger(ErrorLogger errLogger) {
		errorLogger = errLogger;
	}

	/**
	 * Sets the error display (by default it's console)
	 * 
	 * @param errDisplay
	 *            the error display
	 */
	public static void setErrorDisplay(ErrorDisplay errDisplay) {
		errorDisplay = errDisplay;
	}

	/**
	 * Useful for printing temporary messages without any logging markup.  This is meant to be
	 * a replacement for System.out. 
	 * 
	 * @param message 
	 * 			the message to print
	 */
	public static void out(Object message) {
		System.err.println(message);
	}

	/**
	 * Used to record a trace message to the log file. All calls to this method
	 * outside of main methods and JUnit tests will be removed before a
	 * production release.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 */
	public static void trace(Object originator, Object message) {
		errorLogger.trace(originator, message);
	}

	/**
	 * Used to record a trace message to the log file. All calls to this method
	 * outside of main methods and JUnit tests will be removed before a
	 * production release. This may be used to document an exception
	 * without elevating that exception to error or warning status.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void trace(Object originator, Object message, Throwable throwable) {
		errorLogger.trace(originator, message, throwable);
	}

	/**
	 * Used to record a debug message to the log file.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 */
	public static void debug(Object originator, Object message) {
		errorLogger.debug(originator, message);
	}

	/**
	 * Used to record a debug message to the log file.  This may be used to document an exception
	 * without elevating that exception to error or warning status
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void debug(Object originator, Object message, Throwable throwable) {
		errorLogger.debug(originator, message, throwable);
	}

	/**
	 * Used to display an informational message to the user via the console (no
	 * GUI). Also records the message to the logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 */
	public static void info(Object originator, Object message) {
		errorLogger.info(originator, message);
	}

	/**
	 * Used to display an informational message to the user via the console (no
	 * GUI). Also records the message to the logging system.  This may be used to 
	 * document an exception without elevating that exception to error or warning status.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void info(Object originator, Object message, Throwable throwable) {
		errorLogger.info(originator, message, throwable);
	}

	/**
	 * Used to display an informational message to the user
	 * with a pop-up GUI dialog. Also records the message to the logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param parent
	 *            a parent component used to center the dialog (or null if you
	 *            don't have one)
	 * @param title
	 *            the title of the pop-up dialog (main subject of message)
	 * @param message
	 *            the details of the message
	 */
	public static void showInfo(Object originator, Component parent, String title, Object message) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.info(originator, message);
		}
		else {
			errorDisplay.displayInfoMessage(errorLogger, originator, parent, title, message);
		}
	}

	/**
	 * Used to display a warning message to the user via the console (no GUI).
	 * Also records the message to the logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 */
	public static void warn(Object originator, Object message) {
		errorLogger.warn(originator, message);
	}

	/**
	 * Used to display a warning message to the user via the console (no GUI).
	 * Also records the message to the logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            a Throwable for printing a stack trace
	 */
	public static void warn(Object originator, Object message, Throwable throwable) {
		errorLogger.warn(originator, message, throwable);
	}

	/**
	 * Used to display a warning message to the user with a pop-up GUI dialog.
	 * Also records the message to the logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param parent
	 *            a parent component used to center the dialog (or null if you
	 *            don't have one)
	 * @param title
	 *            the title of the pop-up dialog (main subject of message)
	 * @param message
	 *            the details of the message
	 */
	public static void showWarn(Object originator, Component parent, String title, Object message) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.warn(originator, message);
		}
		else {
			errorDisplay.displayWarningMessage(errorLogger, originator, parent, title, message,
				null);
		}
	}

	/**
	 * Used to display an error message with no available Throwable to the user
	 * via the console (no GUI). Also records the message to the logging system.
	 * If you have a Throwable, please use the other error(...) method.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 */
	public static void error(Object originator, Object message) {
		errorLogger.error(originator, message);
	}

	/**
	 * Used to display an error message with a Throwable (for stack trace) to
	 * the user via the console (no GUI). Also records the message to the
	 * logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void error(Object originator, Object message, Throwable throwable) {
		errorLogger.error(originator, message, throwable);
	}

	/**
	 * Used to display an error message with no available Throwable to the user
	 * with a pop-up GUI dialog. Also records the message to the logging system.
	 * If you have a Throwable, please use the other error(...) method.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param parent
	 *            a parent component used to center the dialog (or null if you
	 *            don't have one)
	 * @param title
	 *            the title of the pop-up dialog (main subject of message)
	 * @param message
	 *            the details of the message
	 */
	public static void showError(Object originator, Component parent, String title,
			Object message) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(originator, message);
		}
		else {
			errorDisplay.displayErrorMessage(errorLogger, originator, parent, title, message, null);
		}
	}

	/**
	 * Used to display an error message with a Throwable (for stack trace) to
	 * the user with a pop-up GUI dialog. Also records the message to the
	 * logging system.
	 * 
	 * @param originator
	 *            a Logger instance, "this", or YourClass.class
	 * @param parent
	 *            a parent component used to center the dialog (or null if you
	 *            don't have one)
	 * @param title
	 *            the title of the pop-up dialog (main subject of message)
	 * @param message
	 *            the details of the message
	 * @param throwable
	 *            the Throwable that describes the cause of the error
	 */
	public static void showError(Object originator, Component parent, String title, Object message,
			Throwable throwable) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.error(originator, message, throwable);
		}
		else {
			errorDisplay.displayErrorMessage(errorLogger, originator, parent, title, message,
				throwable);
		}
	}

}
