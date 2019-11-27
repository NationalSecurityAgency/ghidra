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
package docking;

import java.awt.Component;
import java.awt.Window;
import java.io.*;

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.util.*;
import ghidra.util.exception.MultipleCauses;

public class DockingErrorDisplay implements ErrorDisplay {

	private static final int TRACE_BUFFER_SIZE = 250;

	ConsoleErrorDisplay consoleDisplay = new ConsoleErrorDisplay();

	@Override
	public void displayInfoMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message) {
		displayMessage(MessageType.INFO, errorLogger, originator, parent, title, message, null);
	}

	@Override
	public void displayErrorMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {
		displayMessage(MessageType.ERROR, errorLogger, originator, parent, title, message,
			throwable);
	}

	@Override
	public void displayWarningMessage(ErrorLogger errorLogger, Object originator, Component parent,
			String title, Object message, Throwable throwable) {
		displayMessage(MessageType.WARNING, errorLogger, originator, parent, title, message,
			throwable);
	}

	private void displayMessage(MessageType messageType, ErrorLogger errorLogger, Object originator,
			Component parent, String title, Object message, Throwable throwable) {
		int dialogType = OptionDialog.PLAIN_MESSAGE;

		String messageString = message != null ? message.toString() : null;
		String rawMessage = HTMLUtilities.fromHTML(messageString);
		switch (messageType) {
			case INFO:
				dialogType = OptionDialog.INFORMATION_MESSAGE;
				consoleDisplay.displayInfoMessage(errorLogger, originator, parent, title,
					rawMessage);
				break;
			case WARNING:
			case ALERT:
				dialogType = OptionDialog.WARNING_MESSAGE;
				consoleDisplay.displayWarningMessage(errorLogger, originator, parent, title,
					rawMessage, throwable);
				break;
			case ERROR:
				consoleDisplay.displayErrorMessage(errorLogger, originator, parent, title,
					rawMessage, throwable);
				dialogType = OptionDialog.ERROR_MESSAGE;
				break;
		}

		showDialog(title, message, throwable, dialogType, messageString, getWindow(parent));
	}

	private Component getWindow(Component component) {
		while (component != null && !(component instanceof Window)) {
			component = component.getParent();
		}
		return component;
	}

	private void showDialog(final String title, final Object message, final Throwable throwable,
			final int dialogType, final String messageString, final Component parent) {
		SystemUtilities.runIfSwingOrPostSwingLater(
			() -> doShowDialog(title, message, throwable, dialogType, messageString, parent));
	}

	private void doShowDialog(final String title, final Object message, final Throwable throwable,
			int dialogType, String messageString, Component parent) {
		DialogComponentProvider dialog = null;
		if (throwable != null) {
			dialog = createErrorDialog(title, message, throwable, messageString);
		}
		else {
			dialog = new OkDialog(title, messageString, dialogType);
		}
		DockingWindowManager.showDialog(parent, dialog);
	}

	private DialogComponentProvider createErrorDialog(final String title, final Object message,
			final Throwable throwable, String messageString) {

		if (containsMultipleCauses(throwable)) {
			return new ErrLogExpandableDialog(title, messageString, throwable);
		}

		return ErrLogDialog.createExceptionDialog(title, messageString,
			buildStackTrace(throwable, message == null ? throwable.getMessage() : messageString));
	}

	private boolean containsMultipleCauses(Throwable throwable) {
		if (throwable == null) {
			return false;
		}

		if (throwable instanceof MultipleCauses) {
			return true;
		}

		return containsMultipleCauses(throwable.getCause());
	}

	/**
	 * Build a displayable stack trace from a Throwable 
	 * 
	 * @param t the throwable
	 * @param msg message prefix
	 * @return multi-line stack trace
	 */
	private String buildStackTrace(Throwable t, String msg) {
		StringBuffer sb = new StringBuffer(TRACE_BUFFER_SIZE);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream ps = new PrintStream(baos);

		if (msg != null) {
			ps.println(msg);
		}

		t.printStackTrace(ps);
		sb.append(baos.toString());
		ps.close();
		try {
			baos.close();
		}
		catch (IOException e) {
			// shouldn't happen--not really connected to the system
		}

		return sb.toString();
	}
}
