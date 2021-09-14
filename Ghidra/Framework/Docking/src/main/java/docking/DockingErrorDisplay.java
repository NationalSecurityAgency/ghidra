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
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.WordUtils;

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.util.*;
import ghidra.util.exception.MultipleCauses;
import ghidra.util.html.HtmlLineSplitter;

public class DockingErrorDisplay implements ErrorDisplay {

	/**
	 * Error dialog used to append exceptions.
	 *
	 * <p>While this dialog is showing all new exceptions will be added to the dialog.  When
	 * this dialog is closed, this reference will be cleared.
	 *
	 * <p>Note: all use of this variable <b>must be on the Swing thread</b> to avoid thread
	 * visibility issues.
	 */
	private static AbstractErrDialog activeDialog;

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

	private static String wrap(String text) {

		StringBuilder buffy = new StringBuilder();

		// Wrap any poorly formatted text that gets displayed in the label; 80-100 chars is
		// a reasonable line length based on historical print margins.
		// Update: increased the limit to handle long messages containing stack trace elements, 
		//         which look odd when wrapped
		int limit = 120;
		List<String> lines = HtmlLineSplitter.split(text, limit, true);
		String newline = "\n";
		for (String line : lines) {

			if (buffy.length() != 0) {
				buffy.append(newline);
			}

			if (StringUtils.isBlank(line)) {
				// this will trim all leading blank lines, but preserve internal blank lines, 
				// which clients may be providing for visual line separation
				continue;
			}

			String wrapped = line;
			if (line.length() > limit) {
				// this method will trim leading spaces; only call if the line is too long
				wrapped = WordUtils.wrap(line, limit, null, true);
			}

			buffy.append(wrapped);
		}
		return buffy.toString();
	}

	private void displayMessage(MessageType messageType, ErrorLogger errorLogger, Object originator,
			Component parent, String title, Object message, Throwable throwable) {

		int dialogType = OptionDialog.PLAIN_MESSAGE;

		String messageString = message != null ? message.toString() : null;
		if (messageString != null) {
			// prevent excessive message degenerate cases
			int maxChars = 1000;
			String safeMessage = StringUtilities.trimMiddle(messageString, maxChars);

			// wrap any poorly formatted text that gets displayed in the label; 80-100 chars is
			// a reasonable line length based on historical print margins
			messageString = wrap(safeMessage);
		}

		String unformattedMessage = HTMLUtilities.fromHTML(messageString);
		switch (messageType) {
			case INFO:
				dialogType = OptionDialog.INFORMATION_MESSAGE;
				consoleDisplay.displayInfoMessage(errorLogger, originator, parent, title,
					unformattedMessage);
				break;
			case WARNING:
			case ALERT:
				dialogType = OptionDialog.WARNING_MESSAGE;
				consoleDisplay.displayWarningMessage(errorLogger, originator, parent, title,
					unformattedMessage, throwable);
				break;
			case ERROR:
				consoleDisplay.displayErrorMessage(errorLogger, originator, parent, title,
					unformattedMessage, throwable);
				dialogType = OptionDialog.ERROR_MESSAGE;
				break;
		}

		showDialog(title, throwable, dialogType, messageString, getWindow(parent));
	}

	private Component getWindow(Component component) {
		while (component != null && !(component instanceof Window)) {
			component = component.getParent();
		}
		return component;
	}

	private void showDialog(final String title, final Throwable throwable, final int dialogType,
			final String messageString, final Component parent) {

		Swing.runIfSwingOrRunLater(() -> {

			if (dialogType == OptionDialog.ERROR_MESSAGE) {
				showDialogOnSwing(title, throwable, dialogType, messageString, parent);
			}
			else {
				DockingWindowManager.showDialog(parent,
					new OkDialog(title, messageString, dialogType));
			}
		});
	}

	private void showDialogOnSwing(String title, Throwable throwable, int dialogType,
			String messageString, Component parent) {

		if (activeDialog != null) {
			activeDialog.addException(messageString, throwable);
			return;
		}

		activeDialog = createErrorDialog(title, throwable, messageString);
		activeDialog.setClosedCallback(() -> {
			activeDialog.setClosedCallback(null);
			activeDialog = null;
		});
		DockingWindowManager.showDialog(parent, activeDialog);
	}

	private AbstractErrDialog createErrorDialog(String title, Throwable throwable,
			String messageString) {

		if (containsMultipleCauses(throwable)) {
			return new ErrLogExpandableDialog(title, messageString, throwable);
		}

		return ErrLogDialog.createExceptionDialog(title, messageString, throwable);
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
}
