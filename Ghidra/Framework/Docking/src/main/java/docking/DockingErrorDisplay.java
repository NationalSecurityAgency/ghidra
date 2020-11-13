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

import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.util.*;
import ghidra.util.exception.MultipleCauses;

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

		showDialog(title, throwable, dialogType, messageString, getWindow(parent));
	}

	private Component getWindow(Component component) {
		while (component != null && !(component instanceof Window)) {
			component = component.getParent();
		}
		return component;
	}

	private void showDialog(final String title, final Throwable throwable,
			final int dialogType, final String messageString, final Component parent) {

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

	private void showDialogOnSwing(String title, Throwable throwable,
			int dialogType, String messageString, Component parent) {

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
