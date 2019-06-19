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
package docking.widgets;

import javax.swing.Icon;

import ghidra.util.Swing;

/**
 * A dialog with an OK button.  The client can specify the message type in the constructor.
 */
public class OkDialog extends OptionDialog {

	/**
	 * Show a {@link OptionDialog#PLAIN_MESSAGE plain} {@link OkDialog} with the given title and message
	 * @param title the title
	 * @param message the message
	 */
	public static void show(String title, String message) {
		Swing.runNow(() -> {
			new OkDialog(title, message, OptionDialog.PLAIN_MESSAGE).show();
		});
	}

	/**
	 * Show a {@link OptionDialog#INFORMATION_MESSAGE plain} {@link OkDialog} with the given 
	 * title and message
	 * 
	 * @param title the title
	 * @param message the message
	 */
	public static void showInfo(String title, String message) {
		Swing.runNow(() -> {
			new OkDialog(title, message, OptionDialog.INFORMATION_MESSAGE).show();
		});
	}

	/**
	 * Show a {@link OptionDialog#ERROR_MESSAGE plain} {@link OkDialog} with the given 
	 * title and message
	 * 
	 * @param title the title
	 * @param message the message
	 */
	public static void showError(String title, String message) {
		Swing.runNow(() -> {
			new OkDialog(title, message, OptionDialog.ERROR_MESSAGE).show();
		});
	}

	/**
	 * Construct a simple informational dialog with a single OK button
	 *
	 * @param title The String to be placed in the dialogs title area
	 * @param message The information message to be displayed in the dialog
	 * @param messageType used to specify a default icon
	 *              <ul>
	 *                  <li>ERROR_MESSAGE</li>
	 *                  <li>INFORMATION_MESSAGE</li>
	 *                  <li>WARNING_MESSAGE</li>
	 *                  <li>QUESTION_MESSAGE</li>
	 *                  <li>PLAIN_MESSAGE</li>
	 *              </ul>
	 */
	public OkDialog(String title, String message, int messageType) {
		super(title, message, messageType, null);
	}

	/**
	 * Construct a simple informational dialog with a single OK button
	 *
	 * @param title The String to be placed in the dialogs title area
	 * @param message The information message to be displayed in the dialog
	 * @param icon allows the user to specify the icon to be used
	 *              If non-null, this will override the messageType
	 */
	public OkDialog(String title, String message, Icon icon) {
		super(title, message, PLAIN_MESSAGE, icon);
	}
}
