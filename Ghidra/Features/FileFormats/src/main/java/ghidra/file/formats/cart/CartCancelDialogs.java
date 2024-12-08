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
package ghidra.file.formats.cart;

import docking.widgets.OptionDialog;
import ghidra.util.*;

/**
 * Helper class to show Continue or Cancel dialogs at various severity levels
 */
public class CartCancelDialogs {
	/**
	 * Character width to which messages will be wrapped
	 */
	public static final int WRAP_WIDTH_CHARACTERS = 80;

	/**
	 * Wrap a String message to a default (80 characters) width and add front and back HTML
	 * tags. Caller is responsible for neutering any internal unsafe HTML tags in their
	 * message.
	 *
	 * @param message String message to display
	 * @return HTML length-wrapped version of message.
	 */
	private static final String wrapHtml(String message) {
		String wrapped = StringUtilities.wrapToWidth(message, WRAP_WIDTH_CHARACTERS);
		return "<html>" + wrapped.replace("\n", "<br>") + "</html>";
	}

	/**
	 * Prompt the user with a given title and message with a specified message type for them
	 * to "Continue" the operation or cancel. Message may contain HTML and should be
	 * sanitized for safety by the caller. Returns true if the user wants to continue the
	 * operation.
	 *
	 * <B>Note:</B> If in headless mode log the message at the appropriate level and then
	 * treat as if the user chose to <B>cancel</B> the operation. Also, log a message stating
	 * this decision was made.
	 *
	 * @param title          The title of the dialog window
	 * @param message        Message prompt to display to user
	 * @param messageType    The type of message see {@link OptionDialog}
	 * @return               True if the user chooses to continue, False otherwise.
	 */
	public static final boolean promptContinue(String title, String message, int messageType) {
		if (SystemUtilities.isInHeadlessMode()) {
			message = title + " : " + message;

			switch (messageType) {
				case OptionDialog.WARNING_MESSAGE:
					Msg.warn(CartCancelDialogs.class, message);
					break;
				case OptionDialog.ERROR_MESSAGE:
					Msg.error(CartCancelDialogs.class, message);
					break;
				default:
					Msg.info(CartCancelDialogs.class, message);
					break;
			}

			Msg.info(CartCancelDialogs.class,
				"User can't respond to message, treating as cancellation.");
			return false;
		}
		return OptionDialog.showOptionDialogWithCancelAsDefaultButton(null, title,
			wrapHtml(message), "Continue", messageType) == OptionDialog.OPTION_ONE;
	}

	/**
	 * Helper to prompt for Continue or Cancel at the warning level. Returns true if the user
	 * wants to continue the operation.
	 *
	 * @param title          The title of the dialog window
	 * @param message        Message prompt to display to user
	 * @return               True if the user chooses to continue, False otherwise.
	 */
	public static final boolean promptWarningContinue(String title, String message) {
		return promptContinue(title, message, OptionDialog.WARNING_MESSAGE);
	}

	/**
	 * Helper to prompt for Continue or Cancel at the error level. Returns true if the user
	 * wants to continue the operation.
	 *
	 * @param title          The title of the dialog window
	 * @param message        Message prompt to display to user
	 * @return               True if the user chooses to continue, False otherwise.
	 */
	public static final boolean promptErrorContinue(String title, String message) {
		return promptContinue(title, message, OptionDialog.ERROR_MESSAGE);
	}
}
