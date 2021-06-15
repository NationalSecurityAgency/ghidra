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

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.dialogs.*;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GIconLabel;
import ghidra.util.*;
import ghidra.util.exception.AssertException;

/**
 * A utility class to easily show dialogs that require input from the user.
 *
 *
 * <h2>Option Dialogs</h2><br>
 * <blockquote>
 * <p>
 * The primary type of
 * dialog provided herein is the basic option dialog that allows the user to specify the buttons
 * that appear on the dialog.  By default, the given option text will appear as a button(s),
 * followed by a <code>Cancel</code> button (you can call the
 * {@link #showOptionNoCancelDialog(Component, String, String, String, String, int)} methods if
 * you do not want a <code>Cancel</code> button.  To use this type of dialog you can use the
 * various <b><code>showOptionDialog*</code></b> methods.
 * </p>
 * <p>
 * Each of the option dialog methods will return a result, which is a number indicating the
 * choice made by the user.  See each method for more details.
 * </p>
 * </blockquote>
 *
 *
 * <h3>Data Input and Choice Dialogs</h3><br>
 * <blockquote>
 * 		<p>
 * 		The methods listed here allow the user to either enter data from the keyboard or to choose
 * 		from a pre-populated list of data.
 * 		</p>
 * 		<blockquote>
 * 		{@link #showInputChoiceDialog(Component, String, String, String[], String, int)}<br>
 * 		{@link #showInputMultilineDialog(Component, String, String, String)}<br>
 * 		{@link #showInputSingleLineDialog(Component, String, String, String)}
 * 	</blockquote>
 * </blockquote>
 *
 *
 * <h3>Yes/No Dialogs</h3><br>
 * <blockquote>
 * <p>
 * Finally, there are a series of methods that present <code>Yes</code> and <code>No</code> buttons in
 * a dialog.  There are versions that do and do not have a <code>Cancel</code> button.
 * </p>
 * </blockquote>
 *
 *
 * <h3>Basic Message / Warning / Error Dialogs</h3><br>
 * <blockquote>
 * <p>
 * If you would like to display a simple message to the user, but do not require input from the
 * user, then you should use the various methods of {@link Msg}, such as
 * {@link Msg#showInfo(Object, Component, String, Object)}.
 * </p>
 * <p>
 * Note, the user will be unable to select any text shown in the message area of the dialog.
 * </p>
 * </blockquote>
 * 
 * <h3>"Apply to All" / "Don't Show Again"</h3><br>
 * <blockquote>
 * <p>For more advanced input dialog usage, to include allowing the user to tell the dialog
 * to remember a particular decision, or to apply a given choice to all future request, see
 * {@link OptionDialogBuilder}.
 * </blockquote>
 *
 * @see Msg
 * @see OptionDialogBuilder
 */
public class OptionDialog extends DialogComponentProvider {
	public static final String MESSAGE_COMPONENT_NAME = "MESSAGE-COMPONENT";
	/** Used for error messages. */
	public static final int ERROR_MESSAGE = 0;
	/** Used for information messages. */
	public static final int INFORMATION_MESSAGE = 1;
	/** Used for warning messages. */
	public static final int WARNING_MESSAGE = 2;
	/** Used for questions. */
	public static final int QUESTION_MESSAGE = 3;
	/** No icon is used. */
	public static final int PLAIN_MESSAGE = -1;

	/**
	 * Identifier for the cancel option.
	 */
	public static final int CANCEL_OPTION = 0;
	public static final int YES_OPTION = 1;
	public static final int NO_OPTION = 2;

	/**
	 * Identifier for option one.
	 */
	public static final int OPTION_ONE = 1;

	/**
	 * Identifier for option two.
	 */
	public static final int OPTION_TWO = 2;

	/**
	 * Identifier for option three.
	 */
	public static final int OPTION_THREE = 3;

	private int result = CANCEL_OPTION;
	private DialogRememberOption rememberOption;
	private JCheckBox rememberOptionCheckBox;

	private String dialogMessage;

	/**
	 * Construct a simple informational dialog with a single OK button.
	 *
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param messageType used to specify a default icon
	 *              <ul>
	 *                  <li>ERROR_MESSAGE</li>
	 *                  <li>INFORMATION_MESSAGE</li>
	 *                  <li>WARNING_MESSAGE</li>
	 *                  <li>QUESTION_MESSAGE</li>
	 *                  <li>PLAIN_MESSAGE</li>
	 *              </ul>
	 * @param icon allows the user to specify the icon to be used.
	 *              If non-null, this will override the messageType.
	 */
	protected OptionDialog(String title, String message, int messageType, Icon icon) {
		this(title, message, null, null, messageType, icon, false, null);
	}

	/**
	 * Construct a simple two-option dialog.
	 * @param title the String to place in the dialog's title area.
	 * @param message the message string explaining the user's option.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @param addCancel true means add a Cancel button
	 */
	protected OptionDialog(String title, String message, String option1, String option2,
			int messageType, Icon icon, boolean addCancel) {
		super(title, true, false, true, false);
		setTransient(true);
		buildMainPanel(message, messageType, icon, null);
		buildButtons(toList(option1, option2), addCancel, null);
	}

	/**
	 * Construct a simple two-option dialog.
	 * @param title the String to place in the dialog's title area.
	 * @param message the message string explaining the user's option.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @param addCancel true means add a Cancel button
	 * @param defaultButtonName The default button name	
	 */
	protected OptionDialog(String title, String message, String option1, String option2,
			int messageType, Icon icon, boolean addCancel, String defaultButtonName) {
		super(title, true, false, true, false);
		setTransient(true);
		buildMainPanel(message, messageType, icon, null);
		buildButtons(toList(option1, option2), addCancel, defaultButtonName);
	}

	/**
	 * Construct a simple one-option dialog with a Cancel button.
	 * @param title the String to place in the dialog's title area.
	 * @param message the message string explaining the user's option.
	 * @param option1 The text to place on the first option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 */
	protected OptionDialog(String title, String message, String option1, int messageType,
			Icon icon) {
		this(title, message, option1, null, messageType, icon, true, null);
	}

	/**
	 * Construct a simple one-option dialog with a Cancel button.
	 * @param title the String to place in the dialog's title area.
	 * @param message the message string explaining the user's option.
	 * @param option1 The text to place on the first option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @param defaultButtonName the name of the button to be made the default.
	 */
	protected OptionDialog(String title, String message, String option1, int messageType, Icon icon,
			String defaultButtonName) {
		this(title, message, option1, null, messageType, icon, true, defaultButtonName);
	}

	/* Special 3 button constructor */
	protected OptionDialog(String title, String message, String option1, String option2,
			String option3, int messageType, Icon icon, boolean addCancel) {
		super(title, true, false, true, false);
		setTransient(true);
		buildMainPanel(message, messageType, icon, null);
		buildButtons(toList(option1, option2, option3), addCancel, null);
	}

	OptionDialog(String title, String message, int messageType, Icon icon, boolean addCancelButton,
			DialogRememberOption savedDialogChoice, List<String> options, String defaultOption) {
		super(title, true, false, true, false);
		setTransient(true);
		buildMainPanel(message, messageType, icon, savedDialogChoice);
		buildButtons(options, addCancelButton, defaultOption);
	}

	private static List<String> toList(String... option) {
		List<String> options = new ArrayList<>();
		for (String string : option) {
			if (string != null) {
				options.add(string);
			}
		}
		return options;
	}

	private void buildMainPanel(String message, int messageType, Icon icon,
			DialogRememberOption rememberOptionChoice) {

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JPanel messagePanel = buildMessagePanel(message, messageType, icon);
		panel.add(messagePanel, BorderLayout.CENTER);

		JPanel savedDialogChoicePanel = buildRememberOptionChoicePanel(rememberOptionChoice);
		if (savedDialogChoicePanel != null) {
			panel.add(savedDialogChoicePanel, BorderLayout.SOUTH);
		}

		addWorkPanel(panel);
		setRememberLocation(false);
		setRememberSize(false);
	}

	private JPanel buildRememberOptionChoicePanel(DialogRememberOption rememberOptionChoice) {
		if (rememberOptionChoice == null) {
			this.rememberOption = new DoNothingDialogRememberOption();
			rememberOptionCheckBox = new GCheckBox(); // to prevent null checks, create dummy checkbox
			return null;
		}
		this.rememberOption = rememberOptionChoice;
		rememberOptionCheckBox = new GCheckBox(rememberOptionChoice.getDescription());

		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		panel.add(rememberOptionCheckBox, BorderLayout.SOUTH);
		return panel;
	}

	private JPanel buildMessagePanel(String message, int messageType, Icon icon) {
		JPanel panel = new JPanel(new BorderLayout());
		JPanel textPanel = createTextPanel(message);
		textPanel.setMaximumSize(textPanel.getPreferredSize());
		panel.add(new GIconLabel((icon == null) ? getIconForMessageType(messageType) : icon),
			BorderLayout.WEST);
		panel.add(textPanel, BorderLayout.CENTER);
		return panel;
	}

	private void buildButtons(List<String> options, boolean addCancel, String defaultButtonName) {
		List<JButton> buttons = new ArrayList<>();

		for (String option : options) {
			JButton button = createOptionButton(option, buttons.size() + 1); // button numbering starts at 1, not 0
			button.setName(option);
			addButton(button);
			buttons.add(button);
		}

		if (options.size() == 0) {
			JButton button = createOptionButton("OK", 1);
			button.setName("OK");
			addButton(button);
			buttons.add(button);
		}

		if (addCancel) {
			addCancelButton();
			buttons.add(cancelButton);
			if (options.size() == 1 && options.get(0).equals("Yes")) {
				setCancelButtonText("No");
			}
		}

		initializeDefaultButton(defaultButtonName, buttons);
	}

	private void initializeDefaultButton(String defaultButtonName, List<JButton> buttons) {
		if (buttons.isEmpty()) {
			return; // nothing to do; handled elsewhere
		}

		if (defaultButtonName == null) {
			setFocusComponent(buttons.get(0));
			setDefaultButton(buttons.get(0));
			return;
		}

		for (JButton jButton : buttons) {
			if (defaultButtonName.equals(jButton.getText())) {
				setFocusComponent(jButton);
				setDefaultButton(jButton);
				return;
			}
		}

		throw new AssertException(
			"No button exists to make default for name: " + defaultButtonName);
	}

	private JButton createOptionButton(String optionName, final int callbackValue) {
		int ampLoc = optionName.indexOf('&');
		char mnemonicKey = '\0';
		if (ampLoc >= 0 && ampLoc < optionName.length() - 1) {
			mnemonicKey = optionName.charAt(ampLoc + 1);
			optionName = optionName.substring(0, ampLoc) + optionName.substring(ampLoc + 1);
		}

		JButton button = new JButton(optionName);
		if (mnemonicKey != '\0') {
			button.setMnemonic(mnemonicKey);
		}
		button.addActionListener(ev -> {
			result = callbackValue;
			okCallback();
		});
		return button;
	}

	protected JPanel createTextPanel(String message) {

		this.dialogMessage = message;
		if (HTMLUtilities.isHTML(dialogMessage)) {
			JLabel messageLabel = new GHtmlLabel(dialogMessage);
			messageLabel.setName(MESSAGE_COMPONENT_NAME);
			JPanel panel = new JPanel(new BorderLayout());
			panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
			panel.add(messageLabel);
			return panel;
		}
		MultiLineLabel label = new MultiLineLabel(dialogMessage);
		label.setName(MESSAGE_COMPONENT_NAME);
		return label;
	}

	/**
	 * Returns the dialog's message to the user
	 * @return the message
	 */
	public String getMessage() {
		return dialogMessage;
	}

	public int show() {
		return show(null);
	}

	public int show(Component parent) {
		if (rememberOption.hasRememberedResult()) {
			result = rememberOption.getRememberedResult();
			return result;
		}
		DockingWindowManager.showDialog(parent, this);
		return result;
	}

//==================================================================================================
// Show Option Dialog Methods
//==================================================================================================

	/**
	 * A convenience method to create a {@link OptionDialogBuilder}
	 * @param title the dialog title
	 * @param message the dialog message
	 * @return the builder
	 */
	public static OptionDialogBuilder createBuilder(String title, String message) {
		return new OptionDialogBuilder(title, message);
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1) {
		return showOptionDialog(parent, title, message, option1, PLAIN_MESSAGE);
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 * <p>
	 * The dialog shown by this method will have the cancel button set as the default button so
	 * that an Enter key press will trigger a cancel action.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialogWithCancelAsDefaultButton(Component parent, String title,
			String message, String option1) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, QUESTION_MESSAGE, null, "Cancel");
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 * <p>
	 * The dialog shown by this method will have the cancel button set as the default button so
	 * that an Enter key press will trigger a cancel action.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialogWithCancelAsDefaultButton(Component parent, String title,
			String message, String option1, int messageType) {

		String defaultButton = option1.equals("Yes") ? "No" : "Cancel";

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, messageType, null, defaultButton);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, int messageType) {

		return Swing.runNow(() -> {
			OptionDialog info = new OptionDialog(title, message, option1, messageType, null);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @param defaultButtonName the name of the button to be the default.  Null will make the first
	 * button the default
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, int messageType, String defaultButtonName) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, messageType, null, defaultButtonName);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an single-option dialog.  The dialog
	 * will remain until the user presses the Option1 button or the Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the option button.
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @return The options selected by the user. 1 if the option button is pressed
	 *  or 0 if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, Icon icon) {

		return Swing.runNow(() -> {
			OptionDialog info = new OptionDialog(title, message, option1, PLAIN_MESSAGE, icon);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an <b>three-option</b> dialog.  The dialog
	 * will remain until the user presses the Option1, Option2, Option3 or Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used.
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param option3 The text to place on the third option button.
	 * @param messageType The type of message to display
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option and so on.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, String option2, String option3, int messageType) {

		return Swing.runNow(() -> {
			OptionDialog dialog = new OptionDialog(title, message, option1, option2, option3,
				messageType, null, true);
			return dialog.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an two-option dialog.  The dialog
	 * will remain until the user presses the Option1, Option2 or Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.\
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, String option2) {
		return showOptionDialog(parent, title, message, option1, option2, PLAIN_MESSAGE);
	}

	/**
	 * Static helper method to easily display an two-option dialog.  The dialog
	 * will remain until the user presses the Option1, Option2 or Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, String option2, int messageType) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, option2, messageType, null, true);
			return info.show(parent);
		});
	}

	/**
	 *  Static helper method to easily display an two-option dialog.  The dialog
	 * will remain until the user presses the Option1, Option2 or Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionDialog(Component parent, String title, String message,
			String option1, String option2, Icon icon) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, option2, PLAIN_MESSAGE, icon, true);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an two-option dialog.  The dialog
	 * will remain until the user presses the Option1, Option2 or Cancel button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionNoCancelDialog(Component parent, String title, String message,
			String option1, String option2, int messageType) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, option2, messageType, null, false);
			return info.show(parent);
		});
	}

	/**
	 * Static helper method to easily display an two-option dialog with no Cancel button.
	 * The dialog will remain until the user presses the Option1 or Option 2 button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param icon allows the user to specify the icon to be used.  If non-null,
	 *     this will override the messageType.
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionNoCancelDialog(Component parent, String title, String message,
			String option1, String option2, Icon icon) {

		return Swing.runNow(() -> {
			OptionDialog info =
				new OptionDialog(title, message, option1, option2, PLAIN_MESSAGE, icon, false);
			return info.show();
		});
	}

	/**
	 * Static helper method to easily display an three-option dialog with no Cancel button.
	 * The dialog will remain until the user presses the
	 * Option1, Option 2, or Option 3 button.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @param option1 The text to place on the first option button.
	 * @param option2 The text to place on the second option button.
	 * @param option3 The text to place on the third option button.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 * 		INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return The options selected by the user. 1 for the first option and
	 *  2 for the second option.  0 is returned if the operation is cancelled.
	 */
	public static int showOptionNoCancelDialog(Component parent, String title, String message,
			String option1, String option2, String option3, int messageType) {

		return Swing.runNow(() -> {
			OptionDialog info = new OptionDialog(title, message, option1, option2, option3,
				messageType, null, false);
			return info.show();
		});
	}

	/**
	 * Dialog with only YES/NO options, no CANCEL
	 *
	 * @param parent    The parent dialog or frame of this dialog. (Can be null)
	 * @param title     The String to be placed in the dialogs title area.
	 * @param message   The information message to be displayed in the dialog.
	 * @return The options selected by the user:
	 * <pre>
	 *                  0 is returned if the operation is cancelled
	 *                  1 for <b>Yes</b>
	 *                  2 for <b>No</b>
	 * </pre>
	 */
	public static int showYesNoDialog(Component parent, String title, String message) {
		return showOptionNoCancelDialog(parent, title, message, "&Yes", "&No", QUESTION_MESSAGE);
	}

	/**
	 * Dialog with only YES/NO options, <b>no CANCEL</b>
	 * <p>
	 * The dialog shown by this method will have the <code>No</code> button set as the default button so
	 * that an Enter key press will trigger a <code>No</code> action.
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title The String to be placed in the dialogs title area.
	 * @param message The information message to be displayed in the dialog.
	 * @return The options selected by the user:
	 * <pre>
	 *                  1 for <b>Yes</b>
	 *                  2 for <b>No</b>
	 * </pre>
	 */
	public static int showYesNoDialogWithNoAsDefaultButton(Component parent, String title,
			String message) {

		return Swing.runNow(() -> {
			OptionDialog info = new OptionDialog(title, message, "&Yes", "&No", QUESTION_MESSAGE,
				null, false, "No");
			return info.show(parent);
		});
	}

	/**
	 * Dialog with only YES/NO options, <b>no CANCEL</b>
	 *
	 * @param parent    The parent component of this dialog. If the given component is
	 * a frame or dialog, then the component will be used to parent the option dialog.
	 * Otherwise, the parent frame or dialog will be found by traversing up the given
	 * component's parent hierarchy.  Also, null can be used to not parent the dialog at all,
	 * but this promotes poor dialog behavior
	 * @param title     The String to be placed in the dialogs title area.
	 * @param message   The information message to be displayed in the dialog.
	 * @return The options selected by the user:
	 * <pre>
	 *                  0 is returned if the operation is cancelled
	 *                  1 for the first option
	 *                  2 for the second option
	 * </pre>
	 */
	public static int showYesNoCancelDialog(Component parent, String title, String message) {
		return showOptionDialog(parent, title, message, "&Yes", "&No", QUESTION_MESSAGE);
	}

	/**
	 * Displays a dialog for the user to enter a string value on a single line.
	 *
	 * @param parent the component to parent this dialog to
	 * @param title the title to display on the input dialog
	 * @param label the label to display in front of the text field
	 * @param initialValue an optional value to set in the text field, can be null
	 * @return the string entered OR null if the dialog was canceled.
	 */
	public static String showInputSingleLineDialog(Component parent, String title, String label,
			String initialValue) {

		return Swing.runNow(() -> {

			InputDialog dialog = new InputDialog(title, label, initialValue, true);

			// Apply similar settings to that of the OptionDialog, for consistency
			dialog.setRememberLocation(false);
			dialog.setRememberSize(false);

			DockingWindowManager.showDialog(parent, dialog);

			if (dialog.isCanceled()) {
				return null;
			}
			return dialog.getValue();
		});
	}

	/**
	 * Displays a dialog for the user to enter a <b>multi-line</b> string value.
	 *
	 * @param parent the component to parent this dialog to
	 * @param title the title to display on the input dialog
	 * @param label the label to display in front of the text area
	 * @param initialValue an optional value that will be set in the text area, can be null
	 * @return the string entered OR null if the dialog was canceled.
	 */
	public static String showInputMultilineDialog(Component parent, String title, String label,
			String initialValue) {

		return Swing.runNow(() -> {

			Icon icon = getIconForMessageType(QUESTION_MESSAGE);
			MultiLineInputDialog dialog =
				new MultiLineInputDialog(title, label, initialValue, icon);
			DockingWindowManager.showDialog(parent, dialog);

			if (dialog.isCanceled()) {
				return null;
			}
			return dialog.getValue();
		});
	}

	/**
	 * Displays a dialog for the user to enter a string value by either typing it or
	 * selecting from a list of possible strings.
	 *
	 * @param parent the component to parent this dialog to
	 * @param title the title to display on the input dialog
	 * @param label the label to display in front of the combo box
	 * @param selectableValues an array of string to choose from
	 * @param initialValue an optional value to set the combo box to, can be null
	 * in which the combo box will have the first item from the selectable values.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *     INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return the string entered or chosen OR null if the dialog was canceled.
	 */
	public static String showInputChoiceDialog(Component parent, String title, String label,
			String[] selectableValues, String initialValue, int messageType) {

		return Swing.runNow(() -> {

			Icon icon = getIconForMessageType(messageType);

			InputWithChoicesDialog dialog =
				new InputWithChoicesDialog(title, label, selectableValues, initialValue, icon);
			DockingWindowManager.showDialog(parent, dialog);

			if (dialog.isCanceled()) {
				return null;
			}
			return dialog.getValue();
		});
	}

	/**
	 * Displays a dialog for the user to enter a string value by either typing it or
	 * selecting from a list of possible strings.  The list of possible values is editable
	 * such that the user can enter their own value by typing text.
	 *
	 * @param parent the component to parent this dialog to
	 * @param title the title to display on the input dialog
	 * @param label the label to display in front of the combo box
	 * @param selectableValues an array of string to choose from
	 * @param initialValue an optional value to set the combo box to, can be null
	 * in which the combo box will have the first item from the selectable values.
	 * @param messageType used to specify a default icon, can be ERROR_MESSAGE,
	 *     INFORMATION_MESSAGE, WARNING_MESSAGE, QUESTION_MESSAGE, or PLAIN_MESSAGE)
	 * @return the string entered or chosen OR null if the dialog was canceled.
	 */
	public static String showEditableInputChoiceDialog(Component parent, String title, String label,
			String[] selectableValues, String initialValue, int messageType) {

		Icon icon = getIconForMessageType(messageType);

		return Swing.runNow(() -> {
			InputWithChoicesDialog dialog = new InputWithChoicesDialog(title, label,
				selectableValues, initialValue, true, icon);
			DockingWindowManager.showDialog(parent, dialog);

			if (dialog.isCanceled()) {
				return null;
			}
			return dialog.getValue();

		});
	}

	/**
	 * Returns which option was selected:
	 * CANCEL_OPTION if the operation was cancelled;
	 * OPTION_ONE if Option 1 was selected;
	 * OPTION_TWO if Option 2 was selected.
	 * @return selected option; returns CANCEL_OPTION for informational dialogs
	 */
	public final int getResult() {
		return result;
	}

	/**
	 * callback for when the "OK" button is pressed.
	 */
	@Override
	protected void okCallback() {
		if (rememberOptionCheckBox.isSelected()) {
			rememberOption.rememberResult(result);
		}
		close();
	}

	/**
	 * Callback for when the cancel button is pressed.
	 */
	@Override
	protected void cancelCallback() {
		result = CANCEL_OPTION;
		okCallback();
	}

	/**
	 * Returns the Icon to use for the given message type.
	 * @param messageType the type of message being displayed.
	 * @return the appropriate Icon.
	 */
	public static Icon getIconForMessageType(int messageType) {
		switch (messageType) {
			case PLAIN_MESSAGE:
				return null;
			case ERROR_MESSAGE:
				return UIManager.getIcon("OptionPane.errorIcon");
			case INFORMATION_MESSAGE:
				return UIManager.getIcon("OptionPane.informationIcon");
			case WARNING_MESSAGE:
				return UIManager.getIcon("OptionPane.warningIcon");
			case QUESTION_MESSAGE:
				return UIManager.getIcon("OptionPane.questionIcon");
			default:
				throw new IllegalArgumentException(
					"Invalid message type given in " + "OptionDialog.getIconForMessageType()");
		}
	}

	private static class DoNothingDialogRememberOption extends DialogRememberOption {

		public DoNothingDialogRememberOption() {
			super(null);
		}

		@Override
		public void rememberResult(int rememberedResult) {
			throw new UnsupportedOperationException("Can't rememberResult in dummy class");
		}
	}

}
