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

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import ghidra.util.Swing;

/**
 * Class for creating OptionDialogs using the builder pattern.
 *
 * <P>At a minimum, an OptionDialog requires a title and a message.  They can be specified
 * in the constructor or set later.
 *
 * <P>You can also, specify the messageType or an icon.  The messageType is used to set the
 * icon to one of several predefined ones appropriate for the message(ERROR, WARNING, etc.)
 * You should not specify both, but if you do, the specified Icon will be used and the
 * MessageType will be ignored.
 *
 * <P>You can also add "options" which are custom buttons with the given text. Each option
 * button is mapped to a different integer dialog result.  The result values start at 1
 * for the first option and increment by 1 for each additional option.
 * For example, if you add options "yes" and "no" in that order, then pressing the "yes"
 * button will produce a dialog result of 1, and pressing the "no" button will produce a
 * dialog result of 2.  If no options are added, then an "OK" button will automatically be added.
 *
 * <P>You can also set the default button by calling {@link #setDefaultButton(String)} where the
 * string is the text of the button (the option) that you want to be the default .  For example, if you
 * have the options "yes" and "no", you can make the "no" button the default by specifying
 * "no" as the defaultOption.
 *
 * <P>You can also add a Cancel button, which will return a result of 0 if pressed. Note that this
 * is different than adding an option named "Cancel" which would return a result greater than
 * <code>0</code>, depending on where in the order it was added.
 *
 * <P><a id="RememberOption"></a>A "Remember Option" can be added to OptionDialog to
 * present the user with a choice for remembering a dialog result and automatically
 * returning that result instead of showing the dialog or similar dialogs in the future.
 * Note that for simple OK dialogs, there really isn't a meaningful result to remember, other
 * than a decision was made not to show the dialog again.
 *
 * <P>The "Remember Option" is represented as a checkBox at the bottom of an OptionDialog.
 * The checkBox text will be either "Apply to all", "Remember my decision",
 * or "Don't show again" depending on whether {@link #addApplyToAllOption()},
 * {@link #addDontShowAgainOption()}, or {@link #addRememberMyDecisionOption()} method is
 * called.
 *
 * <P>If the user selects the checkBox, then the dialog result will be remembered.
 * In future calls to display that dialog (or any dialog sharing
 * the same DialogRememberChoice object), the dialog will first check if has a
 * DialogRememberChoice object and that it has a remembered result, and if so, will just return
 * the remembered result instead of showing the dialog.
 *
 */
public class OptionDialogBuilder {
	private String title;
	private String message;
	private Icon icon;
	private int messageType;
	private boolean addCancelButton;
	private List<String> options;
	private String defaultOption;
	private DialogRememberOption rememberOption;

	/**
	 * Constructs an OptionDialogBuilder with not even the minimal information required. If
	 * this constructor is used, then both {@link #setTitle(String)} and the
	 * {@link #setMessage(String)} methods must be called
	 * or else the dialog will have no title or message.
	 */
	public OptionDialogBuilder() {
		this(null, null);
	}

	/**
	 * Constructs an OptionDialogBuilder with not even the minimal information required. If
	 * this constructor is used, then the {@link #setMessage(String)} method must be called
	 * or else the dialog will be blank.
	 *
	 * @param title the title of the dialog
	 */
	public OptionDialogBuilder(String title) {
		this(title, null);
	}

	/**
	 * Constructs an OptionDialogBuilder with the minimal information required. If no
	 * other information is set, the builder will create the simplest dialog that has
	 * a title, message and an "Ok" button.
	 *
	 * @param title the title of the dialog.
	 * @param message the main message to be displayed in the dialog.
	 */
	public OptionDialogBuilder(String title, String message) {
		this.title = title;
		this.message = message;
		this.options = new ArrayList<>();
		this.messageType = OptionDialog.PLAIN_MESSAGE;
	}

	/**
	 * Sets the title for the OptionDialog.
	 *
	 * @param title the title for the dialog.
	 * @return this builder object.
	 */
	public OptionDialogBuilder setTitle(String title) {
		this.title = title;
		return this;
	}

	/**
	 * Sets the main message for the OptionDialog.
	 *
	 * @param message the main message for the dialog.
	 * @return this builder object.
	 */
	public OptionDialogBuilder setMessage(String message) {
		this.message = message;
		return this;
	}

	/**
	 * Sets the Icon for the OptionDialog.
	 * <P>
	 * If both an Icon and a message type are specified,
	 * the icon will take precedence.
	 *
	 * @param icon the icon to display in the dialog.
	 * @return this builder object.
	 */
	public OptionDialogBuilder setIcon(Icon icon) {
		this.icon = icon;
		return this;
	}

	/**
	 * Sets the message type for the OptionDialog which will determine the icon that
	 * is in the dialog.
	 *
	 * @param messageType used to specify that this dialog is one of the set types.  See
	 * {@link OptionDialog} for the list of defined messageTypes.
	 * @return this builder object.
	 */
	public OptionDialogBuilder setMessageType(int messageType) {
		this.messageType = messageType;
		return this;
	}

	/**
	 * Adds a cancel button to the OptionDialog.
	 *
	 * @return this builder object.
	 */
	public OptionDialogBuilder addCancel() {
		addCancelButton = true;
		return this;
	}

	/**
	 * Adds a button option to the dialog.
	 *
	 * @param optionName the name of the button to be added to the dialog
	 * @return this builder object.
	 */
	public OptionDialogBuilder addOption(String optionName) {
		options.add(optionName);
		return this;
	}

	/**
	 * Sets the name of the button to be used as the default button.
	 *
	 * @param optionName the name of the option to be the default.
	 * @return this builder object.
	 */
	public OptionDialogBuilder setDefaultButton(String optionName) {
		defaultOption = optionName;
		return this;
	}

	/**
	 * Adds an "Apply to all" option to the dialog. See <a href="#RememberOption">
	 * header documentation</a> for details.
	 * <P>
	 * This will replace any previously added "checkBox" options.
	 *
	 * @return this builder object.
	 */
	public OptionDialogBuilder addApplyToAllOption() {
		this.rememberOption = new DialogRememberOption("Apply to all");
		return this;
	}

	/**
	 * Adds a "Don't show again" option to the dialog. See <a href="#RememberOption">
	 * header documentation</a> for details.
	 * <P>
	 * This will replace any previously added "checkBox" options.
	 *
	 * @return this builder object.
	 */
	public OptionDialogBuilder addDontShowAgainOption() {
		this.rememberOption = new DialogRememberOption("Don't show again");
		return this;
	}

	/**
	 * Adds a "Remember my decision" option to the dialog. See <a href="#RememberOption">
	 * header documentation</a> for details.
	 * <P>
	 * This will replace any previously added "checkBox" options.
	 *
	 * @return this builder object.
	 */
	public OptionDialogBuilder addRememberMyDecisionOption() {
		this.rememberOption = new DialogRememberOption("Remember my decision");
		return this;
	}

	/**
	 * Builds an OptionDialog based on the values set in this builder.
	 *
	 * @return an OptionDialog built based on the values set in this builder.
	 */
	public OptionDialog build() {
		return Swing.runNow(() -> {
			return new OptionDialog(title, message, messageType, icon, addCancelButton,
				rememberOption, options, defaultOption);
		});
	}

	/**
	 * Builds and shows an OptionDialog based on the values set in this builder.
	 *
	 * @return the result returned from the OptionDialog after the user selected an option.
	 */
	public int show() {
		return show(null);
	}

	/**
	 * Builds and shows an OptionDialog based on the values set in this builder.
	 *
	 * @param parent the component to use as the OptionDialog's parent when displaying it.
	 * @return the result returned from the OptionDialog after the user selected an option.
	 */
	public int show(Component parent) {
		if (rememberOption != null && rememberOption.hasRememberedResult()) {
			return rememberOption.getRememberedResult();
		}

		OptionDialog dialog = build();
		dialog.show(parent);
		return dialog.getResult();
	}
}
