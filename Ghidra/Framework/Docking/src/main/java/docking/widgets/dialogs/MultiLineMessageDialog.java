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
package docking.widgets.dialogs;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;
import javax.swing.text.DefaultCaret;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.widgets.OptionDialog;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.util.HTMLUtilities;

public class MultiLineMessageDialog extends DialogComponentProvider {
	/** Used for error messages. */
	public static final int ERROR_MESSAGE = OptionDialog.ERROR_MESSAGE;
	/** Used for information messages. */
	public static final int INFORMATION_MESSAGE = OptionDialog.INFORMATION_MESSAGE;
	/** Used for warning messages. */
	public static final int WARNING_MESSAGE = OptionDialog.WARNING_MESSAGE;
	/** Used for questions. */
	public static final int QUESTION_MESSAGE = OptionDialog.QUESTION_MESSAGE;
	/** No icon is used. */
	public static final int PLAIN_MESSAGE = OptionDialog.PLAIN_MESSAGE;

	/**
	 * Static helper method to easily display a modal message dialog showing a text string
	 * with an "OK" button.
	 * <p>
	 * If the text is too long to fit, a scroll bar will be used.
	 * <p>
	 * The text string can be plain text (with \n line breaks) or HTML (if the first
	 * 6 characters of the string are <code>&lt;html&gt;</code>).
	 * <p>
	 * This method will not return until the user presses the OK button.
	 * <p>
	 * @param parent - parent component or null
	 * @param title - dialog title
	 * @param shortMessage - short message that appears above the main message.
	 * @param detailedMessage - long scrollable message.
	 * @param messageType - see {@link #ERROR_MESSAGE}, {@link #INFORMATION_MESSAGE},
	 * {@link #WARNING_MESSAGE}, {@link #QUESTION_MESSAGE}, {@link #PLAIN_MESSAGE}
	 */
	public static void showModalMessageDialog(Component parent, String title, String shortMessage,
			String detailedMessage, int messageType) {
		MultiLineMessageDialog mlmd =
			new MultiLineMessageDialog(title, shortMessage, detailedMessage, messageType, true);
		DockingWindowManager.showDialog(parent, mlmd);
	}

	public static void showMessageDialog(Component parent, String title, String shortMessage,
			String detailedMessage, int messageType) {
		MultiLineMessageDialog mlmd =
			new MultiLineMessageDialog(title, shortMessage, detailedMessage, messageType, false);
		DockingWindowManager.showDialog(parent, mlmd);
	}

	/**
	 * Creates a multi-line popup dialog.
	 * @param title the dialog title
	 * @param shortMessage a short message to display at the top of the dialog
	 * @param detailedMessage the detailed message
	 * @param messageType the message type (warning, error, info, etc)
	 * @param modal true if the dialog should be modal
	 */
	public MultiLineMessageDialog(String title, String shortMessage, String detailedMessage,
			int messageType, boolean modal) {
		super(title, modal, false, true, false);

		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		if (!StringUtils.isBlank(shortMessage)) {
			JLabel shortMessageLabel = new GLabel(shortMessage);
			shortMessageLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 10, 10));
			workPanel.add(shortMessageLabel, BorderLayout.NORTH);
		}

		if (StringUtils.isBlank(detailedMessage)) {
			// don't add anything to dialog
		}
		else if (HTMLUtilities.isHTML(detailedMessage)) {

			// Use a JTextPane to handle html.  This is similar to what happens in
			// OptionDialog where it looks at the message text for a leading "<html>".
			// In this case, we are also inserting a <body> that specifies the font-family
			// to get us back to the same font the rest of the GUI is using.

			JTextPane textPane = new JTextPane();
			String fontfamily = textPane.getFont().getFamily();
			detailedMessage = "<html><body style=\"font-family: " + fontfamily + "\">" +
				detailedMessage.substring(6);

			// Set the textpane to not auto-scroll to bottom when adding text
			DefaultCaret caret = (DefaultCaret) textPane.getCaret();
			caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

			textPane.setContentType("text/html");
			textPane.setText(detailedMessage);
			textPane.setEditable(false);

			DockingUtils.setTransparent(textPane);
			JScrollPane scrollPane = new JScrollPane(textPane);
			DockingUtils.setTransparent(scrollPane);
			scrollPane.setBorder(BorderFactory.createEmptyBorder());
			workPanel.add(scrollPane, BorderLayout.CENTER);

			// note: this must be done after adding the text component to the scroll pane 
			//       (seems like the scroll pane is changing the border)
			textPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		}
		else {
			JTextArea textArea = new JTextArea(detailedMessage);
			textArea.setEditable(false);

			DockingUtils.setTransparent(textArea);
			JScrollPane scrollPane = new JScrollPane(textArea);
			DockingUtils.setTransparent(scrollPane);
			workPanel.add(scrollPane, BorderLayout.CENTER);

			// note: this must be done after adding the text component to the scroll pane 
			//       (seems like the scroll pane is changing the border)
			textArea.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		}

		Icon icon = OptionDialog.getIconForMessageType(messageType);
		if (icon != null) {
			JLabel iconLabel = new GIconLabel(icon);
			iconLabel.setBorder(BorderFactory.createEmptyBorder(1, 10, 1, 10));
			workPanel.add(iconLabel, BorderLayout.WEST);
		}

		setTransient(true);
		addWorkPanel(workPanel);
		addOKButton();

		setFocusComponent(okButton);
		setDefaultButton(okButton);
		setRememberSize(false);

		// A somewhat arbitrary number to prevent the dialog from stretching across the screen
		setPreferredSize(600, 300);
	}

	@Override
	protected void okCallback() {
		close();
	}

}
