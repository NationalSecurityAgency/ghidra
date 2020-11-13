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
package ghidra.framework.main;

import java.awt.*;
import java.io.InputStream;

import javax.swing.*;
import javax.swing.text.html.HTMLEditorKit;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.framework.DockingApplicationConfiguration;
import docking.framework.DockingApplicationLayout;
import docking.widgets.label.GDLabel;
import ghidra.framework.Application;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

public class UserAgreementDialog extends DialogComponentProvider {
	private static final String USER_AGREEMENT_FILENAME = "UserAgreement.html";
	private boolean showAgreementChoices;
	private boolean exitOnCancel;

	public UserAgreementDialog(boolean showAgreementChoices, boolean exitOnCancel) {
		super("", true, false, true, false);
		this.showAgreementChoices = showAgreementChoices;
		this.exitOnCancel = exitOnCancel;
		addWorkPanel(buildWorkPanel());
		addOKButton();
		if (showAgreementChoices) {
			setOkButtonText("I Agree");
			addCancelButton();
			setCancelButtonText("I Don't Agree");
		}
		else {
			setOkButtonText("OK");
		}
		setPreferredSize(1000, 500);
	}

	private JComponent buildWorkPanel() {
		Font font = new Font("Default", Font.PLAIN, 16);
		JPanel panel = new JPanel(new BorderLayout());
		JLabel label = new GDLabel("Ghidra User Agreement", SwingConstants.CENTER);
		label.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
		label.setFont(font.deriveFont(Font.ITALIC, 22f));
		panel.add(label, BorderLayout.NORTH);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 40, 40, 40));
		JEditorPane editorPane = new JEditorPane();
		editorPane.setEditorKit(new HTMLEditorKit());
		editorPane.setMargin(new Insets(10, 10, 10, 10));

		editorPane.setText(getUserAgreementText());
		editorPane.setCaretPosition(0);
		editorPane.setEditable(false);

		JScrollPane scrollPane = new JScrollPane(editorPane);
		panel.add(scrollPane, BorderLayout.CENTER);
		JPanel checkBoxPanel = new JPanel(new VerticalLayout(10));
		checkBoxPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 10));
		panel.add(checkBoxPanel, BorderLayout.SOUTH);
		return panel;
	}

	private String getUserAgreementText() {
		try (InputStream in = ResourceManager.getResourceAsStream(USER_AGREEMENT_FILENAME)) {
			String text = FileUtilities.getText(in);
			if (!HTMLUtilities.isHTML(text)) {
				// our labels to not render correctly when not using HTML
				text = HTMLUtilities.toHTML(text);
			}

			text = text.replace('\n', ' ');

			return text;
		}
		catch (Exception e) {
			// use default splash screen info
			Msg.debug(this, "Unable to read user agreement text from: " + USER_AGREEMENT_FILENAME);
			return USER_AGREEMENT_FILENAME + " file is missing!";
		}
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	protected void cancelCallback() {
		if (exitOnCancel) {
			System.exit(0);
		}
		close();
	}

	public static void main(String[] args) throws Exception {
		ApplicationLayout layout = new DockingApplicationLayout("User Agreement Main", "1.0");
		DockingApplicationConfiguration config = new DockingApplicationConfiguration();
		Application.initializeApplication(layout, config);
		UserAgreementDialog dialog = new UserAgreementDialog(true, true);
		DockingWindowManager.showDialog(null, dialog);
	}
}
