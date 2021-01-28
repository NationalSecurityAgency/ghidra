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
import java.awt.Insets;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingUtils;

/**
 * General purpose modal dialog to display text in a text area.
 */
public class ReadTextDialog extends DialogComponentProvider {
	private JTextArea textArea;
	private JPanel workPanel;

	/**
	 * Construct a new ReadTextDialog
	 * @param title title for this dialog
	 * @param text text to display in the text area
	 */
	public ReadTextDialog(String title, String text) {
		super(title, true, false, true, false);
		init(createWorkPanel(text));
	}

	/**
	 * Get the text displayed in the text area.
	 */
	public String getText() {
		return textArea.getText();
	}

	/**
	 * Set the text in the text area.
	 */
	public void setText(String text) {
		textArea.setText(text);
	}

	private void init(JPanel workPanelToInit) {
		setTransient(true);
		addWorkPanel(workPanelToInit);
		addOKButton();
		setRememberLocation(false);
		setRememberSize(false);
	}

	@Override
	protected void okCallback() {
		close();
	}

	/**
	 *
	 */
	private JPanel createWorkPanel(String text) {
		workPanel = new JPanel(new BorderLayout());

		textArea = new JTextArea(10, 80);
		textArea.setText(text);
		textArea.setEditable(false);
		textArea.setMargin(new Insets(5, 5, 5, 5));
//        textArea.setFont(font);
		DockingUtils.setTransparent(textArea);
		textArea.setCaretPosition(0);
		JScrollPane scrolledDetails = new JScrollPane(textArea);
		workPanel.add(scrolledDetails, BorderLayout.CENTER);
		return workPanel;
	}
}
