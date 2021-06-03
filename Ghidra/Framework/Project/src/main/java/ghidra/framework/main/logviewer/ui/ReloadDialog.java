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
package ghidra.framework.main.logviewer.ui;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import ghidra.framework.main.logviewer.event.FVEvent;
import ghidra.framework.main.logviewer.event.FVEvent.EventType;
import ghidra.framework.main.logviewer.event.FVEventListener;

/**
 * Simple warning dialog for letting the user know when the input file has been updated. This 
 * includes an option allowing the user to opt-out of seeing subsequent pop-ups.
 * 
 * Note: The Ghidra {@link docking.options.editor.OptionsPanel OptionsPanel}
 * is not sufficient for this as it doesn't allow for custom objects to be
 * displayed (the opt-out checkbox).
 *
 */
public class ReloadDialog extends JDialog {

	// As long as this is true, this dialog will be displayed when setVisible is called. 
	boolean showUpdateWarning = true;

	private FVEventListener eventListener;

	/**
	 * Constructor.
	 */
	public ReloadDialog(FVEventListener eventListener) {

		this.eventListener = eventListener;

		Object[] options = new Object[] { createContent() };
		JOptionPane optionPane = new JOptionPane("File has changed. Reload?",
			JOptionPane.WARNING_MESSAGE, JOptionPane.YES_NO_OPTION, null, options);

		setContentPane(optionPane);
		pack();
		setResizable(false);
		setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
	}

	/**
	 * Creates the visual component of the dialog.
	 * 
	 * @return
	 */
	private JPanel createContent() {

		JPanel contentPane = new JPanel();
		contentPane.setLayout(new BorderLayout());

		JPanel buttonPanel = new JPanel();
		JButton yesBtn = new JButton("Yes");
		JButton noBtn = new JButton("No");
		buttonPanel.add(yesBtn);
		buttonPanel.add(noBtn);
		contentPane.add(buttonPanel, BorderLayout.CENTER);

		JCheckBox checkbox = new GCheckBox("Do not show this message again.");
		contentPane.add(checkbox, BorderLayout.SOUTH);

		// When the user selects the YES button they're indicating they want to reload the file, so
		// fire off an event to do so, making sure to save the checkbox status.
		yesBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				FVEvent reloadEvt = new FVEvent(EventType.RELOAD_FILE, null);
				eventListener.send(reloadEvt);
				setVisible(false);
				showUpdateWarning = !(checkbox.isSelected());
			}

		});

		// When the NO button is selected, we just need to close the warning dialog
		// and return, making sure to save the checkbox status.
		noBtn.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				setVisible(false);
				showUpdateWarning = !(checkbox.isSelected());
			}

		});

		return contentPane;
	}

	/**
	 * Need to override the base implementation so we can short-circuit this and only show
	 * the dialog if the user has not previously selected the opt-out checkbox.
	 */
	@Override
	public void setVisible(boolean visible) {

		if (!showUpdateWarning) {
			return;
		}

		super.setVisible(visible);
	}

}
