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
package ghidra.framework.main.datatree;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.*;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Dialog to get comments for adding a file to version control or 
 * checking in a file.
 * 
 */
public class VersionControlDialog extends DialogComponentProvider {

	static final int OK = 0;
	public static final int APPLY_TO_ALL = 1;
	public static final int CANCEL = 2;

	private JCheckBox keepCB; // keep checked out
	private JCheckBox keepFileCB; // create keep file
	private JLabel descriptionLabel;
	private JTextArea commentsTextArea;
	private JButton allButton; // apply to all
	private int actionID;
	private boolean addToVersionControl; // true if the dialog is for adding

	/**
	 * Constructor
	 * @param addToVersionControl true for adding; false for check-in
	 */
	public VersionControlDialog(boolean addToVersionControl) {
		super(addToVersionControl ? "Add File to Version Control" : "Check In File(s)", true);
		this.addToVersionControl = addToVersionControl;
		addWorkPanel(buildMainPanel());

		allButton = new JButton("Apply to All");
		allButton.setMnemonic('A');
		allButton.addActionListener(e -> {
			actionID = APPLY_TO_ALL;
			close();
		});

		addOKButton();
		addButton(allButton);
		addCancelButton();
		String tag = addToVersionControl ? "Add_to_Version_Control" : "CheckIn";
		setHelpLocation(new HelpLocation(GenericHelpTopics.REPOSITORY, tag));
		setRememberLocation(false);
		setRememberSize(false);
	}

	@Override
	protected void cancelCallback() {
		actionID = CANCEL;
		close();
	}

	@Override
	protected void okCallback() {
		actionID = OK;
		close();
	}

	/**
	 * Show the dialog; return an ID for the action that the user chose.
	 * @param parent parent to this dialog
	 * @return OK, APPLY_TO_ALL, or CANCEL
	 */
	int showDialog(PluginTool tool, Component parent) {
		tool.showDialog(this, parent);
		return actionID;
	}

	void setMultiFiles(boolean multi) {
		allButton.setEnabled(multi);
	}

	/**
	 * Return 
	 * @return
	 */
	boolean keepCheckedOut() {
		return keepCB.isSelected();
	}

	void setKeepCheckedOut(boolean selected) {
		keepCB.setSelected(selected);
	}

	boolean shouldCreateKeepFile() {
		if (addToVersionControl) {
			return false;
		}
		return keepFileCB.isSelected();
	}

	void setCreateKeepFile(boolean selected) {
		if (!addToVersionControl) {
			keepFileCB.setSelected(selected);
		}
	}

	/**
	 * Return the comments for the add to version control.
	 * @return may be the empty string
	 */
	String getComments() {
		return commentsTextArea.getText();
	}

	/**
	 * Disable the check box for "keep checked out" because some files
	 * are still in use. 
	 */
	public void setKeepCheckboxEnabled(boolean enabled) {
		keepCB.setEnabled(enabled);
		keepCB.setToolTipText(enabled ? "" : "Must keep Checked Out because the file is in use");
	}

	private JPanel buildMainPanel() {

		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.Y_AXIS));
		ImageIcon icon = resources.ResourceManager.loadImage(
			addToVersionControl ? "images/vcAdd.png" : "images/vcCheckIn.png");

		descriptionLabel = new GDLabel(addToVersionControl ? "Add comments to describe the file."
				: "Add comments to describe changes",
			SwingConstants.LEFT);
		JPanel dPanel = new JPanel(new BorderLayout(10, 0));
		dPanel.add(new GIconLabel(icon), BorderLayout.WEST);
		dPanel.add(descriptionLabel, BorderLayout.CENTER);

		JPanel cPanel = new JPanel(new BorderLayout());
		cPanel.add(new GLabel("Comments:", SwingConstants.LEFT));

		commentsTextArea = new JTextArea(4, 20);
		JScrollPane sp = new JScrollPane(commentsTextArea);

		keepCB = new GCheckBox("Keep File Checked Out", true);
		JPanel kPanel = new JPanel(new BorderLayout());
		kPanel.add(keepCB, BorderLayout.WEST);

		innerPanel.add(Box.createVerticalStrut(10));
		innerPanel.add(dPanel);
		innerPanel.add(Box.createVerticalStrut(5));
		innerPanel.add(cPanel);
		innerPanel.add(sp);
		innerPanel.add(Box.createVerticalStrut(5));
		innerPanel.add(kPanel);

		if (!addToVersionControl) {
			keepFileCB = new GCheckBox("Create \".keep\" file", false);
			JPanel kpPanel = new JPanel(new BorderLayout());
			kpPanel.add(keepFileCB, BorderLayout.WEST);
			innerPanel.add(kpPanel);
		}

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
		mainPanel.add(innerPanel);
		return mainPanel;
	}

	/**
	 * Set the name of the current file being added to version control or being updated.
	 * @param filename the name of the file currently to be added, whose comment we need.
	 */
	public void setCurrentFileName(String filename) {
		String description = addToVersionControl ? "Add comments to describe " + filename + "."
				: "Add comments to describe changes to " + filename + ".";
		descriptionLabel.setText(description);
	}
}
