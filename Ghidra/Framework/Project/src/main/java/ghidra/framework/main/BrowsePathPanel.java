/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.File;

import javax.swing.*;

import docking.DockingUtils;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.filechooser.GhidraFileChooser;

/**
 * Helper class that restricts the width of the textField to the size of the
 * scrolled paths list; also provides the listener for the textfield if user
 * presses Enter or Tab in a textfield.
 *
 */
class BrowsePathPanel extends JPanel {

	private boolean changed;
	private GhidraFileChooser fileChooser;
	private JTextField pathTextField;
	private EditPluginPathDialog dialog;
	private JButton browseButton;

	/**
	 * Construct a new BrowsePathPanel.
	 * @param editDialog parent dialog
	 * @param sizeComp component to use for size in creating text field
	 * @param button browse button
	 * @param dirOnly
	 * @param textFieldLabel
	 * @param fieldName name of text field component
	 */
	BrowsePathPanel(EditPluginPathDialog editDialog, ActionListener buttonListener, String fieldName) {

		super();
		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		dialog = editDialog;
		create(fieldName);
		addListeners(buttonListener);

	}

	/**
	 * Create the components
	 * @param sizeComp component to use when creating the text field to get the
	 * size
	 * @param textFieldLabel label for the field
	 */
	private void create(String fieldName) {
		pathTextField = new JTextField();
		pathTextField.setName(fieldName);
		pathTextField.setEditable(false);
		pathTextField.setBackground(getBackground());

		browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.setToolTipText("Choose Directory");

		// construct the panel with text field and browse button
		JPanel browsePathPanel = new JPanel(new BorderLayout(5, 5));
		browsePathPanel.add(pathTextField, BorderLayout.CENTER);
		browsePathPanel.add(browseButton, BorderLayout.EAST);
		add(browsePathPanel);

	}

	private void createFileChooser() {
		// create the fileChooser this panel will use based on its input criteria
		fileChooser = new GhidraFileChooser(dialog.getComponent());
		fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
		fileChooser.setFileSelectionMode(GhidraFileChooser.DIRECTORIES_ONLY);
		fileChooser.setApproveButtonToolTipText("Choose Directory With Plugin JAR Files");
		fileChooser.setApproveButtonText("Choose JAR Directory");
	}

	/**
	 * Add listeners.
	 * @param listener listener for the browse button
	 */
	private void addListeners(ActionListener listener) {
		browseButton.addActionListener(listener);

		pathTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();

				// when Esc or Ctrl-C is pressed, reset the plugin
				// jar directory to what is saved in preferences
				if (keyCode == KeyEvent.VK_ESCAPE ||
					(DockingUtils.isControlModifier(e) && keyCode == KeyEvent.VK_C)) {
					dialog.initJarDirectory();
				}
				else {
					dialog.setApplyEnabled(true);
				}
			}
		});

	}

	String getPath() {
		return pathTextField.getText().trim();
	}

	boolean isChanged() {
		return changed;
	}

	@Override
	public boolean hasFocus() {
		return pathTextField.hasFocus();
	}

	@Override
	public void requestFocus() {
		pathTextField.requestFocus();
		pathTextField.selectAll();
	}

	/**
	 * Pop up the file chooser.
	 */
	void showFileChooser() {
		if (fileChooser == null) {
			createFileChooser();
		}
		// reset the status message
		dialog.setStatusMessage(EditPluginPathDialog.EMPTY_STATUS);

		File pluginFile = fileChooser.getSelectedFile();
		if (pluginFile != null) {
			setPath(pluginFile);
		}
		else {
			pathTextField.requestFocus();
			pathTextField.selectAll();

		}
	}

	/**
	 * Set whether something has changed.
	 * @param changed true if something changed
	 */
	void setChanged(boolean changed) {
		this.changed = changed;
	}

	/**
	 * Set the path field.
	 * @param path filename for the path field
	 * @return boolean true if the path is valid
	 */
	private boolean setPath(File path) {
		boolean pathOK = false;
		dialog.setStatusMessage(EditPluginPathDialog.EMPTY_STATUS);

		if (!path.canRead()) {
			pathTextField.selectAll();
			dialog.setStatusMessage("Cannot read path: " + path.toString());
		}
		else {
			pathTextField.setText(path.getAbsolutePath());
			pathOK = (pathTextField.getText().trim().length() > 0);
		}

		if (pathOK) {
			dialog.setStatusMessage("Press Apply or OK to set JAR directory.");
		}

		changed = changed || pathOK;

		dialog.enableApply();

		return pathOK;
	}

	/**
	 * sets the text of the text field of the panel without
	 * any error checking
	 */
	void setText(String text) {
		pathTextField.setText(text);
	}

}
