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
package pdb.symbolserver.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GHtmlLabel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;

/**
 * Non-public, package-only dialog that prompts the user to enter a path
 * in a text field (similar to an {@link OptionDialog}) and allows them to click
 * a "..." browse button to pick the file and/or directory via a 
 * {@link GhidraFileChooser} dialog.
 */
class FilePromptDialog extends DialogComponentProvider {

	/**
	 * Prompts the user to enter the path to a directory,
	 * or to pick it using a browser dialog.
	 * 
	 * @param title the dialog title 
	 * @param prompt HTML enabled prompt
	 * @param initialValue initial value to pre-populate the input field with
	 * @return the {@link File} the user entered / picked, or null if canceled
	 */
	public static File chooseDirectory(String title, String prompt, File initialValue) {
		return chooseFile(title, prompt, "Choose", null, initialValue,
			GhidraFileChooserMode.DIRECTORIES_ONLY);
	}

	/**
	 * Prompts the user to entry the path to a file and/or directory,
	 * or to pick it using a browser dialog.
	 * <p>
	 * 
	 * @param title the dialog title 
	 * @param prompt HTML enabled prompt
	 * @param chooseButtonText text of the choose button in the browser dialog
	 * @param directory the initial directory of the browser dialog
	 * @param initialFileValue the initial value to pre-populate the input field with
	 * @param chooserMode {@link GhidraFileChooserMode} of the browser dialog
	 * @param fileFilters optional {@link GhidraFileFilter filters} 
	 * @return the {@link File} the user entered / picked, or null if canceled
	 */
	public static File chooseFile(String title, String prompt, String chooseButtonText,
			File directory, File initialFileValue, GhidraFileChooserMode chooserMode,
			GhidraFileFilter... fileFilters) {
		FilePromptDialog filePromptDialog = new FilePromptDialog(title, prompt, chooseButtonText,
			directory, initialFileValue, chooserMode, fileFilters);
		DockingWindowManager.showDialog(filePromptDialog);
		return filePromptDialog.chosenValue;
	}

	private GhidraFileChooser chooser;
	private GhidraFileFilter[] fileFilters;
	private File directory;
	private File file;
	private String approveButtonText;
	private JTextField filePathTextField;
	private GhidraFileChooserMode chooserMode;
	private File chosenValue;

	protected FilePromptDialog(String title, String prompt, String approveButtonText,
			File directory, File file, GhidraFileChooserMode chooserMode,
			GhidraFileFilter... fileFilters) {
		super(title, true, false, true, false);

		this.approveButtonText = approveButtonText;
		this.directory = directory;
		this.file = file;
		this.chooserMode = chooserMode;
		this.fileFilters = fileFilters;
		setRememberSize(false);

		build(prompt);
		updateButtonEnablement();
	}

	private void build(String prompt) {

		GHtmlLabel promptLabel = new GHtmlLabel(prompt);
		filePathTextField = new JTextField(file != null ? file.getPath() : null, 40);
		filePathTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				updateButtonEnablement();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				updateButtonEnablement();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				updateButtonEnablement();
			}
		});
		JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.addActionListener(e -> browse());

		JPanel textFieldWithButtonPanel = new JPanel(new BorderLayout());
		textFieldWithButtonPanel.add(filePathTextField, BorderLayout.CENTER);
		textFieldWithButtonPanel.add(browseButton, BorderLayout.EAST);

		JPanel mainPanel = new JPanel(new PairLayout());
		mainPanel.add(promptLabel);
		mainPanel.add(textFieldWithButtonPanel);
		Dimension size = mainPanel.getPreferredSize();
		size.width = Math.max(size.width, 500);
		mainPanel.setPreferredSize(size);
		mainPanel.setMinimumSize(size);
		JPanel newMain = new JPanel(new BorderLayout());
		newMain.add(mainPanel, BorderLayout.CENTER);

		addWorkPanel(newMain);
		addOKButton();
		addCancelButton();
	}

	private void updateButtonEnablement() {
		okButton.setEnabled(!filePathTextField.getText().isBlank());
	}

	@Override
	protected void okCallback() {
		chosenValue = new File(filePathTextField.getText());
		close();
	}

	@Override
	protected void cancelCallback() {
		chosenValue = null;
		close();
	}

	private void browse() {
		initChooser();
		String filePathText = filePathTextField.getText();
		filePathText = filePathText.isBlank() && file != null ? file.getPath() : "";
		if (!filePathText.isBlank()) {
			chooser.setSelectedFile(new File(filePathText));
		}
		File selectedFile = chooser.getSelectedFile();
		if (selectedFile != null) {
			filePathTextField.setText(selectedFile.getPath());
		}
		filePathTextField.requestFocusInWindow();
	}

	private void initChooser() {

		if (chooser == null) {
			chooser = new GhidraFileChooser(rootPanel);
			for (GhidraFileFilter gff : fileFilters) {
				chooser.addFileFilter(gff);
			}
			chooser.setMultiSelectionEnabled(false);
			chooser.setApproveButtonText(approveButtonText);
			chooser.setFileSelectionMode(chooserMode);
			chooser.setTitle(getTitle());

			if (directory != null) {
				chooser.setCurrentDirectory(directory);
			}
		}
	}
}
