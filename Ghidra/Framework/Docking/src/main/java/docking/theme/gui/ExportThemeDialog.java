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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.IOException;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.theme.*;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import generic.theme.*;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;

public class ExportThemeDialog extends DialogComponentProvider {

	private JTextField nameField;
	private JTextField fileTextField;
	private GCheckBox includeDefaultsCheckbox;

	protected ExportThemeDialog() {
		super("Export Theme");

		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		setRememberSize(false);
	}

	@Override
	protected void okCallback() {
		if (exportTheme()) {
			close();
		}
	}

	private boolean exportTheme() {
		File file = new File(fileTextField.getText());
		String themeName = nameField.getText();
		if (themeName.isBlank()) {
			setStatusText("Missing Theme Name", MessageType.ERROR, true);
			return false;
		}
		boolean includeDefaults = includeDefaultsCheckbox.isSelected();

		GTheme activeTheme = Gui.getActiveTheme();
		FileGTheme fileTheme = new FileGTheme(file, themeName, activeTheme.getLookAndFeelType(),
			activeTheme.useDarkDefaults());

		if (includeDefaults) {
			fileTheme.load(Gui.getAllValues());
		}
		else {
			fileTheme.load(Gui.getNonDefaultValues());
		}

		try {
			fileTheme.save();
			return true;
		}
		catch (IOException e) {
			Msg.error("Error Exporting Theme", "I/O Error encountered trying to export theme!", e);
			return false;
		}
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

		panel.add(new GLabel("Theme Name:", SwingConstants.RIGHT));
		panel.add(buildNameField());
		panel.add(new GLabel("Output File:", SwingConstants.RIGHT));
		panel.add(buildFilePanel());
		panel.add(new GLabel("Include Defaults:", SwingConstants.RIGHT));
		panel.add(buildIncludeDefaultsCheckbox());
		return panel;
	}

	private Component buildNameField() {
		nameField = new JTextField(25);
		nameField.setText(Gui.getActiveTheme().getName());
		return nameField;
	}

	private Component buildIncludeDefaultsCheckbox() {
		includeDefaultsCheckbox = new GCheckBox();
		includeDefaultsCheckbox.setSelected(true);
		return includeDefaultsCheckbox;
	}

	private Component buildFilePanel() {
		String name = Gui.getActiveTheme().getName();
		String fileName = name.replaceAll(" ", "_") + GTheme.FILE_EXTENSION;
		File homeDir = new File(System.getProperty("user.home")); // prefer the home directory
		File file = new File(homeDir, fileName);

		fileTextField = new JTextField();
		fileTextField.setText(file.getAbsolutePath());
		fileTextField.setEditable(false);
		fileTextField.setFocusable(false);
		JButton folderButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		folderButton.addActionListener(e -> chooseFile());

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(fileTextField, BorderLayout.CENTER);
		panel.add(folderButton, BorderLayout.EAST);
		return panel;
	}

	private void chooseFile() {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setTitle("Choose Theme File");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		chooser.setSelectedFile(new File(fileTextField.getText()));
		File file = chooser.getSelectedFile();
		if (file != null) {
			fileTextField.setText(file.getAbsolutePath());
		}
	}

}
