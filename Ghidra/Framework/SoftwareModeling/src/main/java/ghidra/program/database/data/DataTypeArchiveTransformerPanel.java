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
package ghidra.program.database.data;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.*;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GLabel;
import ghidra.framework.preferences.Preferences;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DataTypeArchiveTransformerPanel extends JPanel {

	private final static String DOT_DOT_DOT = ". . .";
	private final static Cursor WAIT_CURSOR = new Cursor(Cursor.WAIT_CURSOR);
	private final static Cursor NORM_CURSOR = new Cursor(Cursor.DEFAULT_CURSOR);

	private GhidraFileChooser chooser;

	private JPanel filePanel;
	private JTextField oldFileTextField;
	private JTextField newFileTextField;
	private JTextField destinationFileTextField;
	private JCheckBox useOldFileIDCheckBox;

	public DataTypeArchiveTransformerPanel() {
		super();
		initialize();
	}

	private void initialize() {
		setLayout(new BorderLayout());
		filePanel = new JPanel(new GridBagLayout());
		setupDescription();
		setupOldFileField();
		setupNewFileField();
		setupDestinationFileField();
		add(filePanel, BorderLayout.CENTER);
	}

	private void setupDescription() {
		JLabel label = new GHtmlLabel(
			"<HTML>Specify the files for converting a new data type archive (.gdt)<BR>" +
				"to match the IDs of data types in an old data type archive.<BR>" +
				"The result will be saved to the destination archive.</HTML>");
		label.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
		label.setHorizontalAlignment(SwingConstants.CENTER);
		add(label, BorderLayout.NORTH);
	}

	private void setupOldFileField() {
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.gridy = 0;
		gbc.gridx = 0;
		gbc.gridwidth = 1;
		filePanel.add(new GLabel("Old file name "), gbc);

		gbc.gridx = 1;
		gbc.gridwidth = 1;
		oldFileTextField = new JTextField(30);
		filePanel.add(oldFileTextField, gbc);

		gbc.gridx = 2;
		gbc.gridwidth = 1;
		JButton oldBrowseButton = new JButton(DOT_DOT_DOT);
		oldBrowseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setCursor(WAIT_CURSOR);
				File file = chooseFile("Choose old data type archive");
				setCursor(NORM_CURSOR);
				if (file != null) {
					oldFileTextField.setText(file.getAbsolutePath());
				}
			}
		});
		Font font = oldBrowseButton.getFont();
		oldBrowseButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
		filePanel.add(oldBrowseButton, gbc);

		gbc.gridx = 3;
		gbc.gridwidth = 1;
		useOldFileIDCheckBox = new GCheckBox("  Use Old File ID");
		filePanel.add(useOldFileIDCheckBox, gbc);
	}

	private void setupNewFileField() {
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.gridy = 1;
		gbc.gridx = 0;
		gbc.gridwidth = 1;
		filePanel.add(new GLabel("New file name "), gbc);

		gbc.gridx = 1;
		gbc.gridwidth = 1;
		newFileTextField = new JTextField(30);
		filePanel.add(newFileTextField, gbc);

		gbc.gridx = 2;
		gbc.gridwidth = 1;
		JButton newBrowseButton = new JButton(DOT_DOT_DOT);
		newBrowseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setCursor(WAIT_CURSOR);
				File file = chooseFile("Choose new data type archive");
				setCursor(NORM_CURSOR);
				if (file != null) {
					newFileTextField.setText(file.getAbsolutePath());
				}
			}
		});
		Font font = newBrowseButton.getFont();
		newBrowseButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
		filePanel.add(newBrowseButton, gbc);
	}

	private void setupDestinationFileField() {
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.anchor = GridBagConstraints.WEST;
		gbc.gridy = 2;
		gbc.gridx = 0;
		gbc.gridwidth = 1;
		filePanel.add(new GLabel("Destination file name "), gbc);

		gbc.gridx = 1;
		gbc.gridwidth = 1;
		destinationFileTextField = new JTextField(30);
		filePanel.add(destinationFileTextField, gbc);

		gbc.gridx = 2;
		gbc.gridwidth = 1;
		JButton destinationBrowseButton = new JButton(DOT_DOT_DOT);
		destinationBrowseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setCursor(WAIT_CURSOR);
				File file = chooseFile("Choose destination file");
				setCursor(NORM_CURSOR);
				if (file != null) {
					destinationFileTextField.setText(file.getAbsolutePath());
				}
			}
		});
		Font font = destinationBrowseButton.getFont();
		destinationBrowseButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
		filePanel.add(destinationBrowseButton, gbc);
	}

	File chooseFile(final String buttonText) {
		if (chooser == null) {
			chooser = new GhidraFileChooser(this);
			chooser.setCurrentDirectory(getLastDataTypeArchiveDirectory());
		}
		chooser.setTitle(buttonText);
		chooser.setApproveButtonText(buttonText);
		chooser.setApproveButtonToolTipText(buttonText);

		File file = chooser.getSelectedFile();

		if (file != null && file.exists()) {
			Preferences.setProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY,
				file.getAbsolutePath());
			Preferences.store();
		}

		return file;
	}

	File getLastDataTypeArchiveDirectory() {
		String lastDirStr = Preferences.getProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY,
			System.getProperty("user.home"));
		return new File(lastDirStr);
	}

	protected void transform(TaskMonitor monitor)
			throws InvalidInputException, DuplicateFileException, IOException, CancelledException {

		DataTypeArchiveTransformer.transform(getOldFile(), getNewFile(), getDestinationFile(),
			useOldFileIDCheckBox.isSelected(), monitor);
	}

	protected File getDestinationFile() {
		return new File(destinationFileTextField.getText());
	}

	protected File getNewFile() {
		return new File(newFileTextField.getText());
	}

	protected File getOldFile() {
		return new File(oldFileTextField.getText());
	}

}
