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
package docking.widgets.values;

import java.awt.BorderLayout;
import java.io.File;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;

/**
 * Value class for {@link File} types. FileValues can be used for either file or directory values,
 * depending on the constructor options. The editor component uses a {@link JTextField} with
 * a browse button for bringing up a {@link GhidraFileChooser} for picking files or directories.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly. 
 */
public class FileValue extends AbstractValue<File> {
	private GhidraFileChooserMode chooserMode;
	private File startingDir;
	private FileValuePanel filePanel;

	/**
	 * Constructs a FileValue that expects its value to represent a file and not a directory.
	 * @param name the name of the value
	 */
	public FileValue(String name) {
		this(name, null);
	}

	/**
	 * Constructs a FileValue that expects its value to represent a file and not a directory.
	 * @param name the name of the value
	 * @param defaultValue the optional default File value. 
	 */
	public FileValue(String name, File defaultValue) {
		this(name, defaultValue, null, GhidraFileChooserMode.FILES_AND_DIRECTORIES);
	}

	/**
	 * Constructs a FileValue that could represent either a File or Directory, depending on the
	 * mode value.
	 * @param name the name of the value
	 * @param defaultValue the optional default File value. If non-null this can be either a
	 * file or directory, but it should match the given {@link GhidraFileChooserMode} 
	 * @param startingDir an optional directory specifying where the FileChooser should intialize
	 * its starting selected directory.
	 * @param mode the {@link GhidraFileChooserMode} used to indicate if this File represents a
	 * file or directory. It will put the GhidraFileChooser in a mode for choosing files or
	 * directories.
	 */
	public FileValue(String name, File defaultValue, File startingDir, GhidraFileChooserMode mode) {
		super(name, defaultValue);
		this.chooserMode = mode;
		this.startingDir = startingDir;
	}

	@Override
	public JComponent getComponent() {
		if (filePanel == null) {
			filePanel = new FileValuePanel(getName());
		}
		return filePanel;
	}

	@Override
	public void updateValueFromComponent() {
		setValue(filePanel.getFile());
	}

	@Override
	public void updateComponentFromValue() {
		filePanel.setValue(getValue());
	}

	@Override
	public File fromString(String valueString) {
		return new File(valueString);
	}

	// not private so that tests can access this class
	class FileValuePanel extends JPanel {
		private JTextField textField;
		private JButton browseButton;

		public FileValuePanel(String name) {
			super(new BorderLayout());
			setName(name);
			textField = new JTextField(20);
			browseButton = new BrowseButton();
			browseButton.addActionListener(e -> showFileChooser());
			add(textField, BorderLayout.CENTER);
			add(browseButton, BorderLayout.EAST);
		}

		public void setValue(File value) {
			String text = value == null ? "" : value.toString();
			textField.setText(text);
		}

		private void showFileChooser() {
			GhidraFileChooser chooser = new GhidraFileChooser(null);
			chooser.setSelectedFile(getFile());
			chooser.setTitle("Choose " + getName());
			chooser.setFileSelectionMode(chooserMode);
			if (startingDir != null) {
				chooser.setCurrentDirectory(startingDir);
			}
			File selectedFile = chooser.getSelectedFile();
			if (selectedFile != null) {
				textField.setText(selectedFile.toString());
			}
			chooser.dispose();
		}

		public File getFile() {
			String text = textField.getText().trim();
			if (text.isBlank()) {
				return null;
			}
			return new File(text);
		}

	}
}
