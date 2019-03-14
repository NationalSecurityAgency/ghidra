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
package docking.options.editor;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.MouseListener;
import java.beans.PropertyEditorSupport;
import java.io.File;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.filechooser.GhidraFileChooser;

/**
 * Bean editor to show a text field and a browse button to bring
 * up a File Chooser dialog. This editor is created as a result of
 * get/setFilename() on Options.
 */
public class FileChooserEditor extends PropertyEditorSupport {

	private final static int NUMBER_OF_COLUMNS = 20;
	private File currentFileValue;
	private JTextField textField = new JTextField(NUMBER_OF_COLUMNS);
	private File currentDir;
	private GhidraFileChooser fileChooser;
	private MouseListener otherMouseListener;

	@Override
	public String getAsText() {
		return textField.getText().trim();
	}

	@Override
	public Object getValue() {
		String text = getAsText();
		if (StringUtils.isBlank(text)) {
			return null;
		}
		return new File(text);
	}

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		if (text == null || text.trim().isEmpty()) {
			currentFileValue = null;
			textField.setText("");
			return;
		}

		currentFileValue = new File(text);
		textField.setText(text);
	}

	@Override
	public void setValue(Object value) {
		if (value == null) {
			currentFileValue = null;
		}

		if (value instanceof File) {
			currentFileValue = (File) value;
			textField.setText(currentFileValue.getAbsolutePath());
		}
		else if (value instanceof String) {
			setAsText((String) value);
		}
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return new FileChooserPanel();
	}

	void setMouseListener(MouseListener listener) {
		this.otherMouseListener = listener;
	}

	private class FileChooserPanel extends JPanel {
		private JButton browseButton;

		private FileChooserPanel() {
			BoxLayout bl = new BoxLayout(this, BoxLayout.X_AXIS);
			setLayout(bl);

			textField.setText(currentFileValue != null ? currentFileValue.getAbsolutePath() : "");
			browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
			Font f = browseButton.getFont();
			f = new Font(f.getName(), Font.BOLD, f.getSize());
			browseButton.setFont(f);

			add(textField);
			add(Box.createHorizontalStrut(5));
			add(browseButton);
			setBorder(BorderFactory.createEmptyBorder());
			textField.addActionListener(e -> FileChooserEditor.this.firePropertyChange());
			textField.getDocument().addDocumentListener(new TextListener());

			browseButton.addActionListener(e -> displayFileChooser());
			if (otherMouseListener != null) {
				textField.addMouseListener(otherMouseListener);
				browseButton.addMouseListener(otherMouseListener);
			}
		}

		private void displayFileChooser() {
			if (fileChooser == null) {
				createFileChooser();
			}

			String path = textField.getText().trim();
			if (path.length() != 0) {
				File f = new File(path);
				if (f.isDirectory()) {
					fileChooser.setCurrentDirectory(f);
				}
				else {
					File pf = f.getParentFile();
					if (pf != null && pf.isDirectory()) {
						fileChooser.setSelectedFile(f);
					}
				}
			}

			currentFileValue = fileChooser.getSelectedFile();
			if (currentFileValue != null) {
				textField.setText(currentFileValue.getAbsolutePath());
				FileChooserEditor.this.firePropertyChange();
			}
			else {
				currentFileValue = null;
				currentDir = fileChooser.getCurrentDirectory();
			}

		}

		private void createFileChooser() {
			if (fileChooser == null) {
				fileChooser = new GhidraFileChooser(browseButton);
			}

			fileChooser.setApproveButtonText("Choose Path");
			fileChooser.setTitle("Choose Path");
			fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_AND_DIRECTORIES);
			if (currentFileValue != null) {
				fileChooser.setSelectedFile(currentFileValue);
			}
			else if (currentFileValue != null) {
				File file = currentFileValue;
				if (file.exists()) {
					if (file.isDirectory()) {
						fileChooser.setCurrentDirectory(file);
					}
					else {
						fileChooser.setCurrentDirectory(file.getParentFile());
						fileChooser.setSelectedFile(file);
					}
				}
				else {
					File parent = file.getParentFile();
					if (parent == null) {
						String homeDir = System.getProperty("user.home");
						fileChooser.setCurrentDirectory(new File(homeDir));
					}
					if (parent != null) {
						fileChooser.setCurrentDirectory(parent);
					}
				}
			}
			else if (currentDir != null) {
				fileChooser.setCurrentDirectory(currentDir);
			}
		}

	}

	private class TextListener implements DocumentListener {

		@Override
		public void changedUpdate(DocumentEvent e) {
			FileChooserEditor.this.firePropertyChange();
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			FileChooserEditor.this.firePropertyChange();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			FileChooserEditor.this.firePropertyChange();
		}

	}
}
