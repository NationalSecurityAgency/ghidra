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
package ghidra.app.plugin.core.analysis;

import java.awt.Component;
import java.awt.event.MouseListener;
import java.beans.PropertyEditorSupport;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.button.BrowseButton;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFileFilter;

/**
 * Bean editor to show a text field and a browse button to bring
 * up a Domain File Chooser dialog.  The path of the chosen domain file is returned as
 * a String value.
 */
public class ProjectPathChooserEditor extends PropertyEditorSupport {

	private final static int NUMBER_OF_COLUMNS = 20;
	private JTextField textField = new JTextField(NUMBER_OF_COLUMNS);
	private MouseListener otherMouseListener;
	private String title;
	private DomainFileFilter filter;

	public ProjectPathChooserEditor() {
		this(null, null);
	}

	public ProjectPathChooserEditor(String title, DomainFileFilter filter) {
		this.title = title;
		this.filter = filter;
	}

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
		return text;
	}

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		if (text == null || text.trim().isEmpty()) {
			text = "";
		}

		textField.setText(text);
	}

	@Override
	public void setValue(Object value) {
		if (value == null) {
			setAsText("");
		}
		else if (value instanceof String s) {
			setAsText(s);
		}
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		return new ProjectFileChooserPanel();
	}

	void setMouseListener(MouseListener listener) {
		this.otherMouseListener = listener;
	}

	private class ProjectFileChooserPanel extends JPanel {
		private JButton browseButton;

		private ProjectFileChooserPanel() {
			BoxLayout bl = new BoxLayout(this, BoxLayout.X_AXIS);
			setLayout(bl);

			browseButton = new BrowseButton();

			add(textField);
			add(Box.createHorizontalStrut(5));
			add(browseButton);
			setBorder(BorderFactory.createEmptyBorder());
			textField.addActionListener(e -> ProjectPathChooserEditor.this.firePropertyChange());
			textField.getDocument().addDocumentListener(new TextListener());

			browseButton.addActionListener(e -> displayFileChooser());
			if (otherMouseListener != null) {
				textField.addMouseListener(otherMouseListener);
				browseButton.addMouseListener(otherMouseListener);
			}
		}

		private void displayFileChooser() {
			AtomicReference<String> result = new AtomicReference<>();
			DataTreeDialog dataTreeDialog =
				new DataTreeDialog(this, title, DataTreeDialog.OPEN, filter);
			dataTreeDialog.addOkActionListener(e -> {
				dataTreeDialog.close();
				DomainFile df = dataTreeDialog.getDomainFile();
				result.set(df != null ? df.getPathname() : null);
			});
			dataTreeDialog.showComponent();

			String newPath = result.get();
			if (newPath != null) {
				textField.setText(newPath);
				ProjectPathChooserEditor.this.firePropertyChange();
			}
		}
	}

	private class TextListener implements DocumentListener {

		@Override
		public void changedUpdate(DocumentEvent e) {
			ProjectPathChooserEditor.this.firePropertyChange();
		}

		@Override
		public void insertUpdate(DocumentEvent e) {
			ProjectPathChooserEditor.this.firePropertyChange();
		}

		@Override
		public void removeUpdate(DocumentEvent e) {
			ProjectPathChooserEditor.this.firePropertyChange();
		}

	}

}
