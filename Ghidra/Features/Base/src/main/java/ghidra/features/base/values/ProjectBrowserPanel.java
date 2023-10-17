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
package ghidra.features.base.values;

import java.awt.BorderLayout;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;

/**
 * Component used by Values that use the DataTreeDialog for picking DomainFiles and DomainFolders
 */
class ProjectBrowserPanel extends JPanel {
	private JTextField textField;
	private JButton browseButton;
	private boolean selectFolders;

	ProjectBrowserPanel(String name, boolean selectFolders) {
		super(new BorderLayout());
		this.selectFolders = selectFolders;
		setName(name);
		textField = new JTextField(20);
		browseButton = new BrowseButton();
		browseButton.addActionListener(e -> showDomainFileChooser());
		add(textField, BorderLayout.CENTER);
		add(browseButton, BorderLayout.EAST);
	}

	void setDomainFile(DomainFile value) {
		String text = value == null ? "" : value.getPathname();
		textField.setText(text);
	}

	void setDomainFolder(DomainFolder value) {
		String text = value == null ? "" : value.getPathname();
		textField.setText(text);
	}

	private void showDomainFileChooser() {
		DataTreeDialog dialog = new DataTreeDialog(null, "Choose " + getName(),
			selectFolders ? DataTreeDialog.CHOOSE_FOLDER : DataTreeDialog.OPEN);
		dialog.show();
		if (dialog.wasCancelled()) {
			return;
		}
		String text = selectFolders ? dialog.getDomainFolder().getPathname()
				: dialog.getDomainFile().getPathname();
		textField.setText(text);
		dialog.dispose();
	}

	DomainFile getDomainFile() {
		String text = textField.getText().trim();
		if (text.isBlank()) {
			return null;
		}
		return parseDomainFile(text);
	}

	String getText() {
		return textField.getText().trim();
	}

	DomainFolder getDomainFolder() {
		String text = textField.getText().trim();
		if (text.isBlank()) {
			return parseDomainFolder("/");
		}
		return parseDomainFolder(text);
	}

	static DomainFile parseDomainFile(String val) {
		// Add the slash to make it an absolute path
		if (!val.isEmpty() && val.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			val = FileSystem.SEPARATOR_CHAR + val;
		}
		Project activeProject = AppInfo.getActiveProject();
		DomainFile df = activeProject.getProjectData().getFile(val);
		if (df != null) {
			return df;
		}
		return null;
	}

	static DomainFolder parseDomainFolder(String path) {
		path = path.trim();
		// Add the slash to make it an absolute path
		if (path.isEmpty() || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			path = FileSystem.SEPARATOR_CHAR + path;
		}
		Project activeProject = AppInfo.getActiveProject();
		DomainFolder df = activeProject.getProjectData().getFolder(path);
		if (df != null) {
			return df;
		}
		return null;
	}

}
