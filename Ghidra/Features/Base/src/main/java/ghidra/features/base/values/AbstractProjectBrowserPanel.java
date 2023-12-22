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
import java.util.Objects;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.store.FileSystem;

/**
 * Base class for either project file chooser or project folder chooser
 */
abstract class AbstractProjectBrowserPanel extends JPanel {
	protected Project project;
	protected JTextField textField;
	private JButton browseButton;
	private DomainFolder startFolder;
	private int type;
	protected DomainFileFilter filter = null;

	AbstractProjectBrowserPanel(int type, Project project, String name, String startPath) {
		super(new BorderLayout());
		this.type = type;
		this.project = Objects.requireNonNull(project);
		this.startFolder = parseDomainFolder(project, startPath);
		setName(name);
		textField = new JTextField(20);
		browseButton = new BrowseButton();
		browseButton.addActionListener(e -> showProjectChooser());
		add(textField, BorderLayout.CENTER);
		add(browseButton, BorderLayout.EAST);
	}

	private void showProjectChooser() {
		DataTreeDialog dialog =
			new DataTreeDialog(null, "Choose " + getName(), type, filter, project);

		if (startFolder != null) {
			dialog.selectFolder(startFolder);
		}
		intializeCurrentValue(dialog);

		dialog.show();

		if (dialog.wasCancelled()) {
			return;
		}
		String text = getSelectedPath(dialog);
		textField.setText(text);
		dialog.dispose();
	}

	protected abstract String getSelectedPath(DataTreeDialog dialog);

	protected abstract void intializeCurrentValue(DataTreeDialog dialog);

	String getText() {
		return textField.getText().trim();
	}

	static DomainFile parseDomainFile(Project project, String val) {
		// Add the slash to make it an absolute path
		if (!val.isEmpty() && val.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			val = FileSystem.SEPARATOR_CHAR + val;
		}
		DomainFile df = project.getProjectData().getFile(val);
		if (df != null) {
			return df;
		}
		return null;
	}

	static DomainFolder parseDomainFolder(Project project, String path) {
		if (path == null) {
			return null;
		}
		path = path.trim();
		// Add the slash to make it an absolute path
		if (path.isEmpty() || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			path = FileSystem.SEPARATOR_CHAR + path;
		}
		DomainFolder df = project.getProjectData().getFolder(path);
		if (df != null) {
			return df;
		}
		return null;
	}
}
