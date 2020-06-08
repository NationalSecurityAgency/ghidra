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
package ghidra.app.plugin.core.script;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.MultiLineLabel;
import docking.widgets.label.GLabel;
import docking.widgets.list.ListPanel;
import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.util.HelpLocation;

public class SaveDialog extends DialogComponentProvider implements ListSelectionListener {
	protected GhidraScriptComponentProvider componentProvider;
	protected ResourceFile scriptFile;

	private GhidraScriptProvider provider;

	private List<ResourceFile> paths;
	private ListPanel listPanel;
	private JTextField nameField;
	private boolean cancelled;

	SaveDialog(Component parent, String title, GhidraScriptComponentProvider componentProvider,
			ResourceFile scriptFile, HelpLocation help) {
		this(parent, title, componentProvider, componentProvider.getWritableScriptDirectories(),
			scriptFile, help);
	}

	/**
	 * Only called directly from testing!
	 * 
	 * @param parent parent component
	 * @param title dialog title
	 * @param componentProvider the provider
	 * @param scriptDirs list of directories to give as options when saving
	 * @param scriptFile the default save location
	 * @param help contextual help, e.g. for rename or save
	 */
	public SaveDialog(Component parent, String title,
			GhidraScriptComponentProvider componentProvider, List<ResourceFile> scriptDirs,
			ResourceFile scriptFile, HelpLocation help) {
		super(title, true, true, true, false);

		this.componentProvider = componentProvider;
		this.provider = GhidraScriptUtil.getProvider(scriptFile);
		this.scriptFile = scriptFile;
		this.paths = new ArrayList<>(scriptDirs);

		JPanel pathPanel = buildPathPanel();
		JPanel namePanel = buildNamePanel();

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		if (paths.size() != 0) {
			panel.add(pathPanel, BorderLayout.CENTER);
			panel.add(namePanel, BorderLayout.SOUTH);
		}
		else {
			panel.add(namePanel, BorderLayout.NORTH);
		}

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);

		setHelpLocation(help);

		DockingWindowManager.showDialog(parent, this);
	}

	private JPanel buildNamePanel() {
		nameField = new JTextField(20);
		nameField.setText(scriptFile == null ? "" : scriptFile.getName());

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.add(new GLabel("Enter script file name:"), BorderLayout.NORTH);
		panel.add(nameField, BorderLayout.CENTER);
		return panel;
	}

	private JPanel buildPathPanel() {

		DefaultListModel<ResourceFile> listModel = new DefaultListModel<>();

		for (ResourceFile dir : paths) {
			listModel.addElement(dir);
		}

		listPanel = new ListPanel();
		listPanel.setName("PATH_LIST");
		listPanel.setListModel(listModel);
		listPanel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		listPanel.setSelectedIndex(0);
		listPanel.setDoubleClickActionListener(e -> close());
		if (scriptFile != null) {
			listPanel.setSelectedValue(scriptFile.getParentFile());
		}
		listPanel.setListSelectionListener(this);

		JPanel pathPanel = new JPanel(new BorderLayout());
		MultiLineLabel mll = new MultiLineLabel("Please select a directory:");
		pathPanel.add(mll, BorderLayout.NORTH);
		pathPanel.add(listPanel, BorderLayout.CENTER);
		return pathPanel;
	}

	@Override
	protected void dialogShown() {
		String text = nameField.getText();

		int endIndex = text.length();
		int dotIndex = text.lastIndexOf('.');
		if (dotIndex != -1) {
			endIndex = dotIndex; // exclusive
		}

		nameField.requestFocusInWindow();
		nameField.select(0, endIndex);
		super.dialogShown();
	}

	@Override
	protected void okCallback() {
		if (paths.size() != 0 && listPanel.getSelectedIndex() == -1) {
			setStatusText("Please select a directory.");
			return;
		}
		if (nameField.getText().length() == 0) {
			setStatusText("Please enter a file name.");
			return;
		}
		if (nameField.getText().length() > 100) {
			setStatusText("File name is too long.");
			return;
		}

		String errorMessage = getDuplicateNameErrorMessage(nameField.getText());
		if (errorMessage != null) {
			setStatusText(errorMessage);
			return;
		}

		close();
	}

	protected String getDuplicateNameErrorMessage(String name) {
		ScriptInfo existingInfo = componentProvider.getInfoManager().getExistingScriptInfo(name);
		if (existingInfo != null) {
			// make sure the script has not been deleted
			ResourceFile sourceFile = existingInfo.getSourceFile();
			if (sourceFile.exists()) {
				// we have a script info and a file on disk--do not overwrite
				return "Duplicate script name.";
			}
			return null; // allow overwrite of script, as it has been deleted on disk
		}

		ResourceFile directory = getDirectory();
		File userChoice = new File(directory.getAbsolutePath(), name);
		if (userChoice.exists()) {
			return "File already exists on disk.";
		}

		return null;
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		super.cancelCallback();
	}

	boolean isCancelled() {
		return cancelled;
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		if (!nameField.getText().startsWith(GhidraScriptConstants.DEFAULT_SCRIPT_NAME)) {
			return;
		}
		try {
			scriptFile = GhidraScriptUtil.createNewScript(provider, getDirectory(),
				componentProvider.getScriptDirectories());
			nameField.setText(scriptFile.getName());
		}
		catch (IOException ioe) {
			scriptFile = null;
			nameField.setText("");
		}
	}

	protected ResourceFile getDirectory() {
		if (paths.size() == 0 && scriptFile != null) {
			return scriptFile.getParentFile();
		}
		int index = listPanel.getSelectedIndex();
		if (index < 0) {
			return null;
		}
		return paths.get(index);
	}

	ResourceFile getFile() {
		ResourceFile directory = getDirectory();
		if (directory == null || nameField.getText().length() == 0) {
			return null;
		}
		String name = nameField.getText();
		if (!name.toLowerCase().endsWith(provider.getExtension())) {
			name += provider.getExtension();
		}
		return new ResourceFile(directory, name);
	}
}
