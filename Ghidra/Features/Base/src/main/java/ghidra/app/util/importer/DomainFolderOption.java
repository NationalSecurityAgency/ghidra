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
package ghidra.app.util.importer;

import static ghidra.framework.main.DataTreeDialogType.*;

import java.awt.BorderLayout;
import java.awt.Component;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.SaveState;

/**
 * An {@link Option} used to specify a {@link DomainFolder}
 */
public class DomainFolderOption extends Option {

	/**
	 * Creates a new {@link DomainFolderOption}
	 * 
	 * @param name The name of the option
	 * @param arg The option's command line argument (could be null)
	 */
	public DomainFolderOption(String name, String arg) {
		super(name, String.class, "", arg, null, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY);
	}

	@Override
	public Component getCustomEditorComponent() {
		final SaveState state = getState();
		String defaultValue = (String) getValue();
		String lastFolderPath =
			state != null ? state.getString(getName(), defaultValue) : defaultValue;
		setValue(lastFolderPath);
		JTextField textField = new JTextField(lastFolderPath);
		textField.setEditable(false);
		JButton button = new BrowseButton();
		button.addActionListener(e -> {
			DataTreeDialog dataTreeDialog =
				new DataTreeDialog(null, "Choose a project folder", CHOOSE_FOLDER);
			String folderPath = lastFolderPath.isBlank() ? "/" : lastFolderPath;
			dataTreeDialog.setSelectedFolder(
				AppInfo.getActiveProject().getProjectData().getFolder(folderPath));
			dataTreeDialog.showComponent();
			DomainFolder folder = dataTreeDialog.getDomainFolder();
			if (folder != null) {
				String newFolderPath = folder.getPathname();
				textField.setText(newFolderPath);
				setValue(newFolderPath);
				if (state != null) {
					state.putString(getName(), newFolderPath);
				}
			}
		});
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(textField, BorderLayout.CENTER);
		panel.add(button, BorderLayout.EAST);
		return panel;
	}

	@Override
	public Class<?> getValueClass() {
		return String.class;
	}

	@Override
	public Option copy() {
		return new DomainFolderOption(getName(), getArg());
	}
}
