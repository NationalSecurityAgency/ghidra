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
package ghidra.app.util.importer.options;

import static ghidra.framework.main.DataTreeDialogType.*;

import java.awt.BorderLayout;
import java.awt.Component;
import java.util.Objects;

import javax.swing.*;

import docking.widgets.button.BrowseButton;
import docking.widgets.textfield.ElidingFilePathTextField;
import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.SaveState;

/**
 * An {@link Option} used to specify a {@link DomainFolder}
 */
public class DomainFolderOption extends StringOption {

	/**
	 * Creates a new {@link DomainFolderOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public DomainFolderOption(String name, String value, String arg, String group,
			String stateKey, boolean hidden, String description) {
		super(name, value, arg, group, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY, hidden,
			description);
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		String defaultValue = getValue();
		String lastFolderPath =
			state != null ? state.getString(getName(), defaultValue) : defaultValue;
		setValue(lastFolderPath);
		JTextField textField = new ElidingFilePathTextField(lastFolderPath);
		textField.setEditable(false);
		textField.setColumns(10);
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
	public DomainFolderOption copy() {
		return new DomainFolderOption(getName(), getValue(), getArg(), getGroup(),
			getStateKey(), isHidden(), getDescription());
	}

	/**
	 * Builds a {@link DomainFolderOption}
	 */
	public static class Builder extends StringOption.Builder {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link DomainFolderOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public DomainFolderOption build() {
			return new DomainFolderOption(name, Objects.requireNonNullElse(value, ""),
				commandLineArgument, group, stateKey, hidden, description);
		}
	}
}
