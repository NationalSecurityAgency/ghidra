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

import org.apache.commons.io.FilenameUtils;

import docking.widgets.button.BrowseButton;
import docking.widgets.textfield.ElidingFilePathTextField;
import ghidra.app.util.AddressFactoryService;
import ghidra.app.util.Option;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;

/**
 * An {@link Option} used to specify a {@link DomainFile}
 */
public class DomainFileOption extends StringOption {

	/**
	 * Creates a new {@link DomainFileOption}
	 * 
	* @param name the name of the option
	* @param value the value of the option
	* @param arg the option's command line argument
	* @param group the name for group of options
	* @param stateKey the state key name
	* @param hidden true if this option should be hidden from the user; otherwise, false
	* @param description a description of the option
	 */
	public DomainFileOption(String name, String value, String arg, String group,
			String stateKey, boolean hidden, String description) {
		super(name, value, arg, group, stateKey, hidden, description);
	}

	@Override
	public Component getCustomEditorComponent(AddressFactoryService addressFactoryService) {
		final SaveState state = getState();
		String defaultValue = getValue();
		String lastFilePath =
			state != null ? state.getString(getName(), defaultValue) : defaultValue;
		setValue(lastFilePath);
		JTextField textField = new ElidingFilePathTextField(lastFilePath);
		textField.setEditable(false);
		textField.setColumns(10);
		textField.setToolTipText(getDescription());
		JButton button = new BrowseButton();
		button.addActionListener(e -> {
			DataTreeDialog dataTreeDialog =
				new DataTreeDialog(null, "Choose a project file", OPEN);
			String folderPath =
				lastFilePath.isBlank() ? "/" : FilenameUtils.getPath(lastFilePath);
			dataTreeDialog.setSelectedFolder(
				AppInfo.getActiveProject().getProjectData().getFolder(folderPath));
			dataTreeDialog.showComponent();
			DomainFile file = dataTreeDialog.getDomainFile();
			if (file != null) {
				String newFilePath = file.getPathname();
				textField.setText(newFilePath);
				setValue(newFilePath);
				if (state != null) {
					state.putString(getName(), newFilePath);
				}
			}
		});
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(textField, BorderLayout.CENTER);
		panel.add(button, BorderLayout.EAST);
		return panel;
	}

	@Override
	public DomainFileOption copy() {
		return new DomainFileOption(getName(), getValue(), getArg(), getGroup(), getStateKey(),
			isHidden(), getDescription());
	}

	/**
	 * Builds a {@link DomainFileOption}
	 */
	public static class Builder extends StringOption.Builder {

		/**
		 * Creates a new {@link Builder}
		 * 
		 * @param name The name of the {@link DomainFileOption} to be built
		 */
		public Builder(String name) {
			super(name);
		}

		@Override
		public DomainFileOption build() {
			return new DomainFileOption(name, Objects.requireNonNullElse(value, ""),
				commandLineArgument, group, stateKey, hidden, description);
		}
	}
}
