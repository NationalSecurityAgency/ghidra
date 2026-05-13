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

import org.apache.commons.io.FilenameUtils;

import docking.widgets.button.BrowseButton;
import docking.widgets.textfield.ElidingFilePathTextField;
import ghidra.app.util.Option;
import ghidra.app.util.opinion.Loader;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;

/**
 * An {@link Option} used to specify a {@link DomainFile}
 */
public class DomainFileOption extends Option {

	/**
	 * Creates a new {@link DomainFileOption}
	 * 
	 * @param name The name of the option
	 * @param arg The option's command line argument (could be null)
	 * @param hidden true if this option should be hidden from the user; otherwise, false
	 */
	public DomainFileOption(String name, String arg, boolean hidden) {
		super(name, String.class, "", arg, null, Loader.OPTIONS_PROJECT_SAVE_STATE_KEY, hidden);
	}

	@Override
	public Component getCustomEditorComponent() {
		final SaveState state = getState();
		String defaultValue = (String) getValue();
		String lastFilePath =
			state != null ? state.getString(getName(), defaultValue) : defaultValue;
		setValue(lastFilePath);
		JTextField textField = new ElidingFilePathTextField(lastFilePath);
		textField.setEditable(false);
		textField.setColumns(10);
		JButton button = new BrowseButton();
		button.addActionListener(e -> {
			DataTreeDialog dataTreeDialog =
				new DataTreeDialog(null, "Choose a project file", OPEN);
			String folderPath = lastFilePath.isBlank() ? "/" : FilenameUtils.getPath(lastFilePath);
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
	public Class<?> getValueClass() {
		return String.class;
	}

	@Override
	public Option copy() {
		return new DomainFileOption(getName(), getArg(), isHidden());
	}
}
