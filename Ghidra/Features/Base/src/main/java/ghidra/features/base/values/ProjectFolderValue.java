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

import javax.swing.JComponent;
import javax.swing.JTextField;

import docking.widgets.values.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;

/**
 * Value class for project folders ({@link DomainFile}). The editor component consists of the
 * {@link JTextField} and a browse button for bringing up a {@link DataTreeDialog} for picking
 * project folders from the current project.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class ProjectFolderValue extends AbstractValue<DomainFolder> {

	private Project project;
	private ProjectFolderBrowserPanel domainFilePanel;

	/**
	 * Constructor for ProjectFolderValues with the given name.
	 * @param name the name of the value
	 */
	public ProjectFolderValue(String name) {
		this(name, null);
	}

	/**
	 * Constructor for creating a new ProjectFolderValue with the given name and a path
	 * for a default folder value.
	 * @param name the name of the value
	 * @param defaultValuePath the path for a default folder value
	 */
	public ProjectFolderValue(String name, String defaultValuePath) {
		this(name, AppInfo.getActiveProject(), defaultValuePath);
	}

	/**
	 * Constructor for creating ProjectFolderValues for projects other than the active project.
	 * @param name the name of the value
	 * @param project the project to find a folder from
	 * @param defaultValuePath the path of a default folder value
	 */
	public ProjectFolderValue(String name, Project project, String defaultValuePath) {
		super(name, AbstractProjectBrowserPanel.parseDomainFolder(project, defaultValuePath));
		this.project = project;
	}

	@Override
	public JComponent getComponent() {
		if (domainFilePanel == null) {
			domainFilePanel = new ProjectFolderBrowserPanel(project, getName(), null);
		}
		return domainFilePanel;
	}

	@Override
	protected void updateValueFromComponent() throws ValuesMapParseException {
		if (domainFilePanel != null) {
			DomainFolder domainFolder = domainFilePanel.getDomainFolder();
			if (domainFolder == null) {
				String text = domainFilePanel.getText();
				if (text.isBlank()) {
					setValue(null);
					return;
				}
				throw new ValuesMapParseException(getName(), "Project Folder",
					"No folder found for \"" + text + "\"");
			}
			setValue(domainFolder);
		}
	}

	@Override
	protected void updateComponentFromValue() {

		if (domainFilePanel != null) {
			domainFilePanel.setDomainFolder(getValue());

		}
	}

	@Override
	protected DomainFolder fromString(String valueString) {
		DomainFolder df = AbstractProjectBrowserPanel.parseDomainFolder(project, valueString);
		if (df == null) {
			throw new IllegalArgumentException("Can't find domain folder: " + valueString);
		}
		return df;
	}

	@Override
	protected String toString(DomainFolder v) {
		return v.getPathname();
	}

	/**
	 * Component used by ProjectFolderValues for picking project folders
	 */
	class ProjectFolderBrowserPanel extends AbstractProjectBrowserPanel {

		ProjectFolderBrowserPanel(Project project, String name, String startPath) {
			super(DataTreeDialog.CHOOSE_FOLDER, project, name, startPath);
		}

		void setDomainFolder(DomainFolder value) {
			String text = value == null ? "" : value.getPathname();
			textField.setText(text);
		}

		@Override
		protected void intializeCurrentValue(DataTreeDialog dialog) {
			DomainFolder current = getDomainFolder();
			dialog.selectFolder(current);
		}

		@Override
		protected String getSelectedPath(DataTreeDialog dialog) {
			return dialog.getDomainFolder().getPathname();
		}

		DomainFolder getDomainFolder() {
			String text = textField.getText().trim();
			if (text.isBlank()) {
				return parseDomainFolder(project, "/");
			}
			return parseDomainFolder(project, text);
		}
	}

}
