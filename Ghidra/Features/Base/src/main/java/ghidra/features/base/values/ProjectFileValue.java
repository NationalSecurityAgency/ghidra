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
import ghidra.framework.store.FileSystem;

/**
 * Value class for project files ({@link DomainFile}). The editor component consists of a
 * {@link JTextField} and a browse button for bringing up a {@link DataTreeDialog} for picking
 * project files from the current project.
 * <P>
 * This class and other subclasses of {@link AbstractValue} are part of a subsystem for easily
 * defining a set of values that can be displayed in an input dialog ({@link ValuesMapDialog}).
 * Typically, these values are created indirectly using a {@link GValuesMap} which is then
 * given to the constructor of the dialog. However, an alternate approach is to create the
 * dialog without a ValuesMap and then use its {@link ValuesMapDialog#addValue(AbstractValue)} 
 * method directly.
 */
public class ProjectFileValue extends AbstractValue<DomainFile> {

	private ProjectFileBrowserPanel domainFilePanel;
	private String startingPath;
	private Project project;
	private Class<? extends DomainObject> projectFileClass;

	/**
	 * Constructor for creating a new ProjectFileValue with the given name.
	 * @param name the name of the value
	 */
	public ProjectFileValue(String name) {
		this(name, AppInfo.getActiveProject(), null, DomainObject.class);
	}

	/**
	 * Constructor for creating a new ProgramFileValue with the given name and {@link DomainObject}
	 * class to filter on (All other types will be filtered out in the chooser).
	 * @param name the name of the value
	 * @param projectFileClass the DomainObject class to filter
	 */
	public ProjectFileValue(String name, Class<? extends DomainObject> projectFileClass) {
		this(name, AppInfo.getActiveProject(), null, projectFileClass);
	}

	/**
	 * Constructor for creating a new ProjectFileValue with the given name and a starting
	 * folder when using the project file chooser.
	 * @param name the name of the value
	 * @param startingPath the path to a starting folder
	 */
	public ProjectFileValue(String name, String startingPath) {
		this(name, AppInfo.getActiveProject(), startingPath, DomainObject.class);
	}

	/**
	 * Constructor for ProgramValue when wanting to pick from a different project than the
	 * active project, such as a read-only project.
	 * @param name the name of the value
	 * @param project The project from which to pick a project.
	 * @param startingPath the path to a starting folder (Can also be a path to program)
	 * @param projectFileClass a {@link DomainFile} class to filter on. (Only those types
	 * will appear in the chooser)
	 */
	public ProjectFileValue(String name, Project project, String startingPath,
			Class<? extends DomainObject> projectFileClass) {
		super(name, null);
		this.project = project;
		this.startingPath = startingPath;
		this.projectFileClass = projectFileClass;
	}

	@Override
	public JComponent getComponent() {
		if (domainFilePanel == null) {
			domainFilePanel =
				new ProjectFileBrowserPanel(project, getName(), startingPath, projectFileClass);
		}
		return domainFilePanel;
	}

	@Override
	protected void updateValueFromComponent() throws ValuesMapParseException {
		if (domainFilePanel != null) {
			DomainFile domainFile = domainFilePanel.getDomainFile();
			if (domainFile == null) {
				String text = domainFilePanel.getText();
				if (text.isBlank()) {
					setValue(null);
					return;
				}
				throw new ValuesMapParseException(getName(), "Project File",
					"No file found for \"" + text + "\"");
			}
			Class<? extends DomainObject> domainObjectClass = domainFile.getDomainObjectClass();
			if (!projectFileClass.isAssignableFrom(domainObjectClass)) {
				throw new ValuesMapParseException(getName(), "Project File",
					"Selected path is not a " + projectFileClass.getSimpleName());
			}
			setValue(domainFile);
		}
	}

	@Override
	protected void updateComponentFromValue() {
		if (domainFilePanel != null) {
			domainFilePanel.setDomainFile(getValue());
		}
	}

	@Override
	protected DomainFile fromString(String valueString) {
		DomainFile df = parseDomainFile(valueString);
		if (df == null) {
			throw new IllegalArgumentException("Can't find domain file: " + valueString);
		}
		Class<? extends DomainObject> domainObjectClass = df.getDomainObjectClass();
		if (!projectFileClass.isAssignableFrom(domainObjectClass)) {
			throw new IllegalArgumentException(
				"Specified file path is not a " + projectFileClass.getSimpleName());
		}
		return df;
	}

	private DomainFile parseDomainFile(String val) {
		// Add the slash to make it an absolute path
		if (!val.isEmpty() && val.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			val = FileSystem.SEPARATOR_CHAR + val;
		}
		Project activeProject = AppInfo.getActiveProject();
		if (activeProject == null) {
			throw new IllegalStateException("No Active Project!");
		}
		DomainFile df = activeProject.getProjectData().getFile(val);
		if (df != null) {
			return df;
		}
		return null;
	}

	@Override
	protected String toString(DomainFile v) {
		return v.getPathname();
	}

	/**
	 * Component used by ProjectFileValues for picking project files
	 */
	class ProjectFileBrowserPanel extends AbstractProjectBrowserPanel {

		ProjectFileBrowserPanel(Project project, String name, String startPath,
				Class<? extends DomainObject> projectFileClass) {
			super(DataTreeDialog.OPEN, project, name, startPath);
			filter = df -> projectFileClass.isAssignableFrom(df.getDomainObjectClass());
		}

		void setDomainFile(DomainFile value) {
			String text = value == null ? "" : value.getPathname();
			textField.setText(text);
		}

		@Override
		protected void intializeCurrentValue(DataTreeDialog dialog) {
			DomainFile current = getDomainFile();
			if (current != null) {
				dialog.selectDomainFile(current);
				dialog.setNameText(current.getName());
			}
		}

		@Override
		protected String getSelectedPath(DataTreeDialog dialog) {
			return dialog.getDomainFile().getPathname();
		}

		DomainFile getDomainFile() {
			String text = textField.getText().trim();
			if (text.isBlank()) {
				return null;
			}
			return parseDomainFile(project, text);
		}
	}

}
