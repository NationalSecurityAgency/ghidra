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
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.store.FileSystem;

/**
 * Value class for project files ({@link DomainFile}). The editor component consists of the
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

	private ProjectBrowserPanel domainFilePanel;

	public ProjectFileValue(String name) {
		this(name, null);
	}

	public ProjectFileValue(String name, DomainFile defaultValue) {
		super(name, defaultValue);
	}

	@Override
	public JComponent getComponent() {
		if (domainFilePanel == null) {
			domainFilePanel = new ProjectBrowserPanel(getName(), false);
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
}
