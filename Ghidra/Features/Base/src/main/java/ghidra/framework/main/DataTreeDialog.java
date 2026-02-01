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
package ghidra.framework.main;

import java.awt.Component;

import ghidra.framework.model.*;

/**
 * Dialog to open or save domain data items to a new location or name.
 */
public class DataTreeDialog extends AbstractDataTreeDialog {

	// These are here for backwards compatibility with legacy code
	public final static DataTreeDialogType OPEN = DataTreeDialogType.OPEN;
	public final static DataTreeDialogType SAVE = DataTreeDialogType.SAVE;
	public final static DataTreeDialogType CHOOSE_FOLDER = DataTreeDialogType.CHOOSE_FOLDER;
	public final static DataTreeDialogType CREATE = DataTreeDialogType.CREATE;

	/**
	 * Construct a new DataTreeDialog for the active project.  This chooser will show all project
	 * files and/or folders within the active project only. Broken and external links will not be
	 * shown.  If different behavior is required a filter should be specified using the other 
	 * constructor. 
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, CHOOSE_USER_FOLDER, or CREATE
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, DataTreeDialogType type) {
		this(parent, title, type, DomainFileFilter.ALL_INTERNAL_FILES_FILTER);
	}

	/**
	 * Construct a new DataTreeDialog for the active project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, or CREATE
	 * @param filter filter used to control what is displayed in the data tree.  See static
	 * implementations provided by {@link DomainFileFilter} and a more tailored 
	 * {@link DefaultDomainFileFilter}.
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, DataTreeDialogType type,
			DomainFileFilter filter) {
		this(parent, title, type, filter, AppInfo.getActiveProject());
	}

	/**
	 * Construct a new DataTreeDialog for the given project.
	 *
	 * @param parent dialog's parent
	 * @param title title to use
	 * @param type specify OPEN, SAVE, CHOOSE_FOLDER, or CREATE
	 * @param filter filter used to control what is displayed in the data tree.  See static
	 * implementations provided by {@link DomainFileFilter} and a more tailored 
	 * {@link DefaultDomainFileFilter}.
	 * @param project the project to browse
	 * @throws IllegalArgumentException if invalid type is specified
	 */
	public DataTreeDialog(Component parent, String title, DataTreeDialogType type,
			DomainFileFilter filter, Project project) {
		super(parent, title, type, filter, project);

		addWorkPanel(buildDataTreePanel());
		initializeFocusedComponent();
	}

}
