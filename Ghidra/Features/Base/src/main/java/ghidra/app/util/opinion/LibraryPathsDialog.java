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
package ghidra.app.util.opinion;

import javax.swing.JComponent;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathnameTablePanel;
import ghidra.app.util.importer.LibrarySearchPathManager;

/**
 * Dialog for editing Library Search Paths which are used by the importer to locate referenced
 * shared libraries.
 */
public class LibraryPathsDialog extends DialogComponentProvider {

	private PathnameTablePanel tablePanel;

	public LibraryPathsDialog() {
		super("Edit Library Paths");
		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setPreferredSize(600, 400);
		setRememberSize(false);
	}

	private JComponent buildWorkPanel() {
		String[] libraryPaths = LibrarySearchPathManager.getLibraryPaths();
		tablePanel = new PathnameTablePanel(libraryPaths, false, true, () -> reset());
		// false=> not editable, true=> add new paths to top of the table

		tablePanel.setFileChooserProperties("Select Directory", "LibrarySearchDirectory",
			GhidraFileChooserMode.DIRECTORIES_ONLY, false, null);

		return tablePanel;
	}

	private void reset() {
		LibrarySearchPathManager.reset();
		tablePanel.setPaths(LibrarySearchPathManager.getLibraryPaths());
	}

	@Override
	protected void okCallback() {
		String[] paths = tablePanel.getPaths();
		LibrarySearchPathManager.setLibraryPaths(paths);
		close();
	}

}
