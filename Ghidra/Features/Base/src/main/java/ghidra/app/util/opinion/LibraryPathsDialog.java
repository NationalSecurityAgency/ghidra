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

import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.AbstractPathsDialog;
import docking.widgets.pathmanager.PathnameTablePanel;
import ghidra.app.util.importer.LibrarySearchPathManager;

/**
 * Dialog for editing Library Search Paths which are used by the importer to locate referenced
 * shared libraries.
 */
public class LibraryPathsDialog extends AbstractPathsDialog {

	public LibraryPathsDialog() {
		super("Edit Library Paths");
	}

	@Override
	protected String[] loadPaths() {
		return LibrarySearchPathManager.getLibraryPaths();
	}

	@Override
	protected void savePaths(String[] paths) {
		LibrarySearchPathManager.setLibraryPaths(paths);
	}

	@Override
	protected PathnameTablePanel newPathnameTablePanel() {
		// disable edits, add to top, ordered
		PathnameTablePanel tablePanel =
			new PathnameTablePanel(null, this::reset, false, true, true);
		tablePanel.setFileChooserProperties("Select Directory or Filesystem",
			"LibrarySearchDirectory", GhidraFileChooserMode.FILES_AND_DIRECTORIES, false, null);
		return tablePanel;
	}

	@Override
	protected void reset() {
		LibrarySearchPathManager.reset();
		super.reset();
	}
}
