/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.framework.GenericRunInfo;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.filechooser.ExtensionFileFilter;

import java.awt.Component;
import java.io.File;

import docking.widgets.filechooser.GhidraFileChooser;

public class ArchiveFileChooser extends GhidraFileChooser {

	public ArchiveFileChooser(Component component) {
		super(component);

		setFileFilter(new ExtensionFileFilter(new String[] { FileDataTypeManager.EXTENSION },
			"Ghidra Data Type Files"));
		setApproveButtonText("Save As");
		setApproveButtonToolTipText("Save As");
	}

	/**
	 * Shows this filechooser and uses the given suggested filename as the default filename
	 * @param suggestedFileName The default name to show in the name field
	 * @return the file selected by the user, or null if no selection was made
	 */
	public File promptUserForFile(String suggestedFileName) {
		File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());

		String lastNewArchivePath =
			Preferences.getProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY, null, true);
		if (lastNewArchivePath != null) {
			projectDirectory = new File(lastNewArchivePath);
		}
		setCurrentDirectory(projectDirectory);

		String suggestedName = suggestedFileName + FileDataTypeManager.SUFFIX;
		setSelectedFile(new File(projectDirectory, suggestedName));

		File file = getSelectedFile();
		if (file == null) {
			return null;
		}
		file = fixFilenameSuffix(file);
		Preferences.setProperty(Preferences.LAST_OPENED_ARCHIVE_DIRECTORY, file.getParent());
		Preferences.store();

		return file;
	}

	private File fixFilenameSuffix(File file) {
		String filename = file.getName();
		if (filename.endsWith(FileDataTypeManager.SUFFIX)) {
			return file;
		}
		filename += FileDataTypeManager.SUFFIX;
		return new File(file.getParentFile(), filename);
	}
}
