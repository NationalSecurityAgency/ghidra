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
package ghidra.app.plugin.core.datamgr.archive;

import java.awt.Component;
import java.io.File;
import java.io.IOException;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import docking.widgets.OptionDialog;
import ghidra.framework.store.LockException;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.DuplicateFileException;

public class ArchiveUtils {
	static final Logger log = LogManager.getLogger(ArchiveUtils.class);

	private ArchiveUtils() {
		// utils class
	}

	/**
	 * Saves the given archive to a file of the user's choosing.
	 * 
	 * @param component The component over which GUI message will be shown when required.
	 * @param archive The archive to save.
	 * @throws DuplicateFileException thrown in the case of a naming conflict.
	 * @throws IOException If the sky is falling.
	 */
	public static void saveAs(Component component, FileArchive archive)
			throws DuplicateFileException, IOException {
		File saveAsFile = getFile(component, archive);
		if (saveAsFile == null) {
			return;
		}

		if (saveAsFile.equals(archive.getFile())) {
			archive.save();
		}
		else {
			archive.saveAs(saveAsFile);
		}
	}

	/**
	 * This method will perform a save on the given archive.  However, the one caveat is that if
	 * the archive has never been saved, then a filename needs to be chosen.  Under this 'special'
	 * condition this method logically turns into a {@link #saveAs(Component, FileArchive)}.
	 * 
	 * @param component The component over which GUI message will be shown when required.
	 * @param archive The archive to save.
	 * @throws DuplicateFileException thrown only in the {@link #saveAs(Component, FileArchive)}
	 * 		   condition in the case of a naming conflict.
	 * @throws IOException If the sky is falling.
	 */
	public static void save(Component component, Archive archive)
			throws DuplicateFileException, IOException {
		if (!archive.isSavable()) {
			archive.saveAs(component);
		}
		else {
			archive.save();
		}
	}

	public static boolean canClose(List<Archive> archiveList, Component component) {
		for (Archive archive : archiveList) {
			if (!canClose(archive, component)) {
				return false;
			}
		}
		return true;
	}

	public static boolean lockArchive(FileArchive archive) {
		try {
			archive.acquireWriteLock();
			return true;
		}
		catch (ReadOnlyException e) {
			Msg.showError(log, null, "Unable to Lock File for Writing", e.getMessage());
		}
		catch (LockException exc) {
			Msg.showError(log, null, "Unable to Lock File for Writing",
				"Unable to obtain lock for archive: " + archive.getName() + "\n" +
					exc.getMessage());
		}
		catch (IOException ioe) {
			Msg.showError(log, null, "Unable to Lock File for Writing",
				"Problem attempting to lock archive: " + archive.getName() + "\n" +
					ioe.getMessage());
		}
		return false;
	}

// ==================================================================================================
//	Private methods
//==================================================================================================	

	static File getFile(Component component, FileArchive archive) {
		ArchiveFileChooser fileChooser = new ArchiveFileChooser(component);
		String archiveName = archive.getName();
		File file = fileChooser.promptUserForFile(archiveName);

		if (file == null) {
			return null;
		}
		if (file.equals(archive.getFile().getFile(false))) {
			return file;
		}

		if (archive.getArchiveManager().isInUse(file)) {
			Msg.showInfo(ArchiveUtils.class, component, "Cannot Perform Save As",
				"Cannot save archive to " + file.getName() + "\nbecause " + file.getName() +
					" is in use.");
			return null;
		}

		if (file.exists()) {
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(component,
				"Overwrite Existing File?", "Do you want to overwrite existing file\n" +
					file.getAbsolutePath()) != OptionDialog.OPTION_ONE) {
				return null;
			}

			if (!deleteArchiveFile(file)) {
				Msg.showError(log, component, "Error Deleting File",
					"Could not delete file " + file.getAbsolutePath());

				return null;
			}
		}

		return file;
	}

	private static boolean deleteArchiveFile(File file) {
		try {
			FileDataTypeManager.delete(file);
			return true;
		}
		catch (Exception e) {
			// try below
		}
		return file.delete();
	}

	public static boolean canClose(Archive archive, Component component) {
		if (!archive.isChanged()) {
			return true;
		}
		int result =
			OptionDialog.showYesNoCancelDialog(component, "Save Archive?", "Datatype Archive \"" +
				archive.getName() + "\" has been changed.\n Do you want to save the changes?");

		if (result == OptionDialog.CANCEL_OPTION) {
			return false;
		}
		if (result == OptionDialog.NO_OPTION) {
			if (archive instanceof FileArchive) {
				// Release the write lock without saving. Returns file archive to its unedited state.
				try {
					((FileArchive) archive).releaseWriteLock();
				}
				catch (IOException e) {
					Msg.showError(log, component, "Unable to release File Archive write lock.",
						e.getMessage(), e);
					return false;
				}
			}
			return true;
		}

		return saveArchive(archive, component);
	}

	private static boolean saveArchive(Archive archive, Component component) {
		try {
			ArchiveUtils.save(component, archive);
			return true;
		}
		catch (DuplicateFileException e) {
			Msg.showError(log, component, "Unable to Save Archive",
				"Archive already exists: " + archive, e);
		}
		catch (IOException e) {
			Msg.showError(log, component, "Unable to Save Archive",
				"Unexpected exception attempting to save archive: " + archive, e);
		}
		return false;
	}

}
