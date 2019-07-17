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
package ghidra.framework.main.projectdata.actions;

import java.awt.Component;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.*;
import java.util.Map.Entry;

import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import utilities.util.FileUtilities;

/**
 * {@link Task} that handles deleting {@link DomainFile files} and {@link DomainFolder folders}
 * from the project.
 * <p>
 * This task will iterate all the files and folders specified by the user to weed out
 * common problem issues (read-only files, checked-out files), ask the user to confirm,
 * and then perform the actual delete operations.
 * <p>
 * This task will show a summary dialog if there were multiple files involved or any errors
 * encountered.
 * <p>
 */
public class ProjectDataDeleteTask extends Task {

	private Component parentComponent;

	private List<DomainFile> startFiles;
	private List<DomainFolder> startFolders;

	/**
	 * Files that failed during the preprocess phase because they were checked out
	 */
	private Set<DomainFile> failPreprocessCheckedOut = new HashSet<>();

	/**
	 * Files that failed during the preprocess phase because they were marked read-only.
	 */
	private Set<DomainFile> failPreprocessReadOnly = new HashSet<>();

	/**
	 * A lookup {@link Set set} of the {@link #failPreprocessReadOnly read-only} files
	 * found during the preprocess phase, if the user has chosen to override the read-only
	 * status.
	 */
	private Set<DomainFile> readOnlyOverride = new HashSet<>();

	/**
	 * The files that are queued up to be deleted, pointing to the string error message
	 * that was encountered during the actual delete operation, or null if no error.
	 */
	private Map<DomainFile, String> filesToDelete = new LinkedHashMap<>();

	/**
	 * The folders that are queued up to be deleted  , pointing to the string error message
	 * that was encountered during the actual delete operation, or null if no error.
	 */
	private Map<DomainFolder, String> foldersToDelete = new LinkedHashMap<>();

	/**
	 * The number of files that encountered an error during the delete operation.
	 */
	private int erroredFileCount;

	/**
	 * The number of folders that encountered an error during the delete operation.
	 */
	private int erroredFolderCount;

	/**
	 * The number of milliseconds used during preprocessing and delete operations.
	 */
	private long elapsedTime;

	/**
	 * Count of the number of bytes occupied by files that were successfully deleted.
	 */
	private long fileBytesDeleted;

	/**
	 * Creates a new task to delete the specified files and folders.
	 *
	 * @param files - the {@link DomainFile files} the user requested to be deleted, or null.
	 * @param folders - the {@link DomainFolder folders} the user requested to be deleted, or null.
	 * @param parentComponent - parent java awt component that will be parent of the message dialogs and such.
	 */
	public ProjectDataDeleteTask(List<DomainFile> files, List<DomainFolder> folders,
			Component parentComponent) {
		super("Delete Files", true, true, true);

		this.parentComponent = parentComponent;
		this.startFiles = files != null ? files : Collections.emptyList();
		this.startFolders = folders != null ? folders : Collections.emptyList();
	}

	@Override
	public void run(TaskMonitor monitor) {

		// Check all files directly given to this task
		if (!preprocessStartFilesAndFolders(monitor)) {
			return;
		}

		// If there are problems, ask the user what to do
		if (!failPreprocessReadOnly.isEmpty()) {
			int option = OptionDialog.showOptionDialog(parentComponent, "Delete Read-only Files?",
				"<html>There were " + failPreprocessReadOnly.size() +
					" read-only files found in the requested set of files.  Override the read-only status and delete?",
				"Delete Read-only Files", "Continue and Skip Read-only Files",
				OptionDialog.QUESTION_MESSAGE);
			switch (option) {
				case OptionDialog.OPTION_ONE:// Delete read-only files
					for (DomainFile f : failPreprocessReadOnly) {
						filesToDelete.put(f, null);
					}
					readOnlyOverride.addAll(failPreprocessReadOnly);
					failPreprocessReadOnly.clear();
					break;
				case OptionDialog.OPTION_TWO:// Continue and skip
					// nada
					break;
				case OptionDialog.CANCEL_OPTION:
					// stop delete task
					return;
			}
		}
		if (!failPreprocessCheckedOut.isEmpty()) {
			if (!confirmUserSkipFailedPreprocessedFiles()) {
				return;
			}
		}

		if (filesToDelete.isEmpty() && foldersToDelete.isEmpty()) {
			Msg.showInfo(this, parentComponent, "Delete finished", "Nothing to do, finished.");
			return;
		}

		if (!confirmDeleteFiles()) {
			return;
		}

		try {
			deleteFiles(monitor);
			deleteFolders(monitor);
		}
		catch (CancelledException ce) {
			Msg.info(this, "Canceled delete");
		}

		if (hasErrors()) {
			showErrorSummary(monitor.isCancelled());
		}
	}

	private boolean hasErrors() {
		return erroredFileCount > 0 || erroredFolderCount > 0;
	}

	private boolean confirmUserSkipFailedPreprocessedFiles() {

		String msg = "<html><div style='margin-bottom: 20pt; text-align: center;'>There were " +
			failPreprocessCheckedOut.size() +
			" versioned and checked-out files in the requested set of files that cannot be deleted.</div>" +
			"<div style='margin-bottom: 20pt; text-align: center;'>Skip these files and continue or cancel delete operation?</div>";

		if (OptionDialog.showOptionDialog(parentComponent, "Continue and Skip Problem Files?", msg,
			"Skip and Continue") != OptionDialog.OPTION_ONE) {
			return false;
		}

		return true;
	}

	private boolean confirmDeleteFiles() {

		int fileCount = filesToDelete.size();
		String files = fileCount != 1 ? fileCount + " files" : " 1 file";
		if (!foldersToDelete.isEmpty()) {
			int folderCount = foldersToDelete.size();
			files += folderCount > 1 ? " and " + folderCount + " folders" : " and 1 folder";
		}

		StringBuilder buffy = new StringBuilder("<html>");
		buffy.append("<div style='font-size: 110%; text-align: center;'>");
		buffy.append("<span>");
		buffy.append("Are you sure you want to <u>permanently</u> delete " + files + "?");
		buffy.append("</span><br><br>");

		buffy.append("<span style='color: red;'>");
		buffy.append("There is no undo operation!");
		buffy.append("</span>");
		buffy.append("</div>");

		/*
		msg +=
			"<div style='margin-bottom: 20pt; font-size: 110%; text-align: center; color: red;'>Are you sure you want to permanently delete these files?</div>" +
				"<div style='margin-bottom: 20pt; text-align: center; font-weight: bold;'>There is no undo operation</div>";
				*/

		int choice = OptionDialog.showOptionDialog(parentComponent, "Confirm Delete Files?",
			buffy.toString(), "Delete Files", OptionDialog.QUESTION_MESSAGE, "Cancel");
		return choice == OptionDialog.OPTION_ONE;
	}

	private void showErrorSummary(boolean wasCancelled) {
		int successFileCount = filesToDelete.size() - erroredFileCount;
		int successFolderCount = foldersToDelete.size() - erroredFolderCount;

		//@formatter:off
		String msg =
			"<html><div>Status: " + (wasCancelled ? "Canceled" : "Finished") +" with errors" +"</div>" +
			"<div style='margin-bottom: 20pt;'>Elapsed time: " + DateUtils.formatDuration(elapsedTime) + "</div>" +
			"<table style='margin-bottom: 20pt;' width='100%'>" +
			"<tr><td></td><td style='text-align: center'>Successful</td><td style='text-align: center'>Errored</td><td style='text-align: center'>Bytes</td></tr>" +
			"<tr><td>Files</td><td style='text-align: center'>" + successFileCount + "</td><td style='text-align: center'>" + erroredFileCount + "</td><td style='text-align: center'>" + FileUtilities.formatLength(fileBytesDeleted) + "</td></tr>" +
			"<tr><td>Folders</td><td style='text-align: center'>" + successFolderCount + "</td><td style='text-align: center'>" + erroredFolderCount + "</td><td></td></tr>" +
			"</table>" +
			"</div></body></html>";
		//@formatter:on

		boolean hasErrors = erroredFileCount > 0 || erroredFolderCount > 0;
		SystemUtilities.runSwingLater(() -> showResults(hasErrors, msg));
	}

	private void showResults(boolean hasErrors, String msg) {
		if (!hasErrors) {
			MultiLineMessageDialog.showModalMessageDialog(parentComponent, "Delete Summary", "",
				msg, MultiLineMessageDialog.INFORMATION_MESSAGE);
			return;
		}

		int option = OptionDialog.showOptionNoCancelDialog(parentComponent, "Delete Summary", msg,
			"OK", "Log Errored Files", OptionDialog.INFORMATION_MESSAGE);
		if (option == OptionDialog.OPTION_TWO) {
			for (Entry<DomainFile, String> entry : filesToDelete.entrySet()) {
				if (entry.getValue() != null) {
					Msg.error(this, "Delete file failed for " + entry.getKey().getPathname() +
						": " + entry.getValue());
				}
			}
			for (Entry<DomainFolder, String> entry : foldersToDelete.entrySet()) {
				if (entry.getValue() != null) {
					Msg.error(this, "Delete folder failed for " + entry.getKey().getPathname() +
						": " + entry.getValue());
				}
			}
		}
	}

	/**
	 * Attempts to delete the folders listed in {@link #foldersToDelete} (in reverse
	 * lexical order to delete child folders first before attempting to delete the
	 * containing parent folders).
	 * <p>
	 * Errors are saved into {@link #foldersToDelete} as the value that the folder maps to.
	 * <p>
	 * @param monitor
	 * @throws CancelledException
	 */
	private void deleteFolders(TaskMonitor monitor) throws CancelledException {

		long start_ts = System.currentTimeMillis();

		try {
			monitor.initialize(foldersToDelete.size());
			monitor.setMessage("Deleting directories...");
			List<DomainFolder> sortedFolders = new ArrayList<>(foldersToDelete.keySet());
			Collections.sort(sortedFolders,
				(o1, o2) -> o2.getPathname().compareTo(o1.getPathname()));
			for (DomainFolder folder : sortedFolders) {
				monitor.checkCanceled();
				try {
					folder.delete();
					monitor.incrementProgress(1);
				}
				catch (IOException e) {
					foldersToDelete.put(folder, e.getMessage());
					erroredFolderCount++;
				}
			}
		}
		finally {
			long end_ts = System.currentTimeMillis();
			elapsedTime += (end_ts - start_ts);
		}
	}

	/**
	 * Attempts to delete the files listed in {@link #filesToDelete}.
	 * <p>
	 * Errors are saved into {@link #filesToDelete} as the value that the file maps to.
	 * <p>
	 * @param monitor
	 * @throws CancelledException
	 */
	private void deleteFiles(TaskMonitor monitor) throws CancelledException {

		long start = System.currentTimeMillis();

		try {
			monitor.initialize(filesToDelete.size());
			monitor.setMessage("Deleting files...");

			List<DomainFile> snapshot = new ArrayList<>(filesToDelete.keySet());
			for (DomainFile file : snapshot) {
				monitor.checkCanceled();
				try {
					if (file.isReadOnly() && !readOnlyOverride.contains(file)) {
						// shouldn't happen normally because pre-process filters these out
						throw new IOException("File is marked read-only");
					}
					long len = file.length();
					file.delete();
					fileBytesDeleted += len;
				}
				catch (IOException e) {
					if (e instanceof RemoteException) {
						Msg.showError(this, null, "Delete File Failed", e.getMessage(), e);
					}
					filesToDelete.put(file, e.getMessage());
					erroredFileCount++;
				}
			}
		}
		finally {
			long end = System.currentTimeMillis();
			elapsedTime += (end - start);
		}
	}

	/**
	 * Iterates over the user-supplied files and folders, saving the discovered files and
	 * subfolders and their files into {@link #filesToDelete} and {@link #foldersToDelete}.
	 *
	 * @param monitor
	 * @return
	 */
	private boolean preprocessStartFilesAndFolders(TaskMonitor monitor) {
		try {
			long start_ts = System.currentTimeMillis();

			monitor.initialize(startFiles.size());
			monitor.setMessage("Checking files");
			for (DomainFile file : startFiles) {
				monitor.checkCanceled();
				preprocessFile(file, monitor);
				monitor.incrementProgress(1);
			}

			// Recursively check all files in the folders given to this task.
			monitor =
				new UnknownProgressWrappingTaskMonitor(monitor, Math.max(startFolders.size(), 1));
			monitor.setMessage("Checking folders");
			for (DomainFolder folder : startFolders) {
				monitor.checkCanceled();
				preprocessFolder(folder, monitor);
			}

			long end_ts = System.currentTimeMillis();
			elapsedTime += (end_ts - start_ts);

			return true;
		}
		catch (CancelledException ce) {
			return false;
		}
	}

	private void preprocessFolder(DomainFolder folder, TaskMonitor monitor)
			throws CancelledException {
		if (foldersToDelete.containsKey(folder)) {
			return;
		}

		monitor.setMessage("Checking " + folder.getPathname());
		foldersToDelete.put(folder, null);
		for (DomainFile file : folder.getFiles()) {
			monitor.checkCanceled();
			preprocessFile(file, monitor);
			monitor.incrementProgress(1);
		}

		for (DomainFolder subFolder : folder.getFolders()) {
			monitor.checkCanceled();
			preprocessFolder(subFolder, monitor);
		}
	}

	private void preprocessFile(DomainFile file, TaskMonitor monitor) {
		if (filesToDelete.containsKey(file)) {
			return;
		}

		if (file.isVersioned() && file.isCheckedOut()) {
			failPreprocessCheckedOut.add(file);
			return;
		}
		if (file.isReadOnly()) {
			failPreprocessReadOnly.add(file);
			return;
		}

		filesToDelete.put(file, null);
	}

}
