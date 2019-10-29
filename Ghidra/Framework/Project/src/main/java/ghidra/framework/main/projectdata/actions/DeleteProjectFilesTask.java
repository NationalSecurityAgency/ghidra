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
import java.util.Objects;
import java.util.Set;

import docking.widgets.OptionDialog;
import docking.widgets.OptionDialogBuilder;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Task for recursively deleting project files from a Ghidra project
 */
public class DeleteProjectFilesTask extends Task {

	private Component parent;
	private Set<DomainFile> selectedFiles;
	private Set<DomainFolder> selectedFolders;
	private OptionDialogBuilder readOnlyDialogBuilder;
	private OptionDialogBuilder checkedOutDialogBuilder;
	private OptionDialogBuilder versionedDialogBuilder;
	private OptionDialogBuilder fileInUseDialogBuilder;
	private FileCountStatistics statistics;

	/**
	 * Construct a new DeleteProjectFilesTask with the list of folders and files to delete.
	 *
	 * @param folders the fist of DomainFolders (and all files contained recursively 
	 * in those folders) to delete
	 * @param files the list of DomainFiles to delete
	 * @param fileCount the number of files being deleted
	 * @param parent the component to use for parenting any dialogs that are shown
	 */
	public DeleteProjectFilesTask(Set<DomainFolder> folders, Set<DomainFile> files, int fileCount,
			Component parent) {
		super("Delete Files", true, true, true);
		this.parent = parent;
		this.selectedFiles = Objects.requireNonNull(files);
		this.selectedFolders = Objects.requireNonNull(folders);
		this.statistics = new FileCountStatistics(fileCount);
	}

	@Override
	public void run(TaskMonitor monitor) {

		initializeMonitor(monitor);

		deleteFiles(selectedFiles, monitor);

		deleteFolders(selectedFolders, monitor);

		statistics.showReport(parent);
	}

	private void initializeMonitor(TaskMonitor monitor) {
		monitor.setMessage("Deleting Files...");
		monitor.initialize(statistics.getFileCount());
	}

	private void deleteFiles(Set<DomainFile> files, TaskMonitor monitor) {
		try {
			for (DomainFile file : files) {
				monitor.checkCanceled();
				deleteFile(file);
				monitor.incrementProgress(1);
			}
		}
		catch (CancelledException e) {
			// just return so that statistics for what completed can be displayed
		}
	}

	private void deleteFolders(Set<DomainFolder> folders, TaskMonitor monitor) {

		try {
			for (DomainFolder folder : folders) {
				deleteFolder(folder, monitor);
			}
		}
		catch (CancelledException e) {
			// just return so that statistics for what completed can be displayed
		}
	}

	private void deleteFolder(DomainFolder folder, TaskMonitor monitor) throws CancelledException {

		for (DomainFolder subFolder : folder.getFolders()) {
			monitor.checkCanceled();
			if (!selectedFolders.contains(subFolder)) {
				deleteFolder(subFolder, monitor);
			}
		}

		for (DomainFile file : folder.getFiles()) {
			monitor.checkCanceled();
			if (!selectedFiles.contains(file)) {
				deleteFile(file);
				monitor.incrementProgress(1);
			}
		}

		deleteEmptyFolder(folder);
	}

	private void deleteEmptyFolder(DomainFolder folder) {
		if (folder.isEmpty()) {
			try {
				folder.delete();
			}
			catch (IOException e) {
				Msg.error(this, "Unexpected error deleting empty folder: " + folder.getName(), e);
			}
		}
	}

	private void deleteFile(DomainFile file) throws CancelledException {
		if (file.isOpen()) {
			statistics.incrementFileInUse();
			showFileInUseDialog(file);
			return;
		}

		if (file.isVersioned() && file.isCheckedOut()) {
			showCheckedOutVersionedDialog(file);
			statistics.incrementCheckedOutVersioned();
			return;
		}

		if (file.isReadOnly()) {
			int result = showConfirmReadOnlyDialog(file);
			if (result == OptionDialog.CANCEL_OPTION) {
				throw new CancelledException();
			}
			if (result != OptionDialog.YES_OPTION) {
				statistics.incrementReadOnly();
				return;
			}
		}

		if (file.isVersioned()) {
			int result = showConfirmDeleteVersionedDialog(file);
			if (result == OptionDialog.CANCEL_OPTION) {
				throw new CancelledException();
			}
			if (result != OptionDialog.YES_OPTION) {
				statistics.incrementVersioned();
				return;
			}
		}

		try {
			file.delete();
			statistics.incrementDeleted();
		}
		catch (IOException e) {
			statistics.incrementGeneralFailure();
			OptionDialogBuilder builder = new OptionDialogBuilder("Delete File Failed",
				file.getName() + ": " + e.getMessage());
			int result =
				builder.addCancel().setMessageType(OptionDialog.ERROR_MESSAGE).show(parent);
			if (result == OptionDialog.CANCEL_OPTION) {
				throw new CancelledException();
			}
		}
	}

	private int showConfirmDeleteVersionedDialog(DomainFile file) {
		if (versionedDialogBuilder == null) {

			//@formatter:off
			versionedDialogBuilder = 
				new OptionDialogBuilder("Confirm Delete Versioned File")
				.addOption("Yes")
				.addOption("No")
				.addCancel()
				.setMessageType(OptionDialog.WARNING_MESSAGE)
				;
			//@formatter:on

			if (getFileCount() > 1) {
				versionedDialogBuilder.addApplyToAllOption();
			}
		}

		String msg =
			"The file \"" + file.getName() + "\" is a versioned file and if you continue, \n" +
				"it (and all its versions) will be PERMANENTLY deleted!\n" +
				"If this is a shared project, it will be deleted on the server (if permitted)\n" +
				"for ALL users (if permitted)!" + "\nAre you sure you want to delete it?";
		versionedDialogBuilder.setMessage(msg);
		return versionedDialogBuilder.show(parent);
	}

	private void showCheckedOutVersionedDialog(DomainFile file) throws CancelledException {
		if (checkedOutDialogBuilder == null) {

			//@formatter:off
			checkedOutDialogBuilder = 
				new OptionDialogBuilder("Delete Not Allowed")
				.addOption("OK")
				.addCancel()
				.setMessageType(OptionDialog.ERROR_MESSAGE)
				;
			//@formatter:on

			if (getFileCount() > 1) {
				checkedOutDialogBuilder.addDontShowAgainOption();
			}
		}

		String msg = "The file \"" + file.getName() +
			"\" is a versioned file that you have\n checked out. It can't be deleted!";
		checkedOutDialogBuilder.setMessage(msg);
		if (checkedOutDialogBuilder.show(parent) == OptionDialog.CANCEL_OPTION) {
			throw new CancelledException();
		}
	}

	private void showFileInUseDialog(DomainFile file) throws CancelledException {
		if (fileInUseDialogBuilder == null) {

			//@formatter:off
			fileInUseDialogBuilder = 
				new OptionDialogBuilder("Delete Not Allowed")
				.addOption("OK")
				.setMessageType(OptionDialog.ERROR_MESSAGE)
				.addCancel()
				;
			//@formatter:on

			if (getFileCount() > 1) {
				fileInUseDialogBuilder.addDontShowAgainOption();
			}
		}

		String msg =
			"The file \"" + file.getName() + "\" is currently in use. It can't \nbe deleted!";
		fileInUseDialogBuilder.setMessage(msg);
		if (fileInUseDialogBuilder.show(parent) == OptionDialog.CANCEL_OPTION) {
			throw new CancelledException();
		}
	}

	private int showConfirmReadOnlyDialog(DomainFile file) {
		if (readOnlyDialogBuilder == null) {

			//@formatter:off
			readOnlyDialogBuilder = 
					new OptionDialogBuilder("Confirm Delete Read-only File")
					.addOption("Yes")
					.addOption("No")
					.addCancel()
					.setMessageType(OptionDialog.WARNING_MESSAGE)
					.setDefaultButton("No")
					;
			//@formatter:on

			if (getFileCount() > 1) {
				readOnlyDialogBuilder.addApplyToAllOption();
			}
		}

		String msg = "The file \"" + file.getName() +
			"\" is marked as \"Read-Only\". \nAre you sure you want to delete it?";
		readOnlyDialogBuilder.setMessage(msg);
		return readOnlyDialogBuilder.show(parent);
	}

	public synchronized int getFileCount() {
		return statistics.getFileCount();
	}

	public synchronized int getTotalDeleted() {
		return statistics.getTotalDeleted();
	}

}
