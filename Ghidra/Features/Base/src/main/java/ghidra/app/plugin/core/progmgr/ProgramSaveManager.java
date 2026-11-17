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
package ghidra.app.plugin.core.progmgr;

import static ghidra.framework.main.DataTreeDialogType.*;

import java.awt.event.ActionListener;
import java.io.IOException;
import java.rmi.ConnectException;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class ProgramSaveManager {
	private ProgramManager programMgr;
	private PluginTool tool;
	private boolean treeDialogCancelled;
	private DomainFileFilter programFileFilter;

	ProgramSaveManager(PluginTool tool, ProgramManager programMgr) {
		this.tool = tool;
		this.programMgr = programMgr;
		programFileFilter = new DefaultDomainFileFilter(Program.class, true);
	}

	/**
	 * Checks the given program for changes and performs the save if necessary.  The user
	 * is prompted before the save is performed.
	 * @param program program to be closed
	 * @return true if the program can be closed, or false if the operation was cancelled by
	 * the user
	 */
	boolean canClose(Program program) {
		if (!isOnlyToolConsumer(program)) {
			return true;
		}
		if (acquireSaveLock(program, "Close")) {
			try {
				return handleChangedProgram(program);
			}
			finally {
				program.unlock();
			}
		}
		return false;
	}

	private boolean isOnlyToolConsumer(Program program) {
		List<?> consumers = program.getDomainFile().getConsumers();
		for (Object consumer : consumers) {
			if ((consumer instanceof PluginTool) && consumer != tool) {
				return false;
			}
		}
		return true;
	}

	void saveProgram(Program program) {
		if (program == null) {
			return;
		}
		if (program.canSave()) {
			save(program);
		}
		else {
			saveAs(program);
		}
	}

	private void save(Program p) {
		save(p, null);
	}

	boolean save(Program program, TaskMonitor monitor) {

		tool.prepareToSave(program);
		if (!acquireSaveLock(program, "Save")) {
			return false;
		}

		try {
			DomainFile df = program.getDomainFile();
			SaveFileTask task = new SaveFileTask(df);

			if (monitor != null) {
				task.run(monitor);
			}
			else {
				TaskLauncher.launch(task);
			}

			return task.getSuccess();
		}
		finally {
			program.unlock();
		}
	}

	void saveAs(Program program) {
		if (!getSaveAsLock(program)) {
			return;
		}
		try {
			DataTreeDialog dialog = getSaveDialog();
			DomainFile domainFile = program.getDomainFile();
			String filename = domainFile.getName();
			dialog.setTitle("Save As (" + filename + ")");
			dialog.setNameText(filename + ".1");

			DomainFolder parent = domainFile.getParent();
			dialog.setSelectedFolder(parent);

			treeDialogCancelled = true;
			tool.showDialog(dialog);
			if (!treeDialogCancelled) {
				saveAs(program, dialog.getDomainFolder(), dialog.getNameText());
			}
		}
		finally {
			program.unlock();
		}
	}

	private void saveAs(Program currentProgram, DomainFolder folder, String name) {
		DomainFile existingFile = folder.getFile(name);
		if (existingFile == currentProgram.getDomainFile()) {
			save(currentProgram);
			return;
		}
		if (existingFile != null) {
			String msg = existingFile.getContentType() + " file " + name + " already exists.\n" +
				"Do you want to overwrite it?";
			if (OptionDialog.showOptionDialog(tool.getToolFrame(), "Duplicate Name", msg,
				"Overwrite", OptionDialog.QUESTION_MESSAGE) == OptionDialog.CANCEL_OPTION) {
				return;
			}
		}
		tool.prepareToSave(currentProgram);
		SaveAsTask task = new SaveAsTask(currentProgram, folder, name, existingFile != null);
		new TaskLauncher(task, tool.getToolFrame());
	}

	private boolean handleChangedProgram(Program currentProgram) {
		if (!currentProgram.isChanged()) {
			return true;
		}

		DomainFile df = currentProgram.getDomainFile();
		String filename = df.getName();
		if (!df.isInWritableProject()) {
			return OptionDialog.showOptionDialog(tool.getToolFrame(), "Program Changed",
				HTMLUtilities.lineWrapWithHTMLLineBreaks(
					"<html>Viewed file '" + HTMLUtilities.escapeHTML(filename) +
						"' has been changed.  \n" + "If you continue, your changes will be lost!"),
				"Continue", OptionDialog.QUESTION_MESSAGE) != OptionDialog.CANCEL_OPTION;
		}

		if (df.isReadOnly()) {
			return OptionDialog.showOptionDialog(tool.getToolFrame(), "Program Changed",
				HTMLUtilities.lineWrapWithHTMLLineBreaks(
					"<html>Read-only file '" + HTMLUtilities.escapeHTML(filename) +
						"' has been changed.  \n" + "If you continue, your changes will be lost!"),
				"Continue", OptionDialog.QUESTION_MESSAGE) != OptionDialog.CANCEL_OPTION;

		}

		int choice = OptionDialog.showOptionDialog(tool.getToolFrame(), "Save Program?",
			HTMLUtilities.lineWrapWithHTMLLineBreaks("<html>" + HTMLUtilities.escapeHTML(filename) +
				" has changed.\nDo you want to save it?"),
			"&Save", "Do&n't Save", OptionDialog.QUESTION_MESSAGE);

		if (choice == OptionDialog.CANCEL_OPTION) {
			return false;
		}
		if (choice == OptionDialog.OPTION_ONE) {
			SaveFileTask task = new SaveFileTask(currentProgram.getDomainFile());
			new TaskLauncher(task, tool.getToolFrame());
		}
		return true;
	}

	private boolean acquireSaveLock(Program program, String actionName) {
		if (!program.lock(null)) {
			String title = actionName + " Program" + " (Busy)";
			StringBuilder buf = new StringBuilder();
			buf.append(
				"The Program is currently being modified by the following actions/tasks:\n ");
			TransactionInfo t = program.getCurrentTransactionInfo();
			List<String> list = t.getOpenSubTransactions();
			for (String element : list) {
				buf.append("\n     ");
				buf.append(element);
			}
			buf.append("\n \n");
			buf.append("WARNING! The above task(s) should be cancelled before attempting a " +
				actionName + ".\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append(
				"If you continue, all changes made by these tasks, as well as any other overlapping task,\n");
			buf.append(
				"will be LOST and subsequent transaction errors may occur while these tasks remain active.\n \n");

			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title, buf.toString(),
				actionName + "!", OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				program.forceLock(true, "Save Program");
				return true;
			}
			return false;
		}
		return true;
	}

	private boolean getSaveAsLock(Program program) {
		if (!program.lock(null)) {
			String title = "Save Program As (Busy)";
			StringBuffer buf = new StringBuffer();
			buf.append(
				"The Program is currently being modified by the following actions/tasks:\n ");
			TransactionInfo t = program.getCurrentTransactionInfo();
			List<String> list = t.getOpenSubTransactions();
			for (String element : list) {
				buf.append("\n     ");
				buf.append(element);
			}
			buf.append("\n \n");
			buf.append(
				"WARNING! The above task(s) should be cancelled before attempting a Save As...\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append("If you click 'Save As (Rollback)' {recommended}, all changes made\n");
			buf.append("by these tasks, as well as any other overlapping task, will be LOST!\n");
			buf.append(
				"If you click 'Save As (As Is)', the program will be saved in its current\n");
			buf.append("state which may contain some incomplete data.\n");
			buf.append("Any forced save may also result in subsequent transaction errors while\n");
			buf.append("the above tasks remain active.\n ");

			int result = OptionDialog.showOptionDialog(tool.getToolFrame(), title, buf.toString(),
				"Save As (Rollback)!", "Save As (As Is)!", OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				program.forceLock(true, "Save Program As");
				return true;
			}
			else if (result == OptionDialog.OPTION_TWO) {
				program.forceLock(false, "Save Program As");
				return true;
			}
			return false;
		}
		return true;
	}

	private DataTreeDialog getSaveDialog() {
		DataTreeDialog dialog = new DataTreeDialog(null, "Save As", SAVE, programFileFilter);

		ActionListener listener = event -> {
			DomainFolder folder = dialog.getDomainFolder();
			String newName = dialog.getNameText();
			if (newName.length() == 0) {
				dialog.setStatusText("Please enter a name");
				return;
			}
			else if (folder == null) {
				dialog.setStatusText("Please select a folder");
				return;
			}

			DomainFile file = folder.getFile(newName);
			if (file != null && file.isReadOnly()) {
				dialog.setStatusText("Read Only.  Choose new name/folder");
			}
			else {
				dialog.close();
				treeDialogCancelled = false;
			}
		};

		dialog.addOkActionListener(listener);
		dialog.setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Save_As_File"));

		return dialog;
	}

	private class SaveFileTask extends Task {

		private DomainFile domainFile;
		private volatile boolean success;

		SaveFileTask(DomainFile df) {
			super("Save Program", true, true, true);
			this.domainFile = df;
		}

		boolean getSuccess() {
			return success;
		}

		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Saving Program...");
			try {
				domainFile.save(monitor);
				success = true;
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (NotConnectedException e) {
				ClientUtil.promptForReconnect(tool.getProject().getRepository(),
					tool.getToolFrame());
			}
			catch (ConnectException e) {
				ClientUtil.promptForReconnect(tool.getProject().getRepository(),
					tool.getToolFrame());
			}
			catch (IOException e) {
				ClientUtil.handleException(tool.getProject().getRepository(), e, "Save File",
					tool.getToolFrame());
			}
		}
	}

	private class SaveAsTask extends Task {

		private DomainFolder parentFolder;
		private String newName;
		private DomainObject domainObj;
		private boolean doOverwrite;

		/**
		 * Construct new SaveFileTask to do a "Save As"
		 * @param obj the object to save
		 * @param folder new parent folder
		 * @param newName name for domain object
		 * @param doOverwrite true means the given name already exists and the user
		 * wants to overwrite that existing file; false means a new file will
		 * get created
		 */
		SaveAsTask(DomainObject obj, DomainFolder folder, String newName, boolean doOverwrite) {

			super("Save Program As", true, true, true);
			parentFolder = folder;
			this.newName = newName;
			domainObj = obj;
			this.doOverwrite = doOverwrite;
		}

		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Saving Program...");
			try {
				if (doOverwrite) {
					DomainFile df = parentFolder.getFile(newName);
					if (df != null) {
						df.delete();
					}
				}
				parentFolder.createFile(newName, domainObj, monitor);
			}
			catch (CancelledException e) {
				// ignore
			}
			catch (IOException e) {
				Msg.showError(this, null, "Program SaveAs Error", e.getMessage());
			}
			catch (InvalidNameException e) {
				Msg.showError(this, null, "Program SaveAs Error", e.getMessage());
			}
			catch (Throwable e) {
				Msg.showError(this, null, "Program SaveAs Error", e.getMessage(), e);
			}
		}
	}
}
