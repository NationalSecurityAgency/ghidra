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

import java.awt.event.ActionListener;
import java.io.IOException;
import java.rmi.ConnectException;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.SaveDataDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

class ProgramSaveManager {
	private ProgramManager programMgr;
	private PluginTool tool;
	private DataTreeDialog dataTreeSaveDialog;
	private boolean treeDialogCancelled;
	private DomainFileFilter domainFileFilter;

	ProgramSaveManager(PluginTool tool, ProgramManager programMgr) {
		this.tool = tool;
		this.programMgr = programMgr;
		domainFileFilter = f -> {
			Class<?> c = f.getDomainObjectClass();
			return Program.class.isAssignableFrom(c);
		};
	}

	/**
	 * Checks the given program for changes and performs the save if necessary.  The user
	 * is prompted before the save is performed.
	 * @param program program to be closed
	 * @return true if the program can be closed, or false if the operation was cancelled by
	 * the user
	 */
	boolean canClose(Program program) {
		if (program == null ||
			(program.getDomainFile().getConsumers().size() > 1 && !tool.hasToolListeners())) {
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

	boolean canCloseAll() {
		Program[] programs = programMgr.getAllOpenPrograms();
		List<Program> saveList = new ArrayList<>();
		List<Program> lockList = new ArrayList<>();
		try {
			for (int i = 0; i < programs.length; i++) {
//				if (programs[i].isTemporary()) {
//					continue;
//				}
				if (isOnlyToolConsumer(programs[i])) {
					if (!acquireSaveLock(programs[i], "Close")) {
						return false;
					}
					lockList.add(programs[i]);
					saveList.add(programs[i]);
				}
				else if (isAnalysisTool(programs[i])) {
					if (!acquireSaveLock(programs[i], "Close")) {
						return false;
					}
					lockList.add(programs[i]);
				}
			}

			return saveChangedPrograms(saveList);
		}
		finally {
			Iterator<Program> it = lockList.iterator();
			while (it.hasNext()) {
				Program p = it.next();
				p.unlock();
			}
		}
	}

	private boolean isOnlyToolConsumer(Program program) {
		ArrayList<?> consumers = program.getDomainFile().getConsumers();
		for (Object consumer : consumers) {
			if ((consumer instanceof PluginTool) && consumer != tool) {
				return false;
			}
		}
		return true;
	}

	private boolean isAnalysisTool(Program program) {
		AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
		return tool == analysisManager.getAnalysisTool();
	}

	/**
	 * Saves all programs that have changes
	 *
	 */
	public void saveChangedPrograms() {
		int saveCnt = 0;
		int unsavedCnt = 0;
		Program[] programs = programMgr.getAllOpenPrograms();
		for (Program program : programs) {
			if (program.isChanged()) {
				if (program.canSave()) {
					save(program);
					++saveCnt;
				}
				else {
					++unsavedCnt;
				}
			}
		}
		if (saveCnt != 0) {
			Msg.showInfo(getClass(), tool.getToolFrame(), "Save All...",
				"Saved " + saveCnt + " modified programs.");
		}
		if (unsavedCnt != 0) {
			Msg.showWarn(getClass(), tool.getToolFrame(), "Save All...",
				"Unable to save " + unsavedCnt + " read-only programs!");
		}
	}

	/**
	 * Prompt user for programs to be saved.
	 * Caller must already have lock on all programs contained within the list.
	 * @return true if it is safe to close tool
	 */
	private boolean saveChangedPrograms(List<Program> openProgramList) {
		SaveDataDialog saveDataDialog = new SaveDataDialog(tool);

		// don't modify the original list, as it is used by the caller to perform cleanup
		List<Program> saveProgramsList = new ArrayList<>(openProgramList);

		// make sure we have some files to save
		List<DomainFile> domainFilesToSaveList = new ArrayList<>();
		Iterator<Program> iter = saveProgramsList.iterator();
		while (iter.hasNext()) {
			Program program = iter.next();
			DomainFile domainFile = program.getDomainFile();
			if (!domainFile.isChanged()) {
				iter.remove();
			}
			else {
				domainFilesToSaveList.add(domainFile);
			}
		}

		if (saveProgramsList.size() == 0) {
			return true;
		}
		// calling can close here ensures that we use the same dialog for single files
		else if (saveProgramsList.size() == 1) {
			return canClose(saveProgramsList.get(0));
		}

		return saveDataDialog.showDialog(domainFilesToSaveList);
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

	private void save(Program program) {

		tool.prepareToSave(program);
		if (acquireSaveLock(program, "Save")) {

			try {
				SaveFileTask task = new SaveFileTask(program.getDomainFile());
				new TaskLauncher(task, tool.getToolFrame());
			}
			finally {
				program.unlock();
			}
		}
	}

	void saveAs(Program program) {
		if (!getSaveAsLock(program)) {
			return;
		}
		try {
			DataTreeDialog dialog = getSaveDialog();
			String filename = program.getDomainFile().getName();
			dialog.setTitle("Save As (" + filename + ")");
			dialog.setNameText(filename + ".1");
			dialog.setSelectedFolder(program.getDomainFile().getParent());
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
			String msg = "Program " + name + " already exists.\n" + "Do you want to overwrite it?";
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

		int result = OptionDialog.showOptionDialog(tool.getToolFrame(), "Save Program?",
			HTMLUtilities.lineWrapWithHTMLLineBreaks("<html>" + HTMLUtilities.escapeHTML(filename) +
				" has changed.\nDo you want to save it?"),
			"&Save", "Do&n't Save", OptionDialog.QUESTION_MESSAGE);

		if (result == OptionDialog.CANCEL_OPTION) {
			return false;
		}
		if (result == OptionDialog.OPTION_ONE) {
			SaveFileTask task = new SaveFileTask(currentProgram.getDomainFile());
			new TaskLauncher(task, tool.getToolFrame());
		}
		return true;
	}

//	public boolean askUserToAbort(Program currentProgram) {
//		String title = "Save "+currentProgram.getName();
//		String closeItem = closingProgram ? "program" : "tool";
//		String filename = currentProgram.getDomainFile().getPathname();
//		StringBuffer buf = new StringBuffer(); 
//		buf.append("The program ("+filename+") is currently being modified by the\n");
//		buf.append("the following actions:\n \n");
//		ProgramDB program = (ProgramDB)currentProgram;
//		Transaction t = program.getCurrentTransaction();
//		ArrayList list = t.getOpenSubTransactions();
//		Iterator it = list.iterator();
//		while(it.hasNext()) {
//			buf.append("\n     ");
//			buf.append((String)it.next());
//		}
//		buf.append("\n \n");
//		buf.append("In order to close the ");
//		buf.append(closeItem);
//		buf.append(", all actions must be aborted.\n");
//		buf.append("If you abort the actions, all changes made by those actions\n");
//		buf.append("will be lost!.\n \n");
//		buf.append("Do you want to abort the actions and continue to close the ");
//		buf.append(closeItem);
//		buf.append("?");
//			
//		int result = OptionDialog.showOptionDialog(tool.getToolFrame(),title , buf.toString(),
//				"Abort Actions", OptionDialog.WARNING_MESSAGE);
//			
//		return result == OptionDialog.OPTION_ONE;
//	}
//	private boolean checkForSave(Program currentProgram) {
//		DomainFile df = currentProgram.getDomainFile();
//		
//		String filename = df.getName();            
//
//		if (!df.isInProject()) {
//			return  OptionDialog.showOptionDialog(tool.getToolFrame(),
//					   "Program Changed",
//					   "Viewed file "+filename +
//					   " has been changed.  \n"+
//					   "If you continue, your changes will be lost!",
//					   "Continue", OptionDialog.QUESTION_MESSAGE) != OptionDialog.CANCEL_OPTION;
//		}
//		
//		if (df.isReadOnly()) {
//			return OptionDialog.showOptionDialog(tool.getToolFrame(),
//					   "Program Changed",
//					   "Read-only file "+filename +
//					   " has been changed.  \n"+
//					   "If you continue, your changes will be lost!",
//					   "Continue", OptionDialog.QUESTION_MESSAGE) != OptionDialog.CANCEL_OPTION;
//		
//		}
//		
//
//		int result = OptionDialog.showOptionDialog(tool.getToolFrame(),
//				   "Save Program?",
//				   filename +
//				   " has changed. Do you want to save it?",
//				   "&Save", "Do&n't Save",
//				   OptionDialog.QUESTION_MESSAGE);
//				 
//		if (result == OptionDialog.CANCEL_OPTION) {
//			return false;
//		}
//		if (result == OptionDialog.OPTION_ONE) {
//			save(currentProgram);
//		}
//		return true;
//	}
	private boolean acquireSaveLock(Program program, String actionName) {
		if (!program.lock(null)) {
			String title = actionName + " Program" + " (Busy)";
			StringBuilder buf = new StringBuilder();
			buf.append(
				"The Program is currently being modified by the following actions/tasks:\n ");
			Transaction t = program.getCurrentTransaction();
			List<String> list = t.getOpenSubTransactions();
			Iterator<String> it = list.iterator();
			while (it.hasNext()) {
				buf.append("\n     ");
				buf.append(it.next());
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
			Transaction t = program.getCurrentTransaction();
			List<String> list = t.getOpenSubTransactions();
			Iterator<String> it = list.iterator();
			while (it.hasNext()) {
				buf.append("\n     ");
				buf.append(it.next());
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
		if (dataTreeSaveDialog == null) {

			ActionListener listener = event -> {
				DomainFolder folder = dataTreeSaveDialog.getDomainFolder();
				String newName = dataTreeSaveDialog.getNameText();
				if (newName.length() == 0) {
					dataTreeSaveDialog.setStatusText("Please enter a name");
					return;
				}
				else if (folder == null) {
					dataTreeSaveDialog.setStatusText("Please select a folder");
					return;
				}

				DomainFile file = folder.getFile(newName);
				if (file != null && file.isReadOnly()) {
					dataTreeSaveDialog.setStatusText("Read Only.  Choose new name/folder");
				}
				else {
					dataTreeSaveDialog.close();
					treeDialogCancelled = false;
				}
			};
			dataTreeSaveDialog =
				new DataTreeDialog(null, "Save As", DataTreeDialog.SAVE, domainFileFilter);

			dataTreeSaveDialog.addOkActionListener(listener);
			dataTreeSaveDialog.setHelpLocation(
				new HelpLocation(HelpTopics.PROGRAM, "Save_As_File"));
		}
		return dataTreeSaveDialog;
	}

	/**
	 * 
	 */
	class SaveFileTask extends Task {

		private DomainFile domainFile;

		/**
		 * Construct new SaveFileTask.
		 * @param df domain file to save
		 */
		SaveFileTask(DomainFile df) {
			super("Save Program", true, true, true);
			this.domainFile = df;
		}

		/**
		 * @see ghidra.util.task.Task#run(TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			monitor.setMessage("Saving Program...");
			try {
				domainFile.save(monitor);
			}
			catch (CancelledException e) {
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

	class SaveAsTask extends Task {

		private DomainFolder parentFolder;
		private String newName;
		private DomainObject domainObj;
		private boolean doOverwrite;

		/**
		 * Construct new SaveFileTask to do a "Save As"
		 * @param obj
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

		/**
		 * @see ghidra.util.task.Task#run(TaskMonitor)
		 */
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
