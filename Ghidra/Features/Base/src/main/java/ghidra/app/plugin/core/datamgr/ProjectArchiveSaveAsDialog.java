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
package ghidra.app.plugin.core.datamgr;

import java.io.IOException;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.DataTreeDialogType;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

public class ProjectArchiveSaveAsDialog extends DataTreeDialog {
	private static final String CONTENT_NAME = "Data Type Archive";

	private ProjectDataTypeArchive archive;

	private PluginTool tool;

	public ProjectArchiveSaveAsDialog(PluginTool tool, ProjectDataTypeArchive archive) {
		super(null, "Save Project Archive As", DataTreeDialogType.SAVE);
		this.tool = tool;
		this.archive = archive;
		setHelpLocation(new HelpLocation(HelpTopics.PROGRAM, "Save_As_File"));
	}

	@Override
	protected void okCallback() {
		DomainFolder folder = getDomainFolder();
		String name = getNameText();
		if (name.length() == 0) {
			setStatusText("Please enter a name");
			return;
		}
		if (folder == null) {
			setStatusText("Please select a folder");
			return;
		}
		DomainFile file = folder.getFile(name);
		if (file != null) {
			setStatusText("Choose a name that doesn't exist");
			return;
		}
		close();
		doSaveAs();
	}

	private void doSaveAs() {
		if (!getSaveAsLock(archive)) {
			return;
		}
		try {
			DomainFolder folder = getDomainFolder();
			String newName = getNameText();
			tool.prepareToSave(archive);
			TaskLauncher.launchModal("Save As", monitor -> {
				try {
					folder.createFile(newName, archive, monitor);
				}
				catch (InvalidNameException e) {
					Msg.showError(this, null, "Invalid Name", e.getMessage(), e);
				}
				catch (CancelledException e) {
					// user cancelled, nothing to do
				}
				catch (IOException e) {
					Msg.showError(this, null, "I/O error ", e.getMessage(), e);
				}
			});
		}
		finally {
			archive.unlock();
		}
	}

	private boolean getSaveAsLock(DomainObject domainObject) {
		if (!domainObject.lock(null)) {
			String title = "Save " + CONTENT_NAME + " As (Busy)";
			StringBuffer buf = new StringBuffer();
			buf.append("The " + CONTENT_NAME +
				" is currently being modified by the following actions/tasks:\n \n");
			TransactionInfo t = domainObject.getCurrentTransactionInfo();
			List<String> list = t.getOpenSubTransactions();
			for (String element : list) {
				buf.append("\n     ");
				buf.append(element);
			}
			buf.append("\n \n");
			buf.append(
				"WARNING! The above task(s) should be cancelled before attempting a Save As...\n");
			buf.append("Only proceed if unable to cancel them.\n \n");
			buf.append(
				"If you click 'Save Archive As (Rollback)' {recommended}, all changes made\n");
			buf.append("by these tasks, as well as any other overlapping task, will be LOST!\n");
			buf.append(
				"If you click 'Save As (As Is)', the archive will be saved in its current\n");
			buf.append("state which may contain some incomplete data.\n");
			buf.append("Any forced save may also result in subsequent transaction errors while\n");
			buf.append("the above tasks remain active.\n ");

			int result = OptionDialog.showOptionDialog(null, title, buf.toString(),
				"Save Archive As (Rollback)!", "Save Archive As (As Is)!",
				OptionDialog.WARNING_MESSAGE);

			if (result == OptionDialog.OPTION_ONE) {
				domainObject.forceLock(true, "Save Archive As");
				return true;
			}
			else if (result == OptionDialog.OPTION_TWO) {
				domainObject.forceLock(false, "Save Archive As");
				return true;
			}
			return false;
		}
		return true;
	}

}
