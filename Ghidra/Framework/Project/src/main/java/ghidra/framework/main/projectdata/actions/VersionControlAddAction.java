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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action to add a domain file to version control in the repository.
 */
public class VersionControlAddAction extends VersionControlAction {

	public VersionControlAddAction(Plugin plugin) {
		super("Add to Version Control", plugin.getName(), plugin.getTool());
		ImageIcon icon = ResourceManager.loadImage("images/vcAdd.png");
		setToolBarData(new ToolBarData(icon, GROUP));

		setPopupMenuData(new MenuData(new String[] { "Add to Version Control..." }, icon, GROUP));

		setDescription("Add file to Version Control");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		addToVersionControl(context.getSelectedFiles());
	}

	/**
	 * Returns true if at least one of the provided domain files can be added to the repository.
	 */
	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		List<DomainFile> domainFiles = context.getSelectedFiles();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.canAddToRepository()) {
				return true; // Has at least one domain file that can be added to the repository.
			}
		}
		return false;
	}

	/**
	 * Adds all the non-version controlled domain files to the repository from the 
	 * list of files from the DomainFileProvider.
	 * @param domainFiles 
	 */
	private void addToVersionControl(List<DomainFile> domainFiles) {

		if (!checkRepositoryConnected()) {
			return;
		}
		List<DomainFile> unversioned = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isVersionControlSupported() && !domainFile.isVersioned()) {
				unversioned.add(domainFile);
			}
		}
		if (unversioned.isEmpty()) {
			return;
		}
		ArrayList<DomainFile> list = new ArrayList<>();
		ArrayList<DomainFile> changedList = new ArrayList<>();
		for (DomainFile domainFile : unversioned) {
			if (domainFile.isBusy()) {
				Msg.showWarn(getClass(), null, "Add To Version Control Failed!",
					"One or more selected files is currently being modified!");
				return;
			}
			if (!canCloseDomainFile(domainFile)) {
				tool.setStatusInfo("Add to version control canceled");
				return;
			}
			list.add(domainFile);
			if (domainFile.isChanged()) {
				changedList.add(domainFile);
			}
		}
		if (changedList.size() > 0) {
			ChangedFilesDialog dialog = new ChangedFilesDialog(tool, changedList);
			dialog.setCancelToolTipText("Cancel Add to Version Control");
			if (!dialog.showDialog()) { // blocks until the user hits Save or Cancel
				tool.setStatusInfo("Add to version control canceled");
				return;
			}
			for (int i = 0; i < changedList.size(); i++) {
				DomainFile df = changedList.get(i);
				if (df.isChanged()) {
					list.remove(df);
				}
			}
		}
		if (list.size() > 0) {
			AddToVersionControlTask task = new AddToVersionControlTask(list, tool);
			tool.execute(task);
		}
	}

	/**
	 * Task for adding files to version control. This task displays a dialog for each file 
	 * which allows a comment to be entered for each check-in.
	 */
	private class AddToVersionControlTask extends VersionControlTask {

		AddToVersionControlTask(List<DomainFile> list, PluginTool tool) {
			super("Add to Version Control", tool, list, tool.getToolFrame());
		}

		@Override
		public void run(TaskMonitor monitor) {
			checkFilesInUse();
			try {
				for (DomainFile df : list) {
					String name = df.getName();
					monitor.setMessage("Adding " + name + " to Version Control");

					if (actionID != VersionControlDialog.APPLY_TO_ALL) {
						showDialog(true, name);
					}
					if (actionID == VersionControlDialog.CANCEL) {
						return;
					}

					// Note: this used to be a sleep(200) 
					Swing.allowSwingToProcessEvents();

					df.addToVersionControl(comments, keepCheckedOut, monitor);
				}
			}
			catch (CancelledException e) {
				Msg.info(this, "Add to Version Control was canceled");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Add to Version Control",
					tool.getToolFrame());
			}
		}
	}

}
