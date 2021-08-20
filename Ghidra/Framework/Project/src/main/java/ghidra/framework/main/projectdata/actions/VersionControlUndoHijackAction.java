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
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.UndoActionDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action to undo hijacked domain files in the project.
 */
public class VersionControlUndoHijackAction extends VersionControlAction {

	/**
	 * Creates an action to undo hijacked domain files in the project.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlUndoHijackAction(Plugin plugin) {
		super("Undo Hijack", plugin.getName(), plugin.getTool());
		ImageIcon icon = ResourceManager.loadImage("images/undo_hijack.png");
		setPopupMenuData(new MenuData(new String[] { "Undo Hijack" }, icon, GROUP));
		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		undoHijackedFiles(context.getSelectedFiles());
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

		List<DomainFile> domainFiles = context.getSelectedFiles();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isHijacked()) {
				return true; // At least one hijacked file selected.
			}
		}
		return false;
	}

	/**
	 * Gets the domain files from the provider and then undoes the hijack on any that are hijacked.
	 */
	private void undoHijackedFiles(List<DomainFile> domainFiles) {
		if (!checkRepositoryConnected()) {
			return;
		}

		List<DomainFile> hijackList = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile != null && domainFile.isHijacked()) {
				hijackList.add(domainFile);
			}
		}
		undoHijack(hijackList);
	}

	/**
	 * Displays the undo hijack confirmation dialog for each hijacked file and then 
	 * undoes the hijack while keeping a copy of the hijacked file if the user chooses to do so.
	 * @param hijackList the list of hijacked domain files.
	 */
	void undoHijack(List<DomainFile> hijackList) {
		if (!checkRepositoryConnected()) {
			return;
		}
		if (hijackList.size() > 0) {
			UndoActionDialog dialog = new UndoActionDialog("Confirm Undo Hijack",
				ResourceManager.loadImage("images/undo_hijack.png"), "Undo_Hijack", "hijack",
				hijackList);
			int actionID = dialog.showDialog(tool);

			if (actionID != UndoActionDialog.CANCEL) {
				boolean saveCopy = dialog.saveCopy();
				DomainFile[] files = dialog.getSelectedDomainFiles();
				if (files.length > 0) {
					tool.execute(new UndoHijackTask(files, saveCopy));
				}
			}
		}
	}

	/**
	 * Determines a unique keep file name for saving a copy of the hijack file 
	 * when its hijack is undone.
	 * @param parent the domain folder where the hijacked file exists.
	 * @param name the name of the hijacked file.
	 * @return the unique keep file name.
	 */
	private String getKeepName(DomainFolder parent, String name) {
		int oneUp = 1;
		String keepName = name + ".keep";
		while (true) {
			DomainFile df = parent.getFile(keepName);
			if (df != null) {
				keepName = name + ".keep" + oneUp;
				++oneUp;
			}
			return keepName;
		}
	}

	/**
	 * Task for undoing hijacks of files that are in version control.
	 */
	private class UndoHijackTask extends Task {

		private DomainFile[] hijackFiles;
		private boolean saveCopy;

		/**
		 * Creates a task for undoing hijacks of domain files.
		 * @param hijackFiles the list of hijacked files
		 * @param saveCopy true indicates that copies of the modified files should be made 
		 * before undo of the checkout
		 */
		UndoHijackTask(DomainFile[] hijackFiles, boolean saveCopy) {
			super("Undo Hijack", true, true, true);
			this.hijackFiles = hijackFiles;
			this.saveCopy = saveCopy;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (DomainFile currentDF : hijackFiles) {
					monitor.checkCanceled();
					monitor.setMessage("Undoing Hijack " + currentDF.getName());
					if (saveCopy) {
						// rename the file
						try {
							currentDF.setName(
								getKeepName(currentDF.getParent(), currentDF.getName()));
						}
						catch (InvalidNameException e1) {
							// TODO put error message here
						}
					}
					else {
						currentDF.delete();
					}
				}
			}
			catch (CancelledException e) {
				tool.setStatusInfo("Undo hijack was canceled");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Undo Hijack", tool.getToolFrame());
			}
		}
	}

}
