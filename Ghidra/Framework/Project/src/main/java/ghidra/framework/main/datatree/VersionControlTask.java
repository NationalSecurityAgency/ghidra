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
package ghidra.framework.main.datatree;

import java.awt.Component;
import java.util.List;

import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.SystemUtilities;
import ghidra.util.task.Task;

/**
 * Task to show a dialog to enter comments for checking in a file
 */
public abstract class VersionControlTask extends Task {

	protected List<DomainFile> list;
	protected int actionID;
	protected boolean keepCheckedOut;
	protected boolean createKeep;
	protected String comments;
	protected boolean filesInUse;
	protected PluginTool tool;
	protected boolean wasCanceled;
	protected Component parent;

	/**
	 * Constructor
	 * @param title title of the task
	 * @param tool tool associated with the task
	 * @param list list of domain files
	 * @param parent parent of the version control dialog; may be null
	 */
	protected VersionControlTask(String title, PluginTool tool, List<DomainFile> list,
			Component parent) {
		super(title, true, true, true);
		this.tool = tool;
		this.list = list;
		this.parent = parent;
	}

	/**
	 * Show the dialog.
	 * @param addToVersionControl true if the dialog is for
	 * adding files to version control, false for checking in files.
	 * @param file the file currently to be added or checked-in to version control
	 */
	protected void showDialog(boolean addToVersionControl, DomainFile file) {
		Runnable r = () -> {
			VersionControlDialog vcDialog = new VersionControlDialog(addToVersionControl);
			vcDialog.setCurrentFileName(file.getName());
			vcDialog.setMultiFiles(list.size() > 1);
			if (file.isLinkFile()) {
				vcDialog.setKeepCheckboxEnabled(false, false, "Link file may not be Checked Out");
			}
			else {
				checkFilesInUse();
				if (filesInUse) {
					vcDialog.setKeepCheckboxEnabled(false, true,
						"Must keep Checked Out because the file is in use");
				}
			}
			actionID = vcDialog.showDialog(tool, parent);
			keepCheckedOut = vcDialog.keepCheckedOut();
			createKeep = vcDialog.shouldCreateKeepFile();
			comments = vcDialog.getComments();
			if (comments.length() == 0) {
				comments = null;
			}

		};

		SystemUtilities.runSwingNow(r);
	}

	/**
	 * Sets the filesInUse field if any file is in use.
	 * Call this method from the run() method so that the
	 * "Keep checked out" checkbox on the dialog is disabled if files
	 * are still in use.
	 */
	protected void checkFilesInUse() {
		// NOTE: In-use check is currently limited to files open for update but for the purpose of 
		// maintaining a checkout should really correspond to any file use (e.g., open read-only
		// with DomainFileProxy).
		filesInUse = false;
		for (DomainFile df : list) {
			if (df.getConsumers().size() > 0) {
				filesInUse = true;
				return;
			}
		}
	}

	protected boolean checkFilesForUnsavedChanges() {
		for (DomainFile df : list) {
			if (df.modifiedSinceCheckout()) {
				return true;
			}
		}
		return false;
	}
}
