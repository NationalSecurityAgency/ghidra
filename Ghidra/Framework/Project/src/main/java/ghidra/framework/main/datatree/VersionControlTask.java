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
	 * @param filename the name of the file currently to be added, whose comment we need.
	 */
	protected void showDialog(boolean addToVersionControl, String filename) {
		Runnable r = () -> {
			VersionControlDialog vcDialog = new VersionControlDialog(addToVersionControl);
			vcDialog.setCurrentFileName(filename);
			vcDialog.setMultiFiles(list.size() > 1);
			vcDialog.setKeepCheckboxEnabled(!filesInUse);
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
		filesInUse = false;
		for (int i = 0; i < list.size(); i++) {
			DomainFile df = list.get(i);
			if (df.getConsumers().size() > 0) {
				filesInUse = true;
				return;
			}
		}
	}

	protected boolean checkFilesForUnsavedChanges() {
		for (int i = 0; i < list.size(); i++) {
			DomainFile df = list.get(i);
			if (df.modifiedSinceCheckout()) {
				return true;
			}
		}
		return false;
	}
}
