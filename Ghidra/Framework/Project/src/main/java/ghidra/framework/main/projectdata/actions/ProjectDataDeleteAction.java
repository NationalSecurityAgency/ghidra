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
import java.awt.event.KeyEvent;
import java.util.Set;

import javax.swing.Icon;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.OptionDialogBuilder;
import ghidra.framework.main.datatable.ProjectDataContext;
import ghidra.framework.main.datatable.FrontendProjectTreeAction;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.HTMLUtilities;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;
import util.CollectionUtils;

public class ProjectDataDeleteAction extends FrontendProjectTreeAction {
	private static Icon icon = ResourceManager.loadImage("images/page_delete.png");

	public ProjectDataDeleteAction(String owner, String group) {
		super("Delete", owner);
		setPopupMenuData(new MenuData(new String[] { "Delete" }, icon, group));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(ProjectDataContext context) {
		Set<DomainFile> files = CollectionUtils.asSet(context.getSelectedFiles());
		Set<DomainFolder> folders = CollectionUtils.asSet(context.getSelectedFolders());

		// Task 1 - count the files.  This probably does not need a task, but just in case.
		CountDomainFilesTask countTask = new CountDomainFilesTask(folders, files);
		new TaskLauncher(countTask, context.getComponent(), 750);
		if (countTask.wasCancelled()) {
			return;
		}

		// Confirm the delete *without* using a task so that do not have 2 dialogs showing
		int fileCount = countTask.getFileCount();
		if (!confirmDelete(fileCount, files, context.getComponent())) {
			return;
		}

		// Task 2 - perform the delete--this could take a while
		DeleteProjectFilesTask deleteTask = createDeleteTask(context, files, folders, fileCount);
		TaskLauncher.launch(deleteTask);
	}

	DeleteProjectFilesTask createDeleteTask(ProjectDataContext context, Set<DomainFile> files,
			Set<DomainFolder> folders, int fileCount) {
		return new DeleteProjectFilesTask(folders, files, fileCount, context.getComponent());
	}

	private boolean confirmDelete(int fileCount, Set<DomainFile> files, Component parent) {

		String message = getMessage(fileCount, files);
		OptionDialogBuilder builder = new OptionDialogBuilder("Confirm Delete", message);
		builder.addOption("OK").addCancel().setMessageType(OptionDialog.QUESTION_MESSAGE);
		return builder.show(parent) != OptionDialog.CANCEL_OPTION;
	}

	private String getMessage(int fileCount, Set<DomainFile> selectedFiles) {

		if (fileCount == 0) {
			return "Are you sure you want to delete the selected empty folder(s)?";
		}

		if (fileCount == 1) {
			if (!selectedFiles.isEmpty()) {
				DomainFile file = CollectionUtils.any(selectedFiles);
				return "<HTML>Are you sure you want to <B><U>permanently</U></B> delete \"" +
					HTMLUtilities.escapeHTML(file.getName()) + "\"?";
			}

			// only folders are selected, but they contain files
			return "<HTML>Are you sure you want to <B><U>permanently</U></B> delete the " +
				" selected files and folders?";
		}

		// multiple files selected
		return "<HTML>Are you sure you want to <B><U>permanently</U></B> delete the " + fileCount +
			" selected files?";
	}

	@Override
	protected boolean isEnabledForContext(ProjectDataContext context) {
		if (!context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		if (context.isReadOnlyProject()) {
			return false;
		}
		return !context.containsRootFolder();
	}
}
