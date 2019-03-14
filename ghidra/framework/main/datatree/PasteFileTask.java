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

import java.util.List;

import docking.widgets.tree.GTreeNode;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 *
 * Task to paste files at given destination folder.
 * 
 * 
 */
public class PasteFileTask extends Task {

	private DomainFolderNode destNode;
	private List<GTreeNode> list;
	private boolean isCut;
	private RepositoryAdapter repository; // null if project is not shared
	private FrontEndTool tool;

	/**
	 * Constructor for PasteFileTask.
	 *  
	 * @param destNode destination folder
	 * @param list list of GTreeNodes being pasted
	 * @param isCut boolean flag, true means source nodes were cut instead of copied.
	 */
	public PasteFileTask(DomainFolderNode destNode, List<GTreeNode> list, boolean isCut) {
		super(list.size() > 1 ? "Paste Files" : "Paste File", true, true, true);
		this.destNode = destNode;
		this.list = list;
		this.isCut = isCut;
		tool = AppInfo.getFrontEndTool();
		repository = tool.getProject().getRepository();
	}

	@Override
	public void run(TaskMonitor monitor) {

		TaskMonitor subMonitor = monitor;
		if (list.size() > 1) {
			subMonitor = new CancelOnlyWrappingTaskMonitor(monitor);
		}

		try {
			monitor.initialize(list.size());
			for (int i = 0; i < list.size(); i++) {
				GTreeNode tnode = list.get(i);
				monitor.setProgress(i);
				if (tnode instanceof DomainFolderNode) {
					monitor.setMessage("Pasting folder");
					pasteFolder(((DomainFolderNode) tnode).getDomainFolder(), subMonitor);
				}
				else if (tnode instanceof DomainFileNode) {
					monitor.setMessage("Pasting file");
					pasteFile(((DomainFileNode) tnode).getDomainFile(), subMonitor);
				}
				if (monitor.isCancelled()) {
					break;
				}
			}
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Paste Files at " + destNode.getName(),
				tool.getToolFrame());
		}
	}

	/**
	 * Paste the given file at the folder represented by destNode.
	 * 
	 * @param file file to be pasted.
	 * @param monitor task monitor
	 */
	private void pasteFile(DomainFile file, TaskMonitor monitor) {
		if (isCut) {
			moveFile(file, destNode.getDomainFolder());
		}
		else {
			copyFile(file, destNode.getDomainFolder(), monitor);
		}
	}

	/**
	 * Paste the given folder at destNode.
	 */
	private void pasteFolder(DomainFolder folder, TaskMonitor monitor) {
		if (isCut) {
			moveFolder(folder, destNode.getDomainFolder());
		}
		else {
			copyFolder(folder, destNode.getDomainFolder(), monitor);
		}
	}

	/**
	 * Copy a file into a new folder.
	 * 
	 * @param file source {@link DomainFile file}
	 * @param folder destination {@link DomainFolder folder}
	 * @param monitor {@link TaskMonitor} with progress or cancel
	 */
	private void copyFile(DomainFile file, DomainFolder folder, TaskMonitor monitor) {
		try {
			// file.copyTo() will automatically append a unique number to the end
			// of the filename if needed.
			String name = file.getName();
			DomainFile newFile = file.copyTo(folder, monitor);
			Msg.info(this,
				"Copied file " + name + " to " + folder.toString() + " as " + newFile.getName());
		}
		catch (CancelledException e) {
			// just return
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Copy Files", tool.getToolFrame());
		}
	}

	/**
	 * Copy the given folder and all of its contents into a new parent folder.
	 */
	private void copyFolder(DomainFolder folder, DomainFolder newParent, TaskMonitor monitor) {

		String name = folder.getName();

		try {
			folder.copyTo(newParent, monitor);
			Msg.info(this, "Copied folder " + name + " to " + newParent.toString());

		}
		catch (CancelledException e) {
			// just return
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Copy Folder", tool.getToolFrame());
		}
	}

	/**
	 * Move a file into a folder.
	 * <p>
	 * Displays a error dialog if there was an exception
	 * 
	 * @param file {@link DomainFile file} being moved
	 * @param folder destination {@link DomainFolder folder} 
	 */
	private void moveFile(DomainFile file, DomainFolder folder) {
		try {
			String name = file.getName();
			file.moveTo(folder);
			Msg.info(this, "Moved file " + name + " to " + folder.toString());
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Move File", tool.getToolFrame());
		}
	}

	/**
	 * Move the given folder and all of its contents into a new parent folder.
	 * <p>
	 * Displays a error dialog if there was an exception
	 * 
	 * @param {@link DomainFolder folder} being moved
	 * @param newParent destination
	 */
	private void moveFolder(DomainFolder folder, DomainFolder newParent) {

		String name = folder.getName();
		try {
			folder.moveTo(newParent);
			Msg.info(this, "Moved folder " + name + " to " + folder.toString());
		}
		catch (Exception e) {
			ClientUtil.handleException(repository, e, "Move Folder", tool.getToolFrame());
		}
	}

}
