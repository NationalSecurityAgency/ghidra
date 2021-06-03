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

import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDropEvent;
import java.io.IOException;
import java.util.List;

import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeState;
import ghidra.app.util.FileOpenDataFlavorHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.FileInUseException;
import ghidra.util.task.*;

public final class LocalTreeNodeHandler
		implements DataTreeFlavorHandler, FileOpenDataFlavorHandler {

	private DataTree dataTree;
	private GTreeState treeState;

	@Override
	public void handle(PluginTool tool, Object obj, DropTargetDropEvent e, DataFlavor f) {

		if (f.equals(DataTreeDragNDropHandler.localDomainFileFlavor)) {
			List<?> files = (List<?>) obj;
			DomainFile[] domainFiles = new DomainFile[files.size()];
			for (int i = 0; i < files.size(); i++) {
				domainFiles[i] = (DomainFile) files.get(i);
			}
			tool.acceptDomainFiles(domainFiles);
		}
		else if (f.equals(DataTreeDragNDropHandler.localDomainFileTreeFlavor)) {
			List<?> files = (List<?>) obj;
			DomainFile[] domainFiles = new DomainFile[files.size()];
			for (int i = 0; i < files.size(); i++) {
				DomainFileNode node = (DomainFileNode) files.get(i);
				domainFiles[i] = node.getDomainFile();
			}
			tool.acceptDomainFiles(domainFiles);
		}
	}

	@Override
	@SuppressWarnings("unchecked")
	public void handle(PluginTool tool, DataTree tree, GTreeNode destinationNode,
			Object transferData, int dropAction) {

		this.dataTree = tree;
		this.treeState = tree.getTreeState();

		List<GTreeNode> list = (List<GTreeNode>) transferData;
		if (list.size() == 0) {
			return;
		}

		CopyAllTask task = new CopyAllTask(list, destinationNode, dropAction);
		new TaskLauncher(task, dataTree, 1000);

		if (treeState != null) { // is set to null if drag results in a task
			SystemUtilities.runSwingLater(() -> {
				treeState.updateStateForMovedNodes();
				dataTree.restoreTreeState(treeState);
			});
		}
	}

	private void add(GTreeNode destNode, GTreeNode draggedNode, int dropAction,
			TaskMonitor monitor) {
		DomainFolderNode folderNode = getDestinationFolderNode(destNode);

		if (!isValidDrag(folderNode, draggedNode)) {
			return;
		}

		DomainFolder destFolder = folderNode.getDomainFolder();
		addDraggedTreeNode(destFolder, draggedNode, dropAction, monitor);
	}

	private boolean isValidDrag(DomainFolderNode folderNode, GTreeNode draggedNode) {
		if (folderNode == draggedNode) {
			return false;
		}
		if (draggedNode.getParent() == folderNode) {
			return false; // dragging a node onto its parent has no effect
		}

		if (draggedNode instanceof DomainFolderNode) {
			return !draggedNode.isAncestor(folderNode);
		}

		return true;
	}

	private DomainFolderNode getDestinationFolderNode(GTreeNode destNode) {
		if (destNode instanceof DomainFolderNode) {
			return (DomainFolderNode) destNode;
		}
		return (DomainFolderNode) destNode.getParent();
	}

	private void addDraggedTreeNode(DomainFolder destFolder, GTreeNode data, int dropAction,
			TaskMonitor monitor) {
		try {
			if (data instanceof DomainFolderNode) {
				DomainFolder sourceFolder = ((DomainFolderNode) data).getDomainFolder();
				handleFolderDrag(destFolder, dropAction, sourceFolder, monitor);
			}
			else {
				DomainFile file = ((DomainFileNode) data).getDomainFile();
				handleFileDrag(destFolder, dropAction, file, monitor);
			}
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			String nodeType = (data instanceof DomainFolderNode) ? "folder" : "file";
			Msg.showError(this, dataTree, "Copy/Move Failed",
				"Failed to copy/move " + nodeType + ": " + data.getName() + "\n" + msg, e);
		}
	}

	private void handleFileDrag(DomainFolder destFolder, int dropAction, DomainFile file,
			TaskMonitor monitor) {
		if (dropAction == DnDConstants.ACTION_COPY || !file.isInWritableProject()) {
			CopyTask task = new CopyTask(destFolder, file);
			task.run(monitor);
			return;
		}

		try {
			file.moveTo(destFolder);
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, dataTree, "Cannot Move File",
				"Move file " + file.getName() + " failed.\n" + msg);
		}
	}

	private void handleFolderDrag(DomainFolder destFolder, int dropAction,
			DomainFolder sourceFolder, TaskMonitor monitor) {
		if (dropAction == DnDConstants.ACTION_COPY || !sourceFolder.isInWritableProject()) {
			CopyTask task = new CopyTask(destFolder, sourceFolder);
			task.run(monitor);
			return;
		}

		try {
			sourceFolder.moveTo(destFolder);
		}
		catch (DuplicateFileException dfe) {
			Msg.showError(this, dataTree, "Error Moving Folder",
				"Destination folder already contains a folder named \"" + sourceFolder.getName() +
					"\"");
		}
		catch (FileInUseException fiue) {
			String message = fiue.getMessage();
			if (message == null || message.length() == 0) {
				message = "Cannot move folder '" + sourceFolder.toString() + "' to '" +
					destFolder.toString() +
					"'\nsince it contains a file that is checked out or in use.";
			}
			Msg.showError(this, dataTree, "Error Moving Folder", message);
		}
		catch (IOException e) {
			Msg.showError(this, dataTree, "Error Moving Folder", "Cannot Move Folder", e);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class CopyAllTask extends Task {
		private List<GTreeNode> toCopy;
		private GTreeNode destination;
		private int dropAction;

		CopyAllTask(List<GTreeNode> toCopy, GTreeNode destination, int dropAction) {
			super("Copy Files", true, true, true);
			this.toCopy = toCopy;
			this.destination = destination;
			this.dropAction = dropAction;
		}

		@Override
		public void run(TaskMonitor monitor) {

			int size = toCopy.size();
			TaskMonitor[] subMonitors = TaskMonitorSplitter.splitTaskMonitor(monitor, size);
			monitor.initialize(size);
			for (int i = 0; i < size; i++) {
				if (monitor.isCancelled()) {
					return;
				}

				GTreeNode copyNode = toCopy.get(i);
				monitor.setMessage(
					"Processing file " + (i + 1) + " of " + size + ": " + copyNode.getName());

				add(destination, copyNode, dropAction, subMonitors[i]);
				monitor.setProgress(i);
			}
		}
	}
}
