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

import java.awt.event.InputEvent;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import generic.theme.GIcon;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.LinkedDomainFolder;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

public class ProjectDataPasteAction extends ProjectDataCopyCutBaseAction {
	private static Icon ICON = new GIcon("icon.projectdata.paste");

	public ProjectDataPasteAction(String owner, String group) {
		super("Paste", owner);
		setPopupMenuData(new MenuData(new String[] { "Paste" }, ICON, group));
		setKeyBindingData(new KeyBindingData('V', InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Paste"));
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolder destFolder = DataTree.getRealInternalFolderForNode(node);
		if (destFolder != null) {
			paste(context.getTree(), destFolder);
		}
	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.isInActiveProject() || !context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolder destFolder = DataTree.getRealInternalFolderForNode(node);
		return checkNodeForPaste(destFolder);
	}

	@Override
	protected boolean isAddToPopup(FrontEndProjectTreeContext context) {
		if (!context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		return context.isInActiveProject();
	}

	/**
	 * Check the destination node for whether clipboard data can be pasted there.
	 * Ancestry checks are performed for the node(s) in the clipboard against the
	 * specified destination folder.
	 * 
	 * @param destFolder destination for paste operation
	 * @return true if least one node can be pasted at destNode
	 */
	static boolean checkNodeForPaste(DomainFolder destFolder) {

		if (destFolder == null || !destFolder.isInWritableProject()) {
			return false;
		}

		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();

		for (GTreeNode node : list) {
			if (node instanceof DomainFileNode fileNode && !fileNode.isFolderLink()) {
				return true; // at least one good paste from clipboard
			}
			// Check folder-link or folder
			DomainFolder folder = DataTree.getRealInternalFolderForNode(node);
			if (folder != null && !folder.isSameOrAncestor(destFolder)) {
				return true; // at least one good paste from clipboard
			}
		}
		return false;
	}

	/**
	 * Process a "paste" request from a menu action.
	 */
	private void paste(DataTree tree, DomainFolder destFolder) {

		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();
		boolean isCutOperation = isCutOperation(list);
		checkPasteList(tree, destFolder, list, isCutOperation);

		if (!list.isEmpty()) {
			PasteFileTask task = new PasteFileTask(destFolder, list, isCutOperation);
			new TaskLauncher(task, tree, 1000);
		}
		else {
			// need to force selection event to go out so that the
			// edit actions on the front end edit menu stay in sync
			tree.removeSelectionPath(null);
			tree.setSelectionPath(null);
		}
	}

	/**
	 * Update the given list of nodes to paste if the corresponding file or
	 * folder cannot be pasted; remove it from the list and update the
	 * clipboard with the new list.
	 * @param destFolder destination folder
	 * @param list list of nodes to paste
	 * @param isCutOperation true if this is a cut vs copy; for cut, files
	 * cannot be in use
	 */
	private void checkPasteList(DataTree tree, DomainFolder destFolder, List<GTreeNode> list,
			boolean isCutOperation) {

		if (list == null || list.isEmpty()) {
			return;
		}

		removeDescendantsFromList(list);

		StringBuilder msgBuffer = new StringBuilder();

		for (int i = 0; i < list.size(); i++) {
			GTreeNode tnode = list.get(i);
			boolean removeNodeFromList = true;
			if (tnode instanceof DataTreeNode dataTreeNode) {
				removeNodeFromList =
					!canCopyNode(dataTreeNode, destFolder, isCutOperation, msgBuffer);
			}
			if (removeNodeFromList) {
				// After removing the current 'tnode' from the list, decrement list index 'i' 
				// to compensate for the loop's index 'i' increment since the next node will 
				// reside at the same index position within the list.
				list.remove(i--);
				if (tnode instanceof Cuttable cuttable) {
					cuttable.setIsCut(false);
				}
			}
		}
		if (msgBuffer.length() > 0) {
			String title = isCutOperation ? "Cannot Move File(s)" : "Cannot Copy File(s)";
			String action = isCutOperation ? "moved" : "copied";
			Msg.showWarn(getClass(), tree, title,
				"The following content could not be " + action + ":\n" + msgBuffer.toString());
		}
	}

	private void appendMsg(String msg, StringBuilder msgBuffer) {
		if (!msg.isEmpty()) {
			msgBuffer.append("\n");
		}
		msgBuffer.append(msg);
	}

	/**
	 * Determine if the specified node can be copied or moved to the specified destination folder.
	 * @param dataTreeNode copy/cut node
	 * @param destFolder destination folder
	 * @param isCutOperation true if node is being moved to {@code destFolder}
	 * @param msgBuffer error message buffer
	 * @return true if node copy/move is permitted, else false in which case {@code msgBuffer} 
	 * may have messages.
	 */
	private boolean canCopyNode(DataTreeNode dataTreeNode, DomainFolder destFolder,
			boolean isCutOperation, StringBuilder msgBuffer) {
		try {
			String nodeType = (dataTreeNode instanceof DomainFolderNode) ? "Folder" : "File";
			DomainFolder folder = getRealFolder(dataTreeNode);
			if (isCutOperation) {
				if (!folder.isInWritableProject()) {
					appendMsg("Read-only project. " + nodeType + " '" + dataTreeNode.getName() +
						"' cannot be moved", msgBuffer);
					return false;
				}
				if (dataTreeNode.getParent() == null) {
					return false; // ignore root node cut selection
				}
				DomainFolder checkFolder =
					(dataTreeNode instanceof DomainFolderNode) ? folder.getParent() : folder;
				if (destFolder.equals(checkFolder)) {
					return false; // ignore move to same location
				}
			}

			if (dataTreeNode instanceof DomainFolderNode) {
				if (folder.isSameOrAncestor(destFolder)) {
					appendMsg(
						nodeType + " '" + dataTreeNode.getName() +
							"' contains destination folder '" + destFolder.getName() + "'",
						msgBuffer);
					return false;
				}
				if (destFolder.getFolder(folder.getName()) != null) {
					appendMsg("Folder '" + destFolder.getName() +
						"' already contains a folder named '" + dataTreeNode.getName() + "'",
						msgBuffer);
					return false;
				}
			}
		}
		catch (IOException e) {
			Msg.warn(this,
				"Failed to resolve linked item: " + dataTreeNode.getName() + ": " + e.getMessage());
			appendMsg("Failed to resolve linked item: " + dataTreeNode.getName(), msgBuffer);
			return false;
		}
		return true;
	}

	/**
	 * {@return the real folder which corresponds to a folder node or the parent of a file node}
	 * @param dataTreeNode file or folder data tree node
	 * @throws IOException if a linked-folder IO error occurs
	 */
	private DomainFolder getRealFolder(DataTreeNode dataTreeNode) throws IOException {
		DomainFolder folder = null;
		if (dataTreeNode instanceof DomainFileNode fileNode) {
			folder = fileNode.getDomainFile().getParent();
		}
		else if (dataTreeNode instanceof DomainFolderNode folderNode) {
			folder = folderNode.getDomainFolder();
		}
		if (folder instanceof LinkedDomainFolder linkedFolder) {
			// need real folder to simplify relationship checks
			folder = linkedFolder.getRealFolder();
		}
		return folder;
	}

	/**
	 * Remove descendant nodes from the list; having the parent node
	 * is enough when folders are getting pasted.
	 */
	private void removeDescendantsFromList(List<GTreeNode> list) {
		// NOTE: This needs to be optimized and is not well suited 
		// for a large number of nodes
		List<GTreeNode> newList = new ArrayList<>();
		for (int i = 0; i < list.size(); i++) {
			GTreeNode destNode = list.get(i);
			for (int j = 0; j < list.size(); j++) {
				GTreeNode node = list.get(j);
				if (destNode == node) {
					continue;
				}
				if (node.isAncestor(destNode)) {
					newList.add(node);
				}
			}
		}
		for (int i = 0; i < newList.size(); i++) {
			list.remove(newList.get(i));
		}
	}

	private boolean isCutOperation(List<GTreeNode> list) {
		for (GTreeNode node : list) {
			if (node instanceof Cuttable) {
				if (((Cuttable) node).isCut()) {
					return true;
				}
			}
		}
		return false;
	}
}
