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
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatree.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;

public class ProjectDataPasteAction extends ProjectDataCopyCutBaseAction {
	private static Icon icon = ResourceManager.loadImage("images/page_paste.png");

	public ProjectDataPasteAction(String owner, String group) {
		super("Paste", owner);
		setPopupMenuData(new MenuData(new String[] { "Paste" }, icon, group));
		setKeyBindingData(new KeyBindingData('V', InputEvent.CTRL_DOWN_MASK));
		markHelpUnnecessary();
	}

	@Override
	protected void actionPerformed(FrontEndProjectTreeContext context) {
		GTreeNode node = (GTreeNode) context.getContextObject();
		DomainFolderNode destNode = getFolderForNode(node);

		paste(context.getTree(), destNode);
	}

	@Override
	protected boolean isEnabledForContext(FrontEndProjectTreeContext context) {
		if (!context.hasExactlyOneFileOrFolder()) {
			return false;
		}
		if (!context.isInActiveProject()) {
			return false;
		}
		GTreeNode node = (GTreeNode) context.getContextObject();
		GTreeNode destNode = getFolderForNode(node);
		return checkNodeForPaste(destNode);

	}

	@Override
	protected boolean isAddToPopup(FrontEndProjectTreeContext context) {
		if (!context.hasOneOrMoreFilesAndFolders()) {
			return false;
		}
		return context.isInActiveProject();
	}

	private DomainFolderNode getFolderForNode(GTreeNode node) {
		if (node instanceof DomainFolderNode) {
			return (DomainFolderNode) node;
		}
		return (DomainFolderNode) node.getParent();
	}

	/**
	 * Check the destination node for whether clipboard data can be pasted there.
	 * 
	 * @param destNode destination for paste operation
	 * @return true if least one node can be pasted at destNode
	 */
	private boolean checkNodeForPaste(GTreeNode destNode) {

		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();

		for (GTreeNode node : list) {
			if (!node.isAncestor(destNode)) {
				// at least one node can be pasted from system clipboard
				return true;
			}
		}
		return false;
	}

	/**
	 * Process a "paste" request from a menu action.
	 */
	private void paste(DataTree tree, DomainFolderNode folderNode) {

		List<GTreeNode> list = DataTreeClipboardUtils.getDataTreeNodesFromClipboard();
		boolean isCutOperation = isCutOperation(list);
		checkPasteList(tree, folderNode, list, isCutOperation);

		if (!list.isEmpty()) {
			PasteFileTask task = new PasteFileTask(folderNode, list, isCutOperation);
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
	 * @param destNode destination node
	 * @param list list of nodes to paste
	 * @param isCutOperation true if this is a cut vs copy; for cut, files
	 * cannot be in use
	 */
	private void checkPasteList(DataTree tree, GTreeNode destNode, List<GTreeNode> list,
			boolean isCutOperation) {

		if (list == null) {
			return;
		}

		boolean listChanged = removeDecendantsFromList(list);

		boolean resetClipboard = false;
		StringBuffer sb = new StringBuffer();

		for (int i = 0; i < list.size(); i++) {
			GTreeNode tnode = list.get(i);
			boolean removeNodeFromList = false;

			if (tnode.getParent() != null && isCutOperation && !destNode.equals(tnode)) {
				if (destNode == tnode.getParent()) {
					removeNodeFromList = true;
					sb.append(
						"File " + tnode.getName() + " already exists at " + tnode.getParent());
				}
				else if (tnode instanceof DomainFolderNode) {
					if (destNode.isAncestor(tnode)) {
						removeNodeFromList = true;
					}
				}
			}
			else if (tnode.getParent() == null || destNode == tnode) {
				removeNodeFromList = true;
				if (destNode == tnode) {
					sb.append("Cannot paste file to itself: " + destNode.getName());
				}
			}
			if (removeNodeFromList) {
				list.remove(i);
				if (i > 0) {
					--i;
				}
				resetClipboard = true;
				if (tnode.getParent() != null) {
					if (tnode instanceof Cuttable) {
						((Cuttable) tnode).setIsCut(false);
					}
				}
			}
		}
		if (resetClipboard || listChanged) {
			if (sb.length() > 0) {
				String title = isCutOperation ? "Cannot Move File(s)" : "Cannot Copy File(s)";
				String action = isCutOperation ? "moved" : "copied";

				Msg.showWarn(getClass(), tree, title,
					"The following file(s) could not be " + action + ":\n" + sb.toString());
			}
		}
	}

	/**
	 * Remove descendant nodes from the list; having the parent node
	 * is enough when folders are getting pasted.
	 */
	private boolean removeDecendantsFromList(List<GTreeNode> list) {
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
		return newList.size() > 0;
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
