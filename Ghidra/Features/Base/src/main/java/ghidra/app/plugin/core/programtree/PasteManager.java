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
package ghidra.app.plugin.core.programtree;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.ConcurrentModificationException;

import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.dnd.GClipboard;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

/**
 * Manage paste operations for the tree.
 */
class PasteManager {

	private ProgramTreeActionManager actionMgr;
	private ProgramDnDTree tree;
	private DefaultTreeModel treeModel;
	private Clipboard cutClipboard;
	private String lastGroupPasted;

	/**
	 * Constructor
	 */
	PasteManager(ProgramTreeActionManager actionMgr) {
		this.actionMgr = actionMgr;
		cutClipboard = actionMgr.getCutClipboard();
	}

	/**
	 * Return true if the pasteNode can be pasted at the destNode.
	 * @param destNode destination node for where the pasteNode will be pasted
	 * @param pasteNode node to paste
	 * @param isCutOperation true if the operation was "cut" versus "copy"
	 */
	boolean isPasteAllowed(ProgramNode destNode, ProgramNode pasteNode, boolean isCutOperation) {
		if (destNode.getProgram() != pasteNode.getProgram() ||
			destNode.getRoot() != pasteNode.getRoot()) {
			return false;
		}
		try {
			if (destNode.getName().equals(pasteNode.getName())) {
				return false;
			}
			if (destNode.isNodeAncestor(pasteNode)) {
				return false;
			}

			if (destNode.isFragment() && pasteNode.isModule()) {
				if (isCutOperation && !pasteNode.getModule().isDescendant(destNode.getFragment())) {

					return true; // pasted module can be flattened onto 
					// destination fragment
				}
				return false;
			}

			if (destNode.isFragment() && pasteNode.isFragment()) {
				if (isCutOperation) {
					return true;
				}
				return false;
			}
			if (destNode.isModule()) {
				ProgramModule destModule = destNode.getModule();

				if (pasteNode.isModule()) {
					if (pasteNode.getModule().isDescendant(destModule)) {
						return false;
					}
					if (!isCutOperation && destModule.contains(pasteNode.getModule())) {
						return false;
					}
				}
				else if (!isCutOperation && destModule.contains(pasteNode.getFragment())) {
					return false;
				}
			}

			return true;
		}
		catch (RuntimeException e) {
			// this is a hack for unknown reasons
		}
		return false;
	}

	/**
	 * Do the paste operation.
	 * @param destNode destination node for where the paste the contents of
	 * system clipboard.
	 */
	@SuppressWarnings("unchecked")
	// cast is OK, it is data that we are expecting
	void paste(ProgramNode destNode) {

		int transactionID = tree.startTransaction("Paste");
		if (transactionID < 0) {
			return;
		}

		TreePath path = destNode.getTreePath();

		// paste from clipboard at path
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable t = systemClipboard.getContents(tree);
		try {
			if (t == null || !t.isDataFlavorSupported(TreeTransferable.localTreeNodeFlavor)) {
				return;
			}
			tree.setBusyCursor(true);
			lastGroupPasted = null;
			ArrayList<ProgramNode> list =
				(ArrayList<ProgramNode>) t.getTransferData(TreeTransferable.localTreeNodeFlavor);

			if (list == null) {
				// SCR 7990--something bad has happened to the copy buffer
				return;
			}

			for (int i = 0; i < list.size(); i++) {
				ProgramNode tnode = list.get(i);

				if (destNode.getRoot() != tnode.getRoot()) {
					lastGroupPasted = null;
					break;
				}

				if (!destNode.getName().equals(tnode.getName())) {
					if (pasteGroup(destNode, tnode)) {
						if (!(destNode.isFragment() && tnode.isModule())) {
							// this was not a "flatten module" operation
							// so we can leave the busy cursor set
							// until the domain object event comes in
							lastGroupPasted = tnode.getName();
						}
					}
				}
			}

			if (lastGroupPasted == null) {
				tree.setBusyCursor(false);
			}

			// do "cut" operations now if there are any
			actionMgr.checkClipboard(true);
			actionMgr.clearSystemClipboard();
			actionMgr.enablePasteAction(false);
			tree.removeSelectionPath(path);
			tree.addSelectionPath(path);

		}
		catch (UnsupportedFlavorException e) {
			// data flavor is not supported
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Data flavor in clipboard is not supported.", e);

		}
		catch (IOException e) {
			// data is no longer available
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Data is no longer available for paste operation", e);
		}
		catch (Exception e) {
			Msg.showError(this, null, null, null, e);
		}
		finally {
			tree.endTransaction(transactionID, true);
		}
	}

	/**
	 * Get the name of the last group that was pasted.
	 */
	String getLastGroupPasted() {
		return lastGroupPasted;
	}

	/**
	 * Method setProgramTreeView.
	 * @param tree
	 */
	void setProgramTreeView(ProgramDnDTree tree) {
		this.tree = tree;
		treeModel = (DefaultTreeModel) tree.getModel();
	}

	/**
	 * Paste the group at nodeToPaste at destNode.
	 */
	private boolean pasteGroup(ProgramNode destNode, ProgramNode nodeToPaste) {

		if (destNode.isFragment()) {
			// can paste either a fragment or a module onto a fragment;
			// for module->fragment, the end result is all code units in
			// descendant fragments are moved to the destination fragment.
			try {
				tree.mergeGroup(nodeToPaste.getGroup(), destNode.getFragment());
				actionMgr.removeFromClipboard(cutClipboard, nodeToPaste);
				return true;

			}
			catch (ConcurrentModificationException e) {
			}
			catch (Exception e) {
				Msg.showError(this, null, null, "Error Merging Fragments", e);
			}
			return false;
		}

		ProgramModule targetModule = destNode.getModule();

		if (targetModule == null) {
			nodeToPaste.setDeleted(false);
			treeModel.reload(nodeToPaste);
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Paste of " + nodeToPaste + " at\n" + destNode.getName() + " is not allowed.");

			return false;
		}

		return pasteNode(destNode, nodeToPaste);
	}

	/**
	 * Paste the node at the destination node.
	 */
	private boolean pasteNode(ProgramNode destNode, ProgramNode nodeToPaste) {

		ProgramModule targetModule = destNode.getModule();
		// make sure we have something to paste
		ProgramModule module = nodeToPaste.getModule();
		ProgramFragment fragment = nodeToPaste.getFragment();

		if (module == null && fragment == null) {
			nodeToPaste.setDeleted(false);
			treeModel.reload(nodeToPaste);
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Could not paste " + nodeToPaste + " at " + targetModule.getName());
			return false;
		}

		boolean pasteOK = false;
		try {
			if (module != null) {
				pasteOK = pasteModule(destNode, nodeToPaste, targetModule, module);
			}
			else {
				pasteOK = pasteFragment(nodeToPaste, targetModule, fragment);
			}

			// don't match the expansion state unless the destination
			// node is already expanded
			if (tree.isExpanded(destNode.getTreePath())) {
				ProgramNode newnode = tree.getChild(destNode, nodeToPaste.getName());
				if (newnode != null) {
					tree.matchExpansionState(nodeToPaste, newnode);
				}
			}
			return pasteOK;

		}
		catch (CircularDependencyException e) {
			removeFromClipboard(nodeToPaste);
			Msg.showError(this, null, "Paste from Clipboard Failed", e.getMessage());
		}
		catch (DuplicateGroupException e) {
			nodeToPaste.setDeleted(false);
			tree.reloadNode(nodeToPaste);

		}
		catch (NotFoundException e) {
			removeFromClipboard(nodeToPaste);
			nodeToPaste.setDeleted(false);
			Msg.showError(this, null, "Paste from Clipboard Failed", e.getMessage());
		}
		return false;
	}

	/**
	 * Paste the fragment at the given module.
	 */
	private boolean pasteFragment(ProgramNode nodeToPaste, ProgramModule targetModule,
			ProgramFragment fragment) throws NotFoundException, DuplicateGroupException {
		boolean pasteOK = false;

		if (targetModule.contains(fragment)) {
			if (targetModule.equals(nodeToPaste.getParentModule())) {
				removeFromClipboard(nodeToPaste);
			}
		}
		else if (actionMgr.clipboardContains(nodeToPaste)) {
			targetModule.reparent(nodeToPaste.getName(), nodeToPaste.getParentModule());
			removeFromClipboard(nodeToPaste);
			pasteOK = true;
		}
		else {
			targetModule.add(fragment);
			pasteOK = true;
		}
		return pasteOK;
	}

	private boolean pasteModule(ProgramNode destNode, ProgramNode nodeToPaste,
			ProgramModule targetModule, ProgramModule module)
			throws NotFoundException, CircularDependencyException, DuplicateGroupException {

		boolean pasteOK = false;

		if (!destNode.wasVisited()) {
			tree.visitNode(destNode);
		}
		if (targetModule.contains(module)) {
			if (targetModule.equals(nodeToPaste.getParentModule())) {
				removeFromClipboard(nodeToPaste);
			}
		}
		else if (actionMgr.clipboardContains(nodeToPaste)) {
			targetModule.reparent(nodeToPaste.getName(), nodeToPaste.getParentModule());
			removeFromClipboard(nodeToPaste);
			pasteOK = true;
		}
		else {
			targetModule.add(module);
			pasteOK = true;
		}
		if (pasteOK && tree.isExpanded(destNode.getTreePath())) {
			tree.groupAdded(module); // need to add the
			// group now so that the expansion can be
			// matched
		}
		return pasteOK;
	}

	/**
	 * Remove the given node from the cut clipboard, so that "cut" changes
	 * will not be applied.
	 * @param node node to remove from the cut clipboard
	 */
	private void removeFromClipboard(ProgramNode node) {
		actionMgr.removeFromClipboard(cutClipboard, node);
		node.setDeleted(false);
		tree.reloadNode(node);
	}

}
