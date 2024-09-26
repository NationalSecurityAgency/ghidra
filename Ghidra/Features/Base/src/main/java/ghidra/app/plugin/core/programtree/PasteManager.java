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
import java.util.ConcurrentModificationException;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.dnd.GClipboard;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

/**
 * Manage paste operations for the Program Tree.
 */
class PasteManager {

	private ProgramTreeActionManager actionManager;
	private String lastGroupPasted;

	PasteManager(ProgramTreeActionManager actionManager) {
		this.actionManager = actionManager;
	}

	boolean isPasteAllowed(ProgramNode destNode, ProgramNode pasteNode, boolean isCutOperation) {
		if (destNode.getProgram() != pasteNode.getProgram() ||
			destNode.getRoot() != pasteNode.getRoot()) {
			return false;
		}

		if (destNode.getName().equals(pasteNode.getName())) {
			return false;
		}

		if (destNode.isNodeAncestor(pasteNode)) {
			return false;
		}

		if (destNode.isFragment() && pasteNode.isModule()) {
			if (isCutOperation && !pasteNode.getModule().isDescendant(destNode.getFragment())) {
				return true; // pasted module can be flattened onto destination fragment
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

	@SuppressWarnings("unchecked") // cast is OK, it is data that we are expecting
	void paste(ProgramDnDTree tree, ProgramNode destNode) {

		int transactionID = tree.startTransaction("Paste");
		if (transactionID < 0) {
			return;
		}

		TreePath path = destNode.getTreePath();

		// paste from clipboard at path
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable t = systemClipboard.getContents(tree);
		try {
			if (t == null ||
				!t.isDataFlavorSupported(ProgramTreeTransferable.localTreeNodeFlavor)) {
				return;
			}

			tree.setBusyCursor(true);
			lastGroupPasted = null;
			List<ProgramNode> list =
				(List<ProgramNode>) t.getTransferData(ProgramTreeTransferable.localTreeNodeFlavor);
			if (list == null) {
				return;
			}

			for (ProgramNode node : list) {
				if (destNode.getRoot() != node.getRoot()) {
					lastGroupPasted = null;
					break;
				}

				if (!destNode.getName().equals(node.getName())) {
					if (pasteGroup(tree, destNode, node)) {
						if (!(destNode.isFragment() && node.isModule())) {
							// this was not a "flatten module" operation
							// so we can leave the busy cursor set
							// until the domain object event comes in
							lastGroupPasted = node.getName();
						}
					}
				}
			}

			if (lastGroupPasted == null) {
				tree.setBusyCursor(false);
			}

			// do "cut" operations now if there are any
			actionManager.cutClipboardNodes(tree);
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
			Msg.showError(this, null, "Unexpected Exception Pasting",
				"Unexpected exception pasting nodes", e);
		}
		finally {
			tree.endTransaction(transactionID, true);
		}
	}

	String getLastGroupPasted() {
		return lastGroupPasted;
	}

	private boolean pasteGroup(ProgramDnDTree tree, ProgramNode destNode, ProgramNode nodeToPaste) {

		if (destNode.isFragment()) {
			// can paste either a fragment or a module onto a fragment;
			// for module->fragment, the end result is all code units in
			// descendant fragments are moved to the destination fragment.
			try {
				tree.mergeGroup(nodeToPaste.getGroup(), destNode.getFragment());
				actionManager.removeFromClipboard(tree, nodeToPaste);
				return true;

			}
			catch (ConcurrentModificationException e) {
				// ha!
			}
			catch (Exception e) {
				Msg.showError(this, null, null, "Error Merging Fragments", e);
			}
			return false;
		}

		ProgramModule targetModule = destNode.getModule();

		if (targetModule == null) {
			actionManager.clearCut(nodeToPaste);
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Paste of " + nodeToPaste + " at\n" + destNode.getName() + " is not allowed.");

			return false;
		}

		return pasteNode(tree, destNode, nodeToPaste);
	}

	private boolean pasteNode(ProgramDnDTree tree, ProgramNode destNode, ProgramNode nodeToPaste) {

		ProgramModule targetModule = destNode.getModule();
		ProgramModule module = nodeToPaste.getModule();
		ProgramFragment fragment = nodeToPaste.getFragment();

		if (module == null && fragment == null) {
			actionManager.clearCut(nodeToPaste);
			Msg.showError(this, null, "Paste from Clipboard Failed",
				"Could not paste " + nodeToPaste + " at " + targetModule.getName());
			return false;
		}

		boolean pasteOK = false;
		try {
			if (module != null) {
				pasteOK = pasteModule(tree, destNode, nodeToPaste, targetModule, module);
			}
			else {
				pasteOK = pasteFragment(tree, nodeToPaste, targetModule, fragment);
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
			Msg.showError(this, null, "Paste from Clipboard Failed", e.getMessage());
		}
		catch (DuplicateGroupException e) {
			// handled below
		}
		catch (NotFoundException e) {
			Msg.showError(this, null, "Paste from Clipboard Failed", e.getMessage());
		}

		removeFromClipboard(tree, nodeToPaste);
		return false;
	}

	/**
	 * Paste the fragment at the given module.
	 */
	private boolean pasteFragment(ProgramDnDTree tree, ProgramNode nodeToPaste,
			ProgramModule targetModule, ProgramFragment fragment)
			throws NotFoundException, DuplicateGroupException {
		boolean pasteOK = false;

		if (targetModule.contains(fragment)) {
			if (targetModule.equals(nodeToPaste.getParentModule())) {
				removeFromClipboard(tree, nodeToPaste);
			}
		}
		else if (actionManager.clipboardContains(nodeToPaste)) {
			targetModule.reparent(nodeToPaste.getName(), nodeToPaste.getParentModule());
			removeFromClipboard(tree, nodeToPaste);
			pasteOK = true;
		}
		else {
			targetModule.add(fragment);
			pasteOK = true;
		}
		return pasteOK;
	}

	private boolean pasteModule(ProgramDnDTree tree, ProgramNode destNode, ProgramNode nodeToPaste,
			ProgramModule targetModule, ProgramModule module)
			throws NotFoundException, CircularDependencyException, DuplicateGroupException {

		boolean pasteOK = false;

		if (!destNode.wasVisited()) {
			tree.visitNode(destNode);
		}
		if (targetModule.contains(module)) {
			if (targetModule.equals(nodeToPaste.getParentModule())) {
				removeFromClipboard(tree, nodeToPaste);
			}
		}
		else if (actionManager.clipboardContains(nodeToPaste)) {
			targetModule.reparent(nodeToPaste.getName(), nodeToPaste.getParentModule());
			removeFromClipboard(tree, nodeToPaste);
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

	private void removeFromClipboard(ProgramDnDTree tree, ProgramNode node) {
		actionManager.removeFromClipboard(tree, node);
		actionManager.clearCut(node);
	}

}
