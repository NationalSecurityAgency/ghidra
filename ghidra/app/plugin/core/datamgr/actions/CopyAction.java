/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.datamgr.actions;

import static docking.KeyBindingPrecedence.ActionMapLevel;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;

import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import docking.widgets.tree.support.GTreeTransferHandler;

public class CopyAction extends DockingAction {
	private Clipboard clipboard;

	public CopyAction(DataTypeManagerPlugin plugin) {
		super("Copy", plugin.getName());
		clipboard = plugin.getClipboard();
		String group = "Edit";

		setPopupMenuData(new MenuData(new String[] { "Copy" }, group));
		setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_C,
			InputEvent.CTRL_DOWN_MASK), ActionMapLevel));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length == 0) {
			return false;
		}

		return !containsInvalidNodes(selectionPaths);
	}

	private boolean containsInvalidNodes(TreePath[] selectionPaths) {
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node instanceof ArchiveRootNode) {
				return true;
			}
			else if (node instanceof ArchiveNode) {
				return true;
			}
			else if (node instanceof CategoryNode) {
				CategoryNode categoryNode = (CategoryNode) node;
				return !categoryNode.isEnabled();
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		// cut to clipboard
		TreePath[] paths = gTree.getSelectionPaths();
		List<GTreeNode> nodeList = createList(paths);
		setClipboardContents(gTree, clipboard, nodeList);
	}

	private ArrayList<GTreeNode> createList(TreePath[] paths) {
		ArrayList<GTreeNode> list = new ArrayList<GTreeNode>();
		if (paths != null) {
			for (TreePath element : paths) {
				GTreeNode node = (GTreeNode) element.getLastPathComponent();
				list.add(node);
			}
		}
		return list;
	}

	/**
	 * Set the clipboard contents with the list of tree nodes.
	 * @param gTree the tree fro which the cut operation was triggered
	 * @param clipboard clipboard in which to place our contents
	 * @param list list of nodes to place into the clipboard
	 */
	private void setClipboardContents(GTree gTree, Clipboard clipboard, final List<GTreeNode> list) {
		GTreeTransferHandler dragNDropHandler = gTree.getDragNDropHandler();
		Transferable contents = new GTreeNodeTransferable(dragNDropHandler, list);

		clipboard.setContents(contents, new ClipboardOwner() {
			public void lostOwnership(Clipboard currentClipboard, Transferable transferable) {
				// we don't care
			}
		});
	}
}
