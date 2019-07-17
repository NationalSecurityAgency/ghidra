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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;

import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.KeyBindingPrecedence;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import docking.widgets.tree.support.GTreeTransferHandler;

public class CutAction extends DockingAction {
	private Clipboard clipboard;
	private ClipboardOwner clipboardOwner;

	public CutAction(DataTypeManagerPlugin plugin) {
		super("Cut", plugin.getName());
		clipboard = plugin.getClipboard();
		setPopupMenuData(new MenuData(new String[] { "Cut" }, "Edit"));
		setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_X,
			InputEvent.CTRL_DOWN_MASK), KeyBindingPrecedence.ActionMapLevel));
		setEnabled(true);

		clipboardOwner = new ClipboardOwner() {
			public void lostOwnership(Clipboard currentClipboard, Transferable transferable) {
				GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
				List<GTreeNode> nodeList = gtTransferable.getAllData();
				setNodesCut(nodeList, false);
			}
		};
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

		// only valid if all selected paths are of the correct type
		for (TreePath path : selectionPaths) {
			DataTypeTreeNode node = (DataTypeTreeNode) path.getLastPathComponent();
			if (!node.canCut()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		// cut to clipboard
		TreePath[] paths = gTree.getSelectionPaths();
		List<GTreeNode> nodeList = createList(paths);

		clearClipboard();

		setClipboardContents(gTree, clipboard, nodeList);

		setNodesCut(nodeList, true);
		gTree.repaint();
	}

	private void setNodesCut(List<GTreeNode> nodeList, boolean isCut) {
		for (GTreeNode node : nodeList) {
			DataTypeTreeNode cutNode = (DataTypeTreeNode) node;
			cutNode.setNodeCut(isCut);
		}
	}

	private ArrayList<GTreeNode> createList(TreePath[] paths) {
		ArrayList<GTreeNode> list = new ArrayList<GTreeNode>();
		if (paths != null) {
			for (int i = 0; i < paths.length; i++) {
				GTreeNode node = (GTreeNode) paths[i].getLastPathComponent();
				list.add(node);
			}
		}
		return list;
	}

	private void clearClipboard() {
		Transferable transferable = clipboard.getContents(this);
		if (transferable instanceof DataTypeTreeNodeTransferable) {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			List<GTreeNode> nodeList = gtTransferable.getAllData();
			setNodesCut(nodeList, false);
		}
	}

	/**
	 * Set the clipboard contents with the list of tree nodes.
	 * @param gTree the tree fro which the cut operation was triggered
	 * @param clipboard clipboard in which to place our contents
	 * @param list list of nodes to place into the clipboard
	 */
	private void setClipboardContents(GTree gTree, Clipboard clipboard, List<GTreeNode> list) {
		GTreeTransferHandler dragNDropHandler = gTree.getDragNDropHandler();
		Transferable contents = new DataTypeTreeNodeTransferable(dragNDropHandler, list);

		clipboard.setContents(contents, clipboardOwner);
	}

	// this class is just a marker interface so we can tell if we put the contents into the
	// clipboard
	class DataTypeTreeNodeTransferable extends GTreeNodeTransferable {
		public DataTypeTreeNodeTransferable(GTreeTransferHandler handler,
				List<GTreeNode> selectedData) {
			super(handler, selectedData);
		}
	}
}
