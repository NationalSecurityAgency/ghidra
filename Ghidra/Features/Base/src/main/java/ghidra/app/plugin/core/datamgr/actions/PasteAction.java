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
package ghidra.app.plugin.core.datamgr.actions;

import java.awt.datatransfer.*;
import java.awt.dnd.DnDConstants;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.Collections;
import java.util.List;

import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.KeyBindingPrecedence;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeCopyMoveTask.ActionType;
import ghidra.framework.plugintool.PluginTool;

public class PasteAction extends DockingAction {
	private PluginTool tool;
	private Clipboard clipboard;
	private final DataTypeManagerPlugin plugin;

	public PasteAction(DataTypeManagerPlugin plugin) {
		super("Paste", plugin.getName());
		this.plugin = plugin;
		this.clipboard = plugin.getClipboard();
		this.tool = plugin.getTool();
		setPopupMenuData(new MenuData(new String[] { "Paste" }, "Edit"));
		setKeyBindingData(new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_V,
			InputEvent.CTRL_DOWN_MASK), KeyBindingPrecedence.ActionMapLevel));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (node instanceof BuiltInArchiveNode) {
			return false;
		}
		return (node != null);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (!(node instanceof CategoryNode) || !((CategoryNode) node).isEnabled()) {
			return false;
		}
		List<GTreeNode> transferNodeList = getNodesFromClipboard();
		return canPaste(node, transferNodeList);
	}

	private DataTypeTreeNode getSelectedDataTypeTreeNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length == 0) {
			return null;
		}

		if (selectionPaths.length > 1) {
			return null;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		return node;
	}

	private boolean canPaste(DataTypeTreeNode destinationNode, List<GTreeNode> transferNodeList) {
		if (transferNodeList.isEmpty()) {
			return false;
		}

		if (invalidCutNodes(destinationNode, transferNodeList)) {
			return false; // cut nodes that cannot be pasted here
		}

		DataTypesProvider provider = plugin.getProvider();
		DataTypeArchiveGTree tree = provider.getGTree();
		DataTypeDragNDropHandler handler = (DataTypeDragNDropHandler) tree.getDragNDropHandler();

		if (!destinationNode.canPaste(transferNodeList)) {
			return false;
		}

		DataFlavor[] flavors = handler.getSupportedDataFlavors(transferNodeList);
		return handler.isDropSiteOk(destinationNode, flavors, DnDConstants.ACTION_COPY);
	}

	private boolean invalidCutNodes(DataTypeTreeNode destinationNode, List<GTreeNode> nodeList) {
		DataTypeTreeNode node = (DataTypeTreeNode) nodeList.get(0);
		if (!node.isCut()) {
			return false; // hasn't been cut, no problemo
		}

		// can't cut nodes from one archive and paste into another
		ArchiveNode destinationArchiveNode = destinationNode.getArchiveNode();
		for (GTreeNode cutNode : nodeList) {
			DataTypeTreeNode dataTypeTreeNode = (DataTypeTreeNode) cutNode;
			ArchiveNode archiveNode = dataTypeTreeNode.getArchiveNode();
			if (archiveNode != destinationArchiveNode) {
				return true; // is invalid
			}
		}

		return false; // is valid, all nodes in the same destination archive
	}

	private List<GTreeNode> getNodesFromClipboard() {
		Transferable transferable = clipboard.getContents(this);
		if (transferable instanceof GTreeNodeTransferable) {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			return gtTransferable.getAllData();
		}
		return Collections.emptyList();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		GTreeNode destinationNode = (GTreeNode) selectionPaths[0].getLastPathComponent();

		List<GTreeNode> nodeList = getNodesFromClipboard();
		if (nodeList.isEmpty()) {
			return;
		}
		DataTypeTreeNode dataTypeTreeNode = (DataTypeTreeNode) nodeList.get(0);
		if (dataTypeTreeNode.isCut()) { // clear cut nodes on paste operation
			clipboard.setContents(null, null);
		}

		ActionType actionType = getActionType(dataTypeTreeNode);
		DataTypeTreeCopyMoveTask task =
			new DataTypeTreeCopyMoveTask(destinationNode, nodeList, actionType,
				(DataTypeArchiveGTree) gTree,
				plugin.getConflictHandler());
		tool.execute(task, 250);
	}

	private ActionType getActionType(DataTypeTreeNode pasteNode) {
		if (pasteNode.isCut()) {
			return ActionType.MOVE;
		}
		return ActionType.COPY;
	}
}
