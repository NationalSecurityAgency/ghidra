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
package ghidra.app.plugin.core.symboltree.actions;

import static docking.KeyBindingPrecedence.ActionMapLevel;

import java.awt.datatransfer.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import docking.widgets.tree.support.GTreeTransferHandler;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode;
import resources.ResourceManager;

public class CutAction extends SymbolTreeContextAction {
	private final static Icon CUT_ICON = ResourceManager.loadImage("images/edit-cut22.png");
	private final SymbolTreeProvider provider;
	private ClipboardOwner clipboardOwner;

	public CutAction(SymbolTreePlugin plugin, SymbolTreeProvider provider) {
		super("Cut SymbolTree Node", plugin.getName());
		this.provider = provider;
		setEnabled(false);
		setPopupMenuData(new MenuData(new String[] { "Cut" }, CUT_ICON, "cut/paste"));
		KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK);
		setKeyBindingData(new KeyBindingData(keyStroke, ActionMapLevel));

		clipboardOwner = (currentClipboard, transferable) -> {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			List<GTreeNode> nodeList = gtTransferable.getAllData();
			setNodesCut(nodeList, false);
		};
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length == 0) {
			return false;
		}

		// only valid if all selected paths are of the correct type
		for (TreePath path : selectionPaths) {
			Object pathComponent = path.getLastPathComponent();
			if (!(pathComponent instanceof SymbolTreeNode)) {
				return false;
			}

			SymbolTreeNode node = (SymbolTreeNode) pathComponent;
			if (!node.canCut()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();

		clearClipboardFromPreviousCut();

		List<GTreeNode> transferableList = createList(selectionPaths);
		setClipboardContents(context.getSymbolTree(), provider.getClipboard(), transferableList);

		setNodesCut(transferableList, true);
		context.getSymbolTree().repaint();
	}

	private void clearClipboardFromPreviousCut() {
		Transferable transferable = provider.getClipboard().getContents(this);
		if (transferable instanceof SymbolTreeNodeTransferable) {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			List<GTreeNode> nodeList = gtTransferable.getAllData();
			setNodesCut(nodeList, false);
		}
	}

	private void setNodesCut(List<GTreeNode> nodeList, boolean isCut) {
		for (GTreeNode node : nodeList) {
			SymbolTreeNode cutNode = (SymbolTreeNode) node;
			cutNode.setNodeCut(isCut);
		}
	}

	private List<GTreeNode> createList(TreePath[] paths) {
		ArrayList<GTreeNode> list = new ArrayList<>();
		if (paths != null) {
			for (TreePath element : paths) {
				GTreeNode node = (GTreeNode) element.getLastPathComponent();
				list.add(node);
			}
		}
		return list;
	}

	private void setClipboardContents(GTree gTree, Clipboard clipboard, List<GTreeNode> list) {
		GTreeTransferHandler dragNDropHandler = gTree.getDragNDropHandler();
		Transferable contents = new SymbolTreeNodeTransferable(dragNDropHandler, list);

		clipboard.setContents(contents, clipboardOwner);
	}

	// this class is just a marker interface so we can tell if we put the contents into the
	// clipboard
	class SymbolTreeNodeTransferable extends GTreeNodeTransferable {
		public SymbolTreeNodeTransferable(GTreeTransferHandler handler,
				List<GTreeNode> selectedData) {
			super(handler, selectedData);
		}
	}
}
