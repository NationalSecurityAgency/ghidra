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

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;
import javax.swing.tree.TreePath;

import docking.KeyBindingPrecedence;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import ghidra.app.plugin.core.symboltree.*;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode;
import resources.ResourceManager;

public class PasteAction extends SymbolTreeContextAction {

	private final static Icon PASTE_ICON = ResourceManager.loadImage("images/page_paste.png");

	public PasteAction(SymbolTreePlugin plugin, SymbolTreeProvider provider) {
		super("Paste Symbols", plugin.getName());
		setPopupMenuData(new MenuData(new String[] { "Paste" }, PASTE_ICON, "cut/paste"));
		setKeyBindingData(
			new KeyBindingData(KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK),
				KeyBindingPrecedence.ActionMapLevel));
	}

	@Override
	public boolean isAddToPopup(SymbolTreeActionContext context) {
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		return selectionPaths.length > 0;
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {

		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		Object pathComponent = selectionPaths[0].getLastPathComponent();
		if (!(pathComponent instanceof SymbolTreeNode)) {
			return false;
		}

		SymbolTreeNode node = (SymbolTreeNode) pathComponent;
		Clipboard clipboard = context.getSymbolTreeProvider().getClipboard();
		Transferable transferable = clipboard.getContents(this);
		if (transferable == null) {
			return false;
		}
		return node.supportsDataFlavors(transferable.getTransferDataFlavors());
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		TreePath path = context.getSelectedPath();
		if (path == null) {
			return;
		}
		GTreeNode destinationNode = (GTreeNode) path.getLastPathComponent();
		Clipboard clipboard = context.getSymbolTreeProvider().getClipboard();
		Transferable transferable = clipboard.getContents(this);
		if (transferable == null) {
			return;
		}

		GTreeDragNDropHandler dragNDropHandler = context.getSymbolTree().getDragNDropHandler();
		dragNDropHandler.drop(destinationNode, transferable, DnDConstants.ACTION_MOVE);
		clipboard.setContents(null, null);
	}

}
