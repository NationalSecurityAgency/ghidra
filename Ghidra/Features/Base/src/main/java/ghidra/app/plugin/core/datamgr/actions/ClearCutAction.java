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
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.awt.event.KeyEvent;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;

public class ClearCutAction extends DockingAction {
	private Clipboard clipboard;

	public ClearCutAction(DataTypeManagerPlugin plugin) {
		super("Clear Cut", plugin.getName());
		clipboard = plugin.getClipboard();

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_ESCAPE, 0));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Transferable transferable = clipboard.getContents(this);
		if (transferable instanceof GTreeNodeTransferable) {
			GTreeNodeTransferable gtTransferable = (GTreeNodeTransferable) transferable;
			List<GTreeNode> nodeList = gtTransferable.getAllData();
			if (nodeList.isEmpty()) {
				return;
			}
			DataTypeTreeNode node = (DataTypeTreeNode) nodeList.get(0);
			if (node.isCut()) {
				clipboard.setContents(null, null);
			}

		}
	}

}
