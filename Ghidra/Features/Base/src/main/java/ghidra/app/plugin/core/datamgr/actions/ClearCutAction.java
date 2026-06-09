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

import java.awt.datatransfer.Clipboard;
import java.awt.event.KeyEvent;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;

public class ClearCutAction extends DockingAction {
	private Clipboard clipboard;

	public ClearCutAction(DataTypeManagerPlugin plugin) {
		super("Clear Cut", plugin.getName());
		clipboard = plugin.getClipboard();

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_ESCAPE, 0));

		setEnabled(true);
	}

	@Override
	public boolean isValidContext(ActionContext context) {

		// 
		// This action is particular about when it is valid.  This is so that it does not interfere
		// with Escape key presses for the parent window, except when this action has work to do.
		//
		if (!(context instanceof DataTypesActionContext dtc)) {
			return false;
		}

		return !dtc.getClipboardNodes().isEmpty();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		// If we are valid, then we are enabled (see isValidContext()).  Most actions are always 
		// valid, but only sometimes enabled.  We use the valid check to remove ourselves completely
		// from the workflow.  But, if we are valid, then we are also enabled.
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypesActionContext dtc = (DataTypesActionContext) context;
		List<GTreeNode> nodeList = dtc.getClipboardNodes();
		DataTypeTreeNode node = (DataTypeTreeNode) nodeList.get(0);
		if (node.isCut()) {
			clipboard.setContents(null, null);
		}
	}

}
