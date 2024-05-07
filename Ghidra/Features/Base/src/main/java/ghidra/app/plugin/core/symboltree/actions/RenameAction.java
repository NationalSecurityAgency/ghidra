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

import docking.action.MenuData;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolTreeNode;

public class RenameAction extends SymbolTreeContextAction {

	public RenameAction(SymbolTreePlugin plugin) {
		super("Rename Symbol", plugin.getName());
		setPopupMenuData(
			new MenuData(new String[] { "Rename" }, null, "xxx", MenuData.NO_MNEMONIC, "1"));
	}

	@Override
	public boolean isEnabledForContext(SymbolTreeActionContext context) {
		SymbolTreeNode node = context.getSelectedNode();
		return node instanceof SymbolNode;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		context.getSymbolTree().startEditing(context.getSelectedNode());
	}

}
