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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.app.plugin.core.symboltree.SymbolTreeProvider;

public class CloneSymbolTreeAction extends DockingAction {

	private SymbolTreeProvider provider;

	public CloneSymbolTreeAction(SymbolTreePlugin plugin, SymbolTreeProvider provider) {
		super("Symbol Tree Clone", plugin.getName());
		this.provider = provider;

		setToolBarData(new ToolBarData(new GIcon("icon.provider.clone")));
		setDescription("Create a snapshot (disconnected) copy of this Symbol Tree window");
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return provider.getProgram() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		provider.cloneWindow();
	}

}
