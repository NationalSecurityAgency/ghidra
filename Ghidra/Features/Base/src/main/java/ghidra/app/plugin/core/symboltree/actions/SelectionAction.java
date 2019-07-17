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
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class SelectionAction extends SymbolTreeContextAction {

	private Plugin plugin;

	public SelectionAction(Plugin plugin) {
		super("Make Selection", plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Make Selection" }, "0Middle"));
	}

	@Override
	protected boolean isEnabledForContext(SymbolTreeActionContext context) {
		for (Symbol s : context.getSymbols()) {
			if (!s.isExternal()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public void actionPerformed(SymbolTreeActionContext context) {
		AddressSet set = new AddressSet();
		for (Symbol symbol : context.getSymbols()) {
			if (symbol.isExternal()) {
				continue;
			}
			Object symbolObject = symbol.getObject();
			if (symbolObject instanceof Namespace) {
				Namespace namespace = (Namespace) symbolObject;
				set.add(namespace.getBody());
			}
			else if (symbolObject instanceof Variable) {
				ProgramLocation loc = symbol.getProgramLocation();
				set.addRange(loc.getAddress(), loc.getAddress());
			}
			else if (symbolObject instanceof CodeUnit) {
				CodeUnit cu = (CodeUnit) symbolObject;
				set.addRange(cu.getMinAddress(), cu.getMaxAddress());
			}
		}

		if (!set.isEmpty()) {
			plugin.firePluginEvent(new ProgramSelectionPluginEvent(plugin.getName(),
				new ProgramSelection(set), context.getProgram()));
		}
	}
}
