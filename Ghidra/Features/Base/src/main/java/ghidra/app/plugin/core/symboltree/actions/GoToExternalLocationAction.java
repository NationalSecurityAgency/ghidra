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
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.context.ProgramSymbolContextAction;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.*;
import resources.ResourceManager;

public class GoToExternalLocationAction extends ProgramSymbolContextAction {

	private SymbolTreePlugin plugin;

	public GoToExternalLocationAction(SymbolTreePlugin plugin) {
		super("Go To External Location", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Go to External Location" },
			ResourceManager.loadImage("images/searchm_obj.gif"), "0External"));
	}

	@Override
	public boolean isEnabledForContext(ProgramSymbolActionContext context) {

		if (context.getSymbolCount() != 1) {
			return false;
		}
		Symbol symbol = context.getFirstSymbol();
		if (symbol == null) {
			return false;
		}
		if (symbol.getSymbolType() == SymbolType.LABEL ||
			symbol.getSymbolType() == SymbolType.FUNCTION) {
			return symbol.isExternal();
		}
		return false;
	}

	@Override
	public void actionPerformed(ProgramSymbolActionContext context) {
		Symbol symbol = context.getFirstSymbol();
		if (symbol == null) {
			return; // assume symbol removed
		}
		Object obj = symbol.getObject();
		ExternalLocation extLoc = null;
		if (obj instanceof Function) {
			Function f = (Function) obj;
			if (f.isExternal()) {
				extLoc = f.getExternalLocation();
			}
		}
		if (obj instanceof ExternalLocation) {
			extLoc = (ExternalLocation) obj;
		}
		if (extLoc != null) {
			plugin.goTo(extLoc);
		}
	}
}
