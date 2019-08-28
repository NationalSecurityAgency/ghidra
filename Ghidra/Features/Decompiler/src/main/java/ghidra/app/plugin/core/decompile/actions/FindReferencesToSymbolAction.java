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
package ghidra.app.plugin.core.decompile.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * An action to show all references to the symbol under the cursor in the Decompiler
 */
public class FindReferencesToSymbolAction extends DockingAction {

	private static final String MENU_ITEM_TEXT = "Find References to";
	public static final String NAME = "Find References to Symbol";
	private PluginTool tool;

	public FindReferencesToSymbolAction(PluginTool tool, String owner) {
		super(NAME, owner);
		this.tool = tool;

		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, MENU_ITEM_TEXT }));
		setHelpLocation(new HelpLocation(HelpTopics.FIND_REFERENCES, HelpTopics.FIND_REFERENCES));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
		if (decompilerContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		LocationReferencesService service = tool.getService(LocationReferencesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The " + LocationReferencesService.class.getSimpleName() + " is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		Symbol symbol = getSymbol(decompilerContext);
		LabelFieldLocation location = new LabelFieldLocation(symbol);
		DecompilerProvider provider = decompilerContext.getComponentProvider();
		service.showReferencesToLocation(location, provider);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		Symbol symbol = getSymbol((DecompilerActionContext) context);
		if (symbol == null) {
			return false;
		}

		updateMenuName(symbol);

		return true;
	}

	private Symbol getSymbol(DecompilerActionContext context) {

		ProgramLocation location = context.getLocation();
		if (location == null) {
			return null;
		}

		Address address = location.getAddress();
		Program program = context.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		return symbol;
	}

	private void updateMenuName(Symbol symbol) {

		if (symbol == null) {
			return; // not sure if this can happen
		}

		String symbolName = symbol.getName(false);
		String menuName = MENU_ITEM_TEXT + ' ' + symbolName;

		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { LocationReferencesService.MENU_GROUP, menuName });
		setPopupMenuData(data);
	}
}
