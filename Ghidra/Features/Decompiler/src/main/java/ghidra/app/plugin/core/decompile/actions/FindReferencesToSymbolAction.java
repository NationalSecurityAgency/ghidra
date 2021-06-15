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

import docking.action.MenuData;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
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
public class FindReferencesToSymbolAction extends AbstractDecompilerAction {

	private static final String MENU_ITEM_TEXT = "Find References to";
	public static final String NAME = "Find References to Symbol";

	public FindReferencesToSymbolAction() {
		super(NAME);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFindReferences"));
		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, MENU_ITEM_TEXT }));
	}

	private Symbol getSymbol(DecompilerActionContext context) {

		ProgramLocation location = context.getLocation();
		if (location == null) {
			return null;
		}

		Address address = getDecompilerSymbolAddress(location);
		if (address == null) {
			address = location.getAddress();
		}
		Program program = context.getProgram();
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol = symbolTable.getPrimarySymbol(address);
		return symbol;
	}

	private Address getDecompilerSymbolAddress(ProgramLocation location) {

		if (!(location instanceof DecompilerLocation)) {
			return null;
		}

		ClangToken token = ((DecompilerLocation) location).getToken();
		if (!(token instanceof ClangFuncNameToken)) {
			return null;
		}

		Program program = location.getProgram();
		Function function = DecompilerUtils.getFunction(program, (ClangFuncNameToken) token);
		if (function != null) {
			return function.getEntryPoint();
		}

		return null;
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

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Symbol symbol = getSymbol(context);
		if (symbol == null) {
			return false;
		}

		updateMenuName(symbol);

		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		LocationReferencesService service =
			context.getTool().getService(LocationReferencesService.class);
		if (service == null) {
			Msg.showError(this, null, "Missing Plugin",
				"The " + LocationReferencesService.class.getSimpleName() + " is not installed.\n" +
					"Please add the plugin implementing this service.");
			return;
		}

		Symbol symbol = getSymbol(context);
		LabelFieldLocation location = new LabelFieldLocation(symbol);
		DecompilerProvider provider = context.getComponentProvider();
		service.showReferencesToLocation(location, provider);
	}
}
