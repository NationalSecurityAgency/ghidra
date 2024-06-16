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
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.LabelFieldLocation;
import ghidra.util.*;

/**
 * An action to show all references to the {@link HighSymbol} under the cursor in the Decompiler.
 * A HighSymbol is a symbol recovered by the decompiler during decompilation and is generally 
 * distinct from a {@link Symbol} stored in the Ghidra database (for more details see the
 * "HighSymbol" entry in the "Decompiler Concepts" section of the Ghidra help).  For this action
 * to be enabled, the HighSymbol must represent a function or global variable (not a local variable 
 * or a parameter)
 */
public class FindReferencesToHighSymbolAction extends AbstractDecompilerAction {

	private static final String MENU_ITEM_TEXT = "Find References to";
	public static final String NAME = "Find References to Symbol";

	public FindReferencesToHighSymbolAction() {
		super(NAME);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionFindReferences"));
		setPopupMenuData(
			new MenuData(new String[] { LocationReferencesService.MENU_GROUP, MENU_ITEM_TEXT }));
	}

	private void updateMenuName(String newName) {
		String menuName = MENU_ITEM_TEXT + ' ' + newName;
		MenuData data = getPopupMenuData().cloneData();
		data.setMenuPath(new String[] { LocationReferencesService.MENU_GROUP, menuName });
		setPopupMenuData(data);
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = getFunction(context);
		if (function != null && !(function instanceof UndefinedFunction)) {
			updateMenuName(function.getName());
			return true;
		}
		ClangToken token = context.getTokenAtCursor();
		if (token == null) {
			return false;
		}
		HighSymbol highSymbol = token.getHighSymbol(context.getHighFunction());

		if (highSymbol == null || highSymbol.getStorage().isBadStorage() ||
			!highSymbol.isGlobal()) {
			return false;
		}
		updateMenuName(highSymbol.getName());
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
		LabelFieldLocation location = null;
		Function function = getFunction(context);
		if (function != null && !(function instanceof UndefinedFunction)) {
			location = new LabelFieldLocation(function.getSymbol());
		}
		else {
			HighSymbol highSymbol =
				context.getTokenAtCursor().getHighSymbol(context.getHighFunction());
			location = new LabelFieldLocation(context.getProgram(),
				highSymbol.getStorage().getMinAddress(), highSymbol.getName());
		}
		DecompilerProvider provider = context.getComponentProvider();
		service.showReferencesToLocation(location, provider);
	}
}
