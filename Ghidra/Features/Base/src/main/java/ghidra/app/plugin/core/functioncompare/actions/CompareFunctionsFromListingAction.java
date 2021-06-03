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
package ghidra.app.plugin.core.functioncompare.actions;

import java.util.HashSet;
import java.util.Set;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;

/**
 * Creates a comparison between a set of functions extracted from selections
 * in the listing
 */
public class CompareFunctionsFromListingAction extends CompareFunctionsAction {

	private final static String FUNCTION_MENU_SUBGROUP = "Function";

	/**
	 * Constructor
	 * 
	 * @param tool the plugin tool
	 * @param owner the action owner
	 */
	public CompareFunctionsFromListingAction(PluginTool tool, String owner) {
		super(tool, owner);

		// this action is used as a global action--do not add it to the toolbar
		setToolBarData(null);

		//
		// Guilty knowledge of other function-related menu items.
		// See the FunctionPlugin for this value 
		// 		
		String menuSubGroup = "Z_End";
		Icon icon = null; // we don't use icons in the Listing popup menu
		setPopupMenuData(new MenuData(new String[] { POPUP_MENU_NAME }, icon,
			FUNCTION_MENU_SUBGROUP, MenuData.NO_MNEMONIC,
			menuSubGroup));
	}

	@Override
	public boolean isAddToPopup(ActionContext actionContext) {
		return actionContext instanceof ListingActionContext && isEnabledForContext(actionContext);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context instanceof ListingActionContext;
	}

	@Override
	protected Set<Function> getSelectedFunctions(ActionContext actionContext) {
		ListingActionContext listingContext = (ListingActionContext) actionContext;
		ProgramSelection selection = listingContext.getSelection();
		Program program = listingContext.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Set<Function> functions = new HashSet<>();
		FunctionIterator functionIter = functionManager.getFunctions(selection, true);
		for (Function selectedFunction : functionIter) {
			functions.add(selectedFunction);
		}
		return functions;
	}
}
