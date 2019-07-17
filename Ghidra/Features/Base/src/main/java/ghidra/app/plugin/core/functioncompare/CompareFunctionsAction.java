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
package ghidra.app.plugin.core.functioncompare;

import java.util.ArrayList;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.context.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * An action that displays a function comparison panel for the two functions that are selected
 * in the program.
 */
public class CompareFunctionsAction extends ProgramContextAction {

	FunctionComparisonPlugin functionComparisonPlugin;

	/**
	 * Constructs an action for displaying a panel that allows the user to compare functions.
	 * @param plugin the plugin that owns this action.
	 */
	CompareFunctionsAction(FunctionComparisonPlugin plugin) {
		super("Compare Two Functions", plugin.getName());
		functionComparisonPlugin = plugin;

		// TODO no icon for now, while this action is at the top-level menu.  When we put it in
		//      its final resting place, we can put the icon back.
		// ImageIcon icon = ResourceManager.loadImage("images/page_white_c.png");
		setPopupMenuData(new MenuData(new String[] { "Compare Selected Functions..." }, null,
			FunctionComparisonPlugin.FUNCTION_MENU_SUBGROUP, MenuData.NO_MNEMONIC,
			"Z_End" /* See the FunctionPlugin for this value */));

		setHelpLocation(new HelpLocation("FunctionComparison", "Compare_Selected_Functions"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof ListingActionContext);
	}

	@Override
	protected boolean isEnabledForContext(ProgramActionContext context) {
		return (context instanceof ListingActionContext);
	}

	@Override
	public void actionPerformed(ProgramActionContext context) {

		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			ProgramSelection selection = listingContext.getSelection();
			Program program = listingContext.getProgram();
			FunctionManager functionManager = program.getFunctionManager();
			ArrayList<Function> functionList = new ArrayList<>();
			FunctionIterator functionIter = functionManager.getFunctions(selection, true);
			for (Function selectedFunction : functionIter) {
				functionList.add(selectedFunction);
			}
			Function[] functions = functionList.toArray(new Function[functionList.size()]);
			if (functions.length < 2) {
				String message = "You must select at least two functions in the current program.";
				Msg.showError(this, null, "Compare Functions", message);
				return;
			}
			functionComparisonPlugin.showFunctionComparisonProvider(functions);
		}
	}
}
