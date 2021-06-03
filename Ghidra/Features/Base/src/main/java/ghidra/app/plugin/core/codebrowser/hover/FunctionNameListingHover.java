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
package ghidra.app.plugin.core.codebrowser.hover;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * A hover service to show tool tip text for hovering over a label.
 * The tooltip shows the label along with its namespace information.
 * This provides the hover capability for the FunctionNameHoverPlugin and can
 * also be used to directly provide this hover capability to a listing.
 */
public class FunctionNameListingHover extends AbstractConfigurableHover
		implements ListingHoverService {

	private static final String NAME = "Function Name Display";
	private static final String DESCRIPTION =
		"Toggle whether the full symbol name is shown as a tooltip.  This only applies " +
			"when displaying namespaces.";
	private static final int PRIORITY = 20;

	public FunctionNameListingHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_BROWSER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || programLocation == null) {
			return null;
		}

		if (!(programLocation instanceof LabelFieldLocation)) {
			return null;
		}

		// is the label local to the function
		Symbol symbol = ((LabelFieldLocation) programLocation).getSymbol();
		if (isLocalFunctionSymbol(program, symbol)) {
			return createTooltipComponent(symbol.getName(true));
		}

		return null;
	}

	private boolean isLocalFunctionSymbol(Program program, Symbol symbol) {
		if (symbol == null) {
			return false;
		}

		Namespace parentScope = symbol.getParentNamespace();
		SymbolType symbolType = symbol.getSymbolType();

		if (symbolType != SymbolType.LABEL) {
			return false;
		}

		if (parentScope.getID() == Namespace.GLOBAL_NAMESPACE_ID) {
			return false;
		}

		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(symbol.getAddress());
		if (function == null) {
			return false;
		}
		return function.getName().equals(parentScope.getName());
	}

}
