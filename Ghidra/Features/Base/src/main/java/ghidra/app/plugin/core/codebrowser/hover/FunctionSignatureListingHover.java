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
import javax.swing.JToolTip;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

/**
 * A Listing hover to show tool tips for function signatures
 */
public class FunctionSignatureListingHover extends AbstractConfigurableHover
		implements ListingHoverService {

	private static final String NAME = "Function Signature Display";
	private static final String DESCRIPTION =
		"Toggle whether function signature is displayed in a tooltip " +
			"when the mouse hovers over a function signature.";

	// note: guilty knowledge that the Truncated Text service has a priority of 10
	private static final int POPUP_PRIORITY = 20;

	public FunctionSignatureListingHover(PluginTool tool) {
		super(tool, POPUP_PRIORITY);
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

		Class<? extends ProgramLocation> clazz = programLocation.getClass();
		if (clazz != FunctionSignatureFieldLocation.class &&
			clazz != FunctionNameFieldLocation.class) {
			return null;
		}

		// is the label local to the function
		FunctionSignatureFieldLocation functionLocation =
			(FunctionSignatureFieldLocation) programLocation;

		Address entry = functionLocation.getFunctionAddress();
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(entry);

		String toolTipText = ToolTipUtils.getToolTipText(function, true);
		JToolTip toolTip = new JToolTip();
		toolTip.setTipText(toolTipText);
		return toolTip;
	}

}
