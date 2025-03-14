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

import static ghidra.util.HTMLUtilities.*;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * A hover service to show the full namespace path of a symbol along with its symbol type and
 * source type.
 */
public class LabelListingHover extends AbstractConfigurableHover
		implements ListingHoverService {

	private static final String NAME = "Label Display";
	private static final String DESCRIPTION =
		"Toggle whether the full symbol name is shown as a tooltip.  This only applies " +
			"when displaying namespaces.";
	private static final int PRIORITY = 20;

	public LabelListingHover(PluginTool tool) {
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

		Symbol symbol = getLabelSymbol(programLocation);
		if (symbol == null) {
			return null;
		}
		return createTooltipComponent(getToolTipText(symbol));
	}

	private Symbol getLabelSymbol(ProgramLocation programLocation) {
		if (!enabled || programLocation == null) {
			return null;
		}

		if (!(programLocation instanceof LabelFieldLocation)) {
			return null;
		}

		Symbol symbol = ((LabelFieldLocation) programLocation).getSymbol();
		if (symbol == null) {
			return null;
		}

		return symbol;
	}

	private String getToolTipText(Symbol symbol) {
		StringBuilder buf = new StringBuilder(HTML);
		buf.append(friendlyEncodeHTML(symbol.getName(true)));
		buf.append(BR).append(BR);
		buf.append("Type: ");
		buf.append(HTML_SPACE).append(HTML_SPACE).append(HTML_SPACE).append(HTML_SPACE);
		buf.append(symbol.getSymbolType());
		buf.append(BR);
		buf.append("Source: ");
		buf.append(symbol.getSource().getDisplayString());
		buf.append(BR);
		return buf.toString();

	}

}
