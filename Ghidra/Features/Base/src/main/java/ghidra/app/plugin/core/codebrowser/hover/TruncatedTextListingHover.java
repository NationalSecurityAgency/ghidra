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
import ghidra.app.plugin.core.hover.AbstractTruncatedTextHover;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;

/**
 * A hover service to show tool tip text for hovering over a truncated field, containing a "...",
 * in the listing.
 * The tooltip shows the entire text for that field.
 * This provides the hover capability for the TruncatedTextHoverPlugin and can
 * also be used to directly provide this hover capability to a listing.
 */
public class TruncatedTextListingHover extends AbstractTruncatedTextHover
		implements ListingHoverService {

	private static final String NAME = "Truncated Text Display";
	private static final int POPUP_PRIORITY = 10;

	///////////////////////////////////////////////////////////

	public TruncatedTextListingHover(PluginTool tool) {
		super(tool, POPUP_PRIORITY);
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || programLocation == null || !(field instanceof ListingTextField)) {
			return null;
		}

		if (((ListingTextField) field).isClipped()) {
			String text = field.getTextWithLineSeparators();
			String convertToHtml = HTMLUtilities.toLiteralHTMLForTooltip(text);
			JToolTip toolTip = new JToolTip();
			toolTip.setTipText(convertToHtml);
			return toolTip;
		}

		return null;
	}

	@Override
	public void initializeOptions() {
		options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_POPUPS);
		options.setOptionsHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "MouseHover"));
		options.registerOption(NAME, true,
			new HelpLocation(HelpTopics.CODE_BROWSER, "TruncatedTextPopup"),
			"Toggle whether truncated text is displayed in a tooltip " +
				"when the mouse hovers over a field that is truncated.");
		setOptions(options, NAME);
		options.addOptionsChangeListener(this);
	}

	@Override
	public void setOptions(Options options, String name) {
		enabled = options.getBoolean(NAME, true);
	}
}
