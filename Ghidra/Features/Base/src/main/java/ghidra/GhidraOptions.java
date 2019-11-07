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
package ghidra;

import java.awt.Color;
import java.awt.event.MouseEvent;

import ghidra.framework.options.Options;

/**
 * Contains miscellaneous defines used for options.
 */
public interface GhidraOptions {

	/**
	 * Character used to create a "hierarchy" for a property name; the delimiter creates a
	 * new "level."
	 */
	final char DELIMITER = Options.DELIMITER;

	/**
	 * Category name for the Browser options that affect the display.
	 */
	final String CATEGORY_BROWSER_DISPLAY = "Listing Display";
	@Deprecated //remove a few versions after 8.0
	final String OLD_CATEGORY_BROWSER_DISPLAY = "Browser Display";

	/**
	 * Category name for the Browser Navigation Marker options.
	 */
	final String CATEGORY_BROWSER_NAVIGATION_MARKERS = "Navigation Markers";

	/**
	 * Option for the base font.
	 */
	final String OPTION_BASE_FONT = "BASE FONT";

	/**
	 * Category name for the "Select by Flow" options.
	 */
	final String CATEGORY_FLOW_OPTIONS = "Selection by Flow";
	/**
	 * Option for the following computed calls when selecting by flow.
	 */
	final String OPTION_FOLLOW_COMPUTED_CALL = "Follow computed call";
	/**
	 * Option for the following conditional calls when selecting by flow.
	 */
	final String OPTION_FOLLOW_CONDITIONAL_CALL = "Follow conditional call";
	/**
	 * Option for the following unconditional calls when selecting by flow.
	 */
	final String OPTION_FOLLOW_UNCONDITIONAL_CALL = "Follow unconditional call";
	/**
	 * Option for the following computed jumps when selecting by flow.
	 */
	final String OPTION_FOLLOW_COMPUTED_JUMP = "Follow computed jump";
	/**
	 * Option for the following conditional jumps when selecting by flow.
	 */
	final String OPTION_FOLLOW_CONDITIONAL_JUMP = "Follow conditional jump";
	/**
	 * Option for the following unconditional jumps when selecting by flow.
	 */
	final String OPTION_FOLLOW_UNCONDITIONAL_JUMP = "Follow unconditional jump";
	/**
	 * Option for the following pointers when selecting by flow.
	 */
	final String OPTION_FOLLOW_POINTERS = "Follow pointers";

	/**
	 * Option for the max number of hits found in a search; the search
	 * stops when it reaches this limit.
	 */
	final String OPTION_SEARCH_LIMIT = "Search Limit";

	/**
	 * Options title the search category
	 */
	final String OPTION_SEARCH_TITLE = "Search";

	/**
	 * Category name for the "Auto Analysis" options.
	 */
	final String CATEGORY_AUTO_ANALYSIS = "Auto Analysis";

	/**
	 * Options name for Browser fields
	 */
	final String CATEGORY_BROWSER_FIELDS = "Listing Fields";
	@Deprecated //remove a few versions after 8.0
	final String OLD_CATEGORY_BROWSER_FIELDS = "Browser Fields";

	/**
	 * Options title for Mnemonic group.
	 */
	final String MNEMONIC_GROUP_TITLE = "Mnemonic Field";

	/**
	 * Options title for Operand group.
	 */
	final String OPERAND_GROUP_TITLE = "Operands Field";

	final String LABEL_GROUP_TITLE = "Label Field";

	/**
	 * Option name for whether to show the block name in the operand.
	 */
	final String OPTION_SHOW_BLOCK_NAME = "Show Block Names";

	/**
	 * Category name for Browser Popup options
	 */
	final String CATEGORY_BROWSER_POPUPS = "Listing Popups";
	@Deprecated //remove a few versions after 8.0
	final String OLD_CATEGORY_BROWSER_POPUPS = "Browser Popups";

	/**
	 * Category name for Decompiler Popup options
	 */
	final String CATEGORY_DECOMPILER_POPUPS = "Decompiler Popups";

	/**
	 * Option name for interpreting addresses as a number
	 */
	final String OPTION_NUMERIC_FORMATTING = "Use C-like Numeric Formatting for Addresses";

	/**
	 * Option name for the max number of go to entries to be remembered.
	 */
	final String OPTION_MAX_GO_TO_ENTRIES = "Max Goto Entries";

	final String SHOW_BLOCK_NAME_OPTION = OPERAND_GROUP_TITLE + DELIMITER + OPTION_SHOW_BLOCK_NAME;

	final String DISPLAY_NAMESPACE = "Display Namespace";

	final String NAVIGATION_OPTIONS = "Navigation";

	final String NAVIGATION_RANGE_OPTION = "Range Navigation";

	final String EXTERNAL_NAVIGATION_OPTION = "External Navigation";

	final String FOLLOW_INDIRECTION_NAVIGATION_OPTION = "Follow Indirection";

	//
	// Cursor line highlighting
	//
	final String HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME = "Highlight Cursor Line Color";

	final String HIGHLIGHT_CURSOR_LINE_COLOR = "Cursor." + HIGHLIGHT_CURSOR_LINE_COLOR_OPTION_NAME;

	final Color DEFAULT_CURSOR_LINE_COLOR = new Color(232, 242, 254);

	final String HIGHLIGHT_CURSOR_LINE_OPTION_NAME = "Highlight Cursor Line";

	final String HIGHLIGHT_CURSOR_LINE = "Cursor." + HIGHLIGHT_CURSOR_LINE_OPTION_NAME;
	// end cursor line highlighting

	//
	// cursor highlight
	//
	final String CURSOR_HIGHLIGHT_GROUP = "Cursor Text Highlight";

	final String CURSOR_HIGHLIGHT_BUTTON_NAME =
		CURSOR_HIGHLIGHT_GROUP + Options.DELIMITER + "Mouse Button To Activate";

	final String HIGHLIGHT_COLOR_NAME =
		CURSOR_HIGHLIGHT_GROUP + Options.DELIMITER + "Highlight Color";

	public static enum CURSOR_MOUSE_BUTTON_NAMES {
		LEFT(MouseEvent.BUTTON1), MIDDLE(MouseEvent.BUTTON2), RIGHT(MouseEvent.BUTTON3);
		private int mouseEventID;

		CURSOR_MOUSE_BUTTON_NAMES(int mouseEventID) {
			this.mouseEventID = mouseEventID;
		}

		public int getMouseEventID() {
			return mouseEventID;
		}
	}

	// end cursor highlight

	final String OPTION_SELECTION_COLOR = "Selection Colors.Selection Color";
	final Color DEFAULT_SELECTION_COLOR = new Color(180, 255, 180);

	final String OPTION_HIGHLIGHT_COLOR = "Selection Colors.Highlight Color";
	final Color DEFAULT_HIGHLIGHT_COLOR = new Color(255, 255, 180);
	final String APPLY_ENABLED = "apply.enabled";

}
