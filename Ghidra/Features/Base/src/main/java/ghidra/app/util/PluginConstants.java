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
package ghidra.app.util;

import java.awt.Color;

/**
 * Miscellaneous defined constants
 *
 */
public interface PluginConstants {

	/**
	 * Delimiter used to denote sub-categories for specifying 
	 * a plugin's category.
	 */
	String CATEGORY_DELIMITER = ".";

	/**
	 * Plugin descriptive name suffix used when a Plugin is still in 
	 * a "prototype" stage, where a test
	 * plan hasn't been fully written to thoroughly test the plugin's
	 * functionality to stamp it "released".
	 */
	String PROTOTYPE = " (Prototype)";

	/**
	 * Plugin descriptive name suffix used when a Plugin is still in
	 * "development" stage and needs more work to get to the "prototype"
	 * stage.
	 */
	String DEVELOP = "(Develop)";

	/**
	 * Default name for the default program tree
	 */
	String DEFAULT_TREE_NAME = "Program Tree";

	/**
	 * The default search limit.
	 */
	int DEFAULT_SEARCH_LIMIT = 500;
	/**
	 * Wildcard char for any string.
	 */
	char ANYSUBSTRING_WILDCARD_CHAR = '*';
	/**
	 * Wildcard char for a single char.
	 */
	char ANYSINGLECHAR_WILDCARD_CHAR = '?';

	String CODE_BROWSER = "Listing";
	String MEMORY_MAP = "Memory Map";
	String BYTE_VIEWER = "ByteViewerPlugin";
	String BOOKMARKS = "Bookmarks";

	String PRE_POPULATE_MEM_SEARCH = "Pre-populate Memory Search";

	String AUTO_RESTRICT_SELECTION = "Auto Restrict Memory Search on Selection";

	/**
	 * Name of the Options object for Search.
	 */
	public static final String SEARCH_OPTION_NAME = "Search";
	/**
	 * Option name for highlight color
	 */
	public static final String SEARCH_HIGHLIGHT_COLOR_NAME = " Highlight Color";

	/**
	 * Option name for highlight color used when something to highlight is at the current
	 * address. 
	 */
	public static final String SEARCH_HIGHLIGHT_CURRENT_COLOR_NAME =
		"Highlight Color for Current Match";
	/**
	 * Option name for whether to highlight search results.
	 */
	public static final String SEARCH_HIGHLIGHT_NAME = "Highlight Search Results";

	/**
	 * Color for highlighting for searches.
	 */
	public static final Color SEARCH_HIGHLIGHT_COLOR = new Color(255, 255, 200);
	/**
	 * Default highlight color used when something to highlight is at the current
	 * address. 
	 */
	public static final Color SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR = Color.YELLOW;

}
