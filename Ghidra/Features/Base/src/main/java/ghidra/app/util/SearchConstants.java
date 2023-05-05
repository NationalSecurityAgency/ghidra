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

import generic.theme.GColor;

/**
 * Miscellaneous constants
 */
public interface SearchConstants {

	/**
	 * The default search limit.
	 */
	public static final int DEFAULT_SEARCH_LIMIT = 500;

	/**
	 * Name of the Options object for Search.
	 */
	public static final String SEARCH_OPTION_NAME = "Search";

	/**
	 * Option name for whether to highlight search results.
	 */
	public static final String SEARCH_HIGHLIGHT_NAME = "Highlight Search Results";

	/**
	 * Color for highlighting for searches.
	 */
	public static final String SEARCH_HIGHLIGHT_COLOR_OPTION_NAME = " Highlight Color";
	public static final GColor SEARCH_HIGHLIGHT_COLOR = new GColor("color.bg.search.highlight");

	/**
	 * Default highlight color used when something to highlight is at the current address. 
	 */
	public static final String SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME =
		"Highlight Color for Current Match";
	public static final GColor SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR =
		new GColor("color.bg.search.highlight.current.line");

}
