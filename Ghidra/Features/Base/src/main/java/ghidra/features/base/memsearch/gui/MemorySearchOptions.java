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
package ghidra.features.base.memsearch.gui;

import static ghidra.app.util.SearchConstants.*;

import ghidra.GhidraOptions;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.viewer.field.BytesFieldFactory;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Class for managing search tool options.
 */
public class MemorySearchOptions {
	private static final String PRE_POPULATE_MEM_SEARCH = "Pre-populate Memory Search";
	private static final String AUTO_RESTRICT_SELECTION = "Auto Restrict Search on Selection";

	private OptionsChangeListener searchOptionsListener;
	private OptionsChangeListener browserOptionsListener;

	private boolean prepopulateSearch = true;
	private int searchLimit = DEFAULT_SEARCH_LIMIT;
	private boolean highlightMatches = true;
	private boolean autoRestrictSelection = true;
	private int byteGroupSize;
	private String byteDelimiter;

	public MemorySearchOptions(PluginTool tool) {
		registerSearchOptions(tool);
		registerBrowserOptionsListener(tool);
	}

	public MemorySearchOptions() {
	}

	public int getByteGroupSize() {
		return byteGroupSize;
	}

	public String getByteDelimiter() {
		return byteDelimiter;
	}

	public boolean isShowHighlights() {
		return highlightMatches;
	}

	public int getSearchLimit() {
		return searchLimit;
	}

	public boolean isAutoRestrictSelection() {
		return autoRestrictSelection;
	}

	private void registerSearchOptions(PluginTool tool) {
		ToolOptions options = tool.getOptions(SearchConstants.SEARCH_OPTION_NAME);

		options.registerOption(PRE_POPULATE_MEM_SEARCH, prepopulateSearch, null,
			"Initializes memory search byte sequence from " +
				"the current selection provided the selection is less than 10 bytes.");
		options.registerOption(AUTO_RESTRICT_SELECTION, autoRestrictSelection, null,
			"Automactically restricts searches to the to the current selection," +
				" if a selection exists");
		options.registerOption(SearchConstants.SEARCH_HIGHLIGHT_NAME, highlightMatches, null,
			"Toggles highlight search results");

		options.registerThemeColorBinding(SearchConstants.SEARCH_HIGHLIGHT_COLOR_OPTION_NAME,
			SearchConstants.SEARCH_HIGHLIGHT_COLOR.getId(), null,
			"The search result highlight color");
		options.registerThemeColorBinding(
			SearchConstants.SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME,
			SearchConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR.getId(), null,
			"The search result highlight color for the currently selected match");

		loadSearchOptions(options);

		searchOptionsListener = this::searchOptionsChanged;
		options.addOptionsChangeListener(searchOptionsListener);
	}

	private void registerBrowserOptionsListener(PluginTool tool) {
		ToolOptions options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		loadBrowserOptions(options);
		browserOptionsListener = this::browserOptionsChanged;
		options.addOptionsChangeListener(browserOptionsListener);

	}

	private void loadBrowserOptions(ToolOptions options) {
		byteGroupSize = options.getInt(BytesFieldFactory.BYTE_GROUP_SIZE_MSG, 1);
		byteDelimiter = options.getString(BytesFieldFactory.DELIMITER_MSG, " ");
	}

	private void searchOptionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(SEARCH_LIMIT_NAME)) {
			int limit = (int) newValue;
			if (limit <= 0) {
				throw new OptionsVetoException("Search limit must be greater than 0");
			}
		}

		loadSearchOptions(options);

	}

	private void loadSearchOptions(ToolOptions options) {
		searchLimit = options.getInt(SEARCH_LIMIT_NAME, DEFAULT_SEARCH_LIMIT);
		highlightMatches = options.getBoolean(SEARCH_HIGHLIGHT_NAME, true);
		autoRestrictSelection = options.getBoolean(AUTO_RESTRICT_SELECTION, true);
		prepopulateSearch = options.getBoolean(PRE_POPULATE_MEM_SEARCH, true);
	}

	private void browserOptionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		loadBrowserOptions(options);
	}
}
