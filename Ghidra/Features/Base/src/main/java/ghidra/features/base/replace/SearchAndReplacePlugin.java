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
package ghidra.features.base.replace;

import static ghidra.app.util.SearchConstants.*;

import java.util.ArrayList;
import java.util.List;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.SearchConstants;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Plugin to perform search and replace operations for many different program element types such
 * as labels, functions, classes, datatypes, memory blocks, and more.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search and replace text on program element names or comments.",
	description = "This plugin provides a search and replace capability for a variety of" +
		"program elements including functions, classes, namespaces, datatypes, field names, and" +
		"other.",
	servicesRequired = { ProgramManager.class, GoToService.class }
)
//@formatter:on
public class SearchAndReplacePlugin extends ProgramPlugin {

	private SearchAndReplaceDialog cachedDialog;
	private int searchLimit = DEFAULT_SEARCH_LIMIT;
	private OptionsChangeListener searchOptionsListener;
	private List<SearchAndReplaceProvider> providers = new ArrayList<>();

	public SearchAndReplacePlugin(PluginTool plugintool) {
		super(plugintool);
		createActions();
		initializeOptions();
	}

	@Override
	protected void programClosed(Program program) {
		List<SearchAndReplaceProvider> copy = new ArrayList<>(providers);
		for (SearchAndReplaceProvider provider : copy) {
			provider.programClosed(program);
		}
	}

	private void initializeOptions() {
		ToolOptions options = tool.getOptions(SearchConstants.SEARCH_OPTION_NAME);
		searchLimit = options.getInt(SEARCH_LIMIT_NAME, DEFAULT_SEARCH_LIMIT);

		searchOptionsListener = this::searchOptionsChanged;
		options.addOptionsChangeListener(searchOptionsListener);
	}

	private void searchOptionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(SEARCH_LIMIT_NAME)) {
			int limit = (int) newValue;
			if (limit <= 0) {
				throw new OptionsVetoException("Search limit must be greater than 0");
			}
			searchLimit = limit;
			if (cachedDialog != null) {
				cachedDialog.setSearchLimit(limit);
			}
		}
	}

	private void createActions() {
		new ActionBuilder("Search And Replace", getName())
				.menuPath("&Search", "Search And Replace...")
				.menuGroup("search", "d")
				.description("Search and replace names of various program elements")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Search And Replace"))
				.withContext(NavigatableActionContext.class, true)
				.onAction(this::searchAndReplace)
				.buildAndInstall(tool);
	}

	private void searchAndReplace(NavigatableActionContext c) {
		SearchAndReplaceDialog dialog = getDialog();
		SearchAndReplaceQuery query = dialog.show(tool);
		if (query == null) {
			return;
		}

		Program program = c.getProgram();
		providers.add(new SearchAndReplaceProvider(this, program, query));
	}

	private SearchAndReplaceDialog getDialog() {
		if (cachedDialog == null) {
			cachedDialog = new SearchAndReplaceDialog(searchLimit);
		}
		return cachedDialog;
	}

	void providerClosed(SearchAndReplaceProvider provider) {
		providers.remove(provider);
	}
}
