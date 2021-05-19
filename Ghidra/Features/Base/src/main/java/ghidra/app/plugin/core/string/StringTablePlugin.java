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
package ghidra.app.plugin.core.string;

import java.util.ArrayList;
import java.util.List;

import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Strings Table",
	description = "Displays Strings in a program.",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class StringTablePlugin extends ProgramPlugin {
	final static String SEARCH_ACTION_NAME = "Search for Strings";

	private List<StringTableProvider> transientProviders = new ArrayList<>();

	public StringTablePlugin(PluginTool tool) {
		super(tool, false, true);
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#init()
	 */
	@Override
	protected void init() {
		super.init();
		createActions();
	}

	public void setSelection(ProgramSelection selection) {
		currentSelection = selection;
	}

	private void createActions() {
		NavigatableContextAction stringSearchAction =
			new NavigatableContextAction(SEARCH_ACTION_NAME, getName()) {
				@Override
				public void actionPerformed(NavigatableActionContext context) {
					showSearchDialog(context.getSelection());
				}
			};
		stringSearchAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, SEARCH_ACTION_NAME));
		stringSearchAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_SEARCH, "For &Strings..." }, null, "search for"));

		stringSearchAction.setDescription(getPluginDescription().getDescription());
		stringSearchAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(stringSearchAction);
	}

	protected void showSearchDialog(ProgramSelection selection) {
		AddressSet view = new AddressSet();
		AddressRangeIterator iter = selection.getAddressRanges();
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			view.addRange(range.getMinAddress(), range.getMaxAddress());
		}
		SearchStringDialog searchStringDialog = new SearchStringDialog(this, view);
		tool.showDialog(searchStringDialog);
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
	@Override
	public void dispose() {
		ArrayList<StringTableProvider> list = new ArrayList<>(transientProviders);

		for (StringTableProvider stringTableProvider : list) {
			stringTableProvider.closeComponent();
			stringTableProvider.dispose();
		}
		super.dispose();
	}

	@Override
	protected void programClosed(Program program) {
		if (transientProviders.isEmpty()) {
			return;
		}
		ArrayList<StringTableProvider> list = new ArrayList<>(transientProviders);
		for (StringTableProvider stringTableProvider : list) {
			stringTableProvider.programClosed(program);
		}

	}

	public void createStringsProvider(StringTableOptions options) {
		StringTableProvider transientProvider = new StringTableProvider(this, options, true);
		transientProviders.add(transientProvider);
		transientProvider.setProgram(currentProgram);
		transientProvider.setVisible(true);
	}

	public void removeTransientProvider(StringTableProvider stringTableProvider) {
		transientProviders.remove(stringTableProvider);
	}

}
