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
package ghidra.app.plugin.core.search;

import java.awt.Color;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import generic.theme.GIcon;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.query.TableService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.table.GhidraTable;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Decompiler Text Finder Plugin",
	description = "This plugin adds an action to allow users to search decompiled text.",
	servicesRequired = { TableService.class }
)
//@formatter:on
public class DecompilerTextFinderPlugin extends ProgramPlugin {

	private static final Icon SELECT_FUNCTIONS_ICON =
		new GIcon("icon.plugin.decompiler.text.finder.select.functions");

	private DecompilerTextFinderDialog searchDialog;

	public DecompilerTextFinderPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	private void createActions() {

		NavigatableContextAction searchAction =
			new NavigatableContextAction("Search Decompiled Text", getName()) {
				@Override
				public void actionPerformed(NavigatableActionContext context) {
					search(context.getNavigatable(), context.getProgram());
				}
			};

		// Memory Search uses groups 'a', 'b', and 'c'; Search Text uses group 'd'
		String subGroup = "e";
		searchAction.setMenuBarData(new MenuData(new String[] { "Search", "Decompiled Text..." },
			null, "search", -1, subGroup));

		searchAction.addToWindowWhen(NavigatableActionContext.class);

		tool.addAction(searchAction);
	}

	private void search(Navigatable navigatable, Program program) {

		if (searchDialog == null) {
			searchDialog = new DecompilerTextFinderDialog();
		}

		// update the Search Selection checkbox as needed
		boolean enableSearchSelection = false;
		if (currentSelection != null) {
			FunctionManager functionManager = program.getFunctionManager();
			FunctionIterator it = functionManager.getFunctions(currentSelection, true);
			if (it.hasNext()) {
				enableSearchSelection = true;
			}
		}
		searchDialog.setSearchSelectionEnabled(enableSearchSelection);

		tool.showDialog(searchDialog);
		if (searchDialog.isCancelled()) {
			return;
		}

		String searchText = searchDialog.getSearchText();
		boolean isRegex = searchDialog.isRegex();
		String title = "Decompiler Search Text - '" + searchText + "'";
		String tableTypeName = "Decompiler Search";
		DecompilerTextFinderTableModel model =
			new DecompilerTextFinderTableModel(tool, program, searchText, isRegex);
		if (searchDialog.isSearchSelection()) {
			model.setSelection(currentSelection);
		}

		int searchLimit = getSearchLimit();
		model.setSearchLimit(searchLimit);

		Color markerColor = SearchConstants.SEARCH_HIGHLIGHT_COLOR;
		Icon markerIcon = new GIcon("icon.base.search.marker");
		String windowSubMenu = "Search";
		TableService tableService = tool.getService(TableService.class);
		TableComponentProvider<TextMatch> provider = tableService.showTableWithMarkers(title,
			tableTypeName, model, markerColor, markerIcon, windowSubMenu, navigatable);

		provider.installRemoveItemsAction();

		GhidraTable table = provider.getTable();
		//@formatter:off
		new ActionBuilder("Select Functions", getName())
			.description("Make program selection of function starts from selected rows")
			.toolBarIcon(SELECT_FUNCTIONS_ICON)
			.popupMenuIcon(SELECT_FUNCTIONS_ICON)
			.popupMenuPath("Select Functions")
			.popupMenuGroup(null, "a") // before the others in the table, to match the toolbar
			.enabledWhen(c -> table.getSelectedRowCount() > 0)
			.onAction(c -> selectFunctions(table, model))
			.buildAndInstallLocal(provider)
			;
		//@formatter:on
	}

	private int getSearchLimit() {
		ToolOptions options = tool.getOptions(SearchConstants.SEARCH_OPTION_NAME);
		return options.getInt(SearchConstants.SEARCH_LIMIT_NAME,
			SearchConstants.DEFAULT_SEARCH_LIMIT);
	}

	private void selectFunctions(GhidraTable table, DecompilerTextFinderTableModel model) {

		AddressSet addresses = new AddressSet();
		int[] rows = table.getSelectedRows();
		for (int row : rows) {
			TextMatch match = model.getRowObject(row);
			Function f = match.getFunction();
			addresses.add(f.getEntryPoint());
		}

		ProgramSelection selection = new ProgramSelection(addresses);
		PluginEvent event =
			new ProgramSelectionPluginEvent(getName(), selection, table.getProgram());
		firePluginEvent(event);
	}

}
