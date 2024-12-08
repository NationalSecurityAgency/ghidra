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
package ghidra.app.plugin.core.codebrowser;

import javax.swing.Icon;

import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import generic.theme.GIcon;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.codebrowser.SelectEndpointsAction.RangeEndpoint;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.SearchConstants;
import ghidra.app.util.query.TableService;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.*;
import ghidra.util.task.TaskMonitor;

/**
 * Plugin for adding some basic selection actions for Code Browser Listings.
 */

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Basic Selection actions",
	description = "This plugin provides actions for Code Browser Listing components"
)
//@formatter:on
public class CodeBrowserSelectionPlugin extends Plugin {

	private static final String SELECT_GROUP = "Select Group";
	private static final String SELECTION_LIMIT_OPTION_NAME = "Table From Selection Limit";
	private static final int SELECTION_LIMIT_DEFAULT = 500;
	static final String RANGES_LIMIT_OPTION_NAME = "Ranges From Selection Limit";
	static final int RANGES_LIMIT_DEFAULT = 500;
	static final String MIN_RANGE_SIZE_OPTION_NAME =
		"Minimum Length of Address Range in Range Table";
	static final long MIN_RANGE_SIZE_DEFAULT = 1;

	static final String CREATE_ADDRESS_RANGE_TABLE_ACTION_NAME = "Create Table From Ranges";

	static final String OPTION_CATEGORY_NAME = "Selection Tables";

	public CodeBrowserSelectionPlugin(PluginTool tool) {
		super(tool);
		createActions();
		initializeOptions();
	}

	private void createActions() {
		new ActionBuilder("Select All", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&All in View")
				.menuGroup(SELECT_GROUP, "a")
				.keyBinding("ctrl A")
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select All"))
				.withContext(CodeViewerActionContext.class, true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectAll())
				.buildAndInstall(tool);

		new ActionBuilder("Clear Selection", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Clear Selection")
				.menuGroup(SELECT_GROUP, "b")
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Clear Selection"))
				.withContext(CodeViewerActionContext.class, true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider())
						.setSelection(new ProgramSelection()))
				.buildAndInstall(tool);

		new ActionBuilder("Select Complement", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "&Complement")
				.menuGroup(SELECT_GROUP, "c")
				.helpLocation(new HelpLocation(HelpTopics.SELECTION, "Select Complement"))
				.withContext(CodeViewerActionContext.class, true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> ((CodeViewerProvider) c.getComponentProvider()).selectComplement())
				.buildAndInstall(tool);

		tool.addAction(new MarkAndSelectionAction(getName(), SELECT_GROUP, "d"));

		new ActionBuilder("Create Table From Selection", getName())
				.menuPath(ToolConstants.MENU_SELECTION, "Create Table From Selection")
				.menuGroup("SelectUtils")
				.helpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Selection_Tables"))
				.withContext(CodeViewerActionContext.class, true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(c -> createTable((CodeViewerProvider) c.getComponentProvider()))
				.buildAndInstall(tool);

		new ActionBuilder(CREATE_ADDRESS_RANGE_TABLE_ACTION_NAME, getName())
				.menuPath(ToolConstants.MENU_SELECTION, CREATE_ADDRESS_RANGE_TABLE_ACTION_NAME)
				.menuGroup("SelectUtils")
				.helpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Selection_Tables"))
				.withContext(CodeViewerActionContext.class, true)
				.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
				.onAction(
					c -> createAddressRangeTable((CodeViewerProvider) c.getComponentProvider()))
				.buildAndInstall(tool);

	}

	private void createAddressRangeTable(CodeViewerProvider componentProvider) {
		TableService tableService = tool.getService(TableService.class);
		if (tableService == null) {
			Msg.showWarn(this, null, "No Table Service", "Please add the TableServicePlugin.");
			return;
		}
		Program program = componentProvider.getProgram();
		ProgramSelection selection = componentProvider.getSelection();
		if (selection.isEmpty()) {
			tool.setStatusInfo("Unable to create selected ranges table: no addresses in selection");
			return;
		}
		ToolOptions options = tool.getOptions(OPTION_CATEGORY_NAME);
		int resultsLimit = options.getInt(RANGES_LIMIT_OPTION_NAME, RANGES_LIMIT_DEFAULT);
		long minLength = options.getLong(MIN_RANGE_SIZE_OPTION_NAME, MIN_RANGE_SIZE_DEFAULT);
		AddressRangeTableModel model =
			new AddressRangeTableModel(tool, program, selection, resultsLimit, minLength);
		Icon markerIcon = new GIcon("icon.plugin.codebrowser.cursor.marker");
		String title = "Selected Ranges in " + program.getName();
		TableComponentProvider<AddressRangeInfo> tableProvider =
			tableService.showTableWithMarkers(title, "Selected Ranges", model,
				SearchConstants.SEARCH_HIGHLIGHT_COLOR, markerIcon, title, null);
		tableProvider.installRemoveItemsAction();

		SelectEndpointsAction selectMin =
			new SelectEndpointsAction(this, program, model, RangeEndpoint.MIN);
		selectMin.setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Range_Table_Actions"));
		tableProvider.addLocalAction(selectMin);

		SelectEndpointsAction selectMax =
			new SelectEndpointsAction(this, program, model, RangeEndpoint.MAX);
		selectMax.setHelpLocation(new HelpLocation(HelpTopics.CODE_BROWSER, "Range_Table_Actions"));
		tableProvider.addLocalAction(selectMax);

	}

	private void createTable(CodeViewerProvider componentProvider) {
		TableService tableService = tool.getService(TableService.class);
		if (tableService == null) {
			Msg.showWarn(this, null, "No Table Service", "Please add the TableServicePlugin.");
			return;
		}

		Program program = componentProvider.getProgram();
		Listing listing = program.getListing();
		ProgramSelection selection = componentProvider.getSelection();
		CodeUnitIterator codeUnits = listing.getCodeUnits(selection, true);
		if (!codeUnits.hasNext()) {
			tool.setStatusInfo("Unable to create table from selection: no code units in selection");
			return;
		}

		GhidraProgramTableModel<Address> model = createTableModel(program, codeUnits, selection);
		String title = "Selection Table";
		Icon markerIcon = new GIcon("icon.plugin.codebrowser.cursor.marker");
		TableComponentProvider<Address> tableProvider =
			tableService.showTableWithMarkers(title + " " + model.getName(), "Selection", model,
				SearchConstants.SEARCH_HIGHLIGHT_COLOR, markerIcon, title, null);
		tableProvider.installRemoveItemsAction();
	}

	private GhidraProgramTableModel<Address> createTableModel(Program program,
			CodeUnitIterator iterator, ProgramSelection selection) {

		CodeUnitFromSelectionTableModelLoader loader =
			new CodeUnitFromSelectionTableModelLoader(iterator, selection);
		return new CustomLoadingAddressTableModel(" - from " + selection.getMinAddress(), tool,
			program, loader, null, true);
	}

	private class CodeUnitFromSelectionTableModelLoader implements TableModelLoader<Address> {

		private CodeUnitIterator iterator;
		private ProgramSelection selection;

		CodeUnitFromSelectionTableModelLoader(CodeUnitIterator iterator,
				ProgramSelection selection) {
			this.iterator = iterator;
			this.selection = selection;
		}

		@Override
		public void load(Accumulator<Address> accumulator, TaskMonitor monitor)
				throws CancelledException {

			ToolOptions options = tool.getOptions(OPTION_CATEGORY_NAME);
			int resultsLimit = options.getInt(SELECTION_LIMIT_OPTION_NAME, SELECTION_LIMIT_DEFAULT);

			long size = selection.getNumAddresses();
			monitor.initialize(size);

			while (iterator.hasNext()) {
				if (accumulator.size() >= resultsLimit) {
					Msg.showWarn(this, null, "Results Truncated",
						"Results are limited to " + resultsLimit + " code units.\n" +
							"This limit can be changed by the tool option \"" +
							OPTION_CATEGORY_NAME + " -> " + SELECTION_LIMIT_OPTION_NAME + "\".");
					break;
				}
				monitor.checkCancelled();
				CodeUnit cu = iterator.next();
				accumulator.add(cu.getMinAddress());
				monitor.incrementProgress(cu.getLength());
			}
		}
	}

	private void initializeOptions() {
		Options opt = tool.getOptions(OPTION_CATEGORY_NAME);
		HelpLocation help = new HelpLocation(HelpTopics.CODE_BROWSER, "Selection_Tables");
		opt.registerOption(SELECTION_LIMIT_OPTION_NAME, SELECTION_LIMIT_DEFAULT, help,
			"Maximum number of entries in selection table");

		opt.registerOption(RANGES_LIMIT_OPTION_NAME, RANGES_LIMIT_DEFAULT, help,
			"Maximum number of entries in an address range table");

		opt.registerOption(MIN_RANGE_SIZE_OPTION_NAME, MIN_RANGE_SIZE_DEFAULT, help,
			"Minimum length of an address range in address range table");
	}
}
