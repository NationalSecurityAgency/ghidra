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
package ghidra.features.bsim.gui.search.results;

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.function.IntSupplier;

import javax.swing.*;

import docking.*;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.widgets.table.RowObjectTableModel;
import generic.lsh.vector.LSHVectorFactory;
import generic.theme.GIcon;
import ghidra.app.services.*;
import ghidra.features.base.codecompare.model.MatchedFunctionComparisonModel;
import ghidra.features.bsim.gui.BSimSearchPlugin;
import ghidra.features.bsim.gui.filters.BSimFilterType;
import ghidra.features.bsim.gui.filters.Md5BSimFilterType;
import ghidra.features.bsim.gui.search.dialog.*;
import ghidra.features.bsim.gui.search.results.apply.*;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.description.*;
import ghidra.features.bsim.query.facade.SFQueryInfo;
import ghidra.features.bsim.query.facade.SFQueryResult;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Counter;
import ghidra.util.table.GhidraFilterTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.task.TaskLauncher;
import resources.Icons;

/**
 * ComponentProvider for displaying BSim Similar Functions Search results.
 */
public class BSimSearchResultsProvider extends ComponentProviderAdapter {
	private static final Icon FUNCTIONS_ICON = new GIcon("icon.bsim.functions.table");
	private static final String PROVIDER_WINDOW_GROUP = "bsim.results";
	private static final String NAME = "BSim Search Results";
	private static final Icon SPLIT_VIEW_ICON = new GIcon("icon.bsim.table.split");
	private static final String APPLY_GROUP = "0";
	private BSimServerInfo serverInfo;
	private SFQueryInfo queryInfo;
	private Program program;
	private JComponent mainComponent;
	private JPanel mainPanel;
	private BSimMatchResultsModel matchesModel;
	private BSimExecutablesSummaryModel executablesModel;
	private DatabaseInformation dbInfo;
	private LSHVectorFactory lshVectorFactory;
	private BSimFilterSet postFilters = new BSimFilterSet();
	private List<BSimMatchResult> rows = new ArrayList<>();
	private GhidraFilterTable<BSimMatchResult> matchesTable;

	private JPanel matchesPanel;
	private GhidraFilterTable<ExecutableResult> executablesTable;
	private JPanel executablesPanel;
	private ToggleDockingAction showExecutableTableAction;
	private BSimSearchPlugin plugin;
	private DomainObjectListener listener = new MyDomainObjectListener();
	private BSimSearchSettings settings;

	public BSimSearchResultsProvider(BSimSearchPlugin plugin, PluginTool tool,
			BSimServerInfo serverInfo, DatabaseInformation dbInfo,
			LSHVectorFactory lshVectorFactory, SFQueryInfo queryInfo, BSimSearchSettings settings) {
		super(tool, NAME, plugin.getName());
		this.plugin = plugin;
		this.serverInfo = serverInfo;
		this.dbInfo = dbInfo;
		this.lshVectorFactory = lshVectorFactory;
		this.queryInfo = queryInfo;
		this.settings = settings;
		this.program = queryInfo.getProgram();

		setWindowGroup(PROVIDER_WINDOW_GROUP);
		setDefaultWindowPosition(WindowPosition.WINDOW);
		setTitle(NAME);
		setSubTitle(getIdString());
		setTabText("BSim " + getIdString());
		setWindowMenuGroup("BSim");
		setHelpLocation(new HelpLocation("BSimSearchPlugin", "Similar_Functions_Results"));
		setTransient();

		mainComponent = buildComponent();

		tool.addComponentProvider(this, true);

		createActions();
		matchesTable.installNavigation(tool.getService(GoToService.class));
		matchesTable.setNavigateOnSelectionEnabled(true);
		program.addListener(listener);
	}

	@Override
	public void componentHidden() {
		super.componentHidden();
		if (plugin != null) {
			plugin.providerClosed(this);
		}
	}

	private void createActions() {
		new ActionBuilder("Search Info", getName()).toolBarIcon(Icons.INFO_ICON)
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Search_Info_Action"))
				.onAction(c -> showSearchInfo())
				.buildAndInstallLocal(this);

		new ActionBuilder("Show Searched Functions", getName()).toolBarIcon(FUNCTIONS_ICON)
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Searched_Functions"))
				.onAction(c -> showSearchedFunctions())
				.buildAndInstallLocal(this);

		new ActionBuilder("Filter Results", getName()).toolBarIcon(Icons.CONFIGURE_FILTER_ICON)
				.helpLocation(
					new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Filter_Results_Action"))
				.onAction(c -> showFilterPanel())
				.buildAndInstallLocal(this);

		new ActionBuilder("Filter Executable", getName()).popupMenuPath("Filter on this Executable")
				.description("Filter on a specific executable in the function match table")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Filter_On_Executable"))
				.withContext(ExecutableTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::filterOnExecutable)
				.buildAndInstallLocal(this);

		new ActionBuilder("Load Executable", getName()).popupMenuPath("Load Executable")
				.description("Load the selected executable into the Codebrowser")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Load_Executable"))
				.withContext(ExecutableTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() == 1)
				.onAction(this::loadExecutable)
				.buildAndInstallLocal(this);

		new ActionBuilder("Compare Functions", getName()).popupMenuPath("Compare Functions")
				.popupMenuGroup("1")
				.keyBinding("shift c")
				.sharedKeyBinding()
				.description("Compares the Functions with its remote match")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Compare_Functions"))
				.withContext(BSimMatchesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() > 0)
				.onAction(this::compareFunctions)
				.buildAndInstallLocal(this);

		new ActionBuilder("Apply Function Name", getName()).popupMenuPath("Apply Name")
				.popupMenuGroup(APPLY_GROUP, "1")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Apply_Name"))
				.withContext(BSimMatchesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() > 0)
				.onAction(this::applyName)
				.buildAndInstallLocal(this);

		new ActionBuilder("Apply Function Signature", getName()).popupMenuPath("Apply Signature")
				.popupMenuGroup(APPLY_GROUP, "2")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Apply_Signature"))
				.withContext(BSimMatchesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() > 0)
				.onAction(this::applySignature)
				.buildAndInstallLocal(this);

		new ActionBuilder("Apply Signature and Datatypes", getName())
				.popupMenuPath("Apply Signature and Data Types")
				.popupMenuGroup(APPLY_GROUP, "3")
				.helpLocation(
					new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Apply_Signature_With_Datatypes"))
				.withContext(BSimMatchesTableActionContext.class)
				.enabledWhen(c -> c.getSelectedRowCount() > 0)
				.onAction(this::applySignatureWithDatatypes)
				.buildAndInstallLocal(this);

		showExecutableTableAction = new ToggleActionBuilder("Show Executables Table", getName())
				.toolBarIcon(SPLIT_VIEW_ICON)
				.description("Toggles showing Executables table")
				.helpLocation(
					new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Hide_Show_Executables_Table"))
				.selected(true)
				.onAction(c -> showExecutableTable(showExecutableTableAction.isSelected()))
				.buildAndInstallLocal(this);

		addLocalAction(new SelectionNavigationAction(plugin, matchesTable.getTable()));

		new ActionBuilder("Clear BSim Error Status", getName()).popupMenuPath("Clear error status")
				.helpLocation(new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Clear_Error_Status"))
				.withContext(BSimMatchesTableActionContext.class)
				.enabledWhen(this::canClearErrors)
				.onAction(this::clearErrors)
				.buildAndInstallLocal(this);
	}

	private void applyName(BSimMatchesTableActionContext c) {
		List<BSimMatchResult> selected = matchesTable.getSelectedRowObjects();
		AbstractBSimApplyTask task =
			new NameAndNamespaceBSimApplyTask(program, selected, dockingTool);
		TaskLauncher.launch(task);
		matchesModel.fireTableDataChanged();
	}

	private void applySignature(BSimMatchesTableActionContext c) {
		List<BSimMatchResult> selected = matchesTable.getSelectedRowObjects();
		AbstractBSimApplyTask task =
			new SignatureBSimApplyTask(program, selected, true, dockingTool);
		TaskLauncher.launch(task);
		matchesModel.fireTableDataChanged();
	}

	private void applySignatureWithDatatypes(BSimMatchesTableActionContext c) {
		List<BSimMatchResult> selected = matchesTable.getSelectedRowObjects();
		AbstractBSimApplyTask task =
			new SignatureBSimApplyTask(program, selected, false, dockingTool);
		TaskLauncher.launch(task);
		matchesModel.fireTableDataChanged();
	}

	private boolean canClearErrors(BSimMatchesTableActionContext c) {
		int rowCount = c.getSelectedRowCount();
		if (rowCount == 0) {
			return false;
		}
		if (rowCount == 1) {
			BSimMatchResult selectedRowObject = matchesTable.getSelectedRowObject();
			return selectedRowObject.getStatus() == BSimResultStatus.ERROR;
		}
		return true;
	}

	private void clearErrors(BSimMatchesTableActionContext c) {
		List<BSimMatchResult> selected = matchesTable.getSelectedRowObjects();
		for (BSimMatchResult result : selected) {
			if (result.getStatus() == BSimResultStatus.ERROR) {
				result.setStatus(BSimResultStatus.NOT_APPLIED);
			}
		}
		matchesModel.fireTableDataChanged();
	}

	private void compareFunctions(BSimMatchesTableActionContext c) {
		FunctionComparisonService service = tool.getService(FunctionComparisonService.class);
		if (service == null) {
			Msg.error(this, "Function Comparison Service not found!");
			return;
		}
		MatchedFunctionComparisonModel model = new MatchedFunctionComparisonModel();
		List<BSimMatchResult> selectedRowObjects = matchesTable.getSelectedRowObjects();
		Set<Program> openedPrograms = new HashSet<>();
		for (BSimMatchResult row : selectedRowObjects) {
			try {
				Function originalFunction = getOriginalFunction(row);
				Function matchFunction = getMatchFunction(row, openedPrograms);
				model.addMatch(originalFunction, matchFunction);
			}
			catch (FunctionComparisonException e) {
				Msg.showError(this, null, "Unable to Compare Functions",
					"Compare Functions: " + e.getMessage());
			}
		}
		if (model.isEmpty()) {
			return;
		}
		service.createCustomComparison(model, () -> {
			for (Program remote : openedPrograms) {
				remote.release(BSimSearchResultsProvider.this);
			}
		});
	}

	private void filterOnExecutable(ExecutableTableActionContext c) {
		ExecutableRecord exerecord = c.getSelectedExecutableResult().getExecutableRecord();
		Md5BSimFilterType filterType = new Md5BSimFilterType();
		postFilters.removeAll(filterType);
		postFilters.addEntry(filterType, List.of(exerecord.getMd5()));
		updateTableData();
	}

	private void loadExecutable(ExecutableTableActionContext c) {
		ExecutableResult result = c.getSelectedExecutableResult();
		ExecutableRecord record = result.getExecutableRecord();
		String programUrl = record.getURLString();
		openRemoteProgramInTool(programUrl);
	}

	private void showFilterPanel() {
		List<BSimFilterType> filters = BSimFilterType.generateBsimFilters(dbInfo, false);
		BSimSearchResultsFilterDialog filterDialog =
			new BSimSearchResultsFilterDialog(filters, postFilters);
		tool.showDialog(filterDialog);
		BSimFilterSet results = filterDialog.getFilters();
		if (results != null) {
			postFilters = results;
			updateTableData();
		}
	}

	private void updateTableData() {
		BSimFilter filter = postFilters.getBSimFilter();

		List<BSimMatchResult> filteredrows = BSimMatchResult.filterMatchRows(filter, rows);
		Set<ExecutableResult> execrows = ExecutableResult.generateFromMatchRows(filteredrows);

		matchesModel.reload(program, filteredrows);
		executablesModel.reload(program, execrows);
	}

	private void showSearchInfo() {
		tool.showDialog(new BSimSearchInfoDisplayDialog(serverInfo, settings, false));
	}

	private void showSearchedFunctions() {
		GoToService service = tool.getService(GoToService.class);
		HelpLocation help = new HelpLocation(BSimSearchPlugin.HELP_TOPIC, "Searched_Functions");

		tool.showDialog(new SelectedFunctionsTableDialog(queryInfo.getFunctions(), service, help,
			getFunctionMatchCount()));
	}

	private Map<Address, Integer> getFunctionMatchCount() {
		Map<Address, Counter> map = new HashMap<>();
		for (BSimMatchResult result : rows) {
			Address address = result.getAddress();
			Counter counter = map.computeIfAbsent(address, a -> new Counter());
			counter.increment();
		}

		Map<Address, Integer> countMap = new HashMap<>();
		for (FunctionSymbol functionSymbol : queryInfo.getFunctions()) {
			Counter counter = map.get(functionSymbol.getAddress());
			countMap.put(functionSymbol.getAddress(), counter == null ? 0 : counter.count());
		}
		return countMap;
	}

	private JComponent buildComponent() {
		mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		mainPanel.setPreferredSize(new Dimension(1000, 800));
		matchesModel = new BSimMatchResultsModel(tool, dbInfo, lshVectorFactory);
		matchesTable = new GhidraFilterTable<>(matchesModel);
		matchesPanel = buildTitledTablePanel("Function Matches", matchesTable, () -> rows.size());

		executablesModel = new BSimExecutablesSummaryModel(tool, dbInfo);
		executablesTable = new GhidraFilterTable<>(executablesModel);
		executablesPanel = buildTitledTablePanel("Executables", executablesTable,
			() -> executablesModel.getUnfilteredRowCount());

		showExecutableTable(true);

		return mainPanel;
	}

	private void showExecutableTable(boolean selected) {
		mainPanel.removeAll();
		if (selected) {
			JSplitPane split =
				new JSplitPane(JSplitPane.VERTICAL_SPLIT, matchesPanel, executablesPanel);

			split.setResizeWeight(0.5);
			split.setDividerSize(10);

			mainPanel.add(split, BorderLayout.CENTER);
		}
		else {
			mainPanel.add(matchesPanel, BorderLayout.CENTER);
		}

		mainPanel.validate();
	}

	@Override
	public JComponent getComponent() {
		return mainComponent;
	}

	private String getIdString() {
		String serverShortName = serverInfo.getShortDBName();
		StringBuilder builder = new StringBuilder("[server: ");
		builder.append(serverShortName);
		builder.append(", function: ");

		Set<FunctionSymbol> functions = queryInfo.getFunctions();
		if (functions.size() == 1) {
			builder.append(functions.iterator().next().getName());
		}
		else {
			builder.append(functions.size() + " selected");
		}
		builder.append(", Similarity: ");
		builder.append(queryInfo.getSimilarityThreshold());
		builder.append(", Confidence: ");
		builder.append(queryInfo.getSignificanceThreshold());
		builder.append("]");
		return builder.toString();
	}

	public void setFinalQueryResults(SFQueryResult result) {
		rows = BSimMatchResult.generate(result.getSimilarityResults(), program);
		updateTableData();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event != null) {
			return getActionContext(event.getSource());
		}

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		return getActionContext(kfm.getFocusOwner());
	}

	private ActionContext getActionContext(Object source) {
		if (source == matchesTable.getTable()) {
			return new BSimMatchesTableActionContext();
		}
		else if (source == executablesTable.getTable()) {
			return new ExecutableTableActionContext();
		}
		return new DefaultActionContext(this);
	}

	private Program openRemoteProgramInTool(String urlString) {
		ProgramManager service = tool.getService(ProgramManager.class);

		try {
			URL url = new URL(urlString);
			return service.openProgram(url, ProgramManager.OPEN_CURRENT);
		}
		catch (MalformedURLException exc) {
			return null;
		}
	}

	private Program getCachedRemoteProgram(String urlString, Set<Program> openedPrograms) {
		ProgramManager service = tool.getService(ProgramManager.class);

		try {
			URL url = new URL(urlString);
			Program remote = service.openCachedProgram(url, this);
			if (remote == null) {
				return null;
			}
			if (!openedPrograms.add(remote)) {
				// The service added 'this' as a consumer. We previously opened it and we don't
				// want the program to have the same consumer twice.
				remote.release(this);
			}
			return remote;
		}
		catch (MalformedURLException exc) {
			return null;
		}
	}

	private JPanel buildTitledTablePanel(String title, GhidraFilterTable<?> table,
			IntSupplier nonFilteredRowCount) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 2, 10, 2));
		JLabel titleLabel = new JLabel(title);
		panel.add(titleLabel, BorderLayout.NORTH);
		panel.add(table, BorderLayout.CENTER);

		RowObjectTableModel<?> model = table.getModel();
		model.addTableModelListener((e) -> {
			int rowCount = model.getRowCount();
			String text = title + "  - " + rowCount + " results";
			int nonFilteredSize = nonFilteredRowCount.getAsInt();
			if (nonFilteredSize != rowCount) {
				text += "   (Filtered from " + nonFilteredSize + " results)";
			}
			titleLabel.setText(text);
		});
		return panel;
	}

	private Function getOriginalFunction(BSimMatchResult resultRow)
			throws FunctionComparisonException {
		// Determine the original function (local program's function; left side)
		Address originalEntryPoint = resultRow.getAddress();
		FunctionManager originalFunctionManager = program.getFunctionManager();
		Function originalFunction = originalFunctionManager.getFunctionAt(originalEntryPoint);
		if (originalFunction == null) {
			throw new FunctionComparisonException("Couldn't get local function " +
				resultRow.getOriginalFunctionDescription().getFunctionName() + " at " +
				originalEntryPoint.toString() + ".");
		}
		return originalFunction;
	}

	private Function getMatchFunction(BSimMatchResult resultRow, Set<Program> opened)
			throws FunctionComparisonException {
		// Determine the match function (remote program's function; right side)
		Program matchProgram = getCachedRemoteProgram(resultRow.getExecutableURLString(), opened);
		if (matchProgram == null) {
			throw new FunctionComparisonException(
				"Couldn't open remote program: " + resultRow.getExecutableURLString() + " for " +
					resultRow.getSimilarFunctionName() + ".");
		}
		FunctionDescription matchFunctionDescription = resultRow.getMatchFunctionDescription();

		AddressSpace space = program.getAddressFactory().getAddressSpace(matchFunctionDescription.getSpaceID());
		if (space == null) {
			space = program.getAddressFactory().getDefaultAddressSpace();
		}
		Address matchEntryPoint = space.getAddress(matchFunctionDescription.getAddress());
		FunctionManager matchFunctionManager = matchProgram.getFunctionManager();
		Function matchFunction = matchFunctionManager.getFunctionAt(matchEntryPoint);
		if (matchFunction == null) {
			throw new FunctionComparisonException("Couldn't get remote function " +
				matchFunctionDescription.getFunctionName() + " at " + matchEntryPoint + ".");
		}
		return matchFunction;
	}

	private class BSimMatchesTableActionContext extends DefaultActionContext {

		BSimMatchesTableActionContext() {
			super(BSimSearchResultsProvider.this);
		}

		public int getSelectedRowCount() {
			return matchesTable.getTable().getSelectedRowCount();
		}

	}

	private class ExecutableTableActionContext extends DefaultActionContext {

		ExecutableTableActionContext() {
			super(BSimSearchResultsProvider.this);
		}

		public ExecutableResult getSelectedExecutableResult() {
			return executablesTable.getSelectedRowObject();
		}

		public int getSelectedRowCount() {
			return executablesTable.getTable().getSelectedRowCount();
		}
	}

	public Program getProgram() {
		return program;
	}

//==================================================================================================
// Test methods
//==================================================================================================
	BSimMatchResultsModel getMatchesModel() {
		return matchesModel;
	}

	BSimExecutablesSummaryModel getExecutablesModel() {
		return executablesModel;
	}

//==================================================================================================
// Classes
//==================================================================================================
	private class MyDomainObjectListener implements DomainObjectListener {

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			if (ev.contains(SYMBOL_RENAMED, RESTORED)) {
				matchesModel.fireTableDataChanged();
			}
		}
	}
}
