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
package ghidra.features.bsim.gui;

import java.util.*;

import javax.swing.Icon;
import javax.swing.SwingUtilities;

import docking.DockingWindowManager;
import docking.action.builder.ActionBuilder;
import docking.widgets.OkDialog;
import generic.lsh.vector.LSHVectorFactory;
import generic.theme.GIcon;
import ghidra.app.context.ListingActionContext;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.features.bsim.gui.overview.BSimOverviewProvider;
import ghidra.features.bsim.gui.search.dialog.*;
import ghidra.features.bsim.gui.search.results.BSimSearchResultsProvider;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.BsimPluginPackage;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.facade.*;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Plugin for BSim search features
 */
//@formatter:off
@PluginInfo(category = "BSim",
			description = "This plugin allows users to search selected functions against a database " +
				"of previously analyzed functions and returns a table of similar functions",
			packageName = BsimPluginPackage.NAME,
			shortDescription = "Search Bsim database(s) for similar functions",
			status = PluginStatus.RELEASED)
//@formatter:on
public class BSimSearchPlugin extends ProgramPlugin {

	static final Icon ICON = new GIcon("icon.bsim.query.dialog.provider");
	public static final String HELP_TOPIC = "BSimSearchPlugin";
	private SFQueryServiceFactory queryServiceFactory = new DefaultSFQueryServiceFactory();
	private Set<BSimSearchResultsProvider> searchResultsProviders = new HashSet<>();
	private Set<BSimOverviewProvider> overviewProviders = new HashSet<>();

	private BSimServerManager serverManager = new BSimServerManager();

	private BSimSearchService searchService;
	private BSimServerCache lastUsedServerCache = null;
	private BSimSearchSettings lastUsedSettings = new BSimSearchSettings();
	private volatile AbstractProgramTask currentTask;

	private TaskListener taskListener = new TaskListener() {

		@Override
		public void taskCompleted(Task task) {
			currentTask = null;
		}

		@Override
		public void taskCancelled(Task task) {
			currentTask = null;
		}

	};

	public BSimSearchPlugin(PluginTool plugintool) {
		super(plugintool);
		searchService = new MyBSimSearchService();
	}

	@Override
	protected void init() {
		createActions();
	}

	private void createActions() {
		new ActionBuilder("BSim Overview", getName()).menuPath("BSim", "Perform Overview...")
				.helpLocation(new HelpLocation(getName(), "BSim_Overview_Dialog"))
				.onAction(c -> showOverviewDialog())
				.buildAndInstall(tool);

		new ActionBuilder("BSim Search Functions", getName())
				.menuPath("BSim", "Search Functions...")
				.menuIcon(ICON)
				.toolBarIcon(ICON)
				.toolBarGroup("View", "Bsim")
				.helpLocation(new HelpLocation(getName(), "BSim_Search_Dialog"))
				.onAction(c -> showSearchDialog(getSelectedFunctions()))
				.buildAndInstall(tool);

		new ActionBuilder("Manage BSim Servers", getName()).menuPath("BSim", "Manage Servers")
				.helpLocation(new HelpLocation(getName(), "BSim_Servers_Dialog"))
				.onAction(c -> manageServers())
				.buildAndInstall(tool);

		tool.setMenuGroup(new String[] { "BSim" }, "ZBSIM");
		new ActionBuilder("BSim Search From Listing", getName())
				.popupMenuPath("BSim", "Search Function(s)")
				.popupMenuGroup("ZZZ")
				.helpLocation(new HelpLocation(getName(), "BSim_Quick_Search"))
				.withContext(ListingActionContext.class)
				.enabledWhen(c -> lastUsedServerCache != null && canSearchFunctionsInListing(c))
				.onAction(c -> searchService.search(lastUsedServerCache, lastUsedSettings,
					getSelectedFunctions(c)))
				.buildAndInstall(tool);

		new ActionBuilder("BSim Search From Listing With Dialog", getName())
				.popupMenuPath("BSim", "Search Function(s)...")
				.popupMenuGroup("ZZZ")
				.helpLocation(new HelpLocation(getName(), "BSim_Quick_Search"))
				.withContext(ListingActionContext.class)
				.enabledWhen(c -> canSearchFunctionsInListing(c))
				.onAction(c -> showSearchDialog(getSelectedFunctions(c)))
				.buildAndInstall(tool);

		new ActionBuilder("BSim Search From Decompiler", getName())
				.popupMenuPath("BSim", "Search Function")
				.popupMenuGroup("ZZZ")
				.helpLocation(new HelpLocation(getName(), "BSim_Quick_Search"))
				.withContext(DecompilerActionContext.class)
				.enabledWhen(c -> lastUsedServerCache != null && isDecompilerOnFunction(c))
				.onAction(c -> searchService.search(lastUsedServerCache, lastUsedSettings,
					getFunctions(c)))
				.buildAndInstall(tool);

		new ActionBuilder("BSim Search From Decompiler", getName())
				.popupMenuPath("BSim", "Search Function...")
				.popupMenuGroup("ZZZ")
				.helpLocation(new HelpLocation(getName(), "BSim_Quick_Search"))
				.withContext(DecompilerActionContext.class)
				.enabledWhen(c -> isDecompilerOnFunction(c))
				.onAction(c -> showSearchDialog(getFunctions(c)))
				.buildAndInstall(tool);

	}

	public void doBSimSearch(Program program, List<Address> functionAddresses, boolean showDialog) {
		Set<FunctionSymbol> functions = getFunctions(program, functionAddresses);
		if (showDialog) {
			showSearchDialog(functions);
		}
		else {
			searchService.search(lastUsedServerCache, lastUsedSettings, functions);
		}
	}

	private Set<FunctionSymbol> getFunctions(Program program, List<Address> functionAddresses) {
		Set<FunctionSymbol> functions = new HashSet<FunctionSymbol>();
		FunctionManager functionManager = program.getFunctionManager();
		for (Address address : functionAddresses) {
			Function f = functionManager.getFunctionAt(address);
			if (f != null) {
				functions.add((FunctionSymbol) f.getSymbol());
			}
		}
		return functions;
	}

	private boolean isDecompilerOnFunction(DecompilerActionContext c) {
		if (c.isDecompiling()) {
			return false;
		}
		ClangToken token = c.getTokenAtCursor();
		return token instanceof ClangFuncNameToken;
	}

	private boolean canSearchFunctionsInListing(ListingActionContext c) {
		return canSearchFunctionsInListing(c.getProgram(), c.getSelection(), c.getLocation());
	}

	private boolean canSearchFunctionsInListing(Program program, ProgramSelection selection,
			ProgramLocation loc) {
		if (program == null) {
			return false;
		}
		if (selection != null && !selection.isEmpty() && selection.contains(loc.getAddress())) {
			return hasAtLeastOneFunctionInSelection(program, selection);
		}
		return program.getFunctionManager().isInFunction(loc.getAddress());

	}

	private boolean hasAtLeastOneFunctionInSelection(Program program, ProgramSelection selection) {
		FunctionManager functionManager = program.getFunctionManager();
		FunctionIterator iterator = functionManager.getFunctionsNoStubs(selection, true);
		return iterator.hasNext();
	}

	private Set<FunctionSymbol> getFunctions(DecompilerActionContext c) {
		ClangFuncNameToken funcToken = (ClangFuncNameToken) c.getTokenAtCursor();
		PcodeOp op = funcToken.getPcodeOp();
		Address calledAddress = null;
		if (op == null || (op.getOpcode() != PcodeOp.CALL)) {
			//op is null - user clicked on function token in function signature at the top of the 
			//decompiler window op.getOpcode != PcodeOp.CALL shouldn't happen but provide 
			//reasonable default just to be safe
			//in either case just query the function currently in the decompiler window
			calledAddress = c.getAddress();
		}
		else {
			calledAddress = op.getInput(0).getAddress();
		}
		Program p = c.getProgram();
		Function function = p.getFunctionManager().getFunctionContaining(calledAddress);
		return Set.of((FunctionSymbol) function.getSymbol());
	}

	@Override
	public void dispose() {
		closeAllProviders();
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		AbstractProgramTask task = currentTask;
		return task == null || task.getProgram().equals(dObj);
	}

	@Override
	protected void programClosed(Program program) {
		// Close any overview or search providers based on that program

		// copy to avoid concurrent mod exception as closing will trigger a callback to remove
		List<BSimSearchResultsProvider> searches = new ArrayList<>(searchResultsProviders);
		for (BSimSearchResultsProvider provider : searches) {
			if (provider.getProgram() == program) {
				provider.closeComponent();
			}
		}

		List<BSimOverviewProvider> overviews = new ArrayList<>(overviewProviders);
		for (BSimOverviewProvider provider : overviews) {
			if (provider.getProgram() == program) {
				provider.closeComponent();
			}
		}
	}

	private void manageServers() {
		BSimServerDialog dialog = new BSimServerDialog(getTool(), serverManager);
		DockingWindowManager.showDialog(dialog);
	}

	private void showSearchDialog(Set<FunctionSymbol> functions) {
		if (checkBusy()) {
			return;
		}
		if (functions.isEmpty()) {
			OkDialog.showError("No Function(s) Selected",
				"You must first place your cursor in a function or \n" +
					"create a selection that contains 1 or more functions!");
			return;
		}
		BSimSearchDialog searchDialog =
			new BSimSearchDialog(tool, searchService, serverManager, functions);
		tool.showDialog(searchDialog);
	}

	private boolean checkBusy() {
		if (currentTask != null) {
			OkDialog.showInfo("BSim Database Busy", "Only one BSim query permitted at a time!");
			return true;
		}
		return false;
	}

	private void showOverviewDialog() {
		if (checkBusy()) {
			return;
		}
		BSimOverviewDialog overviewDialog =
			new BSimOverviewDialog(tool, searchService, serverManager);
		tool.showDialog(overviewDialog);
	}

	private Set<FunctionSymbol> getSelectedFunctions() {
		return getSelectedFunctions(currentProgram, currentSelection, currentLocation);
	}

	private Set<FunctionSymbol> getSelectedFunctions(ListingActionContext c) {
		return getSelectedFunctions(c.getProgram(), c.getSelection(), c.getLocation());
	}

	private Set<FunctionSymbol> getSelectedFunctions(Program program, ProgramSelection selection,
			ProgramLocation location) {
		FunctionManager functionManager = program.getFunctionManager();
		Set<FunctionSymbol> functions = new HashSet<>();
		if (selection == null || selection.isEmpty()) {
			if (currentLocation == null) {
				// must be opening
				return functions;
			}

			Function currentFunction = functionManager.getFunctionContaining(location.getAddress());
			if (currentFunction != null) {
				functions.add((FunctionSymbol) currentFunction.getSymbol());
			}
			return functions;
		}

		FunctionIterator iterator = functionManager.getFunctionsNoStubs(selection, true);
		for (Function function : iterator) {
			functions.add((FunctionSymbol) function.getSymbol());
		}
		return functions;
	}

	public void closeAllProviders() {
		for (BSimSearchResultsProvider provider : searchResultsProviders) {
			provider.closeComponent();
		}
		for (BSimOverviewProvider provider : overviewProviders) {
			provider.closeComponent();
		}
	}

	/**
	 * Get all non-stub functions for computing signature overview
	 * @return set of all non-stub function symbols
	 */
	private Set<FunctionSymbol> getOverviewFunctions() {
		Program program = getCurrentProgram();
		if (program == null) {
			return Set.of();
		}

		FunctionManager functionManager = program.getFunctionManager();
		TreeSet<FunctionSymbol> functions = new TreeSet<>(new Comparator<FunctionSymbol>() {
			@Override
			public int compare(FunctionSymbol f1, FunctionSymbol f2) {
				return f1.getAddress().compareTo(f2.getAddress());
			}
		});

		FunctionIterator iterator = functionManager.getFunctionsNoStubs(true);
		for (Function function : iterator) {
			functions.add((FunctionSymbol) function.getSymbol());
		}
		return functions;
	}

	private BSimOverviewProvider getOverviewProvider(BSimServerInfo serverInfo, Program program,
			LSHVectorFactory vectoryFactory, BSimSearchSettings settings) {
		// this call is made from a task, but new providers need to be created in the Swing thread
		return Swing.runNow(
			() -> new BSimOverviewProvider(this, serverInfo, program, vectoryFactory, settings));
	}

	private BSimSearchResultsProvider getSearchResultsProvider(BSimServerInfo serverInfo,
			DatabaseInformation dbInfo, LSHVectorFactory vectorFactory, SFQueryInfo queryInfo,
			BSimSearchSettings settings) {
		// this call is made from a task, but new providers need to be created in the Swing thread
		return Swing.runNow(() -> new BSimSearchResultsProvider(this, tool, serverInfo, dbInfo,
			vectorFactory, queryInfo, settings));
	}

	/**
	 * Get an {@link AutoCloseable} {@link SimilarFunctionQueryService} instance which will
	 * be connected to current BSim Server.  Caller is responsible for closing instance.
	 * @param program program containing functions to be searched
	 * @return new {@link SimilarFunctionQueryService} instance
	 * @throws QueryDatabaseException if error occurs connecting to database
	 */
	private SimilarFunctionQueryService getQueryService(Program program, BSimServerInfo serverInfo)
			throws QueryDatabaseException {

		SimilarFunctionQueryService queryService =
			queryServiceFactory.createSFQueryService(program);
		queryService.initializeDatabase(serverInfo.toURLString());
		String errorMessage = queryService.getDatabaseCompatibility();
		if ((queryService.getLastError() != null) &&
			(queryService.getLastError().category == ErrorCategory.Nodatabase)) {
			errorMessage = "Database does not exist";
		}
		if (errorMessage != null) {
			throw new QueryDatabaseException(errorMessage);
		}
		return queryService;
	}

	public void providerClosed(BSimSearchResultsProvider provider) {
		searchResultsProviders.remove(provider);
	}

	public void providerClosed(BSimOverviewProvider overviewProvider) {
		overviewProviders.remove(overviewProvider);
	}

//==================================================================================================
// Test methods
//==================================================================================================
	BSimServerManager getServerManager() {
		return serverManager;
	}

	void setQueryServiceFactory(SFQueryServiceFactory factory) {
		queryServiceFactory = factory;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	abstract class AbstractProgramTask extends Task {
		AbstractProgramTask(String title) {
			super(title, true, true, false, false);
		}

		abstract Program getProgram();
	}

	class OverviewTask extends AbstractProgramTask
			implements SFResultsUpdateListener<ResponseNearestVector> {

		private BSimSearchSettings settings;
		private BSimServerCache serverCache;
		private BSimOverviewProvider overviewProvider;
		private SFOverviewInfo overviewInfo;

		public OverviewTask(BSimServerCache serverCache, BSimSearchSettings settings,
				Set<FunctionSymbol> functions) {
			super("Computing BSim Overview");

			this.serverCache = serverCache;
			this.settings = settings;
			overviewInfo = new SFOverviewInfo(functions);
			overviewInfo.setSimilarityThreshold(settings.getSimilarity());
			overviewInfo.setSignificanceThreshold(settings.getConfidence());
		}

		@Override
		Program getProgram() {
			return overviewInfo.getProgram();
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			lastUsedServerCache = serverCache;
			lastUsedSettings = settings;

			try (SimilarFunctionQueryService queryService =
				getQueryService(overviewInfo.getProgram(), serverCache.getServerInfo())) {
				monitor.setMessage("Calculating overview...");
				queryService.overviewSimilarFunctions(overviewInfo, this, monitor);
			}
			catch (QueryDatabaseException e) {
				Msg.showError(this, null, "Error Performing BSim Overview", e.getMessage(), e);
			}
		}

		@Override
		public void resultAdded(QueryResponseRecord partialResponse) {
			SwingUtilities.invokeLater(() -> {
				getProvider().overviewResultAdded((ResponseNearestVector) partialResponse);
			});
		}

		@Override
		public void setFinalResult(ResponseNearestVector result) {
			if (result != null) {
				SwingUtilities.invokeLater(() -> {
					getProvider().setFinalOverviewResults(result);
				});
			}
		}

		private BSimOverviewProvider getProvider() {
			if (overviewProvider == null) {
				BSimServerInfo serverInfo = serverCache.getServerInfo();
				LSHVectorFactory lshVectorFactory = serverCache.getLSHVectorFactory();
				Program program = overviewInfo.getProgram();
				overviewProvider =
					getOverviewProvider(serverInfo, program, lshVectorFactory, settings);
				overviewProviders.add(overviewProvider);
			}
			return overviewProvider;
		}

	}

	class SearchTask extends AbstractProgramTask implements SFResultsUpdateListener<SFQueryResult> {

		private BSimServerCache serverCache;
		private BSimSearchResultsProvider resultsProvider;
		private SFQueryInfo queryInfo;
		private BSimSearchSettings settings;

		public SearchTask(BSimServerCache serverCache, BSimSearchSettings settings,
				Set<FunctionSymbol> functions) {
			super("BSim Search For Similar Functions");
			this.serverCache = serverCache;
			this.settings = settings;
			queryInfo = new SFQueryInfo(functions);
			queryInfo.setSimilarityThreshold(settings.getSimilarity());
			queryInfo.setSignificanceThreshold(settings.getConfidence());
			queryInfo.setMaximumResults(settings.getMaxResults());
			BSimFilter bsimFilter = queryInfo.getBsimFilter();
			BSimFilterSet bSimFilterSet = settings.getBSimFilterSet();
			bsimFilter.replaceWith(bSimFilterSet.getBSimFilter());

		}

		@Override
		Program getProgram() {
			return queryInfo.getProgram();
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			monitor.setMessage("Connecting to database...");
			try (SimilarFunctionQueryService queryService =
				getQueryService(queryInfo.getProgram(), serverCache.getServerInfo())) {
				monitor.setMessage("Querying database...");
				queryService.querySimilarFunctions(queryInfo, this, monitor);
			}
			catch (QueryDatabaseException e) {
				Msg.showError(this, null, "Error Performing BSim Search", e.getMessage(), e);
			}
		}

		@Override
		public void resultAdded(QueryResponseRecord partialResponse) {
			// NOTE: QueryResultsProvider is unable to handle incremental results 
		}

		@Override
		public void setFinalResult(SFQueryResult result) {
			if (result != null) {
				SwingUtilities.invokeLater(() -> {
					getSearchProvider().setFinalQueryResults(result);
				});
			}
		}

		private BSimSearchResultsProvider getSearchProvider() {
			if (resultsProvider == null) {
				BSimServerInfo serverInfo = serverCache.getServerInfo();
				DatabaseInformation databaseInfo = serverCache.getDatabaseInformation();
				LSHVectorFactory lshVectorFactory = serverCache.getLSHVectorFactory();
				resultsProvider = getSearchResultsProvider(serverInfo, databaseInfo,
					lshVectorFactory, queryInfo, settings);
				searchResultsProviders.add(resultsProvider);
			}
			return resultsProvider;
		}

	}

	class MyBSimSearchService implements BSimSearchService {

		@Override
		public BSimServerInfo getLastUsedServer() {
			return lastUsedServerCache == null ? null : lastUsedServerCache.getServerInfo();
		}

		@Override
		public BSimSearchSettings getLastUsedSearchSettings() {
			return lastUsedSettings;
		}

		@Override
		public void search(BSimServerCache serverCache, BSimSearchSettings settings,
				Set<FunctionSymbol> functions) {
			if (checkBusy()) {
				return;
			}

			lastUsedServerCache = serverCache;
			lastUsedSettings = settings;

			SearchTask searchTask = new SearchTask(serverCache, settings, functions);
			currentTask = searchTask;
			searchTask.addTaskListener(taskListener);
			TaskLauncher.launch(searchTask);
		}

		@Override
		public void performOverview(BSimServerCache serverCache, BSimSearchSettings settings) {
			if (checkBusy()) {
				return;
			}
			lastUsedServerCache = serverCache;
			lastUsedSettings = settings;

			OverviewTask task = new OverviewTask(serverCache, settings, getOverviewFunctions());
			currentTask = task;
			task.addTaskListener(taskListener);
			TaskLauncher.launch(task);
		}

	}

}
