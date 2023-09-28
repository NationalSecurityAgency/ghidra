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
package ghidra.app.plugin.core.searchtext;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Icon;

import org.apache.commons.lang3.StringUtils;

import docking.*;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.fieldpanel.support.Highlight;
import docking.widgets.table.threaded.*;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult;
import ghidra.app.plugin.core.searchtext.databasesearcher.ProgramDatabaseSearchTableModel;
import ghidra.app.plugin.core.searchtext.databasesearcher.ProgramDatabaseSearcher;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.*;
import ghidra.app.util.query.TableService;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.*;

/**
 * Plugin to search text as it is displayed in the fields of the Code Browser.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search Program Text",
	description = "This plugin searches program text for a string. " +
			"It provides a program database search and a listing display match search. " +
			"The program database search searches the program database and is faster " +
			"than the listing display match search. " +
			"The listing display match search may take a long time because " +
			"a string must be rendered to search for each address " +
			"in the program or in the selection. " +
			"This string is the same as what would be displayed by the " +
			"Code Browser if the address were visible. " +
			"The search can be done incrementally, on a selection, or " +
			"on the entire program. Multiple matches are displayed " +
			"in a query results table. An option allows the search results " +
			"to be highlighted in the Code Browser.",
	servicesRequired = { ProgramManager.class, GoToService.class }
)
//@formatter:on
public class SearchTextPlugin extends ProgramPlugin implements OptionsChangeListener, TaskListener,
		NavigatableRemovalListener, DockingContextListener {

	private static final Icon SEARCH_MARKER_ICON = new GIcon("icon.base.search.marker");

	private static final String DESCRIPTION = "Search program text for string";

	private boolean waitingForSearchAll;
	private SearchTextDialog searchDialog;
	private GoToService goToService;
	private int searchLimit;
	private SearchTask currentTask;
	private String lastSearchedText;
	private boolean doHighlight;
	private Navigatable navigatable;

	private TableLoadingListener currentTableListener; // must keep reference (used by weak set)
	private TaskMonitor searchAllTaskMonitor;

	private boolean searchedOnce;

	/**
	 * The constructor for the SearchTextPlugin.
	 * 
	 * @param plugintool The tool required by this plugin.
	 */
	public SearchTextPlugin(PluginTool plugintool) {
		super(plugintool);
		createActions();
		initializeOptions();
		tool.addContextListener(this);
	}

	@Override
	public void taskCancelled(Task task) {
		searchDialog.setStatusText("Search cancelled");
		if (task == currentTask) {
			currentTask = null;
		}
	}

	@Override
	public void taskCompleted(Task task) {
		if (tool == null || navigatable == null) {
			return; // user either exited the tool, or closed the program
		}

		searchDialog.setStatusText("");
		SearchTask searchTask = (SearchTask) task;
		Navigatable searchNavigatable = ((SearchTask) task).getNavigatable();
		Program program = ((SearchTask) task).getProgram();
		if (searchNavigatable.getProgram() == null || searchNavigatable.isDisposed()) {
			return;
		}

		TextSearchResult result = searchTask.getSearchLocation();
		Searcher textSearcher = searchTask.getTextSearcher();
		SearchOptions searchOptions = textSearcher.getSearchOptions();
		if (result == null) {
			searchDialog.setStatusText("Not found");
		}
		else if (result.programLocation().equals(currentLocation)) {
			searchNext(searchTask.getProgram(), searchNavigatable, textSearcher);
		}
		else {
			searchDialog.setStatusText("");
			ProgramLocation loc = result.programLocation();
			if (goToService.goTo(searchNavigatable, loc, program)) {
				new SearchTextHighlightProvider(searchNavigatable, searchOptions, null, program,
					result);
			}
		}

		lastSearchedText = searchOptions.getText();
		if (task == currentTask) {
			currentTask = null;
		}
	}

	String getLastSearchText() {
		return lastSearchedText;
	}

	@Override
	protected void dispose() {
		tool.removeContextListener(this);
		ToolOptions opt = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		opt.removeOptionsChangeListener(this);

		opt = tool.getOptions(SearchConstants.SEARCH_OPTION_NAME);
		opt.removeOptionsChangeListener(this);

		navigatable = null;

		if (searchDialog != null) {

			if (searchDialog.isVisible()) {
				TaskMonitor taskMonitor = searchDialog.getTaskMonitorComponent();
				taskMonitor.cancel();
				if (searchAllTaskMonitor != null) {
					searchAllTaskMonitor.cancel();
				}
			}

			searchDialog.dispose();
		}

		if (currentTask != null) {
			currentTask.cancel();
		}
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
	}

	private void setNavigatable(Navigatable newNavigatable) {
		if (newNavigatable == navigatable) {
			return;
		}
		if (navigatable != null) {
			navigatable.removeNavigatableListener(this);
		}
		if (newNavigatable != null) {
			newNavigatable.addNavigatableListener(this);
		}
		navigatable = newNavigatable;

		if (searchDialog != null) {
			searchDialog.setSearchEnabled(newNavigatable != null);
		}
	}

	private void updateSelection(NavigatableActionContext context) {
		if (searchDialog != null) {
			searchDialog.setHasSelection(context.hasSelection());
		}
	}

	private void updateSelectionFromCurrentNavigatable() {
		if (navigatable == null) {
			return;
		}

		if (searchDialog == null) {
			return;
		}

		ProgramSelection selection = navigatable.getSelection();
		searchDialog.setHasSelection(selection != null && !selection.isEmpty());
	}

	void next() {
		Program program = navigatable.getProgram();
		ProgramLocation location = getStartLocation();
		Searcher textSearcher = null;
		SearchOptions searchOptions = searchDialog.getSearchOptions();
		AddressSetView addressSet = getAddressSet(navigatable, searchOptions);

		if (searchOptions.isProgramDatabaseSearch()) {
			textSearcher = new ProgramDatabaseSearcher(tool, program, location, addressSet,
				searchOptions,
				searchDialog.showTaskMonitorComponent(AbstractSearchTableModel.TITLE, true, true));
		}
		else {
			textSearcher = new ListingDisplaySearcher(tool, program, location, addressSet,
				searchDialog.getSearchOptions(),
				searchDialog.showTaskMonitorComponent(AbstractSearchTableModel.TITLE, true, true));
		}
		searchNext(navigatable.getProgram(), navigatable, textSearcher);
	}

	private ProgramLocation getStartLocation() {
		return currentLocation = navigatable.getLocation();
	}

	private void searchNext(Program program, Navigatable searchNavigatable, Searcher textSearcher) {
		SearchTask task = new SearchTask(searchNavigatable, program, textSearcher);
		task.addTaskListener(this);
		currentTask = task;
		searchDialog.setStatusText("Searching...");
		searchDialog.executeProgressTask(task, 500);
	}

	void searchAll(SearchOptions options) {

		ProgramSelection selection = navigatable.getSelection();
		Program program = navigatable.getProgram();
		AddressSetView view = getSearchAllAddresses(program, selection);

		waitingForSearchAll = true;
		GhidraProgramTableModel<ProgramLocation> ttModel = null;
		if (options.isProgramDatabaseSearch()) {
			ttModel = new ProgramDatabaseSearchTableModel(tool, program, view, options);
		}
		else {
			ttModel = new ListingDisplaySearchTableModel(tool, program, view, options);
		}

		showQueryData(ttModel, options, program, navigatable);
	}

	private AddressSetView getSearchAllAddresses(Program program, ProgramSelection selection) {
		AddressSetView view = program.getMemory();
		if (searchDialog.searchSelection()) {
			if (!selection.isEmpty()) {
				return new AddressSet(selection);
			}
		}
		return view;
	}

	private void showQueryData(GhidraProgramTableModel<ProgramLocation> model,
			SearchOptions searchOptions, Program searchProgram, Navigatable searchNavigatable) {

		TableService query = tool.getService(TableService.class);
		String matchType = "Listing Display Match";
		if (model instanceof ProgramDatabaseSearchTableModel) {
			matchType = "Program Database";
		}

		String searchString = searchOptions.getText();
		if (searchNavigatable.getProgram() != searchProgram) {
			return;
		}

		currentTableListener = new TableLoadingListener(model);
		model.addInitialLoadListener(currentTableListener);

		TableComponentProvider<ProgramLocation> tableProvider =
			getTableResultsProvider(model, searchProgram, query, matchType, searchString);
		tableProvider.installRemoveItemsAction();
		currentTableListener.setProvider(tableProvider);

		GThreadedTablePanel<ProgramLocation> tablePanel = tableProvider.getThreadedTablePanel();
		searchAllTaskMonitor = tablePanel.getTaskMonitor();

		tableProvider.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "SearchAllResults"));
		new SearchTextHighlightProvider(searchNavigatable, searchOptions, tableProvider,
			searchProgram, null);
	}

	private TableComponentProvider<ProgramLocation> getTableResultsProvider(
			GhidraProgramTableModel<ProgramLocation> model, Program searchProgram,
			TableService query, String matchType, String searchString) {
		if (navigatable.supportsMarkers()) {
			return query.showTableWithMarkers(
				"Search Text - \"" + searchString + "\"  [" + matchType + "]", "Search", model,
				SearchConstants.SEARCH_HIGHLIGHT_COLOR, SEARCH_MARKER_ICON, "Search", navigatable);
		}
		return query.showTable("Search Text - \"" + searchString + "\"  [" + matchType + "]",
			"Search", model, "Search", navigatable);
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		if ((navigatable != null && navigatable.getProgram() == dObj) &&
			(waitingForSearchAll || currentTask != null)) {
			tool.setStatusInfo("Can't close program while searching...", true);
			return false;
		}
		return true;
	}

	void searched() {
		tool.contextChanged(null);
		searchedOnce = true;
	}

	/*junit*/ int getResultsLimit() {
		return searchLimit;
	}

	/*junit*/ SearchTextDialog getSearchDialog() {
		return searchDialog;
	}

	/*junit*/ boolean isWaitingForSearchAll() {
		return waitingForSearchAll;
	}

	/**
	 * Create the action for to pop up the search dialog.
	 */
	private void createActions() {
		String subGroup = getClass().getName();

		new ActionBuilder("Search Text", getName())
			.menuPath("&Search", "Program &Text...")
			.menuGroup("search", subGroup)
			.keyBinding("ctrl shift E")
			.description(DESCRIPTION)
			.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Search Text"))
			.withContext(NavigatableActionContext.class, true)
			.validContextWhen(c -> !(c instanceof RestrictedAddressSetContext))
			.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
			.onAction(c -> {
				setNavigatable(c.getNavigatable());
				displayDialog(c);
			})
			.buildAndInstall(tool);

		new ActionBuilder("Repeat Text Search", getName())
			.menuPath("&Search", "Repeat Text Search")
			.menuGroup("search", subGroup)
			.keyBinding("ctrl shift F3")
			.description(DESCRIPTION)
			.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Repeat Text Search"))
			.withContext(NavigatableActionContext.class, true)
			.inWindow(ActionBuilder.When.CONTEXT_MATCHES)
			.enabledWhen(c -> searchedOnce)
			.onAction(c -> {
				setNavigatable(c.getNavigatable());
				searchDialog.repeatSearch();
			})
			.buildAndInstall(tool);
	}

	protected void updateNavigatable(ActionContext context) {
		if (context instanceof ListingActionContext) {
			NavigatableActionContext navContext = ((NavigatableActionContext) context);
			setNavigatable(navContext.getNavigatable());
			updateSelection(navContext);
		}
		else {
			updateSelectionFromCurrentNavigatable();
		}
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(GhidraOptions.OPTION_SEARCH_LIMIT)) {
			int newSearchLimit = ((Integer) newValue).intValue();
			if (newSearchLimit <= 0) {
				throw new OptionsVetoException("Search limit must be greater than 0");
			}
			searchLimit = newSearchLimit;
		}
		else if (optionName.equals(SearchConstants.SEARCH_HIGHLIGHT_NAME)) {
			doHighlight = ((Boolean) newValue).booleanValue();
		}
	}

	private void initializeOptions() {

		ToolOptions opt = tool.getOptions(SearchConstants.SEARCH_OPTION_NAME);
		HelpLocation loc = new HelpLocation(HelpTopics.SEARCH, "HighlightText");

		opt.registerOption(SearchConstants.SEARCH_HIGHLIGHT_NAME, true, loc,
			"Determines whether to highlight the matched string for a search in the listing.");
		opt.registerThemeColorBinding(SearchConstants.SEARCH_HIGHLIGHT_COLOR_OPTION_NAME,
			SearchConstants.SEARCH_HIGHLIGHT_COLOR.getId(), null,
			"The search result highlight color");
		opt.registerThemeColorBinding(SearchConstants.SEARCH_HIGHLIGHT_CURRENT_COLOR_OPTION_NAME,
			SearchConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR.getId(), null,
			"The search result highlight color for the currently selected match");

		searchLimit =
			opt.getInt(GhidraOptions.OPTION_SEARCH_LIMIT, SearchConstants.DEFAULT_SEARCH_LIMIT);

		doHighlight = opt.getBoolean(SearchConstants.SEARCH_HIGHLIGHT_NAME, true);

		opt.setOptionsHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_Text"));

		opt.addOptionsChangeListener(this);
	}

	private void displayDialog(NavigatableActionContext context) {
		if (searchDialog == null) {
			searchDialog = new SearchTextDialog(this);
			searchDialog.setHasSelection(context.hasSelection());
		}

		String textSelection = navigatable.getTextSelection();
		ProgramLocation location = navigatable.getLocation();
		Address address = location.getAddress();
		Listing listing = context.getProgram().getListing();
		CodeUnit codeUnit = listing.getCodeUnitAt(address);
		boolean isInstruction = false;
		if (textSelection != null) {
			if (codeUnit != null) {
				if (codeUnit instanceof Instruction) {
					isInstruction = true;
				}
				else {
					isInstruction = false;
				}
				searchDialog.setCurrentField(location, isInstruction);
			}
			searchDialog.setValueFieldText(textSelection);
		}
		searchDialog.show(context.getComponentProvider());
	}

	/**
	 * Get the address set for the selection.
	 * 
	 * @return null if there is no selection
	 */
	private AddressSetView getAddressSet(Navigatable searchNavigatable, SearchOptions options) {
		ProgramSelection selection = searchNavigatable.getSelection();
		Program program = searchNavigatable.getProgram();
		AddressSetView addressSet = getMemoryAddressSet(program, options);
		if (selection != null && !selection.isEmpty() && searchDialog.searchSelection()) {
			addressSet = addressSet.intersect(selection);
		}
		return addressSet;
	}

	private AddressSetView getMemoryAddressSet(Program program, SearchOptions options) {
		Memory memory = program.getMemory();
		if (options.includeNonLoadedMemoryBlocks()) {
			return memory;
		}
		AddressSet set = new AddressSet();
		for (MemoryBlock block : memory.getBlocks()) {
			if (block.isLoaded()) {
				set.add(block.getStart(), block.getEnd());
			}
		}
		return set;
	}

	public Navigatable getNavigatable() {
		return navigatable;
	}

	@Override
	public void navigatableRemoved(Navigatable removedNavigatable) {
		setNavigatable(null);
	}

	@Override
	public void contextChanged(ActionContext context) {
		updateNavigatable(context);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class TableLoadingListener implements ThreadedTableModelListener {

		private ThreadedTableModel<?, ?> model;
		private TableComponentProvider<ProgramLocation> provider;

		TableLoadingListener(ThreadedTableModel<?, ?> model) {
			this.model = model;
		}

		void setProvider(TableComponentProvider<ProgramLocation> tableProvider) {
			this.provider = tableProvider;
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			if (isDisposed()) {
				return;
			}

			waitingForSearchAll = false;
			searchDialog.searchAllFinished();
			if (wasCancelled) {
				searchDialog.setStatusText("Search Cancelled");
				return;
			}

			int matchCount = model.getRowCount();
			if (matchCount == 0) {
				searchDialog.setStatusText("No matches found.");
				return;
			}

			if (matchCount >= searchLimit) {

				Msg.showWarn(getClass(), getParentComponent(), "Search Limit Exceeded!",
					"Stopped search after finding " + matchCount + " matches.\n" +
						"The search limit can be changed at Edit->Tool Options, under Search.");
			}
			// there was a suggestion that the dialog should not go way after a search all
//			searchDialog.close();
		}

		private Component getParentComponent() {
			if (provider != null) {
				return provider.getComponent();
			}

			// must have completed too fast for the provider to be set; try something cute
			Component focusOwner =
				KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
			return focusOwner; // assume this IS the provider
		}

		@Override
		public void loadingStarted() {
			// don't care
		}

		@Override
		public void loadPending() {
			// don't care
		}
	}

	private class SearchTextHighlightProvider
			implements ListingHighlightProvider, ComponentProviderActivationListener {
		private SearchOptions searchOptions;
		private TableComponentProvider<?> provider;
		private Program highlightProgram;
		private final Navigatable highlightNavigatable;
		private boolean showAllResults;

		// this is non-null for a single search
		private TextSearchResult searchResult;

		SearchTextHighlightProvider(Navigatable navigatable, SearchOptions searchOptions,
				TableComponentProvider<?> provider, Program program,
				TextSearchResult searchResult) {
			highlightNavigatable = navigatable;
			this.searchOptions = searchOptions;
			this.provider = provider;
			this.highlightProgram = program;
			this.searchResult = searchResult;
			this.showAllResults = searchResult == null;

			if (provider != null) {
				provider.addActivationListener(this);
			}
			highlightNavigatable.setHighlightProvider(this, program);
		}

		@Override
		public Highlight[] createHighlights(String text, ListingField field, int cursorTextOffset) {

			Class<? extends FieldFactory> fieldFactoryClass = field.getFieldFactory().getClass();

			if (!doHighlight) {
				return NO_HIGHLIGHTS;
			}

			if (checkRemoveHighlights()) {
				return NO_HIGHLIGHTS;
			}

			if (!shouldHighlight(field)) {
				return NO_HIGHLIGHTS;
			}

			if (!searchOptions.searchAllFields() && (fieldFactoryClass == XRefFieldFactory.class ||
				fieldFactoryClass == XRefHeaderFieldFactory.class)) {
				return NO_HIGHLIGHTS;
			}

			if (showAllResults) {
				return getAllHighlights(text, cursorTextOffset);
			}

			Address address = searchResult.programLocation().getAddress();
			ProxyObj<?> proxy = field.getProxy();
			if (proxy.contains(address)) {
				return getSingleSearchHighlight(text, field, cursorTextOffset);
			}

			return NO_HIGHLIGHTS;
		}

		private Highlight[] getAllHighlights(String text, int cursorTextOffset) {

			String searchText = searchOptions.getText();
			if (StringUtils.isBlank(searchText) || StringUtils.isBlank(text)) {
				return NO_HIGHLIGHTS;
			}

			List<Highlight> list = new ArrayList<>();
			Pattern regexp =
				UserSearchUtils.createSearchPattern(searchText, searchOptions.isCaseSensitive());
			Matcher matcher = regexp.matcher(text);
			while (matcher.find()) {
				int start = matcher.start();
				int end = matcher.end() - 1;
				Color hlColor = SearchConstants.SEARCH_HIGHLIGHT_COLOR;
				if (start <= cursorTextOffset && end >= cursorTextOffset) {
					// change the highlight color when in the field so it stands out
					hlColor = SearchConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR;
				}
				list.add(new Highlight(start, end, hlColor));
			}

			if (list.isEmpty()) {
				return NO_HIGHLIGHTS;
			}
			return list.toArray(Highlight[]::new);
		}

		private Highlight[] getSingleSearchHighlight(String text, ListingField field,
				int cursorTextOffset) {

			String searchText = searchOptions.getText();
			if (StringUtils.isBlank(searchText) || StringUtils.isBlank(text)) {
				return NO_HIGHLIGHTS;
			}

			FieldFactory fieldFactory = field.getFieldFactory();
			ProgramLocation loc = searchResult.programLocation();
			if (!fieldFactory.supportsLocation(field, loc)) {
				return NO_HIGHLIGHTS;
			}

			int charOffset = searchResult.offset();
			int searchStart = charOffset;
			int searchEnd = searchStart + searchText.length();

			Pattern regexp =
				UserSearchUtils.createSearchPattern(searchText, searchOptions.isCaseSensitive());
			Matcher matcher = regexp.matcher(text);
			while (matcher.find()) {
				int start = matcher.start();
				int end = matcher.end();

				// ensure the particular regex match is the actual search result
				if (start == searchStart && end == searchEnd) {

					Color hlColor = SearchConstants.SEARCH_HIGHLIGHT_COLOR;
					if (start <= cursorTextOffset && end >= cursorTextOffset) {
						// change the highlight color when in the field so it stands out
						hlColor = SearchConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR;
					}

					// this is the matching search hit for a single search
					int endEx = end - 1;
					return new Highlight[] { new Highlight(start, endEx, hlColor) };
				}
			}
			return NO_HIGHLIGHTS;
		}

		private boolean shouldHighlight(ListingField field) {

			ProxyObj<?> proxy = field.getProxy();
			Object obj = proxy.getObject();
			Program navigatableProgram = navigatable == null ? null : navigatable.getProgram();
			if (navigatableProgram != highlightProgram) {
				return false;
			}

			if (searchOptions.searchAllFields()) {
				return true;
			}

			Class<? extends FieldFactory> factoryClass = field.getFieldFactory().getClass();
			if (searchOptions.searchComments()) {
				if (factoryClass == PreCommentFieldFactory.class ||
					factoryClass == PlateFieldFactory.class ||
					factoryClass == PostCommentFieldFactory.class ||
					factoryClass == EolCommentFieldFactory.class) {
					return true;
				}
			}
			if (searchOptions.searchBothInstructionMnemonicAndOperands() &&
				(obj instanceof Instruction)) {
				if (factoryClass == MnemonicFieldFactory.class ||
					factoryClass == OperandFieldFactory.class) {
					return true;
				}

			}
			if (searchOptions.searchOnlyInstructionMnemonics() && (obj instanceof Instruction)) {
				if (factoryClass == MnemonicFieldFactory.class) {
					return true;
				}

			}
			if (searchOptions.searchOnlyInstructionOperands() && (obj instanceof Instruction)) {
				if (factoryClass == OperandFieldFactory.class) {
					return true;
				}

			}
			if (searchOptions.searchBothDataMnemonicsAndOperands() && (obj instanceof Data)) {
				if (factoryClass == MnemonicFieldFactory.class ||
					factoryClass == OperandFieldFactory.class) {
					return true;
				}
			}
			if (searchOptions.searchOnlyDataMnemonics() && (obj instanceof Data)) {
				if (factoryClass == MnemonicFieldFactory.class) {
					return true;
				}
			}
			if (searchOptions.searchOnlyDataOperands() && (obj instanceof Data)) {
				if (factoryClass == OperandFieldFactory.class) {
					return true;
				}
			}

			if (searchOptions.searchFunctions()) {
				if (factoryClass == FunctionRepeatableCommentFieldFactory.class ||
					factoryClass == FunctionSignatureFieldFactory.class ||
					factoryClass == VariableCommentFieldFactory.class ||
					factoryClass == VariableLocFieldFactory.class ||
					factoryClass == VariableNameFieldFactory.class ||
					factoryClass == VariableTypeFieldFactory.class) {
					return true;
				}
			}
			if (searchOptions.searchLabels()) {
				if (factoryClass == LabelFieldFactory.class) {
					return true;
				}
			}

			return false;
		}

		private boolean checkRemoveHighlights() {
			if (provider != null) { // search all - remove highlights when                 
				if (!tool.isVisible(provider)) { // results are no longer showing
					highlightNavigatable.removeHighlightProvider(this, highlightProgram);
					return true;
				}
			}
			else if (!searchDialog.isVisible()) {
				// single search - remove highlights when search dialog no longer showing
				highlightNavigatable.removeHighlightProvider(this, highlightProgram);
				return true;
			}
			return false;
		}

		@Override
		public void componentProviderActivated(ComponentProvider componentProvider) {
			// enable highlighting
			highlightNavigatable.setHighlightProvider(this, highlightProgram);
		}

		@Override
		public void componentProviderDeactivated(ComponentProvider componentProvider) {
			// only handle highlighting during activation
		}
	}

}
