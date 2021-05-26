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
package ghidra.app.plugin.core.searchmem;

import java.awt.Color;
import java.awt.event.KeyEvent;
import java.util.Collections;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.*;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.fieldpanel.support.Highlight;
import docking.widgets.table.threaded.*;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.*;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.*;
import ghidra.app.util.*;
import ghidra.app.util.query.TableService;
import ghidra.app.util.viewer.field.BytesFieldFactory;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.search.memory.*;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Class to handle memory searching of code bytes in a program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search bytes in memory",
	description = "This plugin searches bytes in memory; the search " +
			"is based on a value entered as hex or decimal numbers, or strings." +
			" The value may contain \"wildcards\" or regular expressions" +
			" that will match any byte or nibble.",
	servicesRequired = { ProgramManager.class, GoToService.class, TableService.class, CodeViewerService.class },
	servicesProvided = { MemorySearchService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class MemSearchPlugin extends Plugin implements OptionsChangeListener,
		DockingContextListener, NavigatableRemovalListener, MemorySearchService {

	/** Constant for read/writeConfig() for dialog options */
	private static final String SHOW_ADVANCED_OPTIONS = "Show Advanced Options";

	final static Highlight[] NO_HIGHLIGHTS = new Highlight[0];

	private static final int MAX_PRE_POPULTATE_BYTE_COUNT = 20;

	private DockingAction searchAction;
	private DockingAction searchAgainAction;
	private MemSearchDialog searchDialog;
	private GoToService goToService;
	private int searchLimit;
	private static int DEFAULT_SEARCH_LIMIT = 500; // Default maximum number of search results.
	private ImageIcon searchIcon;

	private Color defaultHighlightColor;
	private Color activeHighlightColor;
	private boolean doHighlight;
	private int byteGroupSize;
	private String byteDelimiter;
	private boolean showAdvancedOptions;
	private boolean prepopulateSearch;
	private boolean autoRestrictSelection;

	private TableComponentProvider<MemSearchResult> currentResultsTableProvider;
	private TaskMonitor searchAllTaskMonitor;
	private TableLoadingListener currentTableListener;
	private volatile boolean waitingForSearchAll;
	private SearchInfo searchInfo;
	private Address lastMatchingAddress;

	private Navigatable navigatable;
	private boolean isMnemonic = false;

	public MemSearchPlugin(PluginTool tool) {
		super(tool);
		searchIcon = ResourceManager.loadImage("images/searchm_obj.gif");

		createActions();
		initializeOptionListeners();
		getOptions();
		tool.addContextListener(this);
	}

	@Override
	public void dispose() {
		tool.removeContextListener(this);
		ToolOptions opt = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		opt.removeOptionsChangeListener(this);

		opt = tool.getOptions(PluginConstants.SEARCH_OPTION_NAME);
		opt.removeOptionsChangeListener(this);

		if (searchAction != null) {
			searchAction.dispose();
			searchAction = null;
		}
		if (searchAgainAction != null) {
			searchAgainAction.dispose();
			searchAgainAction = null;
		}

		if (searchAllTaskMonitor != null) {
			searchAllTaskMonitor.cancel();
		}

		if (searchDialog != null) {
			searchDialog.dispose();
			searchDialog = null;
		}
		goToService = null;

		super.dispose();
	}

	int getSearchLimit() {
		return searchLimit;
	}

	boolean searchAll(SearchInfo newSearchInfo) {
		this.searchInfo = newSearchInfo;
		return performSearch(newSearchInfo);
	}

	boolean searchOnce(SearchInfo newSearchInfo) {
		this.searchInfo = newSearchInfo;
		return performSearch(searchInfo);
	}

	private boolean performSearch(SearchInfo localSearchInfo) {
		Program program = navigatable.getProgram();
		if (program == null) {
			return false;
		}
		searchAgainAction.setEnabled(true);

		if (localSearchInfo.isSearchAll()) {
			waitingForSearchAll = true;
			showIncrementalSearchResults(localSearchInfo);
		}
		else {

			Address start = getSearchStartAddress(localSearchInfo);
			ProgramSelection selection = navigatable.getSelection();
			MemorySearchAlgorithm algorithm =
				searchInfo.createSearchAlgorithm(program, start, selection);
			MemSearcherTask task = new MemSearcherTask(searchInfo, algorithm);
			searchDialog.executeProgressTask(task, 500);
		}
		return true;
	}

	void disableSearchAgain() {
		searchAgainAction.setEnabled(false);
	}

	private Address getSearchStartAddress(SearchInfo localSearchInfo) {
		ProgramLocation location = navigatable.getLocation();
		Address startAddress = location == null ? null : location.getAddress();
		if (startAddress == null) {
			Program program = navigatable.getProgram();
			if (program == null) {
				return null;
			}
			startAddress = localSearchInfo.isSearchForward() ? program.getMinAddress()
					: program.getMaxAddress();
		}

		if (lastMatchingAddress == null) {
			return startAddress;
		}

		// start the search after the last matching search
		CodeUnit cu = navigatable.getProgram().getListing().getCodeUnitContaining(startAddress);
		if (cu.contains(lastMatchingAddress)) {
			startAddress = localSearchInfo.isSearchForward() ? lastMatchingAddress.next()
					: lastMatchingAddress.previous();
		}
		return startAddress;
	}

	protected void updateNavigatable(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			NavigatableActionContext navContext = ((NavigatableActionContext) context);
			setNavigatable(navContext.getNavigatable());
			updateSelection(navContext);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {

		if (event instanceof ProgramSelectionPluginEvent) {
			ProgramSelection selection = ((ProgramSelectionPluginEvent) event).getSelection();
			boolean hasSelection = !selection.isEmpty();

			if (searchDialog != null) {
				searchDialog.setHasSelection(hasSelection, autoRestrictSelection);
			}
		}

	}

	@Override
	public void setIsMnemonic(boolean isMnemonic) {
		// provides the dialog with the knowledge of whether or not
		// the action being performed is a MnemonicSearchPlugin
		this.isMnemonic = isMnemonic;
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
		this.navigatable = newNavigatable;

		lastMatchingAddress = null;
		if (searchDialog != null) {
			searchDialog.setSearchEnabled(newNavigatable != null);
		}
	}

	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
	}

	private void invokeSearchDialog(NavigatableActionContext context) {
		if (searchDialog == null) {
			boolean isBigEndian = navigatable.getProgram().getLanguage().isBigEndian();
			searchDialog = new MemSearchDialog(this, isBigEndian, isMnemonic);
			searchDialog.setShowAdvancedOptions(showAdvancedOptions);
		}
		else {
			searchDialog.setEndianess(navigatable.getProgram().getLanguage().isBigEndian());
			searchDialog.close(); // close it to make sure it gets parented to the current focused window.
		}

		byte[] searchBytes = getInitialSearchBytes(context);
		if (searchBytes != null) {
			searchDialog.setBytes(searchBytes);
		}

		boolean hasSelection = context.hasSelection();
		searchDialog.setHasSelection(hasSelection, autoRestrictSelection);
		searchDialog.show(context.getComponentProvider());
	}

	private byte[] getInitialSearchBytes(NavigatableActionContext context) {
		if (!prepopulateSearch) {
			return null;
		}

		ProgramSelection selection = context.getSelection();
		if (selection == null || selection.isEmpty() || hasBigSelection(context)) {
			return null;
		}
		// safe cast as size has already been checked.
		int numAddresses = (int) selection.getNumAddresses();
		Address address = selection.getMinAddress();
		Memory memory = context.getProgram().getMemory();
		byte[] bytes = new byte[numAddresses];
		try {
			int count = memory.getBytes(address, bytes);
			if (count == numAddresses) {
				return bytes;
			}
		}
		catch (MemoryAccessException e) {
			// fall through and return null
		}
		return null;
	}

	private BytesFieldLocation getBytesFieldLocation(Address address) {
		if (address == null) {
			return null;
		}
		Program program = navigatable.getProgram();

		return new BytesFieldLocation(program, address);
	}

	@Override
	public void search(byte[] bytes, NavigatableActionContext context) {
		setNavigatable(context.getNavigatable());
		invokeSearchDialog(context);
	}

	@Override
	public void setSearchText(String maskedString) {
		//sets the search value to a bit string provided by the MnemonicSearchPlugin
		searchDialog.setSearchText(maskedString);
	}

	private void createActions() {
		searchAction = new NavigatableContextAction("Search Memory", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				setNavigatable(context.getNavigatable());
				invokeSearchDialog(context);
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return !(context instanceof RestrictedAddressSetContext);
			}
		};
		searchAction.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, searchAction.getName()));
		String[] menuPath = new String[] { "&Search", "&Memory..." };
		searchAction.setMenuBarData(new MenuData(menuPath, "search"));
		searchAction.setKeyBindingData(new KeyBindingData('S', 0));
		searchAction.setDescription("Search Memory for byte sequence");
		searchAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(searchAction);

		searchAgainAction = new NavigatableContextAction("Repeat Memory Search", getName()) {
			@Override
			public void actionPerformed(NavigatableActionContext context) {
				setNavigatable(context.getNavigatable());
				performSearch(searchInfo);
			}

			@Override
			protected boolean isEnabledForContext(NavigatableActionContext context) {
				return !(context instanceof RestrictedAddressSetContext) && searchInfo != null;
			}
		};
		searchAgainAction
				.setHelpLocation(new HelpLocation(HelpTopics.SEARCH, searchAgainAction.getName()));
		menuPath = new String[] { "&Search", "Repeat Memory Search" };
		searchAgainAction.setMenuBarData(new MenuData(menuPath, "search"));
		searchAgainAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F3, 0));
		searchAgainAction.setDescription("Search Memory for byte sequence");
		searchAgainAction.addToWindowWhen(NavigatableActionContext.class);
		tool.addAction(searchAgainAction);
	}

	private void initializeOptionListeners() {
		ToolOptions opt = tool.getOptions(PluginConstants.SEARCH_OPTION_NAME);
		opt.registerOption(PluginConstants.PRE_POPULATE_MEM_SEARCH, true, null,
			"Initializes memory search byte sequence from " +
				"the current selection provided the selection is less than 10 bytes.");
		opt.registerOption(PluginConstants.AUTO_RESTRICT_SELECTION, true, null,
			"Automactically adjusts memory searches restricted" +
				" to the current selection, as selections comes and goes");
		opt.registerOption(GhidraOptions.OPTION_SEARCH_LIMIT, DEFAULT_SEARCH_LIMIT, null,
			"Number of search hits found before stopping");
		opt.registerOption(PluginConstants.SEARCH_HIGHLIGHT_NAME, true, null,
			"Toggles highlight search results");

		opt.registerOption(PluginConstants.SEARCH_HIGHLIGHT_COLOR_NAME,
			PluginConstants.SEARCH_HIGHLIGHT_COLOR, null, "The search result highlight color");
		opt.registerOption(PluginConstants.SEARCH_HIGHLIGHT_CURRENT_COLOR_NAME,
			PluginConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR, null,
			"The search result highlight color for the currently selected match");

		opt.addOptionsChangeListener(this);

		opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		opt.addOptionsChangeListener(this);
	}

	private void getOptions() {

		Options opt = tool.getOptions(PluginConstants.SEARCH_OPTION_NAME);
		int newSearchLimit = opt.getInt(GhidraOptions.OPTION_SEARCH_LIMIT, DEFAULT_SEARCH_LIMIT);
		if (newSearchLimit <= 0) {
			throw new OptionsVetoException("Search limit must be greater than 0");
		}
		searchLimit = newSearchLimit;
		prepopulateSearch = opt.getBoolean(PluginConstants.PRE_POPULATE_MEM_SEARCH, true);
		autoRestrictSelection = opt.getBoolean(PluginConstants.AUTO_RESTRICT_SELECTION, true);
		doHighlight = opt.getBoolean(PluginConstants.SEARCH_HIGHLIGHT_NAME, true);
		defaultHighlightColor = opt.getColor(PluginConstants.SEARCH_HIGHLIGHT_COLOR_NAME,
			PluginConstants.SEARCH_HIGHLIGHT_COLOR);
		activeHighlightColor = opt.getColor(PluginConstants.SEARCH_HIGHLIGHT_CURRENT_COLOR_NAME,
			PluginConstants.SEARCH_HIGHLIGHT_CURRENT_ADDR_COLOR);

		opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		byteGroupSize = opt.getInt(BytesFieldFactory.BYTE_GROUP_SIZE_MSG, 1);
		byteDelimiter = opt.getString(BytesFieldFactory.DELIMITER_MSG, " ");
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		getOptions();
	}

	protected void updateSelection(NavigatableActionContext context) {
		if (searchDialog != null) {
			searchDialog.setHasSelection(context.hasSelection(), autoRestrictSelection);
		}
	}

	private boolean hasBigSelection(NavigatableActionContext context) {
		if (!context.hasSelection()) {
			return false;
		}
		ProgramSelection selection = context.getSelection();
		if (selection.getNumAddressRanges() > 1) {
			return true;
		}
		return selection.getNumAddresses() > MAX_PRE_POPULTATE_BYTE_COUNT;

	}

	private void showIncrementalSearchResults(SearchInfo info) {

		Program program = navigatable.getProgram();

		TableService query = tool.getService(TableService.class);

		searchDialog.setStatusText("Searching...");

		SearchData searchData = info.getSearchData();
		byte[] searchBytes = searchData.getBytes();
		int selectionSize = searchBytes.length == 0 ? 1 : searchBytes.length;
		MemSearchTableModel model = new MemSearchTableModel(tool, selectionSize, program, info,
			getSearchStartAddress(info), navigatable.getSelection());

		currentResultsTableProvider =
			getTableResultsProvider(info.getSearchData(), program, model, query);
		currentResultsTableProvider.installRemoveItemsAction();

		currentTableListener = new TableLoadingListener(model);
		model.addInitialLoadListener(currentTableListener);

		GThreadedTablePanel<MemSearchResult> tablePanel =
			currentResultsTableProvider.getThreadedTablePanel();
		searchAllTaskMonitor = tablePanel.getTaskMonitor();

		installHighlightProvider(model, currentResultsTableProvider);
	}

	private void searchFinished() {
		searchDialog.searchCompleted();
		currentResultsTableProvider = null;
	}

	@Override
	protected boolean canCloseDomainObject(DomainObject dObj) {
		if ((navigatable != null && navigatable.getProgram() == dObj) && isSearching()) {
			tool.setStatusInfo("Can't close program while searching...", true);
			return false;
		}
		return true;
	}

	/*testing*/ boolean isSearching() {
		if (waitingForSearchAll) {
			return true;
		}
		if (searchDialog == null) {
			return false;
		}

		return searchDialog.getTaskScheduler().isBusy();
	}

	private TableComponentProvider<MemSearchResult> getTableResultsProvider(SearchData searchData,
			Program program, GhidraProgramTableModel<MemSearchResult> model,
			TableService tableService) {

		String searchString = searchDialog.getSearchText();

		String title = "Search Memory - \"" + searchString + "\"";
		String type = "Search";
		if (navigatable.supportsMarkers()) {
			return tableService.showTableWithMarkers(title, type, model,
				PluginConstants.SEARCH_HIGHLIGHT_COLOR, searchIcon, type, navigatable);
		}
		return tableService.showTable(title, type, model, type, navigatable);
	}

	private void installHighlightProvider(MemSearchTableModel model,
			TableComponentProvider<MemSearchResult> provider) {
		Program program = navigatable.getProgram();
		new SearchTableHighlightHandler(navigatable, model, provider, program);
	}

	private void installHighlightProvider(MemSearcherTask searcher,
			TableComponentProvider<MemSearchResult> provider) {
		Program program = navigatable.getProgram();
		new TaskHighlightHandler(navigatable, searcher, provider, program);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		showAdvancedOptions = saveState.getBoolean(SHOW_ADVANCED_OPTIONS, false);
		if (searchDialog != null) {
			searchDialog.setShowAdvancedOptions(showAdvancedOptions);
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (searchDialog != null) {
			saveState.putBoolean(SHOW_ADVANCED_OPTIONS, searchDialog.getShowAdvancedOptions());
		}
	}

	@Override
	public void navigatableRemoved(Navigatable removedNavigatable) {
		setNavigatable(null);
	}

	@Override
	public void contextChanged(ActionContext context) {
		updateNavigatable(context);
	}

	TaskListener createTaskListener() {
		return new SearchOnceTaskListener();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	class TableLoadingListener implements ThreadedTableModelListener {

		private ThreadedTableModel<MemSearchResult, ?> model;

		TableLoadingListener(ThreadedTableModel<MemSearchResult, ?> model) {
			this.model = model;
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			if (isDisposed()) {
				return;
			}

			ComponentProvider provider = currentResultsTableProvider;
			waitingForSearchAll = false;
			searchFinished();
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
				// use this when showing the dialog below so that the provider does not get
				// hidden behind the tool
				JComponent resultsTable = provider.getComponent();
				Msg.showInfo(getClass(), resultsTable, "Search Limit Exceeded!",
					"Stopped search after finding " + matchCount + " matches.\n" +
						"The Search limit can be changed in the Edit->Options, under Tool Options");
			}

			// suggestion to not close search dialog.  TODO remove  next line in future versions.
			//	searchDialog.close();
			searchDialog.setStatusText("Done");
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

	private abstract class SearchResultsHighlighter
			implements HighlightProvider, ComponentProviderActivationListener {

		private TableComponentProvider<MemSearchResult> provider;
		private Program highlightProgram;
		private final Navigatable highlightNavigatable;

		SearchResultsHighlighter(Navigatable navigatable,
				TableComponentProvider<MemSearchResult> provider, Program program) {
			highlightNavigatable = navigatable;
			this.provider = provider;
			this.highlightProgram = program;

			if (provider != null) {
				provider.addActivationListener(this);
			}
			highlightNavigatable.setHighlightProvider(this, program);
		}

		abstract List<MemSearchResult> getMatches();

		private List<MemSearchResult> getAddressesFoundInRange(Address start, Address end) {
			List<MemSearchResult> data = getMatches();
			int startIndex = findFirstIndex(data, start, end);
			if (startIndex < 0) {
				return Collections.emptyList();
			}

			int endIndex = findIndexAtOrGreater(data, end);
			if (endIndex < data.size() && ((data.get(endIndex)).addressEquals(end))) {
				endIndex++; // exact match on end, so include it
			}

			List<MemSearchResult> resultList = data.subList(startIndex, endIndex);
			return resultList;
		}

		private int findFirstIndex(List<MemSearchResult> list, Address start, Address end) {

			List<MemSearchResult> data = getMatches();

			int startIndex = findIndexAtOrGreater(data, start);
			if (startIndex > 0) { // see if address before extends into this range.
				MemSearchResult resultBefore = data.get(startIndex - 1);
				Address beforeAddr = resultBefore.getAddress();
				int length = resultBefore.getLength();
				if (start.hasSameAddressSpace(beforeAddr) && start.subtract(beforeAddr) < length) {
					return startIndex - 1;
				}
			}

			if (startIndex == data.size()) {
				return -1;
			}

			MemSearchResult result = data.get(startIndex);
			Address addr = result.getAddress();
			if (end.compareTo(addr) >= 0) {
				return startIndex;
			}
			return -1;
		}

		private int findIndexAtOrGreater(List<MemSearchResult> list, Address address) {

			MemSearchResult key = new MemSearchResult(address, 1);
			int index = Collections.binarySearch(list, key);
			if (index < 0) {
				index = -index - 1;
			}
			return index;
		}

		@Override
		public Highlight[] getHighlights(String text, Object obj,
				Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {
			Program program = navigatable != null ? navigatable.getProgram() : null;
			if (fieldFactoryClass != BytesFieldFactory.class) {
				return NO_HIGHLIGHTS;
			}
			if (checkRemoveHighlights()) {
				return NO_HIGHLIGHTS;
			}
			if (!(obj instanceof CodeUnit)) {
				return NO_HIGHLIGHTS;
			}
			if (!doHighlight) {
				return NO_HIGHLIGHTS;
			}

			if (highlightProgram != program) {
				return NO_HIGHLIGHTS;
			}

			CodeUnit cu = (CodeUnit) obj;
			Address minAddr = cu.getMinAddress();
			Address maxAddr = cu.getMaxAddress();
			List<MemSearchResult> results = getAddressesFoundInRange(minAddr, maxAddr);

			Highlight[] highlights = new Highlight[results.size()];
			for (int i = 0; i < highlights.length; i++) {
				MemSearchResult result = results.get(i);
				int highlightLength = result.getLength();
				Address addr = result.getAddress();
				Color highlightColor = getHighlightColor(addr, highlightLength);
				int startByteOffset = (int) addr.subtract(minAddr);
				int endByteOffset = startByteOffset + highlightLength - 1;
				startByteOffset = Math.max(startByteOffset, 0);
				highlights[i] = getHighlight(text, startByteOffset, endByteOffset, highlightColor);
			}

			return highlights;
		}

		private Highlight getHighlight(String text, int start, int end, Color color) {
			int charStart = getCharPosition(text, start);
			int charEnd = getCharPosition(text, end) + 1;
			return new Highlight(charStart, charEnd, color);

		}

		private int getCharPosition(String text, int byteOffset) {
			int groupSize = byteGroupSize * 2 + byteDelimiter.length();
			int groupIndex = byteOffset / byteGroupSize;
			int groupOffset = byteOffset % byteGroupSize;

			int pos = groupIndex * groupSize + 2 * groupOffset;
			return Math.min(text.length() - 1, pos);
		}

		private Color getHighlightColor(Address highlightStart, int highlightLength) {
			ProgramLocation location = navigatable != null ? navigatable.getLocation() : null;
			if (!(location instanceof BytesFieldLocation)) {
				return defaultHighlightColor;
			}

			BytesFieldLocation byteLoc = (BytesFieldLocation) location;
			Address byteAddress = byteLoc.getAddressForByte();
			if (highlightStart.hasSameAddressSpace(byteAddress)) {
				long diff = byteAddress.subtract(highlightStart);
				if (diff >= 0 && diff < highlightLength) {
					return activeHighlightColor; // the current location is in the highlight
				}
			}

			return defaultHighlightColor;
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

	private class SearchTableHighlightHandler extends SearchResultsHighlighter {
		private final MemSearchTableModel model;

		SearchTableHighlightHandler(Navigatable navigatable, MemSearchTableModel model,
				TableComponentProvider<MemSearchResult> provider, Program program) {
			super(navigatable, provider, program);
			this.model = model;
		}

		@Override
		List<MemSearchResult> getMatches() {
			return model.getModelData();
		}
	}

	private class TaskHighlightHandler extends SearchResultsHighlighter {
		private final MemSearcherTask searchTask;

		TaskHighlightHandler(Navigatable navigatable, MemSearcherTask searcher,
				TableComponentProvider<MemSearchResult> provider, Program program) {
			super(navigatable, provider, program);
			this.searchTask = searcher;
		}

		@Override
		List<MemSearchResult> getMatches() {
			return searchTask.getMatchingAddresses();
		}
	}

	private class SearchOnceTaskListener implements TaskListener {
		@Override
		public void taskCompleted(Task task) {
			if (isDisposed()) {
				return;
			}

			MemSearcherTask searcher = (MemSearcherTask) task;
			List<MemSearchResult> results = searcher.getMatchingAddresses();
			if (results.isEmpty()) {
				searchDialog.setStatusText("Not Found");
				return;
			}

			searchDialog.setStatusText("Found");
			MemSearchResult result = results.get(0);
			Address addr = result.getAddress();
			goToService.goTo(navigatable, getBytesFieldLocation(addr), navigatable.getProgram());
			lastMatchingAddress = addr;
			installHighlightProvider(searcher, null);
		}

		@Override
		public void taskCancelled(Task task) {
			// do nothing
		}
	}

}
