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

import java.awt.*;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

import javax.swing.*;

import docking.ActionContext;
import docking.DockingContextListener;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import docking.util.GGlassPaneMessage;
import generic.theme.GIcon;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.nav.Navigatable;
import ghidra.app.nav.NavigatableRemovalListener;
import ghidra.app.util.HelpTopics;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.scan.Scanner;
import ghidra.features.base.memsearch.searcher.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.DeleteTableRowAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import resources.Icons;

/**
 * ComponentProvider used to search memory and display search results.
 */
public class MemorySearchProvider extends ComponentProviderAdapter
		implements DockingContextListener, NavigatableRemovalListener, DomainObjectClosedListener {

	// @formatter:off
	private static final Icon SHOW_SEARCH_PANEL_ICON = new GIcon("icon.base.mem.search.panel.search");
	private static final Icon SHOW_SCAN_PANEL_ICON = new GIcon("icon.base.mem.search.panel.scan");
	private static final Icon SHOW_OPTIONS_ICON = new GIcon("icon.base.mem.search.panel.options");
	// @formatter:on

	private static Set<Integer> USED_IDS = new HashSet<>();

	private final int id = getId();

	private Navigatable navigatable;
	private Program program;
	private AddressableByteSource byteSource;

	private JComponent mainComponent;
	private JPanel controlPanel;
	private MemorySearchControlPanel searchPanel;
	private MemoryScanControlPanel scanPanel;
	private MemorySearchOptionsPanel optionsPanel;
	private MemorySearchResultsPanel resultsPanel;

	private ToggleDockingAction toggleOptionsPanelAction;
	private ToggleDockingAction toggleScanPanelAction;
	private ToggleDockingAction toggleSearchPanelAction;
	private DockingAction previousAction;
	private DockingAction nextAction;
	private DockingAction refreshAction;

	private ByteMatcher byteMatcher;
	private Address lastMatchingAddress;

	private boolean isBusy;
	private MemoryMatchHighlighter matchHighlighter;
	private MemorySearchPlugin plugin;
	private MemorySearchOptions options;
	private SearchGuiModel model;
	private boolean isPrivate = false;

	// used to show a temporary message over the table
	private GGlassPaneMessage glassPaneMessage;

	public MemorySearchProvider(MemorySearchPlugin plugin, Navigatable navigatable,
			SearchSettings settings, MemorySearchOptions options, SearchHistory history) {
		super(plugin.getTool(), "Memory Search", plugin.getName());
		this.plugin = plugin;
		this.navigatable = navigatable;
		this.options = options;
		this.program = navigatable.getProgram();
		this.byteSource = navigatable.getByteSource();

		// always initially use the byte ordering of the program, regardless of previous searches
		if (settings == null) {
			settings = new SearchSettings();
		}
		settings = settings.withBigEndian(program.getMemory().isBigEndian());

		this.model = new SearchGuiModel(settings, byteSource.getSearchableRegions());
		model.setHasSelection(hasSelection(navigatable.getSelection()));
		model.setAutoRestrictSelection(options.isAutoRestrictSelection());
		setHelpLocation(new HelpLocation(HelpTopics.SEARCH, "Memory_Search"));

		SearchMarkers markers = new SearchMarkers(tool, getTitle(), program);
		searchPanel = new MemorySearchControlPanel(this, model, history);
		scanPanel = new MemoryScanControlPanel(this);
		optionsPanel = new MemorySearchOptionsPanel(model);
		resultsPanel = new MemorySearchResultsPanel(this, markers);
		mainComponent = buildMainComponent();
		matchHighlighter =
			new MemoryMatchHighlighter(navigatable, resultsPanel.getTableModel(), options);

		setTransient();
		addToTool();
		setVisible(true);

		createActions(plugin.getName());
		setDefaultFocusComponent(searchPanel.getDefaultFocusComponent());

		tool.addContextListener(this);
		navigatable.addNavigatableListener(this);
		program.addCloseListener(this);
		updateTitle();

	}

	public void setSearchInput(String input) {
		searchPanel.setSearchInput(input);
	}

	public String getSearchInput() {
		return byteMatcher == null ? "" : byteMatcher.getInput();
	}

	public void setSearchSelectionOnly(boolean b) {
		model.setSearchSelectionOnly(b);
	}

	void setPrivate() {
		this.isPrivate = true;
	}

	private void updateTitle() {
		StringBuilder builder = new StringBuilder();
		String searchInput = getSearchInput();
		builder.append("Search Memory: ");
		if (!searchInput.isBlank()) {
			builder.append("\"");
			builder.append(searchInput);
			builder.append("\"");
		}
		builder.append("  (");
		builder.append(getProgramName());
		builder.append(")");
		setTitle(builder.toString());
	}

	@Override
	public JComponent getComponent() {
		return mainComponent;
	}

	void setByteMatcher(ByteMatcher byteMatcher) {
		this.byteMatcher = byteMatcher;
		tool.contextChanged(this);
	}

	/*
	 * This method will disable "search" actions immediately upon initiating any search or
	 * scan action. Normally, these actions would enable and disable via context as usual, but
	 * context changes are issued in a delayed fashion.
	 */
	void disableActionsFast() {
		nextAction.setEnabled(false);
		previousAction.setEnabled(false);
		refreshAction.setEnabled(false);
	}

	boolean canProcessResults() {
		return !isBusy && resultsPanel.hasResults();
	}

	private void searchOnce(boolean forward) {
		if (hasInvalidSearchSettings()) {
			return;
		}
		updateTitle();

		Address start = getSearchStartAddress(forward);
		AddressSet addresses = getSearchAddresses();
		MemorySearcher searcher = new MemorySearcher(byteSource, byteMatcher, addresses, 1);
		searcher.setMatchFilter(createFilter());

		setBusy(true);
		resultsPanel.searchOnce(searcher, start, forward);

		// Only update future memory search settings if this is a standard memory search provider
		// because we don't want potentially highly specialized inputs and settings to be in
		// the history for standard memory search operations.
		if (!isPrivate) {
			plugin.updateByteMatcher(byteMatcher);
		}
	}

	// public so can be called by tests
	public void search() {
		if (hasInvalidSearchSettings()) {
			return;
		}
		updateTitle();
		int limit = options.getSearchLimit();
		AddressSet addresses = getSearchAddresses();
		MemorySearcher searcher = new MemorySearcher(byteSource, byteMatcher, addresses, limit);
		searcher.setMatchFilter(createFilter());

		setBusy(true);
		searchPanel.setSearchStatus(resultsPanel.hasResults(), true);
		resultsPanel.search(searcher, model.getMatchCombiner());

		// Only update future memory search settings if this is a standard memory search provider
		// because we don't want potentially highly specialized inputs and settings to be in
		// the history for standard memory search operations.
		if (!isPrivate) {
			plugin.updateByteMatcher(byteMatcher);
		}
	}

	private boolean hasInvalidSearchSettings() {
		Set<SearchRegion> selectedMemoryRegions = model.getSelectedMemoryRegions();
		if (selectedMemoryRegions.isEmpty()) {
			Msg.showInfo(getClass(), resultsPanel, "No Memory Regions Selected!",
				"You must select one or more memory regions to perform a search!");
			return true;
		}

		if (!(model.includeInstructions() ||
			model.includeDefinedData() ||
			model.includeUndefinedData())) {

			Msg.showInfo(getClass(), resultsPanel, "No Code Types Selected!",
				"You must select at least one of \"Instructions\"," +
					" \"Defined Data\" or \"Undefined Data\" to perform a search!");
			return true;

		}

		return false;
	}

	/**
	 * Performs a scan on the current results, keeping only the results that match the type of scan.
	 * Note: this method is public to facilitate testing.
	 * 
	 * @param scanner the scanner to use to reduce the results.
	 */
	public void scan(Scanner scanner) {
		setBusy(true);
		resultsPanel.refreshAndMaybeScanForChanges(byteSource, scanner);
	}

	private AddressSet getSearchAddresses() {
		AddressSet set = model.getSettings().getSearchAddresses(program);

		if (model.isSearchSelectionOnly()) {
			set = set.intersect(navigatable.getSelection());
		}
		return set;

	}

	private void refreshResults() {
		setBusy(true);
		resultsPanel.refreshAndMaybeScanForChanges(byteSource, null);
	}

	private void setBusy(boolean isBusy) {
		this.isBusy = isBusy;
		boolean hasResults = resultsPanel.hasResults();
		searchPanel.setSearchStatus(hasResults, isBusy);
		scanPanel.setSearchStatus(hasResults, isBusy);
		if (isBusy) {
			disableActionsFast();
		}
		tool.contextChanged(this);
	}

	private Predicate<MemoryMatch> createFilter() {
		AlignmentFilter alignmentFilter = new AlignmentFilter(model.getAlignment());
		CodeUnitFilter codeUnitFilter =
			new CodeUnitFilter(program, model.includeInstructions(),
				model.includeDefinedData(), model.includeUndefinedData());
		return alignmentFilter.and(codeUnitFilter);
	}

	private Address getSearchStartAddress(boolean forward) {
		ProgramLocation location = navigatable.getLocation();
		Address startAddress = location == null ? null : location.getByteAddress();
		if (startAddress == null) {
			startAddress = forward ? program.getMinAddress() : program.getMaxAddress();
		}

		/*
			Finding the correct starting address is tricky. Ideally, we would just use the
		 	current cursor location's address and begin searching. However, this doesn't work
		 	for subsequent searches for two reasons. 
		 
		 	The first reason is simply that subsequent searches need to start one address past the
		 	current address or else you will just find the same location again.
		 
		 	The second reason is caused by the way the listing handles arrays. Since arrays don't
		 	have a bytes field, a previous search may have found a hit inside an array, but because
		 	there is no place in the listing to represent that, the cursor is actually placed at
		 	address that is before (possibly several addresses before) the actual hit. So going
		 	forward in the next search, even after incrementing the address, will result in finding
		 	that same hit.
		  
		 	To solve this, the provider keeps track of a last match address. Subsequent searches
		 	will use this address as long as that address and the cursor address are in the same
		 	code unit. If they are not in the same code unit, we assume the user manually moved the
			cursor and want to start searching from that new location.
		*/

		if (lastMatchingAddress == null) {
			return startAddress;
		}
		CodeUnit cu = program.getListing().getCodeUnitContaining(startAddress);
		if (cu.contains(lastMatchingAddress)) {
			startAddress = forward ? lastMatchingAddress.next() : lastMatchingAddress.previous();
		}
		if (startAddress == null) {
			startAddress = program.getMinAddress();
		}
		return startAddress;
	}

	void searchAllCompleted(boolean foundResults, boolean cancelled, boolean terminatedEarly) {
		setBusy(false);
		updateSubTitle();
		if (!cancelled && terminatedEarly) {
			showAlert("Search Limit Exceeded!\n\nStopped search after finding " +
				options.getSearchLimit() + " matches.\n" +
				"The search limit can be changed at Edit \u2192 Tool Options, under Search.");

		}
		else if (!foundResults) {
			showAlert("No matches found!");
		}
	}

	void searchOnceCompleted(MemoryMatch match, boolean cancelled) {
		setBusy(false);
		updateSubTitle();
		if (match != null) {
			lastMatchingAddress = match.getAddress();
			navigatable.goTo(program, new BytesFieldLocation(program, match.getAddress()));
		}
		else {
			showAlert("No Match Found!");
		}
	}

	void refreshAndScanCompleted(MemoryMatch match) {
		setBusy(false);
		updateSubTitle();
		if (match != null) {
			lastMatchingAddress = match.getAddress();
			navigatable.goTo(program, new BytesFieldLocation(program, match.getAddress()));
		}
	}

	@Override
	public void componentActivated() {
		resultsPanel.providerActivated();
		navigatable.setHighlightProvider(matchHighlighter, program);
	}

	private void updateSubTitle() {
		StringBuilder builder = new StringBuilder();
		builder.append(" ");
		int matchCount = resultsPanel.getMatchCount();
		if (matchCount > 0) {
			builder.append("(");
			builder.append(matchCount);
			builder.append(matchCount == 1 ? " entry)" : " entries)");
		}
		setSubTitle(builder.toString());
	}

	private String getProgramName() {
		return program.getDomainFile().getName();
	}

	private void updateControlPanel() {
		controlPanel.removeAll();
		boolean showSearchPanel = toggleSearchPanelAction.isSelected();
		boolean showScanPanel = toggleScanPanelAction.isSelected();

		if (showSearchPanel) {
			controlPanel.add(searchPanel);
		}
		if (showSearchPanel && showScanPanel) {
			controlPanel.add(new JSeparator());
		}
		if (showScanPanel) {
			controlPanel.add(scanPanel);
		}
		controlPanel.revalidate();
	}

	private void toggleShowScanPanel() {
		plugin.setShowScanPanel(toggleScanPanelAction.isSelected());
		updateControlPanel();
	}

	private void toggleShowSearchPanel() {
		updateControlPanel();
	}

	private void toggleShowOptions() {
		plugin.setShowOptionsPanel(toggleOptionsPanelAction.isSelected());
		if (toggleOptionsPanelAction.isSelected()) {
			mainComponent.add(optionsPanel, BorderLayout.EAST);
		}
		else {
			mainComponent.remove(optionsPanel);
		}
		mainComponent.validate();
	}

	private boolean canSearch() {
		return !isBusy && byteMatcher != null && byteMatcher.isValidSearch();
	}

	private JComponent buildMainComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setPreferredSize(new Dimension(900, 650));
		panel.add(buildCenterPanel(), BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildCenterPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.NORTH);
		panel.add(resultsPanel, BorderLayout.CENTER);
		return panel;
	}

	private JComponent buildControlPanel() {
		controlPanel = new JPanel(new VerticalLayout(0));
		controlPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		controlPanel.add(searchPanel);
		return controlPanel;
	}

	private void createActions(String owner) {

		nextAction = new ActionBuilder("Search Next", owner)
				.toolBarIcon(Icons.DOWN_ICON)
				.toolBarGroup("A")
				.description("Search forward for 1 result")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_Next"))
				.enabledWhen(c -> canSearch())
				.onAction(c -> searchOnce(true))
				.buildAndInstallLocal(this);
		previousAction = new ActionBuilder("Search Previous", owner)
				.toolBarIcon(Icons.UP_ICON)
				.toolBarGroup("A")
				.description("Search backward for 1 result")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Search_Previous"))
				.enabledWhen(c -> canSearch())
				.onAction(c -> searchOnce(false))
				.buildAndInstallLocal(this);

		refreshAction = new ActionBuilder("Refresh Results", owner)
				.toolBarIcon(Icons.REFRESH_ICON)
				.toolBarGroup("A")
				.description(
					"Reload bytes from memory for each search result and show changes in red")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Refresh_Values"))
				.enabledWhen(c -> canProcessResults())
				.onAction(c -> refreshResults())
				.buildAndInstallLocal(this);

		toggleSearchPanelAction = new ToggleActionBuilder("Show Memory Search Controls", owner)
				.toolBarIcon(SHOW_SEARCH_PANEL_ICON)
				.toolBarGroup("Z")
				.description("Toggles showing the search controls")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Toggle_Search"))
				.selected(true)
				.onAction(c -> toggleShowSearchPanel())
				.buildAndInstallLocal(this);

		toggleScanPanelAction = new ToggleActionBuilder("Show Memory Scan Controls", owner)
				.toolBarIcon(SHOW_SCAN_PANEL_ICON)
				.toolBarGroup("Z")
				.description("Toggles showing the scan controls")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Toggle_Scan"))
				.onAction(c -> toggleShowScanPanel())
				.buildAndInstallLocal(this);

		toggleOptionsPanelAction = new ToggleActionBuilder("Show Options", owner)
				.toolBarIcon(SHOW_OPTIONS_ICON)
				.toolBarGroup("Z")
				.description("Toggles showing the search options panel")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Toggle_Options"))
				.onAction(c -> toggleShowOptions())
				.buildAndInstallLocal(this);

		// add standard table actions
		GhidraTable table = resultsPanel.getTable();
		addLocalAction(new MakeProgramSelectionAction(navigatable, owner, table));
		addLocalAction(new SelectionNavigationAction(owner, table));
		addLocalAction(new DeleteTableRowAction(table, owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				super.actionPerformed(context);
				updateSubTitle();
			}
		});

	}

	@Override
	public void removeFromTool() {
		dispose();
		super.removeFromTool();
	}

	private void dispose() {
		if (glassPaneMessage != null) {
			glassPaneMessage.hide();
			glassPaneMessage = null;
		}

		matchHighlighter.dispose();

		USED_IDS.remove(id);

		if (navigatable != null) {
			navigatable.removeNavigatableListener(this);
		}

		resultsPanel.dispose();
		tool.removeContextListener(this);
		program.removeCloseListener(this);
	}

	@Override
	public void contextChanged(ActionContext context) {
		model.setHasSelection(hasSelection(navigatable.getSelection()));
	}

	private boolean hasSelection(ProgramSelection selection) {
		if (selection == null) {
			return false;
		}
		return !selection.isEmpty();
	}

	@Override
	public void navigatableRemoved(Navigatable nav) {
		closeComponent();
	}

	@Override
	public void domainObjectClosed(DomainObject dobj) {
		closeComponent();
	}

	Navigatable getNavigatable() {
		return navigatable;
	}

	private static int getId() {
		for (int i = 0; i < Integer.MAX_VALUE; i++) {
			if (!USED_IDS.contains(i)) {
				USED_IDS.add(i);
				return i;
			}
		}
		return 0;
	}

	void tableSelectionChanged() {
		MemoryMatch selectedMatch = resultsPanel.getSelectedMatch();
		matchHighlighter.setSelectedMatch(selectedMatch);
		if (selectedMatch != null) {
			lastMatchingAddress = selectedMatch.getAddress();
		}
		tool.contextChanged(this);
	}

	public void showOptions(boolean b) {
		toggleOptionsPanelAction.setSelected(b);
		toggleShowOptions();
	}

	public void showScanPanel(boolean b) {
		toggleScanPanelAction.setSelected(b);
		updateControlPanel();
	}

	public void showSearchPanel(boolean b) {
		toggleSearchPanelAction.setSelected(b);
		updateControlPanel();
	}

	// testing
	public boolean isBusy() {
		return isBusy;
	}

	public List<MemoryMatch> getSearchResults() {
		return resultsPanel.getTableModel().getModelData();
	}

	public void setSettings(SearchSettings settings) {
		String converted = searchPanel.convertInput(model.getSettings(), settings);
		model.setSettings(settings);
		searchPanel.setSearchInput(converted);
	}

	public boolean isSearchSelection() {
		return model.isSearchSelectionOnly();
	}

	public String getByteString() {
		return byteMatcher.getDescription();
	}

	@Override
	protected ActionContext createContext(Component sourceComponent, Object contextObject) {
		ActionContext context = new NavigatableActionContext(this, navigatable);
		context.setContextObject(contextObject);
		context.setSourceComponent(sourceComponent);
		return context;
	}

	private void showAlert(String message) {
		Toolkit.getDefaultToolkit().beep();

		if (glassPaneMessage == null) {
			GhidraTable table = resultsPanel.getTable();
			glassPaneMessage = new GGlassPaneMessage(table);
			glassPaneMessage.setHideDelay(Duration.ofSeconds(3));
		}

		glassPaneMessage.showCenteredMessage(message);
	}

}
