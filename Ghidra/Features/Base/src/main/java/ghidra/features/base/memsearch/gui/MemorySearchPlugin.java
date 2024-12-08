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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import docking.action.builder.ActionBuilder;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.*;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.query.TableService;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Plugin for searching program memory. 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SEARCH,
	shortDescription = "Search bytes in memory",
	description = "This plugin searches bytes in memory. The search " +
			"is based on a value entered as hex or decimal numbers, or strings." +
			" The value may contain \"wildcards\" or regular expressions" +
			" that will match any byte or nibble.",
	servicesRequired = { ProgramManager.class, GoToService.class, TableService.class, CodeViewerService.class },
	servicesProvided = { MemorySearchService.class },
	eventsConsumed = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class MemorySearchPlugin extends Plugin implements MemorySearchService {
	private static final int MAX_HISTORY = 10;
	private static final String SHOW_OPTIONS_PANEL = "Show Options Panel";
	private static final String SHOW_SCAN_PANEL = "Show Scan Panel";

	private ByteMatcher lastByteMatcher;
	private MemorySearchOptions options;
	private SearchHistory searchHistory = new SearchHistory(MAX_HISTORY);
	private Address lastSearchAddress;

	private boolean showScanPanel;

	private boolean showOptionsPanel;

	public MemorySearchPlugin(PluginTool tool) {
		super(tool);
		createActions();
		options = new MemorySearchOptions(tool);
	}

	private void createActions() {
		new ActionBuilder("Memory Search", getName())
				.menuPath("&Search", "&Memory...")
				.menuGroup("search", "a")
				.keyBinding("s")
				.description("Search Memory for byte sequence")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Memory Search"))
				.withContext(NavigatableActionContext.class, true)
				.onAction(this::showSearchMemoryProvider)
				.buildAndInstall(tool);

		new ActionBuilder("Repeat Memory Search Forwards", getName())
				.menuPath("&Search", "Repeat Search &Forwards")
				.menuGroup("search", "b")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0))
				.description("Repeat last memory search fowards once")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Repeat Search Forwards"))
				.withContext(NavigatableActionContext.class, true)
				.enabledWhen(c -> lastByteMatcher != null && c.getAddress() != null)
				.onAction(c -> searchOnce(c, true))
				.buildAndInstall(tool);

		new ActionBuilder("Repeat Memory Search Backwards", getName())
				.menuPath("&Search", "Repeat Search &Backwards")
				.menuGroup("search", "c")
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_F3, InputEvent.SHIFT_DOWN_MASK))
				.description("Repeat last memory search backwards once")
				.helpLocation(new HelpLocation(HelpTopics.SEARCH, "Repeat Search Backwards"))
				.withContext(NavigatableActionContext.class, true)
				.enabledWhen(c -> lastByteMatcher != null && c.getAddress() != null)
				.onAction(c -> searchOnce(c, false))
				.buildAndInstall(tool);

	}

	private void showSearchMemoryProvider(NavigatableActionContext c) {
		SearchSettings settings = lastByteMatcher != null ? lastByteMatcher.getSettings() : null;
		SearchHistory copy = new SearchHistory(searchHistory);
		MemorySearchProvider provider =
			new MemorySearchProvider(this, c.getNavigatable(), settings, options, copy);

		provider.showOptions(showOptionsPanel);
		provider.showScanPanel(showScanPanel);
	}

	private void searchOnce(NavigatableActionContext c, boolean forward) {
		SearchOnceTask task = new SearchOnceTask(c.getNavigatable(), forward);
		TaskLauncher.launch(task);
	}

	void updateByteMatcher(ByteMatcher matcher) {
		lastByteMatcher = matcher;
		searchHistory.addSearch(matcher);
	}

	@Override
	public void readConfigState(SaveState saveState) {
		showOptionsPanel = saveState.getBoolean(SHOW_OPTIONS_PANEL, false);
		showScanPanel = saveState.getBoolean(SHOW_SCAN_PANEL, false);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putBoolean(SHOW_OPTIONS_PANEL, showOptionsPanel);
		saveState.putBoolean(SHOW_SCAN_PANEL, showOptionsPanel);
	}
//==================================================================================================
// MemorySearchService methods
//==================================================================================================

	@Override
	public void createMemorySearchProvider(Navigatable navigatable, String input,
			SearchSettings settings, boolean useSelection) {

		SearchHistory copy = new SearchHistory(searchHistory);
		MemorySearchProvider provider =
			new MemorySearchProvider(this, navigatable, settings, options, copy);
		provider.setSearchInput(input);
		provider.setSearchSelectionOnly(false);

		// Custom providers may use input and settings that are fairly unique and not chosen
		// by the user directly. We therefore don't want those settings to be reported back for
		// adding to the default settings state and history and thereby affecting future normal
		// memory searches.
		provider.setPrivate();
	}

	private class SearchOnceTask extends Task {

		private Navigatable navigatable;
		private boolean forward;

		public SearchOnceTask(Navigatable navigatable, boolean forward) {
			super("Search Next", true, true, true);
			this.navigatable = navigatable;
			this.forward = forward;
		}

		private AddressSet getSearchAddresses() {
			SearchSettings settings = lastByteMatcher.getSettings();
			AddressSet searchAddresses = settings.getSearchAddresses(navigatable.getProgram());
			ProgramSelection selection = navigatable.getSelection();
			if (selection != null && !selection.isEmpty()) {
				searchAddresses = searchAddresses.intersect(navigatable.getSelection());
			}
			return searchAddresses;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			AddressableByteSource source = navigatable.getByteSource();
			AddressSet addresses = getSearchAddresses();
			if (addresses.isEmpty()) {
				Msg.showWarn(this, null, "Search Failed!", "Addresses to search is empty!");
				return;
			}

			Address start = getSearchStartAddress();
			if (start == null) {
				Msg.showWarn(this, null, "Search Failed!", "No valid start address!");
				return;
			}
			MemorySearcher searcher = new MemorySearcher(source, lastByteMatcher, addresses, 1);

			MemoryMatch match = searcher.findOnce(start, forward, monitor);

			Swing.runLater(() -> navigateToMatch(match));
		}

		private Address getSearchStartAddress() {
			ProgramLocation location = navigatable.getLocation();
			if (location == null) {
				return null;
			}
			Address start = navigatable.getLocation().getByteAddress();
			if (lastSearchAddress != null) {
				CodeUnit cu = navigatable.getProgram().getListing().getCodeUnitContaining(start);
				if (cu != null && cu.contains(lastSearchAddress)) {
					start = lastSearchAddress;
				}
			}
			return forward ? start.next() : start.previous();
		}

		private void navigateToMatch(MemoryMatch match) {
			if (match != null) {
				lastSearchAddress = match.getAddress();
				Program program = navigatable.getProgram();
				navigatable.goTo(program, new BytesFieldLocation(program, match.getAddress()));
			}
			else {
				Msg.showWarn(this, null, "Match Not Found",
					"No match found going forward for " + lastByteMatcher.getInput());
			}
		}
	}

	public void setShowOptionsPanel(boolean show) {
		showOptionsPanel = show;

	}

	public void setShowScanPanel(boolean show) {
		showScanPanel = show;
	}

}
