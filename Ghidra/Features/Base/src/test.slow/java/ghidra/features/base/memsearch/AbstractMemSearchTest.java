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
package ghidra.features.base.memsearch;

import static org.junit.Assert.*;

import java.nio.charset.Charset;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.collections4.IteratorUtils;

import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.*;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.BytesFieldFactory;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.features.base.memsearch.bytesource.SearchRegion;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.gui.*;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.Swing;

/**
 * Base class for memory search tests.  
 */
public abstract class AbstractMemSearchTest extends AbstractProgramBasedTest {

	protected MemorySearchPlugin memorySearchPlugin;
	protected DockingActionIf searchAction;
	protected CodeViewerProvider provider;
	protected Memory memory;
	protected Listing listing;
	protected MarkerService markerService;

	protected MemorySearchProvider searchProvider;
	private SearchSettings settings = new SearchSettings();

	/*
	 * Note that this setup function does not have the @Before annotation - this is because 
	 * sub-classes often need to override this and if we have the annotation here, the test
	 * runner will only invoke this base class implementation.
	 */
	public void setUp() throws Exception {

		// this builds the program and launches the tool
		initialize();

		memorySearchPlugin = env.getPlugin(MemorySearchPlugin.class);

		listing = program.getListing();
		memory = program.getMemory();

		searchAction = getAction(memorySearchPlugin, "Memory Search");

		provider = codeBrowser.getProvider();
		markerService = tool.getService(MarkerService.class);

		showMemorySearchProvider();
	}

	protected void setInput(String input) {
		Swing.runNow(() -> searchProvider.setSearchInput(input));
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	protected abstract Program buildProgram() throws Exception;

	protected void waitForSearch(int expectedResults) {

		waitForCondition(() -> {
			return runSwing(() -> !searchProvider.isBusy());
		}, "Timed-out waiting for search results");
		assertEquals(expectedResults, searchProvider.getSearchResults().size());
	}

	protected void waitForSearchTask() {
		waitForSwing();
		waitForTasks();
		waitForSwing();
	}

	protected void showMemorySearchProvider() {
		performAction(searchAction, provider, true);
		searchProvider = waitForComponentProvider(MemorySearchProvider.class);
	}

	@SuppressWarnings("unchecked")
	private List<Address> getHighlightAddresses() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		Object codeViewerProvider = getInstanceField("connectedProvider", service);
		Map<Program, ListingHighlightProvider> highlighterMap =
			(Map<Program, ListingHighlightProvider>) getInstanceField("programHighlighterMap",
				codeViewerProvider);
		ListingHighlightProvider highlightProvider = highlighterMap.get(program);

		assertEquals("The inner-class has been renamed", "MemoryMatchHighlighter",
			highlightProvider.getClass().getSimpleName());

		List<MemoryMatch> data = searchProvider.getSearchResults();
		return data.stream().map(result -> result.getAddress()).collect(Collectors.toList());
	}

	protected void checkMarkerSet(List<Address> expected) {
		List<Address> highlights = getHighlightAddresses();
		assertListEqualUnordered("Search highlights not correctly generated", expected, highlights);

		MarkerSet markers =
			runSwing(() -> markerService.getMarkerSet(searchProvider.getTitle(), program));
		assertNotNull(markers);

		AddressSet addressSet = runSwing(() -> markers.getAddressSet());
		AddressIterator it = addressSet.getAddresses(true);
		List<Address> list = IteratorUtils.toList(it);

		assertListEqualUnordered("Search markers not correctly generated", expected, list);
	}

	protected void performSearchNext(Address expected) throws Exception {
		DockingActionIf action = getAction(tool, "MemorySearchPlugin", "Search Next");
		performAction(action);
		waitForSearchTask();
		codeBrowser.updateNow();
		assertEquals(expected, codeBrowser.getCurrentAddress());
	}

	protected void performSearchNext(List<Address> expected) throws Exception {
		DockingActionIf action = getAction(tool, "MemorySearchPlugin", "Search Next");
		performSearchNextPrevious(expected, action);
	}

	protected void performSearchPrevious(List<Address> expected) throws Exception {
		DockingActionIf action = getAction(tool, "MemorySearchPlugin", "Search Previous");
		performSearchNextPrevious(expected, action);
	}

	protected void performSearchNextPrevious(List<Address> expected, DockingActionIf action)
			throws Exception {

		for (Address addr : expected) {
			performAction(action);
			waitForSearchTask();
			codeBrowser.updateNow();
			assertEquals(addr, codeBrowser.getCurrentAddress());
		}

		Address addr = codeBrowser.getCurrentAddress();
		performAction(action);
		waitForSearchTask();
		codeBrowser.updateNow();
		assertEquals(addr, codeBrowser.getCurrentAddress());
	}

	protected void performSearchAll() {
		runSwing(() -> searchProvider.search());
	}

	protected ListingHighlightProvider getHighlightProvider() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		FormatManager fm = (FormatManager) getInstanceField("formatMgr", service);
		return (ListingHighlightProvider) getInstanceField("highlightProvider", fm);
	}

	protected void repeatSearchForward() {
		DockingActionIf action = getAction(memorySearchPlugin, "Repeat Memory Search Forwards");
		assertTrue(action.isEnabled());
		performAction(action, provider, true);
		waitForSearchTask();
	}

	protected void repeatSearchBackward() {
		DockingActionIf action = getAction(memorySearchPlugin, "Repeat Memory Search Backwards");
		assertTrue(action.isEnabled());
		performAction(action, provider, true);
		waitForSearchTask();
	}

	protected Address currentAddress() {
		codeBrowser.updateNow();
		Address addr = codeBrowser.getCurrentLocation().getAddress();
		return addr;
	}

	protected CodeUnit currentCodeUnit() {
		CodeUnit cu = program.getListing().getCodeUnitContaining(currentAddress());
		return cu;
	}

	protected CodeUnit codeUnitContaining(Address addr) {
		CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
		return cu;
	}

	protected void assertSearchSelectionSelected() {
		waitForSwing();
		assertTrue(Swing.runNow(() -> searchProvider.isSearchSelection()));
	}

	protected Highlight[] getByteHighlights(Address address, String bytes) {
		goTo(address);
		ListingHighlightProvider hlProvider = getHighlightProvider();
		ListingField field = getField(address, BytesFieldFactory.FIELD_NAME);
		return hlProvider.createHighlights(bytes, field, -1);
	}

	protected String getInput() {
		return Swing.runNow(() -> searchProvider.getSearchInput());
	}

	protected String getByteString() {
		return Swing.runNow(() -> searchProvider.getByteString());
	}

	protected void setSearchFormat(SearchFormat format) {
		settings = settings.withSearchFormat(format);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setDecimalSize(int size) {
		settings = settings.withDecimalByteSize(size);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setAlignment(int alignment) {
		settings = settings.withAlignment(alignment);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setSearchSelectionOnly(boolean b) {
		runSwing(() -> searchProvider.setSearchSelectionOnly(b));
	}

	protected void setBigEndian(boolean b) {
		settings = settings.withBigEndian(b);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setCaseSensitive(boolean b) {
		settings = settings.withCaseSensitive(b);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setCharset(Charset charset) {
		settings = settings.withStringCharset(charset);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setEscapeSequences(boolean b) {
		settings = settings.withUseEscapeSequence(b);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void addSearchRegion(SearchRegion region, boolean b) {
		settings = settings.withSelectedRegion(region, b);
		runSwing(() -> searchProvider.setSettings(settings));
	}

	protected void setCodeTypeFilters(boolean instructions, boolean data, boolean undefinedData) {
		settings = settings.withIncludeInstructions(instructions);
		settings = settings.withIncludeDefinedData(data);
		settings = settings.withIncludeUndefinedData(undefinedData);
		runSwing(() -> searchProvider.setSettings(settings));
	}
}
