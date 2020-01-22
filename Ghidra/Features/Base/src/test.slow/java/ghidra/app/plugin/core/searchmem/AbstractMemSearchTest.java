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

import static org.junit.Assert.*;

import java.awt.Container;
import java.awt.Window;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.swing.*;

import org.apache.commons.collections4.IteratorUtils;
import org.junit.After;

import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.core.table.TableServicePlugin;
import ghidra.app.services.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.BytesFieldFactory;
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.Msg;
import ghidra.util.search.memory.MemSearchResult;
import ghidra.util.table.GhidraTable;

/**
 * Base class for memory search tests.  
 */
public abstract class AbstractMemSearchTest extends AbstractProgramBasedTest {

	protected MemSearchPlugin memSearchPlugin;
	protected DockingActionIf searchAction;
	protected CodeBrowserPlugin cb;
	protected CodeViewerProvider provider;
	protected JLabel statusLabel;
	protected JTextField valueField;
	protected JComboBox<?> valueComboBox;
	protected Container pane;
	protected JLabel hexLabel;
	protected Memory memory;
	protected Listing listing;
	protected TableServicePlugin tableServicePlugin;
	protected MarkerService markerService;

	protected MemSearchDialog dialog;

	/*
	 * Note that this setup function does not have the @Before annotation - this is because 
	 * sub-classes often need to override this and if we have the annotation here, the test
	 * runner will only invoke this base class implementation.
	 */
	public void setUp() throws Exception {

		// this builds the program and launches the tool
		initialize();

		memSearchPlugin = env.getPlugin(MemSearchPlugin.class);

		listing = program.getListing();
		memory = program.getMemory();

		searchAction = getAction(memSearchPlugin, "Search Memory");

		cb = codeBrowser; // TODO delete after 7.3 release; just use the parent's CodeBrowser

		provider = cb.getProvider();
		markerService = tool.getService(MarkerService.class);

		tableServicePlugin = env.getPlugin(TableServicePlugin.class);

		showMemSearchDialog();
		setToggleButtonSelected(pane, MemSearchDialog.ADVANCED_BUTTON_NAME, true);
		selectRadioButton("Binary");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	protected abstract Program buildProgram() throws Exception;

	protected void waitForSearch(String panelName, int expectedResults) {

		waitForCondition(() -> {
			return !memSearchPlugin.isSearching();
		}, "Timed-out waiting for search results");

		Window window = AbstractDockingTest.waitForWindowByTitleContaining(panelName);
		GhidraTable gTable = findComponent(window, GhidraTable.class, true);
		waitForSwing();
		assertEquals(expectedResults, gTable.getRowCount());
	}

	protected void waitForSearchTask() {
		waitForSwing();
		Thread t = dialog.getTaskScheduler().getCurrentThread();
		if (t == null) {
			return;
		}

		try {
			t.join();
		}
		catch (InterruptedException e) {
			Msg.debug(this, "Interrupted waiting for the search task thread to finish");
		}
		waitForSwing();
	}

	protected void showMemSearchDialog() {
		performAction(searchAction, provider, true);
		// dig up the components of the dialog
		dialog = waitForDialogComponent(MemSearchDialog.class);
		pane = dialog.getComponent();

		statusLabel = (JLabel) findComponentByName(pane, "statusLabel");
		valueComboBox = findComponent(pane, JComboBox.class);
		valueField = (JTextField) valueComboBox.getEditor().getEditorComponent();
		hexLabel = (JLabel) findComponentByName(pane, "HexSequenceField");
	}

	protected void selectRadioButton(String text) {
		setToggleButtonSelected(pane, text, true);
	}

	protected void selectCheckBox(String text, boolean state) {
		setToggleButtonSelected(pane, text, state);
	}

	@SuppressWarnings("unchecked")
	private List<Address> getHighlightAddresses() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		Object codeViewerProvider = getInstanceField("connectedProvider", service);
		Map<Program, HighlightProvider> highlighterMap =
			(Map<Program, HighlightProvider>) getInstanceField("programHighlighterMap",
				codeViewerProvider);
		HighlightProvider highlightProvider = highlighterMap.get(program);

		assertEquals("The inner-class has been renamed", "SearchTableHighlightHandler",
			highlightProvider.getClass().getSimpleName());

		MemSearchTableModel model =
			(MemSearchTableModel) getInstanceField("model", highlightProvider);
		List<MemSearchResult> data = model.getModelData();
		return data.stream().map(result -> result.getAddress()).collect(Collectors.toList());
	}

	protected void checkMarkerSet(List<Address> expected) {

		TableComponentProvider<?>[] providers = tableServicePlugin.getManagedComponents();
		TableComponentProvider<?> tableProvider = providers[0];
		assertTrue(tool.isVisible(tableProvider));

		List<Address> highlights = getHighlightAddresses();
		assertListEqualUnordered("Search highlights not correctly generated", expected, highlights);

		MarkerSet markers =
			runSwing(() -> markerService.getMarkerSet(tableProvider.getName(), program));
		assertNotNull(markers);

		AddressSet addressSet = runSwing(() -> markers.getAddressSet());
		AddressIterator it = addressSet.getAddresses(true);
		List<Address> list = IteratorUtils.toList(it);

		assertListEqualUnordered("Search markers not correctly generated", expected, list);
	}

	protected void pressSearchAllButton() {
		runSwing(() -> invokeInstanceMethod("allCallback", dialog));
	}

	protected void pressSearchButton(String text) throws Exception {
		pressButtonByText(pane, text);
		waitForSearchTask();
	}

	protected void performSearchTest(List<Address> expected, String buttonText) throws Exception {

		for (Address addr : expected) {
			pressSearchButton(buttonText);
			assertEquals("Found", getStatusText());
			cb.updateNow();
			assertEquals(addr, cb.getCurrentLocation().getAddress());
		}

		pressSearchButton(buttonText);
		assertEquals("Not Found", getStatusText());
	}

	protected String getStatusText() {
		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> ref.set(statusLabel.getText()));
		return ref.get();
	}

	protected void setValueText(String s) {
		setText(valueField, s);
	}

	protected void myTypeText(String text) {
		// Note: we do not use setFocusedComponent(valueField), as that method will fail if the
		//       focus change doesn't work.  Here, we will keep on going if the focus change 
		//       doesn't work.
		runSwing(() -> valueField.requestFocus());
		triggerText(valueField, text);
	}

	protected HighlightProvider getHighlightProvider() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		FormatManager fm = (FormatManager) getInstanceField("formatMgr", service);
		return (HighlightProvider) getInstanceField("highlightProvider", fm);
	}

	protected void repeatSearch() {
		DockingActionIf action = getAction(memSearchPlugin, "Repeat Memory Search");
		assertTrue(action.isEnabled());
		performAction(action, provider, true);
		waitForSearchTask();
	}

	protected Address currentAddress() {
		cb.updateNow();
		Address addr = cb.getCurrentLocation().getAddress();
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

		AbstractButton b = findAbstractButtonByText(pane, "Search Selection");
		assertTrue(isEnabled(b));
		assertTrue(isSelected(b));
	}

	protected void assertButtonState(String text, boolean isEnabled, boolean isSelected) {

		AbstractButton b = findAbstractButtonByText(pane, text);
		assertEquals(isEnabled, isEnabled(b));
		assertEquals(isSelected, isSelected(b));
	}

	protected void assertEnabled(String text, boolean isEnabled) {
		// Note: we do not use the findAbstractButtonByText() here as there are two buttons with
		//       the same text.  Only one of the buttons is actually a JButton, so this call works.
		//       Ideally, all buttons would have a name set so that wouldn't have to rely on the 
		//       button text.
		JButton b = findButtonByText(pane, text);
		assertEquals(isEnabled, isEnabled(b));
	}

	protected void setAlignment(String alignment) {
		JTextField alignmentField =
			(JTextField) findComponentByName(dialog.getComponent(), "Alignment");
		setText(alignmentField, alignment);
	}

	protected Highlight[] getByteHighlights(Address address, String bytes) {
		CodeUnit cu = codeUnitContaining(address);
		HighlightProvider provider1 = getHighlightProvider();
		Highlight[] h = provider1.getHighlights(bytes, cu, BytesFieldFactory.class, -1);
		return h;
	}

	protected void setEndianess(String text) {
		// we use this method because the given button may be disabled, which means we cannot
		// click it, but we can select it
		AbstractButton button = findAbstractButtonByText(pane, text);
		runSwing(() -> button.setSelected(true));
	}

}
