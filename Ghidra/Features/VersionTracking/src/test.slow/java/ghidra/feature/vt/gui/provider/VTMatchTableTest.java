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
package ghidra.feature.vt.gui.provider;

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.TableFilter;
import docking.widgets.table.threaded.TableData;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.feature.vt.api.correlator.program.*;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.filters.AncillaryFilterDialogComponentProvider;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class VTMatchTableTest extends AbstractGhidraHeadedIntegrationTest {
	private VTTestEnv env;
	private VTSession session;

	@Before
	public void setUp() throws Exception {

		env = new VTTestEnv();
		PluginTool tool = env.showTool();
		session = env.createSession("VersionTracking/WallaceSrc", "VersionTracking/WallaceVersion2",
			new ExactMatchInstructionsProgramCorrelatorFactory());

		assertNotNull(session);

		JFrame toolFrame = tool.getToolFrame();
		toolFrame.setSize(800, 800);
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testTableSelectionState_TrackByRowIndex() {
		env.focusMatchTable();
		MatchTableSelectionAction action =
			(MatchTableSelectionAction) env.getAction(MatchTableSelectionAction.NAME);
		assertNotNull(action);
		assertTrue(action.isEnabled()); // always enabled

		setActionState(action, TableSelectionTrackingState.MAINTAIN_SELECTED_ROW_INDEX);

		waitForPostedSwingRunnables();

		int selectedRow = 3;
		List<VTMatch> matches = env.selectMatchesInMatchTable(selectedRow);
		assertEquals(1, matches.size());

		// trigger an action that will cause the match to be moved
		VTMatch originalMatch = env.getSelectedMatch();
		applyMatch(originalMatch);

		assertEquals(selectedRow, env.getSelectedMatchTableRow());
		Assert.assertNotEquals(originalMatch, env.getSelectedMatch());
	}

	@Test
	public void testTableSelectionState_TrackByMatch() {
		env.focusMatchTable();
		MatchTableSelectionAction action =
			(MatchTableSelectionAction) env.getAction(MatchTableSelectionAction.NAME);
		assertNotNull(action);
		assertTrue(action.isEnabled()); // always enabled

		setActionState(action, TableSelectionTrackingState.MAINTAIN_SELECTED_ROW_VALUE);
		waitForPostedSwingRunnables();

		int selectedRow = 3;
		List<VTMatch> matches = env.selectMatchesInMatchTable(selectedRow);
		assertEquals(1, matches.size());

		// trigger an action that will cause the match to be moved
		VTMatch originalMatch = env.getSelectedMatch();
		applyMatch(originalMatch);

		Assert.assertNotEquals(selectedRow, env.getSelectedMatchTableRow());
		assertEquals(originalMatch, env.getSelectedMatch());
	}

	@Test
	public void testTableSelectionState_NoTracking() {
		env.focusMatchTable();
		MatchTableSelectionAction action =
			(MatchTableSelectionAction) env.getAction(MatchTableSelectionAction.NAME);
		assertNotNull(action);
		assertTrue(action.isEnabled()); // always enabled

		setActionState(action, TableSelectionTrackingState.NO_SELECTION_TRACKING);
		waitForPostedSwingRunnables();

		int selectedRow = 3;
		List<VTMatch> matches = env.selectMatchesInMatchTable(selectedRow);
		assertEquals(1, matches.size());

		// trigger an action that will cause the match to be moved
		triggerTableDataChanged();

		assertEquals(-1, env.getSelectedMatchTableRow());
		assertNull(env.getSelectedMatch());
	}

	@Test
	public void testMakeProgramSelectionFromTable() {
		env.focusMatchTable();
		DockingActionIf action = env.getAction(CreateSelectionAction.NAME);
		assertNotNull(action);
		assertTrue(!action.isEnabled());

		List<VTMatch> matches = env.selectMatchesInMatchTable(1, 3, 6);
		assertEquals(3, matches.size());

		AddressSet sourceMatchAddrSet = new AddressSet();
		AddressSet destinationMatchAddrSet = new AddressSet();

		for (VTMatch vtMatch : matches) {
			sourceMatchAddrSet.add(vtMatch.getAssociation().getSourceAddress());
			destinationMatchAddrSet.add(vtMatch.getAssociation().getDestinationAddress());
		}

		assertTrue(action.isEnabled());

		VTController controller = env.getVTController();
		AddressSetView sourceSelection = controller.getSelectionInSourceTool();
		AddressSetView destinationSelection = controller.getSelectionInSourceTool();

		assertTrue(sourceSelection.isEmpty());
		assertTrue(destinationSelection.isEmpty());

		env.performMatchTableAction(action);

		sourceSelection = controller.getSelectionInSourceTool();
		destinationSelection = controller.getSelectionInDestinationTool();

		assertEquals(3, sourceSelection.getNumAddressRanges());
		assertEquals(3, destinationSelection.getNumAddressRanges());

		Iterator<AddressRange> sourceMatchIt = sourceMatchAddrSet.iterator();
		Iterator<AddressRange> sourceSelectionIt = sourceSelection.iterator();
		Iterator<AddressRange> destMatchIt = sourceMatchAddrSet.iterator();
		Iterator<AddressRange> destSelectionIt = sourceSelection.iterator();
		for (int i = 0; i < 3; i++) {
			// test source selection (use first addr only as it gets expanded by listing
			AddressRange r1 = sourceMatchIt.next();
			AddressRange r2 = sourceSelectionIt.next();
			assertEquals(r1.getMinAddress(), r2.getMinAddress());

			// test destination selection (use first addr only as it gets expanded by listing
			r1 = destMatchIt.next();
			r2 = destSelectionIt.next();
			assertEquals(r1.getMinAddress(), r2.getMinAddress());
		}
	}

	@Test
	public void testFilterCooperation() throws Exception {

		//
		// Test that the filters in the table UI play well with the filters in the filter dialog.
		//

		// add some different types so we can use the filter (we will now have Data and Function)
		env.addToSession(new ExactDataMatchProgramCorrelatorFactory());
		env.addToSession(new ExactMatchBytesProgramCorrelatorFactory());

		env.focusMatchTable();

		// this will match 168 of 190; matching both Data and Functions
		typeInTextFilter("0041");
		int filteredRowCount = getRowCount();
		assertEquals(186, filteredRowCount);

		AncillaryFilterDialogComponentProvider<?> dialog = showFilterDialog();

		// De-select a matching algorithm, as it will trigger a combined
		// filter to get created (the text filter above and the 'Algorithm' filter), but it will
		// *not* trigger a sub-filter, as it is a completely new filter.  Then, if
		// we deselect another algorithm, we should get the sub-filter effect, as we are creating
		// a subset of an exiting filter (the 'Algorithm' filter).
		//
		// Algorithms in table: 'Exact Function Instructions Match', 'Exact Function Bytes Match', 
		// 						'Exact Data Match'
		//
		deselect(dialog, "Exact Function Instructions Match");
		pressApply(dialog);

		int secondRowCount = getRowCount();
		assertEquals(139, secondRowCount);
		assertTableDidNotUseSubFilter();

		// this algorithm is in the table; disabling it will change the results; trigger sub-filter
		deselect(dialog, "Exact Data Match");
		pressApply(dialog);
		int thirdRowCount = getRowCount();
		assertEquals(18, thirdRowCount);
		assertTableUsedSubFilter();

		// change the filter group to something new; this should prevent sub-filter usage 
		deselect(dialog, "Function");
		pressApply(dialog);
		int fourthRowCount = getRowCount();
		assertEquals(0, fourthRowCount);
		assertTableDidNotUseSubFilter();

		close(dialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertTableUsedSubFilter() {

		ThreadedTableModel<?, ?> model = getModel();
		TableData<?> filteredData = (TableData<?>) getInstanceField("filteredData", model);

		TableFilter<?> filter = (TableFilter<?>) getInstanceField("tableFilter", filteredData);
		assertNotNull(filter);

		TableData<?> parent = (TableData<?>) getInstanceField("source", filteredData);
		assertNotNull(parent);
		getInstanceField("tableFilter", parent);

		TableFilter<?> parentFilter = (TableFilter<?>) getInstanceField("tableFilter", parent);
		assertNotNull("A sub-filter was not used", parentFilter);
	}

	private void assertTableDidNotUseSubFilter() {
		ThreadedTableModel<?, ?> model = getModel();
		TableData<?> filteredData = (TableData<?>) getInstanceField("filteredData", model);

		TableFilter<?> filter = (TableFilter<?>) getInstanceField("tableFilter", filteredData);
		assertNotNull(filter);

		TableData<?> parent = (TableData<?>) getInstanceField("source", filteredData);
		assertNotNull(parent);
		getInstanceField("tableFilter", parent);

		TableFilter<?> parentFilter = (TableFilter<?>) getInstanceField("tableFilter", parent);
		assertNull("A sub-filter was used", parentFilter);
	}

	private void pressApply(AncillaryFilterDialogComponentProvider<?> dialog) {

		JButton apply = findButtonByText(dialog, "Apply");
		waitForCondition(() -> runSwing(() -> apply.isEnabled()));
		pressButton(apply, false);
		waitForSwing();
		waitForTable();
	}

	private void waitForTable() {
		waitForTableModel(getModel());
	}

	private ThreadedTableModel<?, ?> getModel() {
		GTable table = getTable();
		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		return model;
	}

	private void deselect(AncillaryFilterDialogComponentProvider<?> dialog, String name) {
		AbstractButton button = findAbstractButtonByText(dialog.getComponent(), name);
		setToggleButtonSelected(button, false);
		waitForSwing();
	}

	private AncillaryFilterDialogComponentProvider<?> showFilterDialog() {
		VTMatchTableProvider provider = env.getMatchTableProvider();
		JButton button = (JButton) getInstanceField("ancillaryFilterButton", provider);
		pressButton(button, false);
		AncillaryFilterDialogComponentProvider<?> dialog =
			waitForDialogComponent(AncillaryFilterDialogComponentProvider.class);
		waitForSwing();
		return dialog;
	}

	private void typeInTextFilter(String text) {

		VTMatchTableProvider provider = env.getMatchTableProvider();
		JComponent component = provider.getComponent();
		JTextField textField =
			(JTextField) findComponentByName(component, VTMatchTableProvider.TEXT_FILTER_NAME);
		setText(textField, text);
	}

	private int getRowCount() {
		return getTable().getRowCount();
	}

	private GTable getTable() {
		VTMatchTableProvider provider = env.getMatchTableProvider();
		GTable table = (GTable) getInstanceField("matchesTable", provider);
		return table;
	}

	private void triggerTableDataChanged() {
		env.triggerMatchTableDataChanged();
	}

	private void setActionState(MatchTableSelectionAction action,
			TableSelectionTrackingState state) {

		runSwing(() -> action.setCurrentActionStateByUserData(state));
	}

	private void applyMatch(VTMatch match) {
		DockingActionIf action = env.getAction(ApplyMatchAction.NAME);
		assertNotNull(action);

		assertTrue(action.isEnabled());

		env.performMatchTableAction(action);
	}
}
