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
package ghidra.feature.vt.gui.provider.functionassociation;

import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JLabel;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.filter.FilterOptions;
import docking.widgets.filter.TextFilterStrategy;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.actions.CreateManualMatchFromToolsAction;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableModel;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class VTFunctionAssociationTest extends AbstractGhidraHeadedIntegrationTest {

	private VTTestEnv env;
	private VTController controller;
	private Program sourceProgram;
	private Program destinationProgram;
	private PluginTool vtTool;
	private VTPlugin versionTrackingPlugin;
	private FunctionManager sourceFunctionManager;
	private FunctionManager destinationFunctionManager;
	private DockingActionIf createManualMatchAction;
	private MultiStateDockingAction<FilterSettings> functionAssociationFilterAction;
	private DockingActionIf createManualMatchAndAcceptAction;
	private DockingActionIf createManualMatchAndApplyAction;

	private VTMatchTableProvider matchesProvider;
	private GhidraTable matchesTable;
	private VTMatchTableModel matchesTableModel;

	private GhidraTable sourceTable;
	private GhidraTable destinationTable;
	private GhidraTableFilterPanel<?> sourceFilter;
	private GhidraTableFilterPanel<?> destinationFilter;
	private VTFunctionAssociationProvider functionAssociationProvider;

	@SuppressWarnings("unchecked")
	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		env = new VTTestEnv();
		vtTool = env.showTool();
		vtTool.setSize(800, 800);
		env.createSession("VersionTracking/WallaceSrc", "VersionTracking/WallaceVersion2",
			new ExactMatchInstructionsProgramCorrelatorFactory());
		sourceProgram = env.getSourceProgram();
		destinationProgram = env.getDestinationProgram();
		controller = env.getVTController();

		sourceFunctionManager = sourceProgram.getFunctionManager();
		destinationFunctionManager = destinationProgram.getFunctionManager();
		versionTrackingPlugin = env.getVersionTrackingPlugin();
		createManualMatchAction = getAction(versionTrackingPlugin, "Create Manual Match");
		createManualMatchAndAcceptAction =
			getAction(versionTrackingPlugin, "Create And Accept Manual Match");
		createManualMatchAndApplyAction =
			getAction(versionTrackingPlugin, "Create and Apply Manual Match");
		functionAssociationFilterAction =
			(MultiStateDockingAction<FilterSettings>) getAction(versionTrackingPlugin,
				"Function Association Functions Filter");

		//
		// Matches Table
		//
		matchesProvider = (VTMatchTableProvider) TestUtils.getInstanceField("matchesProvider",
			versionTrackingPlugin);
		matchesTable = (GhidraTable) TestUtils.getInstanceField("matchesTable", matchesProvider);
		matchesTableModel =
			(VTMatchTableModel) TestUtils.getInstanceField("matchesTableModel", matchesProvider);
		waitForTableModel(matchesTableModel);

		//
		// Get the source /dest tables and filters
		//
		functionAssociationProvider = displayFunctionAssociationProvider();

		// Verify some defaults we are expecting
		checkProviderStatus("");
		checkFunctionAssociationFilterState(FilterSettings.SHOW_ALL);

		// Check that all functions are displayed in the table.
		sourceTable = (GhidraTable) TestUtils.getInstanceField("sourceFunctionsTable",
			functionAssociationProvider);
		destinationTable = (GhidraTable) TestUtils.getInstanceField("destinationFunctionsTable",
			functionAssociationProvider);
		assertNotNull(sourceTable);
		assertNotNull(destinationTable);

		waitForTable(sourceTable);
		waitForTable(destinationTable);

		sourceFilter =
			(GhidraTableFilterPanel<?>) TestUtils.getInstanceField("sourceTableFilterPanel",
				functionAssociationProvider);
		destinationFilter =
			(GhidraTableFilterPanel<?>) TestUtils.getInstanceField("destinationTableFilterPanel",
				functionAssociationProvider);
	}

	@After
	public void tearDown() throws Exception {

		runSwing(() -> vtTool.close());
		env.dispose();
	}

	@Test
	public void testCountWithNonMatchedFunctionsOn() throws Exception {

		int sourceCount = sourceTable.getRowCount();
		int destinationCount = destinationTable.getRowCount();

		// Determine how many source and destination functions are in the exact match set.
		Set<Function> sourceSet = new HashSet<>();
		Set<Function> destinationSet = new HashSet<>();
		loadFunctionSetsFromExactMatchSet(sourceSet, destinationSet);
		int sourceMatchCount = sourceSet.size();
		int destinationMatchCount = destinationSet.size();

		// Set the filter so we show only non-matched functions.
		setFilterTo(FilterSettings.SHOW_UNMATCHED);

		assertEquals(sourceCount - sourceMatchCount, sourceTable.getRowCount());
		assertEquals(destinationCount - destinationMatchCount, destinationTable.getRowCount());

		Function[] sourceFunctions = sourceSet.toArray(new Function[sourceSet.size()]);
		Function[] destinationFunctions =
			destinationSet.toArray(new Function[destinationSet.size()]);
		assertTrue(sourceFunctions.length > 0);
		assertTrue(destinationFunctions.length > 0);

		VTFunctionAssociationTableModel sourceModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField("sourceFunctionsModel",
				functionAssociationProvider);
		VTFunctionAssociationTableModel destinationModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField(
				"destinationFunctionsModel", functionAssociationProvider);

		int sourceRowCount = sourceTable.getRowCount();
		for (int row = 0; row < sourceRowCount; row++) {
			Function function = sourceModel.getFunction(row);
			assertTrue(!sourceSet.contains(function));
		}
		int destinationRowCount = destinationTable.getRowCount();
		for (int row = 0; row < destinationRowCount; row++) {
			Function function = destinationModel.getFunction(row);
			assertTrue(!destinationSet.contains(function));
		}

		// Set the filter so we don't show accepted functions.
		setFilterTo(FilterSettings.SHOW_UNACCEPTED);

		assertEquals(sourceCount, sourceTable.getRowCount());
		assertEquals(destinationCount, destinationTable.getRowCount());
	}

	@Test
	public void testCountWithNonAcceptedFunctionsOn() throws Exception {

		int sourceCount = sourceTable.getRowCount();
		int destinationCount = destinationTable.getRowCount();

		// Determine how many source and destination functions are in the exact match set.
		HashSet<Function> sourceSet = new HashSet<>();
		HashSet<Function> destinationSet = new HashSet<>();
		loadFunctionSetsFromExactMatchSet(sourceSet, destinationSet);
		int sourceMatchCount = sourceSet.size();
		int destinationMatchCount = destinationSet.size();

		// Accept All the Exact Matches.
		acceptAllExactMatches();

		// Set the filter so we don't show accepted functions.
		setFilterTo(FilterSettings.SHOW_UNACCEPTED);

		int expectedSourceCount = sourceCount - sourceMatchCount;
		int actualSourceCount = sourceTable.getRowCount();

		if (expectedSourceCount != actualSourceCount) {
			debugSourceTableValues(expectedSourceCount, actualSourceCount);
		}

		assertEquals(sourceCount - sourceMatchCount, sourceTable.getRowCount());
		assertEquals(destinationCount - destinationMatchCount, destinationTable.getRowCount());

		Function[] sourceFunctions = sourceSet.toArray(new Function[sourceSet.size()]);
		Function[] destinationFunctions =
			destinationSet.toArray(new Function[destinationSet.size()]);
		assertTrue(sourceFunctions.length > 0);
		assertTrue(destinationFunctions.length > 0);

		VTFunctionAssociationTableModel sourceModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField("sourceFunctionsModel",
				functionAssociationProvider);
		VTFunctionAssociationTableModel destinationModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField(
				"destinationFunctionsModel", functionAssociationProvider);

		int sourceRowCount = sourceTable.getRowCount();
		for (int row = 0; row < sourceRowCount; row++) {
			Function function = sourceModel.getFunction(row);
			assertEquals(false, function.equals(sourceFunctions[0]));
		}
		int destinationRowCount = destinationTable.getRowCount();
		for (int row = 0; row < destinationRowCount; row++) {
			Function function = destinationModel.getFunction(row);
			assertEquals(false, function.equals(destinationFunctions[0]));
		}
	}

	@Test
	public void testSelectFunctions() throws Exception {

		//
		// Existing match: 
		// 'addPeople' (00411700)  ->  FUN_004116f0
		//

		//this will show only entries with add in their label
		String sourceFilterText = "add";
		//this will show entries that have addresses 004116xx
		String destinationText = "004116";
		setSourceFilter(sourceFilterText);
		setDestinationFilter(destinationText);

		selectRowByLocation(sourceTable, "00411700");

		checkProviderStatus("Select a single source function and a single destination function.");

		// FUN_004116b0
		selectRowByLocation(destinationTable, "004116b0");

		// Verify via lack of error status that the single source and single destination 
		// could create a match.
		checkProviderStatus("");

		// now select a row that is not allows due to an already existing match
		selectRowByLocation(destinationTable, "004116f0");
		checkProviderStatus("A match already exists between addPeople and FUN_004116f0.");
	}

	@Test
	public void testCreateManualMatchFailure() throws Exception {

		int matchesCount = matchesTable.getRowCount();

		// Try to create a manual match which exists.		
		assertTrue(hasMatch("Gadget", "FUN_00411430"));

		// Gadget (00411440) -> FUN_00411430 
		assertFalse("Created manual match when a similar match exists",
			createManualMatch("00411440", "00411430", false, false));

		waitForTable(sourceTable);
		waitForTable(destinationTable);

		waitForRowCount(sourceTable, 1);
		waitForRowCount(destinationTable, 1);

		assertEquals(matchesCount, matchesTable.getRowCount());
	}

	@Test
	public void testCreateManualMatchSuccess() throws Exception {

		// Set the filter so we don't show accepted functions.
		setFilterTo(FilterSettings.SHOW_UNMATCHED);

		// Check the status is empty.
		checkProviderStatus("");

		int initialMatchCount = matchesTable.getRowCount();

		// Successfully create a new match, one that is not already in the matches table
		// deployGadget (004118f0) -> FUN_00412340
		assertFalse(hasMatch("deployGadget", "FUN_00412340"));
		assertTrue(createManualMatch("004118f0", "FUN_00412340", false, false));

		waitForTable(sourceTable);
		waitForTable(destinationTable);

		waitForRowCount(sourceTable, 0);
		waitForRowCount(destinationTable, 0);

		assertEquals(initialMatchCount + 1, matchesTable.getRowCount());
		VTMatch match = findMatch("deployGadget", "FUN_00412340");
		assertNotNull(match);
		assertEquals(VTAssociationStatus.AVAILABLE, match.getAssociation().getStatus());
	}

	@Test
	public void testCreateManualMatchFromCodeBrowserToolAction() throws Exception {

		PluginTool sourceTool = env.getSourceTool();
		PluginTool destinationTool = env.getDestinationTool();

		// pick to addresses to 'match'
		goTo(destinationTool, destinationProgram, "00412340");
		goTo(sourceTool, sourceProgram, "004118f0");

		assertFalse(hasMatch("deployGadget", "FUN_00412340"));

		DockingActionIf matchAction =
			getAction(destinationTool, CreateManualMatchFromToolsAction.NAME);
		performActionInCodeBrowser(destinationTool, matchAction);

		VTMatch match = findMatch("deployGadget", "FUN_00412340");
		assertNotNull(match);
		assertEquals(VTAssociationStatus.AVAILABLE, match.getAssociation().getStatus());
	}

	private void performActionInCodeBrowser(PluginTool ghidraTool,
			DockingActionIf matchAction) {

		CodeBrowserPlugin cb = getPlugin(ghidraTool, CodeBrowserPlugin.class);
		CodeViewerProvider provider = cb.getProvider();
		ActionContext context = runSwing(() -> provider.getActionContext(null));
		performAction(matchAction, context, true);
	}

	@Test
	public void testCreateManualMatchAndAcceptAction() throws Exception {

		// Set the filter so we don't show accepted functions.
		setFilterTo(FilterSettings.SHOW_UNMATCHED);

		int initialMatchCount = matchesTable.getRowCount();

		// Successfully create a new match.
		// deployGadget (004118f0) -> FUN_00412340
		assertFalse(hasMatch("deployGadget", "FUN_00412340"));
		assertTrue(createManualMatch("004118f0", "FUN_00412340", true, false));

		waitForTable(sourceTable);
		waitForTable(destinationTable);

		waitForRowCount(sourceTable, 0);
		waitForRowCount(destinationTable, 0);

		assertEquals(initialMatchCount + 1, matchesTable.getRowCount());

		//since it was accepted, the destination function was renamed to "deployGadget";
		assertTrue(!hasMatch("deployGadget", "FUN_00412340"));
		VTMatch match = findMatch("deployGadget", "deployGadget");
		assertNotNull(match);
		assertEquals(VTAssociationStatus.ACCEPTED, match.getAssociation().getStatus());
	}

	@Test
	public void testCreateManualMatchAndApplyAction() throws Exception {

		//
		// deployGadget (004118f0) -> FUN_00412340
		// 

		// change the signature in the source program so that an applyable markup item will be created. 
		int id = sourceProgram.startTransaction("test");
		FunctionManager fm = sourceProgram.getFunctionManager();
		Function function = fm.getFunctionAt(s_addr("004118f0")); // deployGadget
		function.setReturnType(new IntegerDataType(), SourceType.USER_DEFINED);
		sourceProgram.endTransaction(id, true);

		flush(sourceProgram);

		// Set the filter so we don't show accepted functions.
		setFilterTo(FilterSettings.SHOW_UNMATCHED);

		int initialMatchCount = matchesTable.getRowCount();

		// Successfully create a new match.
		assertFalse(hasMatch("deployGadget", "FUN_00412340"));
		assertTrue(createManualMatch("004118f0", "FUN_00412340", true, true));

		waitForTable(sourceTable);
		waitForTable(destinationTable);

		waitForRowCount(sourceTable, 0);
		waitForRowCount(destinationTable, 0);

		assertEquals(initialMatchCount + 1, matchesTable.getRowCount());

		// since it was accepted, the destination function was renamed to "deployGadget";
		assertFalse("The destination function was not renamed",
			hasMatch("deployGadget", "FUN_00412340"));
		VTMatch match = findMatch("deployGadget", "deployGadget");
		assertNotNull(match);
		assertEquals(VTAssociationStatus.ACCEPTED, match.getAssociation().getStatus());

		FunctionManager destionationFM = destinationProgram.getFunctionManager();
		function = destionationFM.getFunctionAt(s_addr("00412340")); // the new deployGadget
		assertEquals("int", function.getReturnType().getName());
	}

	private void flush(DomainObject domo) throws Exception {
		domo.flushEvents();
		waitForTasks();
		waitForTables();
	}

	@Test
	public void testFilters() throws Exception {

		VTFunctionAssociationTableModel sourceModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField("sourceFunctionsModel",
				functionAssociationProvider);
		VTFunctionAssociationTableModel destinationModel =
			(VTFunctionAssociationTableModel) TestUtils.getInstanceField(
				"destinationFunctionsModel", functionAssociationProvider);

		int sourceCount = sourceModel.getRowCount();
		int destinationCount = destinationModel.getRowCount();

		String sourceFilterText = "add";
		setSourceFilter(sourceFilterText);

		//now that thunks have been removed from the function table there are only two in the filtered list
		waitForRowCount(sourceTable, 2);

		int filteredSourceCount = sourceTable.getRowCount();
		assertEquals(2, filteredSourceCount);
		for (int row = 0; row < filteredSourceCount; row++) {
			Function function = sourceModel.getFunction(row);
			assertEquals(true, function.getName().contains(sourceFilterText));
		}

		String destinationFilterText = "lock";
		setDestinationFilter(destinationFilterText);

		//now that thunks have been removed from the function table there is only one in the filtered list
		waitForRowCount(destinationTable, 1);

		int filteredDestinationCount = destinationTable.getRowCount();
		assertEquals(1, filteredDestinationCount);
		for (int row = 0; row < filteredDestinationCount; row++) {
			Function function = destinationModel.getFunction(row);
			assertEquals(true, function.getName().contains(destinationFilterText));
		}

		setSourceFilter("");
		setDestinationFilter("");

		waitForRowCount(sourceTable, sourceCount);
		waitForRowCount(destinationTable, destinationCount);
	}

	private void setFilterTo(final FilterSettings settings) throws Exception {
		runSwing(() -> functionAssociationFilterAction.setCurrentActionStateByUserData(settings));
		waitForSwing();
		waitForTable(sourceTable);
		waitForTable(destinationTable);

		checkFunctionAssociationFilterState(settings);
	}

	private void debugSourceTableValues(int expectedSourceCount, int actualSourceCount)
			throws Exception {

		Msg.debug(this,
			"\nFound failure case where values differ - e v. a: " + expectedSourceCount + " v. " +
				actualSourceCount + "\n  Further, we expect that " +
				"some of the values printed below will be accepted, even though they should " +
				"be filtered out");

		waitForTable(sourceTable);

		Msg.debug(this, "\tnow are they still different after waiting long time?: ");
		// running in the swing thread to check for thread visibility issues
		final AtomicInteger returnValue = new AtomicInteger();
		runSwing(() -> returnValue.set(sourceTable.getRowCount()));

		if (expectedSourceCount != returnValue.get()) {
			FunctionManager functionManager = sourceProgram.getFunctionManager();

			Msg.debug(this, "\tNOPE!: table values: ");
			VTFunctionAssociationTableModel model =
				(VTFunctionAssociationTableModel) sourceTable.getModel();
			List<VTFunctionRowObject> data = model.getModelData();
			for (VTFunctionRowObject datum : data) {
				FunctionAssociationInfo info = datum.getInfo();
				long functionID = info.getFunctionID();
				Function function = functionManager.getFunction(functionID);
				Msg.debug(this,
					"\t\trow value: function=" + function +
						"\n\t\t\tfilter state: isInAssociation=" + info.isInAssociation() +
						" isAcceptedAssociation=" + info.isInAcceptedAssociation() +
						" isFilterInitialized=" + info.isFilterInitialized());
			}
		}
		else {
			Msg.debug(this, "\tALL GOOD AFTER WAITING-- this means that our waitXXX() code " +
				"is missing an asynchronous gadget");
		}
	}

	private void selectRowByLocation(final GTable table, final String locationString)
			throws Exception {

		final TableModel model = table.getModel();

		final AtomicReference<Integer> locationColumn = new AtomicReference<>(-1);
		runSwing(() -> {
			int cols = model.getColumnCount();
			for (int i = 0; i < cols; i++) {
				String name = model.getColumnName(i);
				if ("Location".equals(name)) {
					locationColumn.set(i);
					break;
				}
			}
		});

		assertTrue("Could not find the location column", locationColumn.get() >= 0);

		final AtomicReference<Integer> targetRow = new AtomicReference<>(-1);
		runSwing(() -> {
			int rows = model.getRowCount();
			for (int i = 0; i < rows; i++) {
				Object value = model.getValueAt(i, locationColumn.get());
				if (value.toString().equals(locationString)) {
					targetRow.set(i);
					break;
				}
			}
		});

		assertTrue("Could not find a row for location: " + locationString, targetRow.get() >= 0);

		runSwing(() -> {
			int row = targetRow.get();
			table.setRowSelectionInterval(row, row);
		});

		waitForSwing();
		waitForTable(table);

		waitForRowSelection(table, targetRow.get());
	}

	private void setSourceFilter(final String text) throws Exception {
		runSwing(() -> sourceFilter.setFilterText(text));
		waitForSwing();
		waitForTable(sourceTable);
		waitForFilterText(sourceFilter, text);
	}

	private void setDestinationFilter(final String text) throws Exception {
		runSwing(() -> destinationFilter.setFilterText(text));
		waitForSwing();
		waitForTable(destinationTable);
		waitForFilterText(destinationFilter, text);
	}

	private void waitForTable(GTable table) throws Exception {
		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		waitForTableModel(model);
	}

	private void loadFunctionSetsFromExactMatchSet(Set<Function> sourceSet,
			Set<Function> destinationSet) throws Exception {

		VTMatchSet exactMatchSet = getExactFunctionInstructionsMatchSet();
		Collection<VTMatch> exactMatches = exactMatchSet.getMatches();
		for (VTMatch exactMatch : exactMatches) {
			VTAssociation association = exactMatch.getAssociation();
			Address sourceAddress = association.getSourceAddress();
			Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);
			if (sourceFunction != null) {
				sourceSet.add(sourceFunction);
			}
			Address destinationAddress = association.getDestinationAddress();
			Function destinationFunction =
				destinationFunctionManager.getFunctionAt(destinationAddress);
			if (destinationFunction != null) {
				destinationSet.add(destinationFunction);
			}
		}
	}

	private void checkFunctionAssociationFilterState(FilterSettings expectedFilterSetting) {
		ActionState<FilterSettings> currentState =
			functionAssociationFilterAction.getCurrentState();
		FilterSettings filterSettings = currentState.getUserData();
		assertTrue(
			"Expected action filter state of " + expectedFilterSetting.name() +
				" but is actually " + filterSettings.name() + ".",
			filterSettings == expectedFilterSetting);
	}

	private VTFunctionAssociationProvider displayFunctionAssociationProvider() throws Exception {

		final VTFunctionAssociationProvider provider =
			(VTFunctionAssociationProvider) TestUtils.getInstanceField(
				"functionAssociationProvider", versionTrackingPlugin);
		runSwing(() -> vtTool.showComponentProvider(provider, true));
		waitForSwing();
		waitForTasks();
		waitForSwing();
		return provider;
	}

	private boolean hasMatch(String sourceFunctionName, String destinationFunctionName) {
		return findMatch(sourceFunctionName, destinationFunctionName) != null;
	}

	private VTMatch findMatch(String sourceFunctionName, String destinationFunctionName) {
		List<VTMatch> modelData = matchesTableModel.getModelData();
		for (VTMatch match : modelData) {
			VTAssociation association = match.getAssociation();
			Address sourceAddress = association.getSourceAddress();
			Address destinationAddress = association.getDestinationAddress();
			Function sourceFunction = sourceFunctionManager.getFunctionAt(sourceAddress);
			Function destinationFunction =
				destinationFunctionManager.getFunctionAt(destinationAddress);
			if (sourceFunction == null || destinationFunction == null) {
				continue;
			}
			if (sourceFunctionName.equals(sourceFunction.getName()) &&
				destinationFunctionName.equals(destinationFunction.getName())) {
				return match;
			}
		}
		return null;
	}

	private boolean createManualMatch(final String sourceAddress, final String destionationAddress,
			boolean acceptMatch, boolean applyMarkup) throws Exception {

		// Filter to only show the functions of interest.
		runSwing(() -> {

			// we want a starts-with filter, so we can filter by address
			FilterOptions filter =
				new FilterOptions(TextFilterStrategy.STARTS_WITH, false, false, false);
			sourceFilter.setFilterOptions(filter);
			destinationFilter.setFilterOptions(filter);

			sourceFilter.setFilterText(sourceAddress);
			destinationFilter.setFilterText(destionationAddress);
		});

		waitForFilterText(sourceFilter, sourceAddress);
		waitForFilterText(destinationFilter, destionationAddress);
		waitForRowCount(sourceTable, 1);
		waitForRowCount(destinationTable, 1);

		// Select the functions for the match.
		runSwing(() -> {
			sourceTable.selectRow(0);
			destinationTable.selectRow(0);
		});

		waitForRowSelection(sourceTable, 0);
		waitForRowSelection(destinationTable, 0);
		DockingActionIf action = createManualMatchAction;
		if (acceptMatch) {
			action = createManualMatchAndAcceptAction;
		}
		if (applyMarkup) {
			action = createManualMatchAndApplyAction;
		}

		if (action.isEnabled()) {
			// Invoke the manual match action
			performAction(action, functionAssociationProvider, true);

			waitForTasks();
			VTSession session = env.getSession();
			session.flushEvents(); // make sure our tables are notified of the changes
			waitForSwing();
			waitForTables();
			return true;
		}
		return false;
	}

	private void waitForTables() throws Exception {
		waitForTable(matchesTable);
		waitForTable(destinationTable);
		waitForTable(sourceTable);
	}

	private void waitForRowCount(GhidraTable table, int rowCount) {
		int elapsedTime = 0;
		int frequency = 100;
		int currentRowCount = table.getRowCount();
		if (currentRowCount == rowCount) {
			return;
		}

		int waitTime = 2000;
		while (elapsedTime < waitTime) {
			sleep(frequency);
			waitForSwing();

			currentRowCount = table.getRowCount();
			if (currentRowCount == rowCount) {
				return;
			}
			elapsedTime += frequency;
		}
		Assert.fail("Expected row count of " + rowCount + ", but was " + currentRowCount + ".");
	}

	private void waitForFilterText(GhidraTableFilterPanel<?> filterPanel, String filterString) {

		int elapsedTime = 0;
		int frequency = 100;
		String currentFilterText = filterPanel.getFilterText();
		if (currentFilterText.equals(filterString)) {
			return;
		}

		int waitTime = 2000;
		while (elapsedTime < waitTime) {
			sleep(frequency);
			waitForSwing();

			currentFilterText = filterPanel.getFilterText();
			if (currentFilterText.equals(filterString)) {
				return;
			}
			elapsedTime += frequency;
		}
		Assert.fail(
			"Expected filter text of " + filterString + ", but was " + currentFilterText + ".");
	}

	private void waitForRowSelection(GTable table, int row) {
		waitForSwing();
		int elapsedTime = 0;
		int frequency = 100;
		int currentSelectedRow = table.getSelectedRow();
		if (currentSelectedRow == row) {
			return;
		}

		int waitMilliSeconds = 2000; // should this be 4000?
		while (elapsedTime < waitMilliSeconds) {
			sleep(frequency);
			waitForSwing();

			currentSelectedRow = table.getSelectedRow();
			if (currentSelectedRow == row) {
				waitForSwing();
				return;
			}
			elapsedTime += frequency;
		}
		Assert.fail(
			"Expected row " + row + " to be selected, but was row " + currentSelectedRow + ".");
	}

	private VTMatchSet getExactFunctionInstructionsMatchSet() throws NotFoundException {

		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
			String matchSetName = info.getName();
			if (matchSetName.equals("Exact Function Instructions Match")) {
				return matchSet;
			}
		}
		throw new NotFoundException("Couldn't find Exact Match Set");
	}

	private void acceptAllExactMatches() throws NotFoundException {
		VTMatchSet exactMatchSet = getExactFunctionInstructionsMatchSet();
		Collection<VTMatch> exactMatches = exactMatchSet.getMatches();
		List<VTMatch> matchList = new ArrayList<>(exactMatches);
		AcceptMatchTask task = new AcceptMatchTask(controller, matchList);
		controller.runVTTask(task);
	}

	private void checkProviderStatus(String expectedStatus) {

		JLabel statusLabel =
			(JLabel) TestUtils.getInstanceField("statusLabel", functionAssociationProvider);
		String status = statusLabel.getText().trim();
		assertEquals(expectedStatus, status);
	}

	private Address s_addr(String address) {
		return sourceProgram.getAddressFactory().getAddress(address);
	}
}
