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
package help.screenshot;

import static org.junit.Assert.*;

import java.awt.*;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.options.editor.OptionsDialog;
import docking.options.editor.OptionsPanel;
import docking.widgets.tree.GTree;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.feature.vt.api.correlator.program.ExactMatchInstructionsProgramCorrelatorFactory;
import ghidra.feature.vt.api.correlator.program.SymbolNameProgramCorrelatorFactory;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markupitem.AbstractFunctionSignatureMarkupTest;
import ghidra.feature.vt.api.markuptype.VTMarkupType;
import ghidra.feature.vt.gui.VTTestEnv;
import ghidra.feature.vt.gui.filters.AncillaryFilterDialogComponentProvider;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.provider.functionassociation.VTFunctionAssociationProvider;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchesTableProvider;
import ghidra.feature.vt.gui.provider.markuptable.*;
import ghidra.feature.vt.gui.provider.matchtable.DisplayableLabel;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchDestinationTableProvider;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchSourceTableProvider;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.wizard.*;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.UsrException;
import ghidra.util.table.GhidraTable;
import ghidra.util.task.*;

public class VersionTrackingPluginScreenShots extends GhidraScreenShotGenerator {

	protected static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	protected static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	protected VTTestEnv vtTestEnv;
	protected VTProgramCorrelator correlator;
	protected Program sourceProgram;
	protected Program destinationProgram;
	protected VTController controller;
	protected VTSession session;
	protected Address sourceAddress;
	protected Address destinationAddress;
	protected VTMatch testMatch;
	protected Function sourceFunction;
	protected Function destinationFunction;

	protected PluginTool vtTool;
	protected VTPlugin vtPlugin;

	@Before
	@Override
	public void setUp() throws Exception {
		vtTestEnv = new VTTestEnv();
		session = vtTestEnv.createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
		correlator = vtTestEnv.correlate(new ExactMatchInstructionsProgramCorrelatorFactory(),
			null, TaskMonitor.DUMMY);
		sourceProgram = vtTestEnv.getSourceProgram();
		destinationProgram = vtTestEnv.getDestinationProgram();
		controller = vtTestEnv.getVTController();
		vtTool = vtTestEnv.showTool();
		vtPlugin = vtTestEnv.getPlugin(VTPlugin.class);
		tool = vtTool;
	}

	@After
	@Override
	public void tearDown() {
		sourceProgram = null;
		destinationProgram = null;
		session = null;
		controller = null;
		correlator = null;
		vtTestEnv.dispose();
		saveOrDisplayImage();
	}

	@Test
	public void testVTOptions_AcceptMatchDialog() throws Exception {
		// invoke VTMatchApplySettingsAction and then change selection in tree.
		DockingActionIf dockingAction = getAction(vtPlugin, "Version Tracking Options");
		performAction(dockingAction, false);

		OptionsDialog dialogProvider = waitForDialogComponent(OptionsDialog.class);
		waitForSwing();
		OptionsPanel optionsPanel = (OptionsPanel) getInstanceField("panel", dialogProvider);
		final GTree gtree = (GTree) getInstanceField("gTree", optionsPanel);
		runSwing(() -> gtree.setSelectedNodeByNamePath(
			new String[] { "Options", "Version Tracking", "Accept Match Options" }));
		waitForSwing();

		captureDialog(900, 600);
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testVTOptions_ApplyMarkupDialog() throws Exception {
		// invoke VTMatchApplySettingsAction
		DockingActionIf dockingAction = getAction(vtPlugin, "Version Tracking Options");
		performAction(dockingAction, false);
		captureDialog(1250, 750);
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testFunctionsTable() throws Exception {

		setToolSize(1200, 550);

		showProvider(VTFunctionAssociationProvider.class);
		hideDualListing(VTFunctionAssociationProvider.class);
		captureIsolatedProvider(VTFunctionAssociationProvider.class, 1100, 350);

		// Close the provider that was opened so tests that follow this one don't get messed up.
		closeProvider(VTFunctionAssociationProvider.class);
	}

	@Test
	public void testImpliedMatchesTable() throws Exception {
		// We want the match table and implied match table in the tool.
		// So close the markup items table provider.
		closeProvider(VTMarkupItemsTableProvider.class);

		setToolSize(1200, 550);

		selectMatch("main");

		captureToolWindow(1200, 550);

		// Open the closed provider so that tests that follow this one don't get messed up.
		showProvider(VTMarkupItemsTableProvider.class);
	}

	@Test
	public void testVersionTrackingMarkupItems() throws Exception {

		VTMatch match = getMatch("Call_strncpy_s", VTAssociationType.FUNCTION);
		replaceMarkup(match, "00411ab0", "Function Signature");
		addMarkup(match, "00411ad3", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE, match, "00411ad7", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.REJECT, match, "00411ad8", "EOL Comment");

		selectMatch("Call_strncpy_s");

		setToolSize(1300, 750);

		setMarkupTableDivider(40);

		captureIsolatedProvider(VTMarkupItemsTableProvider.class, 1100, 700);
	}

	@Test
	public void testMarkupItemsFilters() throws Exception {
		Window window = waitForWindowByTitleContaining("Test Tool");
		assertNotNull(window);
		VTMarkupItemsTableProvider provider =
			waitForComponentProvider(VTMarkupItemsTableProvider.class);

		@SuppressWarnings("unchecked")
		final AncillaryFilterDialogComponentProvider<VTMarkupItem> ancillaryFilterDialog =
			(AncillaryFilterDialogComponentProvider<VTMarkupItem>) getInstanceField(
				"ancillaryFilterDialog", provider);

		runSwing(() -> tool.showDialog(ancillaryFilterDialog), false);
		waitForSwing();

		captureDialog(800, 250);
		pressButtonByText(getDialog(), "OK");
	}

	@Test
	public void testVersionTrackingMarkupItemsTableOnly() throws Exception {

		VTMatch match = getMatch("Call_strncpy_s", VTAssociationType.FUNCTION);
		replaceMarkup(match, "00411ab0", "Function Signature");
		addMarkup(match, "00411ad3", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE, match, "00411ad7", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.REJECT, match, "00411ad8", "EOL Comment");

		selectMatch("Call_strncpy_s");

		dualListingIsVisible(getProvider(VTMarkupItemsTableProvider.class));

		hideDualListing(VTMarkupItemsTableProvider.class);

		dualListingIsVisible(getProvider(VTMarkupItemsTableProvider.class));

		setToolSize(1300, 750);

		captureIsolatedProvider(VTMarkupItemsTableProvider.class, 1100, 280);
	}

	@Test
	public void testVersionTrackingMarkupItemsHeader() throws Exception {

		VTMatch match = getMatch("Call_strncpy_s", VTAssociationType.FUNCTION);
		replaceMarkup(match, "00411ab0", "Function Signature");
		addMarkup(match, "00411ad3", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE, match, "00411ad7", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.REJECT, match, "00411ad8", "EOL Comment");

		setToolSize(1300, 750);

		selectMatch("Call_strncpy_s");

		setDualListingHorizontal(VTMarkupItemsTableProvider.class);
		toggleDualListingHeader(VTMarkupItemsTableProvider.class, true);

		setMarkupTableDivider(10);

		captureIsolatedProvider(VTMarkupItemsTableProvider.class, 1100, 1000);

		toggleDualListingHeader(VTMarkupItemsTableProvider.class, false);// Switch header back so we don't mess up later tests.
		setDualListingVertical(VTMarkupItemsTableProvider.class);// Switch orientation back so we don't mess up later tests.
	}

	@Test
	public void testVersionTrackingMarkupItemsSideBySide() throws Exception {

		VTMatch match = getMatch("Call_strncpy_s", VTAssociationType.FUNCTION);
		replaceMarkup(match, "00411ab0", "Function Signature");
		addMarkup(match, "00411ad3", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.IGNORE_DONT_CARE, match, "00411ad7", "EOL Comment");
		tagMarkup(VTMarkupItemConsideredStatus.REJECT, match, "00411ad8", "EOL Comment");

		selectMatch("Call_strncpy_s");

		setToolSize(1300, 800);

		setMarkupTableDivider(70);

		captureIsolatedProvider(VTMarkupItemsTableProvider.class, 1100, 630);
	}

	/////////////////////
	// VT_Matches_Table
	/////////////////////

	@Test
	public void testMatchesTable() throws Exception {

		setToolSize(1200, 450);

		selectMatch("Call_strncpy_s");

		captureIsolatedProvider(VTMatchTableProvider.class, 1200, 400);
	}

	//////////////////////////////////
	// VT_Related_Associations_Table
	//////////////////////////////////

	@Test
	public void testOneToManySource() throws Exception {

		VTMatch match = getMatch("addPerson", VTAssociationType.FUNCTION);
		List<VTMatch> matchesToAccept = new ArrayList<>();
		matchesToAccept.add(match);

		AcceptMatchTask task = new AcceptMatchTask(controller, matchesToAccept);
		controller.runVTTask(task);

		vtTestEnv.correlate(new SymbolNameProgramCorrelatorFactory(), null,
			TaskMonitor.DUMMY);

		sourceAddress = sourceProgram.getAddressFactory().getAddress("0x00411860");
		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		destinationAddress = destinationProgram.getAddressFactory().getAddress("0x004118c0");
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		CreateManualMatchTask createMatchTask =
			new CreateManualMatchTask(session, sourceFunction, destinationFunction);
		controller.runVTTask(createMatchTask);

		waitForBusyTool(vtTool);

		selectMatch("addPerson");

		VTSubToolManager toolManager = vtPlugin.getToolManager();
		PluginTool sourceTool = (PluginTool) getInstanceField("sourceTool", toolManager);
		PluginTool destinationTool = (PluginTool) getInstanceField("destinationTool", toolManager);
		assertNotNull(sourceTool);
		assertNotNull(destinationTool);

		tool = sourceTool;
		setToolSize(1200, 550);
		captureIsolatedProvider(VTMatchSourceTableProvider.class, 800, 240);

		tool = vtTool;
	}

	@Test
	public void testOneToManyDestination() throws Exception {

		VTMatch match = getMatch("addPerson", VTAssociationType.FUNCTION);
		List<VTMatch> matchesToAccept = new ArrayList<>();
		matchesToAccept.add(match);

		AcceptMatchTask task = new AcceptMatchTask(controller, matchesToAccept);
		controller.runVTTask(task);

		vtTestEnv.correlate(new SymbolNameProgramCorrelatorFactory(), null,
			TaskMonitor.DUMMY);

		sourceAddress = sourceProgram.getAddressFactory().getAddress("0x00411860");
		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		destinationAddress = destinationProgram.getAddressFactory().getAddress("0x004118c0");
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		CreateManualMatchTask createMatchTask =
			new CreateManualMatchTask(session, sourceFunction, destinationFunction);
		controller.runVTTask(createMatchTask);

		waitForBusyTool(vtTool);

		selectMatch("addPerson");

		VTSubToolManager toolManager = vtPlugin.getToolManager();
		PluginTool sourceTool = (PluginTool) getInstanceField("sourceTool", toolManager);
		PluginTool destinationTool = (PluginTool) getInstanceField("destinationTool", toolManager);
		assertNotNull(sourceTool);
		assertNotNull(destinationTool);

		tool = destinationTool;
		setToolSize(1200, 550);
		captureIsolatedProvider(VTMatchDestinationTableProvider.class, 800, 220);

		tool = vtTool;
	}

	@Test
	public void testVersionTrackingTool() throws Exception {

		tool = vtTool;

		hideDualListing(VTMarkupItemsTableProvider.class);

		setToolSize(1200, 500);

		VTMatchTableProvider provider = getProvider(VTMatchTableProvider.class);
		setProportionalSplitPaneSize(provider, .6f);

		// We want the match table and markup items table in the tool.
		// So close the implied matches table provider.
		closeProvider(VTImpliedMatchesTableProvider.class);

		selectMatch("addPerson");

		captureWindow();

		showProvider(VTImpliedMatchesTableProvider.class);
	}

	private void setProportionalSplitPaneSize(ComponentProvider provider, float size) {

		SplitPanel split = getSplitPanelFor(provider);
		boolean isLeft = split.isLeft(provider.getComponent());
		float adjustedSize = isLeft ? size : 1 - size;
		runSwing(() -> split.setDividerPosition(adjustedSize));
	}

	private SplitPanel getSplitPanelFor(ComponentProvider provider) {
		JComponent component = provider.getComponent();
		SplitPanel split = getSplitPanelFor(component);
		assertNotNull("Unable to find Split Pane for " + provider.getName());
		return split;
	}

	private SplitPanel getSplitPanelFor(Component component) {
		Component parent = component.getParent();
		while (parent != null) {
			parent = parent.getParent();
			if (parent instanceof SplitPanel) {
				return (SplitPanel) parent;
			}
		}
		return null;
	}

	@Test
	public void testSourceTool() throws Exception {

		waitForBusyTool(vtTool);
		tool = vtTool;

		selectMatch("addPerson");

		VTSubToolManager toolManager = vtPlugin.getToolManager();
		PluginTool sourceTool = (PluginTool) getInstanceField("sourceTool", toolManager);
		PluginTool destinationTool = (PluginTool) getInstanceField("destinationTool", toolManager);
		assertNotNull(sourceTool);
		assertNotNull(destinationTool);

		tool = sourceTool;
		setToolSize(1200, 550);
		sourceTool.toFront();
		captureToolWindow(1200, 550);

		tool = vtTool;
	}

	@Test
	public void testSessionPanel() throws Exception {

		setupVTWizardSessionPanel();
		captureDialog(700, 500);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testPreconditionsPanel() throws Exception {

		setupVTWizardPreconditionsPanel();
		captureDialog(600, 500);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testSummaryPanel() throws Exception {
		setupVTWizardSummaryPanel();
		captureDialog(600, 400);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testCorrelatorPanel() throws Exception {

		setupVTWizardCorrelatorPanel();
		captureDialog(800, 400);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testOptionsPanel() throws Exception {
		setupVTWizardOptionsPanel();
		captureDialog(700, 500);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testVT_Wizard_AddressSetOptions() throws Exception {
		setupVTWizardAddressSetOptionsPanel();
		captureDialog(600, 400);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testVT_Wizard_SelectAddressRanges() throws Exception {
		setupVTWizardSelectAddressRangesPanel();
		captureDialog(600, 600);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	@Test
	public void testVT_Wizard_AddToSession_Summary() throws Exception {
		setupVTWizardAddToSessionPanel();
		captureDialog(600, 400);

		// Once the panel we want is captured, cancel out of the wizard.
		pressButtonByText(getDialog(), "Cancel");
	}

	////////////////
	// VT_Workflow
	////////////////

	@Test
	public void testImpliedMatchExample() throws Exception {
		// We want the match table and implied match table in the tool.
		// So close the markup items table provider.
		closeProvider(VTMarkupItemsTableProvider.class);

		setToolSize(1200, 250);

		selectMatch("main");

		captureToolWindow(1200, 550);

		// Open the closed provider so that tests that follow this one don't get messed up.
		showProvider(VTMarkupItemsTableProvider.class);
	}

	//----------------------------------------------------------------------

	private void setMarkupTableDivider(final int dividerLocationInPixels) {
		Window window = waitForWindowByTitleContaining("Test Tool");
		assertNotNull(window);
		VTMarkupItemsTableProvider provider =
			waitForComponentProvider(VTMarkupItemsTableProvider.class);
		runSwing(() -> {
			JSplitPane splitPane = (JSplitPane) getInstanceField("splitPane", provider);
			splitPane.setDividerLocation(dividerLocationInPixels);
		});
		waitForSwing();
	}

	private VTMatch getMatch(String sourceLabel, VTAssociationType matchType) {
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet vtMatchSet : matchSets) {
			Collection<VTMatch> matches = vtMatchSet.getMatches();
			for (VTMatch vtMatch : matches) {
				VTAssociation association = vtMatch.getAssociation();
				VTAssociationType type = association.getType();
				if (type != matchType) {
					continue;
				}
				Address sourceAddr = association.getSourceAddress();
				SymbolTable symbolTable = sourceProgram.getSymbolTable();
				Symbol primarySymbol = symbolTable.getPrimarySymbol(sourceAddr);
				String name = primarySymbol.getName(false);
				if (name.equals(sourceLabel)) {
					return vtMatch;
				}
			}
		}
		return null;
	}

	private void replaceMarkup(VTMatch match, String markupSourceAddress, String markupType) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			Address itemSourceAddress = vtMarkupItem.getSourceAddress();
			VTMarkupType itemMarkupType = vtMarkupItem.getMarkupType();
			if (itemSourceAddress.toString(false).equals(markupSourceAddress) &&
				itemMarkupType.getDisplayName().equals(markupType)) {
				ToolOptions options = new ToolOptions(VTController.VERSION_TRACKING_OPTIONS_NAME);
				AbstractFunctionSignatureMarkupTest.setApplyMarkupOptionsToReplace(options);
				List<VTMarkupItem> markupItems = new ArrayList<>();
				markupItems.add(vtMarkupItem);
				runApplyMarkupTask(markupItems, options);
				break;
			}
		}
	}

	private void addMarkup(VTMatch match, String markupSourceAddress, String markupType) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			Address itemSourceAddress = vtMarkupItem.getSourceAddress();
			VTMarkupType itemMarkupType = vtMarkupItem.getMarkupType();
			if (itemSourceAddress.toString(false).equals(markupSourceAddress) &&
				itemMarkupType.getDisplayName().equals(markupType)) {
				ToolOptions options = new ToolOptions(VTController.VERSION_TRACKING_OPTIONS_NAME);
				AbstractFunctionSignatureMarkupTest.setApplyMarkupOptionsToAdd(options);
				List<VTMarkupItem> markupItems = new ArrayList<>();
				markupItems.add(vtMarkupItem);
				runApplyMarkupTask(markupItems, options);
				break;
			}
		}
	}

	private void tagMarkup(VTMarkupItemConsideredStatus status, VTMatch match,
			String markupSourceAddress, String markupType) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			Address itemSourceAddress = vtMarkupItem.getSourceAddress();
			VTMarkupType itemMarkupType = vtMarkupItem.getMarkupType();
			if (itemSourceAddress.toString(false).equals(markupSourceAddress) &&
				itemMarkupType.getDisplayName().equals(markupType)) {
				List<VTMarkupItem> markupItems = new ArrayList<>();
				markupItems.add(vtMarkupItem);
				runTagMarkupTask(markupItems, status);
			}
		}
	}

	private void runApplyMarkupTask(List<VTMarkupItem> markupItems, ToolOptions options) {

		waitForBusyTool(vtTestEnv.getTool());
		Msg.debug(this, "runTask(): Apply markup item(s)\n\n");

		ApplyMarkupItemTask task =
			new ApplyMarkupItemTask(controller.getSession(), markupItems, options);
		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task t) {
				controller.refresh();
			}

			@Override
			public void taskCancelled(Task t) {
				// don't care; nothing to do
			}
		});
		controller.runVTTask(task);

		waitForSwing();
		destinationProgram.flushEvents();
		Msg.debug(this, "\tdone task: Apply markup item(s)\n\n");
	}

	private void runTagMarkupTask(List<VTMarkupItem> markupItems,
			VTMarkupItemConsideredStatus status) {

		waitForBusyTool(vtTestEnv.getTool());
		Msg.debug(this, "runTask(): " + status.name() + " markup item(s)\n\n");

		TagMarkupItemTask task = new TagMarkupItemTask(session, markupItems, status);
		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task t) {
				controller.refresh();
			}

			@Override
			public void taskCancelled(Task t) {
				// don't care; nothing to do
			}
		});
		controller.runVTTask(task);

		waitForSwing();
		destinationProgram.flushEvents();
		Msg.debug(this, "\tdone task: " + status.name() + " markup item(s)\n\n");
	}

	@SuppressWarnings("unused")
	private boolean selectRow(GhidraTable markupItemsTable,
			VTMarkupItemsTableModel markupItemsTableModel, int sourceAddressColumn,
			String sourceAddressValue, int markupTypeColumn, String markupTypeValue) {
		int rowCount = markupItemsTableModel.getRowCount();
		for (int row = 0; row < rowCount; row++) {
			Object sourceAddressObject = markupItemsTableModel.getValueAt(row, sourceAddressColumn);
			DisplayableListingAddress sourceAddr = (DisplayableListingAddress) sourceAddressObject;
			Object markupTypeObject = markupItemsTableModel.getValueAt(row, markupTypeColumn);
			String markupType = (String) markupTypeObject;
			if (sourceAddressValue.equals(sourceAddr.getDisplayString()) &&
				markupTypeValue.equals(markupType)) {
				markupItemsTable.selectRow(row);
				return true;
			}
		}
		return false;
	}

	private void selectMatch(final String sourceLabel) {
		waitForSwing();
		Window window = waitForWindowByTitleContaining("Test Tool");
		assertNotNull(window);
		VTMatchTableProvider matchTableProvider =
			waitForComponentProvider(VTMatchTableProvider.class);
		final GhidraTable matchesTable =
			(GhidraTable) getInstanceField("matchesTable", matchTableProvider);
		final TableModel model = matchesTable.getModel();
		int sourceLabelColumn = -1;
		int columnCount = model.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
			String columnName = model.getColumnName(i);
			if (columnName.equals("Source Label")) {
				sourceLabelColumn = i;
				break;
			}
		}
		Assert.assertNotEquals("Couldn't find Source Label column.", -1, sourceLabelColumn);

		final int column = sourceLabelColumn;
		runSwing(() -> {
			boolean setSelectedRow = false;
			int rowCount = model.getRowCount();
			for (int i = 0; i < rowCount; i++) {
				Object valueObject = model.getValueAt(i, column);
				DisplayableLabel currentSourceLabel = (DisplayableLabel) valueObject;
				if (currentSourceLabel.getDisplayString().equals(sourceLabel)) {
					matchesTable.selectRow(i);
					matchesTable.scrollToSelectedRow();
					setSelectedRow = true;
					break;
				}
			}
			assertEquals("Couldn't select row containing " + sourceLabel + ".", true,
				setSelectedRow);
		});
		waitForSwing();
	}

	private void hideDualListing(Class<? extends ComponentProvider> clazz) {

		ComponentProvider provider = getProvider(clazz);

		dualListingIsVisible(provider);

		ToggleDockingAction action =
			(ToggleDockingAction) getLocalAction(provider, "Toggle Dual Listing Visibility");
		assertNotNull(action);
		setToggleActionSelected(action, new ActionContext(), false);
		waitForSwing();
		waitForCondition(() -> !dualListingIsVisible(provider));
	}

	private boolean dualListingIsVisible(ComponentProvider provider) {

		JComponent component = provider.getComponent();
		Component listingComponent =
			findComponentByName(component, ListingCodeComparisonPanel.NAME);
		if (listingComponent == null) {
			return false; // not in the parent's hierarchy
		}

		return listingComponent.isShowing();
	}

	private DockingActionIf setDualListingVertical(Class<? extends ComponentProvider> clazz) {

		return setDualListingLayout(clazz, true);
	}

	private DockingActionIf setDualListingHorizontal(Class<? extends ComponentProvider> clazz) {

		return setDualListingLayout(clazz, false);
	}

	private DockingActionIf setDualListingLayout(Class<? extends ComponentProvider> clazz,
			boolean vertical) {
		ComponentProvider provider = getProvider(clazz);
		assertNotNull(provider);

		ToggleDockingAction action =
			(ToggleDockingAction) getLocalAction(provider, "Dual Listing Toggle Orientation");
		assertNotNull(action);
		setToggleActionSelected(action, new ActionContext(), vertical);
		waitForSwing();
		return action;
	}

	private DockingActionIf toggleDualListingHeader(Class<? extends ComponentProvider> clazz,
			boolean showing) {

		ComponentProvider provider = getProvider(clazz);
		assertNotNull(provider);

		ToggleDockingAction action =
			(ToggleDockingAction) getLocalAction(provider, "Dual Listing Toggle Header");
		assertNotNull(action);
		setToggleActionSelected(action, new ActionContext(), showing);
		waitForSwing();
		return action;
	}

	private void setupVTWizardAddToSessionPanel() throws Exception {
		setupVTWizardSelectAddressRangesPanel();
		pressNextButtonWhenEnabled();
	}

	private void setupVTWizardSelectAddressRangesPanel() throws Exception {
		setupVTWizardAddressSetOptionsPanel();
		pressNextButtonWhenEnabled();

		DialogComponentProvider dialog = getDialog();
		LimitAddressSetsPanel panel = findComponent(dialog, LimitAddressSetsPanel.class);
		AddressSetPanel destinationPanel =
			(AddressSetPanel) getInstanceField("destinationPanel", panel);
		ChooseAddressSetEditorPanel choosePanel =
			findComponent(destinationPanel, ChooseAddressSetEditorPanel.class);
		JRadioButton myRangesButton =
			(JRadioButton) getInstanceField("myRangesButton", choosePanel);
		pressButton(myRangesButton);
	}

	private void setupVTWizardAddressSetOptionsPanel() throws Exception {
		setupVTWizardOptionsPanel();
		pressNextButtonWhenEnabled();

		DialogComponentProvider dialog = getDialog();
		AddressSetOptionsPanel panel = findComponent(dialog, AddressSetOptionsPanel.class);
		JCheckBox showAddressSetPanelsCheckbox =
			(JCheckBox) getInstanceField("showAddressSetPanelsCheckbox", panel);
		showAddressSetPanelsCheckbox.setSelected(true);
	}

	private void setupVTWizardOptionsPanel() throws Exception {
		setupVTWizardCorrelatorPanel();
		DialogComponentProvider dialog = getDialog();
		CorrelatorPanel correlatorPanel = findComponent(dialog, CorrelatorPanel.class);
		VTProgramTableCorrelatorModel model =
			(VTProgramTableCorrelatorModel) getInstanceField("model", correlatorPanel);
		model.setValueAt(true, 1, 0);// Set "Exact Function Bytes Match" to selected.
		model.fireTableDataChanged();
		waitForSwing();
		pressNextButtonWhenEnabled();
	}

	private void setupVTWizardCorrelatorPanel() throws Exception {
		tool = vtTool;
		DockingActionIf dockingAction = getAction(vtPlugin, "Add To Session");
		performAction(dockingAction, false);
		waitForSwing();
	}

	private void setupVTWizardSummaryPanel() throws Exception {
		setupVTWizardPreconditionsPanel();
		pressNextButtonWhenEnabled();
	}

	private void tryToWaitForNextButtonToEnable() {
		Container container = getDialog().getComponent();
		String buttonText = "Next >>";
		AbstractButton button = findAbstractButtonByText(container, buttonText);
		for (int i = 0; i < 100; i++) {
			if (button.isEnabled()) {
				break;
			}
			sleep(20);
		}
	}

	private void pressNextButtonWhenEnabled() throws UsrException {
		Container container = getDialog().getComponent();
		String buttonText = "Next >>";
		AbstractButton button = findAbstractButtonByText(container, buttonText);
		for (int i = 0; i < 100; i++) {
			if (button.isEnabled()) {
				break;
			}
			sleep(20);
		}
		if (button == null) {
			throw new UsrException("Couldn't find button " + buttonText + ".");
		}
		if (!button.isShowing()) {
			throw new UsrException("Button " + buttonText + " is not showing.");
		}
		if (!button.isEnabled()) {
			throw new UsrException("Button " + buttonText + " is not enabled.");
		}
		pressButton(button, true);
		waitForSwing();
	}

	private void setupVTWizardPreconditionsPanel() throws UsrException, FileNotFoundException {
		setupVTWizardSessionPanel();
		pressNextButtonWhenEnabled();
		pressButtonByText(getDialog(), "Run Precondition Checks", true);
		waitForBusyTool(vtTool);
		tryToWaitForNextButtonToEnable();
		waitForSwing();
	}

	private void setupVTWizardSessionPanel() throws FileNotFoundException {
		vtTestEnv.restoreProgram("VersionTracking/WallaceSrc");
		vtTestEnv.restoreProgram("VersionTracking/WallaceVersion2");
		tool = vtTool;
		DockingActionIf dockingAction = getAction(vtPlugin, "Create New Session");
		performAction(dockingAction, false);
		pressButtonByText(getDialog(), "Yes");
		pressButtonByText(getDialog(), "Don't Save");

		JComponent dialogComponent = getDialog().getComponent();
		// Fill in the Version Tracking Wizard panel.

		// Set the Source
		chooseProjectFile(dialogComponent, "SOURCE_BUTTON",
			new String[] { "git_DevTestProject", "WallaceSrc" });

		// Set the Destination
		chooseProjectFile(dialogComponent, "DESTINATION_BUTTON",
			new String[] { "git_DevTestProject", "WallaceVersion2" });
		waitForSwing();
	}

	private void chooseProjectFile(JComponent dialogComponent, String buttonName,
			String[] treePath) {
		pressButtonByName(dialogComponent, buttonName, false);
		DataTreeDialog dataTreeDialog = (DataTreeDialog) getDialog(DataTreeDialog.class);
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dataTreeDialog);
		DataTree tree = (DataTree) getInstanceField("tree", treePanel);
		assertNotNull(tree);
		selectPath(tree, treePath);
		pressButtonByText(dataTreeDialog, "OK");
	}
}
