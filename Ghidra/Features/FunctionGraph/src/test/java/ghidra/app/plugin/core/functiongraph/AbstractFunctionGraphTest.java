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
package ghidra.app.plugin.core.functiongraph;

import static ghidra.graph.viewer.GraphViewerUtils.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.datatransfer.*;
import java.awt.geom.Point2D;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.action.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.test.AbstractDockingTest;
import docking.widgets.EventTrigger;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.MultiLineInputDialog;
import docking.widgets.fieldpanel.FieldPanel;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationModel;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.picking.PickedState;
import generic.test.AbstractGenericTest;
import generic.test.TestUtils;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.clipboard.ClipboardPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.services.*;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.format.*;
import ghidra.app.util.viewer.format.actions.AddFieldAction;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.options.RelayoutOption;
import ghidra.graph.viewer.options.ViewRestoreOption;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.*;
import ghidra.util.Msg;
import ghidra.util.task.RunManager;

public abstract class AbstractFunctionGraphTest extends AbstractGhidraHeadedIntegrationTest {

	protected static final Transferable DUMMY_TRANSFERABLE = new DummyTransferable();

	protected PluginTool tool;
	protected FunctionGraphPlugin graphPlugin;
	protected ProgramDB program;
	protected TestEnv env;
	protected FGProvider graphProvider;
	protected CodeBrowserPlugin codeBrowser;

	protected String startAddressString = "0100415a";// sscanf

	protected List<String> functionAddrs = new ArrayList<>();

	@Before
	public void setUp() throws Exception {

		setErrorGUIEnabled(false);

		env = getEnv();
		tool = env.getTool();

		initializeTool();

		hideSatellite();
	}

	protected void setZoomOutOption(boolean zoomedOut) throws Exception {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();

		ViewRestoreOption restoreOption = null;
		if (zoomedOut) {
			restoreOption = ViewRestoreOption.START_FULLY_ZOOMED_OUT;
		}
		else {
			restoreOption = ViewRestoreOption.START_FULLY_ZOOMED_IN;
		}

		setInstanceField("viewRestoreOption", options, restoreOption);

		performReload();
	}

	protected TestEnv getEnv() throws Exception {
		return new TestEnv();
	}

	protected void initializeTool() throws Exception {
		installPlugins();

		openProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		showTool(tool);

		showFunctionGraphProvider();

		goToAddress(getStartingAddress());

		// make sure the default case is always set in the testing environment
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		setInstanceField("relayoutOption", options, RelayoutOption.VERTEX_GROUPING_CHANGES);
	}

	protected void openProgram() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("sample", true);
		builder.createMemory("sscanf", "0x0100415a", 80);
		builder.createMemory("ghidra", "0x01002cf5", 121);
		builder.createMemory("simple", "0x01002239", 8);
		builder.createMemory("foo", "0x01002339", 2);

		functionAddrs.add("0x0100415a");
		functionAddrs.add("0x01002cf5");
		functionAddrs.add("0x01002239");
		functionAddrs.add("0x01002339");

		build_sscanf(builder);
		build_ghidra(builder);
		buildSimpleFunction(builder);
		buildFoo(builder);

		program = builder.getProgram();
//		program = env.getProgram(getStartingProgramName());
	}

	private void buildSimpleFunction(ToyProgramBuilder builder) throws MemoryAccessException {
		// just a function to render in the graph so that we can clear out settings/cache
		// 01002239

		/*
		
		 A
		 |->B
		 C
		
		
		 */

		// A
		builder.addBytesNOP("0x01002239", 1);
		builder.addBytesBranchConditional("0x0100223a", "0x0100223e");// jump to C

		// B
		builder.addBytesNOP("0x0100223c", 1);
		builder.addBytesNOP("0x0100223d", 1);// fallthrough to C

		// C
		builder.addBytesNOP("0x0100223e", 1);
		builder.addBytesReturn("0x0100223f");

		builder.disassemble("0x01002239", 8, true);
		builder.createFunction("0x01002239");
		builder.createLabel("0x01002239", "simple");// function label
	}

	/**
	 * Added this method for cache testing.  No blocks were needed, just needed another
	 * function to have enough to test a function being removed from the cache.
	 */
	private void buildFoo(ToyProgramBuilder builder) throws MemoryAccessException {
		builder.addBytesReturn("0x01002339");

		builder.disassemble("0x01002339", 1, true);
		builder.createFunction("0x01002339");
		builder.createLabel("0x01002339", "foo");// function label
	}

	private void build_ghidra(ToyProgramBuilder builder) throws MemoryAccessException {
		/*
		 Originally from notepad 'ghidra'
		
		 	A
		 	|->	B
		 	|-> C
		 	|
		 	D
		 	|
		 	E
		 	|-> F
		 	|->	G
		 	|
		 	H
		
		 */

		// A -
		// 1002cf5
		builder.addBytesNOP("0x01002cf5", 1);
		builder.addBytesNOP("0x01002cf6", 2);
		builder.addBytesNOP("0x01002cf8", 4);
		builder.addBytesNOP("0x01002cfc", 1);
		builder.addBytesNOP("0x01002cfd", 6);
		builder.addBytesNOP("0x01002d03", 1);
		builder.addBytesBranchConditional("0x01002d04", "0x01002d0f");// jump to B

		// C
		// 1002d06
		builder.addBytesNOP("0x01002d06", 3);
		builder.addBytesNOP("0x01002d09", 2);
		builder.addBytesNOP("0x01002d0b", 2);
		builder.addBytesBranch("0x01002d0d", "0x01002d11");// jump to D

		// B
		// 1002d0f
		builder.addBytesNOP("0x01002d0f", 2);// fallthrough to D

		// D
		// 1002d11
		builder.addBytesNOP("0x01002d11", 3);
		builder.addBytesNOP("0x01002d14", 2);
		builder.addBytesNOP("0x01002d16", 2);
		builder.addBytesNOP("0x01002d18", 4);
		builder.addBytesNOP("0x01002d1c", 1);
		builder.addBytesNOP("0x01002d1d", 2);// fallthrough to E

		// E
		// 1002d1f
		builder.addBytesNOP("0x01002d1f", 6);
		builder.addBytesNOP("0x01002d25", 2);
		builder.addBytesNOP("0x01002d27", 2);
		builder.addBytesBranchConditional("0x01002d29", "0x01002d52");// jump to F

		// G
		// 1002d2b
		builder.addBytesNOP("0x01002d2b", 1);
		builder.addBytesNOP("0x01002d2c", 3);
		builder.addBytesNOP("0x01002d2f", 3);
		builder.addBytesNOP("0x01002d32", 5);
		builder.addBytesNOP("0x01002d37", 3);
		builder.addBytesNOP("0x01002d3a", 3);
		builder.addBytesNOP("0x01002d3d", 1);
		builder.addBytesNOP("0x01002d3e", 3);
		builder.addBytesNOP("0x01002d41", 6);
		builder.addBytesNOP("0x01002d47", 1);
		builder.addBytesNOP("0x01002d48", 2);
		builder.addBytesNOP("0x01002d4a", 6);
		builder.addBytesBranch("0x01002d50", "0x01002d66");// jump to H

		// F
		// 1002d52
		builder.addBytesNOP("0x01002d52", 3);
		builder.addBytesNOP("0x01002d55", 3);
		builder.addBytesNOP("0x01002d58", 3);
		builder.addBytesNOP("0x01002d5b", 3);
		builder.addBytesNOP("0x01002d5e", 6);
		builder.addBytesNOP("0x01002d64", 2);// fallthrough to H

		// H
		// 1002d66
		builder.addBytesNOP("0x01002d66", 2);
		builder.addBytesNOP("0x01002d68", 1);
		builder.addBytesNOP("0x01002d69", 1);
		builder.addBytesNOP("0x01002d6a", 1);
		builder.addBytesReturn("0x01002d6b");

		builder.disassemble("0x01002cf5", 121, true);

		//
		//
		//
		builder.createLabel("0x01002cf5", "ghidra");// function label
		builder.createLabel("0x01002d1f", "MyLocal");// user labels (these create code blocks)
		builder.createLabel("0x01002d2b", "AnotherLocal");// user labels (these create code blocks)
		builder.createFunction("0x01002cf5");
	}

	private void build_sscanf(ToyProgramBuilder builder) throws MemoryAccessException {
		/*
		 Originally from notepad 'sscanf'
		
		 	A
		 	|->	B
		 	|
		 	C
		 	|-> D
		 	|	|-> E
		 	|
		 	F
		 	|
		 	G
		
		 */

		// A - 9 code units
		builder.addBytesNOP("0x0100415a", 1);
		builder.addBytesNOP("0x0100415b", 2);
		builder.addBytesNOP("0x0100415d", 3);
		builder.addBytesNOP("0x01004160", 2);
		builder.addBytesNOP("0x01004162", 7);
		builder.addBytesNOP("0x01004169", 3);
		builder.addBytesNOP("0x0100416c", 3);
		builder.addBytesNOP("0x0100416f", 7);
		builder.addBytesBranchConditional("0x01004176", "0x01004192");// jump to C

		// B - 10 code units (fallthrough from A)
		// 0x01004178
		builder.addBytesNOP("0x01004178", 3);
		builder.addBytesNOP("0x0100417b", 1);
		builder.addBytesNOP("0x0100417c", 3);
		builder.addBytesNOP("0x0100417f", 1);
		builder.addBytesNOP("0x01004180", 3);
		builder.addBytesNOP("0x01004183", 1);
		builder.addBytesNOP("0x01004184", 2);
		builder.addBytesNOP("0x01004186", 3);
		builder.addBytesNOP("0x01004189", 3);
		builder.addBytesNOP("0x0100418c", 6);// was a call

		// C - 2 code units
		// 0x01004192
		builder.addBytesNOP("0x01004192", 2);
		builder.addBytesBranchConditional("0x01004194", "0x0100419c");// jump to F

		// D - 2 code units (fallthrough from C)
		// 0x01004196
		builder.addBytesNOP("0x01004196", 4);
		builder.addBytesBranchConditional("0x0100419a", "0x010041a1");// jump to E

		// F - 2 code unit
		// 0x0100419c
		builder.addBytesNOP("0x0100419c", 3);
		builder.addBytesBranch("0x0100419f", "0x010041a4");// jump to G

		// E - 1 code units
		// 0x010041a1
		builder.addBytesNOP("0x010041a1", 3);

		// G - 2 code units
		// 0x010041a4
		builder.addBytesNOP("0x010041a4", 1);
		builder.addBytesReturn("0x010041a5");

		builder.disassemble("0x0100415a", 80, true);

		//
		//
		//
		builder.createLabel("0x0100415a", "sscanf");
		builder.createFunction("0x0100415a");
	}

	protected String getStartingProgramName() {
		return "notepad";
	}

	protected String getStartingAddress() {
		return startAddressString;
	}

	protected void installPlugins() throws PluginException {
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(FunctionGraphPlugin.class.getName());

		graphPlugin = env.getPlugin(FunctionGraphPlugin.class);
		codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
	}

	@After
	public void tearDown() throws Exception {
		waitForSwing();
		env.closeTool(tool);
		env.dispose();
	}

//==================================================================================================
// protected methods
//==================================================================================================

	protected Point2D getLocation(FGVertex vertex) {
		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> primaryGraphViewer = view.getPrimaryGraphViewer();
		VisualizationModel<FGVertex, FGEdge> model = primaryGraphViewer.getModel();
		Layout<FGVertex, FGEdge> graphLayout = model.getGraphLayout();
		return graphLayout.apply(vertex);
	}

	protected boolean pointsAreSimilar(Point2D originalPoint, Point2D reloadedPoint) {
		double xDiff = Math.abs(originalPoint.getX() - reloadedPoint.getX());
		if (xDiff > 20) {
			return false;
		}

		double yDiff = Math.abs(originalPoint.getY() - reloadedPoint.getY());
		if (yDiff > 20) {
			return false;
		}

		return true;
	}

	protected Address getAddress(String addressString) {
		AddressFactory factory = program.getAddressFactory();
		return factory.getAddress(addressString);
	}

	protected ProgramLocation getLocationForAddressString(String addressString) {
		Address address = getAddress(addressString);
		return new ProgramLocation(program, address);
	}

	protected void goToAddress(String addressString) {
		ProgramLocation location = getLocationForAddressString(addressString);
		codeBrowser.goTo(location, true);

		waitForSwing();
		waitForBusyGraph();
	}

	protected void performRelayout() {
		long start = System.currentTimeMillis();
		Object actionManager = getInstanceField("actionManager", graphProvider);
		final MultiStateDockingAction<?> action =
			(MultiStateDockingAction<?>) getInstanceField("layoutAction", actionManager);
		runSwing(() -> action.actionPerformed(new ActionContext()));

		// wait for the threaded graph layout code
		FGController controller = getFunctionGraphController();
		waitForBusyRunManager(controller);
		waitForAnimation();
		getPrimaryGraphViewer().repaint();
		waitForSwing();

		long end = System.currentTimeMillis();
		Msg.debug(this, "relayout time: " + ((end - start) / 1000.0) + "s");
	}

	protected void performReload() throws Exception {

		String name = "Reset Graph";

		DockingActionIf action = getAction(tool, graphPlugin.getName(), name);
		long start = System.currentTimeMillis();

		performAction(action, false);

		Window window = waitForWindow("Reset Graph?");
		pressButtonByText(window, "Yes");

		// wait for the threaded graph layout code
		FGController controller = getFunctionGraphController();
		waitForBusyRunManager(controller);
		waitForAnimation();
		getPrimaryGraphViewer().repaint();
		waitForSwing();

		long end = System.currentTimeMillis();
		Msg.debug(this, "reload time: " + ((end - start) / 1000.0) + "s");
	}

	protected FGData getFunctionGraphData() {
		FGController controller = getFunctionGraphController();
		waitForBusyRunManager(controller);
		waitForAnimation();// just in case we have any restoring animations working
		return (FGData) TestUtils.getInstanceField("functionGraphData", controller);
	}

	protected FunctionGraph getFunctionGraph() {
		FGData functionGraphData = getFunctionGraphData();
		return functionGraphData.getFunctionGraph();
	}

	protected FGController getFunctionGraphController() {
		return (FGController) TestUtils.getInstanceField("controller", graphProvider);
	}

	protected FGComponent getGraphComponent() {
		FGController controller =
			(FGController) TestUtils.getInstanceField("controller", graphProvider);
		FGView view = (FGView) TestUtils.getInstanceField("view", controller);
		return (FGComponent) TestUtils.getInstanceField("fgComponent", view);
	}

	protected FGPrimaryViewer getPrimaryGraphViewer() {
		FGComponent component = getGraphComponent();
		if (component == null) {
			return null; // this will be null if the graph has been disposed
		}

		assertNotNull("FG GraphComponent should not be null", component);
		return (FGPrimaryViewer) getInstanceField("primaryViewer", component);
	}

	protected Layout<FGVertex, FGEdge> getPrimaryLayout() {
		FGPrimaryViewer primaryViewer = getPrimaryGraphViewer();
		return primaryViewer.getGraphLayout();
	}

	/**
	 * Waits for the run manager and any animation.
	 */
	protected void waitForBusyGraph() {
		waitForBusyRunManager(getFunctionGraphController());
		waitForAnimation();
	}

	protected void waitForBusyRunManager(FGController controller) {
		FGModel model = controller.getModel();

		long start = System.nanoTime();
		waitForSwing();
		RunManager runManager = (RunManager) TestUtils.getInstanceField("runManager", model);

		waitForCondition(() -> !runManager.isInProgress());
		long end = System.nanoTime();
		long total = end - start;
//		Msg.debug(this,
//			"Run manager wait time: " + TimeUnit.MILLISECONDS.convert(total, TimeUnit.NANOSECONDS));
	}

	protected void showFunctionGraphProvider() {

		ComponentProvider provider = tool.getComponentProvider("Function Graph");
		tool.showComponentProvider(provider, true);

		graphProvider = waitForComponentProvider(FGProvider.class);
		assertNotNull("Graph not shown", graphProvider);
	}

	protected ProgramSelection makeSingleVertexSelectionInCodeBrowser() {
		codeBrowser.goToField(getAddress(startAddressString), "Bytes", 0, 4);
		codeBrowser.updateNow();

		Address from = getAddress(startAddressString);
		Address to = getAddress("0x1004168");
		ProgramSelection selection = new ProgramSelection(from, to);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));
		waitForSwing();
		return selection;
	}

	protected ProgramSelection makeMultiVertexSelectionInCodeBrowser() {

		codeBrowser.goToField(getAddress("0x01004192"), "Bytes", 0, 0, 4, true);
		codeBrowser.updateNow();

		Address from = getAddress("0x01004192");
		Address to = getAddress("0x01004199");
		ProgramSelection selection = new ProgramSelection(from, to);
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));
		waitForSwing();
		return selection;
	}

	protected void assertPointsAreAboutEqual(String message, Point primaryPoint, Point clonePoint) {
		int x1 = primaryPoint.x;
		int x2 = clonePoint.x;

		int xDiff = Math.abs(x1 - x2);
		if (xDiff != 0 && xDiff != 1) {
			Assert.fail(message + ": x value for points is not the same");
		}

		int y1 = primaryPoint.y;
		int y2 = clonePoint.y;

		int yDiff = Math.abs(y1 - y2);
		if (yDiff != 0 && yDiff != 1) {
			Assert.fail(message + ": y value for points is not the same");
		}
	}

	protected void addBytesFormatFieldFactory() throws Exception {

		showFormatAndExecuteAction("Instruction/Data", "Bytes", true);
	}

	protected void showFormatAndExecuteAction(String tabName, String actionName,
			boolean waitForAction) throws Exception {

		SetFormatDialogComponentProvider provider = showFormatEditor();

		selectFormatTab(provider, tabName);

		assertField(provider, actionName, false);

		DockingActionIf action = getFormatAction(provider, tabName, actionName);
		assertNotNull(action);

		FieldHeaderLocation fhLoc = createFieldHeaderLocation(provider);
		ActionContext context = createContext(fhLoc);
		performAction(action, context, true);

		waitForConditionWithoutFailing(() -> fieldIsVisible(provider, actionName));

		assertTrue(actionName + " field was not added to the model",
			fieldIsVisible(provider, actionName));

		JButton OKButton = findButtonByText(provider, "OK");
		pressButton(OKButton);
	}

	private DockingActionIf getFormatAction(SetFormatDialogComponentProvider provider,
			String formatName, String actionName) {

		Set<DockingActionIf> actions = provider.getActions();
		for (DockingActionIf action : actions) {
			if (!action.getName().equals(actionName)) {
				continue;
			}

			if (!(action instanceof AddFieldAction)) {
				continue;
			}

			FieldFormatModel formatModel =
				(FieldFormatModel) getInstanceField("formatModel", action);
			String name = formatModel.getName();
			if (name.equals(formatName)) {
				return action;
			}
		}

		fail("Unable to find action '" + actionName + "' in format model '" + formatName + "'");
		return null;
	}

	private void assertField(SetFormatDialogComponentProvider provider, String name,
			boolean shouldExist) {

		if (shouldExist) {
			assertTrue("Field '" + name + "' is not in the model, but it should be",
				fieldIsVisible(provider, name));
		}
		else {
			assertFalse("Field '" + name + "' is in the model, but it should not be",
				fieldIsVisible(provider, name));
		}
	}

	private boolean fieldIsVisible(SetFormatDialogComponentProvider provider, String name) {
		FieldHeader headerPanel = provider.getFieldHeader();
		FieldHeaderComp fieldHeaderComp = headerPanel.getHeaderTab();
		FieldFormatModel model = fieldHeaderComp.getModel();

		FieldFactory[] unused = model.getUnusedFactories();
		for (FieldFactory ff : unused) {
			if (ff.getFieldName().equals(name)) {
				return false; // field is hidden/unused
			}
		}

		// sanity check
		FieldFactory[] visible = model.getAllFactories();
		for (FieldFactory ff : visible) {
			if (ff.getFieldName().equals(name)) {
				return true; // visible
			}
		}

		fail("Field '" + name + "' + is not in the model at all, hidden or visible!");
		return false; // can't get here
	}

	private void selectFormatTab(SetFormatDialogComponentProvider provider, String tabName) {

		ListingPanel listingPanel = (ListingPanel) getInstanceField("listingPanel", provider);
		FieldHeader header = (FieldHeader) getInstanceField("headerPanel", listingPanel);

		FieldFormatModel model = null;
		FormatManager manager = (FormatManager) getInstanceField("formatManager", listingPanel);
		for (int i = 0; i < manager.getNumModels(); i++) {
			FieldFormatModel formatModel = manager.getModel(i);
			String name = formatModel.getName();
			if (name.equals(tabName)) {
				model = formatModel;
				break;
			}
		}
		assertNotNull("Could not find format '" + tabName + "'", model);

		int index = header.indexOfTab(tabName);
		runSwing(() -> header.setSelectedIndex(index));

		waitForCondition(() -> header.getSelectedIndex() == index);
	}

	protected void performResetFormatAction() {
		SetFormatDialogComponentProvider provider = showFormatEditor();

		DockingActionIf action = getAction(provider, "Reset All Formats");
		assertNotNull(action);

		FieldHeaderLocation fhLoc = createFieldHeaderLocation(provider);
		ActionContext context = createContext(fhLoc);
		performAction(action, context, false);

		Window dialog = waitForWindow("Reset All Formats?");
		JButton continueButton = findButtonByText(dialog, "Continue");
		pressButton(continueButton);

		JButton OKButton = findButtonByText(provider, "OK");
		pressButton(OKButton);
		waitForSwing();
	}

	private FieldHeaderLocation createFieldHeaderLocation(
			SetFormatDialogComponentProvider provider) {
		FieldHeader headerPanel = provider.getFieldHeader();
		FieldHeaderComp fieldHeaderComp = headerPanel.getHeaderTab();
		FieldFormatModel model = fieldHeaderComp.getModel();

		int row = 1;
		int col = 0;
		FieldFactory factory = model.getFactorys(row)[col];
		return new FieldHeaderLocation(model, factory, row, col);
	}

	private SetFormatDialogComponentProvider showFormatEditor() {

		DockingActionIf formatAction = getAction(graphPlugin, "Edit Code Block Fields");
		performAction(formatAction, false);

		SetFormatDialogComponentProvider provider =
			waitForDialogComponent(SetFormatDialogComponentProvider.class);
		assertNotNull(provider);
		return provider;
	}

	protected void waitForAnimation() {
		waitForAnimation(graphProvider.getController());
	}

	protected void waitForAnimation(FGController controller) {

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getGraphUpdater();
		if (updater == null) {
			return; // nothing to wait for; no active graph
		}

//		long start = System.nanoTime();

		waitForSwing();

		int tryCount = 3;
		while (tryCount++ < 5 && updater.isBusy()) {
			waitForConditionWithoutFailing(() -> !updater.isBusy());
		}
		waitForSwing();

		assertFalse(updater.isBusy());

//		long end = System.nanoTime();
//		long total = end - start;
//		Msg.debug(this,
//			"Animation wait time: " + TimeUnit.MILLISECONDS.convert(total, TimeUnit.NANOSECONDS));
	}

	@SuppressWarnings("unchecked")
	protected DockingAction getCopyAction() {
		FGController controller = getFunctionGraphController();
		FGProvider provider = controller.getProvider();

		FGClipboardProvider clipboarProvider =
			(FGClipboardProvider) getInstanceField("clipboardProvider", provider);

		ClipboardPlugin clipboardPlugin = getPlugin(tool, ClipboardPlugin.class);
		Map<ClipboardContentProviderService, List<DockingAction>> actionMap =
			(Map<ClipboardContentProviderService, List<DockingAction>>) getInstanceField(
				"serviceActionMap", clipboardPlugin);

		List<DockingAction> list = actionMap.get(clipboarProvider);
		for (DockingAction pluginAction : list) {
			if (pluginAction.getName().equals("Copy")) {
				return pluginAction;
			}
		}
		return null;
	}

	protected void setZoom(final double d) {
		waitForBusyGraph();

		final FGPrimaryViewer primaryGraphViewer = getPrimaryGraphViewer();
		runSwing(() -> GraphViewerUtils.setGraphScale(primaryGraphViewer, d));
		waitForSwing();
	}

	protected VisualGraphViewUpdater<FGVertex, FGEdge> getGraphUpdater() {
		FGPrimaryViewer viewer = getPrimaryGraphViewer();
		if (viewer == null) {
			return null; // this can happen when disposed or not on a function
		}

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = viewer.getViewUpdater();
		assertNotNull(updater);
		return updater;
	}

	protected void setVertexToCenterTop(final FGVertex vertex) {
		waitForBusyGraph();

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getGraphUpdater();
		runSwing(() -> updater.moveVertexToCenterTopWithoutAnimation(vertex));
		waitForSwing();
	}

	protected FGVertex vertex(String address) {
		FGData data = getFunctionGraphData();
		FunctionGraph functionGraph = data.getFunctionGraph();
		FGVertex v = functionGraph.getVertexForAddress(getAddress(address));
		assertNotNull("Unable to locate vertex for address: " + address, v);
		return v;
	}

	protected FGVertex vertex(Address address) {
		FGData data = getFunctionGraphData();
		FunctionGraph functionGraph = data.getFunctionGraph();
		return functionGraph.getVertexForAddress(address);
	}

	protected void closeProvider() {
		closeProvider(graphProvider);
	}

	protected void showProvider() {
		runSwing(() -> graphPlugin.showProvider());
		waitForBusyGraph();
	}

	protected void setProviderAlwaysFocused() {
		Supplier<Boolean> focusDelegate = () -> true;
		runSwing(() -> graphProvider.setFocusStatusDelegate(focusDelegate));
	}

	protected void assertSatelliteVisible(boolean visible) {
		boolean satelliteVisible = isSatelliteVisible();
		if (visible) {
			assertTrue("Satellite is not showing when it should be", satelliteVisible);
		}
		else {
			assertFalse("Satellite is showing when it should be hidden", satelliteVisible);
		}
	}

	protected boolean isSatelliteVisible() {
		return isSatelliteVisible(getFunctionGraphController());
	}

	protected boolean isSatelliteVisible(FGController controller) {

		FGView view = controller.getView();
		GraphComponent<FGVertex, FGEdge, FunctionGraph> gc = view.getGraphComponent();
		if (gc == null) {
			return false;
		}

		// Note: we cannot rely on 'gc.isSatelliteShowing()', as when the application does not
		//       have focus, isShowing() will return false :(
		ComponentProvider satellite = controller.getProvider().getSatelliteProvider();
		boolean satelliteProviderVisible =
			runSwing(() -> satellite != null && satellite.isVisible());

		return runSwing(() -> gc.isSatelliteShowing()) || satelliteProviderVisible;
	}

	protected void showSatellite() {
		if (!isSatelliteVisible()) {
			toggleSatellite();
		}

		assertTrue(isSatelliteVisible());
	}

	protected void hideSatellite() {
		if (isSatelliteVisible()) {
			toggleSatellite();
		}
	}

	private void toggleSatellite() {
		String name = "Display Satellite View";
		DockingActionIf action = getAction(tool, "FunctionGraphPlugin", name);
		ToggleDockingAction dockAction = (ToggleDockingAction) action;
		performAction(dockAction, true);
	}

	protected void undockSatellite() {
		String name = "Dock Satellite View";

		DockingActionIf action = getAction(tool, "FunctionGraphPlugin", name);
		ToggleDockingAction dockAction = (ToggleDockingAction) action;
		assertTrue(name + " action is not selected as expected", dockAction.isSelected());

		performAction(dockAction, true);
	}

	protected void redockSatellite() {
		String name = "Dock Satellite View";

		DockingActionIf action = getAction(tool, "FunctionGraphPlugin", name);
		ToggleDockingAction dockAction = (ToggleDockingAction) action;
		assertFalse(name + " action is not selected as expected", dockAction.isSelected());

		performAction(dockAction, true);
	}

	protected void pressShowSatelliteButton() {
		pressButton(getShowSatelliteButton());
		waitForSwing();
	}

	private JButton getShowSatelliteButton() {
		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		FGComponent graphViewer = (FGComponent) getInstanceField("graphComponent", view);
		return (JButton) getInstanceField("showUndockedSatelliteButton", graphViewer);
	}

	protected void disableAnimation() {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		runSwing(() -> options.setUseAnimation(false));
	}

	protected void zoomInCompletely() {
		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getGraphUpdater();
		runSwing(() -> updater.zoomInCompletely());
	}

	protected void moveViewerLocationWithoutAnimation(Point translation) {
		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getGraphUpdater();
		runSwing(() -> updater.moveViewerLocationWithoutAnimation(translation));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static void accumulateUngroupedIncidentEdges(Graph<FGVertex, FGEdge> graph,
			Set<FGVertex> groupVertices, Set<FGEdge> ungroupedEdges) {

		for (FGVertex vertex : groupVertices) {
			Collection<FGEdge> inEdges = graph.getInEdges(vertex);
			for (FGEdge edge : inEdges) {
				ungroupedEdges.add(edge);
			}

			Collection<FGEdge> outEdges = graph.getOutEdges(vertex);
			for (FGEdge edge : outEdges) {
				ungroupedEdges.add(edge);
			}
		}
	}

	protected GroupedFunctionGraphVertex addToGroup(GroupedFunctionGraphVertex groupedVertex,
			FGVertex... vertices) {

		Set<FGVertex> set = new HashSet<>();
		for (FGVertex vertex : vertices) {
			set.add(vertex);
		}
		return addToGroup(groupedVertex, set);
	}

	protected GroupedFunctionGraphVertex addToGroup(GroupedFunctionGraphVertex groupedVertex,
			Set<FGVertex> newVertices) {

		// select the new vertices along with the group vertex
		HashSet<FGVertex> combined = new HashSet<>(newVertices);
		combined.add(groupedVertex);
		pickVertices(combined);

		// execute the 'add to group' action		
		JComponent component = getComponent(groupedVertex);
		DockingAction action =
			(DockingAction) TestUtils.getInstanceField("addToGroupAction", component);
		performAction(action, graphProvider, false);
		waitForAnimation();

		MultiLineInputDialog dialog = waitForDialogComponent(MultiLineInputDialog.class);

		pressButtonByText(dialog.getComponent(), "OK");

		waitForAnimation();

		FGData data = getFunctionGraphData();
		FunctionGraph functionGraph = data.getFunctionGraph();
		return getGroupVertex(functionGraph, groupedVertex.getVertexAddress());
	}

	protected void assertEdgesAdded(FunctionGraph functionGraph,
			Collection<FGEdge> ungroupedEdges) {
		for (FGEdge edge : ungroupedEdges) {
			//
			// note: the edges we are given *may* be linked to disposed vertices, so we have 
			//       to locate the edge in the graph that may represent the given edge.
			//
			FGEdge currentEdge = getCurrentEdge(functionGraph, edge);
			assertNotNull("No edge for " + edge, currentEdge);
		}
	}

	protected void assertEdgesRemoved(Graph<FGVertex, FGEdge> graph, Collection<FGEdge> edges) {
		for (FGEdge edge : edges) {
			assertFalse("Edge not removed after its vertex was grouped: " + edge,
				graph.containsEdge(edge));
		}
	}

	protected void assertGrouped(FGVertex... vertices) {
		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		FunctionGraph fg = data.getFunctionGraph();

		FGVertex aVertetx = vertices[0];
		GroupedFunctionGraphVertex group = getGroupVertex(fg, aVertetx.getVertexAddress());
		Set<FGVertex> groupVertices = group.getVertices();
		assertEquals(vertices.length, groupVertices.size());
		assertTrue(groupVertices.containsAll(Arrays.asList(vertices)));
	}

	protected void assertGroupText(GroupedFunctionGraphVertex group, String newText) {
		final GroupedFunctionGraphVertex updatedGroup = update(group);
		final AtomicReference<String> reference = new AtomicReference<>();
		runSwing(() -> reference.set(updatedGroup.getUserText()));

		assertEquals(newText, reference.get());
	}

	protected void assertInGroup(FGVertex... vertices) {
		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		FunctionGraph fg = data.getFunctionGraph();

		for (FGVertex v : vertices) {
			// this will fail if v is not in a group
			getGroupVertex(fg, v.getVertexAddress());
		}
	}

	protected void assertNotGrouped(FGVertex... vertices) {
		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		FunctionGraph fg = data.getFunctionGraph();

		for (FGVertex v : vertices) {
			FGVertex vertexAtAddress = fg.getVertexForAddress(v.getVertexAddress());
			assertFalse("Vertex is unexpectedly in a group: " + v,
				vertexAtAddress instanceof GroupedFunctionGraphVertex);
		}
	}

	protected void assertNotUncollapsed(FGVertex... vertices) {
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				// Unusual Code: for some of the regroup actions, group vertices are created and restored,
				//               but are always equal.  Thus, the Function Graph works correctly, but the
				//				 test can get out-of-sync, so we update before we use it
				vertex = getGroupVertex(getFunctionGraph(), vertex.getVertexAddress());
			}

			assertFalse("Vertex is unexpectedly uncollapsed: " + vertex, isUncollapsed(vertex));
		}
	}

	protected void assertSameEdges(String failureMessage, List<String> originalEdgeStrings,
			List<String> newEdgeStrings) {

		List<String> missingFromNew = new ArrayList<>();
		for (String edgeString : originalEdgeStrings) {
			if (!newEdgeStrings.contains(edgeString)) {
				missingFromNew.add(edgeString);
			}
		}

		List<String> newToNew = new ArrayList<>();
		for (String edgeString : newEdgeStrings) {
			if (!originalEdgeStrings.contains(edgeString)) {
				newToNew.add(edgeString);
			}
		}

		StringBuilder buffy = new StringBuilder();
		if (!missingFromNew.isEmpty()) {
			buffy.append("Found edges in the original graph now missing in the new graph:\n");
			for (String string : missingFromNew) {
				buffy.append(string).append('\n');
			}
		}

		if (!newToNew.isEmpty()) {
			buffy.append("Found edges in the new graph not in the original graph:\n");
			for (String string : newToNew) {
				buffy.append(string).append('\n');
			}
		}

		if (buffy.length() != 0) {
			buffy.insert(0, failureMessage + '\n');
			Assert.fail(buffy.toString());
		}
	}

	protected void assertSelected(Collection<FGVertex> vertices) {
		PickedState<FGVertex> pickedState = getPickedState();
		Set<FGVertex> picked = pickedState.getPicked();

		assertEquals(vertices.size(), picked.size());
		for (FGVertex vertex : picked) {
			assertTrue(picked.contains(vertex));
		}
	}

	private void assertSelected(FGVertex... vertices) {
		assertSelected(Arrays.asList(vertices));
	}

	protected void assertUncollapsed(FGVertex... vertices) {
		for (FGVertex vertex : vertices) {
			boolean uncollapsed = isUncollapsed(vertex);
			if (!uncollapsed) {
				Msg.debug(this, "assertUncollapsed(): ");
			}
			assertTrue("Vertex is unexpectedly not uncollapsed: " + vertex, uncollapsed);
		}
	}

	protected void assertVertexRemoved(Graph<FGVertex, FGEdge> graph,
			GroupedFunctionGraphVertex groupedVertex) {
		assertTrue("The grouped vertex was not removed from the graph after ungrouping",
			!graph.containsVertex(groupedVertex));
	}

	protected void assertVerticesAdded(Graph<FGVertex, FGEdge> graph,
			Collection<FGVertex> ungroupedVertices) {

		for (FGVertex vertex : ungroupedVertices) {
			assertTrue("Graph does not contain the ungrouped vertex: " + vertex,
				graph.containsVertex(vertex));
		}
	}

	protected void assertVerticesRemoved(FGVertex... ungroupedVertices) {

		FunctionGraph functionGraph = getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		for (FGVertex vertex : ungroupedVertices) {
			assertTrue("Graph still contains grouped vertex: " + vertex,
				!graph.containsVertex(vertex));
		}
	}

	protected void assertVerticesRemoved(Graph<FGVertex, FGEdge> graph,
			Set<FGVertex> ungroupedVertices) {

		for (FGVertex vertex : ungroupedVertices) {
			assertTrue("Graph still contains grouped vertex: " + vertex,
				!graph.containsVertex(vertex));
		}
	}

	protected void clearCache() {
		final FGController controller = getFunctionGraphController();
		runSwing(() -> controller.invalidateAllCacheForProgram(program));
	}

	protected FGController cloneGraph() {

		DockingActionIf snapshotAction =
			AbstractDockingTest.getAction(tool, graphPlugin.getName(), "Function Graph Clone");
		performAction(snapshotAction, true);

		@SuppressWarnings("unchecked")
		List<FGProvider> disconnectedProviders =
			(List<FGProvider>) getInstanceField("disconnectedProviders", graphPlugin);
		assertEquals(1, disconnectedProviders.size());
		FGProvider providerClone = disconnectedProviders.get(0);
		FGController controllerClone = providerClone.getController();

		waitForBusyRunManager(controllerClone);
		waitForAnimation(controllerClone);

		return controllerClone;
	}

	protected void color(final FGVertex v1, final Color color) {
		runSwing(() -> v1.setBackgroundColor(color));
	}

	protected FGData create12345Graph() {

		//
		// Note: we are manipulating the graph for testing by removing vertices.  Some layouts
		//       do not handle this well, so we will use one we know works.
		//
		setMinCrossLayout();

		// function sscanf
		FGData funtionGraphData = graphFunction("100415a");

		//
		// create labels so that the vertices are 1-5
		//

		// 1 - 100415a
		Address one = createLabel("100415a", "1");

		// 2 - 1004178
		createLabel("1004178", "2");

		// 3 - 1004192
		Address three = createLabel("1004192", "3");

		// 4 - 1004196
		Address four = createLabel("1004196", "4");

		// 5 - 100419c
		Address five = createLabel("100419c", "5");

		//
		// remove edges to create the 1,2,3,4,5 graph our test describes
		//
		FunctionGraph functionGraph = funtionGraphData.getFunctionGraph();

		// remove edge from 1 -> 3
		removeEdge(functionGraph, one, three);

		// remove edge from 4 -> 5
		removeEdge(functionGraph, four, five);

		//
		// remove vertices we don't want too
		//

		// remove 10041a1
		removeVertex(functionGraph, getAddress("10041a1"));

		// remove 10041a4
		removeVertex(functionGraph, getAddress("10041a4"));

		Graph<FGVertex, FGEdge> graph = functionGraph;
		assertEquals(
			"Do not have the expected number of vertices after modifying our test " + "graph", 5,
			graph.getVertexCount());

		return funtionGraphData;
	}

	protected FGData create12345GraphWithTransaction() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			return create12345Graph();
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	protected Address createLabel(String addressString) {
		return createLabel(addressString, testName.getMethodName());
	}

	private Address createLabel(String addressString, String labelName) {
		Address labelAddress = getAddress(addressString);
		AddLabelCmd addCmd = new AddLabelCmd(labelAddress, labelName, SourceType.USER_DEFINED);
		addCmd.applyTo(program);
		program.flushEvents();

		SetLabelPrimaryCmd primaryCmd = new SetLabelPrimaryCmd(labelAddress, labelName, null);
		primaryCmd.applyTo(program);
		program.flushEvents();

		waitForSwing();
		waitForAnimation();
		return labelAddress;
	}

	//
	// TODO:  I have changed the groups such that you can group a single node, which lets you
	//        replace the view of the node with user-defined text.
	//
	//	      This tests verifies that a group will not be created if there is only one vertex
	//        found upon restoring settings.  If we want to put that code back, then this test
	//        is again valid.
	// 
	public void dontTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup();
		}
		finally {
			program.endTransaction(transactionID, false);
		}
	}

	protected void doTestAddingToGroup() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Collection<FGEdge> originalEdges = graph.getEdges();

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());

		group(ungroupedVertices);

		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		// -1 because one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		//
		// Pick another vertex to add to the current group
		//
		Set<FGVertex> newUngroupedVertices =
			selectVertices(functionGraph, "01002d66" /* LAB_01002d66 */);
		Set<FGEdge> newUngroupedEdges = getEdges(graph, newUngroupedVertices);

		addToGroup(groupedVertex, newUngroupedVertices);

		assertVerticesRemoved(graph, newUngroupedVertices);
		assertEdgesRemoved(graph, newUngroupedEdges);

		expectedGroupedEdgeCount = 3;
		GroupedFunctionGraphVertex updatedGroupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		Assert.assertNotEquals(groupedVertex, updatedGroupedVertex);
		Set<FGVertex> originalVertices = groupedVertex.getVertices();
		Set<FGVertex> newVertices = updatedGroupedVertex.getVertices();
		assertTrue(newVertices.containsAll(originalVertices));

		//
		//  Ungroup and make sure all edges and vertices return
		//

		ungroup(updatedGroupedVertex);

		assertVertexRemoved(graph, updatedGroupedVertex);

		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, originalEdges);

		ungroupedVertices.addAll(newUngroupedVertices);
		assertSelected(ungroupedVertices);
	}

	// @formatter:off
	protected void doTestGroupAndUngroupVertices() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
	
		Set<FGVertex> ungroupedVertices = selectVertices( functionGraph, 
																	"01002d2b" /* Another Local*/, 
																	"01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());
	
		group(ungroupedVertices);
	
		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);
		
		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex =
			validateNewGroupedVertexFromVertices(functionGraph, ungroupedVertices, 
				expectedGroupedEdgeCount);
	
		ungroup(groupedVertex);
	
		assertVertexRemoved(graph, groupedVertex);
		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, ungroupedEdges);
		assertSelected(ungroupedVertices);
		
	}
	// @formatter:on

	protected void doTestGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices() {
		//
		//	WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  
		// This is not a junit test in that it is long, involved, hidden and complicated.  We 
		// need to test this functionality, but we don't have a jComplicatedTest, so we will do
		// it here.
		//

		//
		// Desired Behavior: We want to be able to group vertices, group grouped vertices and then
		//                   ungroup them in any order.  For us to be able to do this, our group
		//                   vertices must store enough edge information to be able to ungroup 
		//                   and find vertices for edges *whether or now those vertices have been
		//                   grouped or ungrouped*
		// 
		// Original Bug: We had a bug loosely described here: 
		// 0) Start with a directed graph of vertices.
		// 1) Create two separate group vertices (A and B), such that A has an edge to B.
		// 2) Create a third group vertex (Z) that contains a non-grouped vertex (B) *and* one 
		//    of the other groups.
		// 3) Now, ungroup the 1 remaining originally grouped vertex (A).
		// 4) **At this point, the code could not determine which endpoint to pick for the edge 
		//      that used to be from Z->A.  Which vertex inside of A represented the connection
		//      pointing into Z (by way of B).
		// 
		// The fix is mentioned in the Desired Behavior section.  
		//

		/*
		 
		 0) Initial Graph
		 
		 1 -> 2 -> 3 -> 4
		           |
		           *
		           5
		           
		*/

		create12345Graph();

		//
		// Our graph maps from number to address like so:
		//

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");
		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");
		FGVertex v5 = vertex("100419c");

		// verify initial graph 
		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
		verifyEdgeCount(4);

		/*
		 1) Create two separate group vertices (A and B), such that A has an edge to B.
		            
		 A (v:{1,2} e:{1->2, 2->3}) -> B (v:{3,4} e:{2->3,3->4,3->5})
		                               |
		                               *
		                               5
		                               		 
		 */

		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		GroupedFunctionGraphVertex groupB = group("B", v3, v4);

		verifyEdge(groupA, groupB);
		verifyEdge(groupB, v5);
		verifyEdgeCount(2);// no other edges

		/*
		 2) Create a third group vertex (Z) that contains a non-grouped vertex *and* one 
		    of the other groups (B).
		    
		 A (v:{1,2} e:{1->2, 2->3}) -> Z (
		 									v:{B (v:{3,4} e:{2->3,3->4,3->5}), 5}
		 									e:{2->3, 3->5}
		 								  )          
		
		*/

		GroupedFunctionGraphVertex groupZ = group("Z", groupB, v5);

		verifyEdge(groupA, groupZ);
		verifyEdgeCount(1);

		/*
		 3) Now, ungroup the 1 remaining originally grouped vertex (A).
		 
		 1 -> 2 -> Z (
						v:{B (v:{3,4} e:{2->3,3->4,3->5}), 5}
						e:{2->3, 3->5}
					  )   
		 
		 */

		ungroup(groupA);

		verifyEdge(v1, v2);
		verifyEdge(v2, groupZ);
		verifyEdgeCount(2);

		/*
		 
		 4) Now, ungroup Z and go back to having one remaining group vertex (B)
		 
		 1 -> 2 -> -> B (v:{3,4} e:{2->3,3->4,3->5})
		              |
		              *
		              5
		            		  
		*/

		ungroup(groupZ);

		verifyEdge(v1, v2);
		verifyEdge(v2, groupB);
		verifyEdge(groupB, v5);
		verifyEdgeCount(3);

		/*
		 5) Finally, ungroup the last group and make sure the graph is restored
		              
		 1 -> 2 -> 3 -> 4
		           |
		           *
		           5		
		  
		 */

		ungroup(groupB);

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
		verifyEdgeCount(4);

	}

	private void doTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup() {
		// 
		// Tests the behavior of how group vertices are restored when one or more of the vertices 
		// inside of the grouped vertex is no longer available when the graph attempts to restore
		// the group vertex user settings (i.e., when restarting Ghidra, the previously grouped
		// vertices should reappear).  
		//
		// In this test, we will be mutating a group of 2 nodes such
		// that one of the nodes has been split into two.  This leaves only one vertex to 
		// be found by the regrouping algorithm.  Furthermore, the regrouping will not take place
		// if at least two vertices cannot be found.
		//

		// 
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d11" /* LAB_01002d11 */, "01002cf5" /* ghidra */);

		group(ungroupedVertices);

		// 5 edges expected: 
		// -01002cf5: 2 out 
		// -01002cf5: 2 in, 1 out
		int expectedGroupedEdgeCount = 5;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();

		//
		// Ideally, we would like to save, close and re-open the program so that we can get 
		// a round-trip saving and reloading.  However, in the test environment, we cannot save 
		// our programs.  So, we will instead just navigate away from the current function, clear
		// the cache (to make sure that we read the settings again), and then verify that the 
		// data saved in the program has been used to re-group.
		//
		graphFunction("0100415a");
		clearCache();

		//
		// Add a label to trigger a code block change
		//
		createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Relaunch the graph, which will use the above persisted group settings...
		//
		graphData = graphFunction("01002cf5");
		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		FGVertex expectedGroupVertex = functionGraph.getVertexForAddress(minAddress);
		assertFalse(expectedGroupVertex instanceof GroupedFunctionGraphVertex);
	}

	protected void doTestRestoringWhenCodeBlocksHaveChanged_WillRegroup() {
		// 
		// Tests the behavior of how group vertices are restored when one or more of the vertices 
		// inside of the grouped vertex is no longer available when the graph attempts to restore
		// the group vertex user settings (i.e., when restarting Ghidra, the previously grouped
		// vertices should reappear).
		//
		// In this test, we will be mutating a group of 3 nodes such
		// that one of the nodes has been split into two.  This leaves 2 vertices to 
		// be found by the regrouping algorithm.  Furthermore, the regrouping *will* still
		// take place, as at least two vertices cannot be found.
		//

		// 
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		Set<FGVertex> ungroupedVertices = selectVertices(functionGraph,
			"01002d11" /* LAB_01002d11 */, "01002cf5" /* ghidra */, "01002d1f" /* MyLocal */);

		group(ungroupedVertices);

		// 5 edges expected: 
		// -01002cf5: 2 out 
		// -01002d11: 2 in, (1 out that was removed)
		// -01002d1f: 2 out (1 in that was removed)
		int expectedGroupedEdgeCount = 6;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMaxAddress();

		//
		// Ideally, we would like to save, close and re-open the program so that we can get 
		// a round-trip saving and reloading.  However, in the test environment, we cannot save 
		// our programs.  So, we will instead just navigate away from the current function, clear
		// the cache (to make sure that we read the settings again), and then verify that the 
		// data saved in the program has been used to re-group.
		//
		graphFunction("0100415a");
		clearCache();

		//
		// Add a label to trigger a code block change
		//
		Address labelAddress = createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Relaunch the graph, which will use the above persisted group settings...
		//
		graphData = graphFunction("01002cf5");
		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		FGVertex expectedGroupVertex = functionGraph.getVertexForAddress(minAddress);
		assertTrue(expectedGroupVertex instanceof GroupedFunctionGraphVertex);
		assertEquals(maxAddress, expectedGroupVertex.getAddresses().getMaxAddress());

		// ...we expect that the two original grouped vertices have again been grouped...
		FGVertex splitVertex =
			functionGraph.getVertexForAddress(getAddress("01002d11") /* LAB_01002d11 */);
		assertTrue("The split vertex should not have been regrouped",
			!(splitVertex instanceof GroupedFunctionGraphVertex));

		FGVertex unchangedVertex =
			functionGraph.getVertexForAddress(getAddress("01002cf5") /* ghidra */);
		assertTrue("An unchanged vertex should have been regrouped: " + unchangedVertex,
			(unchangedVertex instanceof GroupedFunctionGraphVertex));

		unchangedVertex = functionGraph.getVertexForAddress(getAddress("01002d1f") /* MyLocal */);
		assertTrue("An unchanged vertex should have been regrouped: " + unchangedVertex,
			(unchangedVertex instanceof GroupedFunctionGraphVertex));

		// ...but the newly created code block has not
		FGVertex newlyCreatedVertex = functionGraph.getVertexForAddress(labelAddress);
		assertNotNull(newlyCreatedVertex);
	}

	protected void doTestSymbolAddedWhenGrouped_SymbolInsideOfGroupNode() {
		//
		// By default, if the FunctionGraph detects a symbol addition to one of the code blocks
		// in the graph, then it will split the affected vertex (tested elsewhere).  
		// However, if the affected vertex is grouped, then the FG will not split the node, but
		// should still show the 'stale' indicator.
		//

		// 
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d11" /* LAB_01002d11 */, "01002cf5" /* ghidra */);

		group(ungroupedVertices);

		// 5 edges expected: 
		// -01002cf5: 2 out 
		// -01002cf5: 2 in, 1 out
		int expectedGroupedEdgeCount = 5;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		//
		// Add a label to trigger a code block change
		//
		Address labelAddress = createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Make sure the newly created code block does not have a corresponding vertex
		//
		FGVertex exisingVertex = functionGraph.getVertexForAddress(labelAddress);
		assertEquals("Grouped vertex does not contain the address of the newly created label",
			groupedVertex, exisingVertex);
	}

	private JComponent getComponent(final FGVertex vertex) {
		final AtomicReference<JComponent> reference = new AtomicReference<>();
		runSwing(() -> reference.set(vertex.getComponent()));
		return reference.get();
	}

	/** 
	 * Finds an edge that represents the given edge, which may no longer exist with 
	 * the same (==) edge instances.
	 */
	private FGEdge getCurrentEdge(FunctionGraph functionGraph, FGEdge edge) {
		FGVertex start = edge.getStart();
		FGVertex end = edge.getEnd();
		Address startAddress = start.getVertexAddress();
		Address endAddress = end.getVertexAddress();
		FGVertex v1 = functionGraph.getVertexForAddress(startAddress);
		FGVertex v2 = functionGraph.getVertexForAddress(endAddress);
		Graph<FGVertex, FGEdge> graph = functionGraph;
		return graph.findEdge(v1, v2);
	}

	protected Set<FGEdge> getEdges(Graph<FGVertex, FGEdge> graph, Set<FGVertex> ungroupedVertices) {
		Set<FGEdge> ungroupedEdges = new HashSet<>();
		accumulateUngroupedIncidentEdges(graph, ungroupedVertices, ungroupedEdges);
		return ungroupedEdges;
	}

	protected GroupedFunctionGraphVertex getGroupVertex(FunctionGraph functionGraph,
			Address address) {
		FGVertex vertex = functionGraph.getVertexForAddress(address);
		if (!(vertex instanceof GroupedFunctionGraphVertex)) {
			if (vertex == null) {
				Msg.debug(this, "Null vertex for address " + address + ".  All vertices: ");
				Collection<FGVertex> vertices = functionGraph.getVertices();
				for (FGVertex v : vertices) {
					Msg.debug(this, "\t" + v);
				}
			}

			Assert.fail("Did not find group vertex at " + address + ".  Instead found " + vertex);
		}
		return (GroupedFunctionGraphVertex) vertex;
	}

	private PickedState<FGVertex> getPickedState() {
		FGComponent functionGraphViewer = getGraphComponent();
		VisualizationViewer<FGVertex, FGEdge> primaryViewer =
			functionGraphViewer.getPrimaryViewer();
		return primaryViewer.getPickedVertexState();
	}

	private DockingActionIf getRegroupAction(final FGVertex vertex) {
		final AtomicReference<DockingActionIf> reference = new AtomicReference<>();
		runSwing(() -> {
			JComponent component = vertex.getComponent();
			final GenericHeader header =
				(GenericHeader) getInstanceField("genericHeader", component);
			reference.set(header.getAction("Regroup Vertices"));
		});
		return reference.get();
	}

	protected FGData graphFunction(String functionAddress) {
		// Find a good test function.
		goToAddress(functionAddress);

		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		return graphData;
	}

	protected GroupedFunctionGraphVertex group(Set<FGVertex> ungroupedVertices) {
		return group(ungroupedVertices, null);
	}

	protected GroupedFunctionGraphVertex group(Set<FGVertex> ungroupedVertices,
			final String groupVertexText) {
		// execute the group action
		FGVertex aVertex = ungroupedVertices.iterator().next();
		JComponent component = getComponent(aVertex);
		DockingAction action = (DockingAction) TestUtils.getInstanceField("groupAction", component);
		performAction(action, graphProvider, false);
		waitForAnimation();

		MultiLineInputDialog dialog = waitForDialogComponent(MultiLineInputDialog.class);
		if (groupVertexText != null) {
			final JTextArea inputTextArea = (JTextArea) getInstanceField("inputTextArea", dialog);
			runSwing(() -> inputTextArea.setText(groupVertexText));
		}

		pressButtonByText(dialog.getComponent(), "OK");

		if (groupVertexText != null) {
			String value = dialog.getValue();
			assertEquals("Group vertex text was not set in the dialog", groupVertexText, value);
		}

		waitForAnimation();

		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		FunctionGraph fg = data.getFunctionGraph();
		return getGroupVertex(fg, aVertex.getVertexAddress());
	}

	protected GroupedFunctionGraphVertex group(String groupName, FGVertex... vertices) {

		HashSet<FGVertex> set = new HashSet<>();
		for (FGVertex v : vertices) {
			set.add(v);
		}

		pickVertices(set);
		GroupedFunctionGraphVertex groupVertex = group(set, groupName);

		// for debugging
		Object componentPanel = getComponent(groupVertex);
		setInstanceField("title", componentPanel, groupName);

		return groupVertex;
	}

	protected boolean isUncollapsed(final FGVertex vertex) {
		final AtomicReference<Boolean> reference = new AtomicReference<>();
		runSwing(() -> reference.set(vertex.isUncollapsedGroupMember()));
		return reference.get();
	}

	protected void pickVertex(FGVertex v) {
		runSwing(() -> {
			PickedState<FGVertex> pickedState = getPickedState();
			pickedState.clear();
			pickedState.pick(v, true);
		});
	}

	protected void pickVertices(final Set<FGVertex> vertices) {
		runSwing(() -> {
			PickedState<FGVertex> pickedState = getPickedState();
			pickedState.clear();

			for (FGVertex vertex : vertices) {
				pickedState.pick(vertex, true);
			}
		});
	}

	protected GroupedFunctionGraphVertex regroup(FGVertex vertex) {

		DockingActionIf regroupAction = getRegroupAction(vertex);
		if (regroupAction == null) {
			Assert.fail("Did not find the regroup action on vertex: " + vertex.getTitle());
		}
		performAction(regroupAction, false);
		waitForBusyGraph();

		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		FunctionGraph fg = data.getFunctionGraph();
		return getGroupVertex(fg, vertex.getAddresses().getMinAddress());
	}

	private void removeEdge(FunctionGraph functionGraph, Address startAddress,
			Address destinationAddress) {

		Graph<FGVertex, FGEdge> graph = functionGraph;

		FGVertex startVertex = functionGraph.getVertexForAddress(startAddress);
		FGVertex destinationVertex = functionGraph.getVertexForAddress(destinationAddress);

		FGEdge edge = graph.findEdge(startVertex, destinationVertex);
		runSwing(() -> graph.removeEdge(edge));
		FGController controller = getFunctionGraphController();
		controller.repaint();
	}

	protected void removeFromUncollapsedGroup(FGVertex... vertices) {
		FunctionGraph functionGraph = getFunctionGraph();
		selectVertices(functionGraph, vertices);

		DockingActionIf action = getAction(graphPlugin, "Remove From Group");
		assertNotNull(action);

		performAction(action, graphProvider, false);
		waitForBusyGraph();
	}

	private void removeVertex(FunctionGraph functionGraph, Address vertexAddress) {
		Graph<FGVertex, FGEdge> graph = functionGraph;
		FGVertex vertex = functionGraph.getVertexForAddress(vertexAddress);
		runSwing(() -> graph.removeVertex(vertex));
		FGController controller = getFunctionGraphController();
		controller.repaint();
	}

	protected FGData reset() {

		DockingActionIf action = getAction(tool, graphPlugin.getName(), "Reset Graph");
		performAction(action, graphProvider, false);

		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Yes");

		// wait for the threaded graph layout code
		return getFunctionGraphData();
	}

	private Set<FGVertex> selectVertices(FunctionGraph functionGraph, FGVertex... vertices) {

		Set<FGVertex> set = new HashSet<>();
		for (FGVertex vertex : vertices) {
			set.add(vertex);
		}

		pickVertices(set);

		waitForSwing();
		return set;
	}

	protected Set<FGVertex> selectVertices(FunctionGraph functionGraph, String... addressString) {

		Set<FGVertex> vertices = new HashSet<>();
		for (String string : addressString) {
			Address vertexAddress = getAddress(string);
			FGVertex vertex = functionGraph.getVertexForAddress(vertexAddress);
			assertNotNull("No vertex for address: " + vertexAddress, vertex);
			vertices.add(vertex);
		}

		pickVertices(vertices);

		waitForSwing();
		return vertices;
	}

	protected void setGroupText(GroupedFunctionGraphVertex group, final String newText) {

		final GroupedFunctionGraphVertex updatedGroup = update(group);
		runSwing(() -> updatedGroup.editLabel(null), false);

		Window window = waitForWindow("Enter Group Vertex Text");
		assertNotNull(window);

		final JTextArea textArea = findComponent(window, JTextArea.class);
		runSwing(() -> textArea.setText(newText));

		pressButtonByText(window, "OK");

		waitForSwing();
	}

	private void setMinCrossLayout() {
		Object actionManager = getInstanceField("actionManager", graphProvider);
		@SuppressWarnings("unchecked")
		final MultiStateDockingAction<Class<? extends FGLayoutProvider>> action =
			(MultiStateDockingAction<Class<? extends FGLayoutProvider>>) getInstanceField(
				"layoutAction", actionManager);
		runSwing(() -> {
			List<ActionState<Class<? extends FGLayoutProvider>>> states =
				action.getAllActionStates();
			for (ActionState<Class<? extends FGLayoutProvider>> state : states) {
				Class<? extends FGLayoutProvider> layoutClass = state.getUserData();
				if (layoutClass.getSimpleName().contains("MinCross")) {
					action.setCurrentActionState(state);
				}
			}

		});

	}

	protected FGData triggerPersistenceAndReload(String functionAddress) {
		//
		// Ideally, we would like to save, close and re-open the program so that we can get 
		// a round-trip saving and reloading.  However, in the test environment, we cannot save 
		// our programs.  So, we will instead just navigate away from the current function, clear
		// the cache (to make sure that we read the settings again), and then verify that the 
		// data saved in the program has been used to re-group.
		//
		String otherAddress = "0100415a";
		assertNotEquals(functionAddress, otherAddress);
		graphFunction(otherAddress);

		//
		// Graph the original function and make sure that the previously grouped nodes is again
		// grouped.
		//
		return graphFunction(functionAddress);
	}

	// this method is really just a renamed version of ungroup, meant to add clarity of expression
	protected void uncollapse(GroupedFunctionGraphVertex groupedVertex) {
		// Unusual Code: for some of the regroup actions, group vertices are created and restored,
		//               but are always equal.  Thus, the Function Graph works correctly, but the
		//				 test can get out-of-sync, so we update before we use it

		groupedVertex = getGroupVertex(getFunctionGraph(), groupedVertex.getVertexAddress());

		ungroup(groupedVertex);
	}

	protected void ungroup(GroupedFunctionGraphVertex groupedVertex) {
		// execute the ungroup action
		JComponent component = groupedVertex.getComponent();
		component = groupedVertex.getComponent();
		DockingAction action =
			(DockingAction) TestUtils.getInstanceField("ungroupAction", component);
		performAction(action, graphProvider, false);
		waitForBusyGraph();
	}

	protected void ungroupAll() {

		DockingActionIf action = getAction(tool, "FunctionGraphPlugin", "Ungroup All Vertices");
		performAction(action, graphProvider, false);

		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Yes");

		// wait for the threaded graph layout code
		waitForBusyGraph();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private GroupedFunctionGraphVertex update(GroupedFunctionGraphVertex group) {
		// Unusual Code: for some of the regroup actions, group vertices are created and restored,
		//               but are always equal.  Thus, the Function Graph works correctly, but the
		//				 test can get out-of-sync, so we update before we use it
		return getGroupVertex(getFunctionGraph(), group.getVertexAddress());
	}

	protected GroupedFunctionGraphVertex validateNewGroupedVertexFromVertices(
			FunctionGraph functionGraph, Set<FGVertex> vertices, int expectedGroupedEdgeCount) {

		FGVertex aVertex = vertices.iterator().next();
		FGVertex currentVertex = functionGraph.getVertexForAddress(aVertex.getVertexAddress());
		assertTrue(currentVertex instanceof GroupedFunctionGraphVertex);
		GroupedFunctionGraphVertex groupedVertex = (GroupedFunctionGraphVertex) currentVertex;

		//
		// make sure we have new edges
		//
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGEdge> groupedEdges = graph.getIncidentEdges(groupedVertex);

		assertEquals("Ungrouped edges not replaced with new edges for the grouped vertex",
			expectedGroupedEdgeCount, groupedEdges.size());
		assertSelected(groupedVertex);
		return groupedVertex;
	}

	protected void verifyColor(FGVertex vertex, Color expectedColor) {
		Color currentBackgroundColor = vertex.getBackgroundColor();
		assertEquals("Color of vertex is not as expected - vertex: " + vertex, expectedColor,
			currentBackgroundColor);
	}

	protected void verifyDefaultColor(FGVertex... vertices) {
		for (FGVertex v : vertices) {
			Color defaultBackgroundColor = v.getDefaultBackgroundColor();
			Color currentBackgroundColor = v.getBackgroundColor();
			assertEquals("Color of vertex is not as expected - vertex: " + v,
				defaultBackgroundColor, currentBackgroundColor);
		}
	}

	protected void verifyEdge(FGVertex start, FGVertex destination) {
		FGData data = getFunctionGraphData();
		FunctionGraph functionGraph = data.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		FGEdge edge = graph.findEdge(start, destination);
		assertNotNull("No edge exists for vertices: " + start + "   and   " + destination, edge);
	}

	protected void verifyEdgeCount(int expectedCount) {
		FGData data = getFunctionGraphData();
		FunctionGraph functionGraph = data.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		int actualCount = graph.getEdgeCount();
		assertEquals("Graph has a different number of edges than expected.", expectedCount,
			actualCount);
	}

	protected void assertClipboardServiceAddress(DockingAction copyAction, String address) {
		Object clipboardService = getInstanceField("clipboardService", copyAction);
		ProgramLocation location =
			(ProgramLocation) getInstanceField("currentLocation", clipboardService);
		assertEquals("Clipboard service does not have the correct location", getAddress(address),
			location.getAddress());
	}

	protected void assertNoUndockedProvider() {
		ComponentProvider provider = tool.getComponentProvider(FGSatelliteUndockedProvider.NAME);
		assertNull("Undocked satellite provider is installed when it should not be", provider);
	}

	protected void assertUndockedProviderNotShowing() {
		ComponentProvider provider = tool.getComponentProvider(FGSatelliteUndockedProvider.NAME);
		if (provider == null) {
			return; // no provider; not showing
		}
		assertFalse("Undocked provider is not showing after being undocked", provider.isVisible());
	}

	protected void assertUndockedProviderShowing() {
		ComponentProvider provider = tool.getComponentProvider(FGSatelliteUndockedProvider.NAME);
		assertUndockedProviderShowing(provider);
	}

	protected void assertUndockedProviderShowing(ComponentProvider satellite) {
		assertNotNull("Undocked provider is not installed when it should be", satellite);
		assertTrue("Undocked provider is not showing after being undocked", satellite.isVisible());
	}

	protected void assertZoomedIn() {
		Double scale = getGraphScale(getPrimaryGraphViewer());
		int result = Double.compare(scale, 1.0);
		assertEquals("Graph not fully zoomed-in; scale: " + scale, 0, result);
	}

	protected void assertZoomedOut() {
		Double scale = getGraphScale(getPrimaryGraphViewer());
		assertTrue("Graph fully zoomed-in", scale < 1.0);
	}

	protected void chooseColor(FGVertex vertex, Color testColor) {
		SetVertexMostRecentColorAction setColorAction =
			(SetVertexMostRecentColorAction) getInstanceField("setVertexMostRecentAction",
				vertex.getComponent());
		DockingAction action =
			(DockingAction) TestUtils.getInstanceField("chooseColorAction", setColorAction);
		performAction(action, graphProvider, false);

		Window chooserWindow = waitForWindow("Please Select Background Color");
		Object colorChooserDialog = chooserWindow;// the name is the real type
		JColorChooser chooser =
			(JColorChooser) TestUtils.getInstanceField("chooserPane", colorChooserDialog);
		chooser.setColor(testColor);

		JButton okButton = findButtonByText(chooserWindow, "OK");
		runSwing(() -> okButton.doClick());
		waitForSwing();
	}

	protected void closeUndockedProvider() {
		ComponentProvider provider = tool.getComponentProvider(FGSatelliteUndockedProvider.NAME);
		assertNotNull("Undocked provider is not installed when it should be", provider);
		tool.showComponentProvider(provider, false);
		waitForSwing();
	}

	protected void debugAction(DockingAction copyAction, ActionContext context) {

		Msg.debug(this, "Copy action not enabled at location " + codeBrowser.getCurrentLocation());

		FGVertex focusedVertex = getFocusedVertex();
		Msg.debug(this, "\tfocused vertex: " + focusedVertex);

		Msg.debug(this, "\tcontext: " + context);

		// Figure out which check in the action failed
		Object clipboardService = getInstanceField("clipboardService", copyAction);
		Msg.debug(this, "\tservice: " + clipboardService);

		Boolean result = (Boolean) invokeInstanceMethod("isValidContext", clipboardService,
			new Class[] { ActionContext.class }, new Object[] { context });
		Msg.debug(this, "\tisValidContext()?: " + result);

		result = (Boolean) invokeInstanceMethod("canCopy", clipboardService);
		Msg.debug(this, "\tcanCopy: " + result);

		Boolean copyFromSelectionEnabled =
			(Boolean) getInstanceField("copyFromSelectionEnabled", clipboardService);
		Msg.debug(this, "\tcopyFromSelectionEnabled: " + copyFromSelectionEnabled);

		String stringContent = (String) getInstanceField("stringContent", clipboardService);
		Msg.debug(this, "\tstringContent: " + stringContent);

		Object location = getInstanceField("currentLocation", clipboardService);
		Msg.debug(this, "\tservice location: " + location);
	}

	protected DockingAction getClearColorAction(FGVertex vertex) {
		SetVertexMostRecentColorAction recentColorAction = getSetMostRecentColorAction(vertex);
		return (DockingAction) getInstanceField("clearColorAction", recentColorAction);
	}

	protected FGVertex getFocusedVertex() {
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);
		return focusedVertex;
	}

	protected FGVertex getFocusVertex(final FunctionGraph functionGraph) {
		final FGVertex[] box = new FGVertex[1];
		runSwing(() -> box[0] = functionGraph.getFocusedVertex());
		return box[0];
	}

	protected SetVertexMostRecentColorAction getSetMostRecentColorAction(FGVertex vertex) {
		// this action is odd in that it is not installed in the tool, but is owned by each
		// vertex directly

		JComponent internalGraphComponent = vertex.getComponent();
		return (SetVertexMostRecentColorAction) getInstanceField("setVertexMostRecentAction",
			internalGraphComponent);
	}

	protected void goTo(String address) {
		Address addr = getAddress(address);
		goTo(addr);
	}

	protected void goTo(Address address) {
		GoToService goToService = tool.getService(GoToService.class);
		runSwing(() -> goToService.goTo(address));
		waitForBusyGraph();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	protected void moveView(int amount) {
		Point translation = new Point(amount, amount);
		moveViewerLocationWithoutAnimation(translation);
	}

	protected void navigateBack() {
		String name = "Previous Location in History";

		DockingActionIf action = getAction(tool, "NextPrevAddressPlugin", name);
		performAction(action, true);
		waitForBusyGraph();
	}

	protected void pressRightArrowKey(final FGVertex vertex) {
		runSwing(() -> {
			JComponent component = vertex.getComponent();
			ListingPanel listingPanel =
				(ListingPanel) TestUtils.getInstanceField("listingPanel", component);
			FieldPanel fieldPanel = listingPanel.getFieldPanel();
			Object cursorHandler = getInstanceField("cursorHandler", fieldPanel);
			invokeInstanceMethod("doCursorRight", cursorHandler, new Class[] { EventTrigger.class },
				new Object[] { EventTrigger.GUI_ACTION });
		});
	}

	protected void setGraphWindowSize(final int width, final int height) {

		final Window graphWindow = windowForComponent(getPrimaryGraphViewer());
		runSwing(() -> graphWindow.setSize(width, height));
	}

	protected void toggleSatalliteVisible(boolean expectedVisible) {
		String name = "Display Satellite View";

		DockingActionIf action = getAction(tool, "FunctionGraphPlugin", name);
		ToggleDockingAction displayAction = (ToggleDockingAction) action;
		setToggleActionSelected(displayAction, new ActionContext(), expectedVisible);
//	
//		// make sure the action is not already in the state we expect
//		assertEquals(name + " action is not selected as expected", !expectedVisible,
//			displayAction.isSelected());
//	
//		performAction(displayAction, true);
	}

	protected void waitForGraphToLoad() {
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
	}

	protected void swing(Runnable r) {
		AbstractGenericTest.runSwing(r);
	}

	protected <T> T swing(Supplier<T> s) {
		return AbstractGenericTest.runSwing(s);
	}

	static class DummyTransferable implements Transferable {

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			return null;
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return new DataFlavor[0];
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return true;
		}

	}
}
