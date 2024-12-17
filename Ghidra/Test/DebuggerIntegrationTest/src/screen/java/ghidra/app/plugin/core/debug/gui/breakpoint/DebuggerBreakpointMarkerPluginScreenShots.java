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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import docking.DefaultActionContext;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import generic.Unique;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.service.MockTarget;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.debug.api.breakpoint.LogicalBreakpoint.State;
import ghidra.debug.api.target.Target;
import ghidra.graph.viewer.VisualGraphViewUpdater;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.RunManager;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerBreakpointMarkerPluginScreenShots extends GhidraScreenShotGenerator {
	private DebuggerTargetService targetService;
	private DebuggerTraceManagerService traceManager;
	private DebuggerStaticMappingService mappingService;
	private DebuggerLogicalBreakpointService breakpointService;
	private DebuggerBreakpointMarkerPlugin breakpointMarkerPlugin;
	private ProgramManager programManager;

	private ToyDBTraceBuilder tb;

	private CodeViewerProvider listing;

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Before
	public void setUpMine() throws Exception {
		targetService = addPlugin(tool, DebuggerTargetServicePlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		breakpointMarkerPlugin = addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		programManager = addPlugin(tool, ProgramManagerPlugin.class);

		listing = waitForComponentProvider(CodeViewerProvider.class);

		program = programManager.getCurrentProgram();

		tb = new ToyDBTraceBuilder(getName(), "x86:LE:32:default");
	}

	@After
	public void tearDownMine() throws Exception {
		if (tb != null) {
			tb.close();
		}
	}

	protected void placeBreakpoint(long index, Address dynAddr, boolean enabled) {
		try (Transaction tx = tb.startTransaction()) {
			TraceObjectKeyPath pathSpec =
				TraceObjectKeyPath.parse("Processes[1].Breakpoints").index(index);
			DBTraceObject objBptSpec = tb.trace.getObjectManager().createObject(pathSpec);
			DBTraceObject objBptLoc = tb.trace.getObjectManager().createObject(pathSpec.index(1));
			objBptLoc.setAttribute(Lifespan.nowOn(0), "Range",
				new AddressRangeImpl(dynAddr, dynAddr));
			objBptSpec.setAttribute(Lifespan.nowOn(0), "Kinds", "SW_EXECUTE");
			objBptSpec.setAttribute(Lifespan.nowOn(0), "Enabled", enabled);
			objBptLoc.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
		}
	}

	@Test
	public void testCaptureDebuggerBreakpointMarkerPlugin() throws Throwable {
		ListingPanel panel = listing.getListingPanel();
		moveProviderToItsOwnWindow(listing, 1024, 680);

		Target target = new MockTarget(tb.trace);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createRootObject(AbstractGhidraHeadedDebuggerIntegrationTest.SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		targetService.publishTarget(target);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.nowOn(0), true);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.at(0), tb.addr(0x00401c60))));

		Msg.debug(this, "Placing disabled breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c60), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");
		LogicalBreakpoint lbDis = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401c60))));
		placeBreakpoint(1, lbDis.getTraceAddress(tb.trace), false);
		waitForCondition(() -> lbDis.computeState() == State.DISABLED);

		Msg.debug(this, "Placing enabled breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c63), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");
		LogicalBreakpoint lbEn = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401c63))));
		placeBreakpoint(2, lbEn.getTraceAddress(tb.trace), true);
		waitForCondition(() -> lbEn.computeState() == State.ENABLED);

		Msg.debug(this, "Saving program");
		program.save("Placed breakpoints", TaskMonitor.DUMMY);

		Msg.debug(this, "Clicking and capturing");
		AbstractDebuggerBreakpointMarkerPluginTest.clickListing(panel, addr(program, 0x00401c66),
			MouseEvent.BUTTON3);
		waitForSwing();

		captureProviderWithScreenShot(listing);
	}

	protected FGController getFunctionGraphController(FGProvider fgProvider) {
		return (FGController) TestUtils.getInstanceField("controller", fgProvider);
	}

	protected void waitForBusyRunManager(FGController controller) {
		FGModel model = controller.getModel();

		waitForSwing();
		RunManager runManager = (RunManager) TestUtils.getInstanceField("runManager", model);

		waitForCondition(() -> !runManager.isInProgress());
	}

	protected FGComponent getGraphComponent(FGProvider fgProvider) {
		FGController controller =
			(FGController) TestUtils.getInstanceField("controller", fgProvider);
		FGView view = (FGView) TestUtils.getInstanceField("view", controller);
		return (FGComponent) TestUtils.getInstanceField("fgComponent", view);
	}

	protected FGPrimaryViewer getPrimaryGraphViewer(FGProvider fgProvider) {
		FGComponent component = getGraphComponent(fgProvider);
		if (component == null) {
			return null; // this will be null if the graph has been disposed
		}

		assertNotNull("FG GraphComponent should not be null", component);
		return (FGPrimaryViewer) getInstanceField("primaryViewer", component);
	}

	protected VisualGraphViewUpdater<FGVertex, FGEdge> getGraphUpdater(FGProvider fgProvider) {
		FGPrimaryViewer viewer = getPrimaryGraphViewer(fgProvider);
		if (viewer == null) {
			return null; // this can happen when disposed or not on a function
		}

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = viewer.getViewUpdater();
		assertNotNull(updater);
		return updater;
	}

	protected void waitForAnimation(FGController controller, FGProvider fgProvider) {

		VisualGraphViewUpdater<FGVertex, FGEdge> updater = getGraphUpdater(fgProvider);
		if (updater == null) {
			return; // nothing to wait for; no active graph
		}

		waitForSwing();

		int tryCount = 3;
		while (tryCount++ < 5 && updater.isBusy()) {
			waitForConditionWithoutFailing(() -> !updater.isBusy());
		}
		waitForSwing();

		assertFalse(updater.isBusy());
	}

	@SuppressWarnings("rawtypes")
	private void setGraphLayout(FGProvider fgProvider) {
		long start = System.currentTimeMillis();
		Object actionManager = getInstanceField("actionManager", fgProvider);
		final MultiStateDockingAction<?> action =
			(MultiStateDockingAction<?>) getInstanceField("layoutAction", actionManager);

		Object wantState = null;
		List<?> states = action.getAllActionStates();
		for (Object state : states) {
			if (((ActionState) state).getName().indexOf("Flow Chart") != -1) {
				wantState = state;
				break;
			}
		}

		assertNotNull("Could not find desired layout!", wantState);

		invokeInstanceMethod("setCurrentActionState",
			action,
			new Class<?>[] { ActionState.class },
			new Object[] { wantState });

		runSwing(() -> action.actionPerformed(new DefaultActionContext()));

		// wait for the threaded graph layout code
		FGController controller = getFunctionGraphController(fgProvider);
		waitForBusyRunManager(controller);
		waitForAnimation(controller, fgProvider);
		getPrimaryGraphViewer(fgProvider).repaint();
		waitForSwing();

		long end = System.currentTimeMillis();
		Msg.debug(this, "relayout time: " + ((end - start) / 1000.0) + "s");
	}

	@Test
	public void testCaptureDebuggerFunctionGraphBreakpointMargin() throws Throwable {
		Target target = new MockTarget(tb.trace);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createRootObject(AbstractGhidraHeadedDebuggerIntegrationTest.SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		targetService.publishTarget(target);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.nowOn(0), true);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.at(0), tb.addr(0x00401070))));

		Msg.debug(this, "Placing breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401070), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");
		LogicalBreakpoint lbEn = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401070))));
		placeBreakpoint(1, lbEn.getTraceAddress(tb.trace), true);
		waitForCondition(() -> lbEn.computeState() == State.ENABLED);

		addPlugin(tool, FunctionGraphPlugin.class);

		FGProvider fgProvider = waitForComponentProvider(FGProvider.class);
		Swing.runNow(() -> tool.showComponentProvider(fgProvider, true));
		setGraphLayout(fgProvider);
		goTo(tool, program, addr(program, 0x00401070));
		captureIsolatedProvider(fgProvider, 700, 700);
	}

	@Test
	public void testCaptureDebuggerDecompilerBreakpointMargin() throws Throwable {
		Target target = new MockTarget(tb.trace);
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createRootObject(AbstractGhidraHeadedDebuggerIntegrationTest.SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		targetService.publishTarget(target);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.nowOn(0), true);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(tb.trace, null, Lifespan.at(0), tb.addr(0x00401070))));

		Msg.debug(this, "Placing breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401070), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");
		LogicalBreakpoint lbEn = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401070))));
		placeBreakpoint(1, lbEn.getTraceAddress(tb.trace), true);
		waitForCondition(() -> lbEn.computeState() == State.ENABLED);

		addPlugin(tool, DecompilePlugin.class);

		DecompilerProvider decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		Swing.runNow(() -> tool.showComponentProvider(decompilerProvider, true));
		goTo(tool, program, addr(program, 0x00401070));
		waitForCondition(() -> decompilerProvider.getDecompilerPanel().getLines().size() > 4);

		captureIsolatedProvider(decompilerProvider, 500, 700);
	}

	@Test
	public void testCaptureDebuggerPlaceBreakpointDialog() throws Throwable {
		runSwing(
			() -> listing.goTo(program, new ProgramLocation(program, addr(program, 0x00401c63))));
		performAction(breakpointMarkerPlugin.actionSetSoftwareBreakpoint, false);
		DebuggerPlaceBreakpointDialog dialog =
			waitForDialogComponent(DebuggerPlaceBreakpointDialog.class);

		dialog.setName("After setup");
		captureDialog(dialog);
	}
}
