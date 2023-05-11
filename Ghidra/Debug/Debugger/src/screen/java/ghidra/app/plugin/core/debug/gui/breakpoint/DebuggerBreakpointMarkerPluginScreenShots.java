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

import java.awt.event.MouseEvent;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest.TestDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.app.services.LogicalBreakpoint.State;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerBreakpointMarkerPluginScreenShots extends GhidraScreenShotGenerator {
	private DebuggerModelService modelService;
	private DebuggerTraceManagerService traceManager;
	private DebuggerStaticMappingService mappingService;
	private DebuggerLogicalBreakpointService breakpointService;
	private DebuggerBreakpointMarkerPlugin breakpointMarkerPlugin;
	private ProgramManager programManager;

	private TestDebuggerModelBuilder mb;

	private CodeViewerProvider listing;

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Before
	public void setUpMine() throws Exception {
		modelService = addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		breakpointMarkerPlugin = addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		programManager = addPlugin(tool, ProgramManagerPlugin.class);

		listing = waitForComponentProvider(CodeViewerProvider.class);

		program = programManager.getCurrentProgram();

		mb = new TestDebuggerModelBuilder();
	}

	@Test
	public void testCaptureDebuggerBreakpointMarkerPlugin() throws Throwable {
		ListingPanel panel = listing.getListingPanel();

		mb.createTestModel();
		modelService.addModel(mb.testModel);
		mb.createTestProcessesAndThreads();
		TestDebuggerTargetTraceMapper mapper = new TestDebuggerTargetTraceMapper(mb.testProcess1);
		TraceRecorder recorder =
			modelService.recordTarget(mb.testProcess1, mapper, ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();

		traceManager.openTrace(trace);
		traceManager.activateTrace(trace);

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		try (Transaction tx = trace.openTransaction("Add Mapping")) {
			mappingService.addIdentityMapping(trace, program, Lifespan.nowOn(0), true);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(trace, null, Lifespan.at(0), mb.addr(0x00401c60))));

		Msg.debug(this, "Placing breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c60), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");

		Msg.debug(this, "Disabling breakpoint");
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401c60))));

		lb.disable();
		waitForCondition(() -> lb.computeState() == State.DISABLED);

		Msg.debug(this, "Placing another");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c63), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");

		Msg.debug(this, "Saving program");
		program.save("Placed breakpoints", TaskMonitor.DUMMY);

		Msg.debug(this, "Clicking and capturing");
		DebuggerBreakpointMarkerPluginTest.clickListing(panel, addr(program, 0x00401c66),
			MouseEvent.BUTTON3);
		waitForSwing();

		captureProviderWithScreenShot(listing);
	}

	@Test
	public void testCaptureDebuggerDecompilerBreakpointMargin() throws Throwable {
		mb.createTestModel();
		modelService.addModel(mb.testModel);
		mb.createTestProcessesAndThreads();
		TestDebuggerTargetTraceMapper mapper = new TestDebuggerTargetTraceMapper(mb.testProcess1);
		TraceRecorder recorder =
			modelService.recordTarget(mb.testProcess1, mapper, ActionSource.AUTOMATIC);
		Trace trace = recorder.getTrace();

		traceManager.openTrace(trace);
		traceManager.activateTrace(trace);

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		try (Transaction tx = trace.openTransaction("Add Mapping")) {
			mappingService.addIdentityMapping(trace, program, Lifespan.nowOn(0), true);
		}
		waitForValue(() -> mappingService.getOpenMappedLocation(
			new DefaultTraceLocation(trace, null, Lifespan.at(0), mb.addr(0x00401070))));

		Msg.debug(this, "Placing breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401070), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "");

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
