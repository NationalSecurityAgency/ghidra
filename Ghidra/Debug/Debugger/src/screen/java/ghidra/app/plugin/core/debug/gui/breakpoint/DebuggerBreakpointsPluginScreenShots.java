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

import static ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest.waitForPass;
import static org.junit.Assert.assertEquals;

import java.util.Set;

import org.junit.*;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest.TestDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceTest;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.dbg.target.TargetBreakpointContainer;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.util.DebuggerModelTestUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerBreakpointsPluginScreenShots extends GhidraScreenShotGenerator
		implements DebuggerModelTestUtils {

	static {
		DebuggerModelServiceTest.addTestModelPathPatterns();
	}

	TestDebuggerModelBuilder mb = new TestDebuggerModelBuilder();
	DebuggerModelServiceProxyPlugin modelService;
	DebuggerStaticMappingService mappingService;
	DebuggerLogicalBreakpointService breakpointService;
	DebuggerTraceManagerService traceManager;
	ProgramManager programManager;

	Program program;

	protected static Address addr(Trace trace, long offset) {
		return trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Before
	public void setUpMine() throws Exception {
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		modelService = addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		programManager = addPlugin(tool, ProgramManagerPlugin.class);

		program = createDefaultProgram("echo", ToyProgramBuilder._X64, this);
		waitForProgram(program);
		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("echo", program, TaskMonitor.DUMMY);
	}

	@After
	public void tearDownMine() {
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testCaptureDebuggerBreakpointsPlugin() throws Throwable {
		addPlugin(tool, DebuggerBreakpointsPlugin.class);
		DebuggerBreakpointsProvider provider =
			waitForComponentProvider(DebuggerBreakpointsProvider.class);

		mb.createTestModel();
		modelService.addModel(mb.testModel);
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder1 = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1));
		TraceRecorder recorder3 = modelService.recordTarget(mb.testProcess3,
			new TestDebuggerTargetTraceMapper(mb.testProcess3));
		Trace trace1 = recorder1.getTrace();
		Trace trace3 = recorder3.getTrace();

		programManager.openProgram(program);
		traceManager.openTrace(trace1);
		traceManager.openTrace(trace3);

		mb.testProcess1.addRegion("echo:.text", mb.rng(0x00400000, 0x0040fff), "rx");
		mb.testProcess1.addRegion("echo:.data", mb.rng(0x00600000, 0x0060fff), "rw");
		mb.testProcess3.addRegion("echo:.text", mb.rng(0x7fac0000, 0x7facfff), "rx");

		try (UndoableTransaction tid = UndoableTransaction.start(trace1, "Add mapping", true)) {
			mappingService.addMapping(
				new DefaultTraceLocation(trace1, null, Range.atLeast(0L), addr(trace1, 0x00400000)),
				new ProgramLocation(program, addr(program, 0x00400000)), 0x00210000, false);
		}
		try (UndoableTransaction tid = UndoableTransaction.start(trace3, "Add mapping", true)) {
			mappingService.addMapping(
				new DefaultTraceLocation(trace3, null, Range.atLeast(0L), addr(trace3, 0x7fac0000)),
				new ProgramLocation(program, addr(program, 0x00400000)), 0x00010000, false);
		}

		TargetBreakpointContainer<?> bc1 =
			waitFor(() -> Unique.assertAtMostOne(recorder1.collectBreakpointContainers(null)),
				"No container");
		waitOn(bc1.placeBreakpoint(mb.addr(0x00401234), Set.of(TargetBreakpointKind.SOFTWARE)));
		waitOn(bc1.placeBreakpoint(mb.rng(0x00604321, 0x00604324),
			Set.of(TargetBreakpointKind.WRITE)));
		TargetBreakpointContainer<?> bc3 =
			waitFor(() -> Unique.assertAtMostOne(recorder3.collectBreakpointContainers(null)),
				"No container");
		waitOn(bc3.placeBreakpoint(mb.addr(0x7fac1234), Set.of(TargetBreakpointKind.SOFTWARE)));

		TraceBreakpoint bpt = waitForValue(() -> Unique.assertAtMostOne(
			trace3.getBreakpointManager().getBreakpointsAt(0, addr(trace3, 0x7fac1234))));
		try (UndoableTransaction tid =
			UndoableTransaction.start(trace3, "Disable breakpoint", true)) {
			bpt.setEnabled(false);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Add breakpoint", true)) {
			program.getBookmarkManager()
					.setBookmark(addr(program, 0x00401234),
						LogicalBreakpoint.BREAKPOINT_ENABLED_BOOKMARK_TYPE, "SOFTWARE;1", "");
			program.getBookmarkManager()
					.setBookmark(addr(program, 0x00402345),
						LogicalBreakpoint.BREAKPOINT_DISABLED_BOOKMARK_TYPE, "SOFTWARE;1", "");
		}

		waitForPass(() -> {
			assertEquals(3, breakpointService.getAllBreakpoints().size());
		});

		captureIsolatedProvider(provider, 600, 600);
	}
}
