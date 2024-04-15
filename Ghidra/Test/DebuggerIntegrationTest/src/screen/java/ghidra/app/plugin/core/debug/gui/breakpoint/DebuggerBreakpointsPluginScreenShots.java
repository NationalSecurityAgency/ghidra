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

import static ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest.waitForPass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.List;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.control.MockTarget;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.service.target.DebuggerTargetServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetBreakpointSpecContainer;
import ghidra.dbg.target.TargetTogglable;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.breakpoint.DBTraceBreakpointManager;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerBreakpointsPluginScreenShots extends GhidraScreenShotGenerator
		implements DebuggerModelTestUtils {

	DebuggerTargetService targetService;
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
		targetService = addPlugin(tool, DebuggerTargetServicePlugin.class);
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
		Msg.debug(this, "Tearing down");
		Msg.debug(this, "Service breakpoints:");
		for (LogicalBreakpoint lb : breakpointService.getAllBreakpoints()) {
			Msg.debug(this, "  bp: " + lb);
		}
		DebuggerBreakpointsProvider provider =
			waitForComponentProvider(DebuggerBreakpointsProvider.class);
		Msg.debug(this, "Provider breakpoints:");
		for (LogicalBreakpointRow row : provider.breakpointTableModel.getModelData()) {
			Msg.debug(this, "  bp: " + row.getLogicalBreakpoint());
		}
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testCaptureDebuggerBreakpointsPlugin() throws Throwable {
		addPlugin(tool, DebuggerBreakpointsPlugin.class);
		DebuggerBreakpointsProvider provider =
			waitForComponentProvider(DebuggerBreakpointsProvider.class);

		try (
				ToyDBTraceBuilder tb1 =
					new ToyDBTraceBuilder("echo.1", ProgramBuilder._TOY64_BE);
				ToyDBTraceBuilder tb2 =
					new ToyDBTraceBuilder("echo.2", ProgramBuilder._TOY64_BE);) {

			targetService.publishTarget(new MockTarget(tb1.trace));
			targetService.publishTarget(new MockTarget(tb2.trace));
			DomainFolder root = tool.getProject().getProjectData().getRootFolder();
			root.createFile("echo.1", tb1.trace, TaskMonitor.DUMMY);
			root.createFile("echo.2", tb2.trace, TaskMonitor.DUMMY);

			try (Transaction tx = tb1.startTransaction()) {
				DebuggerStaticMappingUtils.addMapping(
					new DefaultTraceLocation(tb1.trace, null, Lifespan.nowOn(0),
						addr(tb1.trace, 0x00400000)),
					new ProgramLocation(program, addr(program, 0x00400000)), 0x00210000, false);
			}
			try (Transaction tx = tb2.startTransaction()) {
				DebuggerStaticMappingUtils.addMapping(
					new DefaultTraceLocation(tb2.trace, null, Lifespan.nowOn(0),
						addr(tb2.trace, 0x7fac0000)),
					new ProgramLocation(program, addr(program, 0x00400000)), 0x00010000, false);
			}
			waitForSwing();

			try (Transaction tx = program.openTransaction("Add breakpoint")) {
				program.getBookmarkManager()
						.setBookmark(addr(program, 0x00401234),
							LogicalBreakpoint.ENABLED_BOOKMARK_TYPE,
							"SW_EXECUTE;1", "before connect");
				program.getBookmarkManager()
						.setBookmark(addr(program, 0x00604321),
							LogicalBreakpoint.ENABLED_BOOKMARK_TYPE,
							"WRITE;4", "write version");
			}

			try (Transaction tx = tb1.startTransaction()) {
				tb1.trace.getObjectManager()
						.createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);
				long snap = tb1.trace.getTimeManager().createSnapshot("First").getKey();

				DBTraceBreakpointManager bm = tb1.trace.getBreakpointManager();
				bm.placeBreakpoint("Breakpoints[1]", snap, tb1.addr(0x00401234), List.of(),
					Set.of(TraceBreakpointKind.SW_EXECUTE), true, "ram:00401234");
				bm.placeBreakpoint("Breakpoints[2]", snap, tb1.range(0x00604321, 0x00604324),
					List.of(),
					Set.of(TraceBreakpointKind.WRITE), true, "ram:00604321");
			}

			try (Transaction tx = tb2.startTransaction()) {
				tb2.trace.getObjectManager()
						.createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);
				long snap = tb2.trace.getTimeManager().createSnapshot("First").getKey();

				DBTraceBreakpointManager bm = tb2.trace.getBreakpointManager();
				bm.placeBreakpoint("Breakpoints[1]", snap, tb2.addr(0x7fac1234), List.of(),
					Set.of(TraceBreakpointKind.SW_EXECUTE), false, "ram:7fac1234");
			}

			programManager.openProgram(program);
			traceManager.openTrace(tb1.trace);
			traceManager.openTrace(tb2.trace);

			waitForPass(() -> {
				Set<LogicalBreakpoint> allBreakpoints = breakpointService.getAllBreakpoints();
				assertEquals(2, allBreakpoints.size());
			});
			/**
			 * TODO: Might be necessary to debounce and wait for service callbacks to settle.
			 * Sometimes, there are 3 for just a moment, and then additional callbacks mess things
			 * up.
			 */
			waitForPass(() -> {
				assertEquals(2, provider.breakpointTable.getRowCount());
				assertEquals(3, provider.locationTable.getRowCount());
			});

			captureIsolatedProvider(provider, 600, 600);
		}
	}
}
