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
package ghidra.app.plugin.core.debug.gui.stack;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerStackPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerStaticMappingService mappingService;
	DebuggerStackPlugin stackPlugin;
	DebuggerStackProvider stackProvider;
	ToyDBTraceBuilder tb;
	Program program;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		stackPlugin = addPlugin(tool, DebuggerStackPlugin.class);

		stackProvider = waitForComponentProvider(DebuggerStackProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (program != null) {
			program.release(this);
		}
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private static AddressSetView set(Program program, long min, long max) {
		return new AddressSet(addr(program, min), addr(program, max));
	}

	@Test
	public void testCaptureDebuggerStackPlugin() throws Throwable {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();
		program = createDefaultProgram("echo", ToyProgramBuilder._X64, this);
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Populate", true)) {
			program.setImageBase(addr(program, 0x00400000), true);
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			FunctionManager fMan = program.getFunctionManager();
			fMan.createFunction("FUN_00401000", addr(0x00401000),
				set(program, 0x00401000, 0x00401100), SourceType.USER_DEFINED);
			fMan.createFunction("FUN_00401200", addr(0x00401200),
				set(program, 0x00401200, 0x00401300), SourceType.USER_DEFINED);
			fMan.createFunction("FUN_00404300", addr(0x00404300),
				set(program, 0x00404300, 0x00404400), SourceType.USER_DEFINED);
		}
		long snap;
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			snap = tb.trace.getTimeManager().createSnapshot("First").getKey();
			thread = tb.getOrAddThread("[1]", snap);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, snap, true);
			stack.setDepth(3, true);

			TraceStackFrame frame;
			frame = stack.getFrame(0, false);
			frame.setProgramCounter(tb.addr(0x00404321));
			frame = stack.getFrame(1, false);
			frame.setProgramCounter(tb.addr(0x00401234));
			frame = stack.getFrame(2, false);
			frame.setProgramCounter(tb.addr(0x00401001));
		}
		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("echo", program, TaskMonitor.DUMMY);
		try (UndoableTransaction tid = tb.startTransaction()) {
			DebuggerStaticMappingUtils.addMapping(
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(snap), tb.addr(0x00400000)),
				new ProgramLocation(program, addr(program, 0x00400000)), 0x10000, false);
		}

		programManager.openProgram(program);
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);

		captureIsolatedProvider(DebuggerStackProvider.class, 600, 300);
	}
}
