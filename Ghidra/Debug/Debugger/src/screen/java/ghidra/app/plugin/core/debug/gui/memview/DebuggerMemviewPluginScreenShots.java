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
package ghidra.app.plugin.core.debug.gui.memview;

import java.util.HashSet;
import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.thread.TraceThread;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerMemviewPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerMemviewPlugin memviewPlugin;
	MemviewProvider memviewProvider;
	ToyDBTraceBuilder tb;
	Program progEcho;
	Program progLibC;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		memviewPlugin = addPlugin(tool, DebuggerMemviewPlugin.class);

		memviewProvider = waitForComponentProvider(MemviewProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (progEcho != null) {
			progEcho.release(this);
		}
		if (progLibC != null) {
			progLibC.release(this);
		}
	}

	@Test
	public void testCaptureDebuggerMemviewPlugin() throws Throwable {
		populateTraceAndPrograms();

		memviewProvider.setVisible(true);
		captureIsolatedProvider(memviewProvider, 1000, 400);
	}

	private void populateTraceAndPrograms() throws Exception {
		tool.getProject().getProjectData().getRootFolder();
		TraceThread thread1;
		try (Transaction tx = tb.startTransaction()) {
			thread1 = tb.trace.getThreadManager().addThread("[0]", Lifespan.span(1, 40));
			tb.trace.getThreadManager().addThread("[1]", Lifespan.span(4, 50));
			tb.trace.getThreadManager().addThread("[2]", Lifespan.span(6, 20));
		}

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash", tb.range(0x00400000, 0x0060ffff), 0);
			tb.trace.getModuleManager()
					.addLoadedModule("/lib/libc.so.6", "/lib/libc.so.6",
						tb.range(0x7fac0000, 0x7faeffff), 10);
		}

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("bash.text", Lifespan.nowOn(5), tb.range(0x00400000, 0x0040ffff),
						TraceMemoryFlag.EXECUTE);
			tb.trace.getMemoryManager()
					.addRegion("bash.data", Lifespan.nowOn(6), tb.range(0x00500000, 0x0060ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);

			tb.trace.getMemoryManager()
					.addRegion("libc.text", Lifespan.nowOn(15), tb.range(0x7fac0000, 0x7facffff),
						TraceMemoryFlag.EXECUTE);
			tb.trace.getMemoryManager()
					.addRegion("libc.data", Lifespan.nowOn(16), tb.range(0x7fae0000, 0x7faeffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}

		try (Transaction tx = tb.startTransaction()) {
			Set<TraceThread> threads = new HashSet<TraceThread>();
			Set<TraceBreakpointKind> kinds = new HashSet<TraceBreakpointKind>();
			threads.add(thread1);
			kinds.add(TraceBreakpointKind.HW_EXECUTE);
			tb.trace.getBreakpointManager()
					.addBreakpoint("bpt1", Lifespan.span(17, 25), tb.range(0x7fac1234, 0x7fc1238),
						threads, kinds, true, "break here");
		}

		/*
		progEcho = createDefaultProgram("bash", ProgramBuilder._X64, this);
		progLibC = createDefaultProgram("libc.so.6", ProgramBuilder._X64, this);
		
		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("echo", progEcho, TaskMonitor.DUMMY);
		root.createFile("libc.so.6", progLibC, TaskMonitor.DUMMY);
		*/

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		/*
		programManager.openProgram(progEcho);
		programManager.openProgram(progLibC);
		*/
	}

}
