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
package ghidra.app.plugin.core.debug.gui.memory;

import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerRegionsPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerRegionsPlugin regionsPlugin;
	DebuggerRegionsProvider regionsProvider;
	ToyDBTraceBuilder tb;
	Program progBash;
	Program progLibC;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		regionsPlugin = addPlugin(tool, DebuggerRegionsPlugin.class);

		regionsProvider = waitForComponentProvider(DebuggerRegionsProvider.class);

		tb = new ToyDBTraceBuilder("echo", ToyProgramBuilder._X64);
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (progBash != null) {
			progBash.release(this);
		}
		if (progLibC != null) {
			progLibC.release(this);
		}
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void populateTrace() throws Exception {
		try (Transaction tx = tb.startTransaction()) {

			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();

			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("/bin/bash (400000:40ffff)", Lifespan.nowOn(snap),
				tb.range(0x00400000, 0x0040ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			mm.addRegion("/bin/bash (600000:60ffff)", Lifespan.nowOn(snap),
				tb.range(0x00600000, 0x0060ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));
			mm.addRegion("/lib/libc (7fac0000:7facffff)", Lifespan.nowOn(snap),
				tb.range(0x7fac0000, 0x7facffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			mm.addRegion("/lib/libc (7fcc0000:7fccffff)", Lifespan.nowOn(snap),
				tb.range(0x7fcc0000, 0x7fccffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));
		}
	}

	private void populateTraceAndPrograms() throws Exception {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();

		populateTrace();

		progBash = createDefaultProgram("bash", ProgramBuilder._X64, this);
		progLibC = createDefaultProgram("libc.so.6", ProgramBuilder._X64, this);

		try (Transaction tx = progBash.openTransaction("Add memory")) {
			progBash.setImageBase(addr(progBash, 0x00400000), true);
			progBash.getMemory()
					.createInitializedBlock(".text", addr(progBash, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			progBash.getMemory()
					.createInitializedBlock(".data", addr(progBash, 0x00600000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
		}

		try (Transaction tx = progLibC.openTransaction("Add memory")) {
			progLibC.setImageBase(addr(progLibC, 0x00400000), true);
			progLibC.getMemory()
					.createInitializedBlock(".text", addr(progLibC, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			progLibC.getMemory()
					.createInitializedBlock(".data", addr(progLibC, 0x00600000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
		}

		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("bash", progBash, TaskMonitor.DUMMY);
		root.createFile("libc.so.6", progLibC, TaskMonitor.DUMMY);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		programManager.openProgram(progBash);
		programManager.openProgram(progLibC);
	}

	@Test
	public void testCaptureDebuggerRegionsPlugin() throws Throwable {
		populateTrace();

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		captureIsolatedProvider(DebuggerRegionsProvider.class, 900, 300);
	}

	@Test
	public void testCaptureDebuggerRegionMapProposalDialog() throws Throwable {
		populateTraceAndPrograms();

		regionsProvider
				.setSelectedRegions(Set.copyOf(tb.trace.getMemoryManager().getAllRegions()));
		performAction(regionsProvider.actionMapRegions, false);

		captureDialog(DebuggerRegionMapProposalDialog.class);
	}
}
