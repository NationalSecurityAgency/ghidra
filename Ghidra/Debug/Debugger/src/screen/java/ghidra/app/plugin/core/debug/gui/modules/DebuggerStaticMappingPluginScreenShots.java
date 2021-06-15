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
package ghidra.app.plugin.core.debug.gui.modules;

import java.util.*;

import org.junit.*;

import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.DebuggerStaticMappingService.ModuleMapEntry;
import ghidra.app.services.DebuggerStaticMappingService.ModuleMapProposal;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerStaticMappingPluginScreenShots extends GhidraScreenShotGenerator {
	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerStaticMappingServicePlugin mappingService;
	DebuggerStaticMappingPlugin mappingPlugin;
	DebuggerStaticMappingProvider mappingProvider;
	ToyDBTraceBuilder tb;
	Program progEcho;
	Program progLibC;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		mappingPlugin = addPlugin(tool, DebuggerStaticMappingPlugin.class);

		mappingProvider = waitForComponentProvider(DebuggerStaticMappingProvider.class);

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

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Test
	public void testCaptureDebuggerStaticMappingPlugin() throws Throwable {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();
		try (UndoableTransaction tid = tb.startTransaction()) {
			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("/bin/bash", "/bin/bash",
						tb.range(0x00400000, 0x0060ffff), snap);
			bin.addSection("bash[.text]", ".text", tb.range(0x00400000, 0x0040ffff));
			bin.addSection("bash[.data]", ".data", tb.range(0x00600000, 0x0060ffff));
			TraceModule lib = tb.trace.getModuleManager()
					.addLoadedModule("/lib/libc.so.6", "/lib/libc.so.6",
						tb.range(0x7fac0000, 0x7faeffff), snap);
			lib.addSection("libc[.text]", ".text", tb.range(0x7fac0000, 0x7facffff));
			lib.addSection("libc[.data]", ".data", tb.range(0x7fae0000, 0x7faeffff));
		}

		progEcho = createDefaultProgram("bash", ProgramBuilder._X64, this);
		progLibC = createDefaultProgram("libc.so.6", ProgramBuilder._X64, this);

		try (UndoableTransaction tid = UndoableTransaction.start(progEcho, "Add memory", true)) {
			progEcho.setImageBase(addr(progEcho, 0x00400000), true);
			progEcho.getMemory()
					.createInitializedBlock(".text", addr(progEcho, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			progEcho.getMemory()
					.createInitializedBlock(".data", addr(progEcho, 0x00600000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
		}

		try (UndoableTransaction tid = UndoableTransaction.start(progLibC, "Add memory", true)) {
			progLibC.setImageBase(addr(progLibC, 0x00400000), true);
			progLibC.getMemory()
					.createInitializedBlock(".text", addr(progLibC, 0x00400000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
			progLibC.getMemory()
					.createInitializedBlock(".data", addr(progLibC, 0x00600000), 0x10000, (byte) 0,
						TaskMonitor.DUMMY, false);
		}

		root.createFile("trace", tb.trace, TaskMonitor.DUMMY);
		root.createFile("echo", progEcho, TaskMonitor.DUMMY);
		root.createFile("libc.so.6", progLibC, TaskMonitor.DUMMY);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		programManager.openProgram(progEcho);
		programManager.openProgram(progLibC);

		try (UndoableTransaction tid = tb.startTransaction()) {
			Map<TraceModule, ModuleMapProposal> proposal =
				mappingService.proposeModuleMaps(tb.trace.getModuleManager().getAllModules(),
					List.of(programManager.getAllOpenPrograms()));
			Collection<ModuleMapEntry> entries = ModuleMapProposal.flatten(proposal.values());
			mappingService.addModuleMappings(entries, TaskMonitor.DUMMY, false);
		}

		captureIsolatedProvider(DebuggerStaticMappingProvider.class, 700, 400);
	}
}
