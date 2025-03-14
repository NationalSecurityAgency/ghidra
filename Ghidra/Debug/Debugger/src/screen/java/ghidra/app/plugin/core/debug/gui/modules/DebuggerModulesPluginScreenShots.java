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

import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
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
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerModulesPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerModulesPlugin modulesPlugin;
	DebuggerModulesProvider modulesProvider;
	ToyDBTraceBuilder tb;
	Program progBash;
	Program progLibC;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		modulesPlugin = addPlugin(tool, DebuggerModulesPlugin.class);

		modulesProvider = waitForComponentProvider(DebuggerModulesProvider.class);

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

	@Test
	public void testCaptureDebuggerModulesPlugin() throws Throwable {
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);

			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("Modules[/bin/bash]", "/bin/bash",
						tb.range(0x00400000, 0x0060ffff), snap);
			bin.addSection(snap, "Modules[/bin/bash].Sections[.text]", ".text",
				tb.range(0x00400000, 0x0040ffff));
			bin.addSection(snap, "Modules[/bin/bash].Sections[.data]", ".data",
				tb.range(0x00600000, 0x0060ffff));

			TraceModule lib = tb.trace.getModuleManager()
					.addLoadedModule("Modules[/lib/libc.so.6]", "/lib/libc.so.6",
						tb.range(0x7fac0000, 0x7faeffff), snap);
			lib.addSection(snap, "Modules[/lib/libc.so.6].Sections[.text]", ".text",
				tb.range(0x7fac0000, 0x7facffff));
			lib.addSection(snap, "Modules[/lib/libc.so.6].Sections[.data]", ".data",
				tb.range(0x7fae0000, 0x7faeffff));

			traceManager.openTrace(tb.trace);
			traceManager.activateTrace(tb.trace);

			captureIsolatedProvider(modulesProvider, 600, 600);
		}
	}

	private static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private void populateTraceAndPrograms() throws Exception {
		DomainFolder root = tool.getProject().getProjectData().getRootFolder();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ProgramEmulationUtils.EMU_SESSION_SCHEMA);
			long snap = tb.trace.getTimeManager().createSnapshot("First").getKey();

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("Modules[/bin/bash]", "/bin/bash",
						tb.range(0x00400000, 0x0060ffff), snap);
			bin.addSection(snap, "Modules[/bin/bash].Sections[.text]", ".text",
				tb.range(0x00400000, 0x0040ffff));
			bin.addSection(snap, "Modules[/bin/bash].Sections[.data]", ".data",
				tb.range(0x00600000, 0x0060ffff));

			TraceModule lib = tb.trace.getModuleManager()
					.addLoadedModule("Modules[/lib/libc.so.6]", "/lib/libc.so.6",
						tb.range(0x7fac0000, 0x7faeffff), snap);
			lib.addSection(snap, "Modules[/lib/libc.so.6].Sections[.text]", ".text",
				tb.range(0x7fac0000, 0x7facffff));
			lib.addSection(snap, "Modules[/lib/libc.so.6].Sections[.data]", ".data",
				tb.range(0x7fae0000, 0x7faeffff));
		}

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
	public void testCaptureDebuggerModuleMapProposalDialog() throws Throwable {
		populateTraceAndPrograms();
		waitForTasks();

		modulesProvider.setSelectedModules(Set.copyOf(tb.trace.getModuleManager().getAllModules()));
		performAction(modulesProvider.actionMapModules, false);

		captureDialog(DebuggerModuleMapProposalDialog.class);
	}

	@Test
	public void testCaptureDebuggerSectionMapProposalDialog() throws Throwable {
		populateTraceAndPrograms();
		waitForTasks();

		modulesProvider
				.setSelectedSections(Set.copyOf(tb.trace.getModuleManager().getAllSections()));
		performAction(modulesProvider.actionMapSections, false);

		captureDialog(DebuggerSectionMapProposalDialog.class);
	}
}
