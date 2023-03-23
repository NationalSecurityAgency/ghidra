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
package ghidra.app.plugin.core.debug.gui.copying;

import java.util.Set;

import org.junit.*;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest.TestDebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.module.DBTraceModuleManager;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerCopyActionsPluginScreenShots extends GhidraScreenShotGenerator {

	ProgramManager programManager;
	DebuggerTraceManagerService traceManager;
	DebuggerModelService modelService;
	DebuggerStaticMappingServicePlugin mappingService;
	DebuggerListingPlugin listingPlugin;
	DebuggerListingProvider listingProvider;
	DebuggerCopyActionsPlugin copyPlugin;
	TestDebuggerModelBuilder mb;
	ToyDBTraceBuilder tb;

	@Before
	public void setUpMine() throws Throwable {
		programManager = addPlugin(tool, ProgramManagerPlugin.class);
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		modelService = addPlugin(tool, DebuggerModelServicePlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		copyPlugin = addPlugin(tool, DebuggerCopyActionsPlugin.class);

		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		mb = new TestDebuggerModelBuilder();
		mb.createTestModel();
		mb.createTestProcessesAndThreads();
		TraceRecorder recorder = modelService.recordTarget(mb.testProcess1,
			new TestDebuggerTargetTraceMapper(mb.testProcess1), ActionSource.AUTOMATIC);
		tb = new ToyDBTraceBuilder(recorder.getTrace());
	}

	@After
	public void tearDownMine() {
		tb.close();

		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testCaptureDebuggerCopyIntoProgramDialog() throws Throwable {
		long snap;
		try (Transaction tx = tb.startTransaction()) {
			snap = tb.trace.getTimeManager().createSnapshot("First").getKey();
			DBTraceMemoryManager mem = tb.trace.getMemoryManager();
			mem.createRegion(".text", snap, tb.range(0x55550000, 0x5555ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			mem.createRegion(".data", snap, tb.range(0x55560000, 0x5556ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));
			mem.createRegion("[stack]", snap, tb.range(0x00100000, 0x001fffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

			DBTraceModuleManager mods = tb.trace.getModuleManager();

			TraceModule modEcho = mods.addLoadedModule("Modules[/bin/echo]", "/bin/echo",
				tb.range(0x55550000, 0x5556ffff), snap);
			modEcho.addSection("Modules[/bin/echo].Sections[.text]", ".text",
				tb.range(0x55550000, 0x5555ffff));
			modEcho.addSection("Modules[/bin/echo].Sections[.data]", ".data",
				tb.range(0x55560000, 0x5556ffff));
		}

		program = createDefaultProgram("echo", "Toy:BE:64:default", this);
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		try (Transaction tx = program.openTransaction("Add memory")) {
			program.setImageBase(tb.addr(stSpace, 0x00400000), true);
			Memory memory = program.getMemory();
			memory.createInitializedBlock(".text", tb.addr(stSpace, 0x00400000), 0x10000, (byte) 0,
				TaskMonitor.DUMMY, false);
			memory.createInitializedBlock(".data", tb.addr(stSpace, 0x00600000), 0x10000, (byte) 0,
				TaskMonitor.DUMMY, false);
		}

		DomainFolder root = tool.getProject().getProjectData().getRootFolder();
		root.createFile(tb.trace.getName(), tb.trace, TaskMonitor.DUMMY);
		root.createFile(program.getName(), program, TaskMonitor.DUMMY);

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(snap), tb.addr(0x55550000)),
				new ProgramLocation(program, tb.addr(stSpace, 0x00400000)), 0x10000, true);
			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(snap), tb.addr(0x55560000)),
				new ProgramLocation(program, tb.addr(stSpace, 0x00600000)), 0x10000, true);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);

		programManager.openProgram(program);

		listingProvider.requestFocus();
		waitForSwing();

		listingProvider.setSelection(
			new ProgramSelection(tb.trace.getMemoryManager().getRegionsAddressSet(snap)));

		waitForCondition(() -> copyPlugin.actionCopyIntoCurrentProgram.isEnabled());
		performAction(copyPlugin.actionCopyIntoCurrentProgram, false);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setRelocate(true);
		dialog.reset();
		waitForSwing();

		captureDialog(DebuggerCopyIntoProgramDialog.class, 700, 600);
	}
}
