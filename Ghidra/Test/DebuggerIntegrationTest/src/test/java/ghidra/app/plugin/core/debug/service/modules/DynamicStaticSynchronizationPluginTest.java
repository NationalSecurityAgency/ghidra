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
package ghidra.app.plugin.core.debug.service.modules;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsolePlugin;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.BoundAction;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider.LogRow;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.ProgramManager;
import ghidra.debug.api.modules.DebuggerMissingModuleActionContext;
import ghidra.debug.api.modules.DebuggerOpenProgramActionContext;
import ghidra.framework.model.*;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.ToyDBTraceBuilder.ToySchemaBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DynamicStaticSynchronizationPluginTest
		extends AbstractGhidraHeadedDebuggerIntegrationTest {

	protected DynamicStaticSynchronizationPlugin syncPlugin;

	protected CodeBrowserPlugin codePlugin;
	protected CodeViewerProvider codeProvider;
	protected DebuggerListingPlugin listingPlugin;
	protected DebuggerListingProvider listingProvider;

	protected DebuggerStaticMappingService mappingService;

	@Before
	public void setUpStaticSyncPluginTest() throws Exception {
		syncPlugin = addPlugin(tool, DynamicStaticSynchronizationPlugin.class);

		// Do before listingPlugin, since types collide
		codePlugin = addPlugin(tool, CodeBrowserPlugin.class);
		codeProvider = waitForComponentProvider(CodeViewerProvider.class);

		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		// TODO: If a task crashes, the test framework hangs.
		listingProvider.setAutoDisassemble(false);

		mappingService = tool.getService(DebuggerStaticMappingService.class);
	}

	protected void createMappedTraceAndProgram() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("Memory[exe:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	@Test
	public void testSyncLocationsStaticToDynamicOnGoto() throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		ProgramLocation loc;

		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		// Check no sync when out of bounds
		goTo(tool, program, ss.getAddress(0x00608765));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00401234), loc.getAddress());

		goTo(tool, program, ss.getAddress(0x00607fff));
		waitForSwing();

		loc = listingProvider.getLocation();
		assertEquals(tb.trace.getProgramView(), loc.getProgram());
		assertEquals(tb.addr(0x00407fff), loc.getAddress());
	}

	@Test
	public void testSyncLocationsDynamicToStaticOnSnapChange() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject(new ToySchemaBuilder()
					.noRegisterGroups()
					.useRegistersPerFrame()
					.build(),
				"Target");
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("Memory[exe:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Threads[1]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
			Register pc = tb.trace.getBaseLanguage().getProgramCounter();
			TraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			regs.setValue(1, new RegisterValue(pc, BigInteger.valueOf(0x00401234)));
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		traceManager.activateSnap(1);
		waitForSwing();

		// Sanity check
		ProgramLocation dynamicLoc = listingPlugin.getCurrentLocation();
		assertEquals(tb.trace.getProgramView(), dynamicLoc.getProgram());
		assertEquals(tb.addr(0x00401234), dynamicLoc.getAddress());

		ProgramLocation staticLoc = codePlugin.getCurrentLocation();
		assertEquals(program, staticLoc.getProgram());
		assertEquals(ss.getAddress(0x00601234), staticLoc.getAddress());
	}

	@Test
	public void testSyncLocationsDynamicToStaticOnLocationChange() throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		listingProvider.getListingPanel()
				.setCursorPosition(
					new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401234)),
					EventTrigger.GUI_ACTION);
		waitForSwing();

		ProgramLocation loc = codePlugin.getCurrentLocation();
		assertEquals(program, loc.getProgram());
		assertEquals(ss.getAddress(0x00601234), loc.getAddress());
	}

	@Test
	public void testSyncSelectionsDynamicToStaticOnSelectionChange()
			throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		runSwing(() -> listingProvider.getListingPanel()
				.setSelection(new ProgramSelection(tb.addr(0x00401234), tb.addr(0x00404321)),
					EventTrigger.GUI_ACTION));
		waitForSwing();

		assertEquals(tb.set(tb.range(ss, 0x00601234, 0x00604321)),
			codePlugin.getCurrentSelection());
	}

	@Test
	public void testSyncSelectionsStaticToDynamicOnSelectionChange()
			throws Exception {
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		runSwing(() -> codePlugin.getListingPanel()
				.setSelection(
					new ProgramSelection(tb.addr(ss, 0x00601234), tb.addr(ss, 0x00604321)),
					EventTrigger.GUI_ACTION));
		waitForSwing();

		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());
	}

	@Test
	public void testActionSyncLocations() throws Exception {
		assertTrue(syncPlugin.actionSyncLocations.isEnabled());

		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		// Check default is on
		assertTrue(syncPlugin.actionSyncLocations.isSelected());
		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		performAction(syncPlugin.actionSyncLocations);
		assertFalse(syncPlugin.actionSyncLocations.isSelected());
		// NOTE: address must be mapped, or else we're not really testing action selection
		goTo(tool, program, ss.getAddress(0x00607654));
		waitForSwing();
		// Verify the goTo was effective, but no change to dynamic listing location
		assertEquals(ss.getAddress(0x00607654), codePlugin.getCurrentLocation().getAddress());
		assertEquals(tb.addr(0x00401234), listingProvider.getLocation().getAddress());

		syncPlugin.setSyncLocations(true);
		// NOTE: Toggling adjusts the dynamic listing, because last goTo was static 
		waitForSwing();
		assertTrue(syncPlugin.actionSyncLocations.isSelected());
		assertEquals(ss.getAddress(0x00607654), codePlugin.getCurrentLocation().getAddress());
		assertEquals(tb.addr(0x00407654), listingProvider.getLocation().getAddress());
	}

	@Test
	public void testActionSyncSelections() throws Exception {
		assertTrue(syncPlugin.actionSyncSelections.isEnabled());

		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		// Check default is on
		assertTrue(syncPlugin.actionSyncSelections.isSelected());
		makeSelection(tool, program, tb.range(ss, 0x00601234, 0x00604321));
		goTo(tool, program, ss.getAddress(0x00601234));
		waitForSwing();
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());

		performAction(syncPlugin.actionSyncSelections);
		assertFalse(syncPlugin.actionSyncSelections.isSelected());
		goTo(tool, program, ss.getAddress(0x00608765));
		makeSelection(tool, program, tb.range(ss, 0x00605678, 0x00608765));
		waitForSwing();
		// Verify the makeSelection was effective, but no change to dynamic listing location
		assertEquals(tb.set(tb.range(ss, 0x00605678, 0x00608765)),
			codePlugin.getCurrentSelection());
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());

		syncPlugin.setSyncSelections(true);
		// NOTE: Toggling adjusts the dynamic listing, because last selection was static 
		waitForSwing();
		assertTrue(syncPlugin.actionSyncSelections.isSelected());
		assertEquals(tb.set(tb.range(ss, 0x00605678, 0x00608765)),
			codePlugin.getCurrentSelection());
		// Part of range is not mapped
		assertEquals(tb.set(tb.range(0x00405678, 0x00407fff)), listingPlugin.getCurrentSelection());
	}

	@Test
	public void testActionTransferSelectionDynamicToStatic() throws Exception {
		syncPlugin.setSyncSelections(false);
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		listingProvider.getListingPanel()
				.setSelection(new ProgramSelection(tb.set(tb.range(0x00401234, 0x00404321))),
					EventTrigger.GUI_ACTION);
		assertTrue(codePlugin.getCurrentSelection().isEmpty());

		performAction(syncPlugin.actionTransferSelectionDynamicToStatic, true);
		assertEquals(tb.set(tb.range(ss, 0x00601234, 0x00604321)),
			codePlugin.getCurrentSelection());
	}

	@Test
	public void testActionTransferSelectionStaticToDynamic() throws Exception {
		syncPlugin.setSyncSelections(false);
		createMappedTraceAndProgram();
		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();

		makeSelection(tool, program, tb.set(tb.range(ss, 0x00601234, 0x00604321)));
		assertTrue(listingPlugin.getCurrentSelection().isEmpty());

		performAction(syncPlugin.actionTransferSelectionStaticToDynamic, true);
		assertEquals(tb.set(tb.range(0x00401234, 0x00404321)), listingPlugin.getCurrentSelection());
	}

	@Test
	public void testSyncLocationsOpensModule() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(".text", ss.getAddress(0x00600000), 0x10000, (byte) 0,
						monitor, false);
		}
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("Memory[exe:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, ss.getAddress(0x00600000));
			mappingService.addMapping(from, to, 0x8000, false);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);

		programManager.closeAllPrograms(true);
		waitForPass(() -> assertEquals(0, programManager.getAllOpenPrograms().length));

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		listingProvider.getListingPanel()
				.setCursorPosition(
					new ProgramLocation(tb.trace.getProgramView(), tb.addr(0x00401234)),
					EventTrigger.GUI_ACTION);
		waitForSwing();

		waitForPass(() -> assertEquals(1, programManager.getAllOpenPrograms().length));
		assertTrue(java.util.List.of(programManager.getAllOpenPrograms()).contains(program));

		assertFalse(consolePlugin
				.logContains(new DebuggerOpenProgramActionContext(program.getDomainFile())));
	}

	@Test
	public void testSyncLocationsLogsRecoverableProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "root");
		DomainFile df = new TestDummyDomainFile(root, "dummyFile") {
			@Override
			public boolean canRecover() {
				return true;
			}
		};

		syncPlugin.doTryOpenProgram(df, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
		waitForSwing();

		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		waitForPass(() -> assertTrue(consolePlugin.logContains(ctx)));
		assertTrue(consolePlugin.getLogRow(ctx).message() instanceof String message &&
			message.contains("recovery"));
	}

	@Test
	public void testSyncLocationsLogsUpgradeableProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "root");
		DomainFile df = new TestDummyDomainFile(root, "dummyFile") {
			@Override
			public boolean canRecover() {
				return false;
			}

			@Override
			public DomainObject getDomainObject(Object consumer, boolean okToUpgrade,
					boolean okToRecover, TaskMonitor monitor)
					throws VersionException, IOException, CancelledException {
				throw new VersionException();
			}
		};

		syncPlugin.doTryOpenProgram(df, DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
		waitForSwing();

		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		waitForPass(() -> assertTrue(consolePlugin.logContains(ctx)));
		assertTrue(consolePlugin.getLogRow(ctx).message() instanceof String message &&
			message.contains("version"));
	}

	@Test
	public void testPromptImportCurrentModuleWithSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			tb.trace.getMemoryManager()
					.addRegion("Memory[bash:.text]", Lifespan.nowOn(0),
						tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			TraceModule bin = tb.trace.getModuleManager()
					.addLoadedModule("Modules[/bin/bash]", "/bin/bash",
						tb.range(0x00400000, 0x0041ffff), 0);
			bin.addSection(0, "Modules[/bin/bash].Sections[.text]",
				tb.range(0x00400000, 0x0040ffff));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		Swing.runNow(() -> consolePlugin.clear());

		// In the module, but not in its section
		assertTrue(listingPlugin.goTo(tb.addr(0x00411234), true));
		waitForSwing();
		waitForPass(() -> assertEquals(0,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));

		assertTrue(listingPlugin.goTo(tb.addr(0x00401234), true));
		waitForSwing();
		waitForPass(() -> assertEquals(1,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));
	}

	@Test
	public void testPromptImportCurrentModuleWithoutSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject("Target");
			tb.trace.getMemoryManager()
					.addRegion("Memory[bash:.text]", Lifespan.nowOn(0),
						tb.range(0x00400000, 0x0041ffff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			tb.trace.getModuleManager()
					.addLoadedModule("Modules[/bin/bash]", "/bin/bash",
						tb.range(0x00400000, 0x0041ffff), 0);
		}
		waitForDomainObject(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// In the module, but not in its section
		assertTrue(listingPlugin.goTo(tb.addr(0x00411234), true));
		waitForSwing();
		waitForPass(() -> assertEquals(1,
			consolePlugin.getRowCount(DebuggerMissingModuleActionContext.class)));
	}

	@Test
	public void testActionOpenProgram() throws Exception {
		DebuggerConsolePlugin consolePlugin = addPlugin(tool, DebuggerConsolePlugin.class);

		createProgram();
		intoProject(program);

		assertEquals(0, programManager.getAllOpenPrograms().length);

		DebuggerOpenProgramActionContext ctx =
			new DebuggerOpenProgramActionContext(program.getDomainFile());
		consolePlugin.log(DebuggerResources.ICON_MODULES, "Test resolution", ctx);
		waitForSwing();

		LogRow<?> row = consolePlugin.getLogRow(ctx);
		assertEquals(1, row.actions().size());
		BoundAction boundAction = row.actions().get(0);
		assertEquals(syncPlugin.actionOpenProgram, boundAction.action);

		boundAction.perform();
		waitForSwing();

		waitForPass(() -> assertEquals(1, programManager.getAllOpenPrograms().length));
		assertTrue(java.util.List.of(programManager.getAllOpenPrograms()).contains(program));
		// TODO: Test this independent of this particular action?
		assertNull(consolePlugin.getLogRow(ctx));
	}
}
