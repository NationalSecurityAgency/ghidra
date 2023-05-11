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

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.action.DockingActionIf;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.action.AutoReadMemorySpec;
import ghidra.app.plugin.core.debug.gui.action.NoneAutoReadMemorySpec;
import ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyIntoProgramDialog.RangeEntry;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.ActionSource;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.test.ToyProgramBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryFlag;

@Category(NightlyCategory.class)
public class DebuggerCopyActionsPluginTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerCopyActionsPlugin copyActionsPlugin;
	DebuggerListingPlugin listingPlugin;
	DebuggerStaticMappingService mappingService;

	DebuggerListingProvider listingProvider;

	@Before
	public void setupCopyActionsPluginTest() throws Exception {
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		copyActionsPlugin = addPlugin(tool, DebuggerCopyActionsPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);
	}

	protected void assertDisabled(DockingActionIf action) {
		assertDisabled(listingProvider, action);
	}

	protected void performEnabledAction(DockingActionIf action) {
		performEnabledAction(listingProvider, action, false);
	}

	protected void select(Address min, Address max) {
		select(listingProvider, min, max);
	}

	protected void select(AddressSetView set) {
		select(listingProvider, set);
	}

	@Test
	public void testActionCopyIntoCurrentProgramWithoutRelocationCreateBlocks() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		createProgram();
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();
		programManager.openProgram(program);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		createAndOpenTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		select(tb.addr(0x00400000), tb.addr(0x0040ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoCurrentProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setRelocate(false);
		dialog.reset();

		RangeEntry entry = Unique.assertOne(dialog.tableModel.getModelData());

		assertEquals(tb.range(stSpace, 0x00400000, 0x0040ffff), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0x00400000, 0x0040ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text", entry.getBlockName());
		assertTrue(entry.isCreate());
		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		MemoryBlock text = Unique.assertOne(Arrays.asList(program.getMemory().getBlocks()));
		assertEquals(".text", text.getName());
	}

	@Test
	public void testActionCopyIntoCurrentProgramWithoutRelocationCrossLanguage() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		createProgram(getSLEIGH_X86_LANGUAGE());
		createAndOpenTrace(ToyProgramBuilder._X64);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		try (Transaction tx = program.openTransaction("Add blocks")) {
			program.getMemory()
					.createInitializedBlock(".text", tb.addr(stSpace, 0x00400000), 0x8000, (byte) 0,
						monitor, false);
			program.getMemory()
					.createInitializedBlock(".text2", tb.addr(stSpace, 0x00408000), 0x8000,
						(byte) 0, monitor, false);
		}

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion(".text", 0, tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ,
				TraceMemoryFlag.EXECUTE);
			mm.putBytes(0, tb.addr(0x00401234), tb.buf(1, 2, 3, 4));

			// This region should be excluded, since it cannot be mapped identically into 32-bits
			mm.createRegion("lib:.text", 0, tb.range(0x7fff00400000L, 0x7fff0040ffffL),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			// This region should be partially excluded, because 32-bits
			// This is not likely to ever happen in practice, but be prepared
			mm.createRegion(".straddle", 0, tb.range(0xfffff000L, 0x100000fffL),
				TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}

		programManager.openProgram(program);
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		select(tb.set(tb.range(0x00400000, 0x0040ffff), tb.range(0x7fff00400000L, 0x7fff0040ffffL),
			tb.range(0xfffff000L, 0x100000fffL)));

		performEnabledAction(copyActionsPlugin.actionCopyIntoCurrentProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setRelocate(false);
		dialog.reset();

		List<RangeEntry> entries = List.copyOf(dialog.tableModel.getModelData());
		assertEquals(3, entries.size());
		RangeEntry entry;

		entry = entries.get(0);
		assertEquals(tb.range(0x00400000, 0x00407fff), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0x00400000, 0x00407fff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text *", entry.getBlockName());
		assertFalse(entry.isCreate());

		entry = entries.get(1);
		assertEquals(tb.range(0x00408000, 0x0040ffff), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0x00408000, 0x0040ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text2 *", entry.getBlockName());
		assertFalse(entry.isCreate());

		entry = entries.get(2);
		assertEquals(tb.range(0xfffff000L, 0xffffffffL), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0xfffff000L, 0xffffffffL), entry.getDstRange());
		assertEquals(".straddle", entry.getRegionName());
		assertEquals(".straddle", entry.getBlockName());
		assertTrue(entry.isCreate());

		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		byte[] dest = new byte[4];
		program.getMemory().getBytes(tb.addr(stSpace, 0x00401234), dest);
		assertArrayEquals(tb.arr(1, 2, 3, 4), dest);
	}

	@Test
	public void testActionCopyIntoCurrentProgramWithRelocationExistingBlocks() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		createAndOpenTrace();
		createProgramFromTrace();
		intoProject(program);
		intoProject(tb.trace);

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		programManager.openProgram(program);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();
		MemoryBlock block;
		try (Transaction tx = program.openTransaction("Create block")) {
			block = program.getMemory()
					.createUninitializedBlock(".text", tb.addr(stSpace, 0x00400000), 0x10000,
						false);
		}

		TraceLocation tloc =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x55550000));
		ProgramLocation ploc = new ProgramLocation(program, tb.addr(stSpace, 0x00400000));
		try (Transaction tx = tb.startTransaction()) {
			mappingService.addMapping(tloc, ploc, 0x10000, true);
		}

		waitForValue(() -> mappingService
				.getOpenMappedViews(tb.trace, tb.set(tb.range(0x55550000, 0x5555ffff)), 0)
				.get(program));

		select(tb.addr(0x55550000), tb.addr(0x5555ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoCurrentProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setRelocate(true);
		dialog.reset();

		RangeEntry entry = Unique.assertOne(dialog.tableModel.getModelData());

		assertEquals(tb.range(stSpace, 0x55550000, 0x5555ffff), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0x00400000, 0x0040ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text *", entry.getBlockName());
		assertFalse(entry.isCreate());
		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		MemoryBlock text = Unique.assertOne(Arrays.asList(program.getMemory().getBlocks()));
		assertEquals(block, text);
	}

	@Test
	public void testActionCopyIntoCurrentProgramWithRelocationOverlayBlocks() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		createAndOpenTrace();
		createProgramFromTrace();
		intoProject(program);
		intoProject(tb.trace);

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		programManager.openProgram(program);
		assertDisabled(copyActionsPlugin.actionCopyIntoCurrentProgram);

		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();
		MemoryBlock block;
		try (Transaction tx = program.openTransaction("Create block")) {
			block = program.getMemory()
					.createUninitializedBlock(".text", tb.addr(stSpace, 0x00400000), 0x10000,
						false);
		}

		TraceLocation tloc =
			new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x55550000));
		ProgramLocation ploc = new ProgramLocation(program, tb.addr(stSpace, 0x00400000));
		try (Transaction tx = tb.startTransaction()) {
			mappingService.addMapping(tloc, ploc, 0x10000, true);
		}

		waitForValue(() -> mappingService
				.getOpenMappedViews(tb.trace, tb.set(tb.range(0x55550000, 0x5555ffff)), 0)
				.get(program));

		select(tb.addr(0x55550000), tb.addr(0x5555ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoCurrentProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setRelocate(true);
		dialog.setUseOverlays(true);
		dialog.reset();

		RangeEntry entry = Unique.assertOne(dialog.tableModel.getModelData());

		assertEquals(tb.range(stSpace, 0x55550000, 0x5555ffff), entry.getSrcRange());
		assertEquals(tb.range(stSpace, 0x00400000, 0x0040ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text_2", entry.getBlockName());
		assertTrue(entry.isCreate());
		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		MemoryBlock text2 =
			Unique.assertOne(Arrays.asList(program.getMemory().getBlock(".text_2")));
		assertNotEquals(block, text2);
		assertTrue(text2.isOverlay());
	}

	@Test
	public void testActionCopyIntoNewProgram() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		createAndOpenTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		select(tb.addr(0x55550000), tb.addr(0x5555ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoNewProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		dialog.setDestination(DebuggerCopyIntoProgramDialog.TEMP_PROGRAM);

		RangeEntry entry = Unique.assertOne(dialog.tableModel.getModelData());

		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getSrcRange());
		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text", entry.getBlockName());
		assertTrue(entry.isCreate());
		entry.setBlockName(".my_text");
		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		// Declare my own, or the @After will try to release it erroneously
		Program program = waitForValue(() -> programManager.getCurrentProgram());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		MemoryBlock text = Unique.assertOne(Arrays.asList(program.getMemory().getBlocks()));
		assertEquals(tb.addr(stSpace, 0x55550000), text.getStart());
		assertEquals(".my_text", text.getName());
	}

	@Test
	public void testActionCopyIntoNewProgramAdjacentRegions() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		createAndOpenTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion(".text", 0, tb.range(0x55550000, 0x5555ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			tb.trace.getMemoryManager()
					.createRegion(".data", 0, tb.range(0x55560000, 0x5556ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		select(tb.addr(0x55550000), tb.addr(0x5556ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoNewProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		assertFalse(dialog.cbCapture.isEnabled());
		assertFalse(dialog.cbCapture.isSelected());
		dialog.setDestination(DebuggerCopyIntoProgramDialog.TEMP_PROGRAM);

		assertEquals(2, dialog.tableModel.getRowCount());
		RangeEntry entry;

		entry = dialog.tableModel.getRowObject(0);
		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getSrcRange());
		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getDstRange());
		assertEquals(".text", entry.getRegionName());
		assertEquals(".text", entry.getBlockName());
		assertTrue(entry.isCreate());

		entry = dialog.tableModel.getRowObject(1);
		assertEquals(tb.range(0x55560000, 0x5556ffff), entry.getSrcRange());
		assertEquals(tb.range(0x55560000, 0x5556ffff), entry.getDstRange());
		assertEquals(".data", entry.getRegionName());
		assertEquals(".data", entry.getBlockName());
		assertTrue(entry.isCreate());

		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();

		// Declare my own, or the @After will try to release it erroneously
		Program program = waitForValue(() -> programManager.getCurrentProgram());
		assertEquals(2, program.getMemory().getBlocks().length);
	}

	@Test
	public void testActionCopyIntoNewProgramCaptureLive() throws Throwable {
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		createTestModel();

		var listener = new DebuggerModelListener() {
			int count = 0;

			@Override
			public void memoryUpdated(TargetObject memory, Address address, byte[] data) {
				count++;
			}
		};
		mb.testModel.addModelListener(listener);

		mb.createTestProcessesAndThreads();
		modelService.recordTarget(mb.testProcess1, createTargetTraceMapper(mb.testProcess1),
			ActionSource.AUTOMATIC);
		mb.testProcess1.memory.addRegion(".text", mb.rng(0x55550000, 0x5555ffff), "rx");
		mb.testProcess1.memory.setMemory(mb.addr(0x55550000), mb.arr(1, 2, 3, 4, 5, 6, 7, 8));
		waitForPass(() -> {
			assertEquals(1, tb.trace.getMemoryManager().getAllRegions().size());
		});

		listingProvider.setAutoReadMemorySpec(
			AutoReadMemorySpec.fromConfigName(NoneAutoReadMemorySpec.CONFIG_NAME));

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		assertDisabled(copyActionsPlugin.actionCopyIntoNewProgram);

		select(tb.addr(0x55550000), tb.addr(0x5555ffff));

		performEnabledAction(copyActionsPlugin.actionCopyIntoNewProgram);
		DebuggerCopyIntoProgramDialog dialog =
			waitForDialogComponent(DebuggerCopyIntoProgramDialog.class);
		assertTrue(dialog.cbCapture.isEnabled());
		assertTrue(dialog.cbCapture.isSelected());
		dialog.setDestination(DebuggerCopyIntoProgramDialog.TEMP_PROGRAM);

		RangeEntry entry = Unique.assertOne(dialog.tableModel.getModelData());

		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getSrcRange());
		assertEquals(tb.range(0x55550000, 0x5555ffff), entry.getDstRange());
		assertEquals("[.text]", entry.getRegionName());
		assertEquals("[.text]", entry.getBlockName());
		assertTrue(entry.isCreate());
		entry.setBlockName(".my_text");

		assertEquals(0, listener.count);
		dialog.okCallback();
		waitOn(dialog.lastTask);
		waitForSwing();
		assertEquals(16, listener.count);

		// Declare my own, or the @After will try to release it erroneously
		Program program = waitForValue(() -> programManager.getCurrentProgram());
		AddressSpace stSpace = program.getAddressFactory().getDefaultAddressSpace();

		MemoryBlock text = Unique.assertOne(Arrays.asList(program.getMemory().getBlocks()));
		assertEquals(tb.addr(stSpace, 0x55550000), text.getStart());
		assertEquals(".my_text", text.getName());
		byte[] arr = new byte[8];
		/**
		 * While waitOn will ensure the read request completes, it doesn't ensure the recorder has
		 * actually written the result to the database, yet.
		 */
		waitForPass(noExc(() -> {
			text.getBytes(tb.addr(stSpace, 0x55550000), arr);
			assertArrayEquals(tb.arr(1, 2, 3, 4, 5, 6, 7, 8), arr);
		}));
	}
}
