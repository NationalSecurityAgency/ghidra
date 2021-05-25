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

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import generic.Unique;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsProvider.RegionTableColumns;
import ghidra.program.model.address.AddressSet;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.memory.*;
import ghidra.util.database.UndoableTransaction;

public class DebuggerRegionsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerRegionsProvider provider;

	@Before
	public void setUpRegionsTest() throws Exception {
		addPlugin(tool, DebuggerRegionsPlugin.class);
		provider = waitForComponentProvider(DebuggerRegionsProvider.class);
	}

	@Test
	public void testNoTraceEmpty() throws Exception {
		assertEquals(0, provider.regionTableModel.getModelData().size());
	}

	@Test
	public void testActivateEmptyTraceEmpty() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, provider.regionTableModel.getModelData().size());
	}

	@Test
	public void testAddThenActivateTracePopulates() throws Exception {
		createTrace();

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());
		assertEquals("bin:.text", row.getName());
		assertEquals(tb.addr(0x00400000), row.getMinAddress());
		assertEquals(tb.addr(0x0040ffff), row.getMaxAddress());
		assertEquals(tb.range(0x00400000, 0x0040ffff), row.getRange());
		assertEquals(0x10000, row.getLength());
		assertEquals(0L, row.getCreatedSnap());
		assertEquals("", row.getDestroyedSnap());
		assertEquals(Range.atLeast(0L), row.getLifespan());
	}

	@Test
	public void testActivateTraceThenAddPopulates() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		waitForSwing();

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());
	}

	@Test
	public void testDeleteRemoves() throws Exception {
		createTrace();

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());

		try (UndoableTransaction tid = tb.startTransaction()) {
			region.delete();
		}
		waitForDomainObject(tb.trace);

		assertEquals(0, provider.regionTableModel.getModelData().size());
	}

	@Test
	public void testUndoRedo() throws Exception {
		createTrace();

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		Unique.assertOne(provider.regionTableModel.getModelData());

		undo(tb.trace);
		assertEquals(0, provider.regionTableModel.getModelData().size());

		redo(tb.trace);
		Unique.assertOne(provider.regionTableModel.getModelData());
	}

	@Test
	public void testAbort() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			waitForDomainObject(tb.trace);
			Unique.assertOne(provider.regionTableModel.getModelData());
			tid.abort();
		}
		waitForDomainObject(tb.trace);
		assertEquals(0, provider.regionTableModel.getModelData().size());
	}

	@Test
	public void testDoubleClickNavigates() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(() -> assertEquals(1, provider.regionTable.getRowCount()));

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());

		clickTableCell(provider.regionTable, 0, RegionTableColumns.START.ordinal(), 2);
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listing.getLocation().getAddress()));

		clickTableCell(provider.regionTable, 0, RegionTableColumns.END.ordinal(), 2);
		waitForPass(() -> assertEquals(tb.addr(0x0040ffff), listing.getLocation().getAddress()));
	}

	@Test
	public void testActionSelectAddresses() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		waitForPass(() -> assertEquals(1, provider.regionTable.getRowCount()));
		assertEquals(region, row.getRegion());
		assertFalse(tb.trace.getProgramView().getMemory().isEmpty());

		provider.setSelectedRegions(Set.of(region));
		waitForSwing();
		assertTrue(provider.actionSelectAddresses.isEnabled());
		performAction(provider.actionSelectAddresses);

		waitForPass(() -> assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			new AddressSet(listing.getSelection())));
	}

	@Test
	public void testActionSelectRows() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (UndoableTransaction tid = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("bin:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.regionTableModel.getModelData());
		// NB. Table is debounced
		waitForPass(() -> assertEquals(1, provider.regionTable.getRowCount()));
		assertEquals(region, row.getRegion());
		assertFalse(tb.trace.getProgramView().getMemory().isEmpty());

		listing.setSelection(new ProgramSelection(tb.set(tb.range(0x00401234, 0x00404321))));
		waitForPass(() -> assertEquals(tb.set(tb.range(0x00401234, 0x00404321)),
			new AddressSet(listing.getSelection())));

		waitForSwing();
		assertTrue(provider.actionSelectRows.isEnabled());
		performAction(provider.actionSelectRows);

		waitForPass(() -> assertEquals(Set.of(row), Set.copyOf(provider.getSelectedRows())));
	}
}
