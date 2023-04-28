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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog.MemoryBlockRow;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerLegacyRegionsPanel.RegionTableColumns;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionMapProposalDialog.RegionMapTableColumns;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceStaticMapping;

@Category(NightlyCategory.class)
public class DebuggerRegionsProviderLegacyTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerRegionsProvider provider;

	protected TraceMemoryRegion regionExeText;
	protected TraceMemoryRegion regionExeData;
	protected TraceMemoryRegion regionLibText;
	protected TraceMemoryRegion regionLibData;

	protected MemoryBlock blockExeText;
	protected MemoryBlock blockExeData;

	@Before
	public void setUpRegionsTest() throws Exception {
		addPlugin(tool, DebuggerRegionsPlugin.class);
		provider = waitForComponentProvider(DebuggerRegionsProvider.class);
	}

	protected void addRegions() throws Exception {
		TraceMemoryManager mm = tb.trace.getMemoryManager();
		try (Transaction tx = tb.startTransaction()) {
			regionExeText = mm.createRegion("Memory[/bin/echo 0x55550000]", 0,
				tb.range(0x55550000, 0x555500ff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			regionExeData = mm.createRegion("Memory[/bin/echo 0x55750000]", 0,
				tb.range(0x55750000, 0x5575007f), TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
			regionLibText = mm.createRegion("Memory[/lib/libc.so 0x7f000000]", 0,
				tb.range(0x7f000000, 0x7f0003ff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			regionLibData = mm.createRegion("Memory[/lib/libc.so 0x7f100000]", 0,
				tb.range(0x7f100000, 0x7f10003f), TraceMemoryFlag.READ, TraceMemoryFlag.WRITE);
		}
	}

	protected void addBlocks() throws Exception {
		try (Transaction tx = program.openTransaction("Add block")) {
			Memory mem = program.getMemory();
			blockExeText = mem.createInitializedBlock(".text", tb.addr(0x00400000), 0x100, (byte) 0,
				monitor, false);
			blockExeData = mem.createInitializedBlock(".data", tb.addr(0x00600000), 0x80, (byte) 0,
				monitor, false);
		}
	}

	@Test
	public void testNoTraceEmpty() throws Exception {
		assertEquals(0, provider.legacyPanel.regionTableModel.getModelData().size());
	}

	@Test
	public void testActivateEmptyTraceEmpty() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(0, provider.legacyPanel.regionTableModel.getModelData().size());
	}

	@Test
	public void testAddThenActivateTracePopulates() throws Exception {
		createTrace();

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());
		assertEquals("Memory[bin:.text]", row.getName());
		assertEquals(tb.addr(0x00400000), row.getMinAddress());
		assertEquals(tb.addr(0x0040ffff), row.getMaxAddress());
		assertEquals(tb.range(0x00400000, 0x0040ffff), row.getRange());
		assertEquals(0x10000, row.getLength());
		assertEquals(0L, row.getCreatedSnap());
		assertEquals("", row.getDestroyedSnap());
		assertEquals(Lifespan.nowOn(0), row.getLifespan());
	}

	@Test
	public void testActivateTraceThenAddPopulates() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		waitForSwing();

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());
	}

	@Test
	public void testDeleteRemoves() throws Exception {
		createTrace();

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());

		try (Transaction tx = tb.startTransaction()) {
			region.delete();
		}
		waitForDomainObject(tb.trace);

		assertEquals(0, provider.legacyPanel.regionTableModel.getModelData().size());
	}

	@Test
	public void testUndoRedo() throws Exception {
		createTrace();

		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());

		undo(tb.trace);
		assertEquals(0, provider.legacyPanel.regionTableModel.getModelData().size());

		redo(tb.trace);
		Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
	}

	@Test
	public void testAbort() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			waitForDomainObject(tb.trace);
			Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
			tx.abort();
		}
		waitForDomainObject(tb.trace);
		assertEquals(0, provider.legacyPanel.regionTableModel.getModelData().size());
	}

	@Test
	public void testDoubleClickNavigates() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(() -> assertEquals(1, provider.legacyPanel.regionTable.getRowCount()));

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		assertEquals(region, row.getRegion());

		clickTableCell(provider.legacyPanel.regionTable, 0, RegionTableColumns.START.ordinal(), 2);
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listing.getLocation().getAddress()));

		clickTableCell(provider.legacyPanel.regionTable, 0, RegionTableColumns.END.ordinal(), 2);
		waitForPass(() -> assertEquals(tb.addr(0x0040ffff), listing.getLocation().getAddress()));
	}

	@Test
	public void testActionMapRegions() throws Exception {
		assertFalse(provider.actionMapRegions.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addRegions();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertFalse(provider.actionMapRegions.isEnabled());

		addBlocks();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName("echo");
		}
		waitForDomainObject(program);
		waitForPass(() -> assertEquals(4, provider.legacyPanel.regionTable.getRowCount()));

		// NB. Feature works "best" when all regions of modules are selected
		// TODO: Test cases where feature works "worst"?
		provider.setSelectedRegions(Set.of(regionExeText, regionExeData));
		waitForSwing();
		performEnabledAction(provider, provider.actionMapRegions, false);

		DebuggerRegionMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerRegionMapProposalDialog.class);

		List<RegionMapEntry> proposal = new ArrayList<>(propDialog.getTableModel().getModelData());
		assertEquals(2, proposal.size());
		RegionMapEntry entry;

		// Table sorts by name by default.
		// Names are file name followed by min address, so .text is first.
		entry = proposal.get(0);
		assertEquals(regionExeText, entry.getRegion());
		assertEquals(blockExeText, entry.getBlock());
		entry = proposal.get(1);
		assertEquals(regionExeData, entry.getRegion());
		assertEquals(blockExeData, entry.getBlock());

		clickTableCell(propDialog.getTable(), 0, RegionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);
		MemoryBlockRow row = blockDialog.getTableFilterPanel().getSelectedItem();
		assertEquals(blockExeText, row.getBlock());

		pressButtonByText(blockDialog, "OK", true);
		assertEquals(blockExeData, entry.getBlock()); // Unchanged
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(2, mappings.size());
		Iterator<? extends TraceStaticMapping> mit = mappings.iterator();
		TraceStaticMapping sm;

		sm = mit.next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x100, sm.getLength());
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());

		sm = mit.next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00600000", sm.getStaticAddress());
		assertEquals(0x80, sm.getLength());
		assertEquals(tb.addr(0x55750000), sm.getMinTraceAddress());

		assertFalse(mit.hasNext());
	}

	// TODO: testActionMapRegionsTo
	// TODO: testActionMapRegionTo

	@Test
	public void testActionSelectAddresses() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		waitForPass(() -> assertEquals(1, provider.legacyPanel.regionTable.getRowCount()));
		assertEquals(region, row.getRegion());
		assertFalse(tb.trace.getProgramView().getMemory().isEmpty());

		provider.setSelectedRegions(Set.of(region));
		waitForSwing();
		performEnabledAction(provider, provider.actionSelectAddresses, true);

		waitForPass(() -> assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			new AddressSet(listing.getSelection())));
	}

	@Test
	public void testActionAddRegion() throws Exception {
		createAndOpenTrace();
	}

	@Test
	public void testActionSelectRows() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createTrace();

		TraceMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			TraceMemoryManager mm = tb.trace.getMemoryManager();
			region = mm.addRegion("Memory[bin:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff), TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
		}

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		RegionRow row = Unique.assertOne(provider.legacyPanel.regionTableModel.getModelData());
		// NB. Table is debounced
		waitForPass(() -> assertEquals(1, provider.legacyPanel.regionTable.getRowCount()));
		assertEquals(region, row.getRegion());
		assertFalse(tb.trace.getProgramView().getMemory().isEmpty());

		listing.setSelection(new ProgramSelection(tb.set(tb.range(0x00401234, 0x00404321))));
		waitForPass(() -> assertEquals(tb.set(tb.range(0x00401234, 0x00404321)),
			new AddressSet(listing.getSelection())));

		waitForSwing();
		performEnabledAction(listing, provider.actionSelectRows, true);

		waitForPass(
			() -> assertEquals(Set.of(row), Set.copyOf(provider.legacyPanel.getSelectedRows())));
	}
}
