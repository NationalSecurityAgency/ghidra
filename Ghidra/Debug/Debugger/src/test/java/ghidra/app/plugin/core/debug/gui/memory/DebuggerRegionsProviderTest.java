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

import java.io.IOException;
import java.util.*;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.table.DynamicTableColumn;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog.MemoryBlockRow;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionMapProposalDialog.RegionMapTableColumns;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.QueryPanelTestHelper;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.util.table.GhidraTable;

@Category(NightlyCategory.class)
public class DebuggerRegionsProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerRegionsProvider provider;

	TraceObjectMemoryRegion regionExeText;
	TraceObjectMemoryRegion regionExeData;
	TraceObjectMemoryRegion regionLibText;
	TraceObjectMemoryRegion regionLibData;

	MemoryBlock blockExeText;
	MemoryBlock blockExeData;

	protected SchemaContext ctx;

	@Override
	protected void createTrace(String langID) throws IOException {
		super.createTrace(langID);
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	public void activateObjectsMode() throws Exception {
		ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Memory' schema='RegionContainer' />
				    </schema>
				    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Region' />
				    </schema>
				    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				        <attribute name='_display' schema='STRING' hidden='yes' />
				        <attribute name='_range' schema='RANGE' hidden='yes' />
				        <attribute name='_readable' schema='BOOL' hidden='yes' />
				        <attribute name='_writable' schema='BOOL' hidden='yes' />
				        <attribute name='_executable' schema='BOOL' hidden='yes' />
				    </schema>
				</context>
				""");

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	protected TraceObjectMemoryRegion addRegion(String name, long loaded, AddressRange range) {
		boolean isData = name.endsWith(".data");
		TraceObjectManager om = tb.trace.getObjectManager();
		TraceObjectKeyPath memPath = TraceObjectKeyPath.parse("Memory");
		Lifespan span = Lifespan.nowOn(loaded);
		TraceObjectMemoryRegion region = Objects.requireNonNull(om.createObject(memPath.index(name))
				.insert(span, ConflictResolution.TRUNCATE)
				.getDestination(null)
				.queryInterface(TraceObjectMemoryRegion.class));
		TraceObject obj = region.getObject();
		obj.setAttribute(span, TargetMemoryRegion.DISPLAY_ATTRIBUTE_NAME, name);
		obj.setAttribute(span, TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, range);
		obj.setAttribute(span, TargetMemoryRegion.READABLE_ATTRIBUTE_NAME, true);
		obj.setAttribute(span, TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME, isData);
		obj.setAttribute(span, TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME, !isData);
		return region;
	}

	protected void addRegions() throws Exception {
		try (Transaction tx = tb.startTransaction()) {
			regionExeText = addRegion("/bin/echo .text", 0, tb.range(0x55550000, 0x555500ff));
			regionExeData = addRegion("/bin/echo .data", 0, tb.range(0x55750000, 0x5575007f));
			regionLibText = addRegion("/lib/libc.so .text", 0, tb.range(0x7f000000, 0x7f0003ff));
			regionLibData = addRegion("/lib/libc.so .data", 0, tb.range(0x7f100000, 0x7f10003f));
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

	protected void assertTableSize(int size) {
		assertEquals(size, provider.panel.getAllItems().size());
	}

	protected void assertRow(int position, Object object, String name, Address start,
			Address end, long length, String flags) {
		ValueRow row = provider.panel.getAllItems().get(position);
		DynamicTableColumn<ValueRow, ?, Trace> nameCol =
			provider.panel.getColumnByNameAndType("Name", ValueRow.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> startCol =
			provider.panel.getColumnByNameAndType("Start", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> endCol =
			provider.panel.getColumnByNameAndType("End", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> lengthCol =
			provider.panel.getColumnByNameAndType("Length", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> readCol =
			provider.panel.getColumnByNameAndType("Read", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> writeCol =
			provider.panel.getColumnByNameAndType("Write", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> executeCol =
			provider.panel.getColumnByNameAndType("Execute", ValueProperty.class).getValue();

		assertSame(object, row.getValue().getValue());
		assertEquals(name, rowColDisplay(row, nameCol));
		assertEquals(start, rowColVal(row, startCol));
		assertEquals(end, rowColVal(row, endCol));
		assertEquals(length, rowColVal(row, lengthCol));
		assertEquals(flags.contains("r"), rowColVal(row, readCol));
		assertEquals(flags.contains("w"), rowColVal(row, writeCol));
		assertEquals(flags.contains("x"), rowColVal(row, executeCol));
	}

	@Before
	public void setUpRegionsProviderTest() throws Exception {
		addPlugin(tool, DebuggerRegionsPlugin.class);
		provider = waitForComponentProvider(DebuggerRegionsProvider.class);
	}

	@After
	public void tearDownRegionsProviderTest() throws Exception {
		traceManager.activate(DebuggerCoordinates.NOWHERE);
		waitForTasks();
		runSwing(() -> traceManager.closeAllTraces());
	}

	@Test
	public void testNoTraceEmpty() throws Exception {
		waitForPass(() -> assertTableSize(0));
	}

	@Test
	public void testActivateEmptyTraceEmpty() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertTableSize(0));
	}

	@Test
	public void testAddThenActivateTracePopulates() throws Exception {
		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});
	}

	@Test
	public void testActivateTraceThenAddPopulates() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		waitForPass(() -> assertTableSize(0));

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});
	}

	@Test
	public void testRemoveRegionRemovesFromTable() throws Exception {
		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});

		try (Transaction tx = tb.startTransaction()) {
			region.getObject().removeTree(Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertTableSize(0));
	}

	@Test
	public void testUndoRedo() throws Exception {
		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});

		undo(tb.trace);
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertTableSize(0));

		redo(tb.trace);
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});
	}

	@Test
	public void testAbort() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
			waitForDomainObject(tb.trace);
			waitForTasks();

			waitForPass(() -> {
				assertTableSize(1);
				assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000),
					tb.addr(0x0040ffff), 0x10000, "rx");
			});
			tx.abort();
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> assertTableSize(0));
	}

	@Test
	public void testDoubleClickNavigates() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000), tb.addr(0x0040ffff),
				0x10000, "rx");
		});
		waitForPass(() -> assertFalse(tb.trace.getProgramView().getMemory().isEmpty()));

		int startColIdx =
			provider.panel.getColumnByNameAndType("Start", ValueProperty.class).getKey();
		int endColIdx = provider.panel.getColumnByNameAndType("End", ValueProperty.class).getKey();
		GhidraTable table = QueryPanelTestHelper.getTable(provider.panel);

		clickTableCell(table, 0, startColIdx, 2);
		waitForPass(() -> assertEquals(tb.addr(0x00400000), listing.getLocation().getAddress()));

		clickTableCell(table, 0, endColIdx, 2);
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
		waitForPass(() -> assertTableSize(4));

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

		// Table sorts by name by default, so .data is first
		entry = proposal.get(0);
		assertEquals(regionExeData, entry.getRegion());
		assertEquals(blockExeData, entry.getBlock());
		entry = proposal.get(1);
		assertEquals(regionExeText, entry.getRegion());
		assertEquals(blockExeText, entry.getBlock());

		// Select the .text row
		clickTableCell(propDialog.getTable(), 1, RegionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);
		MemoryBlockRow row = blockDialog.getTableFilterPanel().getSelectedItem();
		assertEquals(blockExeText, row.getBlock());

		pressButtonByText(blockDialog, "OK", true);
		assertEquals(blockExeText, entry.getBlock()); // Unchanged
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(2, mappings.size());
		// Ordered by db key. Thus, in order added
		Iterator<? extends TraceStaticMapping> mit = mappings.iterator();
		TraceStaticMapping sm;

		sm = mit.next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00600000", sm.getStaticAddress());
		assertEquals(0x80, sm.getLength());
		assertEquals(tb.addr(0x55750000), sm.getMinTraceAddress());

		sm = mit.next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x100, sm.getLength());
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());

		assertFalse(mit.hasNext());
	}

	@Test
	public void testActionSelectAddresses() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000),
				tb.addr(0x0040ffff), 0x10000, "rx");
		});
		waitForPass(() -> assertFalse(tb.trace.getProgramView().getMemory().isEmpty()));

		provider.setSelectedRegions(Set.of(region));
		waitForSwing();
		performEnabledAction(provider, provider.actionSelectAddresses, true);

		waitForPass(() -> assertEquals(tb.set(tb.range(0x00400000, 0x0040ffff)),
			new AddressSet(listing.getSelection())));
	}

	@Test
	public void testActionAddRegion() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		performEnabledAction(provider, provider.actionAddRegion, false);
		DebuggerAddRegionDialog dialog = waitForDialogComponent(DebuggerAddRegionDialog.class);
		runSwing(() -> {
			dialog.setName("Memory[heap]");
			dialog.setFieldLength(0x1000);
			dialog.lengthChanged(); // simulate ENTER/focus-exited
			dialog.okCallback();
		});
		waitForSwing();

		TraceMemoryRegion region = Unique.assertOne(tb.trace.getMemoryManager().getAllRegions());
		assertEquals(tb.range(0, 0xfff), region.getRange());
	}

	@Test
	public void testActionSelectRows() throws Exception {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listing = waitForComponentProvider(DebuggerListingProvider.class);

		createAndOpenTrace();

		TraceObjectMemoryRegion region;
		try (Transaction tx = tb.startTransaction()) {
			region = addRegion("bin:.text", 0, tb.range(0x00400000, 0x0040ffff));
		}

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		waitForPass(() -> {
			assertTableSize(1);
			assertRow(0, region.getObject(), "bin:.text", tb.addr(0x00400000),
				tb.addr(0x0040ffff), 0x10000, "rx");
		});
		waitForPass(() -> assertFalse(tb.trace.getProgramView().getMemory().isEmpty()));

		listing.setSelection(new ProgramSelection(tb.set(tb.range(0x00401234, 0x00404321))));
		waitForPass(() -> assertEquals(tb.set(tb.range(0x00401234, 0x00404321)),
			new AddressSet(listing.getSelection())));

		waitForSwing();
		performEnabledAction(listing, provider.actionSelectRows, true);

		waitForPass(() -> {
			List<ValueRow> allItems = provider.panel.getAllItems();
			assertEquals(Set.of(allItems.get(0)), Set.copyOf(provider.panel.getSelectedItems()));
		});
	}
}
