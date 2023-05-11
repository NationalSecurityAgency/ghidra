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

import static org.junit.Assert.*;

import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.*;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.DynamicTableColumn;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.*;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog.MemoryBlockRow;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractImportFromFileSystemAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.QueryPanelTestHelper;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModuleMapProposalDialog.ModuleMapTableColumns;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapModulesAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapSectionsAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionMapProposalDialog.SectionMapTableColumns;
import ghidra.app.plugin.core.debug.mapping.DebuggerTargetTraceMapper;
import ghidra.app.plugin.core.debug.mapping.ObjectBasedDebuggerTargetTraceMapper;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.app.services.SectionMapProposal.SectionMapEntry;
import ghidra.app.services.TraceRecorder;
import ghidra.dbg.attributes.TargetPrimitiveDataType.DefaultTargetPrimitiveDataType;
import ghidra.dbg.attributes.TargetPrimitiveDataType.PrimitiveKind;
import ghidra.dbg.model.TestTargetModule;
import ghidra.dbg.model.TestTargetTypedefDataType;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.*;
import ghidra.framework.main.DataTreeDialog;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.data.TraceBasedDataTypeManager;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.util.table.GhidraTable;

@Category(NightlyCategory.class)
public class DebuggerModulesProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	DebuggerModulesProvider provider;

	protected TraceObjectModule modExe;
	protected TraceObjectSection secExeText;
	protected TraceObjectSection secExeData;

	protected TraceObjectModule modLib;
	protected TraceObjectSection secLibText;
	protected TraceObjectSection secLibData;

	protected SchemaContext ctx;

	@Override
	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new ObjectBasedDebuggerTargetTraceMapper(target,
			new LanguageID("DATA:BE:64:default"), new CompilerSpecID("pointer64"), Set.of());
	}

	@Override
	protected TraceRecorder recordAndWaitSync() throws Throwable {
		TraceRecorder recorder = super.recordAndWaitSync();
		useTrace(recorder.getTrace());
		return recorder;
	}

	@Override
	protected TargetObject chooseTarget() {
		return mb.testModel.session;
	}

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

	@Override
	protected void useTrace(Trace trace) {
		super.useTrace(trace);
		if (trace.getObjectManager().getRootObject() != null) {
			// If live, recorder will have created it
			return;
		}
		try {
			activateObjectsMode();
		}
		catch (Exception e) {
			throw new AssertionError(e);
		}
	}

	public void activateObjectsMode() throws Exception {
		// NOTE the use of index='1' allowing object-based managers to ID unique path
		ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Processes' schema='ProcessContainer' />
				    </schema>
				    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element index='1' schema='Process' />
				    </schema>
				    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Modules' schema='ModuleContainer' />
				        <attribute name='Memory' schema='RegionContainer' />
				    </schema>
				    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Region' />
				    </schema>
				    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				    </schema>
				    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Module' />
				    </schema>
				    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Module' />
				        <attribute name='Sections' schema='SectionContainer' />
				    </schema>
				    <schema name='SectionContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Section' />
				    </schema>
				    <schema name='Section' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Section' />
				    </schema>
				</context>""");

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(ctx.getSchema(new SchemaName("Session")));
		}
	}

	protected void addRegionsFromModules() throws Exception {
		PathPattern regionPattern = new PathPattern(PathUtils.parse("Processes[1].Memory[]"));
		TraceObjectManager om = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			TraceObject root = om.getRootObject();
			for (TraceObject module : (Iterable<TraceObject>) () -> root
					.querySuccessorsTargetInterface(Lifespan.at(0), TargetModule.class, true)
					.map(p -> p.getDestination(root))
					.iterator()) {
				String moduleName = module.getCanonicalPath().index();
				Lifespan span = module.getLife().bound();
				for (TraceObject section : (Iterable<TraceObject>) () -> module
						.querySuccessorsTargetInterface(Lifespan.at(0), TargetSection.class, true)
						.map(p -> p.getDestination(root))
						.iterator()) {
					String sectionName = section.getCanonicalPath().index();
					TraceObject region = om.createObject(TraceObjectKeyPath
							.of(regionPattern.applyKeys(moduleName + ":" + sectionName)
									.getSingletonPath()))
							.insert(span, ConflictResolution.TRUNCATE)
							.getDestination(root);
					region.setAttribute(span, TargetMemoryRegion.RANGE_ATTRIBUTE_NAME,
						section.getAttribute(0, TargetSection.RANGE_ATTRIBUTE_NAME).getValue());
					region.setAttribute(span, TargetMemoryRegion.READABLE_ATTRIBUTE_NAME, true);
					region.setAttribute(span, TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME,
						".data".equals(sectionName));
					region.setAttribute(span, TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME,
						".text".equals(sectionName));
				}
			}
		}
	}

	protected TraceObjectModule addModule(String name, AddressRange range, Lifespan span) {
		PathPattern modulePattern = new PathPattern(PathUtils.parse("Processes[1].Modules[]"));
		TraceObjectManager om = tb.trace.getObjectManager();
		TraceObjectModule module = Objects.requireNonNull(
			om.createObject(TraceObjectKeyPath.of(modulePattern.applyKeys(name).getSingletonPath()))
					.insert(span, ConflictResolution.TRUNCATE)
					.getDestination(null)
					.queryInterface(TraceObjectModule.class));
		module.getObject().setAttribute(span, TargetModule.MODULE_NAME_ATTRIBUTE_NAME, name);
		module.getObject().setAttribute(span, TargetModule.RANGE_ATTRIBUTE_NAME, range);
		return module;
	}

	protected TraceObjectSection addSection(TraceObjectModule module, String name,
			AddressRange range) {
		TraceObjectManager om = tb.trace.getObjectManager();
		Lifespan span = module.getObject().getLife().bound();
		TraceObjectSection section = Objects.requireNonNull(om
				.createObject(
					module.getObject().getCanonicalPath().key("Sections").index(name))
				.insert(span, ConflictResolution.TRUNCATE)
				.getDestination(null)
				.queryInterface(TraceObjectSection.class));
		section.getObject().setAttribute(span, TargetSection.RANGE_ATTRIBUTE_NAME, range);
		return section;
	}

	protected void addModules() throws Exception {
		Lifespan zeroOn = Lifespan.nowOn(0);
		try (Transaction tx = tb.startTransaction()) {
			modExe = addModule("first_proc", tb.range(0x55550000, 0x5575007f), zeroOn);
			secExeText = addSection(modExe, ".text", tb.range(0x55550000, 0x555500ff));
			secExeData = addSection(modExe, ".data", tb.range(0x55750000, 0x5575007f));

			modLib = addModule("some_lib", tb.range(0x7f000000, 0x7f10003f), zeroOn);
			secLibText = addSection(modLib, ".text", tb.range(0x7f000000, 0x7f0003ff));
			secLibData = addSection(modLib, ".data", tb.range(0x7f100000, 0x7f10003f));
		}
	}

	protected MemoryBlock addBlock() throws Exception {
		try (Transaction tx = program.openTransaction("Add block")) {
			return program.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x1000, (byte) 0, monitor,
						false);
		}
	}

	protected void assertModuleTableSize(int size) {
		assertEquals(size, provider.modulesPanel.getAllItems().size());
	}

	protected void assertSectionTableSize(int size) {
		assertEquals(size, provider.sectionsPanel.getAllItems().size());
	}

	protected void assertProviderEmpty() {
		assertModuleTableSize(0);
		assertSectionTableSize(0);
	}

	protected void assertModuleRow(int pos, Object object, String name, Address start, Address end,
			long length) {
		ValueRow row = provider.modulesPanel.getAllItems().get(pos);
		DynamicTableColumn<ValueRow, ?, Trace> nameCol =
			provider.modulesPanel.getColumnByNameAndType("Name", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> baseCol =
			provider.modulesPanel.getColumnByNameAndType("Base", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> maxCol =
			provider.modulesPanel.getColumnByNameAndType("Max", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> lengthCol =
			provider.modulesPanel.getColumnByNameAndType("Length", ValueProperty.class).getValue();

		assertSame(object, row.getValue().getValue());
		assertEquals(name, rowColVal(row, nameCol));
		assertEquals(start, rowColVal(row, baseCol));
		assertEquals(end, rowColVal(row, maxCol));
		assertEquals(length, rowColVal(row, lengthCol));
	}

	protected void assertSectionRow(int pos, Object object, String moduleName, String name,
			Address start, Address end, long length) {
		ValueRow row = provider.sectionsPanel.getAllItems().get(pos);
		DynamicTableColumn<ValueRow, ?, Trace> moduleNameCol =
			provider.sectionsPanel.getColumnByNameAndType("Module Name", ValueProperty.class)
					.getValue();
		DynamicTableColumn<ValueRow, ?, Trace> nameCol =
			provider.sectionsPanel.getColumnByNameAndType("Name", String.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> startCol =
			provider.sectionsPanel.getColumnByNameAndType("Start", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> endCol =
			provider.sectionsPanel.getColumnByNameAndType("End", ValueProperty.class).getValue();
		DynamicTableColumn<ValueRow, ?, Trace> lengthCol =
			provider.sectionsPanel.getColumnByNameAndType("Length", ValueProperty.class).getValue();

		assertSame(object, row.getValue().getValue());
		assertEquals(moduleName, rowColVal(row, moduleNameCol));
		assertEquals(name, rowColVal(row, nameCol));
		assertEquals(start, rowColVal(row, startCol));
		assertEquals(end, rowColVal(row, endCol));
		assertEquals(length, rowColVal(row, lengthCol));
	}

	protected void assertProviderPopulated() {
		assertModuleTableSize(2);
		assertSectionTableSize(4);

		assertModuleRow(0, modExe.getObject(), "first_proc", tb.addr(0x55550000),
			tb.addr(0x5575007f), 0x00200080);
		assertSectionRow(0, secExeText.getObject(), "first_proc", ".text", tb.addr(0x55550000),
			tb.addr(0x555500ff), 256);
		assertSectionRow(1, secExeData.getObject(), "first_proc", ".data", tb.addr(0x55750000),
			tb.addr(0x5575007f), 128);

		assertModuleRow(1, modLib.getObject(), "some_lib", tb.addr(0x7f000000),
			tb.addr(0x7f10003f), 0x00100040);
		assertSectionRow(2, secLibText.getObject(), "some_lib", ".text", tb.addr(0x7f000000),
			tb.addr(0x7f0003ff), 1024);
		assertSectionRow(3, secLibData.getObject(), "some_lib", ".data", tb.addr(0x7f100000),
			tb.addr(0x7f10003f), 64);
	}

	@Before
	public void setUpModulesProviderTest() throws Exception {
		addPlugin(tool, DebuggerModulesPlugin.class);
		provider = waitForComponentProvider(DebuggerModulesProvider.class);
	}

	@After
	public void tearDownModulesProviderTest() throws Exception {
		traceManager.activate(DebuggerCoordinates.NOWHERE);
		waitForTasks();
		runSwing(() -> traceManager.closeAllTraces());
	}

	@Test
	public void testEmpty() throws Exception {
		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActivateThenAddModulesPopulatesProvider() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		addModules();
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testAddModulesThenActivatePopulatesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		waitForTasks();

		waitForPass(() -> assertProviderEmpty());

		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testBlockChooserDialogPopulates() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForPass(() -> assertSectionTableSize(4));

		runSwing(() -> provider.setSelectedSections(Set.of(secExeText)));
		performEnabledAction(provider, provider.actionMapSections, false);

		DebuggerSectionMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerSectionMapProposalDialog.class);
		clickTableCell(propDialog.getTable(), 0, SectionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);

		assertEquals(1, blockDialog.getTableModel().getRowCount());
		MemoryBlockRow row = blockDialog.getTableModel().getModelData().get(0);
		assertEquals(program, row.getProgram());
		assertEquals(block, row.getBlock());
		// NOTE: Other getters should be tested in a separate MemoryBlockRowTest

		pressButtonByText(blockDialog, "Cancel", true);
	}

	@Test
	public void testRemoveModulesRemovedFromProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		try (Transaction tx = tb.startTransaction()) {
			modExe.getObject().removeTree(Lifespan.nowOn(0));
		}
		waitForDomainObject(tb.trace);
		waitForTasks();

		waitForPass(() -> {
			assertModuleTableSize(1);
			assertSectionTableSize(2);

			assertModuleRow(0, modLib.getObject(), "some_lib", tb.addr(0x7f000000),
				tb.addr(0x7f10003f), 0x00100040);
			assertSectionRow(0, secLibText.getObject(), "some_lib", ".text", tb.addr(0x7f000000),
				tb.addr(0x7f0003ff), 1024);
			assertSectionRow(1, secLibData.getObject(), "some_lib", ".data", tb.addr(0x7f100000),
				tb.addr(0x7f10003f), 64);
		});
	}

	@Test
	public void testUndoRedoCausesUpdateInProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		undo(tb.trace);
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertProviderEmpty());

		redo(tb.trace);
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testActivatingNoTraceEmptiesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		traceManager.activateTrace(null);
		waitForTasks();
		waitForPass(() -> assertProviderEmpty());

		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertProviderPopulated());
	}

	@Test
	public void testCurrentTraceClosedEmptiesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertProviderPopulated());

		traceManager.closeTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertProviderEmpty());
	}

	@Test
	public void testActionMapIdentically() throws Exception {
		assertFalse(provider.actionMapIdentically.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		// No modules necessary
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		waitForPass(() -> assertTrue(provider.actionMapIdentically.isEnabled()));

		// Need some substance in the program
		try (Transaction tx = program.openTransaction("Populate")) {
			addBlock();
		}
		waitForDomainObject(program);

		performEnabledAction(provider, provider.actionMapIdentically, true);
		waitForDomainObject(tb.trace);

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x1000, sm.getLength()); // Block is 0x1000 in length
		assertEquals(tb.addr(0x00400000), sm.getMinTraceAddress());
	}

	@Test
	public void testActionMapModules() throws Exception {
		assertFalse(provider.actionMapModules.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertFalse(provider.actionMapModules.isEnabled());

		try (Transaction tx = program.openTransaction("Change name")) {
			program.setImageBase(addr(program, 0x00400000), true);
			program.setName(modExe.getName());

			addBlock(); // So the program has a size
		}
		waitForDomainObject(program);
		waitForTasks();
		waitForPass(() -> assertModuleTableSize(2));

		runSwing(() -> provider.setSelectedModules(Set.of(modExe)));
		assertTrue(provider.actionMapModules.isEnabled());

		performEnabledAction(provider, provider.actionMapModules, false);

		DebuggerModuleMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerModuleMapProposalDialog.class);

		List<ModuleMapEntry> proposal = propDialog.getTableModel().getModelData();
		ModuleMapEntry entry = Unique.assertOne(proposal);
		assertEquals(modExe, entry.getModule());
		assertEquals(program, entry.getToProgram());

		clickTableCell(propDialog.getTable(), 0, ModuleMapTableColumns.CHOOSE.ordinal(), 1);

		DataTreeDialog programDialog = waitForDialogComponent(DataTreeDialog.class);
		assertEquals(program.getDomainFile(), programDialog.getDomainFile());

		pressButtonByText(programDialog, "OK", true);

		assertEquals(program, entry.getToProgram());
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x1000, sm.getLength()); // Block is 0x1000 in length
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());
	}

	// TODO: testActionMapModulesTo
	// TODO: testActionMapModuleTo

	@Test
	public void testActionMapSections() throws Exception {
		assertFalse(provider.actionMapSections.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		// Still
		assertFalse(provider.actionMapSections.isEnabled());

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForTasks();
		waitForPass(() -> assertSectionTableSize(4));

		runSwing(() -> provider.setSelectedSections(Set.of(secExeText)));
		assertTrue(provider.actionMapSections.isEnabled());

		performEnabledAction(provider, provider.actionMapSections, false);

		DebuggerSectionMapProposalDialog propDialog =
			waitForDialogComponent(DebuggerSectionMapProposalDialog.class);

		List<SectionMapEntry> proposal = propDialog.getTableModel().getModelData();
		SectionMapEntry entry = Unique.assertOne(proposal);
		assertEquals(secExeText, entry.getSection());
		assertEquals(block, entry.getBlock());

		clickTableCell(propDialog.getTable(), 0, SectionMapTableColumns.CHOOSE.ordinal(), 1);

		DebuggerBlockChooserDialog blockDialog =
			waitForDialogComponent(DebuggerBlockChooserDialog.class);
		MemoryBlockRow row = Unique.assertOne(blockDialog.getTableModel().getModelData());
		assertEquals(block, row.getBlock());

		pressButtonByText(blockDialog, "OK", true);
		assertEquals(block, entry.getBlock()); // Unchanged
		// TODO: Test the changed case

		Collection<? extends TraceStaticMapping> mappings =
			tb.trace.getStaticMappingManager().getAllEntries();
		assertEquals(0, mappings.size());

		pressButtonByText(propDialog, "OK", true);
		waitForDomainObject(tb.trace);
		assertEquals(1, mappings.size());

		TraceStaticMapping sm = mappings.iterator().next();
		assertEquals(Lifespan.nowOn(0), sm.getLifespan());
		assertEquals("ram:00400000", sm.getStaticAddress());
		assertEquals(0x100, sm.getLength()); // Section is 0x100, though block is 0x1000 long
		assertEquals(tb.addr(0x55550000), sm.getMinTraceAddress());
	}

	// TODO: testActionMapSectionsTo
	// TODO: testActionMapSectionTo

	@Test
	public void testActionSelectAddresses() throws Exception {
		assertFalse(provider.actionSelectAddresses.isEnabled());

		addPlugin(tool, DebuggerListingPlugin.class);
		waitForComponentProvider(DebuggerListingProvider.class);
		// TODO: Should I hide the action if this service is missing?
		DebuggerListingService listing = tool.getService(DebuggerListingService.class);
		createAndOpenTrace();

		addModules();
		addRegionsFromModules();

		// Still
		assertFalse(provider.actionSelectAddresses.isEnabled());

		traceManager.activateTrace(tb.trace);
		waitForTasks(); // NOTE: The table may select first by default, enabling action
		waitForPass(() -> assertProviderPopulated());
		runSwing(() -> provider.setSelectedModules(Set.of(modExe)));

		performEnabledAction(provider, provider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x55750000, 0x5575007f)),
			new AddressSet(listing.getCurrentSelection()));

		runSwing(() -> provider.setSelectedSections(Set.of(secExeText, secLibText)));

		performEnabledAction(provider, provider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x7f000000, 0x7f0003ff)),
			new AddressSet(listing.getCurrentSelection()));
	}

	@Test
	@Ignore("This action is hidden until supported")
	public void testActionCaptureTypes() throws Exception {
		assertFalse(provider.actionCaptureTypes.isEnabled());
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = modelService.recordTargetAndActivateTrace(mb.testProcess1,
			createTargetTraceMapper(mb.testProcess1));
		Trace trace = recorder.getTrace();

		// TODO: A region should not be required first. Just to get a memMapper?
		mb.testProcess1.addRegion("Memory[first_proc:.text]", mb.rng(0x55550000, 0x555500ff),
			"rx");
		TestTargetModule module =
			mb.testProcess1.modules.addModule("Modules[first_proc]",
				mb.rng(0x55550000, 0x555500ff));
		// NOTE: A section should not be required at this point.
		TestTargetTypedefDataType typedef = module.types.addTypedefDataType("myInt",
			new DefaultTargetPrimitiveDataType(PrimitiveKind.SINT, 4));
		waitForDomainObject(trace);

		// Still
		assertFalse(provider.actionCaptureTypes.isEnabled());

		traceManager.activateTrace(trace);
		waitForSwing();
		TraceModule traceModule = waitForValue(() -> recorder.getTraceModule(module));
		provider.setSelectedModules(Set.of(traceModule));
		waitForSwing();
		// TODO: When action is included, put this assertion back
		//assertTrue(modulesProvider.actionCaptureTypes.isEnabled());

		performEnabledAction(provider, provider.actionCaptureTypes, true);
		waitForBusyTool(tool);
		waitForDomainObject(trace);

		// TODO: A separate action/script to transfer types from trace DTM into mapped program DTMs
		TraceBasedDataTypeManager dtm = trace.getDataTypeManager();
		TargetDataTypeConverter conv = new TargetDataTypeConverter(dtm);
		DataType expType =
			conv.convertTargetDataType(typedef).get(DEFAULT_WAIT_TIMEOUT, TimeUnit.MILLISECONDS);
		// TODO: Some heuristic or convention to extract the module name, if applicable
		waitForPass(() -> {
			DataType actType = dtm.getDataType("/Modules[first_proc].Types/myInt");
			assertTypeEquals(expType, actType);
		});

		// TODO: When capture-types action is included, put this assertion back
		//assertTrue(modulesProvider.actionCaptureTypes.isEnabled());
		waitForLock(trace);
		recorder.stopRecording();
		waitForSwing();
		assertFalse(provider.actionCaptureTypes.isEnabled());
	}

	@Test
	public void testActionCaptureSymbols() throws Throwable {
		assertFalse(provider.actionCaptureSymbols.isEnabled());
		createTestModel();
		mb.createTestProcessesAndThreads();

		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());

		// TODO: A region should not be required first. Just to get a memMapper?
		mb.testProcess1.addRegion("first_proc:.text", mb.rng(0x55550000, 0x555500ff),
			"rx");
		TestTargetModule module =
			mb.testProcess1.modules.addModule("first_proc", mb.rng(0x55550000, 0x555500ff));
		// NOTE: A section should not be required at this point.
		module.symbols.addSymbol("test", mb.addr(0x55550080), 8,
			new DefaultTargetPrimitiveDataType(PrimitiveKind.UNDEFINED, 8));
		waitForDomainObject(tb.trace);

		// Still
		assertFalse(provider.actionCaptureSymbols.isEnabled());

		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> {
			TraceModule traceModule = recorder.getTraceModule(module);
			assertNotNull(traceModule);
			runSwing(() -> provider.setSelectedModules(Set.of(traceModule)));
			assertTrue(provider.actionCaptureSymbols.isEnabled());
		});

		performEnabledAction(provider, provider.actionCaptureSymbols, true);
		waitForBusyTool(tool);
		waitForDomainObject(tb.trace);

		// TODO: A separate action/script to transfer symbols from trace into mapped programs
		// TODO: Let this action work on the TraceObjects instead of TargetObjects
		// NOTE: Used types must go along.
		Collection<? extends TraceSymbol> symbols =
			tb.trace.getSymbolManager().allSymbols().getNamed("test");
		assertEquals(1, symbols.size());
		TraceSymbol sym = symbols.iterator().next();
		// TODO: Some heuristic or convention to extract the module name, if applicable
		assertEquals("Processes[1].Modules[first_proc].Symbols::test", sym.getName(true));
		// NOTE: builder (b) is not initialized here
		assertEquals(tb.addr(0x55550080),
			sym.getAddress());
		// TODO: Check data type once those are captured in Data units.

		assertTrue(provider.actionCaptureSymbols.isEnabled());
		waitForLock(tb.trace);
		recorder.stopRecording();
		waitForSwing();
		assertFalse(provider.actionCaptureSymbols.isEnabled());
	}

	@Test
	public void testActionImportFromFileSystem() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();

		try (Transaction tx = tb.startTransaction()) {
			modExe.setName("/bin/echo"); // File has to exist
		}
		waitForPass(() -> assertModuleTableSize(2));

		runSwing(() -> provider.setSelectedModules(Set.of(modExe)));
		performAction(provider.actionImportFromFileSystem, false);

		GhidraFileChooser dialog = waitForDialogComponent(GhidraFileChooser.class);
		dialog.close();
	}

	protected Set<ValueRow> visibleSections() {
		return Set.copyOf(QueryPanelTestHelper.getFilterPanel(provider.sectionsPanel)
				.getTableFilterModel()
				.getModelData());
	}

	@Test
	public void testActionFilterSections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertProviderPopulated());

		waitForPass(() -> assertEquals(4, visibleSections().size()));

		runSwing(() -> provider.setSelectedModules(Set.of(modExe)));

		waitForPass(() -> assertEquals(4, visibleSections().size()));

		performEnabledAction(provider, provider.actionFilterSectionsByModules, true);
		waitForTasks();

		waitForPass(() -> assertEquals(2, visibleSections().size()));
		for (ValueRow row : visibleSections()) {
			assertEquals(modExe.getObject(), row.getValue()
					.getChild()
					.queryCanonicalAncestorsTargetInterface(TargetModule.class)
					.findFirst()
					.orElse(null));
		}

		runSwing(() -> provider.setSelectedModules(Set.of()));

		waitForPass(() -> assertEquals(4, visibleSections().size()));
	}

	protected static final Set<String> POPUP_ACTIONS = Set.of(AbstractSelectAddressesAction.NAME,
		DebuggerResources.NAME_MAP_MODULES, DebuggerResources.NAME_MAP_SECTIONS,
		AbstractImportFromFileSystemAction.NAME);

	@Test
	public void testPopupActionsOnModuleSelections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertModuleTableSize(2));

		GhidraTable moduleTable = QueryPanelTestHelper.getTable(provider.modulesPanel);
		clickTableCellWithButton(moduleTable, 0, 0, MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));

		pressEscape();

		addPlugin(tool, ImporterPlugin.class);
		waitForSwing();
		clickTableCellWithButton(moduleTable, 0, 0, MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME, AbstractImportFromFileSystemAction.NAME));
	}

	@Test
	public void testPopupActionsOnSectionSelections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForTasks();
		waitForPass(() -> assertSectionTableSize(4));

		GhidraTable sectionTable = QueryPanelTestHelper.getTable(provider.sectionsPanel);
		clickTableCellWithButton(sectionTable, 0, 0, MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));
	}
}
