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
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.core.debug.gui.*;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog.MemoryBlockRow;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractImportFromFileSystemAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction;
import ghidra.app.plugin.core.debug.gui.action.AutoMapSpec;
import ghidra.app.plugin.core.debug.gui.action.NoneAutoMapSpec;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModuleMapProposalDialog.ModuleMapTableColumns;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapModulesAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider.MapSectionsAction;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerSectionMapProposalDialog.SectionMapTableColumns;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServiceTestAccess;
import ghidra.app.services.DebuggerListingService;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry;
import ghidra.framework.main.DataTreeDialog;
import ghidra.plugin.importer.ImporterPlugin;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.modules.*;
import ghidra.util.exception.DuplicateNameException;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerModulesProviderLegacyTest extends AbstractGhidraHeadedDebuggerTest {
	protected DebuggerModulesPlugin modulesPlugin;
	protected DebuggerModulesProvider modulesProvider;

	protected TraceModule modExe;
	protected TraceSection secExeText;
	protected TraceSection secExeData;

	protected TraceModule modLib;
	protected TraceSection secLibText;
	protected TraceSection secLibData;

	@Before
	public void setUpModulesProviderTest() throws Exception {
		modulesPlugin = addPlugin(tool, DebuggerModulesPlugin.class);
		modulesProvider = waitForComponentProvider(DebuggerModulesProvider.class);

		// TODO: This seems to hold up the task manager.
		modulesProvider.setAutoMapSpec(AutoMapSpec.fromConfigName(NoneAutoMapSpec.CONFIG_NAME));
	}

	protected void addRegionsFromModules()
			throws TraceOverlappedRegionException, DuplicateNameException {
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager manager = tb.trace.getMemoryManager();
			for (TraceModule module : tb.trace.getModuleManager().getAllModules()) {
				for (TraceSection section : module.getSections()) {
					Set<TraceMemoryFlag> flags = new HashSet<>();
					flags.add(TraceMemoryFlag.READ);
					if (".text".equals(section.getName())) {
						flags.add(TraceMemoryFlag.EXECUTE);
					}
					else if (".data".equals(section.getName())) {
						flags.add(TraceMemoryFlag.WRITE);
					}
					else {
						throw new AssertionError();
					}
					manager.addRegion(
						"Processes[1].Memory[" + module.getName() + ":" + section.getName() + "]",
						module.getLifespan(), section.getRange(), flags);
				}
			}
		}
	}

	protected void addModules() throws Exception {
		TraceModuleManager manager = tb.trace.getModuleManager();
		try (Transaction tx = tb.startTransaction()) {
			modExe = manager.addLoadedModule("Processes[1].Modules[first_proc]", "first_proc",
				tb.range(0x55550000, 0x5575007f), 0);
			secExeText = modExe.addSection("Processes[1].Modules[first_proc].Sections[.text]",
				".text", tb.range(0x55550000, 0x555500ff));
			secExeData = modExe.addSection("Processes[1].Modules[first_proc].Sections[.data]",
				".data", tb.range(0x55750000, 0x5575007f));

			modLib = manager.addLoadedModule("Processes[1].Modules[some_lib]", "some_lib",
				tb.range(0x7f000000, 0x7f10003f), 0);
			secLibText = modLib.addSection("Processes[1].Modules[some_lib].Sections[.text]",
				".text", tb.range(0x7f000000, 0x7f0003ff));
			secLibData = modLib.addSection("Processes[1].Modules[some_lib].Sections[.data]",
				".data", tb.range(0x7f100000, 0x7f10003f));
		}
	}

	protected MemoryBlock addBlock() throws Exception {
		try (Transaction tx = program.openTransaction("Add block")) {
			return program.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x1000, (byte) 0, monitor,
						false);
		}
	}

	protected void assertProviderEmpty() {
		List<ModuleRow> modulesDisplayed =
			modulesProvider.legacyModulesPanel.moduleTableModel.getModelData();
		assertTrue(modulesDisplayed.isEmpty());

		List<SectionRow> sectionsDisplayed =
			modulesProvider.legacySectionsPanel.sectionTableModel.getModelData();
		assertTrue(sectionsDisplayed.isEmpty());
	}

	protected void assertProviderPopulated() {
		List<ModuleRow> modulesDisplayed =
			new ArrayList<>(modulesProvider.legacyModulesPanel.moduleTableModel.getModelData());
		modulesDisplayed.sort(Comparator.comparing(r -> r.getBase()));
		// I should be able to assume this is sorted by base address. It's the default sort column.
		assertEquals(2, modulesDisplayed.size());

		ModuleRow execRow = modulesDisplayed.get(0);
		assertEquals(tb.addr(0x55550000), execRow.getBase());
		assertEquals("first_proc", execRow.getName());

		// Use only (start) offset for excess, as unique ID
		ModuleRow libRow = modulesDisplayed.get(1);
		assertEquals(tb.addr(0x7f000000), libRow.getBase());

		List<SectionRow> sectionsDisplayed =
			new ArrayList<>(modulesProvider.legacySectionsPanel.sectionTableModel.getModelData());
		sectionsDisplayed.sort(Comparator.comparing(r -> r.getStart()));
		assertEquals(4, sectionsDisplayed.size());

		SectionRow execTextRow = sectionsDisplayed.get(0);
		assertEquals(tb.addr(0x55550000), execTextRow.getStart());
		assertEquals(tb.addr(0x555500ff), execTextRow.getEnd());
		assertEquals("first_proc", execTextRow.getModuleName());
		assertEquals(".text", execTextRow.getName());
		assertEquals(256, execTextRow.getLength());

		SectionRow execDataRow = sectionsDisplayed.get(1);
		assertEquals(tb.addr(0x55750000), execDataRow.getStart());

		SectionRow libTextRow = sectionsDisplayed.get(2);
		assertEquals(tb.addr(0x7f000000), libTextRow.getStart());

		SectionRow libDataRow = sectionsDisplayed.get(3);
		assertEquals(tb.addr(0x7f100000), libDataRow.getStart());
	}

	@Test
	public void testEmpty() throws Exception {
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testActivateThenAddModulesPopulatesProvider() throws Exception {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		addModules();
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testAddModulesThenActivatePopulatesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		waitForSwing();

		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated();
	}

	@Test
	public void testBlockChooserDialogPopulates() throws Exception {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		runSwing(() -> modulesProvider.setSelectedSections(Set.of(secExeText)));
		performEnabledAction(modulesProvider, modulesProvider.actionMapSections, false);

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
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		try (Transaction tx = tb.startTransaction()) {
			modExe.delete();
		}
		waitForDomainObject(tb.trace);

		List<ModuleRow> modulesDisplayed =
			new ArrayList<>(modulesProvider.legacyModulesPanel.moduleTableModel.getModelData());
		modulesDisplayed.sort(Comparator.comparing(r -> r.getBase()));
		assertEquals(1, modulesDisplayed.size());

		ModuleRow libRow = modulesDisplayed.get(0);
		assertEquals("some_lib", libRow.getName());

		List<SectionRow> sectionsDisplayed =
			new ArrayList<>(modulesProvider.legacySectionsPanel.sectionTableModel.getModelData());
		sectionsDisplayed.sort(Comparator.comparing(r -> r.getStart()));
		assertEquals(2, sectionsDisplayed.size());

		SectionRow libTextRow = sectionsDisplayed.get(0);
		assertEquals(".text", libTextRow.getName());
		assertEquals("some_lib", libTextRow.getModuleName());

		SectionRow libDataRow = sectionsDisplayed.get(1);
		assertEquals(".data", libDataRow.getName());
		assertEquals("some_lib", libDataRow.getModuleName());
	}

	@Test
	public void testUndoRedoCausesUpdateInProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		undo(tb.trace);
		assertProviderEmpty();

		redo(tb.trace);
		assertProviderPopulated();
	}

	@Test
	public void testActivatingNoTraceEmptiesProvider() throws Exception {
		DebuggerTraceManagerServiceTestAccess.setEnsureActiveTrace(traceManager, false);
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		traceManager.activateTrace(null);
		waitForSwing();
		assertProviderEmpty();

		traceManager.activateTrace(tb.trace);
		waitForSwing();
		assertProviderPopulated();
	}

	@Test
	public void testCurrentTraceClosedEmptiesProvider() throws Exception {
		createAndOpenTrace();

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertProviderPopulated(); // Cheap sanity check

		traceManager.closeTrace(tb.trace);
		waitForSwing();
		assertProviderEmpty();
	}

	@Test
	public void testActionMapIdentically() throws Exception {
		assertFalse(modulesProvider.actionMapIdentically.isEnabled());

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		// No modules necessary
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertTrue(modulesProvider.actionMapIdentically.isEnabled());

		// Need some substance in the program
		try (Transaction tx = program.openTransaction("Populate")) {
			addBlock();
		}
		waitForDomainObject(program);

		performEnabledAction(modulesProvider, modulesProvider.actionMapIdentically, true);
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
		assertDisabled(modulesProvider, modulesProvider.actionMapModules);

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertDisabled(modulesProvider, modulesProvider.actionMapModules);

		try (Transaction tx = program.openTransaction("Change name")) {
			program.setImageBase(addr(program, 0x00400000), true);
			program.setName(modExe.getName());

			addBlock(); // So the program has a size
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		assertEnabled(modulesProvider, modulesProvider.actionMapModules);

		performEnabledAction(modulesProvider, modulesProvider.actionMapModules, false);

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
		assertDisabled(modulesProvider, modulesProvider.actionMapSections);

		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		// Still
		assertDisabled(modulesProvider, modulesProvider.actionMapSections);

		MemoryBlock block = addBlock();
		try (Transaction tx = program.openTransaction("Change name")) {
			program.setName(modExe.getName());
		}
		waitForDomainObject(program);
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		modulesProvider.setSelectedSections(Set.of(secExeText));
		waitForSwing();
		assertEnabled(modulesProvider, modulesProvider.actionMapSections);

		performEnabledAction(modulesProvider, modulesProvider.actionMapSections, false);

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
		assertFalse(modulesProvider.actionSelectAddresses.isEnabled());

		addPlugin(tool, DebuggerListingPlugin.class);
		waitForComponentProvider(DebuggerListingProvider.class);
		// TODO: Should I hide the action if this service is missing?
		DebuggerListingService listing = tool.getService(DebuggerListingService.class);
		createAndOpenTrace();

		addModules();
		addRegionsFromModules();

		// Still
		assertFalse(modulesProvider.actionSelectAddresses.isEnabled());

		traceManager.activateTrace(tb.trace);
		waitForSwing(); // NOTE: The table may select first by default, enabling action
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));
		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		assertTrue(modulesProvider.actionSelectAddresses.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x55750000, 0x5575007f)),
			new AddressSet(listing.getCurrentSelection()));

		modulesProvider.setSelectedSections(Set.of(secExeText, secLibText));
		waitForSwing();
		assertTrue(modulesProvider.actionSelectAddresses.isEnabled());

		performEnabledAction(modulesProvider, modulesProvider.actionSelectAddresses, true);
		assertEquals(tb.set(tb.range(0x55550000, 0x555500ff), tb.range(0x7f000000, 0x7f0003ff)),
			new AddressSet(listing.getCurrentSelection()));
	}

	@Test
	public void testActionImportFromFileSystem() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		try (Transaction tx = tb.startTransaction()) {
			modExe.setName("/bin/echo"); // File has to exist
		}
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();
		performAction(modulesProvider.actionImportFromFileSystem, false);

		GhidraFileChooser dialog = waitForDialogComponent(GhidraFileChooser.class);
		dialog.close();
	}

	protected Set<SectionRow> visibleSections() {
		return Set
				.copyOf(modulesProvider.legacySectionsPanel.sectionFilterPanel.getTableFilterModel()
						.getModelData());
	}

	@Test
	public void testActionFilterSections() throws Exception {
		addPlugin(tool, ImporterPlugin.class);
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		assertEquals(4, visibleSections().size());

		modulesProvider.setSelectedModules(Set.of(modExe));
		waitForSwing();

		assertEquals(4, visibleSections().size());

		assertTrue(modulesProvider.actionFilterSectionsByModules.isEnabled());
		performEnabledAction(modulesProvider, modulesProvider.actionFilterSectionsByModules, true);
		waitForSwing();

		assertEquals(2, visibleSections().size());
		for (SectionRow row : visibleSections()) {
			assertEquals(modExe, row.getModule());
		}

		modulesProvider.setSelectedModules(Set.of());
		waitForSwing();

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
		waitForSwing();
		// NB. Table is debounced
		waitForPass(
			() -> assertEquals(2, modulesProvider.legacyModulesPanel.moduleTable.getRowCount()));

		clickTableCellWithButton(modulesProvider.legacyModulesPanel.moduleTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));

		pressEscape();

		addPlugin(tool, ImporterPlugin.class);
		waitForSwing();
		clickTableCellWithButton(modulesProvider.legacyModulesPanel.moduleTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME, AbstractImportFromFileSystemAction.NAME));
	}

	@Test
	public void testPopupActionsOnSectionSelections() throws Exception {
		createAndOpenTrace();
		addModules();
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitForPass(
			() -> assertEquals(4, modulesProvider.legacySectionsPanel.sectionTable.getRowCount()));

		clickTableCellWithButton(modulesProvider.legacySectionsPanel.sectionTable, 0, 0,
			MouseEvent.BUTTON3);
		waitForSwing();
		assertMenu(POPUP_ACTIONS, Set.of(MapModulesAction.NAME, MapSectionsAction.NAME,
			AbstractSelectAddressesAction.NAME));
	}
}
