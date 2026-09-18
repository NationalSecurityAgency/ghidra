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
package ghidra.app.plugin.core.datamgr;

import static org.junit.Assert.*;

import java.util.*;

import javax.swing.tree.TreePath;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.compositeeditor.StructureEditorProvider;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.Upgrade;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeStore;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class DataTypesTableTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypesTableProvider provider;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getTableProvider();

		tool.showComponentProvider(provider, true);
		waitForTable();

		removeDistractingPlugins();
	}

	private void removeDistractingPlugins() {

		// cleanup the display a bit
		ProgramTreePlugin ptp = env.getPlugin(ProgramTreePlugin.class);
		tool.removePlugins(List.of(ptp));
	}

	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("Program1", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(miscPath);
		builder.addDataType(struct);
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(miscPath);
		union.add(new ByteDataType());
		builder.addDataType(union);

		CategoryPath cat1Path = new CategoryPath("/Category1");
		builder.addCategory(cat1Path);
		CategoryPath cat2Path = new CategoryPath(cat1Path, "Category2");
		builder.addCategory(cat2Path);
		CategoryPath cat4Path = new CategoryPath(cat2Path, "Category4");
		builder.addCategory(cat4Path);
		builder.addCategory(new CategoryPath(cat2Path, "Category5"));

		CategoryPath cat3Path = new CategoryPath(cat2Path, "Category3");
		builder.addCategory(cat3Path);
		StructureDataType dt = new StructureDataType("IntStruct", 0);
		dt.add(new WordDataType());
		dt.setCategoryPath(cat3Path);
		builder.addDataType(dt);

		dt = new StructureDataType("CharStruct", 0);
		dt.add(new CharDataType());
		dt.setCategoryPath(cat4Path);
		builder.addDataType(dt);

		StructureDataType dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new WordDataType());
		builder.addDataType(dllTable);

		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "struct_field_names", null);
		myStruct.setCategoryPath(cat2Path);
		builder.addDataType(myStruct);

		TypedefDataType typeDefMyStruct = new TypedefDataType("TypeDefToMyStruct", myStruct);
		builder.addDataType(typeDefMyStruct);

		Pointer16DataType ptr16 = new Pointer16DataType(new CharDataType());
		builder.addDataType(ptr16);
		ArrayDataType charDt = new ArrayDataType(new CharDataType(), 10);
		builder.addDataType(charDt);

		return builder.getProgram();
	}

	private Program openSecondProgram() throws Exception {

		ProgramBuilder pBuilder = new ProgramBuilder("Program1", ProgramBuilder._TOY, this);

		pBuilder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC2");
		pBuilder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct2", 4);
		struct.setCategoryPath(miscPath);
		pBuilder.addDataType(struct);

		ProgramDB program2 = pBuilder.getProgram();
		env.open(program2);

		return program2;
	}

	@Test
	public void testFilter_DataTypes() {

		assertStructures(provider, true);

		toggleStructuresInFilter(provider, false);
		assertStructures(provider, false);

		//
		// Test that creating a snapshot will transfer the data type filter settings
		// 
		DataTypesTableProvider snapshot = createSnapshot(provider);
		assertStructures(snapshot, false); // snapshot matches source provider

		//
		// Change filter in snapshot and check that the source provider differs from the snapshot 
		//
		toggleStructuresInFilter(snapshot, true);
		assertStructures(snapshot, true);
		assertStructures(provider, false); // source provider unaffected

		// 
		// Close the snapshot and create a new snapshot.  Verify the filter for the new snapshot 
		// matches the provider.
		// 
		closeProvider(snapshot);
		snapshot = createSnapshot(provider);
		assertStructures(snapshot, false); // snapshot matches source provider
	}

	@Test
	public void testFilter_ProgramTypesOnly() throws Exception {

		// add types from an archive other than the program
		openArchive("generic_clib.gdt");

		assertTypesFromMultipleDtStores(provider);

		toggleProgramTypesOnly(provider, true);
		assertTypesFromOnlyProgram(provider);

		toggleProgramTypesOnly(provider, false);
		assertTypesFromMultipleDtStores(provider);

		//
		// Create a snapshot with the filter on; verify the snapshot is showing only program types.
		//
		toggleProgramTypesOnly(provider, true);
		DataTypesTableProvider snapshot = createSnapshot(provider);
		assertTypesFromOnlyProgram(snapshot); // snapshot matches source provider	

		//
		// Change filter in snapshot and check that the source provider differs from the snapshot 
		//
		toggleProgramTypesOnly(snapshot, false);
		assertTypesFromMultipleDtStores(snapshot);
		assertTypesFromOnlyProgram(provider); // source provider is unchanged

		// 
		// Close the snapshot and create a new snapshot.  Verify the filter for the new snapshot 
		// matches the provider.
		// 
		closeProvider(snapshot);
		snapshot = createSnapshot(provider);
		assertTypesFromOnlyProgram(snapshot); // snapshot matches source provider	

	}

	@Test
	public void testAction_SelectInTree() {

		selectTypeInTable("MyStruct");

		DockingActionIf action = getLocalAction(provider, "Select Data Types in Tree");
		performAction(action);

		assertTypeSelectedInTree("MyStruct");
	}

	@Test
	public void testEdit_ViaDoubleClick() {

		selectTypeInTable("MyStruct");

		doubleClickSelectedRow();

		assertEditingStructure("MyStruct");
	}

	@Test
	public void testChangePrograms() throws Exception {

		// 
		// Test that changing programs will update the connected provider's data types
		//

		// add types from an archive other than the program
		openArchive("generic_clib.gdt");

		String p1Name = program.getName();
		String archiveName = "generic_clib";
		assertTypesFromDtStores(provider, p1Name, archiveName);

		//
		// Create a snapshot and verify it is unaffected by program changes
		//
		DataTypesTableProvider snapshot = createSnapshot(provider);
		assertTypesFromDtStores(snapshot, p1Name, archiveName); // same program as source

		Program program2 = openSecondProgram();
		String p2Name = program2.getName();
		assertTypesFromDtStores(provider, p2Name, archiveName); // newly activated program
		assertTypesFromDtStores(snapshot, p1Name, archiveName); // unchanged

		closeProgram(program2);
		assertTypesFromDtStores(provider, p1Name, archiveName);
		assertTypesFromDtStores(snapshot, p1Name, archiveName); // unchanged
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void closeProgram(Program p) {
		env.close(p);
	}

	private ArchiveNode openArchive(String archiveName) throws Exception {
		ResourceFile clibGdt = Application.getModuleDataFile("typeinfo/generic/" + archiveName);

		ArchiveManager archiveManager = plugin.getArchiveManager();
		archiveManager.openFileArchive(clibGdt, true, Upgrade.YES, false, TaskMonitor.DUMMY);

		DataTypesProvider treeProvider = plugin.getProvider();
		GTree tree = treeProvider.getGTree();
		waitForTree(tree);
		waitForTable(provider);

		GTreeNode rootNode = tree.getViewRoot();
		if (archiveName.endsWith(".gdt")) {
			archiveName = archiveName.substring(0, archiveName.length() - 4);
		}
		return (ArchiveNode) rootNode.getChild(archiveName);
	}

	private void toggleProgramTypesOnly(DataTypesTableProvider dttp, boolean programOnly) {
		DockingActionIf programOnlyAction = getLocalAction(dttp, "Program Types Filter");
		performAction(programOnlyAction);
		waitForTable(dttp);
	}

	private void assertEditingStructure(String name) {
		StructureEditorProvider editor = waitForComponentProvider(StructureEditorProvider.class);
		DataTypePath dtPath = editor.getDtPath();
		assertEquals(name, dtPath.getDataTypeName());
	}

	private void doubleClickSelectedRow() {
		GTable table = provider.getTable();
		int row = runSwing(() -> table.getSelectedRow());
		int col = 0;
		int clickCount = 2;
		clickTableCell(table, row, col, clickCount);
	}

	private void assertTypesFromDtStores(DataTypesTableProvider dttp, String... names) {

		Set<String> archiveNames = getArchivesFromTable(dttp);
		assertEquals(names.length, archiveNames.size());

		for (String expectedName : names) {
			assertTrue(archiveNames.contains(expectedName));
		}
	}

	private void assertTypesFromMultipleDtStores(DataTypesTableProvider dttp) {
		Set<String> archiveNames = getArchivesFromTable(dttp);
		assertTrue(archiveNames.size() > 1);
	}

	private void assertTypesFromOnlyProgram(DataTypesTableProvider dttp) {
		Set<String> archiveNames = getArchivesFromTable(dttp);
		assertEquals(1, archiveNames.size());
		String name = archiveNames.iterator().next();
		assertEquals(program.getName(), name);
	}

	private void assertTypeSelectedInTree(String name) {

		DataTypesProvider treeProvider = plugin.getProvider();
		GTree tree = treeProvider.getGTree();
		waitForTree(tree);

		TreePath[] paths = tree.getSelectionPaths();
		assertEquals(1, paths.length);

		DataTypeNode dtNode = (DataTypeNode) paths[0].getLastPathComponent();
		DataType dt = dtNode.getDataType();
		assertEquals(name, dt.getName());
	}

	private Set<String> getArchivesFromTable(DataTypesTableProvider dttp) {
		Set<String> storeNames = new HashSet<>();
		ThreadedTableModel<DataType, Object> model = dttp.getTableModel();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {

			DataType dt = model.getRowObject(i);
			DataTypeManager dtm = dt.getDataTypeManager();
			DataTypeStore dtStore = dtm.getDataStore();
			String name = dtStore.getName();
			storeNames.add(name);
		}
		return storeNames;
	}

	private void waitForTable() {
		waitForTable(provider);
	}

	private void waitForTable(DataTypesTableProvider dttp) {
		waitForTableModel(dttp.getTableModel());
	}

	private void assertStructures(DataTypesTableProvider dttp,
			boolean structuresExpected) {
		Map<String, Structure> structures = getStructures(dttp);
		if (!structuresExpected) {
			assertEquals(0, structures.size());
		}
		else {
			assertTrue(structures.size() > 0);
		}
	}

	private Map<String, Structure> getStructures(DataTypesTableProvider dttp) {

		Map<String, Structure> map = new HashMap<>();
		ThreadedTableModel<DataType, Object> model = dttp.getTableModel();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {

			DataType dt = model.getRowObject(i);
			if (dt instanceof Structure struct) {
				map.put(dt.getName(), struct);
			}
		}

		return map;
	}

	private void assertType(DataTypesTableProvider dttp, String name,
			boolean isShowing) {

		DataType dt = getTypeFromTable(dttp, name);
		if (isShowing) {
			assertNotNull("Data type not found: '%s'", dt);
		}
		else {
			assertNull(dt);
		}
	}

	private DataType getTypeFromTable(DataTypesTableProvider dttp, String name) {
		ThreadedTableModel<DataType, Object> model = dttp.getTableModel();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {

			DataType dt = model.getRowObject(i);
			String dtName = dt.getName();
			if (dtName.equals(name)) {
				return dt;
			}
		}
		return null;
	}

	private void selectTypeInTable(String name) {
		int index = indexOfType(name);
		GTable table = provider.getTable();
		runSwing(() -> table.selectRow(index));
	}

	private int indexOfType(String name) {

		ThreadedTableModel<DataType, Object> model = provider.getTableModel();
		int n = model.getRowCount();
		for (int i = 0; i < n; i++) {

			DataType dt = model.getRowObject(i);
			String dtName = dt.getName();
			if (dtName.equals(name)) {
				return i;
			}
		}

		fail("Unable to find data type '%s' in the table".formatted(name));
		return -1;
	}

	private void toggleStructuresInFilter(DataTypesTableProvider dttp, boolean showStructues) {
		DtFilterDialog dialog = showDtFilter(dttp);
		setToggleButtonSelected(dialog.getComponent(), "Structures", showStructues);
		pressButtonByText(dialog, "OK");
		waitForTable();
	}

	private DtFilterDialog showDtFilter(DataTypesTableProvider dttp) {
		DockingActionIf action = getLocalAction(dttp, "Show Filter");
		performAction(action, provider, false);
		return waitForDialogComponent(DtFilterDialog.class);
	}

	private DataTypesTableProvider createSnapshot(DataTypesTableProvider dttp) {

		DockingActionIf action = getLocalAction(dttp, "Data Types Table Snapshot");
		performAction(action, false);

		String name = dttp.getName();
		String snapshotTitle = '[' + name + ']';
		DataTypesTableProvider snapshot =
			waitForComponentProvider(DataTypesTableProvider.class, snapshotTitle);
		waitForTable(snapshot);
		return snapshot;
	}

}
