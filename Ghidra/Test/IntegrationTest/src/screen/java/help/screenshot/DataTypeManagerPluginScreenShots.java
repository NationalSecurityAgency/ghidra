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
package help.screenshot;

import java.io.File;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableColumn;

import org.junit.Assert;
import org.junit.Test;

import docking.*;
import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.archive.InvalidFileArchive;
import ghidra.app.plugin.core.datamgr.util.ConflictDialog;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.data.*;
import ghidra.util.UniversalID;
import ghidra.util.table.GhidraTable;

public class DataTypeManagerPluginScreenShots extends GhidraScreenShotGenerator {

	public DataTypeManagerPluginScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		removeInvalidArchives();
	}

	@Test
	public void testCommitDialog() {
		DataTypeManagerPlugin plugin = getPlugin(tool, DataTypeManagerPlugin.class);
		List<DataTypeSyncInfo> list = new ArrayList<>();
		Set<DataTypeSyncInfo> set = new HashSet<>();
		createChangedDatatypesFromArchive(list, set);

		final DataTypeSyncDialog dialog =
			new DataTypeSyncDialog(plugin, "WinHelloCPP.exe", "MyArchive", list, set, "Commit",
				"Commit Datatype Changes From \"WinHelloCpp.exe\" to Archive \"MyArchive\"");

		showModalDialogInTool(dialog);

		runSwing(() -> {
			Object syncPanel = getInstanceField("syncPanel", dialog);
			GhidraTable table = (GhidraTable) getInstanceField("syncTable", syncPanel);
			table.selectRow(0);
		});

		captureDialog(900, 500);
	}

	@Test
	public void testDataTypeConflict() {
		ConflictDialog dialog = new ConflictDialog("SIZE_T", "/baseDTs", "SIZE_T.conflict");
		showModalDialogInTool(dialog);
		captureDialog();
	}

	@Test
	public void testDataTypeManager() {
		captureIsolatedProvider(DataTypesProvider.class, 500, 400);
	}

	@Test
	public void testDataTypeTreeWithAssociations() {
		DataTypesProvider provider = getProvider(DataTypesProvider.class);
		GTree tree = (GTree) getInstanceField("archiveGTree", provider);
		GTreeNode rootNode = tree.getViewRoot();
		GTreeNode child = rootNode.getChild("WinHelloCPP.exe");
		child = child.getChild("basetsd.h");
		tree.expandPath(child);
		captureIsolatedProvider(DataTypesProvider.class, 500, 400);
	}

	@Test
	public void testDisassociateDialog() {
		DataTypeManagerPlugin plugin = getPlugin(tool, DataTypeManagerPlugin.class);
		List<DataTypeSyncInfo> list = new ArrayList<>();
		Set<DataTypeSyncInfo> set = new HashSet<>();
		createChangedDatatypesFromArchive(list, set);

		final DataTypeSyncDialog dialog =
			new DataTypeSyncDialog(plugin, "WinHelloCPP.exe", "MyArchive", list, set, "Diassociate",
				"Disassociate DataType In \"WinHelloCpp.exe\" From Archive \"MyArchive\"");

		showModalDialogInTool(dialog);

		runSwing(() -> {
			Object syncPanel = getInstanceField("syncPanel", dialog);
			GhidraTable table = (GhidraTable) getInstanceField("syncTable", syncPanel);
			table.selectRow(0);
		});

		captureDialog(900, 500);
	}

	@Test
	public void testEditPaths() {
		Preferences.setProperty(DataTypeManagerHandler.DATA_TYPE_ARCHIVE_PATH_KEY,
			"/archives/subPath" + File.pathSeparator + "/otherArchives/subpath");
		performAction("Edit Archive Paths", "DataTypeManagerPlugin", false);

		// change the renderer so that it doesn't paint red for the missing paths
		DialogComponentProvider dialog = getDialog();
		GTable table = findComponent(dialog, GTable.class);
		TableColumn pathColumn = table.getColumnModel().getColumn(1);
		pathColumn.setCellRenderer(new GTableCellRenderer());

		// give our new render a chance to paint the non-red font
		table.paintImmediately(table.getBounds());
		waitForSwing();

		captureDialog();
	}

	@Test
	public void testFavoriteDts() {
		DataTypesProvider provider = getProvider(DataTypesProvider.class);
		GTree tree = (GTree) getInstanceField("archiveGTree", provider);
		GTreeNode rootNode = tree.getViewRoot();
		GTreeNode child = rootNode.getChild("BuiltInTypes");
		tree.expandPath(child);
		captureIsolatedProvider(DataTypesProvider.class, 500, 400);
	}

	@Test
	public void testFindDataTypes() {
		performAction("Find Data Types", "DataTypeManagerPlugin", false);
		JDialog d = waitForJDialog("Find Data Types");
		captureDialog();
		pressButtonByText(d, "Cancel");
	}

	@Test
	public void testPreviewWindow() {

		DockingActionIf action = getAction(tool, "DataTypeManagerPlugin", "Show Preview Window");
		performAction(action);

		DataTypesProvider provider = getProvider(DataTypesProvider.class);
		GTree tree = (GTree) getInstanceField("archiveGTree", provider);
		GTreeNode rootNode = tree.getViewRoot();
		GTreeNode child = rootNode.getChild("WinHelloCPP.exe");
		child = child.getChild("DOS");
		tree.expandPath(child);
		child = child.getChild("IMAGE_DOS_HEADER");
		tree.setSelectedNode(child);
		final JSplitPane splitPane = (JSplitPane) getInstanceField("splitPane", provider);
		runSwing(() -> {
			splitPane.setDividerLocation(0.5);
			splitPane.setResizeWeight(0.4);
		});

		captureIsolatedProvider(DataTypesProvider.class, 500, 1000);
	}

	@Test
	public void testRevertDialog() {
		DataTypeManagerPlugin plugin = getPlugin(tool, DataTypeManagerPlugin.class);
		List<DataTypeSyncInfo> list = new ArrayList<>();
		Set<DataTypeSyncInfo> set = new HashSet<>();
		createChangedDatatypesFromArchive(list, set);

		final DataTypeSyncDialog dialog =
			new DataTypeSyncDialog(plugin, "WinHelloCPP.exe", "MyArchive", list, set, "Revert",
				"Revert DataType Changes In \"WinHelloCpp.exe\" From Archive \"MyArchive\"");

		showModalDialogInTool(dialog);

		runSwing(() -> {
			Object syncPanel = getInstanceField("syncPanel", dialog);
			GhidraTable table = (GhidraTable) getInstanceField("syncTable", syncPanel);
			table.selectRow(0);
		});

		captureDialog(900, 500);
	}

	@Test
	public void testSearchResults() {

		closeNonProgramArchives();
		closeProvider(DataTypesProvider.class);
		runSwing(() -> performAction("Find Data Types", "DataTypeManagerPlugin", false), false);

		final DialogComponentProvider dialog = getDialog();
		runSwing(() -> {
			JTextField[] textFields = (JTextField[]) getInstanceField("textFields", dialog);
			textFields[0].setText("type");
		});

		pressOkOnDialog();
		waitForSwing();
		DataTypesProvider provider = getVisibleProvider();
		GTree tree = (GTree) getInstanceField("archiveGTree", provider);
		waitForTree(tree);
		captureIsolatedProvider(provider, 500, 500);
	}

	@Test
	public void testUpdateDialog() {
		DataTypeManagerPlugin plugin = getPlugin(tool, DataTypeManagerPlugin.class);
		List<DataTypeSyncInfo> list = new ArrayList<>();
		Set<DataTypeSyncInfo> set = new HashSet<>();
		createChangedDatatypesFromArchive(list, set);

		DataTypeManager dtm = program.getDataTypeManager();

		StandAloneDataTypeManager sourceDTM = new StandAloneDataTypeManager("MyArhcive");
		StructureDataType sdt1 = new StructureDataType("MyDataType1", 0);
		sdt1.add(new PointerDataType(new StringDataType()), "name", null);
		sdt1.add(new IntegerDataType(), "age", null);
		sdt1.add(new PointerDataType(new VoidDataType()), "data", null);

		StructureDataType sdt2 = new StructureDataType("MyDataType2", 0);
		sdt2.add(new PointerDataType(new IntegerDataType()));
		sdt2.add(new IntegerDataType());
		sdt2.add(new WordDataType());

		int id = sourceDTM.startTransaction("Test");
		DataType dt1 = sourceDTM.addDataType(sdt1, null);
		sourceDTM.endTransaction(id, true);

		int txID = program.startTransaction("Test");
		Structure struct = (Structure) dtm.addDataType(dt1, null);
		program.endTransaction(txID, true);

		id = sourceDTM.startTransaction("Test2");
		((Structure) dt1).add(new IntegerDataType(), "id", null);
		sourceDTM.endTransaction(id, true);

		DataTypeSyncInfo sync1 = new DataTypeSyncInfo(struct, sourceDTM);
		list.add(sync1);
		set.add(sync1);

		final DataTypeSyncDialog dialog =
			new DataTypeSyncDialog(plugin, "WinHelloCPP.exe", "MyArchive", list, set, "Update",
				"Update DataType Changes From Archive \"MyArchive\" To \"WinHelloCpp.exe\" ");

		showModalDialogInTool(dialog);

		runSwing(() -> {
			Object syncPanel = getInstanceField("syncPanel", dialog);
			GhidraTable table = (GhidraTable) getInstanceField("syncTable", syncPanel);
			table.selectRow(0);
		});

		captureDialog(900, 500);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void removeInvalidArchives() {
		DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
		DataTypeManagerHandler handler = plugin.getDataTypeManagerHandler();
		@SuppressWarnings("unchecked")
		Map<UniversalID, InvalidFileArchive> invalid =
			(Map<UniversalID, InvalidFileArchive>) getInstanceField("invalidArchives", handler);
		Collection<InvalidFileArchive> values = invalid.values();
		for (InvalidFileArchive invalidFileArchive : values) {
			removeArchive(handler, invalidFileArchive);
		}
	}

	private void removeArchive(final DataTypeManagerHandler handler,
			final InvalidFileArchive archive) {
		runSwing(() -> handler.removeInvalidArchive(archive));
	}

	private DataTypesProvider getVisibleProvider() {
		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		List<DataTypesProvider> providers = dwm.getComponentProviders(DataTypesProvider.class);
		for (ComponentProvider provider : providers) {
			if (provider.isVisible()) {
				return (DataTypesProvider) provider;
			}
		}
		Assert.fail("Unable to find a visible provider");
		return null;// cannot get here
	}

	private void createChangedDatatypesFromArchive(List<DataTypeSyncInfo> list,
			Set<DataTypeSyncInfo> set) {
		DataTypeManager dtm = program.getDataTypeManager();

		StandAloneDataTypeManager sourceDTM = new StandAloneDataTypeManager("MyArhcive");
		StructureDataType sdt1 = new StructureDataType("MyDataType1", 0);
		sdt1.add(new PointerDataType(new StringDataType()), "name", null);
		sdt1.add(new IntegerDataType(), "age", null);
		sdt1.add(new PointerDataType(new VoidDataType()), "data", null);

		StructureDataType sdt2 = new StructureDataType("MyDataType2", 0);
		sdt2.add(new PointerDataType(new IntegerDataType()));
		sdt2.add(new IntegerDataType());
		sdt2.add(new WordDataType());

		int id = sourceDTM.startTransaction("Test");
		DataType dt1 = sourceDTM.addDataType(sdt1, null);
		DataType dt2 = sourceDTM.addDataType(sdt2, null);
		sourceDTM.endTransaction(id, true);

		int txID = program.startTransaction("Test");
		try {
			Structure struct = (Structure) dtm.addDataType(dt1, null);
			struct.add(new IntegerDataType(), "id", null);
			Structure struct2 = (Structure) dtm.addDataType(dt2, null);
			struct2.add(new IntegerDataType());

			DataTypeSyncInfo sync1 = new DataTypeSyncInfo(struct, sourceDTM);
			DataTypeSyncInfo sync2 = new DataTypeSyncInfo(struct2, sourceDTM);
			list.add(sync1);
			list.add(sync2);
			set.add(sync1);
		}
		finally {
			program.endTransaction(txID, true);
		}
	}

	private void showModalDialogInTool(final DialogComponentProvider dialog) {
		runSwing(() -> tool.showDialog(dialog), false);

		waitForSwing();
	}

}
