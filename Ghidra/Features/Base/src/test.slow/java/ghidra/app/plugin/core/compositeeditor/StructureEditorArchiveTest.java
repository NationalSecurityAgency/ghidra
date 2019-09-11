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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import java.io.File;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.Before;
import org.junit.Test;

import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.test.TestEnv;

public class StructureEditorArchiveTest extends AbstractStructureEditorTest {

	private DataTypeArchiveGTree dtTree;
	private DataTypeManager archiveDTM;

	private DockingActionIf manageDts;
	private DockingActionIf openForEditing;
	private DockingActionIf closeArchive;
	private DockingActionIf createStruct;

	private Category arcRootCat;

	@Override
	@Before
	public void setUp() throws Exception {
		CommonTestData.initialize();
		emptyStructure = CommonTestData.emptyStructure;
		emptyUnion = CommonTestData.emptyUnion;
		env = new TestEnv();

		program = createDefaultProgram("Test", languageName, this);
		tool = env.showTool(program);
		env.showFrontEndTool();

		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		dtmService = tool.getService(DataTypeManagerService.class);
		plugin = (DataTypeManagerPlugin) dtmService;
		manageDts = getAction(plugin, "DataTypes Provider");
		DataTypesProvider dataTypesProvider = plugin.getProvider();
		dtTree = dataTypesProvider.getGTree();

		createNewArchive();

		createStruct = getAction(plugin, "Structure");
		performAction(createStruct, plugin.getProvider(), true);
		waitForPostedSwingRunnables();
		CompEditorPanel editorPanel =
			findComponent(tool.getToolFrame(), CompEditorPanel.class, true);
		model = editorPanel.model;
		installProvider(model.getProvider());
		archiveDTM = model.getOriginalDataTypeManager();

		loadArchiveWithDts();
		runSwing(() -> provider.closeComponent(), false);
		waitForSwing();

		// Answer "No" to "Save Structure Editor Changes?".
		JDialog dialog = waitForJDialog(null, "Save Structure Editor Changes?", 2000);
		assertNotNull(dialog);
		pressButtonByText(dialog.getContentPane(), "No");
		waitForSwing();

		programDTM = program.getListing().getDataTypeManager();
		txId = programDTM.startTransaction("Modify Program");
		pgmRootCat = programDTM.getCategory(CategoryPath.ROOT);
		programDTM.createCategory(CommonTestData.category.getCategoryPath());
		pgmTestCat = programDTM.getCategory(CommonTestData.category.getCategoryPath());
		pgmAaCat = programDTM.getCategory(CommonTestData.aaCategory.getCategoryPath());
		pgmBbCat = programDTM.getCategory(CommonTestData.bbCategory.getCategoryPath());
		simpleStructure = (Structure) programDTM.resolve(CommonTestData.simpleStructure, null);
		simpleUnion = (Union) programDTM.resolve(CommonTestData.simpleUnion, null);
		complexStructure = (Structure) programDTM.resolve(CommonTestData.complexStructure, null);
		complexUnion = (Union) programDTM.resolve(CommonTestData.complexUnion, null);
		program.endTransaction(txId, true);
		listener = new StatusListener();
	}

	private void createNewArchive(String archiveName, boolean deleteExisting) throws Exception {
		File archiveFile = new File(getTestDirectoryPath(), archiveName);
		if (deleteExisting) {
			archiveFile.delete();
		}

		final DockingActionIf action = getAction(plugin, "New File Data Type Archive");

		DataTypeTestUtils.performAction(action, dtTree, false);

		GhidraFileChooser chooser =
			waitForDialogComponent(tool.getToolFrame(), GhidraFileChooser.class, 10000);
		assertNotNull("Never found chooser!", chooser);
		selectFileInChooser(chooser, archiveFile);

		// hit "Create Archive" button
		JButton saveAsButton = findButtonByText(chooser, "Create Archive");
		pressButton(saveAsButton);
		waitForPostedSwingRunnables();

	}

	private void selectFileInChooser(final GhidraFileChooser fileChooser, final File file)
			throws Exception {
		SwingUtilities.invokeAndWait(() -> fileChooser.setSelectedFile(file));
		waitForUpdateOnChooser(fileChooser);
	}

	private void createNewArchive() throws Exception {
		invoke(manageDts);

		createNewArchive("New Archive.gdt", true);
		openForEditing = getAction(plugin, "Lock Archive");
//		checkOut = getDockingAction(plugin, "Check Out");
//		openArchive = getDockingAction(plugin, "Open Data Type Archive");
		closeArchive = getAction(plugin, "Close Archive");
		waitForTree(dtTree);
		GTreeNode rootNode = dtTree.getModelRoot();
		GTreeNode newNode = rootNode.getChild("New Archive");
		selectNode(newNode);
	}

	private void loadArchiveWithDts() {
		txId = archiveDTM.startTransaction("Modify Archive");
		arcRootCat = archiveDTM.getRootCategory();
		archiveDTM.getCategory(CommonTestData.category.getCategoryPath());
		archiveDTM.getCategory(CommonTestData.aaCategory.getCategoryPath());
		archiveDTM.getCategory(CommonTestData.bbCategory.getCategoryPath());
		archiveDTM.resolve(CommonTestData.simpleStructure, DataTypeConflictHandler.DEFAULT_HANDLER);
		archiveDTM.resolve(CommonTestData.simpleUnion, null);
		archiveDTM.resolve(CommonTestData.complexStructure, null);
		archiveDTM.resolve(CommonTestData.complexUnion, null);
		archiveDTM.endTransaction(txId, true);
	}

	@Test
	public void testCreateArchiveStructure() throws Exception {
		createStruct = getAction(plugin, "Structure");
		performAction(createStruct, plugin.getProvider(), true);
		waitForPostedSwingRunnables();
		CompEditorPanel editorPanel =
			findComponent(tool.getToolFrame(), CompEditorPanel.class, true);

		model = editorPanel.model;
		installProvider(model.getProvider());

		DataTypesProvider dataTypesProvider = plugin.getProvider();
		dtTree = dataTypesProvider.getGTree();
		getActions();
		CycleGroupAction cycleByte = getCycleGroup(new ByteDataType());

		invoke(insertUndefinedAction);
		invoke(cycleByte);
		invoke(cycleByte);
		invoke(applyAction);
		runSwing(() -> provider.closeComponent());
		waitForTree(dtTree);

		Structure struct =
			(Structure) archiveDTM.getDataType(arcRootCat.getCategoryPath(), "struct");
		assertEquals(3, struct.getLength());
		assertEquals(2, struct.getNumComponents());
		DataTypeComponent comp0 = struct.getComponent(0);
		DataTypeComponent comp1 = struct.getComponent(1);
		assertTrue(comp0.getDataType().isEquivalent(DataType.DEFAULT));
		assertTrue(comp1.getDataType().isEquivalent(new WordDataType()));

		GTreeNode rootNode = dtTree.getModelRoot();
		GTreeNode child = rootNode.getChild("New Archive");
		selectNode(child);

		performAction(openForEditing, plugin.getProvider(), true);

		child = rootNode.getChild("New Archive");
		selectNode(child);

		performAction(closeArchive, plugin.getProvider(), false);
		OptionDialog dialog = waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		JButton button = findButtonByText(dialog, "No");
		pressButton(button);
	}

	private void selectNode(GTreeNode node) {
		dtTree.setSelectedNode(node);
		waitForTree(dtTree);
		TreePath selectionPath = dtTree.getSelectionPath();
		Object lastPathComponent = selectionPath.getLastPathComponent();
		assertEquals("Did not select node in tree: " + node.getName(), node, lastPathComponent);
	}

}
