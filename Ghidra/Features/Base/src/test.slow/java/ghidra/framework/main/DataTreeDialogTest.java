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
package ghidra.framework.main;

import static ghidra.framework.main.DataTreeDialogType.*;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatree.*;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class DataTreeDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool frontEndTool;
	private DataTreeDialog dialog;
	private List<String> names =
		List.of("notepad", "XNotepad", "tNotepadA", "tNotepadB", "tNotepadC", "tNotepadD");

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		createBlankProgramsInProject(names);
	}

	private List<DomainFile> createBlankProgramsInProject(List<String> paths) throws Exception {
		List<DomainFile> result = new ArrayList<>();

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY_BE);
		Program p = builder.getProgram();
		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();
		for (String pathFilename : paths) {
			int lastSlash = pathFilename.lastIndexOf('/');
			String path = (lastSlash >= 0) ? pathFilename.substring(0, lastSlash) : "";
			String filename =
				(lastSlash >= 0) ? pathFilename.substring(lastSlash + 1) : pathFilename;
			DomainFolder domainFolder = ProjectDataUtils.createDomainFolderPath(rootFolder, path);
			result.add(domainFolder.createFile(filename, p, TaskMonitor.DUMMY));
		}
		builder.dispose();
		waitForSwing();
		return result;
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testFilters() {

		showFiltered("tN");

		JTree tree = getJTree();
		List<String> expectedFilteredNames = names.stream()
				.filter(s -> s.startsWith("tN"))
				.sorted()
				.collect(Collectors.toList());

		TreeModel model = tree.getModel();
		GTreeNode root = (GTreeNode) model.getRoot();
		assertEquals(expectedFilteredNames.size(), root.getChildCount());
		for (int i = 0; i < expectedFilteredNames.size(); i++) {
			GTreeNode child = root.getChild(i);
			assertEquals(expectedFilteredNames.get(i), child.toString());
		}
	}

	@Test
	public void testOKButtonDisabled_Type_SAVE() {
		// no initial selection--button disabled
		show(SAVE);
		assertOK(false);

		// select a file--enabled; name field populated
		selectFile("notepad");
		assertOK(true);
		assertNameHasText(true);

		// de-select file--text remains; button enabled
		deselectFile();
		assertOK(true);
		assertNameHasText(true);

		// select a folder--text remains; button enabled
		selectFolder();
		assertOK(true);
		assertNameHasText(true);

		// de-select a folder--text remains; button enabled
		deselectFolder();
		assertOK(true);
		assertNameHasText(true);

		// clear text--disabled
		clearText();
		assertOK(false);
	}

	@Test
	public void testOKButtonDisabled_Type_CREATE() {
		// no initial selection--button disabled
		show(CREATE);
		assertOK(false);

		// select a file--enabled; name field populated
		selectFile("notepad");
		assertOK(true);
		assertNameHasText(true);

		// de-select file--text remains; button enabled
		deselectFile();
		assertOK(true);
		assertNameHasText(true);

		// select a folder--text remains; button enabled
		selectFolder();
		assertOK(true);
		assertNameHasText(true);

		// de-select a folder--text remains; button enabled
		deselectFolder();
		assertOK(true);
		assertNameHasText(true);

		// clear text--disabled
		clearText();
		assertOK(false);
	}

	@Test
	public void testOKButtonAlwaysEnabled_Type_CHOOSE_FOLDER() {
		// 
		// This tests that when choosing a folder, the root is selected by default so that users can
		// simply press OK to pick a folder quickly. 
		//
		// **Also, the tree remembers folder selections and files selections, with the file's parent
		// being the selected folder.  It appears that you cannot get rid of the dialog's notion of
		// the current folder.  This tests that.
		//
		show(CHOOSE_FOLDER);
		assertOK(true);

		// select a file--enabled; name field populated
		selectFile("notepad");
		assertOK(true);
		assertNameHasText(true);

		// de-select file--still enabled (root selected by default)
		deselectFile();
		assertOK(true);
		assertNameHasText(true); // "/"

		// select a folder--enabled
		selectFolder();
		assertOK(true);
		assertNameHasText(true);

		// de-select file--still enabled (root selected by default)
		deselectFolder();
		assertOK(true);
		assertNameHasText(true); // "/"
	}

	@Test
	public void testOKButtonDisabled_Type_OPEN() {
		// no initial selection--button disabled
		show(OPEN);
		assertOK(false);

		// select a file--enabled; name field populated
		selectFile("notepad");
		assertOK(true);
		assertNameHasText(true);

		// de-select file--disabled; name field cleared
		deselectFile();
		assertOK(false);
		assertNameHasText(false);

		// select a folder--disabled
		selectFolder();
		assertOK(false);

		// de-select a folder--disabled
		deselectFolder();
		assertNameHasText(false);
	}

	@Test
	public void testOKButtonEnabledWithInitialSelection_Type_OPEN() {
		//  initial selection--button enabled
		show(OPEN, "x07");
		assertOK(true);

		// select a file--enabled; name field populated
		selectFile("notepad");
		assertOK(true);
		assertNameHasText(true);

		// de-select file--disabled; name field cleared
		deselectFile();
		assertOK(false);
		assertNameHasText(false);

		// select a folder--disabled
		selectFolder();
		assertOK(false);

		// de-select a folder--disabled
		deselectFolder();
		assertNameHasText(false);
	}

	@Test
	public void testSelectFiles() throws Exception {
		List<DomainFile> createdFiles = createBlankProgramsInProject(
			List.of("/dir1/dir2/file1", "/dir1/dir2a/dir3a/file2", "/file3"));
		show(OPEN);

		ProjectDataTreePanel projectDataTreePanel = getProjectDataTreePanel();

		DomainFile file1 = createdFiles.get(0);
		DomainFile file2 = createdFiles.get(1);
		projectDataTreePanel.selectDomainFiles(Set.of(file1, file2));
		waitForTree(getGTree());

		Set<DomainFile> selectedData = getSelectedFiles();
		assertEquals(selectedData.size(), 2);
		assertTrue(selectedData.contains(file1));
		assertTrue(selectedData.contains(file2));
	}

	@Test
	public void testSelectFolder() throws Exception {
		List<DomainFile> createdFiles = createBlankProgramsInProject(
			List.of("/dir1/dir2/file1", "/dir1/dir2a/dir3a/file2", "/file3"));
		show(OPEN);

		ProjectDataTreePanel projectDataTreePanel = getProjectDataTreePanel();

		DomainFile file1 = createdFiles.get(0);
		DomainFolder dir2 = file1.getParent();
		projectDataTreePanel.selectDomainFolder(dir2);
		waitForTree(getGTree());

		Set<DomainFolder> selectedData = getSelectedFolders();
		assertEquals(selectedData.size(), 1);
		assertTrue("'dir2' not selected", selectedData.contains(dir2));
	}

//==================================================================================================
// Private
//==================================================================================================

	private Set<DomainFolder> getSelectedFolders() {
		Set<DomainFolder> set = new HashSet<>();
		TreePath[] paths = getGTree().getSelectionPaths();
		for (TreePath path : paths) {
			Object leafNode = path.getLastPathComponent();
			if (leafNode instanceof DomainFolderNode folderNode) {
				set.add(folderNode.getDomainFolder());
			}
		}
		return set;
	}

	private Set<DomainFile> getSelectedFiles() {
		Set<DomainFile> set = new HashSet<>();
		TreePath[] paths = getGTree().getSelectionPaths();
		for (TreePath path : paths) {
			Object leafNode = path.getLastPathComponent();
			if (leafNode instanceof DomainFileNode fileNode) {
				set.add(fileNode.getDomainFile());
			}
		}
		return set;
	}

	private void deselectFolder() {
		clearSelection();
	}

	private void clearText() {
		runSwing(() -> {
			JTextField nameField = getNameField();
			nameField.setText("");
		});
	}

	private void selectFolder() {
		final AtomicBoolean result = new AtomicBoolean(false);
		final GTree gTree = getGTree();
		runSwing(() -> {
			GTreeNode node = gTree.getViewRoot();
			if (node != null) {
				gTree.expandPath(node);
				gTree.setSelectedNode(node);
				result.set(true);
			}
		});

		if (!result.get()) {
			Assert.fail("Unable to select root folder");
		}

		waitForTree(gTree);
	}

	private void deselectFile() {
		clearSelection();
	}

	private void clearSelection() {
		GTree gTree = getGTree();
		gTree.clearSelectionPaths();
		waitForTree(gTree);
	}

	private void assertNameHasText(boolean hasText) {
		final AtomicBoolean result = new AtomicBoolean();
		runSwing(() -> {
			JTextField name = getNameField();
			String text = name.getText();
			result.set(text != null && !text.isEmpty());
		});

		if (hasText) {
			assertEquals("Name field has no text when it should", hasText, result.get());
		}
		else {
			assertEquals("Name field has text when it should be cleared", hasText, result.get());
		}
	}

	private JTextField getNameField() {
		return (JTextField) getInstanceField("nameField", dialog);
	}

	private void assertOK(boolean isOK) {
		JButton ok = getOK();
		assertEquals("OK button not enabled", isOK, ok.isEnabled());
	}

	private JButton getOK() {
		return (JButton) getInstanceField("okButton", dialog);
	}

	private void selectFile(final String name) {
		final AtomicBoolean result = new AtomicBoolean(false);
		final GTree gTree = getGTree();
		runSwing(() -> {
			GTreeNode root = gTree.getModelRoot();
			GTreeNode node = root.getChild(name);
			if (node != null) {
				gTree.expandPath(node);
				gTree.setSelectedNode(node);
				result.set(true);
			}
		});

		if (!result.get()) {
			Assert.fail("Unable to select a node by name: " + name);
		}

		waitForTree(gTree);
	}

	private void show(DataTreeDialogType type) {
		Swing.runLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog", type);
			dialog.showComponent();
		});
		waitForSwing();
		assertNotNull(dialog);
	}

	private void show(DataTreeDialogType type, final String name) {
		Swing.runLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog", type);
			dialog.setNameText(name);
			dialog.showComponent();
		});

		waitForSwing();
		waitForTree(getGTree());
		assertNotNull(dialog);
	}

	private void showFiltered(final String startsWith) {
		Swing.runLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog",
				OPEN, f -> f.getName().startsWith(startsWith));
			dialog.showComponent();
		});
		waitForSwing();
		assertNotNull(dialog);
	}

	private GTree getGTree() {
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dialog);
		return (GTree) getInstanceField("tree", treePanel);
	}

	private ProjectDataTreePanel getProjectDataTreePanel() {
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dialog);
		return treePanel;
	}

	private JTree getJTree() {
		JTree tree = findComponent(dialog.getComponent(), JTree.class);
		assertNotNull(tree);
		return tree;
	}

}
