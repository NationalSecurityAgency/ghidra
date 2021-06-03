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

import static org.junit.Assert.*;

import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.*;
import javax.swing.tree.TreeModel;

import org.junit.*;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;

public class DataTreeDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool frontEndTool;
	private DataTreeDialog dialog;
	private String[] names = new String[] { "tNotepadA", "tNotepadB", "tNotepadC", "tNotepadD" };

	/**
	 * Constructor for DataTreeDialogTest.
	 * @param arg0
	 */
	public DataTreeDialogTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

		DomainFolder rootFolder = env.getProject().getProjectData().getRootFolder();

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY_BE);
		Program p = builder.getProgram();
		rootFolder.createFile("notepad", p, TaskMonitorAdapter.DUMMY_MONITOR);
		rootFolder.createFile("XNotepad", p, TaskMonitorAdapter.DUMMY_MONITOR);
		for (String name : names) {
			rootFolder.createFile(name, p, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		builder.dispose();

		waitForPostedSwingRunnables();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testFilters() {

		showFiltered();

		JTree tree = getJTree();

		TreeModel model = tree.getModel();
		GTreeNode root = (GTreeNode) model.getRoot();
		assertEquals(names.length, root.getChildCount());
		for (int i = 0; i < names.length; i++) {
			GTreeNode child = root.getChild(i);
			assertEquals(names[i], child.toString());
		}
	}

	@Test
	public void testOKButtonDisabled_Type_SAVE() {
		// no initial selection--button disabled
		show(DataTreeDialog.SAVE);
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
		show(DataTreeDialog.CREATE);
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
		// no initial selection--button disabled
		show(DataTreeDialog.CHOOSE_FOLDER);
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
		show(DataTreeDialog.OPEN);
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
		show(DataTreeDialog.OPEN, "x07");
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

//==================================================================================================
// Private
//==================================================================================================

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

	private void show(final int type) {
		SwingUtilities.invokeLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog", type);

			dialog.showComponent();
		});
		waitForPostedSwingRunnables();
		assertNotNull(dialog);
	}

	private void show(final int type, final String name) {
		SwingUtilities.invokeLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog", type);

			dialog.setNameText(name);
			dialog.showComponent();
		});

		waitForPostedSwingRunnables();
		waitForTree(getGTree());
		assertNotNull(dialog);
	}

	private void showFiltered() {
		SwingUtilities.invokeLater(() -> {
			dialog = new DataTreeDialog(frontEndTool.getToolFrame(), "Test Data Tree Dialog",
				DataTreeDialog.OPEN, new MyDomainFileFilter());

			dialog.showComponent();
		});
		waitForPostedSwingRunnables();
		assertNotNull(dialog);
	}

	private GTree getGTree() {
		ProjectDataTreePanel treePanel =
			(ProjectDataTreePanel) getInstanceField("treePanel", dialog);
		return (GTree) getInstanceField("tree", treePanel);
	}

	private JTree getJTree() {
		JTree tree = findComponent(dialog.getComponent(), JTree.class);
		assertNotNull(tree);
		return tree;
	}

	private class MyDomainFileFilter implements DomainFileFilter {
		/* (non-Javadoc)
		 * @see ghidra.framework.model.DomainFileFilter#accept(ghidra.framework.model.DomainFile)
		 */
		@Override
		public boolean accept(DomainFile df) {
			if (df.getName().startsWith("tN")) {
				return true;
			}
			return false;
		}
	}

}
