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
package ghidra.framework.main.datatree;

import static org.junit.Assert.*;

import java.awt.Container;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.GTreeRootNode;
import docking.widgets.tree.support.BreadthFirstIterator;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitorAdapter;
import resources.MultiIcon;
import resources.ResourceManager;

/**
 *
 * Mores Tests for actions in the front end (Ghidra project window). 
 * 
 */
public class ActionManager2Test extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private DataTree tree;
	private DomainFolder rootFolder;
	private GTreeRootNode rootNode;

	public ActionManager2Test() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		tree = findComponent(frontEndTool.getToolFrame(), DataTree.class);
		rootFolder = env.getProject().getProjectData().getRootFolder();

		Program p = createDefaultProgram("p1", ProgramBuilder._TOY, this);

		rootFolder.createFile("notepad", p, TaskMonitorAdapter.DUMMY_MONITOR);
		p.release(this);

		p = createDefaultProgram("p2", ProgramBuilder._TOY, this);
		rootFolder.createFile("X07", p, TaskMonitorAdapter.DUMMY_MONITOR);
		p.release(this);

		rootNode = tree.getRootNode();

		expandPath(rootNode.getTreePath());
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testRenameFolder() throws Exception {
		rootFolder.createFolder("myFolder");
		waitForSwing();

		final GTreeNode myNode = rootNode.getChild("myFolder");
		setSelectionPath(myNode.getTreePath());

		DockingActionIf renameAction = getAction("Rename");
		performAction(renameAction, getDomainFileActionContext(), true);
		waitForTree();

		// select "Rename" action
		SwingUtilities.invokeAndWait(() -> {
			int row = tree.getRowForPath(myNode.getTreePath());
			JTree jTree = (JTree) getInstanceField("tree", tree);
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, myNode,
				true, true, false, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("MyNewFolder");
			tree.stopEditing();
		});
		waitForSwing();
		assertNotNull(rootNode.getChild("MyNewFolder"));
		assertNull(rootNode.getChild("myFolder"));
	}

	@Test
	public void testRenameFile() throws Exception {
		final GTreeNode npNode = rootNode.getChild("notepad");
		setSelectionPath(npNode.getTreePath());

		DockingActionIf renameAction = getAction("Rename");
		performAction(renameAction, getDomainFileActionContext(), true);
		waitForTree();

		// select "Rename" action
		SwingUtilities.invokeAndWait(() -> {
			int row = tree.getRowForPath(npNode.getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			JTree jTree = (JTree) getInstanceField("tree", tree);
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, npNode,
				true, true, false, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("My_notepad");
			tree.stopEditing();
		});
		waitForSwing();
		assertNotNull(rootNode.getChild("My_notepad"));
		assertNull(rootNode.getChild("notepad"));

	}

	@Test
	public void testRenameFileInUse() throws Exception {
		final GTreeNode npNode = rootNode.getChild("notepad");
		DomainFile df = ((DomainFileNode) npNode).getDomainFile();

		setInUse(df);

		setSelectionPath(npNode.getTreePath());

		DockingActionIf renameAction = getAction("Rename");
		executeOnSwingWithoutBlocking(
			() -> performAction(renameAction, getDomainFileActionContext(), true));
		waitForSwing();
		OptionDialog dlg = waitForDialogComponent(OptionDialog.class);
		assertEquals("Rename Not Allowed", dlg.getTitle());
		pressButtonByText(dlg.getComponent(), "OK");
		assertNotNull(rootNode.getChild("notepad"));
	}

	private void setInUse(DomainFile df) throws Exception {
		setInUse(df, "/notepad");
	}

	private void setInUse(DomainFile df, final String path) throws Exception {
		ProgramDB program = createDefaultProgram("test1", ProgramBuilder._TOY, this);

		//
		// 					Unusual Code Alert!
		// We are calling an internal method to trigger the 'in use' state, as it is much
		// faster to do this than it is to open a program in a tool!
		//

		//@formatter:off
		Object projectFileManager = getInstanceField("fileManager", df);
		invokeInstanceMethod("setDomainObject", projectFileManager, 
			new Class[] { String.class, 	DomainObjectAdapter.class }, 
			new Object[] { path, program }
		);
		//@formatter:on
	}

	@Test
	public void testRenameFolderInUse() throws Exception {
		// folder contains a file that is in use
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");

		Program p = createDefaultProgram("new", ProgramBuilder._TOY, this);

		DomainFile df = f.createFile("notepad", p, TaskMonitorAdapter.DUMMY_MONITOR);
		waitForSwing();

		final GTreeNode myNode = rootNode.getChild("myFolder");
		((DomainFolderNode) myNode).getDomainFolder().createFile("notepad", p,
			TaskMonitorAdapter.DUMMY_MONITOR);
		p.release(this);

		waitForSwing();
		tree.expandPath(myNode.getTreePath());
		assertNotNull(myNode.getChild("notepad"));

		setInUse(df, "/myFolder/notepad");

		setSelectionPath(myNode.getTreePath());

		final DockingActionIf renameAction = getAction("Rename");
		performAction(renameAction, getDomainFileActionContext(), true);
		waitForTree();

		// attempt to rename "myFolder"
		SwingUtilities.invokeLater(() -> {
			int row = tree.getRowForPath(myNode.getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			JTree jTree = (JTree) getInstanceField("tree", tree);
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, myNode,
				true, true, false, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("My_Newfolder");
			tree.stopEditing();
		});

		waitForSwing();

		OptionDialog d =
			waitForDialogComponent(frontEndTool.getToolFrame(), OptionDialog.class, 2000);
		assertNotNull(d);
		assertEquals("Rename Failed", d.getTitle());
		pressButtonByText(d.getComponent(), "OK");
		assertNotNull(rootNode.getChild("myFolder"));
	}

	@Test
	public void testExpandAll() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");
		waitForSwing();

		GTreeNode myNode = rootNode.getChild("myFolder");
		setSelectionPath(rootNode.getTreePath());
		DockingActionIf expandAction = getAction("Expand All");
		performAction(expandAction, getDomainFileActionContext(), true);
		GTreeNode aNode = myNode.getChild("A");
		assertNotNull(aNode);
		GTreeNode bNode = aNode.getChild("B");
		assertNotNull(bNode);
		GTreeNode cNode = bNode.getChild("C");
		assertNotNull(cNode);
	}

	@Test
	public void testCollapseAll() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");
		waitForSwing();

		GTreeNode myNode = rootNode.getChild("myFolder");
		setSelectionPath(myNode.getTreePath());
		DockingActionIf expandAction = getAction("Expand All");
		performAction(expandAction, getDomainFileActionContext(), true);
		waitForTree();

		DockingActionIf collapseAction = getAction("Collapse All");
		performAction(collapseAction, getDomainFileActionContext(), true);
		waitForTree();
		assertTrue(!tree.isExpanded(myNode.getTreePath()));
		GTreeNode aNode = myNode.getChild("A");
		assertTrue(!tree.isExpanded(aNode.getTreePath()));
		GTreeNode bNode = aNode.getChild("B");
		assertTrue(!tree.isExpanded(bNode.getTreePath()));
		GTreeNode cNode = bNode.getChild("C");
		assertNotNull(cNode);
		assertTrue(!tree.isExpanded(cNode.getTreePath()));
	}

	@Test
	public void testSelectAll() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");
		waitForSwing();

		setSelectionPath(rootNode.getTreePath());
		DockingActionIf selectAction = getAction("Select All");
		performAction(selectAction, getDomainFileActionContext(), true);
		waitForTree();

		BreadthFirstIterator it = new BreadthFirstIterator(tree, rootNode);
		while (it.hasNext()) {
			GTreeNode node = it.next();
			assertTrue(tree.isPathSelected(node.getTreePath()));
		}
	}

	@Test
	public void testSetReadOnly() throws Exception {
		GTreeNode npNode = rootNode.getChild("notepad");
		setSelectionPath(npNode.getTreePath());
		ToggleDockingAction readOnlyAction = (ToggleDockingAction) getAction("Read-Only");
		readOnlyAction.setSelected(true);
		performAction(readOnlyAction, getDomainFileActionContext(), true);

		assertTrue(((DomainFileNode) npNode).getDomainFile().isReadOnly());
		ImageIcon icon = ResourceManager.loadImage("fileIcons/ProgramReadOnly.gif");
		icon = ResourceManager.getScaledIcon(icon, 16, 16);

		assertTrue(npNode.getIcon(false) instanceof MultiIcon);
	}

	@Test
	public void testSetReadOnlyInUse() throws Exception {
		GTreeNode npNode = rootNode.getChild("notepad");
		DomainFile df = ((DomainFileNode) npNode).getDomainFile();
		setInUse(df);

		setSelectionPath(npNode.getTreePath());
		ToggleDockingAction readOnlyAction = (ToggleDockingAction) getAction("Read-Only");
		readOnlyAction.setSelected(true);
		performAction(readOnlyAction, getDomainFileActionContext(), true);

		assertTrue(((DomainFileNode) npNode).getDomainFile().isReadOnly());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private ActionContext getDomainFileActionContext() {
		List<DomainFile> fileList = new ArrayList<>();
		List<DomainFolder> folderList = new ArrayList<>();

		TreePath[] paths = tree.getSelectionPaths();
		for (TreePath path : paths) {

			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node instanceof DomainFileNode) {
				fileList.add(((DomainFileNode) node).getDomainFile());
			}
			else if (node instanceof DomainFolderNode) {
				folderList.add(((DomainFolderNode) node).getDomainFolder());
			}
		}

		return new ProjectDataTreeActionContext(null, null, paths, folderList, fileList, tree,
			true);
	}

	private DockingActionIf getAction(String actionName) {
		List<DockingActionIf> a =
			frontEndTool.getDockingActionsByFullActionName(actionName + " (FrontEndPlugin)");
		assertEquals(1, a.size());
		return a.get(0);
	}

	private void setSelectionPath(final TreePath path) throws Exception {
		tree.setSelectionPath(path);
		waitForTree();
	}

	private void expandPath(TreePath treePath) {
		tree.expandPath(treePath);
		waitForTree();
	}

	private void waitForTree() {
		waitForSwing();
		while (tree.isBusy()) {
			try {
				Thread.sleep(10);
			}
			catch (InterruptedException e) {
				// try again
			}
		}
		waitForSwing();
	}
}
