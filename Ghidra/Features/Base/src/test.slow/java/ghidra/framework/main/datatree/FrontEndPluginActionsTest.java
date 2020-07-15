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
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.test.AbstractDockingTest;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.*;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import resources.MultiIcon;
import resources.ResourceManager;

/**
 * Tests for actions in the front end (Ghidra project window)
 */
public class FrontEndPluginActionsTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private DataTree tree;
	private DomainFolder rootFolder;
	private GTreeNode rootNode;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		tree = findComponent(frontEndTool.getToolFrame(), DataTree.class);
		rootFolder = env.getProject().getProjectData().getRootFolder();

		Program p = createDefaultProgram("p1", ProgramBuilder._TOY, this);
		rootFolder.createFile("notepad", p, TaskMonitor.DUMMY);
		p.release(this);

		p = createDefaultProgram("p2", ProgramBuilder._TOY, this);
		rootFolder.createFile("X07", p, TaskMonitor.DUMMY);
		p.release(this);

		p = createDefaultProgram("p3", ProgramBuilder._TOY, this);
		rootFolder.createFile("tms", p, TaskMonitor.DUMMY);
		p.release(this);

		rootNode = tree.getModelRoot();
		waitForSwing();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testNewFolder() throws Exception {
		final DockingActionIf newFolderAction = getAction("New Folder");
		setSelectionPaths(new TreePath[] { rootNode.getTreePath() });
		int count = rootNode.getChildCount();
		performAction(newFolderAction, getDomainFileActionContext(), true);
		SwingUtilities.invokeAndWait(() -> tree.stopEditing());
		assertEquals(count + 1, rootNode.getChildCount());
		assertNotNull(getChild(rootNode, "NewFolder"));
	}

	@Test
	public void testNewFolderBlankName() throws Exception {
		// try entering a blank name
		final DockingActionIf newFolderAction = getAction("New Folder");
		setSelectionPaths(new TreePath[] { rootNode.getTreePath() });
		performAction(newFolderAction, getDomainFileActionContext(), true);
		waitForTree();
		SwingUtilities.invokeLater(() -> {
			GTreeNode node = rootNode.getChild("NewFolder");
			int row = tree.getRowForPath(node.getTreePath());
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			JTree jTree = (JTree) getInstanceField("tree", tree);
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, node,
				true, true, false, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("");

			tree.stopEditing();
		});
		waitForSwing();

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Rename Failed", d.getTitle());
		pressButtonByText(d.getComponent(), "OK");
	}

	@Test
	public void testNewFolder2() throws Exception {
		DockingActionIf newFolderAction = getAction("New Folder");

		for (int i = 0; i < 3; i++) {
			setSelectionPaths(new TreePath[] { rootNode.getTreePath() });
			performAction(newFolderAction, getDomainFileActionContext(), true);
			waitForTree();
			SwingUtilities.invokeAndWait(() -> tree.stopEditing());
			waitForTree();
			if (i > 0) {
				assertNotNull(getChild(rootNode, "NewFolder" + (i + 1)));
			}
		}
	}

	@Test
	public void testCutPasteFolder2Folder() throws Exception {

		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		rootFolder.createFolder("otherFolder");
		waitForTree();

		// cut myFolder and paste at otherFolder
		GTreeNode node = getChild(rootNode, "myFolder");
		setSelectionPaths(new TreePath[] { node.getTreePath() });
		waitForTree();

		DockingActionIf cutAction = getAction("Cut");
		DockingActionIf pasteAction = getAction("Paste");

		performAction(cutAction, getDomainFileActionContext(), true);
		GTreeNode otherNode = getChild(rootNode, "otherFolder");
		setSelectionPaths(new TreePath[] { otherNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		// otherFolder should have one child
		expandTreePath(otherNode.getTreePath());
		assertEquals(1, otherNode.getChildCount());
	}

	@Test
	public void testCutPasteFile2Folder() throws Exception {
		// cut/paste file -> folder
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		GTreeNode winNode = getChild(rootNode, "tms");
		setSelectionPaths(new TreePath[] { winNode.getTreePath() });

		DockingActionIf cutAction = getAction("Cut");
		DockingActionIf pasteAction = getAction("Paste");

		performAction(cutAction, getDomainFileActionContext(), true);
		GTreeNode myNode = getChild(rootNode, "myFolder");
		assertNotNull(myNode);
		setSelectionPaths(new TreePath[] { myNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		// myFolder should have 2 files
		expandTreePath(myNode.getTreePath());
		assertEquals(2, myNode.getChildCount());
		assertNull(getChild(rootNode, "tms"));
	}

	@Test
	public void testCopyPasteFile2Folder() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		GTreeNode winNode = getChild(rootNode, "tms");
		setSelectionPaths(new TreePath[] { winNode.getTreePath() });

		DockingActionIf copyAction = getAction("Copy");
		DockingActionIf pasteAction = getAction("Paste");

		performAction(copyAction, getDomainFileActionContext(), true);
		GTreeNode myNode = getChild(rootNode, "myFolder");
		assertNotNull(myNode);
		setSelectionPaths(new TreePath[] { myNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		// myFolder should have 2 files
		expandTreePath(myNode.getTreePath());
		assertEquals(2, myNode.getChildCount());
		assertNotNull(getChild(rootNode, "tms"));
	}

	@Test
	public void testCopyPasteFolder2Folder() throws Exception {

		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		rootFolder.createFolder("otherFolder");
		waitForSwing();
		GTreeNode otherNode = getChild(rootNode, "otherFolder");

		// copy myFolder to otherFolder
		DockingActionIf copyAction = getAction("Copy");
		DockingActionIf pasteAction = getAction("Paste");

		GTreeNode myNode = getChild(rootNode, "myFolder");
		setSelectionPaths(new TreePath[] { myNode.getTreePath() });

		performAction(copyAction, getDomainFileActionContext(), true);

		setSelectionPaths(new TreePath[] { otherNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		expandTreePath(otherNode.getTreePath());
		assertEquals(1, otherNode.getChildCount());
		assertNotNull(getChild(otherNode, "myFolder"));
		assertNotNull(getChild(rootNode, "myFolder"));
	}

	@Test
	public void testMultiSelectionCopyPaste() throws Exception {

		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		DomainFolder f2 = rootFolder.createFolder("otherFolder");
		createNotepadFile(f2);
		GTreeNode otherNode = getChild(rootNode, "otherFolder");

		DockingActionIf copyAction = getAction("Copy");
		DockingActionIf pasteAction = getAction("Paste");

		// copy myFolder, notepad, X07, and tms to otherFolder
		GTreeNode myNode = getChild(rootNode, "myFolder");
		GTreeNode npNode = getChild(rootNode, "notepad");
		GTreeNode xNode = getChild(rootNode, "X07");
		GTreeNode wNode = getChild(rootNode, "tms");

		setSelectionPaths(new TreePath[] { myNode.getTreePath(), npNode.getTreePath(),
			xNode.getTreePath(), wNode.getTreePath() });

		performAction(copyAction, getDomainFileActionContext(), true);

		setSelectionPaths(new TreePath[] { otherNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		expandTreePath(otherNode.getTreePath());
		assertEquals(5, otherNode.getChildCount());
		assertNotNull(getChild(otherNode, "notepad"));
		assertNotNull(getChild(otherNode, "myFolder"));
		assertNotNull(getChild(otherNode, "X07"));
		assertNotNull(otherNode.getChild("notepad.1"));
		assertNotNull(getChild(otherNode, "tms"));

		assertNotNull(getChild(rootNode, "notepad"));
		assertNotNull(getChild(rootNode, "myFolder"));
		assertNotNull(getChild(rootNode, "X07"));
		assertNotNull(getChild(rootNode, "tms"));
	}

	@Test
	public void testMultiSelectionCutPaste() throws Exception {

		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		DomainFolder f2 = rootFolder.createFolder("otherFolder");
		createNotepadFile(f2);
		GTreeNode otherNode = getChild(rootNode, "otherFolder");

		DockingActionIf cutAction = getAction("Cut");
		DockingActionIf pasteAction = getAction("Paste");

		// move myFolder, notepad, X07, and tms to otherFolder
		GTreeNode myNode = getChild(rootNode, "myFolder");
		GTreeNode npNode = getChild(rootNode, "notepad");
		GTreeNode xNode = getChild(rootNode, "X07");
		GTreeNode wNode = getChild(rootNode, "tms");

		setSelectionPaths(new TreePath[] { myNode.getTreePath(), npNode.getTreePath(),
			xNode.getTreePath(), wNode.getTreePath() });

		performAction(cutAction, getDomainFileActionContext(), true);

		setSelectionPaths(new TreePath[] { otherNode.getTreePath() });

		performAction(pasteAction, getDomainFileActionContext(), true);
		waitForTree();

		expandTreePath(otherNode.getTreePath());
		assertEquals(5, otherNode.getChildCount());
		assertNotNull(getChild(otherNode, "notepad"));
		assertNotNull(getChild(otherNode, "myFolder"));
		assertNotNull(getChild(otherNode, "X07"));
		assertNotNull(otherNode.getChild("notepad.1"));
		assertNotNull(getChild(otherNode, "tms"));

		assertNull(getChild(rootNode, "notepad"));
		assertNull(getChild(rootNode, "myFolder"));
		assertNull(getChild(rootNode, "X07"));
		assertNull(getChild(rootNode, "tms"));
	}

	@Test
	public void testDragMoveFolderAndChild2Folder() throws Exception {
		// Test drag/dropping a folder and its children (at the same time)
		// to make sure children aren't moved twice
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);
		rootFolder.createFolder("otherFolder");
		waitForSwing();

		GTreeNode selectedFolderNode = getChild(rootNode, "myFolder");
		GTreeNode selectedFile = getChild(selectedFolderNode, "notepad");
		GTreeNode destNode = getChild(rootNode, "otherFolder");

		doDrag(destNode, DnDConstants.ACTION_MOVE, selectedFolderNode, selectedFile);

		expandTreePath(destNode.getTreePath());
		assertEquals(1, destNode.getChildCount());
		GTreeNode movedFolderNode = getChild(destNode, "myFolder");
		assertNotNull(movedFolderNode);
		assertNotNull(getChild(movedFolderNode, "notepad"));
		assertNull(getChild(rootNode, "myFolder"));
	}

	@Test
	public void testDragMoveFolder2Folder() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		rootFolder.createFolder("otherFolder");
		waitForSwing();
		final GTreeNode otherNode = getChild(rootNode, "otherFolder");
		// drag myFolder to otherFolder
		final GTreeNode myNode = getChild(rootNode, "myFolder");

		doDrag(otherNode, DnDConstants.ACTION_MOVE, myNode);

		expandTreePath(otherNode.getTreePath());
		assertEquals(1, otherNode.getChildCount());
		assertNotNull(getChild(otherNode, "myFolder"));
		assertNull(getChild(rootNode, "myFolder"));
	}

	@Test
	public void testDragMoveFile2Folder() throws Exception {
		rootFolder.createFolder("myFolder");
		waitForSwing();

		GTreeNode npNode = getChild(rootNode, "notepad");
		GTreeNode myNode = getChild(rootNode, "myFolder");

		// drag notepad to myFolder
		doDrag(myNode, DnDConstants.ACTION_MOVE, npNode);

		expandTreePath(myNode.getTreePath());
		assertEquals(1, myNode.getChildCount());
		assertNotNull(getChild(myNode, "notepad"));
		assertNull(getChild(rootNode, "notepad"));

	}

	@Test
	public void testDragCopyFolder2Folder() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		rootFolder.createFolder("otherFolder");

		GTreeNode otherNode = getChild(rootNode, "otherFolder");

		// drag copy myFolder to otherFolder
		GTreeNode myNode = getChild(rootNode, "myFolder");
		setSelectionPaths(new TreePath[] { otherNode.getTreePath() });

		doDrag(otherNode, DnDConstants.ACTION_COPY, myNode);

		waitForTree();

		expandTreePath(otherNode.getTreePath());
		assertEquals(1, otherNode.getChildCount());
		assertNotNull(getChild(otherNode, "myFolder"));
		assertNotNull(getChild(rootNode, "myFolder"));
	}

	@Test
	public void testDragCopyFile2Folder() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		createNotepadFile(f);

		GTreeNode winNode = getChild(rootNode, "tms");
		GTreeNode myNode = getChild(rootNode, "myFolder");
		assertNotNull(myNode);
		setSelectionPaths(new TreePath[] { myNode.getTreePath() });

		doDrag(myNode, DnDConstants.ACTION_COPY, winNode);

		waitForTree();

		// myFolder should have 2 files
		expandTreePath(myNode.getTreePath());
		assertEquals(2, myNode.getChildCount());
		assertNotNull(getChild(rootNode, "tms"));

	}

	@Test
	public void testMoveFileInUse() throws Exception {
		GTreeNode npNode = getChild(rootNode, "notepad");

		DomainFile df = ((DomainFileNode) npNode).getDomainFile();
		setInUse(df);

		rootFolder.createFolder("myFolder");
		waitForSwing();
		GTreeNode myNode = getChild(rootNode, "myFolder");

		// drag notepad to myFolder
		doDrag(myNode, DnDConstants.ACTION_MOVE, npNode);
		waitForTree();

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Cannot Move File", d.getTitle());
		pressButtonByText(d.getComponent(), "OK");

		expandTreePath(myNode.getTreePath());
		assertEquals(0, myNode.getChildCount());
		assertNull(getChild(myNode, "notepad"));
		assertNotNull(getChild(rootNode, "notepad"));
	}

	@Test
	public void testDeleteFolder() throws Exception {
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");

		createNotepadFile(f);

		GTreeNode myNode = getChild(rootNode, "myFolder");
		expandTreePath(myNode.getTreePath());

		// delete "A"; all subfolders should be removed
		GTreeNode aNode = getChild(myNode, "A");
		expandTreePath(aNode.getTreePath());
		setSelectionPaths(new TreePath[] { aNode.getTreePath() });
		GTreeNode bNode = getChild(aNode, "B");

		// ensure that selection occurred
		assertNotNull(tree.getSelectionPath());

		pressDelete();

		confirmDelete();

		waitForTasks();

		assertNull(getChild(myNode, "A"));
		assertNull(bNode.getParent());
	}

	@Test
	public void testDeleteFile() throws Exception {

		selectRootChildren("notepad");

		pressDelete();

		confirmDelete();

		waitForTasks();

		assertNull(getChild(rootNode, "notepad"));
	}

	@Test
	public void testDeleteMultiSelection() throws Exception {
		selectRootChildren("notepad", "tms");

		pressDelete();

		confirmDelete();

		waitForTasks();

		assertNull(getChild(rootNode, "notepad"));
		assertNull(getChild(rootNode, "tms"));
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

	@Test
	public void testRenameFolderInUse() throws Exception {
		// folder contains a file that is in use
		DomainFolder f = rootFolder.createFolder("myFolder");
		f = f.createFolder("A");
		f = f.createFolder("B");
		f = f.createFolder("C");

		Program p = createDefaultProgram("new", ProgramBuilder._TOY, this);

		DomainFile df = f.createFile("notepad", p, TaskMonitor.DUMMY);
		waitForSwing();

		final GTreeNode myNode = rootNode.getChild("myFolder");
		((DomainFolderNode) myNode).getDomainFolder().createFile("notepad", p, TaskMonitor.DUMMY);
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

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
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

		BreadthFirstIterator it = new BreadthFirstIterator(rootNode);
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

	private void setSelectionPath(final TreePath path) throws Exception {
		tree.setSelectionPath(path);
		waitForTree();
	}

	private void pressDelete() {
		DockingActionIf deleteAction = getAction("Delete");
		performAction(deleteAction, getDomainFileActionContext(), false);
		waitForSwing();
	}

	private void selectRootChildren(String... names) {
		List<TreePath> paths = new ArrayList<>();
		for (String name : names) {
			GTreeNode child = getChild(rootNode, name);
			paths.add(child.getTreePath());
		}

		setSelectionPaths(paths);
	}

	private GTreeNode getChild(GTreeNode parent, String childName) {
		waitForTree();
		GTreeNode child = parent.getChild(childName);
		return child;
	}

	private void confirmDelete() {
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Confirm Delete", d.getTitle());
		pressButtonByText(d.getComponent(), "OK");
	}

	private void createNotepadFile(DomainFolder f) throws Exception {
		waitForSwing();
		ProgramDB p = createDefaultProgram("p1", ProgramBuilder._TOY, this);
		f.createFile("notepad", p, TaskMonitor.DUMMY);
		p.release(this);
		waitForSwing();
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

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private void expandTreePath(TreePath path) {
		runSwing(() -> tree.expandPath(path));
		waitForTree();
	}

	private void setSelectionPaths(TreePath[] paths) {
		runSwing(() -> tree.setSelectionPaths(paths));
		waitForTree();
	}

	private void setSelectionPaths(List<TreePath> paths) {
		runSwing(() -> tree.setSelectionPaths(paths));
		waitForTree();
	}

	private void doDrag(GTreeNode destinationNode, int dragAction, GTreeNode... dragNodes) {
		GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>(Arrays.asList(dragNodes));
		Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		executeOnSwingWithoutBlocking(
			() -> dragNDropHandler.drop(destinationNode, transferable, dragAction));
		waitForSwing();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

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

		return new FrontEndProjectTreeContext(null, null, paths, folderList, fileList, tree,
			true);
	}
}
