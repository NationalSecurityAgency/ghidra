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
package ghidra.app.plugin.core.programtree;

import static org.junit.Assert.*;

import java.awt.Component;

import javax.swing.JLabel;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import generic.theme.GIcon;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

/**
 * Tests for cut/copy/paste in the Program tree.
 */
public class ProgramTreePlugin2Test extends AbstractProgramTreePluginTest {

	private Listing listing;
	private DockingActionIf cutAction;
	private DockingActionIf copyAction;
	private DockingActionIf pasteAction;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		listing = program.getListing();

		actionMgr = plugin.getActionManager();
		actions = actionMgr.getActions();

		copyAction = getAction("Copy");
		pasteAction = getAction("Paste");
		cutAction = getAction("Cut");

		assertNotNull(copyAction);
		assertNotNull(pasteAction);
		assertNotNull(cutAction);

		setTreeView("Main Tree");
		expandNode(root);

	}

	@Override
	protected ProgramDB buildProgram() throws Exception {
		//Default Tree
		ProgramBuilder builder = new ProgramBuilder("TestProgram", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x2000);

		//Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "", ".data", "0x1001200", "0x10013ff");
		builder.createFragment("Main Tree", "", ".rsrc", "0x1001400", "0x10015ff");
		builder.createFragment("Main Tree", "", ".imports", "0x1001600", "0x10017ff");
		builder.createFragment("Main Tree", "", ".debug_data", "0x1001800", "0x10019ff");
		builder.createFragment("Main Tree", "DLLs", "ADVAPI32.DLL", "0x1001a00", "0x1001aff");
		builder.createFragment("Main Tree", "DLLs", "USER32.DLL", "0x1001b00", "0x1001bff");
		builder.createFragment("Main Tree", "Functions", "doStuff", "0x1001c00", "0x1001cff");
		builder.createFragment("Main Tree", "Functions", "ghidra", "0x1001d00", "0x1001dff");
		builder.createFragment("Main Tree", "Functions", "sscanf", "0x1001e00", "0x1001eff");
		builder.createFragment("Main Tree", "Not Real Blocks", "stuff", "0x1002000", "0x10020ff");
		builder.createFragment("Main Tree", "Subroutines", "01002a91", "0x1002a91", "0x1002aff");
		builder.createFragment("Main Tree", "Everything.C", "testc", "0x1002200", "0x10022ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "text", "0x1002400",
			"0x10024ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "rsrc", "0x1002500",
			"0x10025ff");
		builder.createFragment("Main Tree", "Strings.L", "testl", "0x1002300", "0x10023ff");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testCopyFragmentToFolder() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);

		setSelectionPath(node);
		assertTrue(copyAction.isEnabled());
		performTreeAction(copyAction);

		node = (ProgramNode) root.getChildAt(5);
		int origCount = node.getChildCount();
		setSelectionPath(node);
		assertTrue(pasteAction.isEnabled());

		performTreeAction(pasteAction);
		waitForProgram(program);

		expandNode(node);
		ProgramNode child = (ProgramNode) node.getChildAt(node.getChildCount() - 1);
		assertEquals(".text", child.getName());

		ProgramNode[] nodes = findNodes("DLLs");
		for (ProgramNode node2 : nodes) {
			assertNotNull(node2.getChild(".text"));
		}

		undo();
		node = (ProgramNode) root.getChildAt(5);
		assertEquals(origCount, node.getChildCount());
		redo();
		node = (ProgramNode) root.getChildAt(5);
		assertEquals(origCount + 1, node.getChildCount());

	}

	@Test
	public void testCopyPasteActionEnabled() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(0);
		setSelectionPath(node);
		assertTrue(copyAction.isEnabled());
		performTreeAction(copyAction);

		setSelectionPath(root);

		// fragment is already in root
		assertFalse(pasteAction.isEnabled());

		// cannot paste fragment to another fragment
		node = (ProgramNode) root.getChildAt(1);
		setSelectionPath(root);
		assertFalse(pasteAction.isEnabled());

		expandNode(root);

		// destination folder is a descendant of the copied folder
		node = (ProgramNode) root.getChildAt(9);
		setSelectionPath(node);
		assertTrue(copyAction.isEnabled());

		performTreeAction(copyAction);
		ProgramNode[] nodes = findNodes("C");
		setSelectionPath(nodes[0]);

		assertFalse(pasteAction.isEnabled());

		// fragment is already in the destination folder
		tx(program, () -> {
			ProgramFragment f = program.getListing().getFragment("Main Tree", "USER32.DLL");
			ProgramModule funcModule = program.getListing().getModule("Main Tree", "Functions");
			funcModule.add(f);
		});

		node = (ProgramNode) root.getChildAt(6);// Functions

		ProgramNode fnode = (ProgramNode) node.getChildAt(3);

		// select USER32.DLL
		setSelectionPath(fnode);
		performTreeAction(copyAction);
		// select DLLs
		node = (ProgramNode) root.getChildAt(6);
		setSelectionPath(node);
		assertFalse(pasteAction.isEnabled());

		//cannot copy root
		setSelectionPath(root);
		assertFalse(copyAction.isEnabled());
	}

	@Test
	public void testCopyFolderToFolder() throws Exception {

		ProgramNode cpNode = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode pasteNode = (ProgramNode) root.getChildAt(5);// DLLs
		int childCount = pasteNode.getChildCount();

		setSelectionPath(cpNode);

		performTreeAction(copyAction);
		setSelectionPath(pasteNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		assertEquals(childCount + 1, pasteNode.getChildCount());
		ProgramNode node = (ProgramNode) pasteNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());

		undo();
		pasteNode = (ProgramNode) root.getChildAt(5);// DLLs
		assertEquals(childCount, pasteNode.getChildCount());
		redo();
		pasteNode = (ProgramNode) root.getChildAt(5);// DLLs
		assertEquals(childCount + 1, pasteNode.getChildCount());
		node = (ProgramNode) pasteNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());
	}

	@Test
	public void testCopyMultiSelection() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode cnode1 = (ProgramNode) node.getChildAt(0);
		ProgramNode cnode2 = (ProgramNode) node.getChildAt(1);
		setSelectionPaths(cnode1, cnode2);
		assertTrue(copyAction.isEnabled());
		performTreeAction(copyAction);
		// create a new module and paste fragments there
		tx(program, () -> {
			root.getModule().createModule("Test");
		});

		ProgramNode destNode = (ProgramNode) root.getChildAt(root.getChildCount() - 1);

		setSelectionPath(destNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		visitNode(destNode);
		assertEquals(2, destNode.getChildCount());
	}

	@Test
	public void testCopyMultiSelection2() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode cnode1 = (ProgramNode) node.getChildAt(0);
		ProgramNode cnode2 = (ProgramNode) node.getChildAt(1);
		setSelectionPaths(cnode1, cnode2);
		assertTrue(copyAction.isEnabled());
		performTreeAction(copyAction);
		// create a new module and paste fragments there
		tx(program, () -> {
			ProgramModule m = root.getModule().createModule("Test");
			ProgramModule subr = listing.getModule("Main Tree", "Subroutines");
			subr.add(m);
		});

		// get node for "Test"
		ProgramNode destNode = (ProgramNode) root.getChildAt(root.getChildCount() - 1);

		setSelectionPath(destNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		expandNode(root);
		assertEquals(2, destNode.getChildCount());
		// make sure other occurrences show pasted fragments
		ProgramNode[] nodes = findNodes("Test");
		for (ProgramNode node2 : nodes) {
			assertEquals(2, node2.getChildCount());
			// verify the paste order
			assertEquals(cnode1.getName(), node2.getChildAt(0).toString());
			assertEquals(cnode2.getName(), node2.getChildAt(1).toString());
		}
		// verify that the root was not affected by the copy
		assertEquals(node, cnode1.getParent());
		assertEquals(node, cnode2.getParent());

		undo();
		destNode = (ProgramNode) root.getChildAt(root.getChildCount() - 1);
		assertEquals(0, destNode.getChildCount());
		redo();
		expandNode(root);
		destNode = (ProgramNode) root.getChildAt(root.getChildCount() - 1);
		assertEquals(2, destNode.getChildCount());
	}

	@Test
	public void testCopyMultiSelection3() throws Exception {

		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode cnode1 = (ProgramNode) node.getChildAt(0);
		ProgramNode cnode2 = (ProgramNode) node.getChildAt(1);
		setSelectionPaths(cnode1, cnode2);
		assertTrue(copyAction.isEnabled());
		performTreeAction(copyAction);

		// get node for DLLs
		ProgramNode destNode = (ProgramNode) root.getChildAt(5);
		int dllCount = destNode.getChildCount();

		setSelectionPath(destNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		expandNode(root);
		assertEquals(dllCount + 2, destNode.getChildCount());
		// make sure other occurrences show pasted fragments
		ProgramNode[] nodes = findNodes("DLLs");
		for (ProgramNode node2 : nodes) {
			assertEquals(dllCount + 2, node2.getChildCount());
			// verify the paste order
			assertEquals(cnode1.getName(), node2.getChildAt(dllCount).toString());
			assertEquals(cnode2.getName(), node2.getChildAt(dllCount + 1).toString());
		}
		// verify that the root was not affected by the copy
		assertEquals(node, cnode1.getParent());
		assertEquals(node, cnode2.getParent());

		undo();
		destNode = (ProgramNode) root.getChildAt(5);
		assertEquals(dllCount, destNode.getChildCount());
		redo();
		destNode = (ProgramNode) root.getChildAt(5);
		assertEquals(dllCount + 2, destNode.getChildCount());
	}

	@Test
	public void testCopyFolderInView() throws Exception {
		// copy a folder that is in the view to another folder
		// that is not in the view
		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		// set the view to Functions
		setSelectionPath(node);
		setViewPaths(node);
		performTreeAction(copyAction);
		ProgramNode subrNode = (ProgramNode) root.getChildAt(8);

		setSelectionPath(subrNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		// verify the view is not affected
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));

		undo();
		node = (ProgramNode) root.getChildAt(6);// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		redo();
		node = (ProgramNode) root.getChildAt(6);// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
	}

	@Test
	public void testCopyFolderNotInView() throws Exception {
		// copy a folder not in the view to a folder that is in the view
		// verify that the view updates to show the copied folder

		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		// set the view to Functions
		setViewPaths(node);
		AddressSetView origSet = node.getModule().getAddressSet();

		// select Subroutines (not in the view)
		ProgramNode subrNode = (ProgramNode) root.getChildAt(8);

		setSelectionPath(subrNode);

		performTreeAction(copyAction);
		setSelectionPath(node);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		undo();
		assertTrue(plugin.getView().hasSameAddresses(origSet));
		redo();
		node = (ProgramNode) root.getChildAt(6);// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
	}

	@Test
	public void testCopyFragmentInView() throws Exception {
		// copy a fragment that is in the view to a folder
		// that is not in the view
		ProgramNode node = (ProgramNode) root.getChildAt(6);// Functions
		// set the view to Functions
		setViewPaths(node);

		ProgramNode child = (ProgramNode) node.getChildAt(0);
		setSelectionPath(child);
		performTreeAction(copyAction);
		ProgramNode subrNode = (ProgramNode) root.getChildAt(8);

		setSelectionPath(subrNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		// verify the view is not affected
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		undo();
		node = (ProgramNode) root.getChildAt(6);// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		redo();
		node = (ProgramNode) root.getChildAt(6);// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
	}

	@Test
	public void testCutFragmentToFragment() throws Exception {
		ProgramNode node = (ProgramNode) root.getChildAt(8);// Subroutines
		int childCount = node.getChildCount();
		ProgramNode fnode = (ProgramNode) node.getChildAt(0);// 01002a91
		AddressSet fnodeSet = new AddressSet(fnode.getFragment());

		setSelectionPath(fnode);
		assertTrue(cutAction.isEnabled());
		performTreeAction(cutAction);

		ProgramNode funcNode = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode destNode = (ProgramNode) funcNode.getChildAt(0);// doStuff fragment

		// now select the doStuff fragment as the destination node
		setSelectionPath(destNode);
		performTreeAction(pasteAction);
		waitForProgram(program);

		assertTrue(destNode.getFragment().contains(fnodeSet));
		assertNull(listing.getFragment("Main Tree", "01002a91"));
		assertEquals(childCount - 1, node.getChildCount());
		assertEquals(0, findNodes("01002a91").length);

		undo();
		node = (ProgramNode) root.getChildAt(8);// Subroutines
		funcNode = (ProgramNode) root.getChildAt(6);// Functions
		destNode = (ProgramNode) funcNode.getChildAt(0);// doStuff fragment
		assertFalse(destNode.getFragment().contains(fnodeSet));
		assertNotNull(listing.getFragment("Main Tree", "01002a91"));

		expandNode(node);

		assertEquals(childCount, node.getChildCount());
		assertTrue(findNodes("01002a91").length > 0);

		redo();
		node = (ProgramNode) root.getChildAt(8);// Subroutines
		funcNode = (ProgramNode) root.getChildAt(6);// Functions
		destNode = (ProgramNode) funcNode.getChildAt(0);// doStuff fragment
		assertTrue(destNode.getFragment().contains(fnodeSet));
		assertNull(listing.getFragment("Main Tree", "01002a91"));
		assertEquals(childCount - 1, node.getChildCount());
		assertEquals(0, findNodes("01002a91").length);
	}

	@Test
	public void testCutFragmentToFragment2() throws Exception {
		// pasted fragment should appear in more than one folder
		tx(program, () -> {
			ProgramFragment f = listing.getFragment("Main Tree", "01002a91");
			ProgramModule m = listing.getModule("Main Tree", "DLLs");
			m.add(f);
		});

		ProgramNode node = (ProgramNode) root.getChildAt(8);// Subroutines
		int childCount = node.getChildCount();
		ProgramNode fnode = (ProgramNode) node.getChildAt(0);// 01002a91
		AddressSet fnodeSet = new AddressSet(fnode.getFragment());

		setSelectionPath(fnode);
		assertTrue(cutAction.isEnabled());
		performTreeAction(cutAction);

		ProgramNode funcNode = (ProgramNode) root.getChildAt(6);// Functions
		ProgramNode destNode = (ProgramNode) funcNode.getChildAt(0);// ghidra fragment

		// now select the ghidra fragment as the destination node
		setSelectionPath(destNode);
		performTreeAction(pasteAction);
		waitForProgram(program);

		assertTrue(destNode.getFragment().contains(fnodeSet));
		assertNull(listing.getFragment("Main Tree", "01002a91"));
		assertEquals(childCount - 1, node.getChildCount());
		assertEquals(0, findNodes("01002a91").length);

		undo();
		node = (ProgramNode) root.getChildAt(8);// Subroutines
		funcNode = (ProgramNode) root.getChildAt(6);// Functions
		destNode = (ProgramNode) funcNode.getChildAt(0);// doStuff fragment

		assertFalse(destNode.getFragment().contains(fnodeSet));
		assertNotNull(listing.getFragment("Main Tree", "01002a91"));

		expandNode(node);

		assertEquals(childCount, node.getChildCount());
		assertTrue(findNodes("01002a91").length > 0);

		redo();
		node = (ProgramNode) root.getChildAt(8);// Subroutines
		funcNode = (ProgramNode) root.getChildAt(6);// Functions
		destNode = (ProgramNode) funcNode.getChildAt(0);// doStuff fragment
		assertTrue(destNode.getFragment().contains(fnodeSet));
		assertNull(listing.getFragment("Main Tree", "01002a91"));
		assertEquals(childCount - 1, node.getChildCount());
		assertEquals(0, findNodes("01002a91").length);
	}

	@Test
	public void testCutFragmentToFolder() throws Exception {
		ProgramNode node = (ProgramNode) root.getChildAt(0);

		setSelectionPath(node);
		assertTrue(cutAction.isEnabled());
		performTreeAction(cutAction);

		node = (ProgramNode) root.getChildAt(5);//DLLs
		int origCount = node.getChildCount();
		setSelectionPath(node);
		assertTrue(pasteAction.isEnabled());

		performTreeAction(pasteAction);
		waitForProgram(program);

		expandNode(node);
		ProgramNode child = (ProgramNode) node.getChildAt(node.getChildCount() - 1);
		assertEquals(".text", child.getName());
		assertEquals(".data", root.getChildAt(0).toString());

		undo();
		node = (ProgramNode) root.getChildAt(5);
		assertEquals(origCount, node.getChildCount());
		assertEquals(".text", root.getChildAt(0).toString());
		redo();
		node = (ProgramNode) root.getChildAt(4);
		assertEquals(origCount + 1, node.getChildCount());

		assertEquals(".data", root.getChildAt(0).toString());
	}

	@Test
	public void testCutFolderToFolder() throws Exception {
		ProgramNode cNode = (ProgramNode) root.getChildAt(6);// Functions

		ProgramNode destNode = (ProgramNode) root.getChildAt(5);// DLLs
		int childCount = destNode.getChildCount();

		setSelectionPath(cNode);
		// cut Functions
		performTreeAction(cutAction);
		setSelectionPath(destNode);// paste at DLLs
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		assertEquals(childCount + 1, destNode.getChildCount());
		ProgramNode node = (ProgramNode) destNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());
		assertEquals("Not Real Blocks", root.getChildAt(6).toString());

		ProgramNode[] nodes = findNodes("Functions");
		for (ProgramNode node2 : nodes) {
			assertTrue(node2.getParent() != root);
		}
		undo();
		destNode = (ProgramNode) root.getChildAt(5);// DLLs
		assertEquals(childCount, destNode.getChildCount());

		redo();
		destNode = (ProgramNode) root.getChildAt(5);// DLLs
		assertEquals(childCount + 1, destNode.getChildCount());
		node = (ProgramNode) destNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());
		nodes = findNodes("Functions");
		for (ProgramNode node2 : nodes) {
			assertTrue(node2.getParent() != root);
		}
	}

	@Test
	public void testCutFolderExpanded() throws Exception {
		// cut a folder that has descendants expanded,
		// expand the destination and paste.
		// The pasted folder should retain its expansion state.
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode lnode = stringsNode.getChild("L");
		expandPath(lnode.getTreePath());

		// Strings, L are expanded

		// select Strings
		setSelectionPath(stringsNode);

		// cut Strings
		performTreeAction(cutAction);
		// paste at Functions
		ProgramNode funcNode = root.getChild("Functions");
		setSelectionPath(funcNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		// Strings, L should be expanded

		stringsNode = funcNode.getChild("Strings");
		assertTrue(tree.isExpanded(stringsNode.getTreePath()));
		lnode = stringsNode.getChild("L");
		assertTrue(tree.isExpanded(lnode.getTreePath()));
	}

	@Test
	public void testCutFolderExpanded2() throws Exception {
		// cut a folder that has descendants expanded,
		// collapse the destination folder and paste.
		// The destination folder should remain collapsed.
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode lnode = stringsNode.getChild("L");
		expandPath(lnode.getTreePath());

		// Strings, L are expanded

		// select Strings
		setSelectionPath(stringsNode);

		// cut Strings
		performTreeAction(cutAction);
		// paste at Functions
		ProgramNode funcNode = root.getChild("Functions");
		collapsePath(funcNode.getTreePath());
		setSelectionPath(funcNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);

		// Functions should remain collapsed
		assertTrue(tree.isCollapsed(funcNode.getTreePath()));
		stringsNode = funcNode.getChild("Strings");
		assertTrue(tree.isCollapsed(stringsNode.getTreePath()));
	}

	@Test
	public void testCutFolderCollapsed() throws Exception {
		// cut a folder that is collapsed;
		// expand the destination and paste.
		// The pasted folder should be collapsed.
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		collapsePath(stringsNode.getTreePath());

		// select Strings
		setSelectionPath(stringsNode);

		// cut Strings
		performTreeAction(cutAction);
		// paste at Functions
		ProgramNode funcNode = root.getChild("Functions");
		expandPath(funcNode.getTreePath());
		setSelectionPath(funcNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);

		stringsNode = funcNode.getChild("Strings");
		assertTrue(tree.isCollapsed(stringsNode.getTreePath()));
		assertNull(root.getChild("Strings"));
	}

	@Test
	public void testCutFolderCollapsed2() throws Exception {
		// cut folder is collapsed,
		// destination folder is collapsed.
		// Paste the folder; the destination folder
		// remains collapsed
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		collapsePath(stringsNode.getTreePath());

		// select Strings
		setSelectionPath(stringsNode);

		// cut Strings
		performTreeAction(cutAction);
		// paste at Functions
		ProgramNode funcNode = root.getChild("Functions");
		visitNode(funcNode);
		collapsePath(funcNode.getTreePath());
		setSelectionPath(funcNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);

		assertTrue(tree.isCollapsed(funcNode.getTreePath()));
	}

	@Test
	public void testCutMultiSelection() throws Exception {
		// select two fragments in a fold and cut;
		// paste at a folder that has no fragments;
		// fragments should be pasted in the order that they were selected;
		// fragments should be placed at the end of the list

		ProgramNode evNode = root.getChild("Everything");
		visitNode(evNode);
		ProgramNode fragNode = evNode.getChild("Fragments");
		visitNode(fragNode);

		// select .rsrc and .text
		ProgramNode rsrcNode = fragNode.getChild("rsrc");
		ProgramNode textNode = fragNode.getChild("text");

		setSelectionPaths(new TreePath[] { rsrcNode.getTreePath(), textNode.getTreePath() });

		// cut Strings
		performTreeAction(cutAction);

		// select Strings (has no fragments)
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		setSelectionPath(stringsNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);

		assertEquals(3, stringsNode.getChildCount());
		assertEquals("rsrc", stringsNode.getChildAt(1).toString());
		assertEquals("text", stringsNode.getChildAt(2).toString());

		assertNull(fragNode.getChild("rsrc"));
		assertNull(fragNode.getChild("text"));

		// verify all occurrences of Strings were updated
		expandNode(root);
		ProgramNode[] nodes = findNodes("Strings");
		for (ProgramNode node : nodes) {
			assertEquals(3, node.getChildCount());
		}

		undo();
		evNode = root.getChild("Everything");
		fragNode = evNode.getChild("Fragments");
		stringsNode = root.getChild("Strings");

		expandNode(fragNode);

		assertNotNull(fragNode.getChild("rsrc"));
		assertNotNull(fragNode.getChild("text"));
		assertEquals(1, stringsNode.getChildCount());

		redo();

		evNode = root.getChild("Everything");
		fragNode = evNode.getChild("Fragments");
		stringsNode = root.getChild("Strings");

		assertEquals(3, stringsNode.getChildCount());
		assertEquals("rsrc", stringsNode.getChildAt(1).toString());
		assertEquals("text", stringsNode.getChildAt(2).toString());

		assertNull(fragNode.getChild("rsrc"));
		assertNull(fragNode.getChild("text"));
	}

	@Test
	public void testMergeFragments() throws Exception {
		// select 2 fragments; note the address ranges, and cut.
		// select a destination fragment, choose paste.
		// verify that the cut fragments are removed from the program.
		// verify the address set of the destination fragment

		ProgramNode evNode = root.getChild("Everything");
		visitNode(evNode);
		ProgramNode fragNode = evNode.getChild("Fragments");
		expandPath(fragNode.getTreePath());
		ProgramNode[] cutNodes = new ProgramNode[2];
		AddressSet set = new AddressSet();
		for (int i = 0; i < cutNodes.length; i++) {
			cutNodes[i] = (ProgramNode) fragNode.getChildAt(i);
			set.add(cutNodes[i].getFragment());
			addSelectionPath(cutNodes[i].getTreePath());
		}

		performTreeAction(cutAction);

		// select a destination fragment
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode cNode = stringsNode.getChild("L");
		visitNode(cNode);
		ProgramNode fnode = cNode.getChild("testl");
		setSelectionPath(fnode);

		performTreeAction(pasteAction);

		for (ProgramNode cutNode : cutNodes) {
			assertNull(listing.getFragment("Main Tree", cutNode.getName()));
			assertEquals(0, findNodes(cutNode.getName()).length);
		}

		// note: >10 events causes the tree to get reloaded...
		root = (ProgramNode) tree.getModel().getRoot();
		stringsNode = root.getChild("Strings");
		cNode = stringsNode.getChild("L");
		fnode = cNode.getChild("testl");
		assertTrue(fnode.getFragment().contains(set));

		undo();
		expandNode(root);
		for (ProgramNode cutNode : cutNodes) {
			assertNotNull(listing.getFragment("Main Tree", cutNode.getName()));
			assertTrue(findNodes(cutNode.getName()).length > 0);
		}

		redo();
		expandNode(root);
		for (ProgramNode cutNode : cutNodes) {
			assertNull(listing.getFragment("Main Tree", cutNode.getName()));
			assertEquals(0, findNodes(cutNode.getName()).length);
		}
		stringsNode = root.getChild("Strings");
		cNode = stringsNode.getChild("L");
		fnode = cNode.getChild("testl");
		assertTrue(fnode.getFragment().contains(set));
	}

	@Test
	public void testCutFolderToFragment() throws Exception {
		// select a folder that has fragments and subfolders that have
		// fragments, and cut.
		// select a fragment not in the hierarchy of the cut folder
		// and paste.
		// verify that the destination fragment contains all code units
		// from the cut folder's descendants;
		// verify that the cut folder and all of its descendants are
		// removed from the program.

		AddressSet set = new AddressSet();

		// first create a folder and add fragments and folders to it
		tx(program, () -> {
			ProgramModule m = root.getModule().createModule("Test");
			m.add(listing.getFragment("Main Tree", ".text"));
			m.add(listing.getFragment("Main Tree", ".debug_data"));
			m.add(listing.getModule("Main Tree", "Subroutines"));
			m.add(listing.getModule("Main Tree", "Functions"));
			set.add(m.getAddressSet());
		});

		expandNode(root);

		ProgramNode testNode = root.getChild("Test");
		setSelectionPath(testNode);

		performTreeAction(cutAction);

		// paste at 010074d4
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode cNode = stringsNode.getChild("L");
		visitNode(cNode);
		ProgramNode fnode = cNode.getChild("testl");
		setSelectionPath(fnode);

		performTreeAction(pasteAction);
		waitForProgram(program);

		root = (ProgramNode) tree.getModel().getRoot();
		expandNode(root);
		stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		cNode = stringsNode.getChild("L");
		visitNode(cNode);
		fnode = cNode.getChild("testl");

		assertTrue(fnode.getFragment().contains(set));
		assertNull(listing.getModule("Main Tree", "Test"));
		assertNull(listing.getModule("Main Tree", "Subroutines"));
		assertNull(listing.getModule("Main Tree", "Functions"));
		assertNull(listing.getFragment("Main Tree", ".text"));
		assertNull(listing.getFragment("Main Tree", ".debug_data"));
		assertEquals(0, findNodes("Test").length);
		assertEquals(0, findNodes("Subroutines").length);
		assertEquals(0, findNodes("Functions").length);
		assertEquals(0, findNodes(".text").length);
		assertEquals(0, findNodes(".debug_data").length);

		undo();
		stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		cNode = stringsNode.getChild("L");
		visitNode(cNode);
		fnode = cNode.getChild("testl");

		assertFalse(fnode.getFragment().contains(set));
		expandNode(root);
		testNode = root.getChild("Test");
		assertNotNull(testNode);
		assertNotNull(testNode.getChild("Subroutines"));
		assertNotNull(testNode.getChild("Functions"));
		assertNotNull(testNode.getChild(".text"));
		assertNotNull(testNode.getChild(".debug_data"));

		redo();
		stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		cNode = stringsNode.getChild("L");
		visitNode(cNode);
		fnode = cNode.getChild("testl");
		assertTrue(fnode.getFragment().contains(set));
		assertNull(listing.getModule("Main Tree", "Test"));
		assertNull(listing.getModule("Main Tree", "Subroutines"));
		assertNull(listing.getModule("Main Tree", "Functions"));
		assertNull(listing.getFragment("Main Tree", ".text"));
		assertNull(listing.getFragment("Main Tree", ".debug_data"));
		assertEquals(0, findNodes("Test").length);
		assertEquals(0, findNodes("Subroutines").length);
		assertEquals(0, findNodes("Functions").length);
		assertEquals(0, findNodes(".text").length);
		assertEquals(0, findNodes(".debug_data").length);
	}

	@Test
	public void testCutFragmentInView() throws Exception {

		// copy a folder that is in the view to another folder
		// that is not in the view
		ProgramNode node = root.getChild("DLLs");

		// set the view to DLLs
		setSelectionPath(node);
		setViewPaths(new TreePath[] { node.getTreePath() });
		performTreeAction(copyAction);
		ProgramNode everythingNode = root.getChild("Everything");

		setSelectionPath(everythingNode);
		assertTrue(pasteAction.isEnabled());
		performTreeAction(pasteAction);
		waitForProgram(program);

		// cut a fragment in the view and paste onto a collapsed folder
		// not in the view
		// the first occurrence of the folder should indicate that one of
		// its descendants is in the view

		ProgramNode dataNode = root.getChild(".data");
		setSelectionPath(dataNode);
		setViewPaths(new TreePath[] { dataNode.getTreePath() });
		performTreeAction(cutAction);

		// select DLLs in Everything
		ProgramNode evNode = root.getChild("Everything");
		visitNode(evNode);
		ProgramNode dllsNode = evNode.getChild("DLLs");
		visitNode(dllsNode);
		setSelectionPath(dllsNode);

		performTreeAction(pasteAction);

		// first occurrence of DLLs should have icon for descendant in view
		ProgramNode[] nodes = findNodes("DLLs");
		int row = getRowForPath(nodes[0].getTreePath());

		Component comp = getCellRendererComponentForNonLeaf(nodes[0], row);
		assertEquals(new GIcon(DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER_WITH_DESC),
			((JLabel) comp).getIcon());

		visitNode(nodes[0]);
		dataNode = nodes[0].getChild(".data");
		assertTrue(plugin.getView().hasSameAddresses(dataNode.getFragment()));
	}

	@Test
	public void testCutFragmentInView2() throws Exception {
		// cut a fragment in the view and paste onto an expanded folder
		// not in the view.
		// The pasted fragment's code units should still show up in the view
		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		AddressSet set = new AddressSet();
		set.add(dataNode.getFragment());
		set.add(debugNode.getFragment());
		setViewPaths(new TreePath[] { dataNode.getTreePath(), debugNode.getTreePath() });
		assertTrue(plugin.getView().hasSameAddresses(set));

		setSelectionPath(debugNode);
		performTreeAction(cutAction);

		// paste to an expanded folder not in the view
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		setSelectionPath(subrNode);
		performTreeAction(pasteAction);

		assertTrue(plugin.getView().hasSameAddresses(set));
	}

	@Test
	public void testCutFrag2FragNotInView() throws Exception {
		// 	cut a fragment that is in the view and paste onto a fragment
		// that is not in the view.
		// The pasted fragment's code units should not be in the view
		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		setViewPaths(dataNode, debugNode);

		setSelectionPath(debugNode);
		performTreeAction(cutAction);
		// paste onto another fragment that is not in the view
		ProgramNode funcNode = root.getChild("Functions");
		visitNode(funcNode);
		ProgramNode sscanfNode = funcNode.getChild("sscanf");

		setSelectionPath(sscanfNode);
		performTreeAction(pasteAction);

		assertTrue(plugin.getView().hasSameAddresses(dataNode.getFragment()));
	}

	@Test
	public void testCutFrag2FragInView() throws Exception {
		// cut a fragment that is not in the view and paste it onto a
		// fragment that is in the view.
		// The pasted fragment's code units should show up in the view

		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		setViewPaths(dataNode, debugNode);

		ProgramNode subrNode = root.getChild("Subroutines");
		visitNode(subrNode);
		ProgramNode node = (ProgramNode) subrNode.getFirstChild();
		AddressSet set = new AddressSet();
		set.add(node.getFragment());

		// cut first fragment in Subroutines
		setSelectionPath(node);
		performTreeAction(cutAction);

		// paste at the debug node
		setSelectionPath(debugNode);
		performTreeAction(pasteAction);

		assertTrue(plugin.getView().contains(set));
	}

	private DockingActionIf getAction(String name) {
		for (DockingActionIf action : actions) {
			if (action.getName().startsWith(name)) {
				return action;
			}
		}
		Assert.fail("Could not find action: " + name);
		return null;// cannot get here
	}

}
