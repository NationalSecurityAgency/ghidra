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
import java.awt.dnd.DnDConstants;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JLabel;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.util.SelectionTransferData;
import ghidra.app.util.SelectionTransferable;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.exception.NotFoundException;
import resources.ResourceManager;

/**
 * Tests for drag/drop/reorder for copy and move in the program tree.
 */
public class ProgramTreePlugin3Test extends AbstractProgramTreePluginTest {

	private Listing listing;

	private DockingActionIf cutAction;
	private DockingActionIf copyAction;
	private DockingActionIf pasteAction;
	private DnDMoveManager dndManager;

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		listing = program.getListing();

		copyAction = getAction("Copy");
		pasteAction = getAction("Paste");
		cutAction = getAction("Cut");

		assertNotNull(copyAction);
		assertNotNull(pasteAction);
		assertNotNull(cutAction);

		setTreeView("Main Tree");
		dndManager = tree.getDnDMoveManager();
		expandNode(root);
	}

	@Override
	protected ProgramDB buildProgram() throws Exception {
		//Default Tree
		ProgramBuilder builder = new ProgramBuilder("TestProgram", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x1001000", 0x4000);

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
		builder.createFragment("Main Tree", "Subroutines", "01004a15", "0x1004a15", "0x1004aff");
		builder.createFragment("Main Tree", "Subroutines", "010030d8", "0x10030d8", "0x10030ff");
		builder.createFragment("Main Tree", "Everything.C", "testc", "0x1002200", "0x10022ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "text", "0x1002400",
			"0x10024ff");
		builder.createFragment("Main Tree", "Everything.Fragments", "rsrc", "0x1002500",
			"0x10025ff");
		builder.createFragment("Main Tree", "Strings.CC", "testcc", "0x1002300", "0x100230f");
		builder.createFragment("Main Tree", "Strings.G", "testg", "0x1002310", "0x100231f");
		builder.createFragment("Main Tree", "Strings.S", "tests", "0x1002320", "0x100232f");
		builder.createFragment("Main Tree", "Strings.L", "testl", "0x1002330", "0x100233f");

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		waitForPostedSwingRunnables();
		env.release(program);
		env.dispose();
	}

	// tests for drag/drop (move vs. copy)
	@Test
	public void testDdDFrag2FragNotInView() throws Exception {
		// drag a fragment not in the view onto another fragment not in the
		// view.
		// verify that code units are merged
		// verify that the merged fragment are removed from the program
		// verify that the view is not affected

		// put .text in the view
		ProgramNode textNode = root.getChild(".text");
		setViewPaths(new TreePath[] { textNode.getTreePath() });
		AddressSet set = plugin.getView();

		ProgramNode subrNode = root.getChild("Subroutines");
		visitNode(subrNode);
		ProgramNode node = subrNode.getChild("01004a15");
		setSelectionPath(node.getTreePath());

		ProgramNode funcNode = root.getChild("Functions");
		visitNode(funcNode);
		ProgramNode sscanfNode = funcNode.getChild("sscanf");
		AddressSet fragSet = new AddressSet(sscanfNode.getFragment());

		dragNodes_Move(node, Arrays.asList(sscanfNode));

		expandNode(root);

		assertNull(listing.getFragment("Main Tree", "sscanf"));
		assertTrue(plugin.getView().hasSameAddresses(set));
		assertTrue(node.getFragment().contains(fragSet));
		assertEquals(0, findNodes("sscanf").length);

		undo();
		expandNode(root);
		assertTrue(plugin.getView().hasSameAddresses(set));
		assertTrue(findNodes("sscanf").length > 0);

		redo();
		expandNode(root);

		assertNull(listing.getFragment("Main Tree", "sscanf"));
		assertTrue(plugin.getView().hasSameAddresses(set));

		subrNode = root.getChild("Subroutines");
		visitNode(subrNode);
		ProgramNode n = subrNode.getChild("01004a15");
		assertTrue(n.getFragment().contains(fragSet));
		assertEquals(0, findNodes("sscanf").length);

	}

	private void dragNodes_Move(ProgramNode node, List<ProgramNode> list) throws Exception {
		dragNodes(node, list, DnDConstants.ACTION_MOVE);
	}

	private void dragNodes_Copy(ProgramNode node, List<ProgramNode> list) throws Exception {
		dragNodes(node, list, DnDConstants.ACTION_COPY);
	}

	private void dragNodes(ProgramNode node, List<ProgramNode> list, int dropAction)
			throws Exception {
		AtomicReference<Exception> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				tree.processDropRequest(node, list, TreeTransferable.localTreeNodeFlavor,
					dropAction);
			}
			catch (NotFoundException | CircularDependencyException | DuplicateGroupException e) {
				ref.set(e);
			}
		});

		Exception exception = ref.get();
		if (exception != null) {
			throw exception;
		}

		program.flushEvents();
	}

	private void dropSelectionOnTree(ProgramNode node, SelectionTransferData data)
			throws Exception {
		AtomicReference<Exception> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				tree.processDropRequest(node, data,
					SelectionTransferable.localProgramSelectionFlavor, DnDConstants.ACTION_MOVE);
			}
			catch (NotFoundException | CircularDependencyException | DuplicateGroupException e) {
				ref.set(e);
			}
		});

		Exception exception = ref.get();
		if (exception != null) {
			throw exception;
		}

		program.flushEvents();
	}

	private void moveNode(ProgramNode to, ProgramNode toMove) throws Exception {

		AtomicReference<Exception> ref = new AtomicReference<>();
		runSwing(() -> {
			try {
				dndManager.add(to, new ProgramNode[] { toMove }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (NotFoundException | CircularDependencyException | DuplicateGroupException e) {
				ref.set(e);
			}
		});

		Exception exception = ref.get();
		if (exception != null) {
			throw exception;
		}

		program.flushEvents();
	}

	@Test
	public void testDnDFrag2FragInView() throws Exception {
		// drag a fragment in the view onto another fragment not in the view
		// verify that the dragged fragment is removed from the program
		// verify that the view shows the code units from the dragged fragment

		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		setViewPaths(new TreePath[] { dataNode.getTreePath(), debugNode.getTreePath() });
		AddressSet set = new AddressSet();
		set.add(dataNode.getFragment());
		set.add(debugNode.getFragment());

		ProgramNode subrNode = root.getChild("Subroutines");
		visitNode(subrNode);
		ProgramNode node = subrNode.getChild("01004a15");
		// drop target is 01004a15
		setSelectionPath(node.getTreePath());

		AddressSet fragSet = new AddressSet(debugNode.getFragment());
		ArrayList<ProgramNode> list = new ArrayList<ProgramNode>();
		list.add(debugNode);

		//drag .debug_data to 01004a15
		dragNodes_Move(node, list);

		expandNode(root);
		assertNull(listing.getFragment("Main Tree", ".debug_data"));
		assertTrue(!plugin.getView().contains(fragSet));

		assertEquals(0, findNodes(".debug_data").length);

		undo();
		expandNode(root);
		assertTrue(plugin.getView().hasSameAddresses(set));
		assertTrue(findNodes(".debug_data").length > 0);

		redo();
		expandNode(root);
		assertNull(listing.getFragment("Main Tree", ".debug_data"));
		assertTrue(!plugin.getView().contains(fragSet));

		assertEquals(0, findNodes(".debug_data").length);
	}

	@Test
	public void testDndFrag2Folder() throws Exception {
		// drag a fragment onto a folder that does not contain the fragment
		// verify that the fragment's parent is updated
		// verify that a drop is not allowed if the folder already contains
		// the fragment.

		ProgramNode dataNode = root.getChild(".data");

		ProgramNode subrNode = root.getChild("Subroutines");
		visitNode(subrNode);
		setSelectionPath(subrNode.getTreePath());

		dragNodes_Move(subrNode, Arrays.asList(dataNode));

		ProgramNode[] nodes = findNodes(".data");
		for (ProgramNode element : nodes) {
			assertTrue(element.getParent() != root);
		}
		boolean found = false;
		for (ProgramNode element : nodes) {
			if (element.getParent() == subrNode) {
				found = true;
				break;
			}
		}
		if (!found) {
			Assert.fail("Did not find new parent of .data");
		}
	}

	@Test
	public void testDnDFolder2Folder() throws Exception {
		// drag a folder onto another folder that does not contain the folder
		// verify that the folder's parent is updated
		// verify that the old parent does not contain the dragged folder

		ProgramNode funcNode = root.getChild("Functions");
		ProgramNode extNode = root.getChild("Not Real Blocks");

		// drag functions to external references
		setSelectionPath(extNode.getTreePath());

		dragNodes_Move(extNode, Arrays.asList(funcNode));

		ProgramNode[] nodes = findNodes("Functions");
		for (ProgramNode element : nodes) {
			assertTrue(element.getParent() != root);
		}
		boolean found = false;
		for (ProgramNode element : nodes) {
			if (element.getParent() == extNode) {
				found = true;
				break;
			}
		}
		if (!found) {
			Assert.fail("Did not find new parent of Functions");
		}
	}

	@Test
	public void testDnDFolder2Fragment() throws Exception {
		// drag a folder that has fragments and subfolders onto a fragment
		// verify that all code units from the dragged folder are moved
		// to the destination fragment
		// verify that the dragged folder and descendants are removed
		// from the program

		AddressSet set = new AddressSet();
		// first create a folder and add fragments and folders to it
		int transactionID = program.startTransaction("test");
		ProgramModule m = root.getModule().createModule("Test");
		m.add(listing.getFragment("Main Tree", ".text"));
		m.add(listing.getFragment("Main Tree", ".debug_data"));
		m.add(listing.getModule("Main Tree", "Subroutines"));
		m.add(listing.getModule("Main Tree", "Functions"));
		program.endTransaction(transactionID, true);
		set.add(m.getAddressSet());
		program.flushEvents();

		expandNode(root);

		ProgramNode testNode = root.getChild("Test");

		setSelectionPath(testNode.getTreePath());
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode cNode = stringsNode.getChild("L");
		visitNode(cNode);
		ProgramNode fnode = cNode.getChild("testl");
		//
		// drag Test to testl
		ProgramNode n = testNode;
		ProgramNode tgtNode = fnode;
		dragNodes_Move(tgtNode, Arrays.asList(n));

		waitForSwing();

		root = (ProgramNode) tree.getModel().getRoot();
		// reacquire nodes
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

		assertTrue(!fnode.getFragment().contains(set));
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
	public void testDnDFragInView2FolderNotInView() throws Exception {
		// drag a fragment in the view to a collapsed folder not in the view
		// verify that the collapsed folder indicates a descendant in the view
		// verify that the view contains the moved fragment

		//create scenario
		copyFolderOrFragment("DLLs", "Everything");

		ProgramNode dataNode = root.getChild(".data");
		setSelectionPath(dataNode.getTreePath());
		setViewPaths(new TreePath[] { dataNode.getTreePath() });

		// drag .data to DLLs

		// select DLLs in Everything
		ProgramNode evNode = root.getChild("Everything");
		visitNode(evNode);
		ProgramNode dllsNode = evNode.getChild("DLLs");
		visitNode(dllsNode);
		setSelectionPath(dllsNode.getTreePath());

		ProgramNode dragNode = dataNode;
		dragNodes_Move(dllsNode, Arrays.asList(dragNode));

		// first occurrence of DLLs should have icon for descendant in view
		ProgramNode[] nodes = findNodes("DLLs");
		int row = getRowForPath(nodes[0].getTreePath());

		Component comp = getCellRendererComponentForNonLeaf(nodes[0], row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_CLOSED_FOLDER_WITH_DESC),
			((JLabel) comp).getIcon());

		visitNode(nodes[0]);
		dataNode = nodes[0].getChild(".data");
		assertTrue(plugin.getView().hasSameAddresses(dataNode.getFragment()));

	}

	@Test
	public void testDnDFragInView2FolderInView() throws Exception {
		// drag a fragment that is in the view to an expanded folder that
		// is not in the view
		// verify that the fragment has the "in view" icon
		// verify that the view contains the moved fragment

		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		AddressSet set = new AddressSet(debugNode.getFragment());

		setViewPaths(new TreePath[] { dataNode.getTreePath(), debugNode.getTreePath() });

		ProgramNode subrNode = root.getChild("Subroutines");
		visitNode(subrNode);

		// drag .debug_data to Subroutines
		dragNodes_Move(subrNode, Arrays.asList(debugNode));

		assertTrue(plugin.getView().contains(set));
		expandNode(subrNode);
		ProgramNode n = subrNode.getChild(".debug_data");

		int row = getRowForPath(n.getTreePath());

		waitForSwing();

		Component comp = getCellRendererComponentForLeaf(n, row);
		assertEquals(ResourceManager.loadImage(DnDTreeCellRenderer.VIEWED_FRAGMENT),
			((JLabel) comp).getIcon());
	}

	@Test
	public void testDnDCodeUnits2FragNotInView() throws Exception {
		// drag code units to another fragment
		// verify that the destination fragment contains the dragged
		// code units
		ProgramNode dataNode = root.getChild(".data");
		setViewPaths(new TreePath[] { dataNode.getTreePath() });

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x01002a9b), getAddr(0x01002aad));
		SelectionTransferData data =
			new SelectionTransferData(set, program.getDomainFile().getPathname());
		ProgramNode debugNode = root.getChild(".debug_data");

		dropSelectionOnTree(debugNode, data);

		assertTrue(debugNode.getFragment().contains(set));

		// verify that the view remains unaffected
		assertTrue(plugin.getView().hasSameAddresses(dataNode.getFragment()));
	}

	@Test
	public void testDnDCodeUnits2FragNotInView2() throws Exception {
		// drag all code units from a fragment to another fragment
		// verify that all code units are in the destination fragment
		// verify that the source fragment is removed from the program

		ProgramNode dataNode = root.getChild(".data");
		setViewPaths(new TreePath[] { dataNode.getTreePath() });

		ProgramNode debugNode = root.getChild(".debug_data");

		ProgramFragment f = listing.getFragment("Main Tree", "sscanf");
		AddressSet set = new AddressSet(f);
		SelectionTransferData data =
			new SelectionTransferData(set, program.getDomainFile().getPathname());

		// drag code units for sscanf to debug node (not in the view)
		dropSelectionOnTree(debugNode, data);

		assertTrue(debugNode.getFragment().contains(set));
		assertNull(listing.getFragment("Main Tree", "sscanf"));
		expandNode(root);
		assertEquals(0, findNodes("sscanf").length);

		// verify that the view remains unaffected
		assertTrue(plugin.getView().hasSameAddresses(dataNode.getFragment()));

	}

	@Test
	public void testDnDCodeUnits2FragInView() throws Exception {
		// drag code units to a another fragment in the view
		// verify that the code units are in the destination fragment
		// verify that the view is not affected

		ProgramNode dataNode = root.getChild(".data");
		ProgramNode debugNode = root.getChild(".debug_data");
		setViewPaths(new TreePath[] { dataNode.getTreePath(), debugNode.getTreePath() });

		AddressSet origSet = plugin.getView();
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x1001800L), getAddr(0x100180cL));
		SelectionTransferData data =
			new SelectionTransferData(set, program.getDomainFile().getPathname());

		dropSelectionOnTree(dataNode, data);

		assertTrue(dataNode.getFragment().contains(set));
		assertTrue(plugin.getView().hasSameAddresses(origSet));
	}

	@Test
	public void testDnDCodeUnits2FolderDup() throws Exception {
		// drag code units to a folder
		// verify that the name of the fragment that get created is the
		// same as the first address in the set
		// drag the first few code units to a folder
		// verify that the fragment is named "New Fragment"

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x01004000), getAddr(0x0100400a));
		SelectionTransferData data =
			new SelectionTransferData(set, program.getDomainFile().getPathname());

		dropSelectionOnTree(root, data);

		ProgramNode[] nodes = findNodes("01004000");
		assertEquals(1, nodes.length);

		set.clear();
		set.addRange(getAddr(0x01004000), getAddr(0x01004003));

		SelectionTransferData data2 =
			new SelectionTransferData(set, program.getDomainFile().getPathname());
		dropSelectionOnTree(root, data2);

		nodes = findNodes("New Fragment");
		assertEquals(1, nodes.length);
		assertTrue(set.hasSameAddresses(nodes[0].getFragment()));
	}

	@Test
	public void testDnDCopyFrag2FragInvalid() throws Exception {
		// drag/copy a fragment onto another fragment
		// verify that there is no valid drop target

		ProgramNode textNode = root.getChild(".text");
		ProgramNode debugNode = root.getChild(".debug_data");

		assertTrue(!dndManager.isDropSiteOk(debugNode, new ProgramNode[] { textNode },
			DnDConstants.ACTION_COPY, 0));
	}

	@Test
	public void testDnDCopyFrag2Folder() throws Exception {
		// drag/copy a fragment onto a folder that does not contain
		//this fragment.
		// Verify that all occurrences of the dest folder are updated with
		// the new child.
		// Verify that the original parent folder remains intact.
		ProgramNode textNode = root.getChild(".text");

		setSelectionPath(textNode.getTreePath());

		ProgramNode dllsNode = root.getChild("DLLs");
		int origCount = dllsNode.getChildCount();
		setSelectionPath(dllsNode.getTreePath());

		dragNodes_Copy(dllsNode, Arrays.asList(textNode));

		expandNode(dllsNode);
		ProgramNode child = (ProgramNode) dllsNode.getChildAt(dllsNode.getChildCount() - 1);
		assertEquals(".text", child.getName());
		assertNotNull(root.getChild(".text"));
		ProgramNode[] nodes = findNodes("DLLs");
		for (ProgramNode element : nodes) {
			assertNotNull(element.getChild(".text"));
		}

		undo();
		ProgramNode node = root.getChild("DLLs");
		assertEquals(origCount, node.getChildCount());
		redo();
		node = (ProgramNode) root.getChildAt(5);
		assertEquals(origCount + 1, node.getChildCount());
	}

	@Test
	public void testDnDCopyFrag2FolderInvalid() throws Exception {
		// drag/copy a fragment onto a folder that already contains the
		// fragment.
		// verify that there is no valid drop target.

		//setup scenario
		copyFolderOrFragment(".debug_data", "Not Real Blocks");

		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode nrbNode = root.getChild("Not Real Blocks");
		assertTrue(!dndManager.isDropSiteOk(nrbNode, new ProgramNode[] { debugNode },
			DnDConstants.ACTION_COPY, 0));
	}

	@Test
	public void testDnDCopyFolder2Folder() throws Exception {
		// drag/copy a folder onto another folder that does not contain
		// the folder.
		// Verify that all occurrences of the dest folder are updated with
		// the new child.
		// Verify that the original parent folder remains intact.

		ProgramNode dragNode = root.getChild("Functions");
		ProgramNode destNode = root.getChild("DLLs");
		int childCount = destNode.getChildCount();

		setSelectionPath(dragNode.getTreePath());

		// drag/copy Functions to DLLs
		ProgramNode tgtNode = destNode;
		dragNodes_Copy(tgtNode, Arrays.asList(dragNode));

		assertEquals(childCount + 1, destNode.getChildCount());
		ProgramNode node = (ProgramNode) destNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());

		undo();
		destNode = root.getChild("DLLs");
		assertEquals(childCount, destNode.getChildCount());
		redo();
		destNode = root.getChild("DLLs");
		assertEquals(childCount + 1, destNode.getChildCount());
		node = (ProgramNode) destNode.getChildAt(childCount);
		assertEquals("Functions", node.getName());

	}

	@Test
	public void testDnDCopyFolder2FolderInvalid() throws Exception {

		//First copy folder into another folder
		copyFolderOrFragment("Subroutines", "Everything");

		// drag/copy a folder onto another folder that already contains
		// the folder.
		// 	Verify that there is no valid drop target.
		ProgramNode subrNode = root.getChild("Subroutines");
		ProgramNode evNode = root.getChild("Everything");
		assertTrue(!dndManager.isDropSiteOk(evNode, new ProgramNode[] { subrNode },
			DnDConstants.ACTION_COPY, 0));
	}

	@Test
	public void testDnDCopyFolderExpanded() throws Exception {
		// drag/copy an expanded folder to another expanded folder.
		// The dropped folder should  retain its expansion state.

		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode lnode = stringsNode.getChild("L");
		expandPath(lnode.getTreePath());

		// Strings, L are expanded

		// select Strings
		setSelectionPath(stringsNode.getTreePath());

		// drag/copy Strings to Functions
		ProgramNode funcNode = root.getChild("Functions");
		setSelectionPath(funcNode.getTreePath());

		dragNodes_Copy(funcNode, Arrays.asList(stringsNode));

		// Strings, L should be expanded

		ProgramNode sNode = funcNode.getChild("Strings");
		assertTrue(tree.isExpanded(sNode.getTreePath()));
		lnode = sNode.getChild("L");
		assertTrue(tree.isExpanded(lnode.getTreePath()));
	}

	@Test
	public void testDnDCopyFolderCollapsed() throws Exception {
		// drag/copy an expanded folder to a collapsed folder.
		// The dest folder should remain collapsed.
		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		ProgramNode lnode = stringsNode.getChild("L");
		expandPath(lnode.getTreePath());

		// Strings, L are expanded

		// select Strings
		setSelectionPath(stringsNode.getTreePath());

		// paste at Functions
		ProgramNode funcNode = root.getChild("Functions");
		collapsePath(funcNode.getTreePath());
		setSelectionPath(funcNode.getTreePath());

		// drag/copy Strings to Functions
		dragNodes_Copy(funcNode, Arrays.asList(stringsNode));

		// Functions should remain collapsed
		assertTrue(tree.isCollapsed(funcNode.getTreePath()));
		ProgramNode sNode = funcNode.getChild("Strings");
		assertTrue(tree.isCollapsed(sNode.getTreePath()));
	}

	@Test
	public void testDnDCopyCollapsedFolder() throws Exception {
		// drag/copy a collapsed folder to an expanded folder.
		// The dropped folder should be collapsed.

		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		collapsePath(stringsNode.getTreePath());

		// select Strings
		setSelectionPath(stringsNode.getTreePath());

		// drag/copy Strings to Functions
		ProgramNode funcNode = root.getChild("Functions");
		expandPath(funcNode.getTreePath());
		setSelectionPath(funcNode.getTreePath());

		dragNodes_Copy(funcNode, Arrays.asList(stringsNode));

		ProgramNode snode = funcNode.getChild("Strings");
		assertTrue(tree.isCollapsed(snode.getTreePath()));
		assertNotNull(root.getChild("Strings"));

	}

	@Test
	public void testDnDCopyFolderBothCollapsed() throws Exception {
		// drag/copy a collapsed folder to a collpased folder.
		// The dest folder should remain collapsed.

		ProgramNode stringsNode = root.getChild("Strings");
		visitNode(stringsNode);
		collapsePath(stringsNode.getTreePath());

		// select Strings
		setSelectionPath(stringsNode.getTreePath());

		// drag/copy Strings to Functions
		ProgramNode funcNode = root.getChild("Functions");
		visitNode(funcNode);
		collapsePath(funcNode.getTreePath());
		setSelectionPath(funcNode.getTreePath());

		dragNodes_Move(funcNode, Arrays.asList(stringsNode));

		assertTrue(tree.isCollapsed(funcNode.getTreePath()));
	}

	@Test
	public void testDnDCopyFrag2FolderNotInView() throws Exception {
		// drag/copy a fragment in the view to another folder not
		/// in the view.
		// verify that the view is not affected.
		ProgramNode funcNode = root.getChild("Functions");
		// set the view to Functions
		setViewPaths(new TreePath[] { funcNode.getTreePath() });

		ProgramNode child = funcNode.getChild("doStuff");
		setSelectionPath(child.getTreePath());

		ProgramNode subrNode = root.getChild("Subroutines");

		// drag/copy doStuff to Subroutines
		dragNodes_Copy(subrNode, Arrays.asList(funcNode));

		// verify the view is not affected
		assertTrue(plugin.getView().hasSameAddresses(funcNode.getModule().getAddressSet()));
		undo();
		ProgramNode fNode = root.getChild("Functions");
		assertTrue(plugin.getView().hasSameAddresses(fNode.getModule().getAddressSet()));
		redo();
		fNode = root.getChild("Functions");
		assertTrue(plugin.getView().hasSameAddresses(fNode.getModule().getAddressSet()));
	}

	@Test
	public void testDnDCopyFolder2FolderNotInView() throws Exception {
		// drag/copy a folder in the view to another folder not in the
		// view.
		// verify that the view is not affected.
		ProgramNode funcNode = root.getChild("Functions");

		// set the view to Functions
		setSelectionPath(funcNode.getTreePath());
		setViewPaths(new TreePath[] { funcNode.getTreePath() });

		ProgramNode subrNode = root.getChild("Subroutines");

		// copy to Subroutines
		dragNodes_Copy(subrNode, Arrays.asList(funcNode));

		// verify the view is not affected
		assertTrue(plugin.getView().hasSameAddresses(funcNode.getModule().getAddressSet()));

		undo();
		ProgramNode node = root.getChild("Functions");
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
		redo();
		node = root.getChild("Functions");
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
	}

	@Test
	public void testDnDCopyFolderNotInView2Folder() throws Exception {
		// drag/copy a folder not in the view to a folder in the view.
		// verify that the view updates to show the copied folder

		ProgramNode funcNode = root.getChild("Functions");
		// set the view to Functions
		setViewPaths(new TreePath[] { funcNode.getTreePath() });
		AddressSetView origSet = funcNode.getModule().getAddressSet();

		// select Subroutines (not in the view)
		ProgramNode subrNode = root.getChild("Subroutines");

		setSelectionPath(subrNode.getTreePath());

		dragNodes_Move(funcNode, Arrays.asList(subrNode));

		assertTrue(plugin.getView().hasSameAddresses(funcNode.getModule().getAddressSet()));
		undo();
		assertTrue(plugin.getView().hasSameAddresses(origSet));
		redo();
		ProgramNode node = root.getChild("Functions");// Functions
		assertTrue(plugin.getView().hasSameAddresses(node.getModule().getAddressSet()));
	}

	@Test
	public void testReorderFolder() throws Exception {

		// expand Strings folder

		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag "L" and place it after "CC"
		ProgramNode lnode = stringsNode.getChild("L");
		ProgramNode cnode = stringsNode.getChild("CC");
		setSelectionPath(lnode.getTreePath());

		moveNode(cnode, lnode);

		String[] names = new String[] { "CC", "L", "G", "S" };
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], stringsNode.getChildAt(i).toString());
		}
		ProgramNode node = stringsNode.getChild("L");
		assertTrue(tree.isPathSelected(node.getTreePath()));
		undo();
		stringsNode = root.getChild("Strings");
		String[] origNames = new String[] { "CC", "G", "S", "L" };
		for (int i = 0; i < origNames.length; i++) {
			assertEquals(origNames[i], stringsNode.getChildAt(i).toString());
		}

		redo();
		stringsNode = root.getChild("Strings");
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], stringsNode.getChildAt(i).toString());
		}

	}

	@Test
	public void testReorderFolder2() throws Exception {

		// expand Strings folder

		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag "S" and place it after "CC"
		ProgramNode snode = stringsNode.getChild("S");
		ProgramNode cnode = stringsNode.getChild("CC");
		setSelectionPath(snode.getTreePath());

		runSwing(() -> {
			try {
				// place S after CC
				dndManager.add(cnode, new ProgramNode[] { snode }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();
		String[] names = new String[] { "CC", "S", "G", "L" };
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], stringsNode.getChildAt(i).toString());
		}
		ProgramNode node = stringsNode.getChild("S");
		assertTrue(tree.isPathSelected(node.getTreePath()));
		undo();
		stringsNode = root.getChild("Strings");
		String[] origNames = new String[] { "CC", "G", "S", "L" };
		for (int i = 0; i < origNames.length; i++) {
			assertEquals(origNames[i], stringsNode.getChildAt(i).toString());
		}

		redo();
		stringsNode = root.getChild("Strings");
		for (int i = 0; i < names.length; i++) {
			assertEquals(names[i], stringsNode.getChildAt(i).toString());
		}
	}

	@Test
	public void testReorderFolder3() throws Exception {

		// expand DLLs folder

		ProgramNode dllsNode = root.getChild("DLLs");
		expandNode(dllsNode);

		// drag "USER32.DLL" and place it above "ADVAPI32.DLL"
		ProgramNode wnode = dllsNode.getChild("USER32.DLL");
		ProgramNode anode = dllsNode.getChild("ADVAPI32.DLL");
		setSelectionPath(wnode.getTreePath());

		runSwing(() -> {
			try {
				// place USER32.DLL above ADVAPI32.DLL
				dndManager.add(anode, new ProgramNode[] { wnode }, DnDConstants.ACTION_MOVE, -1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();
		assertEquals("USER32.DLL", dllsNode.getFirstChild().toString());

		ProgramNode node = dllsNode.getChild("USER32.DLL");
		assertTrue(tree.isPathSelected(node.getTreePath()));

		undo();
		dllsNode = root.getChild("DLLs");
		assertEquals("ADVAPI32.DLL", dllsNode.getFirstChild().toString());
		redo();
		dllsNode = root.getChild("DLLs");
		assertEquals("USER32.DLL", dllsNode.getFirstChild().toString());
	}

	@Test
	public void testReorderMoveFrag2Folder() throws Exception {

		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);
		// expand Not Real Blocks
		ProgramNode nrbNode = root.getChild("Not Real Blocks");
		expandNode(nrbNode);

		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode cnode = stringsNode.getChild("CC");

		setSelectionPath(debugNode.getTreePath());

		// drag .debug_data to Strings and place it above C

		runSwing(() -> {
			try {
				// place .debug_data above C
				dndManager.add(cnode, new ProgramNode[] { debugNode }, DnDConstants.ACTION_MOVE,
					-1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();
		// verify that .debug_data is the first child in Strings
		// .debug_data should remain selected
		// .debug_data should be removed from Not Real Blocks
		assertEquals(".debug_data", stringsNode.getFirstChild().toString());
		ProgramNode node = stringsNode.getChild(".debug_data");
		assertTrue(tree.isPathSelected(node.getTreePath()));
		assertNull(root.getChild(".debug_data"));

		undo();
		stringsNode = root.getChild("Strings");
		assertEquals("CC", stringsNode.getFirstChild().toString());
		assertNotNull(root.getChild(".debug_data"));

		redo();
		stringsNode = root.getChild("Strings");
		assertEquals(".debug_data", stringsNode.getFirstChild().toString());
		node = stringsNode.getChild(".debug_data");
		assertNull(root.getChild(".debug_data"));
	}

	@Test
	public void testReorderMoveFolder2Folder() throws Exception {
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);
		// expand DLLs
		ProgramNode dllsNode = root.getChild("DLLs");
		expandNode(dllsNode);
		setSelectionPath(dllsNode.getTreePath());
		ProgramNode lnode = stringsNode.getChild("L");
		collapseNode(lnode);

		// drag DLLs below L in Strings
		runSwing(() -> {
			try {
				// place DLLs below L
				dndManager.add(lnode, new ProgramNode[] { dllsNode }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that DLLs is the last child in Strings
		// verify that DLLs is still expanded
		// verify that DLLs remains selected
		// verify that DLLs is removed from the root folder
		assertEquals("DLLs", stringsNode.getLastChild().toString());
		ProgramNode node = stringsNode.getChild("DLLs");
		assertTrue(tree.isExpanded(node.getTreePath()));
		assertTrue(tree.isPathSelected(node.getTreePath()));
		assertNull(root.getChild("DLLs"));

		undo();
		stringsNode = root.getChild("Strings");
		assertEquals("L", stringsNode.getLastChild().toString());
		assertNull(stringsNode.getChild("DLLs"));
		assertNotNull(root.getChild("DLLs"));

		redo();
		stringsNode = root.getChild("Strings");
		assertEquals("DLLs", stringsNode.getLastChild().toString());
		node = stringsNode.getChild("DLLs");
		assertNull(root.getChild("DLLs"));
	}

	@Test
	public void testReorderMoveFolder2FolderBelow() throws Exception {
		// expand Subroutines
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag Strings between 01004a15 and 010030d8 in Subroutines
		ProgramNode node = subrNode.getChild("01004a15");
		ProgramNode strNode = stringsNode;
		runSwing(() -> {
			try {
				// place Strings below 01004a15 in Subroutines
				dndManager.add(node, new ProgramNode[] { strNode }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that Strings is expanded and is the 3rd child in Subroutines
		// Verify that Strings remains selected
		// verify that Strings was removed from root
		stringsNode = subrNode.getChild("Strings");
		assertTrue(tree.isExpanded(stringsNode.getTreePath()));
		assertEquals("Strings", subrNode.getChildAt(2).toString());
		assertTrue(tree.isPathSelected(stringsNode.getTreePath()));
		assertNull(root.getChild("Strings"));

		undo();
		subrNode = root.getChild("Subroutines");
		assertNull(subrNode.getChild("Strings"));
		assertNotNull(root.getChild("Strings"));

		redo();
		subrNode = root.getChild("Subroutines");
		stringsNode = subrNode.getChild("Strings");
		assertEquals("Strings", subrNode.getChildAt(2).toString());
		assertNull(root.getChild("Strings"));
	}

	@Test
	public void testReorderMoveFolder2FolderAbove() throws Exception {
		// expand Subroutines
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag Strings between 01004a15 and 010030d8 in Subroutines
		ProgramNode node = subrNode.getChild("01004a15");
		ProgramNode strNode = stringsNode;
		runSwing(() -> {
			try {
				// place Strings above 01004a15 in Subroutines
				dndManager.add(node, new ProgramNode[] { strNode }, DnDConstants.ACTION_MOVE, -1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that Strings is expanded and is the 2nd child in Subroutines
		// Verify that Strings remains selected
		// verify that Strings was removed from root
		stringsNode = subrNode.getChild("Strings");
		assertTrue(tree.isExpanded(stringsNode.getTreePath()));
		assertEquals("Strings", subrNode.getChildAt(1).toString());
		assertTrue(tree.isPathSelected(stringsNode.getTreePath()));
		assertNull(root.getChild("Strings"));

		undo();
		subrNode = root.getChild("Subroutines");
		assertNull(subrNode.getChild("Strings"));
		assertNotNull(root.getChild("Strings"));

		redo();
		subrNode = root.getChild("Subroutines");
		stringsNode = subrNode.getChild("Strings");
		assertEquals("Strings", subrNode.getChildAt(1).toString());
		assertNull(root.getChild("Strings"));
	}

	@Test
	public void testReorderMove2Expanded() throws Exception {
		// expand Everything
		ProgramNode evNode = root.getChild("Everything");
		runSwing(() -> expandNode(evNode));
		ProgramNode subrNode = root.getChild("Subroutines");
		runSwing(() -> expandNode(subrNode));

		ProgramNode node = subrNode.getChild("010030d8");

		// drag 010030d8 from Subroutines to Everything and place after
		// Everything
		runSwing(() -> {
			try {
				dndManager.add(evNode, new ProgramNode[] { node }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that 010030d8 is the first child in Everything
		assertEquals("010030d8", evNode.getFirstChild().toString());
		assertNull(subrNode.getChild("010030d8"));

		// collapse Everything
		collapseNode(evNode);

		// from Subroutines drag 01004a15 below Everything
		ProgramNode node2 = subrNode.getChild("01004a15");
		runSwing(() -> {
			try {
				dndManager.add(evNode, new ProgramNode[] { node2 }, DnDConstants.ACTION_MOVE, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that 01004a15 is moved to the root node and placed
		// after Everything
		assertNotNull(root.getChild("01004a15"));
		ProgramNode e = root.getChild("Everything");
		assertEquals("01004a15", root.getChildAfter(e).toString());
		assertNull(subrNode.getChild("01004a15"));
	}

	// reorder/copy tests
	@Test
	public void testReorderCopy2Expanded() throws Exception {
		// expand Everything
		ProgramNode evNode = root.getChild("Everything");
		expandNode(evNode);
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		ProgramNode node = subrNode.getChild("010030d8");

		// drag/copy 010030d8 from Subroutines to Everything and place after
		// Everything
		runSwing(() -> {
			try {
				dndManager.add(evNode, new ProgramNode[] { node }, DnDConstants.ACTION_COPY, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that 010030d8 is the first child in Everything
		assertEquals("010030d8", evNode.getFirstChild().toString());
		assertNotNull(subrNode.getChild("010030d8"));

		// collapse Everything
		collapseNode(evNode);

		// from Subroutines drag 01004a15 below Everything
		ProgramNode node2 = subrNode.getChild("01004a15");
		runSwing(() -> {
			try {
				dndManager.add(evNode, new ProgramNode[] { node2 }, DnDConstants.ACTION_COPY, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		// verify that 01004a15 is copied to the root node and placed
		// after Everything
		assertNotNull(root.getChild("01004a15"));
		ProgramNode e = root.getChild("Everything");
		assertEquals("01004a15", root.getChildAfter(e).toString());
	}

	@Test
	public void testReorderCopyFolder2Folder() throws Exception {
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);
		// expand DLLs
		ProgramNode dllsNode = root.getChild("DLLs");
		expandNode(dllsNode);
		setSelectionPath(dllsNode.getTreePath());
		ProgramNode lnode = stringsNode.getChild("L");
		collapseNode(lnode);

		// drag/copy DLLs below L in Strings
		runSwing(() -> {
			try {
				// place DLLs below L
				dndManager.add(lnode, new ProgramNode[] { dllsNode }, DnDConstants.ACTION_COPY, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that DLLs is the last child in Strings
		// verify that DLLs is still expanded
		// verify that DLLs remains selected
		// verify that DLLs is remains in the root folder
		assertEquals("DLLs", stringsNode.getLastChild().toString());
		ProgramNode node = stringsNode.getChild("DLLs");
		assertTrue(tree.isExpanded(node.getTreePath()));
		assertTrue(tree.isPathSelected(node.getTreePath()));
		assertNotNull(root.getChild("DLLs"));

		undo();
		stringsNode = root.getChild("Strings");
		assertEquals("L", stringsNode.getLastChild().toString());
		assertNull(stringsNode.getChild("DLLs"));
		assertNotNull(root.getChild("DLLs"));

		redo();
		stringsNode = root.getChild("Strings");
		assertEquals("DLLs", stringsNode.getLastChild().toString());
		node = stringsNode.getChild("DLLs");
		assertNotNull(root.getChild("DLLs"));
	}

	@Test
	public void testReorderCopyFolder2FolderAbove() throws Exception {
		// expand Subroutines
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag/copy Strings between 01004a15 and 010030d8 in Subroutines
		ProgramNode node = subrNode.getChild("01004a15");
		ProgramNode strNode = stringsNode;
		runSwing(() -> {
			try {
				// place Strings above 01004a15 in Subroutines
				dndManager.add(node, new ProgramNode[] { strNode }, DnDConstants.ACTION_COPY, -1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that Strings is expanded and is the 2nd child in Subroutines
		// Verify that Strings remains selected
		// verify that Strings was not removed from root
		stringsNode = subrNode.getChild("Strings");
		assertTrue(tree.isExpanded(stringsNode.getTreePath()));
		assertEquals("Strings", subrNode.getChildAt(1).toString());
		assertTrue(tree.isPathSelected(stringsNode.getTreePath()));
		assertNotNull(root.getChild("Strings"));

		undo();
		subrNode = root.getChild("Subroutines");
		assertNull(subrNode.getChild("Strings"));
		assertNotNull(root.getChild("Strings"));

		redo();
		subrNode = root.getChild("Subroutines");
		stringsNode = subrNode.getChild("Strings");
		assertEquals("Strings", subrNode.getChildAt(1).toString());
		assertNotNull(root.getChild("Strings"));
	}

	@Test
	public void testReorderCopyFolder2FolderBelow() throws Exception {
		// expand Subroutines
		ProgramNode subrNode = root.getChild("Subroutines");
		expandNode(subrNode);
		// expand Strings
		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);

		// drag/copy Strings between 01004a15 and 010030d8 in Subroutines
		ProgramNode node = subrNode.getChild("01004a15");
		ProgramNode strNode = stringsNode;
		runSwing(() -> {
			try {
				// place Strings below 01004a15 in Subroutines
				dndManager.add(node, new ProgramNode[] { strNode }, DnDConstants.ACTION_COPY, 1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();

		// verify that Strings is expanded and is the 3rd child in Subroutines
		// Verify that Strings remains selected
		// verify that Strings was not removed from root
		stringsNode = subrNode.getChild("Strings");
		assertTrue(tree.isExpanded(stringsNode.getTreePath()));
		assertEquals("Strings", subrNode.getChildAt(2).toString());
		assertTrue(tree.isPathSelected(stringsNode.getTreePath()));
		assertNotNull(root.getChild("Strings"));

		undo();
		subrNode = root.getChild("Subroutines");
		assertNull(subrNode.getChild("Strings"));
		assertNotNull(root.getChild("Strings"));

		redo();
		subrNode = root.getChild("Subroutines");
		stringsNode = subrNode.getChild("Strings");
		assertEquals("Strings", subrNode.getChildAt(2).toString());
		assertNotNull(root.getChild("Strings"));
	}

	@Test
	public void testReorderCopyFrag2Folder() throws Exception {

		ProgramNode stringsNode = root.getChild("Strings");
		expandNode(stringsNode);
		ProgramNode nrbNode = root.getChild("Not Real Blocks");
		expandNode(nrbNode);

		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode cnode = stringsNode.getChild("CC");

		setSelectionPath(debugNode.getTreePath());

		// drag/copy .debug_data to Strings and place it above CC

		runSwing(() -> {
			try {
				// place .debug_data above CC
				dndManager.add(cnode, new ProgramNode[] { debugNode }, DnDConstants.ACTION_COPY,
					-1);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		});

		program.flushEvents();
		// verify that .debug_data is the first child in Strings
		// .debug_data should remain selected
		// .debug_data should not be removed from Not Real Blocks
		assertEquals(".debug_data", stringsNode.getFirstChild().toString());
		ProgramNode node = stringsNode.getChild(".debug_data");
		assertTrue(tree.isPathSelected(node.getTreePath()));
		assertNotNull(root.getChild(".debug_data"));

		undo();
		stringsNode = root.getChild("Strings");
		assertEquals("CC", stringsNode.getFirstChild().toString());
		assertNotNull(root.getChild(".debug_data"));

		redo();
		stringsNode = root.getChild("Strings");
		assertEquals(".debug_data", stringsNode.getFirstChild().toString());
		node = stringsNode.getChild(".debug_data");
		assertNotNull(root.getChild(".debug_data"));
	}

	@Test
	public void testReorderCopyDupFrag2Folder() {
		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode nrbNode = root.getChild("Not Real Blocks");

		assertTrue(!dndManager.isDropSiteOk(nrbNode, new ProgramNode[] { debugNode },
			DnDConstants.ACTION_COPY, 1));
	}

	@Test
	public void testReorderCopyDupFrag2Frag() {
		ProgramNode debugNode = root.getChild(".debug_data");
		ProgramNode textNode = root.getChild(".text");

		assertTrue(!dndManager.isDropSiteOk(textNode, new ProgramNode[] { debugNode },
			DnDConstants.ACTION_COPY, 1));
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

	private void copyFolderOrFragment(String src, String dst) {
		// copy a folder that is in the view to another folder that is not in the view
		ProgramNode node = root.getChild(src);

		setSelectionPath(node.getTreePath());
		setViewPaths(new TreePath[] { node.getTreePath() });
		performAction(copyAction, true);
		ProgramNode everythingNode = root.getChild(dst);

		setSelectionPath(everythingNode.getTreePath());
		assertTrue(pasteAction.isEnabled());
		performAction(pasteAction, true);
	}

}
