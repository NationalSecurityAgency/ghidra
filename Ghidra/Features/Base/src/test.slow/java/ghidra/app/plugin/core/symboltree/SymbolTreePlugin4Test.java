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
package ghidra.app.plugin.core.symboltree;

import static org.junit.Assert.*;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * More symbol tree tests.
 */
public class SymbolTreePlugin4Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private SymbolTreePlugin plugin;
	private CodeBrowserPlugin cbPlugin;
	private GTreeNode rootNode;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DockingActionIf selectionAction;
	private DockingActionIf createNamespaceAction;
	private DockingActionIf createClassAction;
	private SymbolTreeTestUtils util;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		env.launchDefaultTool();
		plugin = env.getPlugin(SymbolTreePlugin.class);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		util = new SymbolTreeTestUtils(plugin);
		program = util.getProgram();
		util.showSymbolTree();
		getActions();
		rootNode = util.getRootNode();
		util.setGoToNavigationSelected(true);
	}

	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testCutPasteAtNamespace() throws Exception {
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);

		// create a new namespace;
		// cut and paste a function at the new namespace
		GTreeNode nsParentNode = rootNode.getChild(5);
		GTreeNode nsNode = util.createObject(nsParentNode, "MYNamespace", createNamespaceAction);
		util.waitForTree();
		fNode = rootNode.getChild(2);
		gNode = fNode.getChild(1);
		util.selectNode(gNode);

		performAction(cutAction, util.getSymbolTreeContext(), true);
		util.selectNode(nsNode);

		SymbolTreeProvider provider = plugin.getProvider();
		assertTrue(pasteAction.isEnabledForContext(provider.getActionContext(null)));
		performAction(pasteAction, util.getSymbolTreeContext(), true);

		program.flushEvents();
		waitForSwing();

		// re-acquire nsNode
		nsParentNode = rootNode.getChild(5);
		nsNode = nsParentNode.getChild(0);
		util.expandNode(nsNode);
		util.waitForTree();
		gNode = nsNode.getChild(0);

		Symbol s = ((SymbolNode) gNode).getSymbol();
		assertEquals("ghidra", s.getName());

		fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		assertEquals(2, fNode.getChildCount());
	}

	@Test
	public void testCutPasteAtClass() throws Exception {
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);

		// create a new namespace;
		// cut and paste a function at the new class
		GTreeNode cParentNode = rootNode.getChild(4);
		GTreeNode cNode = util.createObject(cParentNode, "MYClass", createClassAction);
		int index = cNode.getIndexInParent();
		util.waitForTree();
		fNode = rootNode.getChild(2);
		gNode = fNode.getChild(1);

		util.selectNode(gNode);

		performAction(cutAction, util.getSymbolTreeContext(), true);
		util.selectNode(cNode);

		SymbolTreeProvider provider = plugin.getProvider();
		assertTrue(pasteAction.isEnabledForContext(provider.getActionContext(null)));
		performAction(pasteAction, util.getSymbolTreeContext(), true);
		program.flushEvents();
		waitForSwing();

		// re-acquire cNode
		cParentNode = rootNode.getChild(4);
		cNode = cParentNode.getChild(index);
		util.expandNode(cNode);
		util.waitForTree();
		waitForSwing();
		gNode = cNode.getChild(0);
		Symbol s = ((SymbolNode) gNode).getSymbol();
		assertEquals("ghidra", s.getName());

		fNode = rootNode.getChild(2);
		assertNotNull(fNode);
		util.expandNode(fNode);
		assertEquals(2, fNode.getChildCount());
	}

	@Test
	public void testMakeSelection() throws Exception {
		// select the ghidra function; make selection
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		util.selectNode(gNode);

		Symbol s = ((SymbolNode) gNode).getSymbol();

		Function f = (Function) s.getObject();

		performAction(selectionAction, util.getSymbolTreeContext(), true);
		assertTrue(f.getBody().hasSameAddresses(cbPlugin.getCurrentSelection()));

		GTreeNode dNode = fNode.getChild(0);
		util.expandNode(dNode);
		GTreeNode pNode = dNode.getChild(0);

		GTreeNode sNode = fNode.getChild(2);
		s = ((SymbolNode) sNode).getSymbol();
		f = (Function) s.getObject();
		util.selectNodes(new GTreeNode[] { pNode, sNode });
		performAction(selectionAction, util.getSymbolTreeContext(), true);
		program.flushEvents();
		waitForSwing();
		AddressSet set = new AddressSet(f.getBody());
		Address address = util.addr(0x010048a3);
		CodeUnit cu = program.getListing().getCodeUnitAt(address);
		set.addRange(address, cu.getMaxAddress());

		assertTrue(set.hasSameAddresses(cbPlugin.getCurrentSelection()));
	}

	@Test
	public void testMakeSelectionNotInMemory() throws Exception {
		SymbolTable symTable = program.getSymbolTable();

		int transactionID = program.startTransaction("test");
		try {
			symTable.createLabel(util.addr(0), "MySymbol", SourceType.USER_DEFINED);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		program.flushEvents();
		waitForSwing();

		// select the Label node; make selection
		GTreeNode lNode = rootNode.getChild(3);
		util.expandNode(lNode);

		for (int i = 0; i < lNode.getChildCount(); i++) {
			GTreeNode node = lNode.getChild(i);
			if (node instanceof SymbolNode) {
				Symbol s = ((SymbolNode) node).getSymbol();
				if (s.getName().equals("MySymbol")) {
					util.selectNodes(new GTreeNode[] { node });
					performAction(selectionAction, util.getSymbolTreeContext(), true);
					assertTrue(cbPlugin.getCurrentSelection().isEmpty());
					break;
				}
			}
		}
	}

	@Test
	public void testNavigateFromListing() throws Exception {
		//
		// The symbol tree should select nodes according to where the cursor is in the listing.
		// Also, the location in the listing should not change after it has been set
		//

		// address of 'ghidra' function
		cbPlugin.goTo(new FunctionSignatureFieldLocation(program, addr("01002cf5")));

		util.waitForTree();

		GTreeNode selectedNode = util.getSelectedNode();
		assertEquals("Symbol tree did not selected node when navigating in code browser", "ghidra",
			selectedNode.getName());

		// make sure the browser's location didn't change
		ProgramLocation location = cbPlugin.getCurrentLocation();
		assertEquals("Code browser location changed after a selection was made in the symbol tree",
			addr("01002cf5"), location.getAddress());

		// call to 'doStuff' function
		cbPlugin.goTo(new OperandFieldLocation(program, addr("0x1002cf9"), null, null, null, 0, 0));

		util.waitForTree();

		selectedNode = util.getSelectedNode();
		assertEquals("Symbol tree did not selected node when navigating in code browser", "doStuff",
			selectedNode.getName());

		// make sure the browser's location didn't change
		location = cbPlugin.getCurrentLocation();
		assertEquals("Code browser location changed after a selection was made in the symbol tree",
			addr("0x1002cf9"), location.getAddress());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Address addr(String address) {
		return program.getAddressFactory().getAddress(address);
	}

	private void getActions() {
		cutAction = getAction(plugin, "Cut SymbolTree Node");
		assertNotNull(cutAction);
		pasteAction = getAction(plugin, "Paste Symbols");
		assertNotNull(pasteAction);

		selectionAction = getAction(plugin, "Make Selection");
		assertNotNull(selectionAction);

		createClassAction = getAction(plugin, "Create Class");
		assertNotNull(createClassAction);

		createNamespaceAction = getAction(plugin, "Create Namespace");
		assertNotNull(createNamespaceAction);
	}

}
