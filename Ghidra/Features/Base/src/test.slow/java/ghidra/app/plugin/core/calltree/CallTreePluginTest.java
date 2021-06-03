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
package ghidra.app.plugin.core.calltree;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import org.apache.commons.collections4.map.LazyMap;
import org.junit.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.tree.*;
import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.function.CreateExternalFunctionCmd;
import ghidra.app.cmd.function.SetFunctionNameCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.cmd.refs.SetExternalRefCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.NamespaceUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class CallTreePluginTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private CodeBrowserPlugin codeBrowserPlugin;
	private PluginTool tool;
	private CallTreePlugin callTreePlugin;
	private CallTreeProvider provider;

	private GTree incomingTree;
	private GTree outgoingTree;

	private ProgramBuilder builder;
	private ProgramDB program;

	private GoToService goToService;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(CallTreePlugin.class.getName());

		callTreePlugin = env.getPlugin(CallTreePlugin.class);

		GoToServicePlugin goToPlugin = env.getPlugin(GoToServicePlugin.class);
		goToService = (GoToService) invokeInstanceMethod("getGotoService", goToPlugin);
		codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();

		program = createProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		// setup a good start location
		goTo(addr("5000"));

		provider = callTreePlugin.getPrimaryProvider();
		tool.showComponentProvider(provider, true);
		incomingTree = (GTree) getInstanceField("incomingTree", provider);
		outgoingTree = (GTree) getInstanceField("outgoingTree", provider);
	}

	private ProgramDB createProgram() throws Exception {

		builder = new ProgramBuilder("Call Trees", ProgramBuilder._TOY);
		builder.createMemory(".text", "0x0", 0x11000);

		/*
		 	Create a function call tree that looks like:
		 	
		root 0000
		 	 a 1000
		 		 b 2000
		 			 c 3000
		 				 d 4000
		 					 <test function> e 5000
		 										 f 6000
		 											 g 7000
		 												 h 8000
		 													 i 9000
		 										 k 6100
		 											 l 7100
		 										 m 6000  (duplicate)
		 										     n 7000
		 
		 */

		//
		// 
		// -called by a chain of 5 other functions
		// -calls a chain of 4 other children
		// -has multiple children
		// -has duplicate children
		//
		function(0x0000, 0x1000);
		function(0x1000, 0x2000);
		function(0x2000, 0x3000);
		function(0x3000, 0x4000);
		function(0x4000, 0x5000);
		function(0x5000, 0x6000);
		function(0x5000, 0x6100);

		// second reference inside of function 0x5000 to 0x6000
		createReference(0x5020, 0x6000);

		function(0x6000, 0x7000);
		function(0x6100, 0x7100);
		function(0x7000, 0x8000);
		function(0x8000, 0x9000);
		function(0x9000, 0x10000);

		return builder.getProgram();
	}

	private Function function(int addr) throws Exception {
		return ensureFunction(addr);
	}

	private void function(int from, int to) throws Exception {
		ensureFunction(from);
		ensureFunction(to);

		int offset = from + 5;// a bit of space so the function call is not at the entry point
		while (!createReference(offset, to)) {
			offset++;
		}
	}

	private Function function(String namespace, String name, int addr) throws Exception {
		Function f = ensureFunction(addr);
		tx(program, () -> {

			f.setName(name, SourceType.ANALYSIS);
			Namespace ns = NamespaceUtils.createNamespaceHierarchy(namespace, null, program,
				SourceType.ANALYSIS);
			f.setParentNamespace(ns);
		});

		return f;
	}

	private void function(Function from, Function to) {

		// a bit of space so the function call is not at the entry point
		int offset = (int) from.getEntryPoint().getOffset() + 5;
		int toOffset = (int) to.getEntryPoint().getOffset();
		while (!createReference(offset, toOffset)) {
			offset++;
		}
	}

	private Function ensureFunction(long from) throws Exception {
		ProgramDB p = builder.getProgram();
		FunctionManager fm = p.getFunctionManager();
		Function f = fm.getFunctionAt(addr(from));
		if (f != null) {
			return f;
		}

		String a = Long.toHexString(from);
		return builder.createEmptyFunction("Function_" + a, "0x" + a, 50, DataType.DEFAULT);
	}

	private boolean createReference(long from, long to) {
		ProgramDB p = builder.getProgram();
		ReferenceManager rm = p.getReferenceManager();
		Reference existing = rm.getReference(addr(from), addr(to), 0);
		if (existing != null) {
			return false;
		}

		builder.createMemoryCallReference("0x" + Long.toHexString(from),
			"0x" + Long.toHexString(to));
		return true;
	}

	private Address addr(long addr) {
		return builder.addr(addr);
	}

	@After
	public void tearDown() throws Exception {

		incomingTree.cancelWork();
		outgoingTree.cancelWork();

		env.dispose();
	}

	@Test
	public void testTextFilterIncoming() {
		setProviderFunction("0x5000");// has good depth for in and out

		int depth = 4;
		setDepth(depth);

		String existingCaller = "Function_1000";// four levels back
		setIncomingFilter(existingCaller);
		assertIncomingMaxDepth(depth, true);

		assertIncomingNode(existingCaller, depth);

		depth = 3;
		setDepth(depth);
		setIncomingFilter(existingCaller);
		assertIncomingMaxDepth(0, true);// filter no longer matches

		assertIncomingNoNode(existingCaller, depth, true);
	}

	@Test
	public void testTextFilterOutgoing() {
		setProviderFunction("0x5000");// has good depth for in and out

		int depth = 3;
		setDepth(depth);

		String existingCallee = "Function_8000";
		setOutgoingFilter(existingCallee);
		assertOutgoingMaxDepth(depth, true);

		assertOutgoingNode(existingCallee, depth);

		depth = 2;
		setDepth(depth);
		setOutgoingFilter(existingCallee);
		assertOutgoingMaxDepth(0, true);// filter no longer matches

		assertOutgoingNoNode(existingCallee, depth, true);
	}

	@Test
	public void testChangingDepthWillFilterOnNewText() {
		// 
		// Verifies that we can match a filter at one depth and then increase the depth and match
		// a new filtered item that is at a deeper level than the previous depth.
		//
		setProviderFunction("0x5000");// has good depth for in and out

		int depth = 3;
		setDepth(depth);

		String existingCaller = "2000";// at depth 3
		setIncomingFilter(existingCaller);
		assertIncomingMaxDepth(depth, true);

		assertIncomingNode(existingCaller, depth);

		setIncomingFilter("");
		depth = 4;
		setDepth(depth);
		existingCaller = "1000";// at depth 4
		setIncomingFilter(existingCaller);

		assertIncomingMaxDepth(depth, true);
		assertIncomingNode(existingCaller, depth);
	}

	@Test
	public void testDepthPersistence() {
		//
		// Set the depth and make sure it is passed to snapshot windows and such
		//
		int depth = 10;
		setDepth(depth);

		goTo(addr("0x5000"));// new function

		CallTreeProvider initialProvider = provider;
		CallTreeProvider newProvider = showProvider("6000");
		assertNotEquals(initialProvider, newProvider);
		assertEquals(depth, currentDepthSetting(newProvider));
	}

	@Test
	public void testShowingTransientProvider() {

		goTo(addr("0x5000"));// new function
		assertOnlyOneToolbarIcon(); // this was a regression

		CallTreeProvider initialProvider = provider;
		CallTreeProvider newProvider = showProvider("6000");
		assertNotEquals(initialProvider, newProvider);
		assertOnlyOneToolbarIcon();
	}

	private void assertOnlyOneToolbarIcon() {

		int toolBarActionCount = 0;
		Set<DockingActionIf> actions =
			getActionsByOwnerAndName(tool, callTreePlugin.getName(), provider.getName());
		for (DockingActionIf action : actions) {
			ToolBarData data = action.getToolBarData();
			if (data != null) {
				toolBarActionCount++;
			}
		}

		assertEquals("Expected exactly one toolbar action", 1, toolBarActionCount);
	}

	@Test
	public void testIncomingExpandToDepthFromRoot() {
		//
		// Select a node and expand it recursively, limiting it to the current recurse depth
		//
		setDepth(5);// restore default
		setProviderFunction("0x5000");

		String rootNodeAddress = "5000";
		GTreeNode node = selectIncomingNode(rootNodeAddress);

		fullyExpandIncomingNode(node);

		assertIncomingMaxDepth(currentDepthSetting(provider), false);
	}

	@Test
	public void testOutgoingExpandToDepthFromRoot() {
		//
		// Select a node and expand it recursively, limiting it to the current recurse depth
		//
		setDepth(5);// restore default
		setProviderFunction("0x5000");

		String rootNodeAddress = "5000";
		GTreeNode node = selectOutgoingNode(rootNodeAddress);

		fullyExpandOutgoingNode(node);

		assertOutgoingMaxDepth(currentDepthSetting(provider), false);
	}

	@Test
	public void testIncomingExpandToDepthSelectively() {
		//
		// Select a node and expand it recursively, limiting it to the current recurse depth
		// This is testing the expand action.
		//
		setProviderFunction("0x5000");// a function with multiple callers (incoming depth of 4)

		String rootChildAddress = "Function_4000";// // this node has at least 5 (default) depth
		GTreeNode node = selectIncomingNode(rootChildAddress);

		fullyExpandIncomingNode(node);

		int nodeDepth = node.getTreePath().getPathCount() - 1;// -1 for root node 
		int depth = 4 + nodeDepth;
		assertIncomingMaxDepth(depth, false);
		assertDepth(node, depth);
	}

	@Test
	public void testOutgoingExpandToDepthSelectively() {
		//
		// Select a node and expand it recursively, limiting it to the current recurse depth.
		// This is testing the expand action.
		//
		setProviderFunction("0x5000");// a function with multiple callers

		String rootChildAddress = "Function_6000";// this node has at least 5 (default) depth
		GTreeNode node = selectOutgoingNode(rootChildAddress);

		fullyExpandOutgoingNode(node);

		int depth = currentDepthSetting(provider);
		assertOutgoingMaxDepth(depth, false);
		assertDepth(node, depth);
	}

	@Test
	public void testFollowsNavigation() {
		//
		// Test that navigating in the code browser will update the provider when the cursor
		// is inside of a function.  This will only work when the 'follow incoming changes' action
		// is selected.
		//
		assertTrue(provider.isVisible());
		assertNotNull("Provider did not update its information when made visible",
			providerFunction());

		toggleFollowIncomingNavigation(false);

		assertProviderMatchesListingFunction();

		goTo(addr("0x6000"));
		assertNotEquals(
			"Provider's location should not have changed when not tracking location changes",
			getListingFunction(), providerFunction());

		toggleFollowIncomingNavigation(true);
		assertProviderMatchesListingFunction();

		goTo(addr("0x6100"));
		assertProviderMatchesListingFunction();
	}

	@Test
	public void testIncomingCalls() {
		//
		// Make sure there are some incoming calls.  Make sure we can open child nodes to see 
		// more incoming calls.
		//

		waitForTree(incomingTree);
		GTreeNode rootNode = getRootNode(incomingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Incoming tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		GTreeNode child0 = children.get(0);
		incomingTree.expandPath(child0);
		waitForTree(incomingTree);

		List<GTreeNode> grandChildren = child0.getChildren();
		assertTrue("Incoming tree child does not have callers as expected for child: " + child0,
			grandChildren.size() > 0);
	}

	@Test
	public void testOutgoingCalls() {
		setProviderFunction("0x5000");

		waitForTree(outgoingTree);
		GTreeNode rootNode = getRootNode(outgoingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Outgoing tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		GTreeNode child1 = children.get(1);
		outgoingTree.expandPath(child1);
		waitForTree(outgoingTree);

		List<GTreeNode> grandChildren = child1.getChildren();
		assertTrue("Outgoing tree child does not have callers as expected for child: " + child1,
			grandChildren.size() > 0);
	}

	@Test
	public void testGoToFromNode() {
		setProviderFunction("0x5000");

		waitForTree(outgoingTree);
		GTreeNode rootNode = getRootNode(outgoingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Outgoing tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		ProgramLocation originalLocation = currentLocation();

		GTreeNode child1 = children.get(1);// skip the first child--it is an external function
		outgoingTree.setSelectedNode(child1);
		waitForTree(outgoingTree);

		ActionContext actionContext = new ActionContext(provider, outgoingTree);
		DockingActionIf goToAction = getAction("Go To Destination");
		performAction(goToAction, actionContext, true);

		CallNode callNode = (CallNode) child1;
		ProgramLocation newCodeBrowserLocation = codeBrowserPlugin.getCurrentLocation();
		assertTrue("The Go To action did not navigate the code browser",
			!originalLocation.equals(newCodeBrowserLocation));
		assertEquals("The code browser did not navigate to the address of the selected node",
			callNode.getLocation().getAddress(), newCodeBrowserLocation.getAddress());
	}

	@Test
	public void testMakeSelectionFromNodes() {
		//
		// Test that the user can select a node and then right-click to make a program selection.
		//
		setProviderFunction("0x5000");

		DockingActionIf selectSourceAction = getAction("Select Call Source");
		ActionContext context = new ActionContext(provider, outgoingTree);

		assertTrue("The selection action was enabled when no node was selected",
			!selectSourceAction.isEnabledForContext(context));

		ProgramSelection currentSelection = codeBrowserPlugin.getCurrentSelection();
		assertTrue(currentSelection.isEmpty());

		waitForTree(outgoingTree);
		GTreeNode rootNode = getRootNode(outgoingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Outgoing tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		OutgoingCallNode child0 = (OutgoingCallNode) children.get(0);
		clickNode(outgoingTree, child0);
		waitForTree(outgoingTree);

		assertTrue("The selection action was not enabled when a node was selected",
			selectSourceAction.isEnabledForContext(context));

		performAction(selectSourceAction, context, true);
		currentSelection = codeBrowserPlugin.getCurrentSelection();
		assertTrue(!currentSelection.isEmpty());

		Address callAddress = child0.getSourceAddress();
		assertEquals("Expected address not selected after performing action", callAddress,
			currentSelection.getMinAddress());
	}

	@Test
	public void testHomeAction_Navigation_DoNotFollow() {

		//
		// Test that the 'home' address does not change when the user navigates
		// 

		toggleFollowIncomingNavigation(false);
		Address startAddress = addr("0x5000");
		setProviderFunction("0x5000");

		DockingActionIf homeAction = getAction("Home");

		// go to some other address
		Address firstCallAddress = addr("0x6000");
		goTo(firstCallAddress);

		assertEquals(firstCallAddress, getListingAddress());

		performAction(homeAction, true);
		assertEquals(startAddress, getListingAddress());
	}

	@Test
	public void testHomeAction_Navigation_Follow() {

		//
		// Test that the 'home' address does not change when the user navigates
		// 

		toggleFollowIncomingNavigation(true);
		setProviderFunction("0x5000");

		DockingActionIf homeAction = getAction("Home");

		// go to some other address
		Address firstCallAddress = addr("0x6000");
		goTo(firstCallAddress);

		assertEquals(firstCallAddress, getListingAddress());

		performAction(homeAction, true);
		assertEquals(firstCallAddress, getListingAddress());
	}

	@Test
	public void testFilterOutgoingDuplicates_DifferentSource_SameDestination() {
		//
		// Test that the filter action will remove duplicate entries from the child nodes of 
		// the outgoing tree
		//
		// setup a known state

		setProviderFunction("0x5000");

		ToggleDockingAction filterDuplicatesAction =
			(ToggleDockingAction) getAction("Filter Duplicates");
		setToggleActionSelected(filterDuplicatesAction, new ActionContext(), true);
		waitForTree(outgoingTree);

		GTreeNode rootNode = getRootNode(outgoingTree);
		boolean shouldHaveDuplicates = false;
		Map<String, List<GTreeNode>> nameCountMap = createNameCountMap(rootNode);
		assertDuplicateChildStatus(nameCountMap, shouldHaveDuplicates);

		performAction(filterDuplicatesAction, true);// deselect

		waitForTree(outgoingTree);

		rootNode = getRootNode(outgoingTree);
		nameCountMap = createNameCountMap(rootNode);
		shouldHaveDuplicates = true;
		assertDuplicateChildStatus(nameCountMap, shouldHaveDuplicates);
	}

	@Test
	public void testFilterOutgoingDuplicates_SameSource_SameDestination() {
		//
		// Test that 2 references from the same source address to the same function will not get
		// added to the tree, regardless of the duplicate filter state
		// 

		// add a second reference (this is already defined in setup)
		builder.createMemoryCallReference("0x5020", "0x6000");

		setProviderFunction("0x5000");

		ToggleDockingAction filterDuplicatesAction =
			(ToggleDockingAction) getAction("Filter Duplicates");

		setToggleActionSelected(filterDuplicatesAction, new ActionContext(), true);

		waitForTree(outgoingTree);
		GTreeNode rootNode = getRootNode(outgoingTree);
		Map<String, List<GTreeNode>> nameCountMap = createNameCountMap(rootNode);

		// 1, not 2 entries (the exact duplicate and the duplicate destination are ignored)		
		assertEquals(1, nameCountMap.get("Function_6000").size());

		performAction(filterDuplicatesAction, true);// deselect
		waitForTree(outgoingTree);

		rootNode = getRootNode(outgoingTree);
		nameCountMap = createNameCountMap(rootNode);

		// 2, not 3 entries (the exact duplicate is ignored)
		assertEquals(2, nameCountMap.get("Function_6000").size());
	}

	@Test
	public void testFilterOutgoingDuplicates_SameSource_DifferentDestination() {
		//
		// Test that 2 references from the same source address to the same function will not get
		// added to the tree, regardless of the duplicate filter state
		// 

		// add a second reference from 0x5020 to a function already called (see setup)
		builder.createMemoryCallReference("0x5020", "0x6000");

		setProviderFunction("0x5000");

		ToggleDockingAction filterDuplicatesAction =
			(ToggleDockingAction) getAction("Filter Duplicates");
		setToggleActionSelected(filterDuplicatesAction, new ActionContext(), true);
		waitForTree(outgoingTree);

		GTreeNode rootNode = getRootNode(outgoingTree);
		boolean shouldHaveDuplicates = false;
		Map<String, List<GTreeNode>> nameCountMap = createNameCountMap(rootNode);
		assertDuplicateChildStatus(nameCountMap, shouldHaveDuplicates);

		performAction(filterDuplicatesAction, true);// deselect

		waitForTree(outgoingTree);

		rootNode = getRootNode(outgoingTree);
		nameCountMap = createNameCountMap(rootNode);
		shouldHaveDuplicates = true;
		assertDuplicateChildStatus(nameCountMap, shouldHaveDuplicates);
	}

	@Test
	public void testFilterIncomingDuplicates_SameFunctionNameInDifferentNamespaces()
			throws Exception {

		/*
		Create a function call tree that looks like:
		
		
			NS1::Foo
					root
			NS2::Foo
					root
					
				 */

		Function f1 = function("NS1", "Foo", 0x11000);
		Function f2 = function("NS2", "Foo", 0x12000);
		Function root = function(0x0000);
		function(f1, root);
		function(f2, root);

		setProviderFunction("0x0000");

		ToggleDockingAction filterDuplicatesAction =
			(ToggleDockingAction) getAction("Filter Duplicates");
		setToggleActionSelected(filterDuplicatesAction, new ActionContext(), true);
		waitForTree(incomingTree);

		// copy the names of the children into a map so that we can verify no duplicates
		GTreeNode rootNode = getRootNode(incomingTree);
		boolean shouldHaveDuplicates = true;
		Map<String, List<GTreeNode>> nameCountMap = createNameCountMap(rootNode);
		assertDuplicateChildStatus(nameCountMap, shouldHaveDuplicates);
	}

	@Test
	public void testTracksSelection() {
		//
		// Test the action that tracks node selection in the outgoing tree.  When toggled on, 
		// navigating the nodes in the outgoing tree should trigger a listing navigation.
		//
		Address startAddress = addr("0x5000");
		setProviderFunction("0x5000");

		// put the action in the correct state
		final ToggleDockingAction navigateAction =
			(ToggleDockingAction) getAction("Navigate Outgoing Nodes");

		if (!navigateAction.isSelected()) {
			performAction(navigateAction, true);
		}

		waitForTree(outgoingTree);
		GTreeNode rootNode = getRootNode(outgoingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Outgoing tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		OutgoingCallNode child0 = (OutgoingCallNode) children.get(0);
		clickNode(outgoingTree, child0);
		waitForTree(outgoingTree);
		Address expectedAddress0 = child0.getSourceAddress();
		assertEquals("Node selection did not trigger navigation", getListingAddress(),
			expectedAddress0);

		OutgoingCallNode child1 = (OutgoingCallNode) children.get(1);
		clickNode(outgoingTree, child1);
		waitForTree(outgoingTree);
		Address expectedAddress1 = child1.getSourceAddress();
		assertEquals("Node selection did not trigger navigation", getListingAddress(),
			expectedAddress1);

		//
		// now de-select the action and make so no navigation takes place
		//
		goTo(startAddress);

		performAction(navigateAction, true);// don't track selection

		rootNode = getRootNode(outgoingTree);
		children = rootNode.getChildren();
		assertTrue(
			"Outgoing tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		child0 = (OutgoingCallNode) children.get(0);
		clickNode(outgoingTree, child0);
		waitForTree(outgoingTree);
		assertEquals("Node selection triggered navigation when the action is disabled",
			getListingAddress(), startAddress);

		child1 = (OutgoingCallNode) children.get(1);
		clickNode(outgoingTree, child1);
		waitForTree(outgoingTree);
		assertEquals("Node selection triggered navigation when the action is disabled",
			getListingAddress(), startAddress);
	}

	@Test
	public void testCallTreeForExternalFicticiousFunction() {
		// 
		// Apparently, we create fake function markup for external functions.  Thus, there is no
		// real function at that address and our plugin has to do some work to find out where
		// we 'hang' references to the external function, which is itself a Function.  These 
		// fake function will usually just be a pointer to another function.
		//

		// Setup external call linkage, 2000 -> PTR@10100 -> GDI32.DLL:LineTo
		String addrString = "10100";
		applyCmd(program, new CreateDataCmd(addr(addrString), true, PointerDataType.dataType));
		applyCmd(program,
			new CreateExternalFunctionCmd("GDI32.DLL", "LineTo", null, SourceType.IMPORTED));
		applyCmd(program, new SetExternalRefCmd(addr(addrString), 0, "GDI32.DLL", "LineTo", null,
			RefType.DATA, SourceType.IMPORTED));
		applyCmd(program, new AddMemRefCmd(addr("2000"), addr(addrString), RefType.INDIRECTION,
			SourceType.ANALYSIS, 0));
		applyCmd(program, new SetExternalRefCmd(addr("2000"), Reference.MNEMONIC, "GDI32.DLL",
			"LineTo", null, RefType.COMPUTED_CALL, SourceType.ANALYSIS));

		setProviderFunction(addrString);

		waitForTree(incomingTree);
		GTreeNode rootNode = getRootNode(incomingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue("Incoming tree does not have callers as expected for function: " + addrString,
			children.size() > 0);
	}

	@Test
	public void testRenamingIncomingFunction() {
		//
		// Test that renaming a function in the incoming tree will rename the node, if it is
		// visible.
		//
		setProviderFunction("0x5000");

		waitForTree(incomingTree);
		GTreeNode rootNode = getRootNode(incomingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Incoming tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		GTreeNode child1 = children.get(0);
		String nodeName = child1.getName();

		String originalName = "0x4000";
		Function incomingFunction = getFunction(addr(originalName));
		assertEquals(incomingFunction.getName(), nodeName);

		String newName = "bob";
		renameFunction(incomingFunction, newName);

		rootNode = getRootNode(incomingTree);
		children = rootNode.getChildren();
		assertTrue(
			"Incoming tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		assertContainsChild(children, newName);
		assertDoesntContainChild(children, originalName);
	}

	@Test
	public void testRenamingIncomingRootFunction() {
		setProviderFunction("0x5000");

		waitForTree(incomingTree);
		GTreeNode rootNode = getRootNode(incomingTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertTrue(
			"Incoming tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		Function rootFunction = getFunction(addr("0x5000"));
		assertEquals("Incoming References - " + rootFunction.getName(), rootNode.getName());

		String newName = "bob";
		renameFunction(rootFunction, newName);

		rootNode = getRootNode(incomingTree);
		children = rootNode.getChildren();
		assertTrue(
			"Incoming tree does not have callers as expected for function: " + getListingFunction(),
			children.size() > 0);

		assertEquals("Incoming References - " + newName, rootNode.getName());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertProviderMatchesListingFunction() {
		assertEquals("Provider's location does not match that of the listing.",
			getListingFunction(), providerFunction());
	}

	private void toggleFollowIncomingNavigation(boolean selected) {
		ToggleDockingAction navigateIncomingLoctionsAction =
			(ToggleDockingAction) getAction("Navigation Incoming Location Changes");
		setToggleActionSelected(navigateIncomingLoctionsAction, provider.getActionContext(null),
			selected);
	}

	private void assertContainsChild(List<GTreeNode> children, String name) {
		for (GTreeNode node : children) {
			if (node.getName().equals(name)) {
				return;
			}
		}

		Assert.fail("Unable to find expected node by name: " + name);
	}

	private void assertDoesntContainChild(List<GTreeNode> children, String name) {
		for (GTreeNode node : children) {
			if (node.getName().equals(name)) {
				Assert.fail("Found unexpected node by name: " + name);
			}
		}
	}

	private GTreeNode getRootNode(GTree tree) {
		return getRootNode(tree, false);
	}

	private GTreeNode getRootNode(final GTree tree, boolean filtered) {
		waitForTree(tree);
		final AtomicReference<GTreeNode> ref = new AtomicReference<>();
		runSwing(() -> ref.set(filtered ? tree.getViewRoot() : tree.getModelRoot()));
		return ref.get();
	}

	private void renameFunction(Function function, String newName) {

		SetFunctionNameCmd cmd =
			new SetFunctionNameCmd(function.getEntryPoint(), newName, SourceType.USER_DEFINED);
		boolean result = false;

		int txID = program.startTransaction("Test - Create Function");
		try {
			result = cmd.applyTo(program);
		}
		finally {
			program.endTransaction(txID, true);
		}

		assertTrue("Failed to rename function: " + cmd.getStatusMsg(), result);
		program.flushEvents();
		waitForSwing();
	}

	private Function getFunction(Address address) {
		FunctionManager functionManager = program.getFunctionManager();
		return functionManager.getFunctionAt(address);
	}

	private void assertOutgoingNoNode(String name, int depth, boolean filtered) {
		List<NodeDepthInfo> nodes = getNodesByDepth(false, filtered);
		for (NodeDepthInfo info : nodes) {
			String nodeName = info.node.getName();
			if (nodeName.indexOf(name) != -1) {
				Assert.fail("Found node that should have been filtered out - depth: " + depth +
					"; node: " + info);
			}
		}
	}

	private void assertOutgoingNode(String name, int depth) {
		List<NodeDepthInfo> nodes = getNodesByDepth(false);
		List<NodeDepthInfo> matches = new ArrayList<>();
		for (NodeDepthInfo info : nodes) {
			String nodeName = info.node.getName();
			if (nodeName.indexOf(name) != -1) {
				matches.add(info);
			}
		}

		for (NodeDepthInfo info : matches) {
			if (info.depth == depth) {
				// found one!
				return;
			}
		}

		Assert.fail("Unable to find a node by name: " + name + " at depth: " + depth);
	}

	private void assertOutgoingMaxDepth(int depth, boolean filtered) {
		List<NodeDepthInfo> nodes = getNodesByDepth(false, filtered);
		NodeDepthInfo maxDepthNode = nodes.get(nodes.size() - 1);

		assertEquals("Node max depth does not match: " + maxDepthNode, depth, maxDepthNode.depth);
	}

	private void setOutgoingFilter(final String text) {
		runSwing(() -> provider.setOutgoingFilter(text));
		waitForTree(outgoingTree);
	}

	private void setProviderFunction(String address) {
		final Address addr = addr(address);
		goTo(addr);
		runSwing(() -> {
			ProgramLocation location = new ProgramLocation(program, addr);
			invokeInstanceMethod("doSetLocation", provider, new Class[] { ProgramLocation.class },
				new Object[] { location });
		});

		waitForSwing();
		waitForTree(incomingTree);
		waitForTree(outgoingTree);
	}

	private GTreeNode selectIncomingNode(String text) {
		GTreeNode rootNode = getRootNode(incomingTree);
		GTreeNode node = findNode(rootNode, text);
		assertNotNull(node);
		incomingTree.setSelectedNode(node);
		waitForTree(incomingTree);
		return node;
	}

	private GTreeNode selectOutgoingNode(String text) {
		GTreeNode rootNode = getRootNode(outgoingTree);
		GTreeNode node = findNode(rootNode, text);
		assertNotNull(node);
		outgoingTree.setSelectedNode(node);
		waitForTree(outgoingTree);
		return node;
	}

	private GTreeNode findNode(GTreeNode node, String text) {
		String name = node.getName();
		if (name.indexOf(text) != -1) {
			return node;
		}

		if (node instanceof GTreeSlowLoadingNode) {
			boolean loaded = ((GTreeSlowLoadingNode) node).isLoaded();
			if (!loaded) {
				return null;// children not loaded--don't load
			}
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			GTreeNode foundNode = findNode(child, text);
			if (foundNode != null) {
				return foundNode;
			}
		}
		return null;
	}

	private void assertDepth(GTreeNode node, int depth) {
		int currentDepth = node.getTreePath().getPathCount() - 1;
		int maxNodeDepth = getMaxNodeDepth(node, currentDepth);
		assertEquals("Node depth is not correct " + node, depth, maxNodeDepth);
	}

	private int getMaxNodeDepth(GTreeNode node, int currentDepth) {
		int maxDepth = currentDepth;
		if (node instanceof GTreeSlowLoadingNode) {
			boolean loaded = ((GTreeSlowLoadingNode) node).isLoaded();
			if (!loaded) {
				return maxDepth;// children not loaded--don't load
			}
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			maxDepth = Math.max(maxDepth, getMaxNodeDepth(child, currentDepth + 1));
		}

		return maxDepth;
	}

	private void fullyExpandIncomingNode(GTreeNode node) {
		DockingActionIf expandAction = getLocalAction(provider, "Fully Expand Selected Nodes");
		performAction(expandAction, new ActionContext(provider, incomingTree), false);
		waitForTree(node.getTree());
	}

	private void fullyExpandOutgoingNode(GTreeNode node) {
		DockingActionIf expandAction = getLocalAction(provider, "Fully Expand Selected Nodes");
		performAction(expandAction, new ActionContext(provider, outgoingTree), false);
		waitForTree(node.getTree());
	}

	private void assertIncomingNode(String name, int depth) {
		List<NodeDepthInfo> nodes = getNodesByDepth(true);
		List<NodeDepthInfo> matches = new ArrayList<>();
		for (NodeDepthInfo info : nodes) {
			String nodeName = info.node.getName();
			if (nodeName.indexOf(name) != -1) {
				matches.add(info);
			}
		}

		for (NodeDepthInfo info : matches) {
			if (info.depth == depth) {
				// found one!
				return;
			}
		}

		Assert.fail("Unable to find a node by name: " + name + " at depth: " + depth);
	}

	private void assertIncomingNoNode(String name, int depth, boolean filtered) {
		List<NodeDepthInfo> nodes = getNodesByDepth(true, filtered);
		for (NodeDepthInfo info : nodes) {
			String nodeName = info.node.getName();
			if (nodeName.indexOf(name) != -1) {
				Assert.fail("Found node that should have been filtered out - depth: " + depth +
					"; node: " + info);
			}
		}
	}

	private void assertIncomingMaxDepth(int depth, boolean filtered) {
		List<NodeDepthInfo> nodes = getNodesByDepth(true, filtered);
		NodeDepthInfo maxDepthNode = nodes.get(nodes.size() - 1);

		assertEquals("Node max depth does not match: " + maxDepthNode, depth, maxDepthNode.depth);
	}

	private List<NodeDepthInfo> getNodesByDepth(boolean incoming) {
		return getNodesByDepth(incoming, false);
	}

	private List<NodeDepthInfo> getNodesByDepth(boolean incoming, boolean filtered) {
		List<NodeDepthInfo> list = new ArrayList<>();
		GTreeNode root =
			incoming ? getRootNode(incomingTree, filtered) : getRootNode(outgoingTree, filtered);
		accumulateNodeDepths(list, root, 0);
		Collections.sort(list);
		return list;
	}

	private void accumulateNodeDepths(List<NodeDepthInfo> list, GTreeNode node, int depth) {

		NodeDepthInfo info = new NodeDepthInfo(node, depth);
		if (!list.contains(info)) {
			list.add(info);
		}

		if (node instanceof GTreeSlowLoadingNode) {
			boolean loaded = ((GTreeSlowLoadingNode) node).isLoaded();
			if (!loaded) {
				return;// children not loaded--don't load
			}
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			accumulateNodeDepths(list, child, depth + 1);
		}
	}

	private void setIncomingFilter(final String text) {
		runSwing(() -> provider.setIncomingFilter(text));
		waitForTree(incomingTree);
	}

	private void setDepth(final int depth) {
		runSwing(() -> provider.setRecurseDepth(depth));
	}

	private int currentDepthSetting(CallTreeProvider aProvider) {
		return aProvider.getRecurseDepth();
	}

	private Function getListingFunction() {
		FunctionManager functionManager = program.getFunctionManager();
		ProgramLocation codeBrowserLocation = codeBrowserPlugin.getCurrentLocation();
		return functionManager.getFunctionContaining(codeBrowserLocation.getAddress());
	}

	private Function providerFunction() {
		return (Function) getInstanceField("currentFunction", provider);
	}

	private ProgramLocation currentLocation() {
		return codeBrowserPlugin.getCurrentLocation();
	}

	private Address getListingAddress() {
		return codeBrowserPlugin.getCurrentAddress();
	}

	private Map<String, List<GTreeNode>> createNameCountMap(GTreeNode node) {
		Map<String, List<GTreeNode>> map = LazyMap.lazyMap(new HashMap<>(), k -> new ArrayList<>());
		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			map.get(child.getName()).add(child);
		}
		return map;
	}

	private void assertDuplicateChildStatus(Map<String, List<GTreeNode>> childCountMap,
			boolean shouldHaveDuplicates) {
		boolean foundDuplicates = false;
		Set<Entry<String, List<GTreeNode>>> entrySet = childCountMap.entrySet();
		String duplicateName = null;
		for (Entry<String, List<GTreeNode>> entry : entrySet) {
			List<GTreeNode> list = entry.getValue();
			if (list.size() != 1) {
				duplicateName = entry.getKey();
				foundDuplicates = true;
				break;
			}
		}

		String errorMessage =
			(shouldHaveDuplicates ? "Did not find " : "Found") + " duplicate child entries for '" +
				duplicateName + "'";
		assertEquals(errorMessage, shouldHaveDuplicates, foundDuplicates);
	}

	private void clickNode(final GTree tree, GTreeNode node) {
		Rectangle pathBounds = tree.getPathBounds(node.getTreePath());
		JTree jTree = (JTree) AbstractGenericTest.getInstanceField("tree", tree);
		int x = pathBounds.x + 2;
		int y = pathBounds.y + 2;
		clickMouse(jTree, MouseEvent.BUTTON1, x, y, 1, 0);
	}

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action = getLocalAction(provider, actionName);
		return action;
	}

	/**
	 * Shows and returns a provider for the specified address.
	 */
	private CallTreeProvider showProvider(String address) {
		goTo(addr(address));
		ProgramLocation location = codeBrowserPlugin.getCurrentLocation();

		DockingAction action = callTreePlugin.getShowCallTreeFromMenuAction();
		performAction(action);

		return runSwing(() -> callTreePlugin.findTransientProviderForLocation(location));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}

	private void goTo(final Address address) {
		runSwing(() -> goToService.goTo(address));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NodeDepthInfo implements Comparable<NodeDepthInfo> {
		private GTreeNode node;
		private int depth;

		NodeDepthInfo(GTreeNode node, int depth) {
			this.node = node;
			this.depth = depth;
		}

		@Override
		public int compareTo(NodeDepthInfo o) {
			if (depth != o.depth) {
				return depth - o.depth;
			}

			String myName = node.getName();
			String otherName = o.node.getName();
			if (!myName.equals(otherName)) {
				return myName.compareTo(otherName);
			}

			// something suitable
			return System.identityHashCode(node) - System.identityHashCode(o.node);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + depth;
			result = prime * result + ((node == null) ? 0 : node.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			NodeDepthInfo other = (NodeDepthInfo) obj;
			if (!getOuterType().equals(other.getOuterType())) {
				return false;
			}
			if (depth != other.depth) {
				return false;
			}
			if (node == null) {
				if (other.node != null) {
					return false;
				}
			}
			else if (!node.equals(other.node)) {
				return false;
			}
			return true;
		}

		private CallTreePluginTest getOuterType() {
			return CallTreePluginTest.this;
		}

		@Override
		public String toString() {
			return "depth=" + depth + ", path: " + getPath();
		}

		private String getPath() {
			StringBuilder buffy = new StringBuilder();
			TreePath treePath = node.getTreePath();
			Object[] path = treePath.getPath();
			for (Object object : path) {
				if (buffy.length() != 0) {
					buffy.append(" -> ");
				}
				buffy.append(object);
			}
			return buffy.toString();
		}
	}
}
